#!/usr/bin/env python3
"""
azure_copy_permissions.py
=========================
Copy Azure permissions from one user to another.

Covers four permission categories:
  1. Azure RBAC role assignments      (ARM / azure-mgmt-authorization)
  2. Azure AD group memberships       (Microsoft Graph)
  3. Enterprise app role assignments  (Microsoft Graph)
  4. Entra ID directory role assignments (Microsoft Graph beta —
     e.g. Global Admin, User Admin, Billing Admin)

Authentication uses DefaultAzureCredential, which tries (in order):
  - Environment variables (AZURE_CLIENT_ID / AZURE_CLIENT_SECRET / AZURE_TENANT_ID)
  - Workload Identity / Managed Identity
  - Azure CLI  (`az login`)
  - Azure Developer CLI (`azd auth login`)
  - Interactive browser (if --interactive flag is given)

Requirements:
  pip install azure-identity azure-mgmt-authorization azure-mgmt-subscription requests

Usage examples:
  # Copy everything from alice to bob (by UPN)
  python azure_copy_permissions.py alice@contoso.com bob@contoso.com

  # Dry-run only, show what would be copied
  python azure_copy_permissions.py alice@contoso.com bob@contoso.com --dry-run

  # Copy only RBAC and group memberships (skip app roles + directory roles)
  python azure_copy_permissions.py alice@contoso.com bob@contoso.com --scope rbac groups

  # Copy Entra ID directory roles only (Global Admin, etc.)
  python azure_copy_permissions.py alice@contoso.com bob@contoso.com --scope dirroles

  # Limit RBAC scan to two specific subscriptions
  python azure_copy_permissions.py alice@contoso.com bob@contoso.com --subscriptions sub-id-1 sub-id-2

  # Debug output + JSON summary
  python azure_copy_permissions.py alice@contoso.com bob@contoso.com --debug --output json
"""

import argparse
import json
import logging
import sys
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional

import requests
from azure.identity import DefaultAzureCredential, InteractiveBrowserCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.subscription import SubscriptionClient

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GRAPH_BASE      = "https://graph.microsoft.com/v1.0"
GRAPH_BETA_BASE = "https://graph.microsoft.com/beta"   # required for transitiveRoleAssignments
ARM_BASE        = "https://management.azure.com"

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
ARM_SCOPE   = "https://management.azure.com/.default"

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

log = logging.getLogger("azure_copy_permissions")


def _configure_logging(debug: bool) -> None:
    level = logging.DEBUG if debug else logging.INFO
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    log.setLevel(level)
    log.addHandler(handler)
    if not debug:
        # Suppress noisy Azure SDK HTTP logs unless debug is on
        logging.getLogger("azure").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# Result data structures
# ---------------------------------------------------------------------------

@dataclass
class CopyResult:
    """Accumulates counts and errors for a single permission category."""
    category: str
    found: int = 0
    copied: int = 0
    skipped_existing: int = 0
    skipped_transitive: int = 0
    errors: list = field(default_factory=list)

    def summary(self) -> str:
        parts = (
            f"[{self.category}] found={self.found}  "
            f"copied={self.copied}  "
            f"skipped_existing={self.skipped_existing}  "
            f"errors={len(self.errors)}"
        )
        if self.skipped_transitive:
            parts += f"  skipped_transitive={self.skipped_transitive}"
        return parts


# ---------------------------------------------------------------------------
# Token / credential helpers
# ---------------------------------------------------------------------------

class TokenProvider:
    """Wraps a credential and delegates token acquisition to the Azure SDK."""

    def __init__(self, credential) -> None:
        self._cred = credential

    def get(self, scope: str) -> str:
        # Always delegate to the SDK — it handles caching and refresh internally.
        # Caching the raw token string here would cause 401s after the ~1 hr expiry.
        return self._cred.get_token(scope).token

    def headers(self, scope: str) -> dict:
        return {"Authorization": f"Bearer {self.get(scope)}",
                "Content-Type": "application/json"}


# ---------------------------------------------------------------------------
# Graph API helpers
# ---------------------------------------------------------------------------

def _graph_get(token_provider: TokenProvider, path: str, params: dict = None) -> dict:
    """GET a single Graph resource; raises on non-2xx."""
    url = f"{GRAPH_BASE}{path}"
    log.debug("GRAPH GET %s params=%s", url, params)
    resp = requests.get(url, headers=token_provider.headers(GRAPH_SCOPE), params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()


def _graph_get_all(token_provider: TokenProvider, path: str, params: dict = None) -> list:
    """Follow @odata.nextLink pages and return the combined value list."""
    results = []
    url = f"{GRAPH_BASE}{path}"
    while url:
        log.debug("GRAPH GET (paged) %s", url)
        resp = requests.get(url, headers=token_provider.headers(GRAPH_SCOPE), params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        results.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
        params = None  # nextLink already includes query string
    return results


def _graph_post(token_provider: TokenProvider, path: str, body: dict) -> dict:
    """POST to Graph; raises on non-2xx."""
    url = f"{GRAPH_BASE}{path}"
    log.debug("GRAPH POST %s body=%s", url, body)
    resp = requests.post(url, headers=token_provider.headers(GRAPH_SCOPE),
                         json=body, timeout=30)
    resp.raise_for_status()
    if resp.status_code == 204 or not resp.content:
        return {}
    return resp.json()


# ---------------------------------------------------------------------------
# User resolution
# ---------------------------------------------------------------------------

def resolve_user(token_provider: TokenProvider, upn_or_id: str) -> dict:
    """
    Resolve a UPN (user@domain.com) or object ID to a Graph user object.
    Returns dict with at least 'id' and 'displayName'.
    """
    log.debug("Resolving user: %s", upn_or_id)
    try:
        data = _graph_get(token_provider, f"/users/{upn_or_id}",
                          params={"$select": "id,displayName,userPrincipalName"})
        log.info("Resolved %s → %s (%s)", upn_or_id, data["displayName"], data["id"])
        return data
    except requests.HTTPError as exc:
        if exc.response.status_code == 404:
            log.error("User not found: %s", upn_or_id)
        raise


# ---------------------------------------------------------------------------
# 1. Azure RBAC role assignments
# ---------------------------------------------------------------------------

def _list_subscriptions(arm_client: SubscriptionClient) -> list[str]:
    """Return all accessible subscription IDs."""
    subs = [s.subscription_id for s in arm_client.subscriptions.list()]
    log.debug("Found %d subscriptions", len(subs))
    return subs


def get_rbac_assignments(
    token_provider: TokenProvider,
    object_id: str,
    subscription_ids: list[str],
) -> list[dict]:
    """
    Return all RBAC role assignments for *object_id* across the given subscriptions.
    Each item is the raw ARM role assignment object, augmented with 'roleName'.
    """
    all_assignments = []
    headers = token_provider.headers(ARM_SCOPE)

    for sub_id in subscription_ids:
        url = (f"{ARM_BASE}/subscriptions/{sub_id}/providers/"
               f"Microsoft.Authorization/roleAssignments"
               f"?api-version=2022-04-01"
               f"&$filter=assignedTo('{object_id}')")
        log.debug("ARM GET role assignments for sub %s", sub_id)
        while url:
            resp = requests.get(url, headers=headers, timeout=30)
            if resp.status_code == 403:
                log.warning("No access to subscription %s – skipping", sub_id)
                break
            resp.raise_for_status()
            data = resp.json()
            for ra in data.get("value", []):
                # Resolve the role definition name for human readability
                ra["_roleName"] = _resolve_role_name(token_provider, ra["properties"]["roleDefinitionId"])
                all_assignments.append(ra)
            url = data.get("nextLink")

    log.info("Found %d RBAC role assignments for object %s", len(all_assignments), object_id)
    return all_assignments


def _resolve_role_name(token_provider: TokenProvider, role_definition_id: str) -> str:
    """Fetch the friendly name for a role definition ID (cached via lru-style dict)."""
    if not hasattr(_resolve_role_name, "_cache"):
        _resolve_role_name._cache = {}
    cache = _resolve_role_name._cache
    if role_definition_id not in cache:
        url = f"{ARM_BASE}{role_definition_id}?api-version=2022-04-01"
        resp = requests.get(url, headers=token_provider.headers(ARM_SCOPE), timeout=30)
        if resp.ok:
            cache[role_definition_id] = resp.json()["properties"]["roleName"]
        else:
            cache[role_definition_id] = role_definition_id  # fallback to ID
    return cache[role_definition_id]


def copy_rbac_assignments(
    token_provider: TokenProvider,
    from_id: str,
    to_id: str,
    assignments: list[dict],
    dry_run: bool,
) -> CopyResult:
    """
    Assign each role from *assignments* to *to_id* at the same scope.
    Skips assignments the target already has.
    """
    result = CopyResult(category="RBAC")
    result.found = len(assignments)

    # Pre-fetch existing assignments for the target so we can skip dupes.
    # Track which scopes we've already loaded to avoid redundant API calls.
    existing_keys: set = set()
    loaded_scopes: set = set()
    headers = token_provider.headers(ARM_SCOPE)

    for ra in assignments:
        scope = ra["properties"]["scope"]
        role_def_id = ra["properties"]["roleDefinitionId"]
        role_name = ra.get("_roleName", role_def_id)
        key = (scope, role_def_id)

        # Lazy-load all of the target's existing assignments at this scope (once per scope).
        # Follow nextLink pagination so no existing assignments are missed.
        if scope not in loaded_scopes:
            loaded_scopes.add(scope)
            check_url = (f"{ARM_BASE}{scope}/providers/Microsoft.Authorization/roleAssignments"
                         f"?api-version=2022-04-01&$filter=assignedTo('{to_id}')")
            while check_url:
                check_resp = requests.get(check_url, headers=headers, timeout=30)
                if not check_resp.ok:
                    break
                page = check_resp.json()
                for existing in page.get("value", []):
                    ep = existing["properties"]
                    existing_keys.add((ep["scope"], ep["roleDefinitionId"]))
                check_url = page.get("nextLink")

        if key in existing_keys:
            log.info("  SKIP (already assigned): %s @ %s", role_name, scope)
            result.skipped_existing += 1
            continue

        log.info("  %sCOPY RBAC: %s @ %s",
                 "[DRY-RUN] " if dry_run else "", role_name, scope)

        if not dry_run:
            new_ra_id = str(uuid.uuid4())
            put_url = (f"{ARM_BASE}{scope}/providers/Microsoft.Authorization/"
                       f"roleAssignments/{new_ra_id}?api-version=2022-04-01")
            body = {
                "properties": {
                    "roleDefinitionId": role_def_id,
                    "principalId": to_id,
                    "principalType": "User",
                }
            }
            put_resp = requests.put(put_url, headers=headers, json=body, timeout=30)
            if put_resp.ok:
                result.copied += 1
                existing_keys.add(key)
            else:
                err = f"Failed to assign {role_name} @ {scope}: {put_resp.text}"
                log.error(err)
                result.errors.append(err)
        else:
            result.copied += 1

    return result


# ---------------------------------------------------------------------------
# 2. Azure AD group memberships
# ---------------------------------------------------------------------------

def get_group_memberships(token_provider: TokenProvider, object_id: str) -> list[dict]:
    """
    Return the *direct* group memberships of a user.
    (Transitive memberships via nested groups cannot be directly replicated.)
    """
    members = _graph_get_all(
        token_provider,
        f"/users/{object_id}/memberOf",
        params={"$select": "id,displayName,groupTypes,mailEnabled,securityEnabled"},
    )
    # Filter to security/M365 groups only (not directory roles, etc.)
    groups = [m for m in members if m.get("@odata.type") == "#microsoft.graph.group"]
    log.info("Found %d direct group memberships for %s", len(groups), object_id)
    return groups


def copy_group_memberships(
    token_provider: TokenProvider,
    from_id: str,
    to_id: str,
    groups: list[dict],
    dry_run: bool,
) -> CopyResult:
    """Add *to_id* to each group *from_id* belongs to (skips if already a member)."""
    result = CopyResult(category="Groups")
    result.found = len(groups)

    # Fetch target's existing group memberships to detect skips
    existing_groups = {g["id"] for g in get_group_memberships(token_provider, to_id)}

    for group in groups:
        gid   = group["id"]
        gname = group.get("displayName", gid)

        if gid in existing_groups:
            log.info("  SKIP (already member): %s", gname)
            result.skipped_existing += 1
            continue

        log.info("  %sCOPY GROUP: %s",
                 "[DRY-RUN] " if dry_run else "", gname)

        if not dry_run:
            try:
                _graph_post(
                    token_provider,
                    f"/groups/{gid}/members/$ref",
                    {"@odata.id": f"{GRAPH_BASE}/directoryObjects/{to_id}"},
                )
                result.copied += 1
                existing_groups.add(gid)
            except requests.HTTPError as exc:
                # 400 "One or more added object references already exist" → treat as skip
                if exc.response.status_code == 400 and "already exist" in exc.response.text:
                    log.info("  SKIP (race/already member): %s", gname)
                    result.skipped_existing += 1
                else:
                    err = f"Failed to add to group {gname}: {exc.response.text}"
                    log.error(err)
                    result.errors.append(err)
        else:
            result.copied += 1

    return result


# ---------------------------------------------------------------------------
# 3. Enterprise app role assignments
# ---------------------------------------------------------------------------

def get_app_role_assignments(token_provider: TokenProvider, object_id: str) -> list[dict]:
    """
    Return all app role assignments for the user (roles granted by enterprise apps).
    Each item contains resourceId, resourceDisplayName, appRoleId.
    """
    assignments = _graph_get_all(
        token_provider,
        f"/users/{object_id}/appRoleAssignments",
    )
    log.info("Found %d app role assignments for %s", len(assignments), object_id)
    return assignments


def copy_app_role_assignments(
    token_provider: TokenProvider,
    from_id: str,
    to_id: str,
    assignments: list[dict],
    dry_run: bool,
) -> CopyResult:
    """Grant each app role assignment to *to_id* (skips if already granted)."""
    result = CopyResult(category="AppRoles")
    result.found = len(assignments)

    # Fetch existing app role assignments for the target
    existing = get_app_role_assignments(token_provider, to_id)
    existing_keys = {(a["resourceId"], a["appRoleId"]) for a in existing}

    for ra in assignments:
        resource_id   = ra["resourceId"]
        app_role_id   = ra["appRoleId"]
        resource_name = ra.get("resourceDisplayName", resource_id)
        key = (resource_id, app_role_id)

        if key in existing_keys:
            log.info("  SKIP (already assigned): %s / role=%s", resource_name, app_role_id)
            result.skipped_existing += 1
            continue

        log.info("  %sCOPY APP ROLE: %s / role=%s",
                 "[DRY-RUN] " if dry_run else "", resource_name, app_role_id)

        if not dry_run:
            try:
                _graph_post(
                    token_provider,
                    f"/users/{to_id}/appRoleAssignments",
                    {
                        "principalId": to_id,
                        "resourceId": resource_id,
                        "appRoleId": app_role_id,
                    },
                )
                result.copied += 1
                existing_keys.add(key)
            except requests.HTTPError as exc:
                err = f"Failed to assign app role on {resource_name}: {exc.response.text}"
                log.error(err)
                result.errors.append(err)
        else:
            result.copied += 1

    return result


# ---------------------------------------------------------------------------
# 4. Entra ID directory role assignments
# ---------------------------------------------------------------------------
# These are tenant-level roles (Global Admin, User Admin, etc.) managed by
# Entra ID (formerly Azure AD) — distinct from Azure RBAC resource roles.
#
# We use the BETA Graph endpoint because v1.0 does not expose
# transitiveRoleAssignments (which surfaces roles granted via PIM groups):
#   GET /beta/roleManagement/directory/transitiveRoleAssignments
#       ?$filter=principalId eq '{userId}'
#
# NOTE: This endpoint returns BOTH direct and transitive (group-based) assignments.
# We can only *copy* the direct ones; transitive assignments come from group
# membership which is already handled by the groups category.
#
# Required Graph permissions:
#   Read  : RoleManagement.Read.All
#   Write : RoleManagement.ReadWrite.Directory
# ---------------------------------------------------------------------------

def _graph_beta_get_all(
    token_provider: TokenProvider,
    path: str,
    params: dict = None,
    consistency_level: str = None,
) -> list:
    """Follow @odata.nextLink pages against the Graph *beta* endpoint.

    Pass consistency_level='eventual' for endpoints that require advanced query
    support (e.g. transitiveRoleAssignments), which also need $count=true.
    """
    results = []
    url = f"{GRAPH_BETA_BASE}{path}"
    headers = token_provider.headers(GRAPH_SCOPE)
    if consistency_level:
        headers = {**headers, "ConsistencyLevel": consistency_level}
    while url:
        log.debug("GRAPH BETA GET (paged) %s", url)
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        results.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
        params = None
    return results


def _resolve_directory_role_name(token_provider: TokenProvider, role_definition_id: str) -> str:
    """Fetch the friendly display name for an Entra ID role definition (cached)."""
    if not hasattr(_resolve_directory_role_name, "_cache"):
        _resolve_directory_role_name._cache = {}
    cache = _resolve_directory_role_name._cache
    if role_definition_id not in cache:
        try:
            data = _graph_get(
                token_provider,
                f"/roleManagement/directory/roleDefinitions/{role_definition_id}",
                params={"$select": "displayName"},
            )
            cache[role_definition_id] = data.get("displayName", role_definition_id)
        except Exception:
            cache[role_definition_id] = role_definition_id
    return cache[role_definition_id]


def get_directory_role_assignments(token_provider: TokenProvider, object_id: str) -> list[dict]:
    """
    Return all Entra ID directory role assignments for *object_id*, including
    those granted transitively through PIM-managed groups.

    Each item has: id, principalId, roleDefinitionId, directoryScopeId,
    memberType ('Direct' or 'Group'), and _roleName (resolved display name).
    """
    # transitiveRoleAssignments requires advanced query support:
    # ConsistencyLevel: eventual header + $count=true query param.
    assignments = _graph_beta_get_all(
        token_provider,
        "/roleManagement/directory/transitiveRoleAssignments",
        params={"$filter": f"principalId eq '{object_id}'", "$count": "true"},
        consistency_level="eventual",
    )
    for a in assignments:
        a["_roleName"] = _resolve_directory_role_name(token_provider, a["roleDefinitionId"])
    log.info(
        "Found %d Entra ID directory role assignments for %s "
        "(%d direct, %d via group/PIM)",
        len(assignments),
        object_id,
        sum(1 for a in assignments if a.get("memberType") == "Direct"),
        sum(1 for a in assignments if a.get("memberType") != "Direct"),
    )
    return assignments


def copy_directory_role_assignments(
    token_provider: TokenProvider,
    from_id: str,
    to_id: str,
    assignments: list[dict],
    dry_run: bool,
) -> CopyResult:
    """
    Assign each *direct* Entra ID directory role to *to_id*.

    Transitive (group/PIM-based) assignments are logged but skipped here —
    they will be handled implicitly if the 'groups' category is also copied.
    """
    result = CopyResult(category="DirectoryRoles")
    result.found = len(assignments)

    # Fetch existing direct directory role assignments for the target
    existing_raw = _graph_beta_get_all(
        token_provider,
        "/roleManagement/directory/roleAssignments",
        params={"$filter": f"principalId eq '{to_id}'"},
    )
    existing_keys = {(a["roleDefinitionId"], a.get("directoryScopeId", "/")) for a in existing_raw}

    for ra in assignments:
        role_name      = ra.get("_roleName", ra["roleDefinitionId"])
        role_def_id    = ra["roleDefinitionId"]
        scope_id       = ra.get("directoryScopeId", "/")
        member_type    = ra.get("memberType", "Direct")

        # Transitive assignments come from group membership — skip them here
        if member_type != "Direct":
            log.info(
                "  SKIP (transitive via group/PIM — copy groups to replicate): %s", role_name
            )
            result.skipped_transitive += 1
            continue

        key = (role_def_id, scope_id)
        if key in existing_keys:
            log.info("  SKIP (already assigned): %s", role_name)
            result.skipped_existing += 1
            continue

        log.info("  %sCOPY DIR ROLE: %s (scope=%s)",
                 "[DRY-RUN] " if dry_run else "", role_name, scope_id)

        if not dry_run:
            try:
                _graph_post(
                    token_provider,
                    "/roleManagement/directory/roleAssignments",
                    {
                        "principalId":      to_id,
                        "roleDefinitionId": role_def_id,
                        "directoryScopeId": scope_id,
                    },
                )
                result.copied += 1
                existing_keys.add(key)
            except requests.HTTPError as exc:
                # 409 Conflict → already exists (race condition)
                if exc.response.status_code == 409:
                    log.info("  SKIP (conflict/already assigned): %s", role_name)
                    result.skipped_existing += 1
                else:
                    err = f"Failed to assign directory role {role_name}: {exc.response.text}"
                    log.error(err)
                    result.errors.append(err)
        else:
            result.copied += 1

    return result


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="azure_copy_permissions",
        description=(
            "Copy Azure permissions from one user to another.\n\n"
            "Covers four categories:\n"
            "  rbac      — Azure RBAC role assignments (sub/RG/resource scopes)\n"
            "  groups    — Azure AD / Microsoft 365 group memberships\n"
            "  approles  — Enterprise application role assignments\n"
            "  dirroles  — Entra ID directory roles (Global Admin, User Admin, etc.)\n\n"
            "Authentication uses DefaultAzureCredential (env vars → Managed Identity\n"
            "→ Azure CLI → Azure Developer CLI). Use --interactive to force browser login.\n\n"
            "Required permissions for the running identity:\n"
            "  Microsoft Graph : User.Read.All, GroupMember.ReadWrite.All,\n"
            "                    AppRoleAssignment.ReadWrite.All,\n"
            "                    RoleManagement.ReadWrite.Directory\n"
            "  ARM             : Owner or User Access Administrator on target scope(s)\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s alice@contoso.com bob@contoso.com\n"
            "  %(prog)s alice@contoso.com bob@contoso.com --dry-run\n"
            "  %(prog)s alice@contoso.com bob@contoso.com --scope rbac groups\n"
            "  %(prog)s alice@contoso.com bob@contoso.com --scope dirroles\n"
            "  %(prog)s alice@contoso.com bob@contoso.com --subscriptions sub-id-1 sub-id-2\n"
            "  %(prog)s alice@contoso.com bob@contoso.com --debug --output json\n"
        ),
    )

    # -- Positional / required -----------------------------------------------
    parser.add_argument(
        "from_user",
        metavar="FROM_USER",
        help="Source user: UPN (user@domain.com) or Azure AD Object ID.",
    )
    parser.add_argument(
        "to_user",
        metavar="TO_USER",
        help="Target user: UPN (user@domain.com) or Azure AD Object ID.",
    )

    # -- Scope ---------------------------------------------------------------
    parser.add_argument(
        "--scope",
        nargs="+",
        choices=["rbac", "groups", "approles", "dirroles"],
        default=["rbac", "groups", "approles", "dirroles"],
        metavar="CATEGORY",
        help=(
            "Permission categories to copy. One or more of: rbac, groups, approles, dirroles. "
            "Default: all four. "
            "'dirroles' covers Entra ID tenant-level roles (e.g. Global Admin). "
            "Example: --scope rbac groups"
        ),
    )

    # -- RBAC options --------------------------------------------------------
    parser.add_argument(
        "--subscriptions",
        nargs="+",
        metavar="SUB_ID",
        default=None,
        help=(
            "Limit RBAC scan to these subscription IDs. "
            "Default: all subscriptions accessible to the running credential."
        ),
    )

    # -- Behaviour -----------------------------------------------------------
    parser.add_argument(
        "--dry-run", "-n",
        action="store_true",
        help="Preview changes without making any modifications.",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Force interactive browser login instead of DefaultAzureCredential.",
    )

    # -- Output / logging ----------------------------------------------------
    parser.add_argument(
        "--debug", "-D",
        action="store_true",
        help="Enable verbose debug logging.",
    )
    parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format for the final summary. Default: text.",
    )

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    _configure_logging(args.debug)

    if args.dry_run:
        log.info("*** DRY-RUN mode — no changes will be made ***")

    # -- Authentication ------------------------------------------------------
    log.info("Authenticating…")
    try:
        credential = (
            InteractiveBrowserCredential() if args.interactive
            else DefaultAzureCredential()
        )
        token_provider = TokenProvider(credential)
        # Warm up Graph token to catch auth errors early
        token_provider.get(GRAPH_SCOPE)
    except Exception as exc:
        log.error("Authentication failed: %s", exc)
        log.error("Try `az login` or set AZURE_CLIENT_ID / AZURE_CLIENT_SECRET / AZURE_TENANT_ID.")
        return 1

    # -- Resolve users -------------------------------------------------------
    log.info("Resolving users…")
    try:
        from_user = resolve_user(token_provider, args.from_user)
        to_user   = resolve_user(token_provider, args.to_user)
    except Exception as exc:
        log.error("Failed to resolve user: %s", exc)
        return 1

    from_id = from_user["id"]
    to_id   = to_user["id"]

    log.info("FROM: %s (%s)", from_user["displayName"], from_id)
    log.info("TO:   %s (%s)", to_user["displayName"],   to_id)

    if from_id == to_id:
        log.error("FROM and TO users are the same object — nothing to do.")
        return 1

    results: list[CopyResult] = []

    # -- 1. RBAC -------------------------------------------------------------
    if "rbac" in args.scope:
        log.info("─── RBAC Role Assignments ───")
        try:
            # Warm up ARM token
            token_provider.get(ARM_SCOPE)
            sub_client = SubscriptionClient(credential)

            sub_ids = args.subscriptions or _list_subscriptions(sub_client)
            if not sub_ids:
                log.warning("No subscriptions found; skipping RBAC.")
            else:
                assignments = get_rbac_assignments(token_provider, from_id, sub_ids)
                r = copy_rbac_assignments(token_provider, from_id, to_id, assignments, args.dry_run)
                results.append(r)
                log.info(r.summary())
        except Exception as exc:
            log.error("RBAC processing failed: %s", exc, exc_info=args.debug)
            results.append(CopyResult(category="RBAC", errors=[str(exc)]))

    # -- 2. Group memberships ------------------------------------------------
    if "groups" in args.scope:
        log.info("─── Group Memberships ───")
        try:
            groups = get_group_memberships(token_provider, from_id)
            r = copy_group_memberships(token_provider, from_id, to_id, groups, args.dry_run)
            results.append(r)
            log.info(r.summary())
        except Exception as exc:
            log.error("Group processing failed: %s", exc, exc_info=args.debug)
            results.append(CopyResult(category="Groups", errors=[str(exc)]))

    # -- 3. App role assignments ---------------------------------------------
    if "approles" in args.scope:
        log.info("─── App Role Assignments ───")
        try:
            app_roles = get_app_role_assignments(token_provider, from_id)
            r = copy_app_role_assignments(token_provider, from_id, to_id, app_roles, args.dry_run)
            results.append(r)
            log.info(r.summary())
        except Exception as exc:
            log.error("App role processing failed: %s", exc, exc_info=args.debug)
            results.append(CopyResult(category="AppRoles", errors=[str(exc)]))

    # -- 4. Entra ID directory role assignments ------------------------------
    if "dirroles" in args.scope:
        log.info("─── Entra ID Directory Role Assignments ───")
        try:
            dir_roles = get_directory_role_assignments(token_provider, from_id)
            r = copy_directory_role_assignments(token_provider, from_id, to_id, dir_roles, args.dry_run)
            results.append(r)
            log.info(r.summary())
        except Exception as exc:
            log.error("Directory role processing failed: %s", exc, exc_info=args.debug)
            results.append(CopyResult(category="DirectoryRoles", errors=[str(exc)]))

    # -- Summary -------------------------------------------------------------
    log.info("═══════════════════════ SUMMARY ═══════════════════════")
    if args.output == "json":
        summary = {
            "from": {"id": from_id, "displayName": from_user["displayName"]},
            "to":   {"id": to_id,   "displayName": to_user["displayName"]},
            "dry_run": args.dry_run,
            "results": [asdict(r) for r in results],
        }
        print(json.dumps(summary, indent=2))
    else:
        for r in results:
            print(r.summary())

    total_errors = sum(len(r.errors) for r in results)
    if total_errors:
        log.warning("%d error(s) occurred — review output above.", total_errors)
        return 2

    log.info("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
