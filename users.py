import argparse
import configparser
import csv
import json
import re
from concurrent.futures import ThreadPoolExecutor

import requests

from cxsupport import CxOneClient


PAGE_SIZE = 100
MAX_PAGES = 1000


def _headers(client):
    token = client.get_bearer_token()
    if not token:
        return None
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }


def get_user_count(client, search=None, enabled=None):
    """GET /{realm}/users/count so paging can be validated against a total."""
    headers = _headers(client)
    if headers is None:
        return None

    url = f"{client.iam_host}/auth/admin/realms/{client.tenant}/users/count"
    params = {}
    if search:
        params["search"] = search
    if enabled is not None:
        params["enabled"] = str(enabled).lower()

    response = requests.get(url, headers=headers, params=params, verify=client.verify)
    if response.status_code != 200:
        return None
    try:
        return int(response.json())
    except (ValueError, TypeError):
        return None


def get_users(client, idp_alias=None, idp_user_id=None, search=None,
              enabled=None, brief=True, page_size=PAGE_SIZE, verbose=False):
    """
    GET /{realm}/users (Keycloak Admin API) with paging.

    Realm == CxOne tenant. Keycloak applies first/max at the storage layer and
    filters afterwards, so a page can come back shorter than max while more
    users still exist. Paging therefore continues until a page is empty rather
    than stopping at the first short page, and results are de-duplicated by id.
    """
    headers = _headers(client)
    if headers is None:
        return None

    url = f"{client.iam_host}/auth/admin/realms/{client.tenant}/users"

    users = []
    seen = set()
    first = 0
    pages = 0

    while pages < MAX_PAGES:
        params = {
            "first": first,
            "max": page_size,
            "briefRepresentation": str(brief).lower(),
        }
        if idp_alias:
            params["idpAlias"] = idp_alias
        if idp_user_id:
            params["idpUserId"] = idp_user_id
        if search:
            params["search"] = search
        if enabled is not None:
            params["enabled"] = str(enabled).lower()

        response = requests.get(url, headers=headers, params=params, verify=client.verify)
        if response.status_code != 200:
            print(f"ERROR: {response.status_code} - {response.text}")
            return None

        page = response.json()
        pages += 1

        if not page:
            break

        for u in page:
            uid = u.get("id")
            if uid and uid in seen:
                continue
            if uid:
                seen.add(uid)
            users.append(u)

        if verbose:
            print(f"  page {pages}: offset {first}, returned {len(page)}, total so far {len(users)}")

        first += page_size

    return users


def get_federated_identities(client, user_id):
    """GET /{realm}/users/{id}/federated-identity for one user."""
    headers = _headers(client)
    if headers is None:
        return []

    url = f"{client.iam_host}/auth/admin/realms/{client.tenant}/users/{user_id}/federated-identity"
    response = requests.get(url, headers=headers, verify=client.verify)
    if response.status_code != 200:
        return []
    return response.json() or []


def resolve_links(client, users, workers=8):
    """
    Map user id to the list of identity provider aliases linked to that user.

    The user list endpoint never returns federatedIdentities, and some Keycloak
    builds ignore idpAlias as a filter, so links are read per user instead.
    """
    ids = [u.get("id") for u in users if u.get("id")]

    def one(uid):
        return uid, [fi.get("identityProvider") for fi in get_federated_identities(client, uid)]

    links = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for uid, aliases in pool.map(one, ids):
            links[uid] = [a for a in aliases if a]
    return links


def get_json(client, path, params=None):
    """GET an arbitrary admin API path under the realm and return parsed JSON."""
    headers = _headers(client)
    if headers is None:
        return None

    url = f"{client.iam_host}/auth/admin/realms/{client.tenant}{path}"
    response = requests.get(url, headers=headers, params=params, verify=client.verify)
    if response.status_code != 200:
        return None
    try:
        return response.json()
    except ValueError:
        return None


def find_user(client, identifier):
    """
    Resolve a user by id, username or email.

    A UUID is tried directly against /users/{id}; anything else goes through an
    exact search on username, then email, then a loose search.
    """
    if re.fullmatch(r"[0-9a-fA-F-]{36}", identifier or ""):
        user = get_json(client, f"/users/{identifier}")
        if isinstance(user, dict) and user.get("id"):
            return user

    for params in (
        {"username": identifier, "exact": "true"},
        {"email": identifier, "exact": "true"},
        {"search": identifier},
    ):
        params["briefRepresentation"] = "false"
        matches = get_json(client, "/users", params=params) or []
        if len(matches) == 1:
            full = get_json(client, f"/users/{matches[0]['id']}")
            return full if isinstance(full, dict) and full.get("id") else matches[0]
        if len(matches) > 1:
            print(f"'{identifier}' matched {len(matches)} users:")
            for m in matches[:20]:
                print(f"  {m.get('id')}  {m.get('username')}  {m.get('email', '')}")
            if len(matches) > 20:
                print(f"  ... and {len(matches) - 20} more")
            print("Re-run with the exact user id.")
            return None

    return None


def get_user_details(client, user):
    """Collect everything the admin API exposes about a single user."""
    uid = user.get("id")

    details = {
        "user": user,
        "federatedIdentities": get_json(client, f"/users/{uid}/federated-identity"),
        "groups": get_json(client, f"/users/{uid}/groups"),
        "roleMappings": get_json(client, f"/users/{uid}/role-mappings"),
        "realmRolesEffective": get_json(client, f"/users/{uid}/role-mappings/realm/composite"),
        "credentialTypes": get_json(client, f"/users/{uid}/credentials"),
        "consents": get_json(client, f"/users/{uid}/consents"),
        "sessions": get_json(client, f"/users/{uid}/sessions"),
        "offlineSessions": get_json(client, f"/users/{uid}/offline-sessions"),
        "unmanagedAttributes": get_json(client, f"/users/{uid}/unmanagedAttributes"),
    }

    return {k: v for k, v in details.items() if v not in (None, [], {})}


def print_user_details(details):
    user = details.get("user", {})

    print("\nUser")
    print("-------------------------------------------------------------")
    for key in ("id", "username", "email", "firstName", "lastName", "enabled",
                "emailVerified", "createdTimestamp", "requiredActions"):
        if key in user:
            print(f"{key:20}: {user[key]}")

    for attr, value in (user.get("attributes") or {}).items():
        print(f"{('attr.' + attr):20}: {value}")

    for fi in details.get("federatedIdentities", []):
        print(f"{'idp':20}: {fi.get('identityProvider')} "
              f"(userId={fi.get('userId')}, userName={fi.get('userName')})")

    for g in details.get("groups", []):
        print(f"{'group':20}: {g.get('path') or g.get('name')}")

    role_mappings = details.get("roleMappings") or {}
    if not isinstance(role_mappings, dict):
        role_mappings = {}
    realm_roles = (role_mappings.get("realmMappings") or [])
    for r in realm_roles:
        print(f"{'realm role':20}: {r.get('name')}")

    for client_key, mapping in (role_mappings.get("clientMappings") or {}).items():
        for r in mapping.get("mappings", []):
            print(f"{'client role':20}: {client_key} / {r.get('name')}")

    print(f"{'active sessions':20}: {len(details.get('sessions', []))}")
    print(f"{'offline sessions':20}: {len(details.get('offlineSessions', []))}")


OTP_HINTS = ("otp", "totp")


def _is_otp_execution(execution):
    fields = " ".join(
        str(execution.get(k, "")).lower()
        for k in ("providerId", "displayName", "alias")
    )
    return any(h in fields for h in OTP_HINTS)


def inspect_flow(client, alias, seen=None):
    """
    Return OTP-related executions found in a flow, following subflows.

    /authentication/flows/{alias}/executions already returns the flattened
    tree, so nested subflows come back in the same call; seen only guards
    against a flow being inspected twice.
    """
    seen = seen if seen is not None else set()
    if not alias or alias in seen:
        return []
    seen.add(alias)

    executions = get_json(client, f"/authentication/flows/{requests.utils.quote(alias)}/executions") or []
    findings = []
    for i, e in enumerate(executions):
        if not _is_otp_execution(e):
            continue

        # An OTP step preceded by a "user configured" condition at the same or
        # an outer level only fires for users that already have OTP set up, so
        # it does not force enrollment.
        level = e.get("level") or 0
        guarded = any(
            "conditional" in str(prev.get("providerId", "")).lower()
            and (prev.get("level") or 0) <= level
            for prev in executions[:i]
        )

        findings.append({
            "flow": alias,
            "execution": e.get("displayName") or e.get("providerId"),
            "providerId": e.get("providerId"),
            "requirement": e.get("requirement"),
            "level": level,
            "guarded": guarded,
        })
    return findings


def diagnose_mfa(client, idp_alias=None, user=None):
    """
    Work out where a forced OTP enrollment is coming from.

    Checks, in order: the user record itself, the CONFIGURE_TOTP required
    action, the realm browser flow, and the identity provider broker flows.
    """
    print("\nMFA diagnosis")
    print("-------------------------------------------------------------")

    causes = []

    # 1. The user record
    if user:
        uid = user.get("id")
        required = user.get("requiredActions") or []
        creds = get_json(client, f"/users/{uid}/credentials") or []
        cred_types = [c.get("type") for c in creds]
        print(f"User                  : {user.get('username')}")
        print(f"  requiredActions     : {required or '(none)'}")
        print(f"  credentials         : {cred_types or '(none)'}")
        print(f"  totp flag           : {user.get('totp')}")
        if any("CONFIGURE_TOTP" in str(a).upper() for a in required):
            causes.append("CONFIGURE_TOTP is stored on the user record itself.")
        if not any(t and "otp" in t.lower() for t in cred_types):
            print("  note                : no OTP credential yet, so any OTP step "
                  "in the flow will force enrollment.")

    # 2. Required actions registered on the realm
    actions = get_json(client, "/authentication/required-actions") or []
    otp_actions = [a for a in actions if any(h in str(a.get("alias", "")).lower() or
                                             h in str(a.get("providerId", "")).lower()
                                             for h in OTP_HINTS)]
    print("\nRealm required actions")
    for a in otp_actions:
        print(f"  {a.get('alias'):22} enabled={a.get('enabled')} defaultAction={a.get('defaultAction')}")
        if a.get("enabled") and a.get("defaultAction"):
            causes.append(
                f"Required action '{a.get('alias')}' is a default action, so it is "
                "applied to every new user at first login."
            )
    if not otp_actions:
        print("  (no OTP required actions returned)")

    # 3. Realm authentication flows
    realm = get_json(client, "") or {}
    realm_flows = {
        "browserFlow": realm.get("browserFlow"),
        "directGrantFlow": realm.get("directGrantFlow"),
        "resetCredentialsFlow": realm.get("resetCredentialsFlow"),
    }

    print("\nFlow executions containing OTP")
    seen = set()
    findings = []
    for label, alias in realm_flows.items():
        if not alias:
            continue
        for f in inspect_flow(client, alias, seen):
            f["source"] = label
            findings.append(f)

    # 4. Identity provider broker flows
    providers = get_json(client, "/identity-provider/instances") or []
    if idp_alias:
        providers = [p for p in providers if p.get("alias") == idp_alias] or providers

    for p in providers:
        config = p.get("config") or {}
        for key in ("firstBrokerLoginFlowAlias", "postBrokerLoginFlowAlias"):
            alias = p.get(key) or config.get(key)
            if not alias:
                continue
            for f in inspect_flow(client, alias, seen):
                f["source"] = f"{p.get('alias')}.{key}"
                findings.append(f)

    if findings:
        for f in findings:
            guard = "conditional" if f["guarded"] else "unconditional"
            print(f"  {f['source']:34} | {f['flow']:28} | "
                  f"{str(f['execution']):28} | {f['requirement']:9} | {guard}")
            if (str(f["requirement"]).upper() == "REQUIRED"
                    and not f["guarded"]
                    and "conditional" not in str(f["providerId"]).lower()):
                causes.append(
                    f"{f['execution']} is REQUIRED in flow '{f['flow']}' ({f['source']}), "
                    "so users without an OTP credential are forced to enroll."
                )
    else:
        print("  (no OTP executions found in the inspected flows)")

    print("\nConclusion")
    print("-------------------------------------------------------------")
    if causes:
        for c in dict.fromkeys(causes):
            print(f"  - {c}")
        print("\n  Nothing in the user creation payload can override these. The totp")
        print("  field is read-only and requiredActions=[] only clears user-level")
        print("  actions at creation time.")
    else:
        print("  No forced OTP source found in the required actions or the inspected")
        print("  flows. Check tenant level MFA settings in the CxOne UI, and confirm")
        print("  the account is actually using the broker flow rather than a local login.")


def main():
    parser = argparse.ArgumentParser(description="CxOne Users Inspector (Keycloak Admin API)")

    parser.add_argument(
        "--config", "-c",
        type=str,
        help="Path to the configuration file to read",
        required=True,
    )

    parser.add_argument(
        "--idp-alias", "-i",
        type=str,
        help="Identity provider alias to filter on. If omitted, all realm users are returned.",
        required=False,
        default=None,
    )

    parser.add_argument(
        "--idp-user-id",
        type=str,
        help="User ID at the identity provider (used together with --idp-alias)",
        required=False,
        default=None,
    )

    parser.add_argument(
        "--search", "-s",
        type=str,
        help="Free text search across username, first name, last name and email",
        required=False,
        default=None,
    )

    parser.add_argument(
        "--enabled",
        type=str,
        help="Filter on enabled state",
        choices=["true", "false"],
        required=False,
        default=None,
    )

    parser.add_argument(
        "--tenant-id", "-t",
        type=str,
        help="CxOne tenant (Keycloak realm) if different from CXONE.tenant in config",
        required=False,
    )

    parser.add_argument(
        "--full",
        action="store_true",
        help="Request full user representations instead of the brief form",
    )

    parser.add_argument(
        "--user", "-u",
        type=str,
        help="Show every available detail for a single user (id, username or email)",
        required=False,
        default=None,
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="With --user, print the raw JSON instead of the formatted summary",
    )

    parser.add_argument(
        "--out",
        type=str,
        help="With --user, also write the full JSON to this file",
        required=False,
        default=None,
    )

    parser.add_argument(
        "--diagnose-mfa",
        action="store_true",
        help="Report where a forced OTP/TOTP enrollment originates. Combine with --user and/or --idp-alias.",
    )

    parser.add_argument(
        "--resolve-links",
        action="store_true",
        help="Read federated identity links per user (slower, but authoritative)",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=8,
        help="Parallel requests used when resolving federated identity links",
    )

    parser.add_argument(
        "--page-size",
        type=int,
        default=PAGE_SIZE,
        help="Page size for the users endpoint",
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print per-page paging detail",
    )

    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification",
    )

    args = parser.parse_args()

    if not args.config or not args.config.strip():
        print("ERROR: Configuration file path is required.")
        exit(1)

    config = configparser.ConfigParser()
    config.read(args.config)

    iam_host = config["CXONE"]["iam_host"]
    ast_host = config["CXONE"]["ast_host"]
    tenant   = args.tenant_id if args.tenant_id else config["CXONE"]["tenant"]
    api_key  = config["CXONE"]["api_key"]

    csv_file = f"users_{args.idp_alias or 'all'}.csv"

    print("-------------------------------------------------------------")
    print("CxOne Users Inspector (read-only)")
    print(f"IAM Host  : {iam_host}")
    print(f"Tenant    : {tenant}")
    print(f"IdP Alias : {args.idp_alias or '(none, all users)'}")
    print(f"Search    : {args.search or '(none)'}")
    print("-------------------------------------------------------------")

    print("Connecting...")
    cxone_client = CxOneClient(
        iam_host, ast_host, tenant, api_key, False, verify=not args.insecure
    )

    if args.diagnose_mfa:
        target = None
        if args.user:
            print(f"Looking up '{args.user}'...")
            target = find_user(cxone_client, args.user)
            if not target:
                print("ERROR: user not found.")
                exit(1)

        diagnose_mfa(cxone_client, idp_alias=args.idp_alias, user=target)
        return

    if args.user:
        print(f"Looking up '{args.user}'...")
        user = find_user(cxone_client, args.user)
        if not user:
            print("ERROR: user not found.")
            exit(1)

        details = get_user_details(cxone_client, user)

        if args.json:
            print(json.dumps(details, indent=2, ensure_ascii=False))
        else:
            print_user_details(details)

        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(details, f, indent=2, ensure_ascii=False)
            print(f"\nJSON written to {args.out}")

        return

    enabled = None if args.enabled is None else (args.enabled == "true")

    expected = get_user_count(cxone_client, search=args.search, enabled=enabled)
    if expected is not None:
        print(f"Realm reports {expected} users.")

    print("Fetching all users...")
    all_users = get_users(
        cxone_client,
        search=args.search,
        enabled=enabled,
        brief=not args.full,
        page_size=args.page_size,
        verbose=args.verbose,
    )

    if all_users is None:
        print("ERROR: Failed to fetch users; aborting.")
        exit(1)

    if expected is not None and len(all_users) < expected:
        print(f"WARNING: fetched {len(all_users)} of {expected} users reported by the realm.")

    idp_ids = set()
    links = {}

    if args.idp_alias:
        print(f"Fetching users linked to identity provider '{args.idp_alias}'...")
        idp_users = get_users(
            cxone_client,
            idp_alias=args.idp_alias,
            idp_user_id=args.idp_user_id,
            search=args.search,
            enabled=enabled,
            brief=not args.full,
            page_size=args.page_size,
            verbose=args.verbose,
        )

        if idp_users is None:
            print("ERROR: Failed to fetch identity provider users; aborting.")
            exit(1)

        idp_ids = {u.get("id") for u in idp_users if u.get("id")}
        print(f"idpAlias filter returned {len(idp_ids)} users.")

        # Some Keycloak builds ignore idpAlias on the list endpoint and just
        # return the unfiltered realm. Fall back to per-user link lookups when
        # the filter clearly did not work.
        if not idp_ids or len(idp_ids) == len(all_users) or args.resolve_links:
            print("Resolving federated identity links per user...")
            links = resolve_links(cxone_client, all_users, workers=args.workers)
            idp_ids = {
                uid for uid, aliases in links.items()
                if args.idp_alias in aliases
            }
            print(f"Per-user lookup found {len(idp_ids)} users linked to '{args.idp_alias}'.")

    elif args.resolve_links:
        print("Resolving federated identity links per user...")
        links = resolve_links(cxone_client, all_users, workers=args.workers)
        idp_ids = {uid for uid, aliases in links.items() if aliases}

    if not all_users:
        print("No users found for the specified scope.")
        return

    print(f"Processing {len(all_users)} users...")

    rows = []
    uw = len("Username")
    ew = len("Email")
    nw = len("Name")

    for u in all_users:
        username = u.get("username", "")
        email    = u.get("email", "")
        name     = " ".join(p for p in [u.get("firstName", ""), u.get("lastName", "")] if p)
        enabled_flag = "YES" if u.get("enabled") else "NO"
        linked = "YES" if u.get("id") in idp_ids else "NO"
        aliases = ", ".join(links.get(u.get("id"), []))

        rows.append((username, email, name, enabled_flag, linked, aliases))

        uw = max(uw, len(username) + 2)
        ew = max(ew, len(email)    + 2)
        nw = max(nw, len(name)     + 2)

    # Table. Link data only exists when it has been read per user, so the
    # IdP columns are omitted unless --resolve-links was requested.
    show_idp = args.resolve_links
    aw = len("Enabled")
    idp_header = f"In '{args.idp_alias}'?" if args.idp_alias else "Linked to IdP?"
    iw = len(idp_header)

    header = (
        f"{'Username':{uw}} | {'Email':{ew}} | "
        f"{'Name':{nw}} | {'Enabled':{aw}}"
    )
    if show_idp:
        header += f" | {idp_header:{iw}}"

    sep = "-" * len(header)
    print(f"\nUsers")
    print(sep)
    print(header)
    print(sep)
    for username, email, name, enabled_flag, linked, aliases in rows:
        line = (
            f"{username:{uw}} | {email:{ew}} | "
            f"{name:{nw}} | {enabled_flag:{aw}}"
        )
        if show_idp:
            line += f" | {linked:{iw}}"
        print(line)

    # Summary
    linked_count = sum(1 for r in rows if r[4] == "YES")
    print(sep)
    print(f"Total users           : {len(rows)}")
    if show_idp and args.idp_alias:
        print(f"Linked to IdP         : {linked_count}")
        print(f"Not linked to IdP     : {len(rows) - linked_count}")

    # CSV
    with open(csv_file, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        columns = ["Username", "Email", "Name", "Enabled"]
        if show_idp:
            columns += [idp_header, "IdP aliases"]
        writer.writerow(columns)
        for row in rows:
            writer.writerow(list(row) if show_idp else list(row[:4]))
    print(f"\nCSV written to {csv_file}")


if __name__ == "__main__":
    main()
