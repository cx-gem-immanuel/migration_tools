import argparse
import configparser
import json
import os
import socket
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter

from cxsupport import CxOneClient


PAGE_SIZE = 1000
MAX_PAGES = 1000        # per window, a guard against an endpoint that ignores offset
MAX_ATTEMPTS = 5
TIMEOUT = (10, 120)     # connect, read (seconds)
RETRY_STATUS = {429, 500, 502, 503, 504}


class ApiError(Exception):
    """A non-retryable HTTP failure from CxOne."""


def fail(message):
    print(f"ERROR: {message}")
    sys.exit(1)


def describe_error(e):
    """One line explanation of a failed HTTP request, without the traceback."""
    host = urlparse(e.request.url).netloc if getattr(e, "request", None) is not None else None
    where = f" ({host})" if host else ""

    chain, cause = [], e
    while cause is not None and cause not in chain:
        chain.append(cause)
        cause = cause.__cause__ or cause.__context__

    if any(isinstance(c, socket.gaierror) for c in chain):
        return f"Cannot resolve host name{where}. Check the host values in the config file."
    if isinstance(e, requests.exceptions.SSLError):
        return f"TLS certificate verification failed{where}. Use --insecure to skip verification."
    if isinstance(e, requests.exceptions.Timeout):
        return f"Request{where} timed out."
    if isinstance(e, requests.exceptions.ConnectionError):
        return f"Cannot connect{where}. Check the host values and your network."
    return f"Request{where} failed: {e}"


class Api:
    """
    Shared HTTP access for all worker threads: one pooled session (connections and
    TLS handshakes are reused), one token that is refreshed on 401, and retries with
    backoff on 429/5xx and transient connection errors.
    """

    def __init__(self, client, workers):
        self.client = client
        self.session = requests.Session()
        adapter = HTTPAdapter(pool_connections=workers, pool_maxsize=workers)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self._lock = threading.Lock()
        self._generation = 0

    def _token(self, stale_generation=None):
        with self._lock:
            # Another thread already refreshed since this caller saw a 401.
            if stale_generation is not None and stale_generation != self._generation:
                return self.client.bearer_token, self._generation
            if stale_generation is not None:
                self.client.bearer_token = None
                self._generation += 1
            token = self.client.get_bearer_token()
            if not token:
                raise ApiError("Could not obtain an access token. "
                               "Check iam_host, tenant and api_key in the config file.")
            return token, self._generation

    def get(self, url, params=None, accept="application/json; version=1.0"):
        token, generation = self._token()
        refreshed = False

        for attempt in range(MAX_ATTEMPTS):
            try:
                response = self.session.get(
                    url,
                    headers={"Authorization": f"Bearer {token}", "Accept": accept},
                    params=params,
                    verify=self.client.verify,
                    timeout=TIMEOUT,
                )
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                if attempt == MAX_ATTEMPTS - 1:
                    raise
                time.sleep(min(2 ** attempt, 30))
                continue

            if response.status_code == 401 and not refreshed:
                token, generation = self._token(stale_generation=generation)
                refreshed = True
                continue

            if response.status_code in RETRY_STATUS and attempt < MAX_ATTEMPTS - 1:
                try:
                    delay = float(response.headers.get("Retry-After", ""))
                except ValueError:
                    delay = 2 ** attempt
                time.sleep(min(delay, 60))
                continue

            return response

        return response


def build_windows(date_from, date_to, hours):
    """
    Split [date_from 00:00, date_to + 1 day) into windows of `hours` hours, in UTC.
    Each window is (start, end) with end one microsecond before the next start, so
    windows neither overlap nor leave gaps whether the endpoint treats endDate as
    inclusive or exclusive.
    """
    try:
        start = datetime.strptime(date_from, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        stop = datetime.strptime(date_to, "%Y-%m-%d").replace(tzinfo=timezone.utc) + timedelta(days=1)
    except ValueError:
        fail("Dates must be in YYYY-MM-DD format.")
    if start >= stop:
        fail("--from must not be after --to.")

    step = timedelta(hours=hours)
    windows = []
    current = start
    while current < stop:
        following = min(current + step, stop)
        windows.append((current, following - timedelta(microseconds=1)))
        current = following
    return windows


def _rfc3339(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def fetch_window(api, window, args):
    """
    GET /api/audit-events for one window, paged by offset. Every page is filtered
    as it arrives, so only matching events are kept.

    Returns (events fetched, matching events sorted by eventDate). The offset
    advances by the number of events actually returned, so a server that caps the
    page size below the requested limit is handled.
    """
    start, end = window
    url = f"{api.client.ast_host}/api/audit-events"

    fetched = 0
    kept = []
    offset = 0
    total = None

    for _ in range(MAX_PAGES):
        params = {
            "offset": offset,
            "limit": args.page_size,
            "startDate": _rfc3339(start),
            "endDate": _rfc3339(end),
        }
        response = api.get(url, params=params)
        if response.status_code != 200:
            raise ApiError(f"audit-events request failed: {response.status_code} - {response.text}")

        payload = response.json() or {}
        page = payload.get("events") or []
        if total is None:
            total = payload.get("filteredTotalCount")

        fetched += len(page)
        kept.extend(e for e in page if matches(e, args))

        if not page:
            break
        offset += len(page)
        if total is not None and offset >= total:
            break
    else:
        raise ApiError(f"Window {start:%Y-%m-%d %H:%M} has more than "
                       f"{MAX_PAGES * args.page_size} events; use a smaller --window-hours.")

    kept.sort(key=lambda e: str(e.get("eventDate", "")))
    return fetched, kept


def run_windows(windows, fetch, workers):
    """
    Fetch windows concurrently and yield (window, result) in window order. Only a
    bounded number of windows are in flight, so memory stays proportional to the
    matches of those windows, not to the whole range.
    """
    with ThreadPoolExecutor(max_workers=workers) as pool:
        remaining = iter(windows)
        pending = deque()

        def submit_next():
            window = next(remaining, None)
            if window is not None:
                pending.append((window, pool.submit(fetch, window)))

        for _ in range(workers * 2):
            submit_next()

        try:
            while pending:
                window, future = pending.popleft()
                result = future.result()
                submit_next()
                yield window, result
        finally:
            for _, future in pending:
                future.cancel()


class UserLookup:
    """
    GET {iam_host}/auth/admin/realms/{tenant}/users/{user-id}, once per distinct id.
    Ids that cannot be resolved (deleted users, service accounts, no permission)
    are remembered and return an empty user.
    """

    def __init__(self, api, verbose=False):
        self.api = api
        self.verbose = verbose
        self.cache = {}

    def get(self, user_id):
        if not user_id:
            return {}
        if user_id not in self.cache:
            client = self.api.client
            url = f"{client.iam_host}/auth/admin/realms/{client.tenant}/users/{user_id}"
            response = self.api.get(url, accept="application/json")
            if response.status_code == 200:
                self.cache[user_id] = response.json() or {}
            else:
                if self.verbose:
                    print(f"  user {user_id}: {response.status_code} - {response.text}")
                self.cache[user_id] = None
        return self.cache[user_id] or {}

    @property
    def resolved(self):
        return sum(1 for u in self.cache.values() if u is not None)


def build_audit_record(event, user, tenant):
    """Flatten an audit event into an output record enriched with user metadata."""
    data = event.get("data") or {}
    return {
        "tenant": tenant,
        "eventDate": event.get("eventDate"),
        "actionType": event.get("actionType"),
        "roleId": data.get("roleId"),
        "roleName": data.get("name") if data.get("roleId") else None,
        "actionUserId": event.get("actionUserId"),
        "actionUser": user.get("email"),
        "actionUserFirstName": user.get("firstName"),
        "actionUserLastName": user.get("lastName"),
        "ipAddress": event.get("ipAddress"),
    }


class JsonArrayWriter:
    """
    Writes a JSON array one record at a time, formatted like json.dump(indent=2).
    Output goes to <path>.part and is moved into place on commit, so a failed run
    never leaves a truncated file.
    """

    def __init__(self, path):
        self.path = path
        self.tmp = path + ".part"
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.file = open(self.tmp, "w", encoding="utf-8")
        self.count = 0

    def write(self, record):
        text = json.dumps(record, indent=2, ensure_ascii=False)
        self.file.write(("[\n" if self.count == 0 else ",\n") + "  " + text.replace("\n", "\n  "))
        self.count += 1

    def commit(self):
        """Finish the file. Returns False, writing nothing, if there were no records."""
        if self.count == 0:
            self.abort()
            return False
        self.file.write("\n]\n")
        self.file.close()
        os.replace(self.tmp, self.path)
        return True

    def abort(self):
        self.file.close()
        try:
            os.remove(self.tmp)
        except OSError:
            pass


def matches(event, args):
    """Apply the client side filters that the endpoint does not support."""
    if args.action and args.action.lower() != str(event.get("actionType", "")).lower():
        return False
    if args.resource and args.resource.lower() != str(event.get("auditResource", "")).lower():
        return False
    if args.change_types:
        change_type = (event.get("data") or {}).get("changeType")
        if change_type is None or str(change_type).lower() not in args.change_types:
            return False
    if args.user and args.user.lower() not in str(event.get("actionUserId", "")).lower():
        return False
    if args.ip and args.ip not in str(event.get("ipAddress", "")):
        return False
    if args.search and args.search.lower() not in json.dumps(event, default=str).lower():
        return False
    return True


def main():
    parser = argparse.ArgumentParser(description="CxOne Audit Trail Inspector")

    parser.add_argument(
        "--config", "-c",
        type=str,
        help="Path to the configuration file to read",
        required=True,
    )

    parser.add_argument(
        "--days", "-d",
        type=int,
        help="Look back this many days from now. Ignored when --from is given.",
        default=7,
    )

    parser.add_argument(
        "--from", "-f",
        dest="date_from",
        type=str,
        help="Start date, YYYY-MM-DD. Cannot be more than 365 days in the past.",
        default=None,
    )

    parser.add_argument(
        "--to", "-t",
        dest="date_to",
        type=str,
        help="End date, YYYY-MM-DD. Defaults to today.",
        default=None,
    )

    parser.add_argument(
        "--action",
        type=str,
        help="Filter on action type, for example create, update, delete "
             "(exact match, case-insensitive). Default: all actions",
        default=None,
    )

    parser.add_argument(
        "--resource",
        type=str,
        help="Filter on audited resource (exact match, case-insensitive). "
             "Default: all resources",
        default=None,
    )

    parser.add_argument(
        "--change-type",
        dest="change_type",
        type=str,
        help="Comma separated list of data.changeType values to keep, for example "
             "\"state,severity\" (exact match, case-insensitive). Events without a "
             "changeType in their data are excluded. Default: no filtering",
        default=None,
    )

    parser.add_argument(
        "--user", "-u",
        type=str,
        help="Filter on the acting user id (substring match)",
        default=None,
    )

    parser.add_argument(
        "--ip",
        type=str,
        help="Filter on source IP address",
        default=None,
    )

    parser.add_argument(
        "--search", "-s",
        type=str,
        help="Free text match across the whole event, including the data payload",
        default=None,
    )

    parser.add_argument(
        "--out-raw",
        action="store_true",
        help="Write the audit events exactly as returned by the API (after the "
             "filters) instead of the user-enriched records. Skips the user "
             "lookups. Default file name is audit_raw_<from>_<to>.json",
    )

    parser.add_argument(
        "--out",
        type=str,
        help="Where to write the JSON. A directory (existing, or ending in a "
             "path separator) gets audit_<from>_<to>.json inside it; otherwise "
             "the value is used as the file path. Defaults to the current directory.",
        default=None,
    )

    parser.add_argument(
        "--tenant-id",
        type=str,
        help="CxOne tenant if different from CXONE.tenant in config",
        required=False,
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Number of date windows fetched concurrently (default 4). Lower it if "
             "the API answers 429 (too many requests).",
    )

    parser.add_argument(
        "--window-hours",
        type=int,
        default=24,
        help="Size of each date window in hours (default 24). Use a smaller value "
             "for tenants with very many events per day.",
    )

    parser.add_argument(
        "--page-size",
        type=int,
        default=PAGE_SIZE,
        help="Page size for the audit events endpoint (max 1000)",
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print per-window detail",
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

    if args.workers < 1 or args.window_hours < 1 or args.page_size < 1:
        fail("--workers, --window-hours and --page-size must be at least 1.")
    args.page_size = min(args.page_size, 1000)

    args.change_types = None
    if args.change_type is not None:
        args.change_types = {v.strip().lower() for v in args.change_type.split(",") if v.strip()}
        if not args.change_types:
            fail("--change-type needs at least one value, for example \"state,severity\".")

    config = configparser.ConfigParser()
    if not config.read(args.config):
        fail(f"Cannot read configuration file '{args.config}'.")
    if "CXONE" not in config:
        fail(f"Configuration file '{args.config}' has no [CXONE] section.")

    cxone = config["CXONE"]
    required = ["iam_host", "ast_host", "api_key"] + ([] if args.tenant_id else ["tenant"])
    missing = [k for k in required if not cxone.get(k)]
    if missing:
        fail(f"[CXONE] in '{args.config}' is missing: {', '.join(missing)}.")

    iam_host = cxone["iam_host"]
    ast_host = cxone["ast_host"]
    tenant   = args.tenant_id if args.tenant_id else cxone["tenant"]
    api_key  = cxone["api_key"]

    unset = [k for k, v in (("iam_host", iam_host), ("ast_host", ast_host),
                            ("tenant", tenant), ("api_key", api_key)) if "<YOUR_" in v]
    if unset:
        fail(f"'{args.config}' still has template placeholders for: {', '.join(unset)}. "
             "Fill in the [CXONE] values first.")

    now = datetime.now(timezone.utc)
    date_to = args.date_to or now.strftime("%Y-%m-%d")
    date_from = args.date_from or (now - timedelta(days=args.days)).strftime("%Y-%m-%d")
    windows = build_windows(date_from, date_to, args.window_hours)

    default_name = f"audit_{'raw_' if args.out_raw else ''}{date_from}_{date_to}.json"
    if not args.out:
        json_file = default_name
    elif os.path.isdir(args.out) or args.out.endswith(("/", "\\")):
        json_file = os.path.join(args.out, default_name)
    else:
        json_file = args.out

    print("-------------------------------------------------------------")
    print("CxOne Audit Trail Inspector (read-only)")
    print(f"AST Host  : {ast_host}")
    print(f"IAM Host  : {iam_host}")
    print(f"Tenant    : {tenant}")
    print(f"Range     : {date_from} to {date_to}")
    print(f"Windows   : {len(windows)} x {args.window_hours}h, {args.workers} concurrent")
    print("-------------------------------------------------------------")

    started = time.monotonic()
    writer = None
    try:
        print("Connecting...")
        cxone_client = CxOneClient(
            iam_host, ast_host, tenant, api_key, False, verify=not args.insecure
        )
        api = Api(cxone_client, args.workers)
        users = None if args.out_raw else UserLookup(api, verbose=args.verbose)

        print("Fetching audit events...")
        writer = JsonArrayWriter(json_file)
        fetched = 0

        for number, (window, (window_fetched, kept)) in enumerate(
                run_windows(windows, lambda w: fetch_window(api, w, args), args.workers), 1):
            fetched += window_fetched
            for event in kept:
                writer.write(event if args.out_raw
                             else build_audit_record(event, users.get(event.get("actionUserId")), tenant))
            if args.verbose:
                print(f"  window {number}/{len(windows)} {window[0]:%Y-%m-%d %H:%M}: "
                      f"fetched {window_fetched}, matched {len(kept)}")

        matched = writer.count
        wrote = writer.commit()
        writer = None
    except requests.exceptions.RequestException as e:
        if writer:
            writer.abort()
        fail(describe_error(e))
    except ApiError as e:
        if writer:
            writer.abort()
        fail(str(e))
    except BaseException:
        if writer:
            writer.abort()
        raise

    elapsed = time.monotonic() - started
    print(f"Fetched {fetched} events, {matched} matched ({elapsed:.1f}s).")
    if not wrote:
        print("No audit events found for the specified scope.")
        return

    if users is not None:
        print(f"Users resolved: {users.resolved} of {len(users.cache)} "
              f"({len(users.cache) - users.resolved} not found; use --verbose for detail)")
    print(f"JSON written to {json_file}")


if __name__ == "__main__":
    main()
