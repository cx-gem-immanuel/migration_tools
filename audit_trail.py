import argparse
import configparser
import json
import logging
import os
import platform
import re
import socket
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter

from cxsupport import CxOneClient
from logsupport import setup_logger, add_file_handler


PAGE_SIZE = 1000
MAX_PAGES = 1000        # per window, a guard against an endpoint that ignores offset
MAX_ATTEMPTS = 5
TIMEOUT = (10, 120)     # connect, read (seconds)
RETRY_STATUS = {429, 500, 502, 503, 504}

LOG_NAME = "cx_audit_trail"
BODY_LIMIT = 2000       # characters of a response body written to the log
REDACTED_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie"}

# The detailed log goes to a file only; the console keeps its short messages. The
# null handler stops Python from printing log records to stderr before the file
# handler exists, or when the log file cannot be opened.
logger = setup_logger(name=LOG_NAME, enable_console=False, file_logging=False)
logger.addHandler(logging.NullHandler())

_log_handler = None
LOG_PATH = None


class ApiError(Exception):
    """A non-retryable HTTP failure from CxOne."""


class Cancelled(Exception):
    """Raised in a worker when the run is ending, so it stops without more requests."""


# Set when the run ends, normally or on an error, so windows still in flight stop at
# their next page or retry instead of finishing all their work first.
CANCEL = threading.Event()


def pause(seconds):
    """Sleep, but wake up and stop at once if the run is ending."""
    if CANCEL.wait(seconds):
        raise Cancelled()


def start_log(log_dir):
    """
    Start writing the detailed log to <log_dir>/cx_audit_trail_<timestamp>.log.
    Returns the path, or None (with a warning) if the file cannot be created.
    The shared logger used by cxsupport.py is pointed at the same file, so token
    errors raised there are captured too.
    """
    global _log_handler, LOG_PATH
    stop_log()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = Path(log_dir) / f"cx_audit_trail_{stamp}.log"
    # Two runs started in the same second must not write into the same file.
    for suffix in range(2, 1000):
        if not path.exists():
            break
        path = Path(log_dir) / f"cx_audit_trail_{stamp}_{suffix}.log"
    try:
        add_file_handler(str(path), name=LOG_NAME)
    except OSError as e:
        print(f"WARNING: cannot write the log file '{path}': {e}. Continuing without a log file.")
        return None
    _log_handler = logger.handlers[-1]
    logging.getLogger("cxlogger").addHandler(_log_handler)
    LOG_PATH = path
    return path


def stop_log():
    global _log_handler, LOG_PATH
    if _log_handler is not None:
        logging.getLogger("cxlogger").removeHandler(_log_handler)
        logger.removeHandler(_log_handler)
        _log_handler.close()
    _log_handler = None
    LOG_PATH = None


def fail(message, see_log=False):
    logger.error(message)
    if see_log and LOG_PATH:
        message = f"{message} (details in {LOG_PATH})"
    print(f"ERROR: {message}")
    logger.info("Exiting with status 1")
    sys.exit(1)


def _redacted(headers):
    return {k: ("<redacted>" if k.lower() in REDACTED_HEADERS else v) for k, v in headers.items()}


def _clip(text, limit=BODY_LIMIT):
    text = text or ""
    return text if len(text) <= limit else f"{text[:limit]}... [{len(text) - limit} more characters]"


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
    backoff on 429/5xx and transient connection errors. Every request, response,
    retry and token refresh is written to the log; tokens are never logged.
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
                logger.debug("Token already refreshed by another thread (generation %d)", self._generation)
                return self.client.bearer_token, self._generation
            if stale_generation is not None:
                self.client.bearer_token = None
                self._generation += 1
                logger.warning("Refreshing the access token after a 401 (generation %d -> %d)",
                               stale_generation, self._generation)
            began = time.monotonic()
            token = self.client.get_bearer_token()
            if not token:
                logger.error("Could not obtain an access token from %s (realm %s); see the "
                             "preceding log lines from cxlogger for the response",
                             self.client.iam_host, self.client.tenant)
                raise ApiError("Could not obtain an access token. "
                               "Check iam_host, tenant and api_key in the config file.")
            logger.info("Access token ready (generation %d, %.0f ms, valid until %s)",
                        self._generation, (time.monotonic() - began) * 1000,
                        self.client.token_expiration)
            return token, self._generation

    def get(self, url, params=None, accept="application/json; version=1.0"):
        token, generation = self._token()
        refreshed = False

        for attempt in range(MAX_ATTEMPTS):
            if CANCEL.is_set():
                raise Cancelled()
            number = f"attempt {attempt + 1}/{MAX_ATTEMPTS}"
            logger.debug("GET %s params=%s %s", url, params, number)
            began = time.monotonic()
            try:
                response = self.session.get(
                    url,
                    headers={"Authorization": f"Bearer {token}", "Accept": accept},
                    params=params,
                    verify=self.client.verify,
                    timeout=TIMEOUT,
                )
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                logger.warning("GET %s %s failed after %.2fs: %s: %s", url, number,
                               time.monotonic() - began, type(e).__name__, e)
                if attempt == MAX_ATTEMPTS - 1:
                    logger.error("GET %s gave up after %d attempts", url, MAX_ATTEMPTS)
                    raise
                delay = min(2 ** attempt, 30)
                logger.warning("Retrying in %ss", delay)
                pause(delay)
                continue

            elapsed = (time.monotonic() - began) * 1000
            logger.debug("-> %s %s in %.0f ms, %d bytes (%s) %s", response.status_code,
                         response.reason, elapsed, len(response.content), number, response.url)
            logger.trace("Response headers: %s", _redacted(response.headers))

            if response.status_code == 401 and not refreshed:
                logger.warning("GET %s answered 401: %s", url, _clip(response.text, 500))
                token, generation = self._token(stale_generation=generation)
                refreshed = True
                continue

            if response.status_code in RETRY_STATUS and attempt < MAX_ATTEMPTS - 1:
                try:
                    delay = float(response.headers.get("Retry-After", ""))
                    source = "Retry-After"
                except ValueError:
                    delay = 2 ** attempt
                    source = "backoff"
                delay = min(delay, 60)
                logger.warning("GET %s answered %s %s (%s); body: %s; retrying in %ss (%s)",
                               response.url, response.status_code, response.reason, number,
                               _clip(response.text, 500) or "(empty)", delay, source)
                pause(delay)
                continue

            if response.status_code != 200:
                logger.error("GET %s failed: %s %s after %d attempt(s)\n  response headers: %s\n"
                             "  response body: %s", response.url, response.status_code, response.reason,
                             attempt + 1, _redacted(response.headers), _clip(response.text) or "(empty)")
            return response

        return response


ONE_MICROSECOND = timedelta(microseconds=1)

# YYYY-MM-DD, optionally followed by a time (seconds, fraction and offset optional).
WHEN_PATTERN = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})"
    r"(?:[Tt ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?(Z|z|[+-]\d{2}:\d{2})?)?$"
)


def local_to_utc(naive):
    """Read a datetime without a time zone as this machine's local time, as UTC."""
    return naive.astimezone().astimezone(timezone.utc)


def local_now():
    return datetime.now().astimezone()


def parse_when(text, is_end):
    """
    Parse --from / --to into (UTC datetime, label for file names, read as local time).

    Accepts YYYY-MM-DD or an RFC 3339 timestamp such as 2026-09-14T15:42:37.881290Z
    (seconds and fraction optional). A value with Z or an offset such as -05:00 is
    used as given. A value with no offset, including a bare date, is read as this
    machine's local time. A bare date means the start of that local day for --from
    and the end of that local day for --to. A timestamp is used as given, and --to
    is inclusive.
    """
    match = WHEN_PATTERN.match(text.strip())
    if not match:
        raise ValueError(f"'{text}' is not a date or timestamp. Use YYYY-MM-DD or "
                         "YYYY-MM-DDTHH:MM:SS[.ffffff]Z.")
    year, month, day, hour, minute, second, fraction, offset = match.groups()

    try:
        if hour is None:
            midnight = datetime(int(year), int(month), int(day))
            label = midnight.strftime("%Y-%m-%d")
            if is_end:
                # The next local midnight, converted on its own: days with a daylight
                # saving change are 23 or 25 hours long.
                return local_to_utc(midnight + timedelta(days=1)) - ONE_MICROSECOND, label, True
            return local_to_utc(midnight), label, True

        micros = int((fraction or "0")[:6].ljust(6, "0"))
        naive = datetime(int(year), int(month), int(day), int(hour), int(minute),
                         int(second or 0), micros)
        if offset:
            moment = naive.replace(tzinfo=timezone.utc)
            if offset.upper() != "Z":
                sign = 1 if offset[0] == "+" else -1
                moment -= sign * timedelta(hours=int(offset[1:3]), minutes=int(offset[4:6]))
            used_local = False
        else:
            moment = local_to_utc(naive)
            used_local = True
    except (ValueError, OverflowError, OSError):
        raise ValueError(f"'{text}' is not a valid date or time.")

    label = moment.strftime("%Y-%m-%dT%H%M%S")
    if moment.microsecond:
        label += f".{moment.microsecond:06d}"
    return moment, label + "Z", used_local


def build_windows(start, end, hours):
    """
    Split the inclusive range [start, end] into windows of `hours` hours.
    Each window is (start, end) with end one microsecond before the next start, so
    windows neither overlap nor leave gaps whether the endpoint treats endDate as
    inclusive or exclusive.
    """
    step = timedelta(hours=hours)
    windows = []
    current = start
    while current <= end:
        window_end = min(current + step - ONE_MICROSECOND, end)
        windows.append((current, window_end))
        current = window_end + ONE_MICROSECOND
    return windows


def _rfc3339(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def fetch_window(api, window, args, label="1/1"):
    """
    GET /api/audit-events for one window, paged by offset. Every page is filtered
    as it arrives, so only matching events are kept.

    Returns (events fetched, matching events sorted by eventDate). The offset
    advances by the number of events actually returned, so a server that caps the
    page size below the requested limit is handled.
    """
    start, end = window
    url = f"{api.client.ast_host}/api/audit-events"
    tag = f"[window {label}]"
    began = time.monotonic()
    logger.info("%s start %s to %s", tag, _rfc3339(start), _rfc3339(end))

    fetched = 0
    kept = []
    offset = 0
    total = None
    pages = 0
    cap_noted = False

    for _ in range(MAX_PAGES):
        if CANCEL.is_set():
            raise Cancelled()
        params = {
            "offset": offset,
            "limit": args.page_size,
            "startDate": _rfc3339(start),
            "endDate": _rfc3339(end),
        }
        response = api.get(url, params=params)
        if response.status_code != 200:
            raise ApiError(f"audit-events request failed: {response.status_code} {response.reason} - "
                           f"{_clip(response.text, 500) or '(empty response body)'}")

        payload = response.json() or {}
        page = payload.get("events") or []
        if total is None:
            total = payload.get("filteredTotalCount")
            logger.debug("%s the service reports %s events for this window", tag, total)

        pages += 1
        before = len(kept)
        kept.extend(e for e in page if matches(e, args))
        fetched += len(page)
        logger.debug("%s page %d: offset %d, returned %d, kept %d, running total %d of %s%s",
                     tag, pages, offset, len(page), len(kept) - before, fetched, total,
                     f" ({page[0].get('eventDate')} .. {page[-1].get('eventDate')})" if page else "")

        if not page:
            break
        if (len(page) < args.page_size and not cap_noted
                and (total is None or offset + len(page) < total)):
            cap_noted = True
            logger.info("%s the service returned %d events for a limit of %d although more remain; "
                        "continuing from the returned count", tag, len(page), args.page_size)
        offset += len(page)
        if total is not None and offset >= total:
            break
    else:
        raise ApiError(f"Window {start:%Y-%m-%d %H:%M} has more than "
                       f"{MAX_PAGES * args.page_size} events; use a smaller --window-hours.")

    if total is not None and fetched != total:
        logger.warning("%s fetched %d events but the service reported %s", tag, fetched, total)

    kept.sort(key=lambda e: str(e.get("eventDate", "")))
    logger.info("%s done: %d fetched, %d matched, %d dropped by the filters, %d page(s), %.1fs",
                tag, fetched, len(kept), fetched - len(kept), pages, time.monotonic() - began)
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
            CANCEL.set()
            cancelled = 0
            for _, future in pending:
                cancelled += future.cancel()
            if cancelled:
                logger.warning("Cancelled %d window(s) that had not started", cancelled)


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
                logger.debug("User %s resolved (email %s)", user_id,
                             "present" if self.cache[user_id].get("email") else "missing")
            else:
                logger.warning("User %s could not be resolved: %s %s - %s", user_id,
                               response.status_code, response.reason, _clip(response.text, 500) or "(empty)")
                if self.verbose:
                    print(f"  user {user_id}: {response.status_code} - {response.text}")
                self.cache[user_id] = None
        return self.cache[user_id] or {}

    @property
    def resolved(self):
        return sum(1 for u in self.cache.values() if u is not None)

    @property
    def unresolved_ids(self):
        return sorted(i for i, u in self.cache.items() if u is None)


def enrich_event(event, user):
    """
    Return a copy of the audit event with the acting user's details added right
    after actionUserId (at the end if the event has none). The fields are null when
    the user could not be resolved. All original fields are kept unchanged.
    """
    details = {
        "actionUser": user.get("email"),
        "actionUserFirstName": user.get("firstName"),
        "actionUserLastName": user.get("lastName"),
    }
    enriched = {}
    for key, value in event.items():
        enriched[key] = value
        if key == "actionUserId":
            enriched.update(details)
    for key, value in details.items():
        enriched.setdefault(key, value)
    return enriched


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
        logger.info("Writing events to %s (moved to %s when the run succeeds)", self.tmp, self.path)

    def write(self, record):
        text = json.dumps(record, indent=2, ensure_ascii=False)
        self.file.write(("[\n" if self.count == 0 else ",\n") + "  " + text.replace("\n", "\n  "))
        self.count += 1

    def commit(self):
        """Finish the file. Returns False, writing nothing, if there were no records."""
        if self.count == 0:
            logger.info("No events to write; removing %s", self.tmp)
            self.abort()
            return False
        self.file.write("\n]\n")
        self.file.close()
        os.replace(self.tmp, self.path)
        logger.info("Wrote %d event(s), %d bytes, to %s", self.count, os.path.getsize(self.path),
                    os.path.abspath(self.path))
        return True

    def abort(self):
        self.file.close()
        try:
            os.remove(self.tmp)
            logger.warning("Removed the partial file %s", self.tmp)
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


def parse_args():
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
        help="Look back this many days, starting at local midnight of that day. "
             "Ignored when --from is given.",
        default=7,
    )

    parser.add_argument(
        "--from", "-f",
        dest="date_from",
        type=str,
        help="Start, as YYYY-MM-DD (from local midnight) or a timestamp such as "
             "2026-09-14T15:42:37.881290Z or 2026-09-14T09:00:00-05:00. A value with "
             "no Z or offset is read as this machine's local time. Cannot be more "
             "than 365 days in the past.",
        default=None,
    )

    parser.add_argument(
        "--to", "-t",
        dest="date_to",
        type=str,
        help="End, inclusive: YYYY-MM-DD (through the end of that local day) or a "
             "timestamp, read like --from. Defaults to the end of today (local).",
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
        "--user-lookup",
        action="store_true",
        help="Look up the acting user of each event and add actionUser (email), "
             "actionUserFirstName and actionUserLastName after actionUserId. "
             "Without this option no user information is requested and the events "
             "are written exactly as the API returned them.",
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
        "--log-dir",
        type=str,
        default="./logs",
        metavar="DIR",
        help="Directory for the detailed log file, cx_audit_trail_<timestamp>.log "
             "(default ./logs).",
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

    return parser.parse_args()


def log_environment(args):
    logger.info("CxOne Audit Trail Inspector started")
    logger.info("Command line: %s", " ".join(sys.argv))
    logger.info("Python %s on %s; requests %s; working directory %s",
                platform.python_version(), platform.platform(), requests.__version__, os.getcwd())
    logger.info("Local time zone: %s (UTC%s)", datetime.now().astimezone().tzname(),
                f"{datetime.now().astimezone():%z}")
    proxies = [n for n in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy")
               if os.environ.get(n)]
    logger.info("Proxy environment variables set: %s", ", ".join(proxies) or "none")
    logger.info("Options: %s", {k: v for k, v in sorted(vars(args).items())})


def run(args):
    if not args.config or not args.config.strip():
        fail("Configuration file path is required.")

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
    logger.info("Configuration '%s' read: ast_host=%s iam_host=%s tenant=%s (api_key is set, not logged)",
                os.path.abspath(args.config), ast_host, iam_host, tenant)

    now = local_now()
    try:
        start, date_from, from_is_local = parse_when(
            args.date_from or (now - timedelta(days=args.days)).strftime("%Y-%m-%d"), is_end=False)
        end, date_to, to_is_local = parse_when(args.date_to or now.strftime("%Y-%m-%d"), is_end=True)
    except ValueError as e:
        fail(str(e))
    if start > end:
        fail("--from must not be after --to.")
    windows = build_windows(start, end, args.window_hours)
    logger.info("Range %s to %s (%s%s); %d window(s) of %dh, %d concurrent",
                _rfc3339(start), _rfc3339(end),
                "from: " + ("local time" if from_is_local else "explicit offset"),
                ", to: " + ("local time" if to_is_local else "explicit offset"),
                len(windows), args.window_hours, args.workers)

    filters = {k: v for k, v in (("action", args.action), ("resource", args.resource),
                                 ("change-type", sorted(args.change_types) if args.change_types else None),
                                 ("user", args.user), ("ip", args.ip), ("search", args.search)) if v}
    logger.info("Client side filters: %s", filters or "none (every event in the range is kept)")
    logger.info("User lookup: %s", "on" if args.user_lookup else "off")

    default_name = f"audit_{date_from}_{date_to}.json"
    if not args.out:
        json_file = default_name
    elif os.path.isdir(args.out) or args.out.endswith(("/", "\\")):
        json_file = os.path.join(args.out, default_name)
    else:
        json_file = args.out
    logger.info("Output file: %s", os.path.abspath(json_file))

    print("-------------------------------------------------------------")
    print("CxOne Audit Trail Inspector (read-only)")
    print(f"AST Host  : {ast_host}")
    print(f"IAM Host  : {iam_host}")
    print(f"Tenant    : {tenant}")
    print(f"Range     : {_rfc3339(start)} to {_rfc3339(end)}")
    if from_is_local or to_is_local:
        first = start.astimezone()
        offset = f"{first:%z}"
        print(f"Time zone : values without an offset were read as local time "
              f"({first.tzname()}, UTC{offset[:3]}:{offset[3:]} at the start)")
    print(f"Windows   : {len(windows)} x {args.window_hours}h, {args.workers} concurrent")
    if LOG_PATH:
        print(f"Log file  : {LOG_PATH}")
    print("-------------------------------------------------------------")

    started = time.monotonic()
    writer = None
    try:
        print("Connecting...")
        cxone_client = CxOneClient(
            iam_host, ast_host, tenant, api_key, False, verify=not args.insecure
        )
        if args.insecure:
            logger.warning("TLS certificate verification is disabled (--insecure)")
        api = Api(cxone_client, args.workers)
        users = UserLookup(api, verbose=args.verbose) if args.user_lookup else None

        print("Fetching audit events...")
        writer = JsonArrayWriter(json_file)
        fetched = 0
        numbers = {w: i for i, w in enumerate(windows, 1)}

        def fetch(window):
            label = f"{numbers[window]}/{len(windows)}"
            try:
                return fetch_window(api, window, args, label)
            except Cancelled:
                logger.info("[window %s] stopped because the run is ending", label)
                raise

        CANCEL.clear()
        results = run_windows(windows, fetch, args.workers)
        try:
            for number, (window, (window_fetched, kept)) in enumerate(results, 1):
                fetched += window_fetched
                for event in kept:
                    writer.write(event if users is None
                                 else enrich_event(event, users.get(event.get("actionUserId"))))
                logger.info("Window %d/%d written: %d event(s); running total %d fetched, %d written",
                            number, len(windows), len(kept), fetched, writer.count)
                if args.verbose:
                    print(f"  window {number}/{len(windows)} {window[0]:%Y-%m-%d %H:%M}: "
                          f"fetched {window_fetched}, matched {len(kept)}")
        finally:
            results.close()   # stops the windows still in flight if the loop ended early

        matched = writer.count
        wrote = writer.commit()
        writer = None
    except requests.exceptions.RequestException as e:
        logger.error("Request failed: %s: %s", type(e).__name__, e, exc_info=True)
        if writer:
            writer.abort()
        fail(describe_error(e), see_log=True)
    except ApiError as e:
        if writer:
            writer.abort()
        fail(str(e), see_log=True)
    except KeyboardInterrupt:
        logger.warning("Interrupted by the user")
        if writer:
            writer.abort()
        raise
    except SystemExit:
        if writer:
            writer.abort()
        raise
    except BaseException:
        logger.exception("Unexpected error")
        if writer:
            writer.abort()
        raise

    elapsed = time.monotonic() - started
    logger.info("Finished: %d event(s) fetched, %d matched, in %.1fs", fetched, matched, elapsed)
    print(f"Fetched {fetched} events, {matched} matched ({elapsed:.1f}s).")
    if not wrote:
        logger.info("No audit events matched; no output file written")
        print("No audit events found for the specified scope.")
        return

    if users is not None:
        logger.info("Users resolved: %d of %d; unresolved ids: %s", users.resolved,
                    len(users.cache), users.unresolved_ids or "none")
        print(f"Users resolved: {users.resolved} of {len(users.cache)} "
              f"({len(users.cache) - users.resolved} not found; use --verbose for detail)")
    print(f"JSON written to {json_file}")


def main():
    args = parse_args()
    start_log(args.log_dir)
    try:
        log_environment(args)
        run(args)
    finally:
        logger.info("Run ended")
        stop_log()


if __name__ == "__main__":
    main()
