from datetime import datetime, timedelta
import requests
import urllib3
import time
from logsupport import get_logger

logger = get_logger()


class CxOneClient:
    def __init__(self, iam_host, ast_host, tenant, api_key, is_verbose=False, verify=True):
        self.api_key = api_key
        self.iam_host = iam_host
        self.ast_host = ast_host
        self.tenant = tenant
        self.bearer_token = None
        self.is_verbose = is_verbose
        self.token_expiration = None
        self.verify = verify
        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.debug("CxOne client: TLS certificate verification is disabled (--insecure).")

    def get_bearer_token(self):
        if self.bearer_token is not None and datetime.now() < self.token_expiration:
            return self.bearer_token

        url = f"{self.iam_host}/auth/realms/{self.tenant}/protocol/openid-connect/token"
        data = {
            "grant_type": "refresh_token",
            "client_id": "ast-app",
            "refresh_token": f"{self.api_key}",
        }

        response = requests.post(url, data=data, verify=self.verify)
        if response.status_code == 200:
            response_json = response.json()
            expires_in = response_json["expires_in"]
            now = datetime.now()
            self.token_expiration = now + timedelta(seconds=expires_in - 300)
            self.bearer_token = response_json["access_token"]
            return self.bearer_token

        logger.debug(f"Error: {response.status_code} - {response.text}")
        return None

    def _get(self, url: str, params: dict | None = None,
             retries: int = 4, backoff: float = 2.0):
        """
        GET wrapper with exponential backoff retry.

        Retries on connection errors (RemoteDisconnected, etc.) and on
        HTTP 429 / 5xx responses.  Waits backoff * 2^attempt seconds between
        attempts (2 s, 4 s, 8 s, 16 s by default).
        """
        headers = {
            "Accept": "application/json; version=1.0",
            "Authorization": f"Bearer {self.get_bearer_token()}",
        }
        for attempt in range(retries + 1):
            try:
                response = requests.get(url, headers=headers, params=params, verify=self.verify)
                if response.status_code in (429, 500, 502, 503, 504, 529) and attempt < retries:
                    wait = backoff * (2 ** attempt)
                    logger.debug(
                        f"HTTP {response.status_code} on {url} – "
                        f"retrying in {wait:.0f}s (attempt {attempt + 1}/{retries})"
                    )
                    time.sleep(wait)
                    continue
                if attempt > 0:
                    logger.debug(f"Retry succeeded on {url} (attempt {attempt + 1})")
                return response
            except requests.exceptions.ConnectionError as exc:
                if attempt < retries:
                    wait = backoff * (2 ** attempt)
                    logger.debug(
                        f"Connection error on {url}: {exc} – "
                        f"retrying in {wait:.0f}s (attempt {attempt + 1}/{retries})"
                    )
                    time.sleep(wait)
                else:
                    raise

    # ------------------------------------------------------------------
    # Scans lookup by scan ID
    # ------------------------------------------------------------------

    # Keep the query string comfortably under typical server/proxy limits.
    _MAX_SCAN_IDS_URL_LEN = 1800

    def get_scans_by_ids(self, scan_ids: list[str]) -> list[dict]:
        """
        Fetch scan records for a list of scan IDs.

        Uses:
            GET /api/scans/?scan-ids=<id>&scan-ids=<id>...&limit=0

        Automatically splits the request into smaller sub-batches if the
        resulting query string would be too long, and merges the results
        into a single flat list (deduplicated by scan id). ``limit=0`` is
        always passed so the full match set is returned regardless of the
        API's default page size (20).

        Parameters
        ----------
        scan_ids : List of scan UUIDs to fetch.

        Returns
        -------
        list[dict]
            One entry per scan found, in the shape documented for
            GET /api/scans/. Scan IDs with no matching record are simply
            absent from the result — callers should diff against the input
            list to detect scan IDs that were not found.
        """
        if not scan_ids:
            return []

        by_id: dict[str, dict] = {}
        self._fetch_scans_sub_batch(scan_ids, by_id)
        return list(by_id.values())

    def _fetch_scans_sub_batch(self, scan_ids: list[str], by_id: dict[str, dict]) -> None:
        """
        Attempt to fetch *scan_ids* in one API call. If the resulting URL
        would likely be too long the list is halved recursively until each
        chunk fits. Retries/backoff on transient errors are handled by the
        shared self._get() wrapper.
        """
        if not scan_ids:
            return

        url = f"{self.ast_host}/api/scans/"
        # Rough length estimate: "&scan-ids=" (10) + uuid (36) per id.
        est_len = len(url) + len(scan_ids) * 46
        if est_len > self._MAX_SCAN_IDS_URL_LEN and len(scan_ids) > 1:
            mid = len(scan_ids) // 2
            logger.debug(
                f"get_scans_by_ids: query too long ({est_len} est. chars); "
                f"splitting {len(scan_ids)} scan-id(s) into two sub-batches."
            )
            self._fetch_scans_sub_batch(scan_ids[:mid], by_id)
            self._fetch_scans_sub_batch(scan_ids[mid:], by_id)
            return

        params = {"scan-ids": scan_ids, "limit": 0}
        logger.debug(f"Fetching {len(scan_ids)} scan(s) by scan-ids from {url}")
        response = self._get(url, params=params)

        if response is None:
            logger.warning(
                f"get_scans_by_ids: no response for {len(scan_ids)} scan-id(s) "
                f"(network failure after retries)."
            )
            return

        if response.status_code != 200:
            logger.debug(
                f"get_scans_by_ids: HTTP {response.status_code} for "
                f"{len(scan_ids)} scan-id(s) - {response.text}"
            )
            return

        body = response.json() or {}
        for scan in body.get("scans") or []:
            sid = scan.get("id")
            if sid:
                by_id[sid] = scan
