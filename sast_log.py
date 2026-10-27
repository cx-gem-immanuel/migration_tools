"""
Download a scan log from CxSAST.

Usage:
  python sast_log.py --config cxsast.ini --project-id 123[,124,...] [--output-dir logs] [--insecure]
  python sast_log.py --config cxsast.ini --scan-id 456[,457,...]    [--output-dir logs] [--insecure]

  --project-id  comma-separated project ids; downloads the log of each project's
                latest successful (Finished) scan.
  --scan-id     comma-separated scan ids; downloads the log of each specific scan.
  The two are mutually exclusive; exactly one is required.
  A failure on one id is reported and the rest continue; exit code is 1 if any failed.

Config file (same as projects.py):
  [CXSAST]
  host     = https://cxsast.example.com
  username = ...
  password = ...
"""
import argparse
import configparser
import os
import re
import sys

import requests

from cxsupport import CxSastClient
from logsupport import get_logger

logger = get_logger()


class ScanLogError(Exception):
    pass


def api_headers(client):
    token = client.get_bearer_token()
    if not token:
        logger.critical("Failed to authenticate to CxSAST.")
        sys.exit(1)
    return {
        "Accept": "application/json;v=5.0",
        "Authorization": f"Bearer {token}",
    }


def parse_id_list(value):
    """argparse type: '1, 2,3' -> [1, 2, 3] (order kept, duplicates dropped)."""
    ids = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if not part.isdigit():
            raise argparse.ArgumentTypeError(f"invalid id '{part}' (expected comma-separated integers)")
        if int(part) not in ids:
            ids.append(int(part))
    if not ids:
        raise argparse.ArgumentTypeError("at least one id is required")
    return ids


def get_latest_finished_scan_id(client, project_id):
    url = f"{client.cxsast_host}/cxrestapi/sast/scans"
    params = {"projectId": project_id, "scanStatus": "Finished", "last": 1}
    response = requests.get(url, headers=api_headers(client), params=params,
                            verify=client.verify)
    if response.status_code != 200:
        raise ScanLogError(f"failed to list scans for project {project_id}: "
                           f"{response.status_code} - {response.text}")

    scans = response.json()
    if not scans:
        raise ScanLogError(f"no finished scans found for project {project_id}")

    # 'last=1' should return one scan, but pick the highest id defensively.
    return max(scan["id"] for scan in scans)


def download_scan_log(client, scan_id, output_dir):
    url = f"{client.cxsast_host}/cxrestapi/sast/scans/{scan_id}/logs"
    headers = api_headers(client)
    headers["Accept"] = "application/octet-stream, application/json;v=5.0"

    with requests.get(url, headers=headers, verify=client.verify, stream=True) as response:
        if response.status_code != 200:
            raise ScanLogError(f"failed to download log for scan {scan_id}: "
                               f"{response.status_code} - {response.text}")

        filename = None
        disposition = response.headers.get("Content-Disposition", "")
        match = re.search(r"""filename\*?=(?:UTF-8'')?"?([^";]+)"?""", disposition, re.IGNORECASE)
        if match:
            filename = os.path.basename(match.group(1).strip())
        if not filename:
            content_type = response.headers.get("Content-Type", "")
            ext = ".zip" if "zip" in content_type or "octet-stream" in content_type else ".log"
            filename = f"scan_{scan_id}_log{ext}"

        # Prefix with the scan id so logs from different scans never overwrite each other.
        if str(scan_id) not in filename:
            filename = f"scan_{scan_id}_{filename}"

        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, filename)
        with open(output_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=65536):
                f.write(chunk)

    return output_path


parser = argparse.ArgumentParser(description="Download CxSAST scan logs")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("--project-id", "-p", type=parse_id_list,
                   help="Comma-separated project ids; downloads each project's "
                        "latest successful scan log.")
group.add_argument("--scan-id", "-s", type=parse_id_list,
                   help="Comma-separated scan ids; downloads each scan's log.")
parser.add_argument("--config", "-c", type=str, required=True,
                    help="Path to the configuration file.")
parser.add_argument("--output-dir", "-o", type=str, default=".",
                    help="Directory to save the logs into (default: current directory).")
parser.add_argument("--insecure", action="store_true", default=False,
                    help="Disable TLS certificate verification (use with caution).")
args = parser.parse_args()

config = configparser.ConfigParser()
config.read(args.config)

client = CxSastClient(config["CXSAST"]["host"], config["CXSAST"]["username"],
                      config["CXSAST"]["password"], False, not args.insecure)

# (label, id) work items: a project id is resolved to its latest finished scan first.
if args.project_id is not None:
    items = [("project", i) for i in args.project_id]
else:
    items = [("scan", i) for i in args.scan_id]

failures = 0
for kind, item_id in items:
    try:
        if kind == "project":
            scan_id = get_latest_finished_scan_id(client, item_id)
            logger.info(f"Latest successful scan for project {item_id}: {scan_id}")
        else:
            scan_id = item_id
        path = download_scan_log(client, scan_id, args.output_dir)
        source = f"project {item_id} (scan {scan_id})" if kind == "project" else f"scan {scan_id}"
        print(f"Scan log for {source} saved to: {path}")
    except (ScanLogError, requests.RequestException) as e:
        failures += 1
        logger.error(f"{kind} {item_id}: {e}")
        print(f"FAILED {kind} {item_id}: {e}", file=sys.stderr)

if len(items) > 1:
    print(f"Done: {len(items) - failures} succeeded, {failures} failed.")
sys.exit(1 if failures else 0)
