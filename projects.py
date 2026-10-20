"""
projects.py  -  List projects (id, name) from CxOne or CxSAST and export to CSV.

Usage
-----
  python projects.py --source cxone  --config cxone.ini  [--output cxone_projects.csv] [--insecure]
  python projects.py --source cxsast --config cxsast.ini [--output cxsast_projects.csv] [--insecure]

If --output is omitted the source value is prepended to the default filename:
  cxone  -> cxone_projects.csv
  cxsast -> cxsast_projects.csv

Config file sections
--------------------
[CXONE]                         [CXSAST]
iam_host = ...                  host     = ...
ast_host = ...                  username = ...
tenant   = ...                  password = ...
api_key  = ...

CxOne performance model
-----------------------
A "fetch-batch" pipeline runs in parallel workers:

  +-----------------------------------------------------------+
  |  Page 0  |  Page 1  |  Page 2  |  ...  |  Page N-1        |
  |  fetch   |  fetch   |  fetch   |       |  fetch           |  <- ThreadPoolExecutor
  +-----------------------------------------------------------+

CxSAST performance model
------------------------
The CxSAST OData endpoint is paged using $skip/$top (10,000 records per page).
"""

import argparse
import configparser
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed


from cxsupport import CxOneClient, CxSastClient
from logsupport import setup_logger

logger = setup_logger()

# ------------------------------------------------------------------------------
# Tunables
# ------------------------------------------------------------------------------
PAGE_SIZE   = 100   # CxOne: records per API page
MAX_WORKERS = 8     # CxOne: parallel threads for fetch batches

HEADER_RULE = "=" * 63


# ------------------------------------------------------------------------------
# CxOne helpers
# ------------------------------------------------------------------------------

def fetch_cxone_project_batch(client, offset):
    """
    Fetch one page of CxOne projects.
    Returns: list of (project_id, project_name) tuples.
    """
    page_dict, _ = client.get_projects_page(offset, PAGE_SIZE)
    logger.debug(f"Fetched {len(page_dict)} project(s) at offset {offset}")
    return [(pid, name) for name, pid in page_dict.items()]


def fetch_cxone_projects(client):
    """
    Parallel fetch driver for CxOne projects.

    1. Fetches page 0 to learn the total record count.
    2. Fans out all remaining pages to a thread pool.
    3. Returns a list of (project_id, project_name) tuples.
    """
    logger.debug("--------------------------------------------")
    logger.debug("Querying project count...")

    page_dict, total = client.get_projects_page(0, PAGE_SIZE)

    if total == 0:
        logger.debug("No projects found in tenant.")
        return []

    logger.debug(f"Tenant contains {total} project(s). "
                 f"Processing in pages of {PAGE_SIZE} with {MAX_WORKERS} workers.")

    rows = [(pid, name) for name, pid in page_dict.items()]
    remaining_offsets = list(range(PAGE_SIZE, total, PAGE_SIZE))

    if remaining_offsets:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = {
                pool.submit(fetch_cxone_project_batch, client, offset): offset
                for offset in remaining_offsets
            }
            for future in as_completed(futures):
                offset = futures[future]
                try:
                    rows.extend(future.result())
                except Exception as exc:
                    logger.error(f"Batch at offset {offset} raised: {exc}")

    return rows


# ------------------------------------------------------------------------------
# CxSAST helpers
# ------------------------------------------------------------------------------

def fetch_cxsast_projects(client):
    """
    Fetch all CxSAST projects via the REST endpoint in a single call.

    Uses /cxrestapi/projects, which returns all projects server-side with no
    client-side paging required.

    Returns a list of (project_id, project_name) tuples.
    """
    logger.debug("--------------------------------------------")
    logger.debug("Fetching projects via REST...")

    projects = client.get_projects()

    if not projects:
        logger.debug("No projects found.")
        return []

    logger.debug(f"Fetched {len(projects)} project(s).")
    return [(str(p["id"]), p["name"]) for p in projects]


# ------------------------------------------------------------------------------
# Shared helpers
# ------------------------------------------------------------------------------

def write_csv(rows, output_path):
    """
    Write (project_id, project_name) rows to a CSV file, sorted by name.
    """
    rows_sorted = sorted(rows, key=lambda r: r[1].lower())
    with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["project_id", "project_name"])
        writer.writerows(rows_sorted)
    return rows_sorted


# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------

parser = argparse.ArgumentParser(description="CxOne / CxSAST Project lister / exporter")
parser.add_argument("--source", "-s", type=str, required=True,
                    choices=["cxone", "cxsast"],
                    help="Source system to query: 'cxone' or 'cxsast'.")
parser.add_argument("--config", "-c", type=str, required=True,
                    help="Path to the configuration file.")
parser.add_argument("--output", "-o", type=str, default=None,
                    help="Path to the output CSV file. "
                         "Defaults to '<source>_projects.csv' if omitted.")
parser.add_argument("--workers", "-w", type=int, default=MAX_WORKERS,
                    help=f"(CxOne only) Parallel worker threads (default: {MAX_WORKERS}).")
parser.add_argument("--page-size", type=int, default=PAGE_SIZE,
                    help=f"(CxOne only) Records per API page (default: {PAGE_SIZE}).")
parser.add_argument("--insecure", action="store_true", default=False,
                    help="Disable TLS certificate verification (use with caution).")

args = parser.parse_args()

MAX_WORKERS = args.workers
PAGE_SIZE   = args.page_size
source      = args.source.lower()
verify      = not args.insecure
output_path = args.output or f"{source}_projects.csv"

if not args.config or not args.config.strip():
    logger.critical("Configuration file path is required.")
    exit(1)

config = configparser.ConfigParser()
config.read(args.config)

# ------------------------------------------------------------------------------
# Source-specific init
# ------------------------------------------------------------------------------

if source == "cxone":
    iam_host = config["CXONE"]["iam_host"]
    ast_host = config["CXONE"]["ast_host"]
    tenant   = config["CXONE"]["tenant"]
    api_key  = config["CXONE"]["api_key"]

    logger.debug(HEADER_RULE)
    logger.debug("  CxOne Project Lister / Exporter")
    logger.debug(HEADER_RULE)
    logger.debug(f"  Target tenant : {tenant}")
    logger.debug(f"  AST host      : {ast_host}")
    logger.debug(f"  IAM host      : {iam_host}")
    logger.debug(f"  Output CSV    : {output_path}")
    logger.debug(f"  Workers       : {MAX_WORKERS}")
    logger.debug(f"  Page size     : {PAGE_SIZE}")
    logger.debug(f"  Insecure      : {args.insecure}")
    logger.debug(HEADER_RULE)

    logger.debug("Initializing CxOne client...")
    client = CxOneClient(iam_host, ast_host, tenant, api_key, False, verify)

    logger.debug("")
    logger.debug(f"Fetching projects from tenant [{tenant}]...")
    project_rows = fetch_cxone_projects(client)

    source_label = f"tenant [{tenant}]"

else:  # cxsast
    host     = config["CXSAST"]["host"]
    username = config["CXSAST"]["username"]
    password = config["CXSAST"]["password"]

    logger.debug(HEADER_RULE)
    logger.debug("  CxSAST Project Lister / Exporter")
    logger.debug(HEADER_RULE)
    logger.debug(f"  Host       : {host}")
    logger.debug(f"  Username   : {username}")
    logger.debug(f"  Output CSV : {output_path}")
    logger.debug(f"  Insecure   : {args.insecure}")
    logger.debug(HEADER_RULE)

    logger.debug("Initializing CxSAST client...")
    client = CxSastClient(host, username, password, False, verify)

    logger.debug("")
    logger.debug(f"Fetching projects from [{host}]...")
    project_rows = fetch_cxsast_projects(client)

    source_label = f"host [{host}]"

# ------------------------------------------------------------------------------
# Write CSV + display
# ------------------------------------------------------------------------------

sorted_rows = write_csv(project_rows, output_path)

print(f"{'project_id':<40} project_name")
print("-" * 80)
for project_id, project_name in sorted_rows:
    print(f"{project_id:<40} {project_name}")

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------

logger.debug(HEADER_RULE)
logger.debug("  Summary")
logger.debug(HEADER_RULE)
logger.debug(f"  Source        : {source}")
logger.debug(f"  Fetched       : {len(sorted_rows)} project(s) from {source_label}")
logger.debug(f"  Written to    : {output_path}")
logger.debug(HEADER_RULE)
logger.debug("  Done.")
