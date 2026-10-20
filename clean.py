"""
clean.py  –  Delete CxOne projects and applications.

Execution modes
---------------
Dry-run (default): lists what *would* be deleted; nothing is touched.
Exec (--exec flag): requires explicit confirmation, then deletes.

Performance model
-----------------
Rather than fetching ALL records first and deleting after, we use a
"fetch-batch → filter → delete" pipeline that runs in parallel workers.

  ┌─────────────────────────────────────────────────────────┐
  │  Page 0  │  Page 1  │  Page 2  │  …  │  Page N-1       │
  │  fetch   │  fetch   │  fetch   │     │  fetch          │  ← ThreadPoolExecutor
  │  filter  │  filter  │  filter  │     │  filter         │
  │  delete  │  delete  │  delete  │     │  delete         │
  └─────────────────────────────────────────────────────────┘

Steps
-----
1. Fetch page 0 to discover filteredTotalCount.
2. Compute all remaining page offsets.
3. Submit every offset as a task to the thread pool.
4. Each task: fetch page → filter → delete matching records.
5. Collect results and print a summary.

The bearer token is re-fetched inside each worker call through the
existing get_bearer_token() caching logic (token is shared and
refreshed only when it expires).
"""

import argparse
import configparser
import csv
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from cxsupport import CxOneClient
from logsupport import logger

# ──────────────────────────────────────────────────────────────────────────────
# Tunables
# ──────────────────────────────────────────────────────────────────────────────
PAGE_SIZE   = 100   # records per API page
MAX_WORKERS = 8     # parallel threads for fetch+delete batches


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def confirm(prompt="Are you ABSOLUTELY sure? (y/n): "):
    return input(prompt).strip().lower() == "y"


def parse_keep_filters(raw_values):
    """
    Parse keep filters from repeated args and/or comma-separated values.
    Matching is case-agnostic.
    """
    filter_set = set()
    for raw_value in raw_values or []:
        for token in str(raw_value).split(","):
            token = token.strip().lower()
            if token:
                filter_set.add(token)
    return filter_set


def process_project_batch(client, offset, filter_set, csv_provided, is_exec):
    """
    Fetch one page of projects, filter, delete.
    Returns: (n_fetched, n_deleted, n_kept)
    """
    page_dict, _ = client.get_projects_page(offset, PAGE_SIZE)
    n_deleted = 0
    n_kept = 0
    for name, pid in page_dict.items():
        if csv_provided and name.lower() not in filter_set:
            n_kept += 1
            continue
        logger.debug(f"Deleting CxOne Project [{name}, id: {pid}]")
        if is_exec:
            client.delete_project(pid)
        n_deleted += 1
    return len(page_dict), n_deleted, n_kept


def process_application_batch(client, offset, filter_set, csv_provided, is_exec):
    """
    Fetch one page of applications, filter, delete.
    Returns: (n_fetched, n_deleted, n_kept)
    """
    page_dict, _ = client.get_applications_page(offset, PAGE_SIZE)
    n_deleted = 0
    n_kept = 0
    for name, aid in page_dict.items():
        if csv_provided and name.lower() not in filter_set:
            n_kept += 1
            continue
        logger.debug(f"Deleting CxOne Application [{name}, id: {aid}]")
        if is_exec:
            client.delete_application(aid)
        n_deleted += 1
    return len(page_dict), n_deleted, n_kept


def process_project_keep_batch(client, offset, filter_set, keep_provided, is_exec):
    """
    Fetch one page of projects, keep any whose names contain any of the
    provided strings, and delete the rest.
    Returns: (n_fetched, n_deleted, n_kept)
    """
    page_dict, _ = client.get_projects_page(offset, PAGE_SIZE)
    n_deleted = 0
    n_kept = 0
    for name, pid in page_dict.items():
        normalized_name = name.lower()
        if keep_provided and any(token in normalized_name for token in filter_set):
            n_kept += 1
            continue
        logger.debug(f"Deleting CxOne Project [{name}, id: {pid}]")
        if is_exec:
            client.delete_project(pid)
        n_deleted += 1
    return len(page_dict), n_deleted, n_kept


def process_application_keep_batch(client, offset, filter_set, keep_provided, is_exec):
    """
    Fetch one page of applications, keep any whose names contain any of the
    provided strings, and delete the rest.
    Returns: (n_fetched, n_deleted, n_kept)
    """
    page_dict, _ = client.get_applications_page(offset, PAGE_SIZE)
    n_deleted = 0
    n_kept = 0
    for name, aid in page_dict.items():
        normalized_name = name.lower()
        if keep_provided and any(token in normalized_name for token in filter_set):
            n_kept += 1
            continue
        logger.debug(f"Deleting CxOne Application [{name}, id: {aid}]")
        if is_exec:
            client.delete_application(aid)
        n_deleted += 1
    return len(page_dict), n_deleted, n_kept


def delete_in_parallel(label, fetch_first_page_fn, process_batch_fn,
                        client, filter_set, csv_provided, is_exec):
    """
    Generic parallel fetch-batch-delete driver.

    1. Fetches page 0 to learn the total record count.
    2. Fans out all remaining pages to a thread pool.
    3. Returns total number of records deleted (or would-delete in dry-run).
    """
    logger.debug("--------------------------------------------")
    logger.debug(f"Deleting {label}s")

    # Probe page 0 to get total
    _, total = fetch_first_page_fn(0)

    if total == 0:
        logger.debug(f"No {label}s found in tenant.")
        return 0, 0, 0

    logger.debug(f"Tenant contains {total} {label}(s). "
                 f"Processing in pages of {PAGE_SIZE} with {MAX_WORKERS} workers.")

    offsets = list(range(0, total, PAGE_SIZE))
    total_deleted = 0
    total_kept = 0
    total_fetched = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {
            pool.submit(process_batch_fn, client, offset,
                        filter_set, csv_provided, is_exec): offset
            for offset in offsets
        }
        for future in as_completed(futures):
            offset = futures[future]
            try:
                fetched, deleted, kept = future.result()
                total_fetched += fetched
                total_deleted += deleted
                total_kept += kept
            except Exception as exc:
                logger.error(f"Batch at offset {offset} raised: {exc}")

    return total_fetched, total_deleted, total_kept


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

parser = argparse.ArgumentParser(description="CxOne Project / Application cleaner")
parser.add_argument("--exec", "-exec", action="store_true", default=False,
                    help="Execution mode (default is dry-run).")
parser.add_argument("--config", "-c", type=str, required=True,
                    help="Path to the configuration file.")
parser.add_argument("--projects", "-p", type=str, required=False,
                    help="Path to the CSV file listing projects to clean.")
parser.add_argument("--keep", nargs="+", required=False,
                    help="Keep projects and applications whose names contain any of these strings; delete the rest.")
parser.add_argument("--workers", "-w", type=int, default=MAX_WORKERS,
                    help=f"Parallel worker threads (default: {MAX_WORKERS}).")
parser.add_argument("--page-size", type=int, default=PAGE_SIZE,
                    help=f"Records per API page (default: {PAGE_SIZE}).")

args = parser.parse_args()

is_exec     = args.exec
MAX_WORKERS = args.workers
PAGE_SIZE   = args.page_size

if not args.config or not args.config.strip():
    logger.critical("Configuration file path is required.")
    exit(1)

if args.projects and args.keep:
    logger.critical("Use either --projects or --keep, not both.")
    exit(1)

config = configparser.ConfigParser()
config.read(args.config)

iam_host = config["CXONE"]["iam_host"]
ast_host = config["CXONE"]["ast_host"]
tenant   = config["CXONE"]["tenant"]
api_key  = config["CXONE"]["api_key"]

logger.debug("-------------------------------------------------------------")
logger.debug("Project / Application cleaner")
logger.debug(f"Target  : {ast_host}")
logger.debug(f"Mode    : {'REAL EXECUTION' if is_exec else 'DRY-RUN'}")
logger.debug(f"Workers : {MAX_WORKERS}  |  Page size: {PAGE_SIZE}")
logger.debug("-------------------------------------------------------------")

# ── Load optional CSV filter ─────────────────────────────────────────────────
projects_to_delete     = set()
applications_to_delete = set()

if args.projects:
    try:
        with open(args.projects, "r", encoding="utf-8-sig") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                projects_to_delete.add(row["Project Name"].strip().lower())
                applications_to_delete.add(Path(row["Team"].strip()).name.lower())
    except FileNotFoundError:
        logger.error(f"Projects CSV file not found: {args.projects}")
        exit(1)
    except KeyError:
        logger.error("CSV file must contain 'Project Name' and 'Team' columns.")
        exit(1)

csv_provided = bool(projects_to_delete or applications_to_delete)
keep_filters = parse_keep_filters(args.keep)
keep_provided = bool(keep_filters)

if csv_provided:
    logger.debug(f"CSV filter — projects: {len(projects_to_delete)}, "
                 f"applications: {len(applications_to_delete)}")

if keep_provided:
    logger.debug(f"Keep filter — names containing any of: {sorted(keep_filters)}")

# ── Initialise client ─────────────────────────────────────────────────────────
logger.debug("Initializing CxOne client...")
client = CxOneClient(iam_host, ast_host, tenant, api_key, False)

# ── Confirm before real deletion ──────────────────────────────────────────────
if is_exec and not confirm():
    exit(0)

# ── Projects ──────────────────────────────────────────────────────────────────
if keep_provided:
    n_projects_total, n_projects_deleted, n_projects_kept = delete_in_parallel(
        label               = "Project",
        fetch_first_page_fn = lambda offset: client.get_projects_page(offset, PAGE_SIZE),
        process_batch_fn    = process_project_keep_batch,
        client              = client,
        filter_set          = keep_filters,
        csv_provided        = keep_provided,
        is_exec             = is_exec,
    )
else:
    n_projects_total, n_projects_deleted, n_projects_kept = delete_in_parallel(
        label               = "Project",
        fetch_first_page_fn = lambda offset: client.get_projects_page(offset, PAGE_SIZE),
        process_batch_fn    = process_project_batch,
        client              = client,
        filter_set          = projects_to_delete,
        csv_provided        = csv_provided,
        is_exec             = is_exec,
    )

# ── Applications ──────────────────────────────────────────────────────────────
if keep_provided:
    n_applications_total, n_applications_deleted, n_applications_kept = delete_in_parallel(
        label               = "Application",
        fetch_first_page_fn = lambda offset: client.get_applications_page(offset, PAGE_SIZE),
        process_batch_fn    = process_application_keep_batch,
        client              = client,
        filter_set          = keep_filters,
        csv_provided        = keep_provided,
        is_exec             = is_exec,
    )
else:
    n_applications_total, n_applications_deleted, n_applications_kept = delete_in_parallel(
        label               = "Application",
        fetch_first_page_fn = lambda offset: client.get_applications_page(offset, PAGE_SIZE),
        process_batch_fn    = process_application_batch,
        client              = client,
        filter_set          = applications_to_delete,
        csv_provided        = csv_provided,
        is_exec             = is_exec,
    )

# ── Summary ───────────────────────────────────────────────────────────────────
logger.debug("--------------------------------------------")
logger.debug("Summary:")
logger.debug(f"{'Deleted' if is_exec else 'Would delete'} "
             f"{n_projects_deleted} Project(s) from tenant [{tenant}].")
logger.debug(f"Project(s) retained: {n_projects_kept} of {n_projects_total}.")
logger.debug(f"{'Deleted' if is_exec else 'Would delete'} "
             f"{n_applications_deleted} Application(s) from tenant [{tenant}].")
logger.debug(f"Application(s) retained: {n_applications_kept} of {n_applications_total}.")
logger.debug("Done.")
