"""
get-scans.py
============
Fetch scan records from CxOne for a list of scan IDs supplied via
--scan-ids or --csv.

  1. Reads the list of scan IDs (comma-separated or from a CSV file)
  2. Calls GET /api/scans/ with the scan-ids filter (chunked automatically
     if the list is large enough that the query string would be too long)
  3. Reports which requested scan IDs were not found
  4. Writes the results to a CSV or JSON file (--format, default csv)

Usage examples
--------------
  python get-scans.py --scan-ids "fc6e36d8-943f-4a0b-82db-d0c1b4a79b81,d4196700-1c4f-4993-9848-c7a5035306eb"
  python get-scans.py --csv scan_ids.csv
  python get-scans.py --csv scan_ids.csv --format json --output scans.json
  python get-scans.py --csv scan_ids.csv --insecure --config config.ini
"""

import argparse
import configparser
import csv
import io
import json
import sys
from datetime import datetime
from pathlib import Path

from cxsupport import CxOneClient
from logsupport import setup_logger, add_file_handler

logger = setup_logger(file_logging=False)


# ---------------------------------------------------------------------------
# Windows console UTF-8 fix
# ---------------------------------------------------------------------------

def _fix_console_encoding() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name)
        if getattr(stream, "encoding", "utf-8").lower().replace("-", "") != "utf8":
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except AttributeError:
                setattr(
                    sys, stream_name,
                    io.TextIOWrapper(
                        stream.buffer,
                        encoding="utf-8",
                        errors="replace",
                        line_buffering=stream.line_buffering,
                    ),
                )


_fix_console_encoding()


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

_BANNER_WIDTH = 62


def _banner_line(label: str, value: str) -> str:
    return f"  {label:<20} {value}"


def _print_banner(args: argparse.Namespace, iam: str, ast_host: str,
                  ten: str, scan_ids: list[str], log_file: Path) -> None:
    sep = "=" * _BANNER_WIDTH
    logger.info(sep)
    logger.info("  CxOne Get Scans Tool")
    logger.info("  Fetch scan records for a list of scan IDs")
    logger.info(sep)
    logger.info(_banner_line("Tenant:",     ten))
    logger.info(_banner_line("AST host:",   ast_host))
    logger.info(_banner_line("IAM host:",   iam))
    logger.info(_banner_line("Config:",     str(Path(args.config).resolve())))
    logger.info(_banner_line("Output file:", str(Path(args.output).resolve())))
    logger.info(_banner_line("Format:",     args.format))
    logger.info(_banner_line("Log file:",   str(log_file.resolve())))
    logger.info(_banner_line("TLS verify:", "NO (--insecure)" if args.insecure else "yes"))
    src = f"--csv {args.csv}" if args.csv else f"--scan-ids ({len(scan_ids)} scan-id(s))"
    logger.info(_banner_line("Source:",     src))
    logger.info(sep)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_ids_from_csv(csv_path: str) -> list[str]:
    """
    Read scan IDs from *csv_path*.
    Accepts one scan ID per line, or a CSV where the first column holds
    scan IDs. Header row skipped when first cell is 'scan', 'scan_id',
    'scanid', or 'id' (case-insensitive).
    Raises SystemExit on file-not-found or read errors.
    """
    try:
        scan_ids = []
        with open(csv_path, newline="", encoding="utf-8") as fh:
            reader = csv.reader(fh)
            for i, row in enumerate(reader):
                if not row:
                    continue
                sid = row[0].strip()
                if i == 0 and sid.lower() in ("scan", "scan_id", "scanid", "id"):
                    logger.debug("CSV header row detected and skipped: %s", row)
                    continue
                if sid:
                    scan_ids.append(sid)
    except FileNotFoundError:
        logger.error("CSV file not found: '%s'", csv_path)
        sys.exit(1)
    except OSError as exc:
        logger.error("Failed to read CSV file '%s': %s", csv_path, exc)
        sys.exit(1)

    logger.debug("Loaded %d scan-id(s) from '%s'.", len(scan_ids), csv_path)
    return scan_ids


def _dedup_ordered(items: list[str]) -> list[str]:
    """Return *items* with duplicates removed, preserving first-occurrence order."""
    seen: set[str] = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _fmt_tags(tags: dict) -> str:
    """Render the tags dict as a compact 'key:value, key2:value2' string."""
    if not tags:
        return ""
    return ", ".join(f"{k}:{v}" if v else k for k, v in tags.items())


def write_csv(scans: list[dict], output_path: Path) -> None:
    fieldnames = [
        "id", "status", "projectId", "projectName", "branch",
        "createdAt", "updatedAt", "initiator", "sourceType",
        "sourceOrigin", "userAgent", "engines", "tags",
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for scan in scans:
            writer.writerow({
                "id":           scan.get("id", ""),
                "status":       scan.get("status", ""),
                "projectId":    scan.get("projectId", ""),
                "projectName":  scan.get("projectName", ""),
                "branch":       scan.get("branch", ""),
                "createdAt":    scan.get("createdAt", ""),
                "updatedAt":    scan.get("updatedAt", ""),
                "initiator":    scan.get("initiator", ""),
                "sourceType":   scan.get("sourceType", ""),
                "sourceOrigin": scan.get("sourceOrigin", ""),
                "userAgent":    scan.get("userAgent", ""),
                "engines":      ", ".join(scan.get("engines") or []),
                "tags":         _fmt_tags(scan.get("tags") or {}),
            })


def write_json(scans: list[dict], output_path: Path) -> None:
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(scans, fh, indent=2)


def log_status_table(scan_ids: list[str], scans_by_id: dict[str, dict]) -> None:
    """
    Log a simple scan_id / status table, in the original input order.
    Scan IDs that were not found are shown with status NOT_FOUND.
    """
    id_width = max((len(sid) for sid in scan_ids), default=8)
    id_width = max(id_width, len("scan_id"))

    logger.info("  %-*s  %s", id_width, "scan_id", "status")
    logger.info("  %s  %s", "-" * id_width, "-" * 10)
    for sid in scan_ids:
        status = scans_by_id.get(sid, {}).get("status", "NOT_FOUND")
        logger.info("  %-*s  %s", id_width, sid, status)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fetch CxOne scan records for a list of scan IDs.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--scan-ids", metavar="ID[,ID...]",
                     help="Comma-separated list of CxOne scan IDs.")
    src.add_argument("--csv", metavar="FILE",
                     help="Path to a CSV file containing scan IDs (first column).")

    parser.add_argument("--config",  default="config.ini",
                        help="Path to config.ini with [CXONE] section.")
    parser.add_argument("--output",  default="./scans", metavar="FILE",
                        help="Path to write the results to. The extension is "
                             "always forced to match --format (e.g. .json "
                             "when --format json).")
    parser.add_argument("--format",  choices=["csv", "json"], default="csv",
                        help="Output file format.")
    parser.add_argument("--log-dir", default="./logs", metavar="DIR",
                        help="Directory to write the execution log file.")
    parser.add_argument("--insecure", action="store_true",
                        help="Disable TLS certificate verification.")

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # ── File logging ─────────────────────────────────────────────────
    log_dir  = Path(args.log_dir)
    run_ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"cx_get_scans_{run_ts}.log"
    add_file_handler(str(log_file))

    # ── Config ───────────────────────────────────────────────────────
    config = configparser.ConfigParser()
    if not config.read(args.config):
        logger.error("Cannot read config file: '%s'", args.config)
        sys.exit(1)

    try:
        cx  = config["CXONE"]
        iam = cx["iam_host"]
        ast = cx["ast_host"]
        ten = cx["tenant"]
        key = cx["api_key"]
    except KeyError as exc:
        logger.error("Missing [CXONE] config key: %s", exc)
        sys.exit(1)

    # ── Scan ID list ─────────────────────────────────────────────────
    if args.scan_ids:
        raw = [s.strip() for s in args.scan_ids.split(",") if s.strip()]
    else:
        raw = load_ids_from_csv(args.csv)

    scan_ids = _dedup_ordered(raw)
    dupes    = len(raw) - len(scan_ids)
    if dupes:
        logger.warning("%d duplicate scan ID(s) removed from input.", dupes)

    if not scan_ids:
        logger.error("No scan IDs found. Exiting.")
        sys.exit(1)

    # ── Output directory ────────────────────────────────────────────
    # The output file's extension always matches --format, regardless of
    # what was passed to --output (e.g. --format json forces a .json
    # extension even if --output ended in .csv or had no extension).
    output_path  = Path(args.output)
    desired_ext  = f".{args.format}"
    if output_path.suffix.lower() != desired_ext:
        original = output_path
        output_path = output_path.with_suffix(desired_ext)
        logger.debug(
            "Adjusted output filename to match --format %s: '%s' -> '%s'",
            args.format, original, output_path,
        )

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.error("Failed to create output directory: %s", exc)
        sys.exit(1)

    _print_banner(args, iam, ast, ten, scan_ids, log_file)

    # ── Client ───────────────────────────────────────────────────────
    client = CxOneClient(iam, ast, ten, key, False, not args.insecure)

    # ── Fetch scans ──────────────────────────────────────────────────
    logger.info("  Fetching %d scan(s)...", len(scan_ids))
    scans = client.get_scans_by_ids(scan_ids)

    found_ids   = {s.get("id") for s in scans if s.get("id")}
    missing_ids = [sid for sid in scan_ids if sid not in found_ids]
    scans_by_id = {s["id"]: s for s in scans if s.get("id")}

    # ── Write output ─────────────────────────────────────────────────
    if args.format == "json":
        write_json(scans, output_path)
    else:
        write_csv(scans, output_path)

    # ── Summary ───────────────────────────────────────────────────────
    sep = "=" * _BANNER_WIDTH
    logger.info(sep)
    logger.info("  SUMMARY: %d / %d scan(s) found.", len(found_ids), len(scan_ids))
    logger.info(sep)
    log_status_table(scan_ids, scans_by_id)
    logger.info(sep)

    if missing_ids:
        logger.info("  Not found (%d):", len(missing_ids))
        for sid in missing_ids:
            logger.info("    [MISSING]  %s", sid)

    logger.info("  Output written to: %s", output_path.resolve())
    logger.info(sep)

    sys.exit(0 if not missing_ids else 1)


if __name__ == "__main__":
    main()
