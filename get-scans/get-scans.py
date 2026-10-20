import argparse
import configparser
import csv
import io
import json
import re
import sys
from datetime import datetime
from pathlib import Path

from cxsupport import CxOneClient
from logsupport import setup_logger, add_file_handler

logger = setup_logger(file_logging=False)

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

INVALID_FORMAT = "INVALID_FORMAT"
NOT_FOUND      = "NOT_FOUND"


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


_BANNER_WIDTH = 62


def _banner_line(label: str, value: str) -> str:
    return f"  {label:<20} {value}"


def _print_banner(args: argparse.Namespace, iam: str, ast_host: str,
                  ten: str, scan_ids: list[str], log_file: Path) -> None:
    sep = "=" * _BANNER_WIDTH
    logger.debug(sep)
    logger.debug("  CxOne Get Scans Tool")
    logger.debug("  Fetch scan records for a list of scan IDs")
    logger.debug(sep)
    logger.debug(_banner_line("Tenant:",     ten))
    logger.debug(_banner_line("AST host:",   ast_host))
    logger.debug(_banner_line("IAM host:",   iam))
    logger.debug(_banner_line("Config:",     str(Path(args.config).resolve())))
    logger.debug(_banner_line("Output file:", str(DEFAULT_OUTPUT_PATH.resolve())))
    logger.debug(_banner_line("Log file:",   str(log_file.resolve())))
    logger.debug(_banner_line("TLS verify:", "NO (--insecure)" if args.insecure else "yes"))
    src = f"--csv {args.csv}" if args.csv else f"--scan-ids ({len(scan_ids)} scan-id(s))"
    logger.debug(_banner_line("Source:",     src))
    logger.debug(sep)


def load_ids_from_csv(csv_path: str) -> list[str]:
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
    seen: set[str] = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _split_valid_ids(scan_ids: list[str]) -> tuple[list[str], list[str]]:
    valid, invalid = [], []
    for sid in scan_ids:
        (valid if _UUID_RE.match(sid) else invalid).append(sid)
    return valid, invalid


def write_json(scans: list[dict], output_path: Path) -> None:
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(scans, fh, indent=2)


def log_status_table(scan_ids: list[str], scans_by_id: dict[str, dict],
                     invalid_ids: set[str]) -> None:
    id_width = max((len(sid) for sid in scan_ids), default=8)
    id_width = max(id_width, len("scan_id"))

    logger.info("  %-*s  %s", id_width, "scan_id", "status")
    logger.info("  %s  %s", "-" * id_width, "-" * 10)
    for sid in scan_ids:
        if sid in invalid_ids:
            status = INVALID_FORMAT
        else:
            status = scans_by_id.get(sid, {}).get("status", NOT_FOUND)
        logger.info("  %-*s  %s", id_width, sid, status)


DEFAULT_OUTPUT_PATH = Path("./scans.json")


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
    parser.add_argument("--log-dir", default="./logs", metavar="DIR",
                        help="Directory to write the execution log file.")
    parser.add_argument("--insecure", action="store_true",
                        help="Disable TLS certificate verification.")

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    log_dir  = Path(args.log_dir)
    run_ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"cx_get_scans_{run_ts}.log"
    add_file_handler(str(log_file))

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

    valid_ids, invalid_ids = _split_valid_ids(scan_ids)
    invalid_id_set = set(invalid_ids)
    if invalid_ids:
        logger.warning(
            "%d scan ID(s) have invalid format and will be skipped "
            "(not sent to the API): %s",
            len(invalid_ids), ", ".join(invalid_ids),
        )

    output_path = DEFAULT_OUTPUT_PATH

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.error("Failed to create output directory: %s", exc)
        sys.exit(1)

    _print_banner(args, iam, ast, ten, scan_ids, log_file)

    client = CxOneClient(iam, ast, ten, key, False, not args.insecure)

    logger.debug("Fetching %d scan(s)...", len(valid_ids))
    scans = client.get_scans_by_ids(valid_ids) if valid_ids else []

    found_ids   = {s.get("id") for s in scans if s.get("id")}
    missing_ids = [sid for sid in valid_ids if sid not in found_ids]
    scans_by_id = {s["id"]: s for s in scans if s.get("id")}

    write_json(scans, output_path)

    logger.info("  SUMMARY: %d / %d scan(s) found (%d invalid format skipped).",
                len(found_ids), len(scan_ids), len(invalid_ids))
    log_status_table(scan_ids, scans_by_id, invalid_id_set)

    if missing_ids:
        logger.debug("Not found (%d): %s", len(missing_ids), ", ".join(missing_ids))
    if invalid_ids:
        logger.debug("Invalid format, skipped (%d): %s", len(invalid_ids), ", ".join(invalid_ids))
    logger.debug("Output written to: %s", output_path.resolve())

    sys.exit(0 if not missing_ids and not invalid_ids else 1)


if __name__ == "__main__":
    main()
