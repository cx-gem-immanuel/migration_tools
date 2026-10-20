import argparse
import configparser
import csv
from datetime import datetime
from logsupport import get_logger

logger = get_logger()

from cxsupport import CxOneClient

OUTPUT_FILE = "projects_by_date.output.csv"


def parse_iso_date(date_str: str) -> datetime:
    """Parse ISO 8601 datetime string to datetime object (always UTC-aware)."""
    from datetime import timezone
    try:
        # Handle 'Z' suffix
        normalized = date_str.replace('Z', '+00:00')
        dt = datetime.fromisoformat(normalized)
        
        # If naive (user provided date only, like "2026-06-13"), make it UTC-aware at midnight
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        
        return dt
    except ValueError:
        raise ValueError(
            f"Invalid date format: {date_str}. "
            f"Expected ISO 8601 format (e.g., 2023-01-29 or 2023-01-29T10:23:08Z)"
        )


def main():
    parser = argparse.ArgumentParser(
        description="CxOne Project Date Filter – lists projects created between two dates"
    )

    parser.add_argument(
        "--config", "-c",
        type=str,
        help="Path to the configuration file to read",
        required=True,
    )

    parser.add_argument(
        "--from",
        type=str,
        help="Start date (ISO 8601 format, e.g., 2023-01-29T00:00:00Z)",
        required=True,
        dest="from_date",
    )

    parser.add_argument(
        "--to",
        type=str,
        help="End date (ISO 8601 format, e.g., 2024-01-31T23:59:59Z)",
        required=True,
        dest="to_date",
    )

    parser.add_argument(
        "--tenant-id", "-t",
        type=str,
        help="CxOne tenant ID (overrides CXONE.tenant in config)",
        required=False,
    )

    args = parser.parse_args()

    if not args.config or not args.config.strip():
        logger.critical("Configuration file path is required.")
        exit(1)

    # Parse date arguments
    try:
        from_date = parse_iso_date(args.from_date)
        to_date = parse_iso_date(args.to_date)
    except ValueError as e:
        logger.critical(str(e))
        exit(1)

    if from_date > to_date:
        logger.critical("'from' date must be before 'to' date")
        exit(1)

    config = configparser.ConfigParser()
    config.read(args.config)

    iam_host = config["CXONE"]["iam_host"]
    ast_host = config["CXONE"]["ast_host"]
    tenant = args.tenant_id if args.tenant_id else config["CXONE"]["tenant"]
    api_key = config["CXONE"]["api_key"]

    print("-------------------------------------------------------------")
    print("CxOne Project Date Filter (read-only)")
    print(f"AST Host  : {ast_host}")
    print(f"IAM Host  : {iam_host}")
    print(f"Tenant    : {tenant}")
    print(f"From Date : {args.from_date}")
    print(f"To Date   : {args.to_date}")
    print("-------------------------------------------------------------")

    client = CxOneClient(iam_host, ast_host, tenant, api_key, False)

    projects = client.get_all_projects_id_map()
    if not projects:
        logger.critical("No projects found; aborting.")
        exit(1)

    total = len(projects)
    print(f"Found {total} projects, filtering by date range...\n")

    # Collect matching rows and track column widths
    rows = []
    pcw = len("Project Name")
    dcw = len("Created At")

    for project_id, project in projects.items():
        project_name = project.get("name", project_id)
        created_at_str = project.get("createdAt")

        if not created_at_str:
            continue

        try:
            created_at = parse_iso_date(created_at_str)
        except ValueError:
            logger.debug(f"Could not parse createdAt for project {project_name}: {created_at_str}")
            continue

        # Check if created_at falls within the date range (inclusive)
        if from_date <= created_at <= to_date:
            rows.append((project_name, created_at_str))
            pcw = max(pcw, len(project_name) + 2)
            dcw = max(dcw, len(created_at_str) + 2)

    # --- stdout: formatted table ---
    print(f"Projects created between {args.from_date} and {args.to_date}")
    print("-" * (pcw + dcw + 1))
    header = f"{'Project Name':<{pcw}}|{'Created At':<{dcw}}"
    print(header)
    print("-" * (pcw + dcw + 1))

    for project_name, created_at in rows:
        row = f"{project_name:<{pcw}}|{created_at:<{dcw}}"
        print(row)

    print(f"\nMatching projects: {len(rows)}")

    # --- file: CSV ---
    csv_header = ["Project Name", "Created At"]

    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(csv_header)
        for project_name, created_at in rows:
            writer.writerow([project_name, created_at])

    print(f"CSV written to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()