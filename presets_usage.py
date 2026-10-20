import argparse
import configparser
import csv
import time
from logsupport import get_logger

logger = get_logger()

from cxsupport import CxOneClient

OUTPUT_FILE = "presets_usage.output.csv"


def main():
    parser = argparse.ArgumentParser(
        description="CxOne Preset Usage Inspector – lists projects whose preset matches the given name"
    )

    parser.add_argument(
        "--config", "-c",
        type=str,
        help="Path to the configuration file to read",
        required=True,
    )

    parser.add_argument(
        "--preset", "-p",
        type=str,
        help="Preset name to filter on (case-insensitive, e.g. 'ASA Premium')",
        required=True,
    )

    parser.add_argument(
        "--tenant-id", "-t",
        type=str,
        help="CxOne tenant ID (overrides CXONE.tenant in config)",
        required=False,
    )

    parser.add_argument(
        "--project",
        action="store_true",
        default=False,
        help="Inspect project-level configuration for preset (default: both)",
    )

    parser.add_argument(
        "--scan",
        action="store_true",
        default=False,
        help="Inspect latest scan configuration for preset (default: both)",
    )

    args = parser.parse_args()

    if not args.config or not args.config.strip():
        logger.critical("Configuration file path is required.")
        exit(1)

    # If neither flag is set, inspect both; if one or both are set, honour them
    check_project = args.project or not args.scan
    check_scan    = args.scan    or not args.project

    config = configparser.ConfigParser()
    config.read(args.config)

    iam_host = config["CXONE"]["iam_host"]
    ast_host = config["CXONE"]["ast_host"]
    tenant   = args.tenant_id if args.tenant_id else config["CXONE"]["tenant"]
    api_key  = config["CXONE"]["api_key"]

    preset_filter = args.preset.strip().lower()

    scope_label = "project + scan" if (check_project and check_scan) else ("project" if check_project else "scan")

    print("-------------------------------------------------------------")
    print("CxOne Preset Usage Inspector (read-only)")
    print(f"AST Host  : {ast_host}")
    print(f"IAM Host  : {iam_host}")
    print(f"Tenant    : {tenant}")
    print(f"Preset    : {args.preset}")
    print(f"Scope     : {scope_label}")
    print("-------------------------------------------------------------")

    client = CxOneClient(iam_host, ast_host, tenant, api_key, False)

    projects = client.get_all_projects_id_map()
    if not projects:
        logger.critical("No projects found; aborting.")
        exit(1)

    app_id_to_name = client.get_all_applications_id_map()

    total = len(projects)
    print(f"Found {total} projects")

    # Collect matching rows and track column widths
    rows = []
    pcw  = len("Project")
    prcw = len("Project Preset") if check_project else 0
    scw  = len("Scan Preset")    if check_scan    else 0
    acw  = len("Applications")

    for n, (project_id, project) in enumerate(projects.items(), start=1):
        if n == 1 or n % 5 == 0:
            print(f"Processing {n} of {total}")

        time.sleep(0.25)   # pace requests to avoid server-side rate limiting
        project_name = project.get("name", project_id)

        project_preset = ""
        if check_project:
            project_preset = client.extract_sast_preset(
                client.get_project_configuration(project_id)
            )

        scan_preset = ""
        if check_scan:
            last_scan = client.get_project_last_scan(project_id)
            if last_scan:
                scan_id = last_scan.get("id")
                if scan_id:
                    scan_preset = client.extract_sast_preset(
                        client.get_scan_configuration(project_id, scan_id)
                    )

        # Match against whichever scopes are active
        matched = (
            (check_project and preset_filter in project_preset.lower())
            or (check_scan  and preset_filter in scan_preset.lower())
        )
        if not matched:
            continue

        app_ids   = project.get("applicationIds") or []
        app_names = [app_id_to_name.get(aid, aid) for aid in app_ids]
        apps_str  = ", ".join(app_names)

        rows.append((project_name, project_preset, scan_preset, app_names, apps_str))

        pcw  = max(pcw,  len(project_name)  + 2)
        if check_project:
            prcw = max(prcw, len(project_preset) + 2)
        if check_scan:
            scw  = max(scw,  len(scan_preset)    + 2)
        acw  = max(acw,  len(apps_str)       + 2)

    # --- stdout: formatted table ---
    # Build header dynamically based on active scopes
    header_parts = [f"{'Project':<{pcw}}"]
    if check_project:
        header_parts.append(f"{'Project Preset':<{prcw}}")
    if check_scan:
        header_parts.append(f"{'Scan Preset':<{scw}}")
    header_parts.append(f"{'Applications':<{acw}}")
    header = "|".join(header_parts)

    print(f"\nProjects using preset [{args.preset}] (scope: {scope_label})")
    print("-" * len(header))
    print(header)
    print("-" * len(header))
    for project_name, project_preset, scan_preset, _, apps_str in rows:
        row_parts = [f"{project_name:<{pcw}}"]
        if check_project:
            row_parts.append(f"{project_preset:<{prcw}}")
        if check_scan:
            row_parts.append(f"{scan_preset:<{scw}}")
        row_parts.append(f"{apps_str:<{acw}}")
        print("|".join(row_parts))
    print(f"\nMatching projects: {len(rows)}")

    # --- file: CSV ---
    csv_header = ["Project"]
    if check_project:
        csv_header.append("Project Preset")
    if check_scan:
        csv_header.append("Scan Preset")
    csv_header.append("Applications...")

    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(csv_header)
        for project_name, project_preset, scan_preset, app_names, _ in rows:
            row = [project_name]
            if check_project:
                row.append(project_preset)
            if check_scan:
                row.append(scan_preset)
            row += app_names
            writer.writerow(row)

    print(f"\nCSV written to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
