import argparse
import configparser
import csv

from cxsupport import CxOneClient


def main():
    parser = argparse.ArgumentParser(description="CxOne Query Overrides Inspector")

    parser.add_argument(
        "--config", "-c",
        type=str,
        help="Path to the configuration file to read",
        required=True,
    )

    parser.add_argument(
        "--language", "-l",
        type=str,
        help="Programming language filter for Audit session (e.g. CSharp, Java, JavaScript). If omitted, all languages are returned.",
        required=False,
        default=None,
    )

    parser.add_argument(
        "--tenant-id", "-t",
        type=str,
        help="CxOne tenant ID for query overrides scope (if different from CXONE.tenant in config)",
        required=False,
    )

    parser.add_argument(
        "--application-id", "-a",
        type=str,
        help="CxOne application ID to include in query overrides lookup (reserved for future use)",
        required=False,
    )

    parser.add_argument(
        "--project-id", "-p",
        type=str,
        help="CxOne project ID to include in query overrides lookup (reserved for future use)",
        required=False,
    )

    parser.add_argument(
        "--level",
        type=str,
        help="Query override level to include in query overrides lookup",
        choices=["tenant", "application", "project"],
        required=True,
    )

    args = parser.parse_args()

    if not args.config or not args.config.strip():
        print("ERROR: Configuration file path is required.")
        exit(1)

    config = configparser.ConfigParser()
    config.read(args.config)

    iam_host = config["CXONE"]["iam_host"]
    ast_host = config["CXONE"]["ast_host"]
    tenant   = args.tenant_id if args.tenant_id else config["CXONE"]["tenant"]
    api_key  = config["CXONE"]["api_key"]

    language = args.language.lower() if args.language else None
    csv_file = f"{language or 'all'}.csv"

    print("-------------------------------------------------------------")
    print("CxOne SAST Query Overrides Inspector (read-only)")
    print(f"AST Host  : {ast_host}")
    print(f"IAM Host  : {iam_host}")
    print(f"Tenant    : {tenant}")
    print(f"Language  : {language or '(all)'}")
    print(f"Level     : {args.level}")
    print("-------------------------------------------------------------")

    print("Connecting...")
    cxone_client = CxOneClient(iam_host, ast_host, tenant, api_key, False)

    session = cxone_client.start_audit_session(language)
    if not session:
        print("ERROR: Failed to create Audit session; aborting.")
        exit(1)

    session_id = session.get("id")
    _ = cxone_client.wait_for_audit_session_ready(session)

    try:
        print("Fetching queries...")
        overrides = cxone_client.get_query_overrides(
            language=language,
            level=args.level,
            session_id=session_id,
        ) or []

        if not overrides:
            print("No query overrides found for the specified scope.")
            return

        print(f"Processing {len(overrides)} queries...")

        rows = []
        nw = len("Name")
        lw = len("Level")
        gw = len("Language")
        cw = len("Category")

        for q in overrides:
            q_id   = q.get("id")
            q_name = q.get("name", "")
            q_level = str(q.get("level", ""))
            q_lang = q.get("language", "")
            q_cat  = q.get("category", "")

            if not q_id:
                continue

            q_data = cxone_client.get_query_details(
                query_id=q_id,
                session_id=session_id,
                include_source=True,
            )

            if q_data is None:
                continue

            has_custom_logic = cxone_client.query_has_custom_logic(q_data)
            rows.append((q_name, q_level, q_lang, q_cat, has_custom_logic))

            nw = max(nw, len(q_name)  + 2)
            lw = max(lw, len(q_level) + 2)
            gw = max(gw, len(q_lang)  + 2)
            cw = max(cw, len(q_cat)   + 2)

        # Table
        hw  = len("Has custom logic?")
        header = (
            f"{'Name':{nw}} | {'Level':{lw}} | "
            f"{'Language':{gw}} | {'Category':{cw}} | {'Has custom logic?':{hw}}"
        )
        sep = "-" * len(header)
        print(f"\nQuery Overrides (custom logic only)")
        print(sep)
        print(header)
        print(sep)
        for q_name, q_level, q_lang, q_cat, has_custom_logic in rows:
            if has_custom_logic:
                print(
                    f"{q_name:{nw}} | {q_level:{lw}} | "
                    f"{q_lang:{gw}} | {q_cat:{cw}} | YES"
                )

        # Summary
        custom_logic_count = sum(1 for r in rows if r[4])
        print(sep)
        print(f"Total query overrides : {len(rows)}")
        print(f"With custom logic     : {custom_logic_count}")
        print(f"Base call only        : {len(rows) - custom_logic_count}")

        # CSV
        with open(csv_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Name", "Level", "Language", "Category", "Has custom logic?"])
            for q_name, q_level, q_lang, q_cat, has_custom_logic in rows:
                writer.writerow([q_name, q_level, q_lang, q_cat, "YES" if has_custom_logic else "NO"])
        print(f"\nCSV written to {csv_file}")

    finally:
        if session_id:
            cxone_client.delete_audit_session(session_id)


if __name__ == "__main__":
    main()
