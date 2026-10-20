import argparse
import configparser
import csv
import xml.etree.ElementTree as ET
from collections import defaultdict

from cxsupport import CxOneClient, CxSASTSOAPClient
from logsupport import setup_logger


class FatalMigrationError(Exception):
    """Raised when a query create/update fails; triggers session close and exit."""
    pass

logger = setup_logger(log_file="migrate_queries.log", enable_console=True, format_log=True)


# ---------------------------------------------------------------------------
# Query migration
# ---------------------------------------------------------------------------

def create_or_overwrite_application_query(
    cxone_client: CxOneClient,
    session_id: str,
    application_id: str,
    application_name: str,
    query_group: ET.Element,
    query: ET.Element,
) -> bool:
    """
    Create or overwrite a single custom query at the application level in
    CxOne for the given application, using ``CxOneClient.create_query_override``.

    Parameters
    ----------
    cxone_client : CxOneClient
        An authenticated CxOne client instance.
    session_id : str
        The active Query Editor (Audit) session ID.
    application_id : str
        CxOne application ID that will own the override.
    application_name : str
        Human-readable application name (for logging).
    query_group : xml.etree.ElementTree.Element
        ``<CxWSQueryGroup>`` element from the CxSAST SOAP response.
    query : xml.etree.ElementTree.Element
        ``<CxWSQuery>`` element to migrate.

    Returns
    -------
    bool
        ``True`` on success, ``False`` on failure.
    """
    _ns = lambda el, tag: (
        el.findtext(f"{{http://Checkmarx.com}}{tag}") or el.findtext(tag) or ""
    )

    query_name  = _ns(query, "Name")
    language    = _ns(query_group, "LanguageName")
    group       = _ns(query_group, "Name")
    source      = _ns(query, "Source").strip(' \n')
    description = _ns(query, "Description") or 0
    cwe_str     = _ns(query, "Cwe")
    sev_str     = _ns(query, "Severity")
    exe_str     = _ns(query, "IsExecutable")

    cwe        = int(cwe_str) if cwe_str.isdigit() else 0
    severity   = int(sev_str) if sev_str.isdigit() else 1
    executable = bool(exe_str) and exe_str.strip().lower() == "true"

    if not query_name or not language:
        logger.debug(
            f"create_or_overwrite_application_query: skipping entry with "
            f"missing name or language (name={query_name!r}, lang={language!r})"
        )
        return False

    try:
        query_id = cxone_client.create_query_override(
            session_id=session_id,
            query_name=query_name,
            language=language,
            group=group,
            severity=severity,
            executable=executable,
            cwe=cwe,
            description=description,
            source=source,
            level="Application",
            application_id=application_id,
        )
        if query_id:
            logger.debug(
                f"  OK  '{query_name}' -> application '{application_name}' "
                f"(cxone_id={query_id!r})"
            )
            return True
        logger.debug(
            f"  FAILED  '{query_name}' -> application '{application_name}': "
            f"no query id returned"
        )
        return False
    except ValueError as exc:
        logger.debug(
            f"  FAILED  '{query_name}' -> application '{application_name}': {exc}"
        )
        return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_application_names(filepath: str) -> list[str]:
    """
    Read a plain-text file where each non-empty line is an application name.
    Lines starting with ``#`` are treated as comments and ignored.
    """
    names: list[str] = []
    with open(filepath, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if line and not line.startswith("#"):
                names.append(line)
    return names


def collect_queries_by_language(
    soap_client: CxSASTSOAPClient,
    language_filter: str | None = None,
) -> dict[str, list[tuple[ET.Element, ET.Element]]]:
    """
    Fetch all custom query groups from CxSAST and return a map of
    ``{language_name: [(query_group, query), ...]}`` held entirely in memory.

    The language name is taken from ``<LanguageName>`` in each
    ``<CxWSQueryGroup>`` element.  This is the value CxOne's Audit session
    ``filter`` field expects (e.g. ``"CSharp"``, ``"Java"``).

    Parameters
    ----------
    soap_client : CxSASTSOAPClient
        An authenticated SOAP client instance.
    language_filter : str | None
        If provided (lower-case), only include pairs for that language.

    Returns
    -------
    dict mapping each language name to its list of (group, query) pairs.
    """
    custom_groups = soap_client._get_custom_query_groups()

    queries_by_lang: dict[str, list[tuple[ET.Element, ET.Element]]] = defaultdict(list)

    for group in custom_groups:
        lang = soap_client._findtext(group, "LanguageName")
        if not lang:
            logger.debug(
                f"collect_queries_by_language: skipping group with no LanguageName "
                f"(PackageFullName={soap_client._findtext(group, 'PackageFullName')!r})"
            )
            continue

        if language_filter and lang.lower() != language_filter:
            continue

        queries_el = soap_client._find(group, "Queries")
        if queries_el is None:
            continue

        for query_el in soap_client._findall(queries_el, "CxWSQuery"):
            queries_by_lang[lang].append((group, query_el))

    for lang, pairs in queries_by_lang.items():
        logger.debug(
            f"collect_queries_by_language: {lang} -> {len(pairs)} query/queries"
        )

    return dict(queries_by_lang)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="CxSAST -> CxOne Custom Query Migration Tool",
    )

    parser.add_argument(
        "--config", "-c",
        type=str,
        required=True,
        help="Path to the configuration file (INI format).",
    )

    parser.add_argument(
        "--applications-file", "-f",
        type=str,
        required=True,
        metavar="FILE",
        help=(
            "Path to a plain-text file containing one CxOne application name "
            "per line.  Lines starting with '#' are ignored."
        ),
    )

    parser.add_argument(
        "--language", "-l",
        type=str,
        required=False,
        default=None,
        help=(
            "Restrict migration to a single language "
            "(e.g. CSharp, Java, JavaScript).  If omitted, all languages "
            "with custom queries are migrated, each in its own Audit session."
        ),
    )

    parser.add_argument(
        "--limit", "-n",
        type=int,
        required=False,
        default=None,
        metavar="N",
        help=(
            "Test throttle: process at most N queries per language. "
            "Applied after the language filter, before any Audit session is "
            "opened.  Omit for no limit."
        ),
    )

    parser.add_argument(
        "--exec", "-exec",
        action="store_true",
        default=False,
        dest="is_exec",
        help=(
            "Execution mode.  When absent (default) the script runs in "
            "dry-run mode: application name resolution and query fetching "
            "are performed but no Audit session is opened and no queries "
            "are created or modified in CxOne."
        ),
    )

    args = parser.parse_args()

    # ------------------------------------------------------------------ #
    # Configuration                                                        #
    # ------------------------------------------------------------------ #
    config = configparser.ConfigParser()
    config.read(args.config)

    iam_host      = config["CXONE"]["iam_host"]
    ast_host      = config["CXONE"]["ast_host"]
    tenant        = config["CXONE"]["tenant"]
    api_key       = config["CXONE"]["api_key"]

    sast_host     = config["CXSAST"]["host"]
    sast_user     = config["CXSAST"]["username"]
    sast_password = config["CXSAST"]["password"]

    is_exec         = args.is_exec
    language_filter = args.language.lower() if args.language else None
    query_limit     = args.limit
    csv_file        = f"migrate_queries_{args.language or 'all'}.csv"

    logger.info("-------------------------------------------------------------")
    logger.info("CxSAST -> CxOne Custom Query Migration")
    logger.info(f"AST Host       : {ast_host}")
    logger.info(f"IAM Host       : {iam_host}")
    logger.info(f"Tenant         : {tenant}")
    logger.info(f"SAST Host      : {sast_host}")
    logger.info(f"Language       : {args.language or '(all)'}")
    logger.info(f"Limit          : {query_limit if query_limit is not None else '(none)'}")
    logger.info(f"Apps file      : {args.applications_file}")
    logger.info(f"Mode           : {'EXECUTION' if is_exec else 'DRY-RUN (pass --exec to apply changes)'}")
    logger.info("-------------------------------------------------------------")

    # ------------------------------------------------------------------ #
    # Load the requested application names from disk                      #
    # ------------------------------------------------------------------ #
    requested_app_names = load_application_names(args.applications_file)
    if not requested_app_names:
        logger.info("ERROR: Applications file is empty or contains only comments.")
        exit(1)

    logger.info(f"Loaded {len(requested_app_names)} application name(s) from '{args.applications_file}'")

    # ------------------------------------------------------------------ #
    # CxOne: build application name -> ID map                             #
    # ------------------------------------------------------------------ #
    logger.info("Connecting to CxOne...")
    cxone_client = CxOneClient(iam_host, ast_host, tenant, api_key, False)

    logger.info("Fetching all CxOne applications...")
    id_to_name = cxone_client.get_all_applications_id_map()
    if not id_to_name:
        logger.info("ERROR: Could not retrieve applications from CxOne.")
        exit(1)

    logger.info(f"Found {len(id_to_name)} application(s) in CxOne tenant.")

    name_lower_to_id: dict[str, tuple[str, str]] = {
        name.lower(): (name, app_id)
        for app_id, name in id_to_name.items()
    }

    resolved: list[tuple[str, str]] = []
    unresolved: list[str] = []

    for req_name in requested_app_names:
        match = name_lower_to_id.get(req_name.lower())
        if match:
            resolved.append((match[0], match[1]))
        else:
            unresolved.append(req_name)

    if unresolved:
        logger.info(f"WARNING: {len(unresolved)} application name(s) not found in CxOne:")
        for u in unresolved:
            logger.info(f"  - {u}")

    if not resolved:
        logger.info("ERROR: None of the requested application names could be resolved.")
        exit(1)

    logger.info(f"Resolved {len(resolved)} / {len(requested_app_names)} application(s).")

    # ------------------------------------------------------------------ #
    # CxSAST SOAP: authenticate and fetch queries grouped by language     #
    # ------------------------------------------------------------------ #
    logger.info("Connecting to CxSAST...")
    soap_client = CxSASTSOAPClient(sast_host, sast_user, sast_password)
    soap_client.authenticate()

    logger.info("Fetching custom queries from CxSAST (grouped by language)...")
    queries_by_lang = collect_queries_by_language(soap_client, language_filter)

    if not queries_by_lang:
        logger.info("No custom queries found in CxSAST. Nothing to migrate.")
        exit(0)

    total_queries = sum(len(v) for v in queries_by_lang.values())
    logger.info(
        f"Fetched {total_queries} custom query/queries across "
        f"{len(queries_by_lang)} language(s): {', '.join(sorted(queries_by_lang))}."
    )

    # Apply per-language limit
    if query_limit is not None:
        queries_by_lang = {
            lang: pairs[:query_limit]
            for lang, pairs in queries_by_lang.items()
        }
        limited_total = sum(len(v) for v in queries_by_lang.values())
        logger.info(
            f"Limit applied: processing {limited_total} query/queries "
            f"({query_limit} per language)."
        )

    # ------------------------------------------------------------------ #
    # Migration loop -- one Audit session per language                    #
    # ------------------------------------------------------------------ #
    csv_rows: list[tuple[str, str, str, str, str]] = []
    total_attempted = 0
    total_succeeded = 0
    total_skipped   = 0
    total_failed    = 0

    nw = len("Query Name")
    gw = len("Group")
    lw = len("Language")
    aw = len("Application")
    sw = len("Status")

    fatal_error: str | None = None

    for lang, query_pairs in sorted(queries_by_lang.items()):
        logger.info(f"{'=' * 60}")
        logger.info(f" Language : {lang}  ({len(query_pairs)} queries)")
        logger.info(f"{'=' * 60}")

        session_id: str | None = None

        if is_exec:
            logger.info(f"  Opening Audit session for language '{lang}'...")
            session = cxone_client.start_audit_session(lang.lower())
            if not session:
                logger.info(
                    f"  ERROR: Failed to create Audit session for '{lang}'. "
                    f"Skipping this language."
                )
                for app_name, app_id in resolved:
                    for query_group, query in query_pairs:
                        q_name  = soap_client._findtext(query, "Name")
                        q_group = soap_client._findtext(query_group, "Name")
                        csv_rows.append((q_name, q_group, lang, app_name, "SESSION-FAILED"))
                        total_attempted += 1
                        total_failed    += 1
                        nw = max(nw, len(q_name)  + 2)
                        gw = max(gw, len(q_group) + 2)
                        aw = max(aw, len(app_name) + 2)
                continue

            session_id = session.get("id")
            logger.info(f"  Audit session created: {session_id}")
            logger.info("  Waiting for session to become ready...")
            _ = cxone_client.wait_for_audit_session_ready(session)
        else:
            logger.info(f"  dry-run - would open Audit session for language '{lang}'.")

        try:
            for app_name, app_id in resolved:
                logger.info(f"    Application : {app_name}  ({app_id})")
                app_attempted = 0
                app_succeeded = 0

                for query_group, query in query_pairs:
                    q_name  = soap_client._findtext(query, "Name")
                    q_group = soap_client._findtext(query_group, "Name")

                    total_attempted += 1
                    app_attempted   += 1

                    if not is_exec:
                        logger.info(
                            f"      dry-run - would migrate '{q_name}' "
                            f"[{lang}/{q_group}] -> application '{app_name}'"
                        )
                        status = "DRY-RUN"
                        total_skipped += 1
                    else:
                        ok = create_or_overwrite_application_query(
                            cxone_client=cxone_client,
                            session_id=session_id,
                            application_id=app_id,
                            application_name=app_name,
                            query_group=query_group,
                            query=query,
                        )
                        if ok:
                            total_succeeded += 1
                            app_succeeded   += 1
                            status = "OK"
                        else:
                            status = "FAILED"
                            total_failed += 1
                            raise FatalMigrationError(
                                f"Query create/update failed for '{q_name}' "
                                f"[{lang}/{q_group}] -> application '{app_name}'. "
                                f"Closing session and aborting."
                            )

                    csv_rows.append((q_name, q_group, lang, app_name, status))

                    nw = max(nw, len(q_name)  + 2)
                    gw = max(gw, len(q_group) + 2)
                    lw = max(lw, len(lang)    + 2)
                    aw = max(aw, len(app_name) + 2)
                    sw = max(sw, len(status)  + 2)

                if is_exec:
                    logger.info(
                        f"      -> {app_succeeded}/{app_attempted} queries migrated successfully."
                    )
                else:
                    logger.info(
                        f"      -> {app_attempted} queries would be migrated (dry-run)."
                    )

        except FatalMigrationError as e:
            logger.error(f"FATAL: {e}")
            fatal_error = str(e)
        finally:
            if session_id:
                logger.info(f"Closing Audit session {session_id}...")
                cxone_client.delete_audit_session(session_id)
                session_id = None

        if fatal_error:
            break

    # ------------------------------------------------------------------ #
    # Summary table                                                        #
    # ------------------------------------------------------------------ #
    header = (
        f"{'Query Name':{nw}} | {'Group':{gw}} | "
        f"{'Language':{lw}} | {'Application':{aw}} | {'Status':{sw}}"
    )
    sep = "-" * len(header)

    logger.info(f"Migration Results")
    logger.info(sep)
    logger.info(header)
    logger.info(sep)
    for q_name, q_group, q_lang, app_name, status in csv_rows:
        logger.info(
            f"{q_name:{nw}} | {q_group:{gw}} | "
            f"{q_lang:{lw}} | {app_name:{aw}} | {status:{sw}}"
        )
    logger.info(sep)
    logger.info(f"Languages processed    : {len(queries_by_lang)}")
    logger.info(f"Applications resolved  : {len(resolved)} / {len(requested_app_names)}")
    if unresolved:
        logger.info(f"Applications not found : {len(unresolved)}")
    logger.info(f"Total queries attempted: {total_attempted}")
    if not is_exec:
        logger.info(f"Dry-run (skipped)      : {total_skipped}")
    else:
        logger.info(f"Succeeded              : {total_succeeded}")
        logger.info(f"Failed                 : {total_failed}")

    # ------------------------------------------------------------------ #
    # CSV output                                                           #
    # ------------------------------------------------------------------ #
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Query Name", "Group", "Language", "Application", "Status"])
        for row in csv_rows:
            writer.writerow(row)

    logger.info(f"CSV written to {csv_file}")

    if fatal_error:
        logger.error("Exiting due to fatal migration error.")
        exit(1)


if __name__ == "__main__":
    main()
