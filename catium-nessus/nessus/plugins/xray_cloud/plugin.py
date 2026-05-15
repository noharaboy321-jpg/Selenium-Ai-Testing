"""
Xray Cloud pytest plugin — collects @pytest.mark.xray markers and reports
test results to Xray Cloud after the test session completes.

This is a drop-in replacement for catium.plugins.xray that fixes:
1. Hardcoded on-prem Jira URL → uses Xray Cloud GraphQL API
2. Single marker per test → supports multiple @pytest.mark.xray markers
3. Hardcoded project key → configurable via env var / CLI option

Usage:
    pytest --enable-xray-cloud-reporting

    # With custom project key (overrides CAT_XRAY_PROJECT_KEY env var):
    pytest --enable-xray-cloud-reporting --xray-project-key NES

Environment variables:
    XRAY_CLIENT_ID       - Xray Cloud API client ID (required)
    XRAY_CLIENT_SECRET   - Xray Cloud API client secret (required)
    XRAY_REGION          - "global", "us", or "eu" (default: "us")
    CAT_XRAY_PROJECT_KEY - Jira project key for test execution
    CAT_XRAY_TEST_EXECUTION_SUMMARY - Optional summary text
"""
import glob
import os
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from catium.lib.typechecking import Parser

log = logging.getLogger(__name__)

# Status mapping from pytest outcome to Xray Cloud status
PYTEST_TO_XRAY = {
    "passed": "PASSED",
    "failed": "FAILED",
    "error": "FAILED",
}


def pytest_addoption(parser: 'Parser'):
    """Register command-line options for Xray Cloud reporting."""
    group = parser.getgroup('xray-cloud', 'Xray Cloud test reporting')
    group.addoption(
        '--enable-xray-cloud-reporting',
        action='store_true',
        dest='enable_xray_cloud_reporting',
        default=False,
        help="Push test results to Xray Cloud via GraphQL API",
    )
    group.addoption(
        '--xray-project-key',
        dest='xray_project_key',
        default=None,
        help="Jira project key for test execution (overrides CAT_XRAY_PROJECT_KEY env var)",
    )
    group.addoption(
        '--xray-region',
        dest='xray_region',
        default=None,
        help="Xray Cloud region: global, us, eu (overrides XRAY_REGION env var, default: us)",
    )
    group.addoption(
        '--xray-test-execution',
        dest='xray_test_execution',
        default=None,
        help="Use an existing Test Execution issue key (e.g. SCE-4409) instead of creating a new one",
    )
    group.addoption(
        '--xray-no-verify-ssl',
        action='store_true',
        dest='xray_no_verify_ssl',
        default=False,
        help="Disable SSL certificate verification for Xray Cloud API calls",
    )
    group.addoption(
        '--xray-keys',
        dest='xray_keys',
        default=None,
        help="Comma-separated list of Xray test keys to select (e.g. SCE-3312,NES-13893). "
             "Only tests with matching @pytest.mark.xray markers will run.",
    )


def pytest_configure(config):
    """Register the xray marker."""
    config.addinivalue_line(
        "markers",
        "xray(test_key): Link a test to one or more Xray Cloud test case keys",
    )


def _extract_xray_keys(item):
    """Extract all xray test keys from a test item's markers."""
    test_keys = []
    for marker in item.iter_markers(name='xray'):
        test_key = marker.kwargs.get('test_key')
        if test_key:
            test_keys.append(test_key)
        # Also support positional: @pytest.mark.xray("NES-123")
        if marker.args:
            test_keys.extend(marker.args)
    return test_keys


def pytest_collection_modifyitems(config, items):
    """Collect all xray markers from test items during collection.

    Unlike the legacy plugin which only captured one marker per test,
    this collects ALL @pytest.mark.xray markers (including inherited from class).

    When --xray-keys is specified, deselects tests that don't match any of the
    requested keys (works independently of --enable-xray-cloud-reporting).
    """
    reporting_enabled = config.getoption('enable_xray_cloud_reporting')
    keys_filter = config.getoption('xray_keys')
    filter_set = set(k.strip() for k in keys_filter.split(',')) if keys_filter else None

    if not reporting_enabled and not filter_set:
        return

    xray_map = {}  # nodeid -> list of test_keys
    selected = []
    deselected = []

    for item in items:
        test_keys = _extract_xray_keys(item)

        if test_keys:
            xray_map[item.nodeid] = test_keys
            log.debug("Collected xray markers for %s: %s", item.nodeid, test_keys)

        if filter_set is not None:
            if test_keys and filter_set.intersection(test_keys):
                selected.append(item)
            else:
                deselected.append(item)

    # Apply key-based filtering
    if filter_set is not None:
        items[:] = selected
        if deselected:
            config.hook.pytest_deselected(items=deselected)
        log.info("Xray key filter: %d selected, %d deselected (keys: %s)",
                 len(selected), len(deselected), ', '.join(sorted(filter_set)))

    # Store on config so terminal_summary can access it
    config._xray_cloud_map = xray_map
    log.info("Collected %d tests with xray markers (%d total test keys)",
             len(xray_map), sum(len(v) for v in xray_map.values()))


def _build_evidence(report, outcome):
    """Build evidence dict from a pytest report.

    Returns a dict with "comment" and/or "evidence_files" keys, or None.
    """
    evidence = {}
    parts = []

    # Always include the node ID and duration
    parts.append(f"Test: {report.nodeid}")
    if hasattr(report, 'duration'):
        parts.append(f"Duration: {report.duration:.2f}s")

    if outcome == "passed":
        parts.append("Result: PASSED")
    elif outcome in ("failed", "error"):
        parts.append(f"Result: {'FAILED' if outcome == 'failed' else 'ERROR'}")
        # Include the failure representation (traceback/assertion)
        if hasattr(report, 'longreprtext') and report.longreprtext:
            tb = report.longreprtext
            # Truncate very long tracebacks to keep the comment readable
            if len(tb) > 4000:
                tb = tb[:2000] + "\n\n... [truncated] ...\n\n" + tb[-1500:]
            parts.append(f"\n--- Traceback ---\n{tb}")

    if parts:
        evidence["comment"] = "\n".join(parts)

    # Look for screenshots in the output directory
    # Catium saves screenshots as output/<test_name>_*.png
    evidence_files = _find_screenshots(report.nodeid)
    if evidence_files:
        evidence["evidence_files"] = evidence_files

    return evidence if evidence else None


def _find_screenshots(nodeid):
    """Find screenshot files that match a test's node ID.

    Catium saves screenshots to output/ with the test name in the filename.
    """
    screenshots = []
    output_dir = os.path.join(os.getcwd(), "output")
    if not os.path.isdir(output_dir):
        return screenshots

    # Extract test name from nodeid: "path/to/test.py::Class::test_method" -> "test_method"
    test_name = nodeid.split("::")[-1]
    # Also try class::method combo
    parts = nodeid.split("::")
    class_method = "_".join(parts[-2:]) if len(parts) >= 2 else test_name

    # Search both output/ and output/screenshots/ (Catium saves screenshots in the subdirectory)
    search_dirs = [output_dir, os.path.join(output_dir, "screenshots")]

    escaped_test_name = glob.escape(test_name)
    escaped_class_method = glob.escape(class_method)

    for search_dir in search_dirs:
        if not os.path.isdir(search_dir):
            continue
        for pattern in (f"*{escaped_test_name}*.png", f"*{escaped_class_method}*.png",
                        f"*{escaped_test_name}*.jpg", f"*{escaped_test_name}*.html"):
            screenshots.extend(glob.glob(os.path.join(search_dir, pattern)))

    # Deduplicate and return
    return list(set(screenshots))


def pytest_terminal_summary(terminalreporter):
    """After all tests complete, push results to Xray Cloud."""
    config = terminalreporter.config

    if not config.getoption('enable_xray_cloud_reporting'):
        return

    xray_map = getattr(config, '_xray_cloud_map', {})
    if not xray_map:
        log.info("Xray Cloud: No tests with @pytest.mark.xray markers found. Skipping.")
        return

    # Resolve configuration
    client_id = os.environ.get('XRAY_CLIENT_ID')
    client_secret = os.environ.get('XRAY_CLIENT_SECRET')
    if not client_id or not client_secret:
        log.error("XRAY_CLIENT_ID and XRAY_CLIENT_SECRET must be set. Skipping Xray reporting.")
        return

    project_key = (
        config.getoption('xray_project_key')
        or os.environ.get('CAT_XRAY_PROJECT_KEY')
    )
    if not project_key:
        log.error("No project key specified. Use --xray-project-key or CAT_XRAY_PROJECT_KEY env var.")
        return

    region = (
        config.getoption('xray_region')
        or os.environ.get('XRAY_REGION', 'us')
    )
    verify_ssl = not config.getoption('xray_no_verify_ssl')
    summary = os.environ.get('CAT_XRAY_TEST_EXECUTION_SUMMARY')

    # Build results: map each test_key to its pytest outcome
    # If a test has multiple xray markers, each key gets the same result.
    # If the same key appears on multiple tests (parametrized), use the worst result (FAILED > PASSED).
    # Evidence is accumulated across all parametrized runs of the same key.
    test_results = {}
    test_evidence = {}  # test_key -> {"comment": str, "evidence_files": [paths]}
    _run_entries = {}  # test_key -> list of per-run comment strings

    for outcome in ("passed", "failed"):
        if outcome not in terminalreporter.stats:
            continue
        xray_status = PYTEST_TO_XRAY[outcome]
        for report in terminalreporter.stats[outcome]:
            # Only look at the "call" phase (not setup/teardown)
            if report.when != "call":
                continue
            test_keys = xray_map.get(report.nodeid, [])
            for key in test_keys:
                # FAILED takes priority over PASSED
                if key in test_results and test_results[key] == "FAILED":
                    pass  # keep FAILED but still collect evidence below
                else:
                    test_results[key] = xray_status

                # Accumulate evidence from each parametrized run
                evidence = _build_evidence(report, outcome)
                if evidence:
                    _run_entries.setdefault(key, []).append(evidence.get("comment", ""))
                    # Collect screenshot evidence files from all runs
                    test_evidence.setdefault(key, {"evidence_files": []})
                    test_evidence[key]["evidence_files"].extend(
                        evidence.get("evidence_files", [])
                    )

    # Also check for errors (setup/teardown failures)
    if "error" in terminalreporter.stats:
        for report in terminalreporter.stats["error"]:
            test_keys = xray_map.get(report.nodeid, [])
            for key in test_keys:
                test_results[key] = "FAILED"
                evidence = _build_evidence(report, "error")
                if evidence:
                    _run_entries.setdefault(key, []).append(evidence.get("comment", ""))
                    test_evidence.setdefault(key, {"evidence_files": []})
                    test_evidence[key]["evidence_files"].extend(
                        evidence.get("evidence_files", [])
                    )

    # Merge accumulated run entries into a single comment per test key
    for key, entries in _run_entries.items():
        if len(entries) == 1:
            test_evidence.setdefault(key, {})["comment"] = entries[0]
        else:
            header = f"{len(entries)} parametrized runs:"
            separator = "\n" + "=" * 60 + "\n"
            test_evidence.setdefault(key, {})["comment"] = (
                header + separator + separator.join(entries)
            )

    if not test_results:
        log.info("Xray Cloud: No matched test results to report.")
        return

    log.info("Xray Cloud reporting: %d test keys to push (%d PASSED, %d FAILED)",
             len(test_results),
             sum(1 for v in test_results.values() if v == "PASSED"),
             sum(1 for v in test_results.values() if v == "FAILED"))

    # Push results to Xray Cloud
    from .client import XrayCloudClient

    try:
        client = XrayCloudClient(
            client_id=client_id,
            client_secret=client_secret,
            region=region,
            verify_ssl=verify_ssl,
        )
        existing_exec = config.getoption('xray_test_execution')
        client.authenticate()
        test_exec_key, test_exec_url = client.report_results(
            project_key=project_key,
            test_results=test_results,
            summary=summary,
            existing_test_exec_key=existing_exec,
            test_evidence=test_evidence,
        )
        if test_exec_key:
            terminalreporter.write_line(
                f"\nXray Cloud: Test results published to {test_exec_key}",
                bold=True,
            )
            terminalreporter.write_line(f"  URL: {test_exec_url}")
            terminalreporter.write_line(
                f"  Results: {sum(1 for v in test_results.values() if v == 'PASSED')} passed, "
                f"{sum(1 for v in test_results.values() if v == 'FAILED')} failed, "
                f"{len(test_results)} total"
            )
    except Exception:
        log.exception("Failed to push results to Xray Cloud")
        terminalreporter.write_line(
            "\nXray Cloud: ERROR - Failed to push test results. Check logs for details.",
            red=True,
        )
