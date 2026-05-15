"""
Xray Cloud pytest plugin — reports test results to Xray Cloud via GraphQL API.

Replacement for the legacy catium.plugins.xray plugin which was hardcoded to
Jira Server (jira.eng.tenable.com). This plugin uses Xray Cloud's GraphQL API
with JWT authentication and supports multiple @pytest.mark.xray markers per test.

Usage:
    pytest --enable-xray-cloud-reporting

Environment variables:
    XRAY_CLIENT_ID       - Xray Cloud API client ID
    XRAY_CLIENT_SECRET   - Xray Cloud API client secret
    XRAY_REGION          - Xray Cloud region: "global", "us", or "eu" (default: "us")
    CAT_XRAY_PROJECT_KEY - Jira project key for test execution (e.g. "NES")
    CAT_XRAY_TEST_EXECUTION_SUMMARY - Optional summary for the test execution issue
"""
