"""
Xray Cloud GraphQL client for authenticating and pushing test results.

Handles JWT authentication via client_id/client_secret and provides methods
for creating test executions and updating test run statuses via GraphQL mutations.
"""
import base64
import json
import mimetypes
import os
import time
import logging

import requests
import urllib3

log = logging.getLogger(__name__)


def _parse_jira_field(jira_data):
    """Parse the jira field which may be a JSON string or a dict."""
    if isinstance(jira_data, str):
        return json.loads(jira_data)
    return jira_data or {}

XRAY_REGIONS = {
    "global": "https://xray.cloud.getxray.app",
    "us": "https://us.xray.cloud.getxray.app",
    "eu": "https://eu.xray.cloud.getxray.app",
}


class XrayCloudClient:
    """Client for Xray Cloud GraphQL API with JWT authentication."""

    def __init__(self, client_id, client_secret, region="us", verify_ssl=True):
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = XRAY_REGIONS.get(region, XRAY_REGIONS["us"])
        self.graphql_url = f"{self.base_url}/api/v2/graphql"
        self.auth_url = f"{self.base_url}/api/v2/authenticate"
        self.verify_ssl = verify_ssl
        self.token = None
        self.session = requests.Session()
        if not verify_ssl:
            self.session.verify = False
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def authenticate(self):
        """Authenticate with Xray Cloud and obtain JWT token."""
        payload = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        resp = self.session.post(self.auth_url, json=payload)
        resp.raise_for_status()
        self.token = resp.json()
        self.session.headers["Authorization"] = f"Bearer {self.token}"
        log.info("Authenticated with Xray Cloud (%s)", self.base_url)

    def _graphql(self, query, variables=None, retries=3):
        """Execute a GraphQL query/mutation with retry on rate limiting."""
        if not self.token:
            self.authenticate()

        payload = {"query": query}
        if variables:
            payload["variables"] = variables

        for attempt in range(retries):
            resp = self.session.post(self.graphql_url, json=payload)
            if resp.status_code == 429:
                wait = 2 ** attempt + 1
                log.warning("Rate limited by Xray Cloud, waiting %ds...", wait)
                time.sleep(wait)
                continue
            if resp.status_code >= 400:
                log.error("GraphQL HTTP %d: %s", resp.status_code, resp.text[:500])
            resp.raise_for_status()
            data = resp.json()
            if "errors" in data:
                log.error("GraphQL errors: %s", data["errors"])
                raise RuntimeError(f"Xray GraphQL error: {data['errors']}")
            return data.get("data", {})

        raise RuntimeError("Xray Cloud rate limit exceeded after retries")

    def create_test_execution(self, project_key, summary=None):
        """Create a Test Execution issue in Xray Cloud via GraphQL mutation.

        Returns the test execution issue key (e.g. "NES-12345").
        """
        if not summary:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            summary = f"Automated Test Execution - {timestamp}"

        mutation = """
        mutation CreateTestExecution($projectKey: String!, $summary: String!) {
            createTestExecution(
                testIssueIds: [],
                jira: {
                    fields: {
                        summary: $summary,
                        project: { key: $projectKey }
                    }
                }
            ) {
                testExecution {
                    issueId
                    jira(fields: ["key"])
                }
                warnings
            }
        }
        """
        variables = {"projectKey": project_key, "summary": summary}
        result = self._graphql(mutation, variables)

        te = result.get("createTestExecution", {})
        if te.get("warnings"):
            log.warning("Xray warnings: %s", te["warnings"])

        issue_key = _parse_jira_field(te.get("testExecution", {}).get("jira")).get("key")
        issue_id = te.get("testExecution", {}).get("issueId")
        log.info("Created Test Execution: %s (issueId=%s)", issue_key, issue_id)
        return issue_key, issue_id

    def resolve_test_keys_to_ids(self, test_keys):
        """Resolve Jira issue keys (e.g. 'SCE-4405') to Jira issue IDs (e.g. '1504294').

        Uses the Xray getTests query with a JQL filter to look up issue IDs.
        Returns a dict mapping key -> issueId.
        """
        if not test_keys:
            return {}

        # Build JQL: key in (SCE-4405, NES-12345, ...)
        keys_str = ", ".join(test_keys)
        jql = f"key in ({keys_str})"

        query = """
        query GetTestsByJql($jql: String!, $limit: Int!) {
            getTests(jql: $jql, limit: $limit) {
                results {
                    issueId
                    jira(fields: ["key"])
                }
            }
        }
        """
        variables = {"jql": jql, "limit": len(test_keys) + 10}
        result = self._graphql(query, variables)

        key_to_id = {}
        for test in result.get("getTests", {}).get("results", []):
            key = _parse_jira_field(test.get("jira")).get("key")
            issue_id = test.get("issueId")
            if key and issue_id:
                key_to_id[key] = issue_id

        log.info("Resolved %d/%d test keys to issue IDs", len(key_to_id), len(test_keys))
        missing = set(test_keys) - set(key_to_id.keys())
        if missing:
            log.warning("Could not resolve keys: %s", missing)

        return key_to_id

    def add_tests_to_execution(self, test_exec_issue_id, test_issue_ids):
        """Add test cases to an existing test execution.

        Args:
            test_exec_issue_id: The Xray issue ID of the test execution
            test_issue_ids: List of Jira issue IDs (numeric strings, NOT keys)
        """
        if not test_issue_ids:
            return

        mutation = """
        mutation AddTestsToExecution($testExecIssueId: String!, $testIssueIds: [String!]!) {
            addTestsToTestExecution(
                issueId: $testExecIssueId,
                testIssueIds: $testIssueIds
            ) {
                addedTests
                warning
            }
        }
        """
        variables = {
            "testExecIssueId": test_exec_issue_id,
            "testIssueIds": test_issue_ids,
        }
        result = self._graphql(mutation, variables)
        added = result.get("addTestsToTestExecution", {})
        log.info("Added %s tests to execution", added.get("addedTests", []))
        if added.get("warning"):
            log.warning("Xray warning: %s", added["warning"])

    def get_test_run(self, test_exec_issue_id, test_issue_id):
        """Get a specific test run by test execution and test issue ID.

        Returns the test run dict with 'id', 'status', etc., or None if not found.
        """
        query = """
        query GetTestRun($testExecIssueId: String!, $testIssueId: String!) {
            getTestRun(testExecIssueId: $testExecIssueId, testIssueId: $testIssueId) {
                id
                status {
                    name
                }
                test {
                    issueId
                    jira(fields: ["key"])
                }
            }
        }
        """
        variables = {"testExecIssueId": test_exec_issue_id, "testIssueId": test_issue_id}
        result = self._graphql(query, variables)
        return result.get("getTestRun")

    def update_test_run_status(self, test_run_id, status):
        """Update the status of a single test run.

        Args:
            test_run_id: The Xray test run ID
            status: One of "PASSED", "FAILED", "TODO", "EXECUTING"
        """
        mutation = """
        mutation UpdateTestRunStatus($id: String!, $status: String!) {
            updateTestRunStatus(id: $id, status: $status)
        }
        """
        variables = {"id": test_run_id, "status": status}
        self._graphql(mutation, variables)

    def update_test_run_comment(self, test_run_id, comment):
        """Add or update the comment on a test run.

        Args:
            test_run_id: The Xray test run ID
            comment: Plain text comment to attach to the test run
        """
        # Xray Cloud has an 8192 char limit for comments
        max_len = 8192
        if len(comment) > max_len:
            comment = comment[:max_len - 50] + "\n\n... [truncated to 8192 char limit]"

        mutation = """
        mutation UpdateTestRunComment($id: String!, $comment: String!) {
            updateTestRunComment(id: $id, comment: $comment)
        }
        """
        variables = {"id": test_run_id, "comment": comment}
        self._graphql(mutation, variables)
        log.debug("Added comment to test run %s", test_run_id)

    def add_evidence_to_test_run(self, test_run_id, file_path):
        """Add a file as evidence to a test run.

        Args:
            test_run_id: The Xray test run ID
            file_path: Path to the file to attach (screenshot, log, etc.)
        """
        if not os.path.isfile(file_path):
            log.warning("Evidence file not found: %s", file_path)
            return

        filename = os.path.basename(file_path)
        mime_type = mimetypes.guess_type(file_path)[0] or "application/octet-stream"

        with open(file_path, "rb") as f:
            file_data = base64.b64encode(f.read()).decode("ascii")

        mutation = """
        mutation AddEvidence($id: String!, $evidence: [AttachmentDataInput]!) {
            addEvidenceToTestRun(id: $id, evidence: $evidence) {
                addedEvidence
                warnings
            }
        }
        """
        variables = {
            "id": test_run_id,
            "evidence": [{
                "filename": filename,
                "mimeType": mime_type,
                "data": file_data,
            }],
        }
        self._graphql(mutation, variables)
        log.debug("Added evidence '%s' to test run %s", filename, test_run_id)

    def resolve_issue_key_to_id(self, issue_key):
        """Resolve a single Jira issue key to its issue ID via Xray GraphQL."""
        query = """
        query GetTestExecution($jql: String!) {
            getTestExecutions(jql: $jql, limit: 1) {
                results {
                    issueId
                    jira(fields: ["key"])
                }
            }
        }
        """
        variables = {"jql": f"key = {issue_key}"}
        result = self._graphql(query, variables)
        results = result.get("getTestExecutions", {}).get("results", [])
        if results:
            return results[0].get("issueId")
        log.warning("Could not resolve issue key %s to ID", issue_key)
        return None

    def report_results(self, project_key, test_results, summary=None,
                       existing_test_exec_key=None, test_evidence=None):
        """High-level method to create or reuse execution and report all results.

        Args:
            project_key: Jira project key (e.g. "NES")
            test_results: dict mapping test_key -> "PASSED" or "FAILED"
                          e.g. {"NES-12345": "PASSED", "NES-12346": "FAILED"}
            summary: Optional summary for the test execution
            existing_test_exec_key: If provided, use this existing Test Execution
                                    (e.g. "SCE-4409") instead of creating a new one
            test_evidence: dict mapping test_key -> {
                              "comment": str (optional),
                              "evidence_files": list of file paths (optional)
                           }

        Returns:
            Tuple of (test_exec_key, test_exec_url)
        """
        if not test_results:
            log.info("No test results with Xray markers to report.")
            return None, None

        if existing_test_exec_key:
            # Use existing test execution
            test_exec_key = existing_test_exec_key
            test_exec_issue_id = self.resolve_issue_key_to_id(existing_test_exec_key)
            if not test_exec_issue_id:
                raise RuntimeError(
                    f"Could not resolve existing Test Execution '{existing_test_exec_key}' to an issue ID"
                )
            log.info("Using existing Test Execution: %s (issueId=%s)", test_exec_key, test_exec_issue_id)
        else:
            # Create a new test execution
            test_exec_key, test_exec_issue_id = self.create_test_execution(
                project_key, summary
            )

        # Resolve test keys (e.g. "SCE-4405") to Jira issue IDs (e.g. "1504294")
        test_keys = list(test_results.keys())
        key_to_id = self.resolve_test_keys_to_ids(test_keys)

        # Add tests by their numeric issue IDs
        test_issue_ids = [key_to_id[k] for k in test_keys if k in key_to_id]
        self.add_tests_to_execution(test_exec_issue_id, test_issue_ids)

        # Look up the test run ID for each key directly
        key_to_run_id = {}
        for test_key in test_keys:
            test_issue_id = key_to_id.get(test_key)
            if not test_issue_id:
                continue
            run = self.get_test_run(test_exec_issue_id, test_issue_id)
            if run and run.get("id"):
                key_to_run_id[test_key] = run["id"]
                log.debug("Resolved %s -> run_id %s", test_key, run["id"])
            else:
                log.warning("No test run found for %s (issueId=%s) in execution", test_key, test_issue_id)

        # Update each test run status, comment, and evidence
        test_evidence = test_evidence or {}
        updated = 0
        for test_key, status in test_results.items():
            run_id = key_to_run_id.get(test_key)
            if run_id:
                self.update_test_run_status(run_id, status)
                updated += 1
                log.debug("Updated %s -> %s", test_key, status)

                # Add comment and evidence — don't let errors here abort other tests
                evidence = test_evidence.get(test_key, {})
                try:
                    comment = evidence.get("comment")
                    if comment:
                        self.update_test_run_comment(run_id, comment)

                    for filepath in evidence.get("evidence_files", []):
                        self.add_evidence_to_test_run(run_id, filepath)
                except Exception:
                    log.exception("Failed to add evidence for %s, continuing", test_key)
            else:
                log.warning("No test run found for %s in execution %s", test_key, test_exec_key)

        log.info("Updated %d/%d test run statuses in %s", updated, len(test_results), test_exec_key)

        # Build the browsable URL
        jira_domain = os.getenv("JIRA_DOMAIN", "tenable.atlassian.net")
        test_exec_url = f"https://{jira_domain}/browse/{test_exec_key}"

        return test_exec_key, test_exec_url
