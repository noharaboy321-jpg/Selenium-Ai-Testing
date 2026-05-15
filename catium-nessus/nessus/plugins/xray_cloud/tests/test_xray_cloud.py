"""
Unit tests for the Xray Cloud pytest plugin and GraphQL client.

Tests cover:
- plugin.py: marker extraction, screenshot finding, evidence building
- client.py: jira field parsing, authentication, GraphQL calls, result reporting

Run with: pytest nessus/plugins/xray_cloud/tests/
"""
import os
from unittest.mock import MagicMock, patch

import pytest

from nessus.plugins.xray_cloud.client import XrayCloudClient, _parse_jira_field
from nessus.plugins.xray_cloud.plugin import (
    _extract_xray_keys,
    _find_screenshots,
    _build_evidence,
)


# ---------------------------------------------------------------------------
# _parse_jira_field
# ---------------------------------------------------------------------------

class TestParseJiraField:

    def test_dict_unchanged(self):
        assert _parse_jira_field({"key": "NES-123"}) == {"key": "NES-123"}

    def test_json_string(self):
        assert _parse_jira_field('{"key": "NES-123"}') == {"key": "NES-123"}

    def test_none_returns_empty_dict(self):
        assert _parse_jira_field(None) == {}

    def test_empty_dict(self):
        assert _parse_jira_field({}) == {}


# ---------------------------------------------------------------------------
# _extract_xray_keys
# ---------------------------------------------------------------------------

class TestExtractXrayKeys:

    def _make_marker(self, kwargs=None, args=None):
        m = MagicMock()
        m.kwargs = kwargs or {}
        m.args = args or ()
        return m

    def test_keyword_arg(self):
        item = MagicMock()
        item.iter_markers.return_value = [self._make_marker(kwargs={'test_key': 'NES-123'})]
        assert _extract_xray_keys(item) == ['NES-123']

    def test_positional_arg(self):
        item = MagicMock()
        item.iter_markers.return_value = [self._make_marker(args=('NES-456',))]
        assert _extract_xray_keys(item) == ['NES-456']

    def test_multiple_markers(self):
        item = MagicMock()
        item.iter_markers.return_value = [
            self._make_marker(kwargs={'test_key': 'NES-100'}),
            self._make_marker(kwargs={'test_key': 'NES-200'}),
        ]
        assert _extract_xray_keys(item) == ['NES-100', 'NES-200']

    def test_no_markers(self):
        item = MagicMock()
        item.iter_markers.return_value = []
        assert _extract_xray_keys(item) == []

    def test_mixed_keyword_and_positional(self):
        item = MagicMock()
        item.iter_markers.return_value = [
            self._make_marker(kwargs={'test_key': 'NES-1'}, args=('NES-2',)),
        ]
        assert _extract_xray_keys(item) == ['NES-1', 'NES-2']


# ---------------------------------------------------------------------------
# _find_screenshots
# ---------------------------------------------------------------------------

class TestFindScreenshots:

    def test_no_output_dir(self, tmp_path):
        with patch('nessus.plugins.xray_cloud.plugin.os.getcwd', return_value=str(tmp_path)):
            assert _find_screenshots("test_file.py::TestClass::test_method") == []

    def test_finds_matching_screenshots(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "test_method_failure.png").touch()
        (output_dir / "unrelated.png").touch()

        with patch('nessus.plugins.xray_cloud.plugin.os.getcwd', return_value=str(tmp_path)):
            result = _find_screenshots("test_file.py::TestClass::test_method")
            assert any("test_method_failure.png" in f for f in result)
            assert not any("unrelated.png" in f for f in result)

    def test_finds_screenshots_in_subdirectory(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        screenshots_dir = output_dir / "screenshots"
        screenshots_dir.mkdir()
        (screenshots_dir / "F-test_method_failure.png").touch()
        (output_dir / "unrelated.png").touch()

        with patch('nessus.plugins.xray_cloud.plugin.os.getcwd', return_value=str(tmp_path)):
            result = _find_screenshots("test_file.py::TestClass::test_method")
            assert any("F-test_method_failure.png" in f for f in result)
            assert not any("unrelated.png" in f for f in result)

    def test_handles_parametrized_brackets(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "test_export_policy[create_policy0]_fail.png").touch()

        with patch('nessus.plugins.xray_cloud.plugin.os.getcwd', return_value=str(tmp_path)):
            result = _find_screenshots(
                "test_file.py::TestClass::test_export_policy[create_policy0]"
            )
            assert len(result) == 1


# ---------------------------------------------------------------------------
# _build_evidence
# ---------------------------------------------------------------------------

class TestBuildEvidence:

    def _make_report(self, nodeid="test.py::Test::test_it", duration=1.0, longreprtext=""):
        report = MagicMock()
        report.nodeid = nodeid
        report.duration = duration
        report.longreprtext = longreprtext
        return report

    def test_passed(self):
        report = self._make_report(duration=1.23)
        with patch('nessus.plugins.xray_cloud.plugin._find_screenshots', return_value=[]):
            evidence = _build_evidence(report, "passed")
        assert "PASSED" in evidence["comment"]
        assert "1.23s" in evidence["comment"]

    def test_failed_includes_traceback(self):
        report = self._make_report(longreprtext="AssertionError: expected True")
        with patch('nessus.plugins.xray_cloud.plugin._find_screenshots', return_value=[]):
            evidence = _build_evidence(report, "failed")
        assert "FAILED" in evidence["comment"]
        assert "AssertionError" in evidence["comment"]

    def test_long_traceback_truncated(self):
        report = self._make_report(longreprtext="x" * 5000)
        with patch('nessus.plugins.xray_cloud.plugin._find_screenshots', return_value=[]):
            evidence = _build_evidence(report, "failed")
        assert "[truncated]" in evidence["comment"]

    def test_includes_screenshot_files(self):
        report = self._make_report()
        with patch('nessus.plugins.xray_cloud.plugin._find_screenshots',
                   return_value=["/output/test_it.png"]):
            evidence = _build_evidence(report, "passed")
        assert evidence["evidence_files"] == ["/output/test_it.png"]


# ---------------------------------------------------------------------------
# XrayCloudClient
# ---------------------------------------------------------------------------

class TestXrayCloudClient:

    def _make_client(self):
        client = XrayCloudClient("id", "secret", region="us", verify_ssl=False)
        client.token = "fake-token"
        return client

    def _mock_graphql_response(self, data):
        resp = MagicMock()
        resp.status_code = 200
        resp.raise_for_status = MagicMock()
        resp.json.return_value = {"data": data}
        return resp

    # -- authenticate --

    def test_authenticate(self):
        client = self._make_client()
        client.token = None

        mock_resp = MagicMock()
        mock_resp.json.return_value = "jwt-token-123"
        client.session.post = MagicMock(return_value=mock_resp)

        client.authenticate()

        assert client.token == "jwt-token-123"
        assert client.session.headers["Authorization"] == "Bearer jwt-token-123"
        client.session.post.assert_called_once()

    # -- _graphql --

    def test_graphql_retry_on_rate_limit(self):
        client = self._make_client()
        resp_429 = MagicMock(status_code=429)
        resp_200 = self._mock_graphql_response({"result": "ok"})
        client.session.post = MagicMock(side_effect=[resp_429, resp_200])

        with patch('nessus.plugins.xray_cloud.client.time.sleep'):
            result = client._graphql("query { test }")

        assert result == {"result": "ok"}
        assert client.session.post.call_count == 2

    def test_graphql_raises_on_errors(self):
        client = self._make_client()
        resp = MagicMock(status_code=200)
        resp.raise_for_status = MagicMock()
        resp.json.return_value = {"errors": [{"message": "something broke"}]}
        client.session.post = MagicMock(return_value=resp)

        with pytest.raises(RuntimeError, match="Xray GraphQL error"):
            client._graphql("query { test }")

    # -- create_test_execution --

    def test_create_test_execution(self):
        client = self._make_client()
        client.session.post = MagicMock(return_value=self._mock_graphql_response({
            "createTestExecution": {
                "testExecution": {"issueId": "12345", "jira": {"key": "NES-100"}},
                "warnings": []
            }
        }))

        key, issue_id = client.create_test_execution("NES", "Test Summary")
        assert key == "NES-100"
        assert issue_id == "12345"

    def test_create_test_execution_jira_as_string(self):
        client = self._make_client()
        client.session.post = MagicMock(return_value=self._mock_graphql_response({
            "createTestExecution": {
                "testExecution": {"issueId": "12345", "jira": '{"key": "NES-100"}'},
                "warnings": []
            }
        }))

        key, issue_id = client.create_test_execution("NES", "Test Summary")
        assert key == "NES-100"

    # -- resolve_test_keys_to_ids --

    def test_resolve_test_keys(self):
        client = self._make_client()
        client.session.post = MagicMock(return_value=self._mock_graphql_response({
            "getTests": {
                "results": [
                    {"issueId": "111", "jira": {"key": "NES-1"}},
                    {"issueId": "222", "jira": {"key": "NES-2"}},
                ]
            }
        }))

        result = client.resolve_test_keys_to_ids(["NES-1", "NES-2", "NES-3"])
        assert result == {"NES-1": "111", "NES-2": "222"}

    def test_resolve_empty_keys(self):
        client = self._make_client()
        assert client.resolve_test_keys_to_ids([]) == {}

    # -- update_test_run_comment --

    def test_comment_truncation(self):
        client = self._make_client()
        client.session.post = MagicMock(
            return_value=self._mock_graphql_response({"updateTestRunComment": None})
        )

        client.update_test_run_comment("run-1", "x" * 10000)

        payload = client.session.post.call_args[1]["json"]
        sent_comment = payload["variables"]["comment"]
        assert len(sent_comment) <= 8192
        assert "[truncated" in sent_comment

    # -- add_evidence_to_test_run --

    def test_evidence_missing_file(self, tmp_path):
        client = self._make_client()
        client.session.post = MagicMock()

        client.add_evidence_to_test_run("run-1", str(tmp_path / "nonexistent.png"))
        client.session.post.assert_not_called()

    def test_evidence_valid_file(self, tmp_path):
        client = self._make_client()
        client.session.post = MagicMock(
            return_value=self._mock_graphql_response({
                "addEvidenceToTestRun": {"addedEvidence": ["screenshot.png"], "warnings": []}
            })
        )

        test_file = tmp_path / "screenshot.png"
        test_file.write_bytes(b"fake png data")

        client.add_evidence_to_test_run("run-1", str(test_file))
        assert client.session.post.called

        # Verify the mutation uses correct GraphQL type
        payload = client.session.post.call_args[1]["json"]
        assert "AttachmentDataInput" in payload["query"]
        assert "addedEvidence" in payload["query"]
        assert payload["variables"]["evidence"][0]["filename"] == "screenshot.png"

    # -- report_results --

    def test_report_empty_results(self):
        client = self._make_client()
        key, url = client.report_results("NES", {})
        assert key is None
        assert url is None

    def test_report_uses_jira_domain_env(self):
        client = self._make_client()
        client.create_test_execution = MagicMock(return_value=("NES-999", "99999"))
        client.resolve_test_keys_to_ids = MagicMock(return_value={"NES-1": "111"})
        client.add_tests_to_execution = MagicMock()
        client.get_test_run = MagicMock(return_value={"id": "run-1"})
        client.update_test_run_status = MagicMock()

        with patch.dict(os.environ, {"JIRA_DOMAIN": "custom.atlassian.net"}):
            key, url = client.report_results("NES", {"NES-1": "PASSED"})

        assert "custom.atlassian.net" in url
        assert key == "NES-999"

    def test_report_existing_execution(self):
        client = self._make_client()
        client.resolve_issue_key_to_id = MagicMock(return_value="88888")
        client.resolve_test_keys_to_ids = MagicMock(return_value={"NES-1": "111"})
        client.add_tests_to_execution = MagicMock()
        client.get_test_run = MagicMock(return_value={"id": "run-1"})
        client.update_test_run_status = MagicMock()

        key, url = client.report_results(
            "NES", {"NES-1": "PASSED"}, existing_test_exec_key="NES-500"
        )

        assert key == "NES-500"
        client.resolve_issue_key_to_id.assert_called_once_with("NES-500")

    def test_report_existing_execution_not_found(self):
        client = self._make_client()
        client.resolve_issue_key_to_id = MagicMock(return_value=None)

        with pytest.raises(RuntimeError, match="Could not resolve"):
            client.report_results(
                "NES", {"NES-1": "PASSED"}, existing_test_exec_key="NES-999"
            )

    def test_report_skips_unresolved_keys(self):
        client = self._make_client()
        client.create_test_execution = MagicMock(return_value=("NES-999", "99999"))
        client.resolve_test_keys_to_ids = MagicMock(return_value={})
        client.add_tests_to_execution = MagicMock()
        client.update_test_run_status = MagicMock()

        key, url = client.report_results("NES", {"NES-MISSING": "PASSED"})

        assert key == "NES-999"
        client.update_test_run_status.assert_not_called()
