#!/usr/bin/env python3
"""Xray Test Coverage Audit Script.

Audits automated tests in nessus/tests/ against test cases tracked in
Xray Cloud (projects NES and SCE). Identifies coverage gaps and fetches
test steps from Xray to verify automation correctness.

Modes:
    --local-only     Parse local tests only (no credentials needed)
    --jira           Discover tests via Jira REST API (keys + summaries)
    --jira-xray      Jira discovers keys, Xray enriches with test steps (recommended)
    (default)        Xray GraphQL only

Environment variables:
    JIRA_DOMAIN, JIRA_EMAIL, JIRA_API_TOKEN   (for --jira / --jira-xray)
    XRAY_CLIENT_ID, XRAY_CLIENT_SECRET        (for --jira-xray / default)
"""

import argparse
import ast
import csv
import json
import os
import re
import sys
import time
from collections import defaultdict
from pathlib import Path

import requests

XRAY_REGIONS = {
    "global": "https://xray.cloud.getxray.app",
    "us": "https://us.xray.cloud.getxray.app",
    "eu": "https://eu.xray.cloud.getxray.app",
}

ISSUE_ID_PATTERN = re.compile(r'\b(NES|NQA|SCE)-\d+\b')


class XrayClient:
    """Client for Xray Cloud GraphQL API."""

    def __init__(self, client_id, client_secret, verify_ssl=True, region="us"):
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = None
        self.session = requests.Session()
        self.session.verify = verify_ssl
        base = XRAY_REGIONS.get(region, XRAY_REGIONS["us"])
        self.auth_url = f"{base}/api/v2/authenticate"
        self.graphql_url = f"{base}/api/v2/graphql"

    def authenticate(self):
        """Authenticate with Xray Cloud and obtain a JWT token."""
        resp = self.session.post(
            self.auth_url,
            json={"client_id": self.client_id, "client_secret": self.client_secret},
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        self.token = resp.json()
        if isinstance(self.token, str):
            # API returns a bare JWT string
            pass
        else:
            # Unexpected format – try to extract token field
            self.token = self.token.get("token", self.token)
        self.session.headers.update({"Authorization": f"Bearer {self.token}"})

    def _graphql(self, query, variables=None):
        """Execute a GraphQL query against Xray Cloud."""
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        resp = self.session.post(self.graphql_url, json=payload)
        resp.raise_for_status()
        data = resp.json()
        if "errors" in data:
            raise RuntimeError(f"GraphQL errors: {json.dumps(data['errors'], indent=2)}")
        return data["data"]

    def introspect_schema(self):
        """Run introspection to discover the getTests query signature."""
        query = """
        {
          __schema {
            queryType {
              fields {
                name
                args { name type { name kind ofType { name kind } } }
              }
            }
          }
        }
        """
        data = self._graphql(query)
        fields = data["__schema"]["queryType"]["fields"]
        test_queries = [f for f in fields if "test" in f["name"].lower()]
        return test_queries

    def fetch_tests(self, project_key, limit=100):
        """Fetch all test cases for a project using pagination."""
        query = """
        query GetTests($jql: String!, $limit: Int!, $start: Int!) {
          getTests(jql: $jql, limit: $limit, start: $start) {
            total
            start
            limit
            results {
              issueId
              jira(fields: ["key", "summary", "status", "labels"])
              testType { name kind }
              steps { action data result }
              gherkin
              unstructured
              preconditions(limit: 10) {
                total
                results { issueId jira(fields: ["key", "summary"]) }
              }
              folder { name path }
              status { name }
            }
          }
        }
        """
        all_tests = []
        start = 0
        total = None

        while total is None or start < total:
            variables = {
                "jql": f"project = {project_key}",
                "limit": limit,
                "start": start,
            }
            # Retry on rate limit
            for attempt in range(3):
                try:
                    data = self._graphql(query, variables)
                    break
                except requests.HTTPError as e:
                    if e.response is not None and e.response.status_code == 429:
                        wait = 2 ** attempt * 5
                        print(f"    Rate limited, waiting {wait}s...", flush=True)
                        time.sleep(wait)
                    else:
                        raise
            else:
                raise RuntimeError(f"Rate limited after 3 retries at start={start}")

            result = data["getTests"]
            total = result["total"]
            batch = result["results"] or []
            all_tests.extend(batch)
            print(f"    Fetched {len(all_tests)}/{total}...", flush=True)
            start += limit
            if not batch:
                break
            time.sleep(1)  # pace between pages

        return all_tests, total

    def fetch_all_tests(self, project_keys):
        """Fetch test cases from multiple projects."""
        combined = {}
        for key in project_keys:
            tests, total = self.fetch_tests(key)
            print(f"  Fetched {len(tests)}/{total} test cases from {key}")
            for t in tests:
                jira_data = t.get("jira") or {}
                if isinstance(jira_data, str):
                    jira_data = json.loads(jira_data)
                test_key = jira_data.get("key", "")
                summary = jira_data.get("summary", "")
                jira_status = jira_data.get("status", {})
                if isinstance(jira_status, dict):
                    jira_status = jira_status.get("name", "")
                labels = jira_data.get("labels", [])
                test_type = (t.get("testType") or {}).get("name", "")

                # Parse steps
                steps = []
                for step in (t.get("steps") or []):
                    steps.append({
                        "action": step.get("action", ""),
                        "data": step.get("data", ""),
                        "expected": step.get("result", ""),
                    })

                # Parse preconditions
                preconditions = []
                for pc in (t.get("preconditions") or {}).get("results") or []:
                    pc_jira = pc.get("jira") or {}
                    if isinstance(pc_jira, str):
                        pc_jira = json.loads(pc_jira)
                    preconditions.append({
                        "key": pc_jira.get("key", ""),
                        "summary": pc_jira.get("summary", ""),
                    })

                xray_status = (t.get("status") or {}).get("name", "")
                folder = (t.get("folder") or {}).get("path", "")

                combined[test_key] = {
                    "key": test_key,
                    "summary": summary,
                    "status": jira_status,
                    "xray_status": xray_status,
                    "labels": labels,
                    "test_type": test_type,
                    "project": key,
                    "steps": steps,
                    "gherkin": t.get("gherkin") or "",
                    "unstructured": t.get("unstructured") or "",
                    "preconditions": preconditions,
                    "folder": folder,
                }
        return combined

    def enrich_test(self, issue_key):
        """Fetch detailed test data (steps, gherkin, preconditions) for a single test."""
        query = """
        query GetTest($issueId: String!) {
          getTest(issueId: $issueId) {
            issueId
            projectId
            testType { name kind }
            steps {
              id
              action
              data
              result
              customFields { name value }
            }
            gherkin
            unstructured
            preconditions(limit: 10) {
              total
              results {
                issueId
                jira(fields: ["key", "summary"])
              }
            }
            folder { name path }
            status { name description }
          }
        }
        """
        data = self._graphql(query, {"issueId": issue_key})
        return data.get("getTest")

    def enrich_tests(self, test_dict, keys=None, rate_limit=0.15):
        """Enrich a dict of test cases with Xray step data.

        Args:
            test_dict: dict of key -> test info (modified in place)
            keys: optional subset of keys to enrich; defaults to all keys
            rate_limit: seconds to wait between API calls (default 0.15)
        Returns:
            (enriched_count, failed_keys) tuple
        """
        target_keys = keys if keys is not None else list(test_dict.keys())
        enriched = 0
        failed = []

        for i, key in enumerate(target_keys, 1):
            if i % 10 == 0 or i == len(target_keys):
                print(f"  Enriching test {i}/{len(target_keys)}...", flush=True)

            # Rate limiting
            if rate_limit and i > 1:
                time.sleep(rate_limit)

            # Retry on 429
            detail = None
            for attempt in range(3):
                try:
                    detail = self.enrich_test(key)
                    break
                except requests.HTTPError as e:
                    if e.response is not None and e.response.status_code == 429:
                        wait = 2 ** attempt * 5
                        print(f"  Rate limited, waiting {wait}s...", flush=True)
                        time.sleep(wait)
                        continue
                    failed.append((key, str(e)))
                    break
                except RuntimeError as e:
                    failed.append((key, str(e)))
                    break
            else:
                failed.append((key, "rate limited after 3 retries"))
                continue

            if detail is None:
                if not any(k == key for k, _ in failed):
                    failed.append((key, "not found in Xray"))
                continue

            # Parse steps
            steps = []
            for step in (detail.get("steps") or []):
                steps.append({
                    "action": step.get("action", ""),
                    "data": step.get("data", ""),
                    "expected": step.get("result", ""),
                })

            # Parse preconditions
            preconditions = []
            for pc in (detail.get("preconditions") or {}).get("results") or []:
                jira_data = pc.get("jira") or {}
                if isinstance(jira_data, str):
                    jira_data = json.loads(jira_data)
                preconditions.append({
                    "key": jira_data.get("key", ""),
                    "summary": jira_data.get("summary", ""),
                })

            test_dict[key]["steps"] = steps
            test_dict[key]["gherkin"] = detail.get("gherkin") or ""
            test_dict[key]["unstructured"] = detail.get("unstructured") or ""
            test_dict[key]["preconditions"] = preconditions
            test_dict[key]["test_type"] = (detail.get("testType") or {}).get("name", "")
            xray_status = (detail.get("status") or {}).get("name", "")
            if xray_status:
                test_dict[key]["xray_status"] = xray_status
            folder = detail.get("folder") or {}
            if folder:
                test_dict[key]["folder"] = folder.get("path", "")
            enriched += 1

        print()  # clear \r line
        return enriched, failed


class JiraClient:
    """Client for Jira REST API to fetch Xray Test issues directly."""

    def __init__(self, domain, email, api_token, verify_ssl=True):
        self.base_url = f"https://{domain}"
        self.session = requests.Session()
        self.session.auth = (email, api_token)
        self.session.verify = verify_ssl

    def fetch_tests(self, project_key, max_results=100):
        """Fetch all Test-type issues for a project using cursor pagination."""
        jql = f"project = {project_key} AND issuetype = Test ORDER BY key ASC"
        all_issues = []
        next_page_token = None

        while True:
            params = {
                "jql": jql,
                "maxResults": max_results,
                "fields": "key,summary,status,labels",
            }
            if next_page_token:
                params["nextPageToken"] = next_page_token

            resp = self.session.get(
                f"{self.base_url}/rest/api/3/search/jql", params=params,
            )
            resp.raise_for_status()
            data = resp.json()
            issues = data.get("issues", [])
            all_issues.extend(issues)

            if data.get("isLast", True):
                break
            next_page_token = data.get("nextPageToken")
            if not next_page_token:
                break

        return all_issues

    def fetch_all_tests(self, project_keys):
        """Fetch test cases from multiple Jira projects."""
        combined = {}
        for key in project_keys:
            issues = self.fetch_tests(key)
            print(f"  Fetched {len(issues)} test cases from {key}")
            for issue in issues:
                fields = issue.get("fields", {})
                test_key = issue.get("key", "")
                summary = fields.get("summary", "")
                status = fields.get("status", {})
                if isinstance(status, dict):
                    status = status.get("name", "")
                labels = fields.get("labels", [])
                combined[test_key] = {
                    "key": test_key,
                    "summary": summary,
                    "status": status,
                    "labels": labels,
                    "test_type": "",  # Not available from Jira REST
                    "project": key,
                }
        return combined


class TestCollector:
    """Parses automated test files using AST to extract test metadata."""

    def __init__(self, test_dir):
        self.test_dir = Path(test_dir)

    def collect_tests(self):
        """Walk test directory and parse all test_*.py files."""
        tests = []
        for path in sorted(self.test_dir.rglob("test_*.py")):
            try:
                tests.extend(self._parse_file(path))
            except SyntaxError as e:
                print(f"  WARNING: Syntax error parsing {path}: {e}", file=sys.stderr)
        return tests

    def _parse_file(self, path):
        """Parse a single test file and extract test methods."""
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(path))
        results = []

        # Extract file-level comments for issue IDs
        file_comment_ids = self._extract_ids_from_comments(source)

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                class_name = node.name
                class_docstring = ast.get_docstring(node) or ""
                class_markers = self._extract_markers(node.decorator_list)
                class_ids = self.extract_issue_ids(class_docstring) | file_comment_ids

                for item in node.body:
                    if isinstance(item, ast.FunctionDef) and item.name.startswith("test_"):
                        method_docstring = ast.get_docstring(item) or ""
                        method_markers = self._extract_markers(item.decorator_list)

                        # Collect issue IDs from all sources
                        method_ids = self.extract_issue_ids(method_docstring)

                        # Extract IDs from inline comments in the method body
                        method_source = self._get_source_segment(source, item)
                        inline_ids = self.extract_issue_ids(method_source) if method_source else set()

                        all_ids = class_ids | method_ids | inline_ids

                        # Extract explicit xray/jira marker keys
                        xray_keys = set()
                        jira_keys = set()
                        for m in class_markers + method_markers:
                            if m["name"] == "xray":
                                xray_keys.update(m.get("keys", []))
                            elif m["name"] == "jira":
                                jira_keys.update(m.get("keys", []))

                        all_ids.update(xray_keys)
                        all_ids.update(self._extract_ids_from_marker_keys(jira_keys))

                        rel_path = path.relative_to(self.test_dir.parent.parent)
                        test_id = f"{rel_path}::{class_name}::{item.name}"

                        results.append({
                            "test_id": test_id,
                            "file": str(rel_path),
                            "class": class_name,
                            "method": item.name,
                            "docstring": method_docstring,
                            "markers": [m["name"] for m in method_markers],
                            "class_markers": [m["name"] for m in class_markers],
                            "xray_keys": xray_keys,
                            "jira_keys": jira_keys,
                            "issue_ids": all_ids,
                        })

            # Top-level test functions (not in a class)
            elif isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                if not any(
                    isinstance(parent, ast.ClassDef)
                    for parent in ast.walk(tree)
                    if node in getattr(parent, 'body', [])
                ):
                    method_docstring = ast.get_docstring(node) or ""
                    method_markers = self._extract_markers(node.decorator_list)
                    method_ids = self.extract_issue_ids(method_docstring)
                    method_source = self._get_source_segment(source, node)
                    inline_ids = self.extract_issue_ids(method_source) if method_source else set()
                    all_ids = method_ids | inline_ids

                    xray_keys = set()
                    jira_keys = set()
                    for m in method_markers:
                        if m["name"] == "xray":
                            xray_keys.update(m.get("keys", []))
                        elif m["name"] == "jira":
                            jira_keys.update(m.get("keys", []))

                    all_ids.update(xray_keys)
                    all_ids.update(self._extract_ids_from_marker_keys(jira_keys))

                    rel_path = path.relative_to(self.test_dir.parent.parent)
                    test_id = f"{rel_path}::{node.name}"

                    results.append({
                        "test_id": test_id,
                        "file": str(rel_path),
                        "class": None,
                        "method": node.name,
                        "docstring": method_docstring,
                        "markers": [m["name"] for m in method_markers],
                        "class_markers": [],
                        "xray_keys": xray_keys,
                        "jira_keys": jira_keys,
                        "issue_ids": all_ids,
                    })

        return results

    def _get_source_segment(self, source, node):
        """Extract the source text for an AST node."""
        lines = source.splitlines()
        start = node.lineno - 1
        end = getattr(node, 'end_lineno', None)
        if end is not None:
            return "\n".join(lines[start:end])
        # Fallback: grab lines until next def/class at same indent or end
        indent = node.col_offset
        segment = [lines[start]]
        for line in lines[start + 1:]:
            stripped = line.lstrip()
            if stripped and not line[:1].isspace():
                break
            if stripped.startswith(("def ", "class ")) and (len(line) - len(stripped)) <= indent:
                break
            segment.append(line)
        return "\n".join(segment)

    @staticmethod
    def extract_issue_ids(text):
        """Extract all NES-/NQA-/SCE- issue IDs from text."""
        if not text:
            return set()
        return set(match.group(0) for match in ISSUE_ID_PATTERN.finditer(text))

    @staticmethod
    def _extract_ids_from_comments(source):
        """Extract issue IDs from Python comments in source."""
        ids = set()
        for line in source.splitlines():
            comment_start = line.find('#')
            if comment_start >= 0:
                comment = line[comment_start:]
                ids.update(m.group(0) for m in ISSUE_ID_PATTERN.finditer(comment))
        return ids

    @staticmethod
    def _extract_ids_from_marker_keys(keys):
        """Extract issue IDs from marker key strings (e.g., 'NES-17105: fix later')."""
        ids = set()
        for k in keys:
            ids.update(m.group(0) for m in ISSUE_ID_PATTERN.finditer(k))
        return ids

    @staticmethod
    def _extract_markers(decorator_list):
        """Extract pytest marker info from AST decorator nodes."""
        markers = []
        for dec in decorator_list:
            marker_name, marker_args = TestCollector._parse_marker(dec)
            if marker_name:
                markers.append({"name": marker_name, **marker_args})
        return markers

    @staticmethod
    def _parse_marker(node):
        """Parse a single decorator node to extract marker name and arguments."""
        # @pytest.mark.NAME or @pytest.mark.NAME(...)
        if isinstance(node, ast.Call):
            func = node.func
            name = TestCollector._get_marker_name(func)
            if name:
                args = TestCollector._extract_marker_args(node, name)
                return name, args
        elif isinstance(node, ast.Attribute):
            name = TestCollector._get_marker_name(node)
            if name:
                return name, {}
        return None, {}

    @staticmethod
    def _get_marker_name(node):
        """Extract marker name from pytest.mark.NAME pattern."""
        # pytest.mark.NAME
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Attribute):
                if (isinstance(node.value.value, ast.Name)
                        and node.value.value.id == "pytest"
                        and node.value.attr == "mark"):
                    return node.attr
        return None

    @staticmethod
    def _extract_marker_args(call_node, marker_name):
        """Extract arguments from marker call, e.g., xray(test_key='NES-123')."""
        result = {"keys": []}
        for kw in call_node.keywords:
            if kw.arg == "test_key" and isinstance(kw.value, ast.Constant):
                result["keys"].append(kw.value.value)
        # Positional args (e.g., @pytest.mark.jira('NES-7597'))
        for arg in call_node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                result["keys"].append(arg.value)
        return result


class AuditEngine:
    """Matches automated tests against Xray test cases and generates reports."""

    def __init__(self, xray_tests, automated_tests):
        self.xray_tests = xray_tests  # dict: key -> test info
        self.automated_tests = automated_tests  # list of test dicts
        self.matched = {}  # xray_key -> list of test_ids
        self.unmatched_xray = {}  # xray_key -> test info
        self.unmatched_auto = []  # tests with no issue IDs

    def match_tests(self):
        """Match automated tests to Xray test cases."""
        xray_keys = set(self.xray_tests.keys())

        # Build reverse index: issue_id -> [test_ids]
        id_to_tests = defaultdict(list)
        for test in self.automated_tests:
            for issue_id in test["issue_ids"]:
                id_to_tests[issue_id].append(test["test_id"])

        # Find matches
        for key in xray_keys:
            if key in id_to_tests:
                self.matched[key] = {
                    "xray": self.xray_tests[key],
                    "tests": id_to_tests[key],
                    "match_type": self._determine_match_type(key, id_to_tests[key]),
                }
            else:
                self.unmatched_xray[key] = self.xray_tests[key]

        # Find automated tests with no issue IDs at all
        for test in self.automated_tests:
            if not test["issue_ids"]:
                self.unmatched_auto.append(test)

    def _determine_match_type(self, xray_key, test_ids):
        """Determine the confidence level of a match."""
        for test in self.automated_tests:
            if test["test_id"] in test_ids:
                if xray_key in test["xray_keys"]:
                    return "xray_marker"
                if xray_key in test["jira_keys"] or any(
                    xray_key in k for k in test["jira_keys"]
                ):
                    return "jira_marker"
        return "docstring_or_comment"

    def generate_report(self, output_file=None):
        """Print coverage gap report and optionally save to CSV."""
        total_xray = len(self.xray_tests)
        total_auto = len(self.automated_tests)
        total_matched = len(self.matched)
        total_unmatched_xray = len(self.unmatched_xray)
        total_unmatched_auto = len(self.unmatched_auto)

        # Count by match type
        match_types = defaultdict(int)
        for m in self.matched.values():
            match_types[m["match_type"]] += 1

        print("\n" + "=" * 60)
        print("  XRAY TEST COVERAGE AUDIT")
        print("=" * 60)

        print(f"\nSUMMARY:")
        print(f"  Xray test cases:                    {total_xray:,}")
        print(f"  Automated tests:                    {total_auto:,}")
        print(f"  Matched Xray -> Automated:          {total_matched:,}")
        print(f"  Xray tests without automation:      {total_unmatched_xray:,}")
        print(f"  Automated tests without Xray link:  {total_unmatched_auto:,}")

        if match_types:
            print(f"\nMATCH TYPES:")
            print(f"  @pytest.mark.xray:                  {match_types.get('xray_marker', 0):,}")
            print(f"  @pytest.mark.jira:                  {match_types.get('jira_marker', 0):,}")
            print(f"  Docstring/comment reference:        {match_types.get('docstring_or_comment', 0):,}")

        print(f"\n{'─' * 60}")
        print(f"XRAY TESTS WITHOUT AUTOMATION ({total_unmatched_xray:,}):")
        print(f"{'─' * 60}")
        if self.unmatched_xray:
            for key in sorted(self.unmatched_xray.keys()):
                info = self.unmatched_xray[key]
                summary = info.get("summary", "")
                test_type = info.get("test_type", "")
                suffix = f" [{test_type}]" if test_type else ""
                print(f"  {key} - {summary}{suffix}")
        else:
            print("  (none)")

        print(f"\n{'─' * 60}")
        print(f"AUTOMATED TESTS WITHOUT XRAY LINK ({total_unmatched_auto:,}):")
        print(f"{'─' * 60}")
        if self.unmatched_auto:
            for test in sorted(self.unmatched_auto, key=lambda t: t["test_id"]):
                print(f"  {test['test_id']}")
        else:
            print("  (none)")

        print(f"\n{'─' * 60}")
        print(f"MATCHED TESTS ({total_matched:,}):")
        print(f"{'─' * 60}")
        if self.matched:
            for key in sorted(self.matched.keys()):
                m = self.matched[key]
                info = m["xray"]
                summary = info.get("summary", "")
                match_type = m["match_type"]
                tests = m["tests"]
                steps = info.get("steps", [])
                print(f"  {key} - {summary}")
                print(f"    Match type: {match_type}")
                for t in tests[:5]:  # Show up to 5 linked tests
                    print(f"    -> {t}")
                if len(tests) > 5:
                    print(f"    ... and {len(tests) - 5} more")
                if steps:
                    print(f"    Steps ({len(steps)}):")
                    for j, step in enumerate(steps, 1):
                        action = (step.get("action") or "").strip()
                        expected = (step.get("expected") or "").strip()
                        if action:
                            print(f"      {j}. {action}")
                        if expected:
                            print(f"         Expected: {expected}")
                gherkin = info.get("gherkin", "")
                if gherkin:
                    print(f"    Gherkin: {gherkin[:200]}...")
                unstructured = info.get("unstructured", "")
                if unstructured:
                    print(f"    Definition: {unstructured[:200]}...")
        else:
            print("  (none)")

        print()

        if output_file:
            self._write_csv(output_file)

    @staticmethod
    def _format_steps(steps):
        """Format test steps as a readable string for CSV."""
        if not steps:
            return ""
        parts = []
        for i, step in enumerate(steps, 1):
            action = (step.get("action") or "").strip()
            expected = (step.get("expected") or "").strip()
            line = f"{i}. {action}"
            if expected:
                line += f" -> Expected: {expected}"
            parts.append(line)
        return "\n".join(parts)

    def _write_csv(self, output_file):
        """Write audit results to a CSV file."""
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)

            # Xray coverage sheet
            writer.writerow(["Section: Xray Test Cases"])
            writer.writerow(["Key", "Summary", "Project", "Test Type", "Status",
                             "Folder", "Has Automation", "Match Type",
                             "Automated Test(s)", "Test Steps",
                             "Gherkin", "Unstructured Definition",
                             "Preconditions"])
            for key in sorted(self.xray_tests.keys()):
                info = self.xray_tests[key]
                steps_str = self._format_steps(info.get("steps", []))
                gherkin = info.get("gherkin", "")
                unstructured = info.get("unstructured", "")
                preconditions = "; ".join(
                    f"{pc['key']}: {pc['summary']}"
                    for pc in info.get("preconditions", [])
                )
                folder = info.get("folder", "")
                if key in self.matched:
                    m = self.matched[key]
                    writer.writerow([
                        key, info.get("summary", ""), info.get("project", ""),
                        info.get("test_type", ""), info.get("status", ""),
                        folder, "Yes", m["match_type"],
                        "; ".join(m["tests"]), steps_str,
                        gherkin, unstructured, preconditions,
                    ])
                else:
                    writer.writerow([
                        key, info.get("summary", ""), info.get("project", ""),
                        info.get("test_type", ""), info.get("status", ""),
                        folder, "No", "", "", steps_str,
                        gherkin, unstructured, preconditions,
                    ])

            writer.writerow([])
            writer.writerow(["Section: Automated Tests"])
            writer.writerow(["Test ID", "File", "Class", "Method",
                             "Has Xray Link", "Issue IDs"])
            for test in sorted(self.automated_tests, key=lambda t: t["test_id"]):
                writer.writerow([
                    test["test_id"], test["file"], test.get("class", ""),
                    test["method"], "Yes" if test["issue_ids"] else "No",
                    "; ".join(sorted(test["issue_ids"])),
                ])

        print(f"CSV report written to: {output_file}")


def run_local_only(test_dir, output_file=None):
    """Run local-only analysis without Xray API access."""
    print("Running local-only analysis (no Xray API)...")
    print(f"Scanning test directory: {test_dir}\n")

    collector = TestCollector(test_dir)
    automated_tests = collector.collect_tests()
    print(f"Found {len(automated_tests):,} automated test methods\n")

    # Aggregate all referenced issue IDs
    all_ids = defaultdict(list)
    tests_with_ids = 0
    tests_without_ids = 0
    xray_marker_count = 0
    jira_marker_count = 0

    for test in automated_tests:
        if test["issue_ids"]:
            tests_with_ids += 1
            for issue_id in test["issue_ids"]:
                all_ids[issue_id].append(test["test_id"])
        else:
            tests_without_ids += 1
        if test["xray_keys"]:
            xray_marker_count += 1
        if test["jira_keys"]:
            jira_marker_count += 1

    # Group by prefix
    prefix_counts = defaultdict(int)
    for issue_id in all_ids:
        prefix = issue_id.split("-")[0]
        prefix_counts[prefix] += 1

    print("=" * 60)
    print("  LOCAL TEST ANALYSIS")
    print("=" * 60)
    print(f"\nSUMMARY:")
    print(f"  Total test methods:                 {len(automated_tests):,}")
    print(f"  Tests with issue ID references:     {tests_with_ids:,}")
    print(f"  Tests without issue ID references:  {tests_without_ids:,}")
    print(f"  Tests with @pytest.mark.xray:       {xray_marker_count:,}")
    print(f"  Tests with @pytest.mark.jira:       {jira_marker_count:,}")
    print(f"  Unique issue IDs referenced:        {len(all_ids):,}")

    print(f"\nISSUE ID BREAKDOWN:")
    for prefix in sorted(prefix_counts.keys()):
        print(f"  {prefix}-*: {prefix_counts[prefix]:,} unique IDs")

    print(f"\n{'─' * 60}")
    print(f"TESTS WITH @pytest.mark.xray ({xray_marker_count}):")
    print(f"{'─' * 60}")
    for test in automated_tests:
        if test["xray_keys"]:
            keys = ", ".join(sorted(test["xray_keys"]))
            print(f"  {test['test_id']}")
            print(f"    Keys: {keys}")

    print(f"\n{'─' * 60}")
    print(f"TESTS WITH @pytest.mark.jira ({jira_marker_count}):")
    print(f"{'─' * 60}")
    for test in automated_tests:
        if test["jira_keys"]:
            keys = ", ".join(sorted(test["jira_keys"]))
            print(f"  {test['test_id']}")
            print(f"    Keys: {keys}")

    print(f"\n{'─' * 60}")
    print(f"TESTS WITHOUT ANY ISSUE ID REFERENCES ({tests_without_ids:,}):")
    print(f"{'─' * 60}")
    for test in sorted(
        [t for t in automated_tests if not t["issue_ids"]],
        key=lambda t: t["test_id"],
    ):
        print(f"  {test['test_id']}")

    print()

    if output_file:
        _write_local_csv(output_file, automated_tests, all_ids)


def _write_local_csv(output_file, automated_tests, all_ids):
    """Write local-only audit results to a CSV file."""
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        writer.writerow(["Section: Automated Tests"])
        writer.writerow(["Test ID", "File", "Class", "Method",
                         "Has Issue ID", "Issue IDs", "Xray Keys", "Jira Keys"])
        for test in sorted(automated_tests, key=lambda t: t["test_id"]):
            writer.writerow([
                test["test_id"], test["file"], test.get("class", ""),
                test["method"], "Yes" if test["issue_ids"] else "No",
                "; ".join(sorted(test["issue_ids"])),
                "; ".join(sorted(test["xray_keys"])),
                "; ".join(sorted(test["jira_keys"])),
            ])

        writer.writerow([])
        writer.writerow(["Section: Issue ID References"])
        writer.writerow(["Issue ID", "Referenced By (count)", "Test IDs"])
        for issue_id in sorted(all_ids.keys()):
            test_ids = all_ids[issue_id]
            writer.writerow([issue_id, len(test_ids), "; ".join(test_ids)])

    print(f"CSV report written to: {output_file}")


def _run_jira_fetch(project_keys, verify_ssl):
    """Fetch test cases via Jira REST API."""
    domain = os.environ.get("JIRA_DOMAIN")
    email = os.environ.get("JIRA_EMAIL")
    api_token = os.environ.get("JIRA_API_TOKEN")
    if not all([domain, email, api_token]):
        print(
            "Error: JIRA_DOMAIN, JIRA_EMAIL, and JIRA_API_TOKEN environment "
            "variables required for --jira mode.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"Fetching test cases from Jira ({domain})...")
    client = JiraClient(domain, email, api_token, verify_ssl=verify_ssl)
    try:
        return client.fetch_all_tests(project_keys)
    except requests.HTTPError as e:
        print(f"Error fetching from Jira: {e}", file=sys.stderr)
        sys.exit(1)


def _load_from_file(filepath):
    """Load Xray test data from a JSON export file (e.g., flattened_tests.json)."""
    path = Path(filepath)
    if not path.is_file():
        print(f"Error: File not found: {filepath}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading test data from {filepath}...")
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)

    # Support both {metadata, tests: [...]} and plain [...] formats
    if isinstance(raw, dict) and "tests" in raw:
        tests_list = raw["tests"]
        meta = raw.get("metadata", {})
        print(f"  Metadata: {json.dumps(meta)}")
    elif isinstance(raw, list):
        tests_list = raw
    else:
        print(f"Error: Unexpected JSON structure (expected dict with 'tests' or list)", file=sys.stderr)
        sys.exit(1)

    combined = {}
    for t in tests_list:
        key = t.get("test_key", "")
        if not key:
            continue
        steps = []
        for s in t.get("steps", []):
            steps.append({
                "action": s.get("action", ""),
                "data": s.get("data", ""),
                "expected": s.get("expected_result", s.get("result", "")),
            })
        combined[key] = {
            "key": key,
            "summary": t.get("summary", ""),
            "status": t.get("status", ""),
            "labels": t.get("labels", []),
            "test_type": t.get("test_type", ""),
            "project": key.split("-")[0] if "-" in key else "",
            "steps": steps,
            "gherkin": t.get("gherkin", ""),
            "unstructured": t.get("description", t.get("unstructured", "")),
            "preconditions": t.get("preconditions", []),
            "folder": t.get("folder", ""),
        }

    print(f"  Loaded {len(combined):,} test cases")
    return combined


def _create_xray_client(verify_ssl, region="us"):
    """Create and authenticate an XrayClient."""
    client_id = os.environ.get("XRAY_CLIENT_ID")
    client_secret = os.environ.get("XRAY_CLIENT_SECRET")
    if not client_id or not client_secret:
        print(
            "Error: XRAY_CLIENT_ID and XRAY_CLIENT_SECRET environment variables required.\n"
            "Use --jira for Jira REST API or --local-only for no API access.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"Authenticating with Xray Cloud ({region} region)...")
    client = XrayClient(client_id, client_secret, verify_ssl=verify_ssl, region=region)
    try:
        client.authenticate()
    except (requests.HTTPError, requests.ConnectionError) as e:
        print(f"Error: Authentication failed: {e}", file=sys.stderr)
        sys.exit(1)
    print("  Authenticated successfully.\n")
    return client


def _run_jira_xray_fetch(project_keys, verify_ssl, region="us"):
    """Hybrid: discover test keys from Jira, enrich with Xray steps."""
    # Step 1: Get test keys from Jira
    jira_tests = _run_jira_fetch(project_keys, verify_ssl)

    # Step 2: Authenticate with Xray
    xray_client = _create_xray_client(verify_ssl, region)

    # Step 3: Enrich with Xray test step data
    print(f"Enriching {len(jira_tests):,} tests with Xray step data...")
    enriched_count, failed = xray_client.enrich_tests(jira_tests)
    print(f"  Enriched: {enriched_count:,}")
    if failed:
        not_found = [k for k, reason in failed if "not found" in reason]
        errors = [k for k, reason in failed if "not found" not in reason]
        if not_found:
            print(f"  Not found in Xray: {len(not_found):,}")
        if errors:
            print(f"  Errors: {len(errors):,}")
            for k, reason in failed[:5]:
                if "not found" not in reason:
                    print(f"    {k}: {reason[:100]}")

    return jira_tests


def _run_xray_fetch(args, verify_ssl):
    """Fetch test cases via Xray Cloud GraphQL API. Returns None for introspect mode."""
    client = _create_xray_client(verify_ssl, args.xray_region)

    if args.introspect:
        print("Running schema introspection...")
        test_queries = client.introspect_schema()
        for q in test_queries:
            print(f"\n  Query: {q['name']}")
            for arg in q.get("args", []):
                arg_type = arg.get("type", {})
                type_name = arg_type.get("name") or (arg_type.get("ofType") or {}).get("name", "?")
                print(f"    arg: {arg['name']} ({type_name})")
        return None

    print(f"Fetching test cases from Xray ({', '.join(args.projects)})...")
    try:
        return client.fetch_all_tests(args.projects)
    except (requests.HTTPError, RuntimeError) as e:
        print(f"Error fetching Xray tests: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Audit automated test coverage against Xray/Jira test cases.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Local-only analysis (no credentials needed)
  python scripts/xray_audit.py --local-only --test-dir nessus/tests/

  # Full audit via Jira REST API only (no test steps)
  python scripts/xray_audit.py --jira --projects NES SCE --test-dir nessus/tests/

  # Hybrid: Jira discovers tests, Xray enriches with steps (recommended)
  python scripts/xray_audit.py --jira-xray --projects NES SCE --test-dir nessus/tests/

  # Full audit via Xray Cloud GraphQL API only
  python scripts/xray_audit.py --projects NES SCE --test-dir nessus/tests/

  # Save report to CSV
  python scripts/xray_audit.py --jira-xray --projects NES SCE -o report.csv
        """,
    )
    parser.add_argument(
        "--projects", nargs="+", default=["NES", "SCE"],
        help="Xray project keys to audit (default: NES SCE)",
    )
    parser.add_argument(
        "--test-dir", default="nessus/tests/",
        help="Path to test directory (default: nessus/tests/)",
    )
    parser.add_argument(
        "--output", "-o", default=None,
        help="Optional CSV output file path",
    )
    parser.add_argument(
        "--local-only", action="store_true",
        help="Run local analysis only (no API calls)",
    )
    parser.add_argument(
        "--jira", action="store_true",
        help="Use Jira REST API only (requires JIRA_DOMAIN, JIRA_EMAIL, JIRA_API_TOKEN)",
    )
    parser.add_argument(
        "--jira-xray", action="store_true",
        help="Hybrid: Jira discovers test keys, Xray enriches with steps "
             "(requires both Jira and Xray credentials)",
    )
    parser.add_argument(
        "--xray-region", default="us", choices=["global", "us", "eu"],
        help="Xray Cloud region (default: us)",
    )
    parser.add_argument(
        "--from-file", default=None, metavar="JSON",
        help="Load Xray test data from a JSON file (e.g., flattened_tests.json) "
             "instead of fetching from API",
    )
    parser.add_argument(
        "--introspect", action="store_true",
        help="Print Xray GraphQL schema introspection and exit",
    )
    parser.add_argument(
        "--no-verify-ssl", action="store_true",
        help="Disable SSL certificate verification (for corporate proxies)",
    )
    args = parser.parse_args()

    test_dir = Path(args.test_dir)
    if not test_dir.is_dir():
        print(f"Error: Test directory not found: {test_dir}", file=sys.stderr)
        sys.exit(1)

    if args.local_only:
        run_local_only(test_dir, output_file=args.output)
        return

    verify_ssl = not args.no_verify_ssl
    if not verify_ssl:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        print("WARNING: SSL certificate verification disabled.\n")

    if args.from_file:
        xray_tests = _load_from_file(args.from_file)
    elif args.jira_xray:
        xray_tests = _run_jira_xray_fetch(args.projects, verify_ssl, args.xray_region)
    elif args.jira:
        xray_tests = _run_jira_fetch(args.projects, verify_ssl)
    else:
        xray_tests = _run_xray_fetch(args, verify_ssl)
        if xray_tests is None:
            return  # introspect mode

    print(f"  Total test cases: {len(xray_tests):,}\n")

    # Collect automated tests
    print(f"Scanning automated tests in {test_dir}...")
    collector = TestCollector(test_dir)
    automated_tests = collector.collect_tests()
    print(f"  Found {len(automated_tests):,} automated test methods\n")

    # Match and report
    print("Matching tests...")
    engine = AuditEngine(xray_tests, automated_tests)
    engine.match_tests()
    engine.generate_report(output_file=args.output)


if __name__ == "__main__":
    main()
