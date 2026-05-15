"""
Tests to verity the KB file
:copyright: Tenable Network Security, 2023
:created: March 20, 2023
:author: @stellex
"""
import pytest
import requests
from catium.helpers.testdata import get_file_path
from catium.lib.const import TIME_FIVE_MINUTES, TIME_FIVE_SECONDS
from catium.lib.ssh import SSH

from nessus.helpers.waiters import wait_for_scanner_status

from nessus.helpers.nessuscli.fix import set
from nessus.helpers.nessuscli.helper import get_nessus_conf_dir, stop_nessus, start_nessus, get_command, \
    get_nessus_log_dir, path_join, get_os_name, get_nessus_bin_dir
from nessus.lib.const import API, OperatingSystems


@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
class TestKBFile:
    """
    Tests for the KB file from a host in a scan
    """

    # Setup test variables
    cat = None
    kb_scan_data = {
        'scan_json_path': (get_file_path('nessus/tests/api/scan/test_data/test_kb_file.json')),
        'scan_type': 'basic'
    }

    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': kb_scan_data['scan_json_path'], 'scan_type': kb_scan_data['scan_type'],
         'settings': {'niap_mode': 'enforcing'}, 'cleanup_settings': True},
    ], indirect=True)
    def test_kb_file_newline_scan(self, test_data_file, nessus_api_login, create_scan_class):
        """
        Runs a basic scan on localhost then verifies the resulting KB file has a newline at the end
        """

        # Get Scan related information for newly created scan and verify its 200 response
        kb_scan = create_scan_class
        scan_exists = kb_scan.scan_state()

        assert scan_exists, 'Failed to create scan'

        kb_scan.launch_scan()

        # Verify scan is pass or fail to complete
        assert kb_scan.scan_result, "Scan failed to complete."

        kb_scan.get_kb()
        for host in kb_scan.hosts.keys():
            assert kb_scan.hosts[host]["kb_file"].decode("utf-8")[-1:] == "\n", "Newline not found at the end of the KB file"

    bin_dir = get_nessus_bin_dir()

    @pytest.mark.parametrize('add_test_file', [[{'file_path': bin_dir, 'file_name': 'sce3436kb.txt', 'cleanup_file': True},
                                                      {'file_path': bin_dir, 'file_name': 'sce3436.nasl', 'cleanup_file': True}]], indirect=True)
    def test_kb_file_newline_nasl(self, add_test_file):
        """
        Runs a basic scan on localhost then verifies the resulting KB file has a newline at the end
        """
        bin_dir = get_nessus_bin_dir()
        kb_file = add_test_file[0]
        nasl_file = add_test_file[1]

        with SSH() as ssh:
            assert ssh.execute(f"{bin_dir}/nasl -k {kb_file} {nasl_file}")[0] == "word", \
                "Expected nasl output to be 'word'"
