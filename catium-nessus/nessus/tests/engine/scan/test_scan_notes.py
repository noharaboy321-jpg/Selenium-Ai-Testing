"""
Test to verify various scan notes
:copyright: Tenable Network Security, 2022
:created: September 1, 2022
:last_modified: September 1, 2022
:author: @stellex
"""

import os
import platform
import re
import logging

import pytest
from catium.helpers.testdata import get_file_path
from catium.lib.log import create_logger
from nessus.lib.const.constants import Nessus

from nessus.helpers.nessusd_rules import remove_nessusd_rules_file
from catium.lib.ssh import SSH

from nessus.helpers.nessus_db import ScanDB
from nessus.helpers.nessuscli.helper import path_join, get_nessus_log_dir, get_command
from nessus.helpers.nessusd_rules import replace_nessusd_rules_file, update_nessusd_rules_file, \
    remove_nessusd_rules_file
from nessus.lib.const import API


@pytest.mark.nessus_engine
class TestScanNotes:
    """
    Test for various scan notes to ensure they are correct.
    """

    # Setup test variables
    cat = None

    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': (get_file_path('nessus/tests/engine/scan/test_data/test_restricted_target_scan.json')),
         'scan_type': 'basic', 'expected_notes': [{'title': 'Invalid Target', 'message': r"""Host '0\.0\.0\.0' was not scanned because it is a "restricted" IP address\. Remove the IP address from the scan's target list\."""}],
         'rules': None},
        {'scan_json_path': (get_file_path('nessus/tests/engine/scan/test_data/test_invalid_target_scan.json')),
         'scan_type': 'basic', 'expected_notes': [{'title': 'Invalid Target', 'message': r"""The target 'ab\[c\]' was not scanned because the target did not match any valid target specification\."""}],
         'rules': None},
        {'scan_json_path': (get_file_path('nessus/tests/engine/scan/test_data/test_unreachable_target_scan.json')),
         'scan_type': 'basic', 'expected_notes': [{'title': 'Invalid Target', 'message': r'(The )?[Tt]arget "no\.such\.target\.tenable\.com" was not scanned because IP address resolution failed.*'},
                                                  {'title': 'Invalid Target', 'message': r'The scan attempt was rejected because there are no valid targets\.'}],
         'rules': None},
        {'scan_json_path': (get_file_path('nessus/tests/engine/scan/test_data/test_invalid_parsing_target_scan.json')),
         'scan_type': 'basic', 'expected_notes': [{'title': 'Invalid Target', 'message': r'(The )?[Tt]arget "1\.2\.3\.500" was not scanned because IP address resolution failed.*'},
                                                  {'title': 'Invalid Target', 'message': r'The scan attempt was rejected because there are no valid targets\.'}],
         'rules': None},
        {'scan_json_path': (get_file_path('nessus/tests/engine/scan/test_data/test_forbidden_target_scan.json')),
         'scan_type': 'basic', 'expected_notes': [{'title': 'Scan Forbidden', 'message': r"""Host '127\.0\.0\.1' was not scanned because it violates user-defined scanning rules\. If you believe this to be in error, check the nessusd\.rules file on the scanner and/or verify that your scan target exclusions are correct\. Otherwise, remove the target from your scan's target list\."""}],
         'rules': ['reject 127.0.0.1', 'default accept'], 'cleanup_rules': True}
    ], indirect=True)
    @pytest.mark.xray(test_key='SCE-3291')
    def test_scan_notes(self, test_data_file, nessus_api_login, create_scan_class, set_nessus_rules):
        """
        Creates a scan designed to generate a particular scan note text then verifies text is correct.
        """
        number_of_scan_notes = None

        # Get Scan related information for newly created scan and verify its 200 response
        log = create_logger()
        scan = create_scan_class
        scan_exists = scan.scan_state()
        expected_notes = test_data_file['expected_notes']
        rules = test_data_file['rules'] if 'rules' in test_data_file.keys() else None

        assert scan_exists, 'Failed to create scan'

        scan.launch_scan()

        # Verify scan is pass or fail to complete
        assert scan.scan_result, "Scan failed to complete."

        scan.get_scan_details()

        if scan.scan_details['notes'] is not None:
            number_of_scan_notes = len(scan.scan_details['notes']['note'])
        else:
            log.debug("Scan notes: " + str(scan.scan_details['notes']))
            pytest.fail('Notes not found in scan details!')

        assert number_of_scan_notes == len(expected_notes), \
            f"Expected {len(expected_notes)} note(s), but {number_of_scan_notes} notes were found"

        for note in expected_notes:
            note_found = False
            for scan_note in scan.scan_details['notes']['note']:
                if scan_note['title'] == note['title']:
                    if re.search(note['message'], scan_note['message']):
                        note_found = True
            assert note_found, f"Expected note titled {note['title']} with message {note['message']} not found in scan notes: {scan.scan_details['notes']['note']}"

        if rules is not None:
            remove_nessusd_rules_file()

    report_error_plugin = {'plugin_filename': 'report_error.nasl', 'cleanup_file': True}
    report_error_plugin_test_data = {'scan_json_path': (get_file_path('nessus/tests/engine/scan/test_data/test_scan_note_error_codes.json')),
                                     'scan_type': 'advanced', 'plugin_data': report_error_plugin}

    db_decrypt = {"file_path": "./scripts/db/", "file_name": f"nessusdbDecrypt_{platform.system().lower()}_amd64",
                  "cleanup_file": True, "execute_locally": True}

    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.parametrize('test_data_file', [{'scan_json_path': report_error_plugin_test_data['scan_json_path'],
                                                 'scan_type': report_error_plugin_test_data['scan_type']}], indirect=True)
    @pytest.mark.xray(test_key='SCE-3418')
    @pytest.mark.parametrize('add_test_file', [db_decrypt], indirect=True)
    @pytest.mark.parametrize('install_custom_plugin', [report_error_plugin_test_data['plugin_data']], indirect=True)
    def test_scan_note_error_codes(self, nessus_api_login, install_custom_plugin, test_data_file, add_test_file,
                                   create_scan_class):
        """
        Creates a scan using a custom plugin to trigger various scan errors, then verifies these errors are correctly
        reported in the scan notes and scan DB.
        """

        # Get Scan related information for newly created scan and verify its 200 response
        report_error_scan = create_scan_class
        scan_exists = report_error_scan.scan_state()

        assert scan_exists, 'Failed to create scan'

        report_error_scan.launch_scan()

        # Verify scan is pass or fail to complete
        assert report_error_scan.scan_result, "Scan failed to complete."

        report_error_scan.get_scan_details()

        notes = []
        notes.append({"Title": "Scan Error 1", "Text": "This is the first scan error."})
        notes.append({"Title": "Scan Error 4", "Text": "This error should have severity 1"})
        notes.append({"Title": "Scan Error 5", "Text": "Scan error 5 sets nothing in options"})
        notes.append({"Title": "Scan Error 6", "Text": "Scan error 6 sets code = SCAN_ERROR_PLUGIN_GENERIC + 1 (109000 + 1 = 109001)"})
        notes.append({"Title": "Scan Error 7", "Text": "Scan error 7 sets type = not_a_real_plugin"})
        notes.append({"Title": "Scan Error 8", "Text": "Scan error 8 sets type = not_a_real_plugin AND code = SCAN_ERROR_PLUGIN_GENERIC + 1"})
        notes.append({"Title": "Scan Error 9", "Text": "Scan error 9 should try to set a non-string as the type, and get the default value instead"})

        for note in notes:
            note_found = False
            if report_error_scan.scan_details['notes'] is not None:
                for scan_note in report_error_scan.scan_details['notes']['note']:
                    if scan_note['title'] == note["Title"]:
                        if scan_note['message'] == note["Text"]:
                            note_found = True
                            break
            assert note_found, f"Expected note titled {note['Title']} with message {note['Text']} not found in scan " \
                               f"notes: {report_error_scan.scan_details['notes']}"

    scan_note_timeout_data = {'scan_json_path': (get_file_path('nessus/tests/engine/scan/test_data/test_scan_note_timeout.json')),
                              'scan_type': 'advanced'}
    nessus_settings = {'nessus_syn_scanner.portscan_timeout': 1, 'nessus_tcp_scanner.portscan_timeout': 1,
                       'nessus_udp_scanner.max_run_time': 1}

    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.parametrize("test_data_file", [{"scan_json_path": scan_note_timeout_data["scan_json_path"],
                                                 "scan_type": scan_note_timeout_data["scan_type"],
                                                 "settings": nessus_settings, "restart": False,
                                                 "cleanup_settings": True, "updated_settings": {"syn_scanner": "yes",
                                                                                                "tcp_scanner": "no",
                                                                                                "udp_scanner": "no"}},
                                                {"scan_json_path": scan_note_timeout_data["scan_json_path"],
                                                 "scan_type": scan_note_timeout_data["scan_type"],
                                                 "settings": nessus_settings, "restart": False,
                                                 "cleanup_settings": True, "updated_settings": {"syn_scanner": "no",
                                                                                                "tcp_scanner": "yes",
                                                                                                "udp_scanner": "no"}},
                                                {"scan_json_path": scan_note_timeout_data["scan_json_path"], "scan_type": scan_note_timeout_data["scan_type"],
                                                 "settings": nessus_settings, "restart": False,
                                                 "cleanup_settings": True, "updated_settings": {"syn_scanner": "no",
                                                                                                "tcp_scanner": "no",
                                                                                                "udp_scanner": "yes"}}],
                             indirect=True)
    @pytest.mark.xray(test_key='SCE-3420')
    def test_scan_note_timeout(self, nessus_api_login, test_data_file, create_scan_class,
                               configure_advanced_settings_and_env_variables):
        """
        Test to validate scan notes when portscan timeouts occur.
        """

        # Using Linux target constant if running in Jenkins, else provide CAT_TARGET in environment variables for local
        target_ip = Nessus.Scan.Target.AWS_LINUX_TARGET_1 if 'CAT_TARGET' not in os.environ.keys() else \
            os.environ['CAT_TARGET']
        updated_settings = test_data_file["updated_settings"]
        updated_settings["text_targets"] = target_ip

        # Get Scan related information for newly created scan and verify its 200 response
        report_error_scan = create_scan_class
        scan_exists = report_error_scan.scan_state()

        assert scan_exists, 'Failed to create scan'

        report_error_scan.update_scan_settings(updated_settings)

        if updated_settings['syn_scanner'] == 'yes':
            scan_type = "SYN"
            scan_note_port_type = "TCP"
        elif updated_settings['tcp_scanner'] == 'yes':
            scan_type = "TCP"
            scan_note_port_type = "TCP"
        elif updated_settings['udp_scanner'] == 'yes':
            scan_type = "UDP"
            scan_note_port_type = "UDP"
        else:
            scan_type = None
            scan_note_port_type = None

        report_error_scan.launch_scan()

        # Verify scan is pass or fail to complete
        assert report_error_scan.scan_result, "Scan failed to complete."

        report_error_scan.get_scan_details()

        notes = [{"Title": f"{scan_type} Scanner Timeout", "Text": f"The {scan_type} port scan against target "
                                                                   f"{target_ip} timed out after .* seconds - "
                                                                   f"{scan_note_port_type} port results may be "
                                                                   f"incomplete"}]

        for note in notes:
            note_found = False
            if report_error_scan.scan_details['notes'] is not None:
                for scan_note in report_error_scan.scan_details['notes']['note']:
                    if scan_note['title'] == note["Title"]:
                        if re.match(note["Text"], scan_note['message']):
                            note_found = True
                            break
            assert note_found, f"Expected note titled {note['Title']} with message {note['Text']} not found in scan " \
                               f"notes: {report_error_scan.scan_details['notes']}"
