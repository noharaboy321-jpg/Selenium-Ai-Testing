"""
Test to verify various scan notes
:copyright: Tenable Network Security, 2023
:created: April 24, 2023
:last_modified: April 24, 2023
:author: @stellex
"""

import pytest
from catium.helpers.testdata import get_file_path
from catium.lib.log import create_logger

from nessus.helpers.nessuscli.helper import path_join, get_nessus_var_dir
from nessus.helpers.policy import configure_policy


@pytest.mark.nessus_engine
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
class TestPolicySettings:
    """
    Test for various scan policy settings to ensure they behave correctly.
    """

    # Setup test variables
    cat = None

    file_path = "nessus/tests/engine/scan/test_data/"
    disable_file_name = 'disable_mandatory_plugins.nessus'
    enable_file_name = 'enable_mandatory_plugins.nessus'
    policy_paths = [path_join([file_path, disable_file_name]), path_join([file_path, enable_file_name])]

    @pytest.mark.parametrize('upload_policy', [{'filepath': policy_paths}], indirect=True)
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': (get_file_path('nessus/tests/engine/scan/test_data/test_disable_mandatory_plugins.json')),
         'scan_type': 'advanced'}
    ], indirect=True)
    @pytest.mark.xray(test_key='SCE-3528')
    def test_disable_mandatory_plugins(self, test_data_file, nessus_api_login, upload_policy, create_scan_class):
        """
        Creates a scan designed to generate a particular scan note text then verifies text is correct.
        """

        # Get Scan related information for newly created scan and verify its 200 response
        log = create_logger()
        disable_mandatory_plugins_policy = upload_policy[0]
        enable_mandatory_plugins_policy = upload_policy[1]
        scan = create_scan_class
        scan_exists = scan.scan_state()
        scan.update_scan_settings({'policy_id': disable_mandatory_plugins_policy['id']})

        assert scan_exists, 'Failed to create scan'

        scan.launch_scan()

        # Verify scan is pass or fail to complete
        assert scan.scan_result, "Scan failed to complete."

        scan.get_scan_details()

        assert len(scan.scan_details['vulnerabilities']) == 0, "Expected zero vulnerabilities to be found with the scan"

        scan.update_scan_settings({'policy_id': enable_mandatory_plugins_policy['id']})

        scan.launch_scan()

        # Verify scan is pass or fail to complete
        assert scan.scan_result, "Scan failed to complete."

        scan.get_scan_details()

        assert len(scan.scan_details['vulnerabilities']) >= 1, "Expected at least 1 vulnerability to be fouond with the scan"
        assert scan.scan_details['vulnerabilities'][0]['plugin_name'] == "Nessus Scan Information"
