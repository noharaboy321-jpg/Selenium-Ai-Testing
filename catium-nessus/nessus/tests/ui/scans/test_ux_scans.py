"""
Test cases to verify Nessus UX Scans

:copyright: Tenable Network Security, 2017
:date: December 20, 2017
:last_modified: July 16, 2018
:author: @mameta, @rdutta
"""

import pytest
from selenium.webdriver.support.expected_conditions import visibility_of_element_located

from catium.lib.const.base_constants import TIME_THREE_SECONDS, TIME_TEN_MINUTES, WAIT_NORMAL
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.helpers.scan import delete_created_scan, scan_save_launch_and_status_verification
from nessus.helpers.scanner import get_remote_scanner
from nessus.lib.const import Nessus, API
from nessus.pageobjects.scans.scans_page import ScansPage, ScanList
from nessus.pageobjects.shared.loading import LoadingCircle


@pytest.mark.update
@pytest.mark.scanning
@pytest.mark.nessus_home
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_legacy
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login', 'login', 'create_new_folder')
class TestScanControls:
    """
    Test class to cover Nessus Regression UX related test cases
    #NQA-1024 : Covers all test that should be run on a build/release.
    """
    cat = None

    @pytest.mark.skip('mdabra: Skipping this test case because it got stuck in infinite loop in scanning pipeline #393.')
    @pytest.mark.parametrize('scan_details', [
        {'scan_name': 'NQA-110 - Basic Scan',
         'scan_control_action': [{'control_action': API.Scan.Actions.STOP, 'status': API.Scan.Status.CANCELED}]},
        {'scan_name': 'NQA-104 - Basic Scan',
         'scan_control_action': [{'control_action': API.Scan.Actions.PAUSE, 'status': API.Scan.Status.PAUSED},
                                 {'control_action': API.Scan.Actions.STOP, 'status': API.Scan.Status.CANCELED}]}])
    def test_scan_control_on_running_scan(self, create_new_folder, scan_details):
        """
        #NQA-104 : UX - Scans - Stop and Pause a scan when connected to Manager.
        #NQA-110 : UX - Scans - Remote Scanner - Stop a scan
        1. Create a basic scan using the remote scanner and launch it.
        2. While scan is running, on the remote scanner find the scan and hit 'control_action' to control the scan
        3. Verify the scan status according to action taken.
        """
        folder_name = create_new_folder[1]
        scan_name = scan_details.get('scan_name')

        # get remote scanner to add in scan configuration
        remote_scanners = get_remote_scanner(api=self.cat.api)
        LoadingCircle(TIME_THREE_SECONDS)
        remote_scanner = remote_scanners[0] if remote_scanners \
            else pytest.xfail("Can't proceed further as no remote scanner linked to the product.")

        # Create scan with data to be scanned
        scans_page = ScansPage()
        scans_page.create_new_scan(
            scan_template=Nessus.TemplateNames.BASIC_NETWORK, scan_type=Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
            scan_name=scan_name, scanner=remote_scanner, folder=folder_name, target_ip=Nessus.Scan.Target.LOCALHOST,
            description='Check scan control for {}.'.format(scan_name), add_configuration=True)

        # Save scan, launch it and verify it's running status
        LoadingCircle(TIME_THREE_SECONDS)
        assert scan_save_launch_and_status_verification(
            scan_name=scan_name, scan_folder_name=folder_name, scan_status=API.Scan.Status.RUNNING), \
            'Scan has not been in running state.'

        # Click the action button to control the scan and verify status accordingly
        LoadingCircle(WAIT_NORMAL)
        scan_list = ScanList()
        for action_to_perform in scan_details.get('scan_control_action'):
            LoadingCircle(TIME_THREE_SECONDS)
            if action_to_perform.get('control_action') == API.Scan.Actions.PAUSE:
                scan_list.pause_scan(scan_name=scan_name)
            else:
                scan_list.stop_scan(scan_name=scan_name)

            scan_status = scans_page.get_scan_status(scan_name=scan_name, scan_status=action_to_perform.get('status'))
            wait(lambda: visibility_of_element_located((scan_status.we_by, scan_status.we_value))(get_driver_no_init()),
                 waiting_for='Scan to be in required status', timeout_seconds=TIME_TEN_MINUTES)

            assert scan_status.is_displayed(), "Scan status mismatched in accordance to action taken."

        # Delete the created scan
        delete_created_scan(scan_name=scan_name)
