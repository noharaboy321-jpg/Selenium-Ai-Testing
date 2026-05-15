"""
Cluster manager related tests

:copyright: Tenable Network Security, 2021
:date: March 18, 2021
:last_modified: March 18, 2020
:author: @vsoni
"""
import pytest
from selenium.webdriver.support.expected_conditions import visibility_of_element_located
from waiting import TimeoutExpired

from catium.lib.util import random_name
from catium.lib.webium.wait import wait
from nessus.lib.const import Nessus
from nessus.pageobjects.advanced_settings.advanced_settings_page import AdvancedSettingsPage, AdvancedSettingsList
from nessus.pageobjects.scans.scan_view_page import ScanViewPage
from nessus.pageobjects.scans.scans_page import ScanList


@pytest.mark.cluster_manager
@pytest.mark.usefixtures('create_manager_cluster', 'login')
@pytest.mark.parametrize('create_manager_cluster', [{'total_nodes': 1, 'total_agents': 1}], indirect=True)
class TestSeverityBaseOnClusterManager:

    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'folder': Nessus.Scan.Folder.MY_SCANS.split(' (')[0], 'target_ip': Nessus.Scan.Target.AWS_LINUX_TARGET_1,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED))}]}], indirect=True)
    def test_verify_scan_severity_base_can_not_be_changed_in_cluster_manager(self, create_scans):
        """
        NES-12825 : [UI - Automation] : Verify that user can not change severity base of scan in cluster manager

        Scenario Tested:
            [x] Verify that user can not change scan severity base from created scan result page in cluster manager.
        """
        scan_list = ScanList()

        # Launching created scan and waiting to be completed
        assert scan_list.launch_scan_and_wait_for_status(create_scans[0]), "launch of created scan wasn't successful"

        # Click on scan
        scan_list.click_on_scan(create_scans[0])
        scan_view_page = ScanViewPage()
        wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
             waiting_for='Vulnerabilities to get loads')

        assert scan_view_page.severity_base_value.text in ['CVSS v2.0', 'CVSS v3.0'], \
            "Severity base value does not loaded correctly."

        # Verify that pencil icon is not visible in created scan result page.
        assert not scan_view_page.is_element_present('severity_base_change_icon'), \
            "Pencil icon is present for severity base change in cluster manager."

    def test_verify_user_can_not_update_severity_base_from_settings(self):
        """
        NES-12825 : [UI - Automation] : Verify that user can not change severity base of scan in cluster manager

        Scenario Tested:
            [x] Verify that user can not change severity_basis from advanced settings in cluster manager.
        """
        advanced_setting_page = AdvancedSettingsPage()
        advanced_setting_page.open()
        wait(lambda: advanced_setting_page.is_element_present('search_textbox'),
             waiting_for="Advanced settings page to get loaded.")
        advanced_setting_page.search_textbox.value = 'severity_basis'
        advanced_setting_list = AdvancedSettingsList()

        # Verify that user can not change severity_basis from advanced setting in cluster manager.
        try:
            wait(lambda: advanced_setting_list.is_element_present('empty_advanced_settings'),
                 waiting_for="Advanced settings list to get empty as per the search text.")
        except TimeoutExpired:
            raise AssertionError("{} setting found in cluster manager.".format(Nessus.AdvancedSettings.SEVERITY_BASIS))
