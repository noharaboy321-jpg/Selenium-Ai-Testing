""""
Nessus test cases related to CVSS score verification on scan results page.

:copyright: Tenable Network Security, 2021
:date: June 25, 2021
:last_modified: July 23, 202

:author: @vsoni, @krpatel
"""
from http import HTTPStatus

import pytest
from selenium.webdriver.support.expected_conditions import visibility_of_element_located
from waiting import TimeoutExpired

from catium.helpers.sleep_lib import sleep
from catium.lib.const import TIME_THIRTY_MINUTES, TIME_THIRTY_SECONDS, WAIT_NORMAL
from catium.lib.util import random_name
from catium.lib.webium.wait import wait
from nessus.helpers.polling_ui import polling_ui
from nessus.helpers.scan import get_scan_id
from nessus.helpers.waiters import wait_scan_state
from nessus.lib.const import API, Nessus
from nessus.pageobjects.advanced_settings.advanced_settings_page import AdvancedSettingsPage, AdvancedSettingsList, \
    AddAdvancedSettingModal
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.plugins.plugins_page import PluginsList, PluginDetailsWindow, Plugin
from nessus.pageobjects.scans.scan_trash_page import ScansTrashPage
from nessus.pageobjects.scans.scan_view_page import ScanViewPage, VulnerabilityList, ScansHostList, ModifyVulnerability, \
    VulnerabilityDescription
from nessus.pageobjects.scans.scans_page import ScanList, ScansPage
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav


@pytest.mark.nessus_pro
@pytest.mark.nessus_home
@pytest.mark.usefixtures('nessus_api_login', 'login')
class TestVerifyCVSSScoreOnScanResultsPage:
    cat = None

    @staticmethod
    def go_to_scan_result_and_verify_that_cvss_column_exist(scan_name: str, scan_result_tab: str) -> None:
        """
        This method go to scan result page and verifies that 'CVSS' column is present on
        'Vulnerability' or 'Hosts' tab of scan result page.

        :param str scan_name: Name of the scan
        :param str scan_result_tab: 'Hosts' or 'Vulnerabilities' tab
        :return: None
        """
        scan_list = ScanList()
        scan_list.loaded()

        scan_list.click_on_scan(scan_name=scan_name)
        scan_details_page = ScanViewPage()
        wait(lambda: scan_details_page.is_element_present('vulnerability_tab'), waiting_for='scan results to load')

        # Navigate to required tab ('Hosts'/'Vulnerabilities') for verification
        if scan_result_tab == Nessus.Scan.Results.Tabs.VULNERABILITIES_TAB:
            scan_details_page.vulnerability_tab.click()
        elif scan_result_tab == Nessus.Scan.Results.Tabs.HOSTS_TAB:
            scan_details_page.host_tab.click()
            wait(lambda: scan_details_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

            hosts_list = ScansHostList()
            hosts_list.click_on_host(host_name=hosts_list.get_host_names()[0])

        vuln_list = VulnerabilityList()
        vuln_list.loaded()
        vuln_list.vulnerability_setting.click()
        vuln_list.click_on_group_enable_disable(enable=False)

        assert vuln_list.columns[2].text == "CVSS", "Column for CVSS score is not present on {} tab". \
            format(scan_result_tab)
        assert vuln_list.columns[3].text == "VPR", "Column for VPR score is not present on {} tab". \
            format(scan_result_tab)

    @staticmethod
    def wait_till_vulnerability_loaded(vuln_name: str):
        """
        Wait till given vulnerability is loaded
        :param str vuln_name: Name of vulnerability
        """
        vuln_list = VulnerabilityList()
        vuln_list.loaded()
        wait(lambda: vuln_name in vuln_list.get_plugin_names(),
             timeout_seconds=TIME_THIRTY_SECONDS, waiting_for="Vulnerabilities list to be populated.")

    @staticmethod
    def navigate_to_host_or_vulnerability_tab(scan_result_tab: str):
        """
        Navigates to host or vulnerability tab on current scan result tab.
        """
        scan_details_page = ScanViewPage()

        # Navigate to required tab ('Hosts'/'Vulnerabilities') for verification
        if scan_result_tab == Nessus.Scan.Results.Tabs.VULNERABILITIES_TAB:
            scan_details_page.vulnerability_tab.click()
        elif scan_result_tab == Nessus.Scan.Results.Tabs.HOSTS_TAB:
            scan_details_page.host_tab.click()
            wait(lambda: scan_details_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

            hosts_list = ScansHostList()
            hosts_list.click_on_host(host_name=hosts_list.get_host_names()[0])

    @staticmethod
    def navigate_to_host_or_vulnerability_tab_for_imported_scan(imported_scan_details: tuple):
        """
        Navigates to imported scan's Host or Vulnerabilities tab.

        :param tuple imported_scan_details: Imported scan details - scan_name, created_folder_name, created_folder_id
        """
        scan_name, created_folder_name, created_folder_id = imported_scan_details
        ScansPage().refresh()
        SideNav().get_sidenav_element(element_name=created_folder_name).click()

        scan_list = ScanList()
        scan_list.loaded()

        scan_list.click_on_scan(scan_name=scan_name)
        wait(lambda: ScanViewPage().is_element_present('vulnerability_tab'), waiting_for='scan results to load')

    @pytest.mark.nessus_manager
    @pytest.mark.usefixtures('nessus_api_login', 'login')
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.BASIC_NETWORK, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'folder': Nessus.Scan.Folder.MY_SCANS.split(' (')[0], 'target_ip': Nessus.Scan.Target.PUB_TARGET_3,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.BASIC_NETWORK))}]}], indirect=True)
    @pytest.mark.parametrize('scan_result_tab', [Nessus.Scan.Results.Tabs.HOSTS_TAB,
                                                 Nessus.Scan.Results.Tabs.VULNERABILITIES_TAB])
    def test_verify_cvss_score_visibility_for_completed_scan(self, create_scans, scan_result_tab):
        """
        NES-13165 : [UI-Automation] : Verify CVSS score on 'Hosts' and 'Vulnerabilities' tab

        Scenario Tested:
            [x] Verify that 'CVSS' score column is present on 'Hosts' and 'Vulnerabilities' section of scan result page.
        """
        scan_name = create_scans[0]
        ScanList().loaded()
        scan_id = get_scan_id(api_object=self.cat.api, scan_name=scan_name)

        # Launch scan and wait for complete
        self.cat.api.scans.launch(scan_id)

        with polling_ui():
            wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                            timeout=TIME_THIRTY_MINUTES)
        ScansPage().refresh()

        # Verify that 'CVSS' score column is present on 'Hosts' and 'Vulnerabilities' tabs of scan result page.
        self.go_to_scan_result_and_verify_that_cvss_column_exist(scan_name, scan_result_tab)
        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.nessus_manager
    @pytest.mark.usefixtures('nessus_api_login', 'login')
    @pytest.mark.parametrize('import_scan_via_api', [
        {'file_name': 'Basic_Network_Scan_Result.db', 'file_path': 'nessus/tests/ui/scans/test_data/',
         'password': 'nessus', 'create_folder': True, 'encrypted': True},
        pytest.param({'file_name': 'Basic_agent_scan_7171ny.nessus', 'file_path': 'nessus/tests/ui/scans/test_data/',
                      'create_folder': True}, marks=pytest.mark.nessus_manager),
        pytest.param({'file_name': 'Basic_agent_scan_6xkzb9.db', 'file_path': 'nessus/tests/ui/scans/test_data/',
                      'password': 'nessus', 'create_folder': True, 'encrypted': True},
                     marks=pytest.mark.nessus_manager)], indirect=True)
    @pytest.mark.parametrize('scan_result_tab', [Nessus.Scan.Results.Tabs.HOSTS_TAB,
                                                 Nessus.Scan.Results.Tabs.VULNERABILITIES_TAB])
    @pytest.mark.nessus_expert
    def test_verify_cvss_score_visibility_for_imported_scan(self, scan_result_tab, import_scan_via_api):
        """
        NES-13165 : [UI-Automation] : Verify CVSS score on 'Hosts' and 'Vulnerabilities' tab

        Scenario Tested:
            [x] For Imported scans, Verify that 'CVSS' score column is present on 'Hosts' and 'Vulnerabilities' tabs
                of scan result page.
        """
        scan_name, created_folder_name, created_folder_id = import_scan_via_api
        ScansPage().refresh()
        SideNav().get_sidenav_element(element_name=created_folder_name).click()

        # Verify that 'CVSS' score column is present on 'Hosts' and 'Vulnerabilities' tabs of scan result page.
        self.go_to_scan_result_and_verify_that_cvss_column_exist(scan_name, scan_result_tab)
        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.nessus_expert
    @pytest.mark.usefixtures('nessus_api_login', 'login')
    @pytest.mark.parametrize('import_scan_via_api', [
        {'file_name': 'Basic_Network_Scan_Result.db', 'file_path': 'nessus/tests/ui/scans/test_data/',
         'password': 'nessus', 'create_folder': True, 'encrypted': True}], indirect=True)
    @pytest.mark.parametrize('default_cvss_plugin_names', [[
        'MS11-058: Vulnerabilities in DNS Server Could Allow Remote Code Execution (2562485) (remote check)',
        'MS11-058: Vulnerabilities in DNS Server Could Allow Remote Code Execution (2562485) (uncredentialed check)']])
    @pytest.mark.parametrize('scan_result_tab', [Nessus.Scan.Results.Tabs.HOSTS_TAB,
                                                 Nessus.Scan.Results.Tabs.VULNERABILITIES_TAB])
    def test_verify_asterisk_sign_in_cvss_score_column(self, import_scan_via_api, scan_result_tab,
                                                       default_cvss_plugin_names):
        """
        NES-13191 : [UI- Automation] : Verify that CVSS score column has asterisk (*) sign
                    when cvss 3.0 score is not available

        Scenario Tested:
            For Host/Vulnerabilities tab -when CVSS 3.0 score is not available for given vulnerability then verify below
            [x] Tooltip is displayed for CVSS score
            [x] CVSS score value has asterisk sign
        """
        self.navigate_to_host_or_vulnerability_tab_for_imported_scan(imported_scan_details=import_scan_via_api)

        # Navigate to required tab ('Hosts'/'Vulnerabilities') for verification
        self.navigate_to_host_or_vulnerability_tab(scan_result_tab=scan_result_tab)

        vuln_list = VulnerabilityList()
        vuln_list.loaded()
        vuln_list.vulnerability_setting.click()
        vuln_list.click_on_group_enable_disable(enable=False)
        self.wait_till_vulnerability_loaded(vuln_name=default_cvss_plugin_names[0])

        for vuln_name in default_cvss_plugin_names:
            # Verify "asterisk" sign is displayed on given vulnerabilities for which CVSS v3.0 score is not available.
            assert "*" in vuln_list.get_cvss_score_for_given_vulnerability(vulnerability_name=vuln_name), \
                "Asterisk sign is not present in CVSS score column for vulnerability " \
                "where CVSS 3.0 score is not available."

            # Verify CVSS score tooltip when CVSS v3.0 score is not available for particular vulnerability.
            assert "CVSS v2.0 score" == vuln_list.get_cvss_score_tooltip_for_vulnerability(
                vulnerability_name=vuln_name), "Tooltip for cvss score column is not present."

    @pytest.mark.usefixtures('nessus_api_login', 'login')
    @pytest.mark.nessus_expert
    @pytest.mark.parametrize('import_scan_via_api', [
        {'file_name': 'Basic_Network_Scan_Result.db', 'file_path': 'nessus/tests/ui/scans/test_data/',
         'password': 'nessus', 'create_folder': True, 'encrypted': True}], indirect=True)
    @pytest.mark.parametrize('plugin_details', [{'name': 'SSL 64-bit Block Size Cipher Suites Supported (SWEET32)',
                                                 'cvss_score_3_0': '3.7', 'cvss_score_2_0': '2.6'}])
    @pytest.mark.parametrize('scan_result_tab', [Nessus.Scan.Results.Tabs.HOSTS_TAB,
                                                 Nessus.Scan.Results.Tabs.VULNERABILITIES_TAB])
    def test_verify_cvss_score_updates_as_per_severity_base_changes(self, import_scan_via_api, scan_result_tab,
                                                                    plugin_details):
        """
        NES-13192 : [UI - Automation] : Verify CVSS score updated in Hosts/Vulnerabilities table column

        Scenario Tested:
            [x] Verify that cvss score is updated in vulnerabilities table when user changes severity base value.
        """
        self.navigate_to_host_or_vulnerability_tab_for_imported_scan(imported_scan_details=import_scan_via_api)

        # Navigate to required tab ('Hosts'/'Vulnerabilities') for verification
        scan_details_page = ScanViewPage()
        wait(lambda: scan_details_page.is_element_present('vulnerability_tab'), waiting_for='scan results to load')

        # Navigate to required tab ('Hosts'/'Vulnerabilities') for verification
        if scan_result_tab == Nessus.Scan.Results.Tabs.VULNERABILITIES_TAB:
            scan_details_page.vulnerability_tab.click()
        elif scan_result_tab == Nessus.Scan.Results.Tabs.HOSTS_TAB:
            scan_details_page.host_tab.click()
            wait(lambda: scan_details_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

        # self.navigate_to_host_or_vulnerability_tab(scan_result_tab=scan_result_tab)

        vuln_list = VulnerabilityList()
        vuln_list.loaded()

        scan_view_page = ScanViewPage()
        severity = 'CVSS v3.0'
        scan_view_page.change_severity_base_value_from_popup(severity)

        if scan_result_tab == Nessus.Scan.Results.Tabs.HOSTS_TAB:
            hosts_list = ScansHostList()
            hosts_list.click_on_host(host_name=hosts_list.get_host_names()[0])

        LoadingCircle(WAIT_NORMAL)
        vuln_list.vulnerability_setting.click()
        vuln_list.click_on_group_enable_disable(enable=False)
        self.wait_till_vulnerability_loaded(vuln_name=plugin_details.get('name'))

        assert plugin_details.get('cvss_score_3_0') == vuln_list.get_cvss_score_for_given_vulnerability(
            plugin_details.get('name')), "CVSS score is not set as per severity base v3.0"

        if scan_result_tab == Nessus.Scan.Results.Tabs.HOSTS_TAB:
            scan_view_page.back_link.click()

        severity = 'CVSS v2.0'
        scan_view_page.change_severity_base_value_from_popup(severity)

        # Navigate to required tab ('Hosts'/'Vulnerabilities') for verification
        self.navigate_to_host_or_vulnerability_tab(scan_result_tab=scan_result_tab)

        self.wait_till_vulnerability_loaded(vuln_name=plugin_details.get('name'))

        # Verify that cvss score is updated in vulnerabilities table when user changes severity base value.
        assert plugin_details.get('cvss_score_2_0') == vuln_list.get_cvss_score_for_given_vulnerability(
            plugin_details.get('name')), \
            "CVSS score is not updated in vulnerabilities table after modifying severity base."

    @pytest.mark.usefixtures('nessus_api_login', 'login')
    @pytest.mark.nessus_expert
    @pytest.mark.parametrize('import_scan_via_api', [
        {'file_name': 'Basic_Network_Scan_Result.db', 'file_path': 'nessus/tests/ui/scans/test_data/',
         'password': 'nessus', 'create_folder': True, 'encrypted': True}], indirect=True)
    @pytest.mark.parametrize('plugin_details', ['SSL 64-bit Block Size Cipher Suites Supported (SWEET32)'])
    @pytest.mark.parametrize('scan_result_tab', [Nessus.Scan.Results.Tabs.VULNERABILITIES_TAB])
    def test_verify_cvss_score_unchanged_when_severity_modified(self, import_scan_via_api, scan_result_tab,
                                                                plugin_details):
        """
        NES-13199 : [UI - Automation] : Verify that modifying severity of vulnerability does not impact cvss score

        Scenario Tested:
            [x] Verify that cvss score does not change when plugin severity gets modified
        """
        self.navigate_to_host_or_vulnerability_tab_for_imported_scan(imported_scan_details=import_scan_via_api)

        scan_result_page = ScanViewPage()
        scan_result_page.vulnerability_tab.click()
        wait(lambda: scan_result_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

        # Making sure the severity base is set to 'CVSS v3.0' initially
        scan_view_page = ScanViewPage()
        severity = 'CVSS v3.0'
        scan_view_page.change_severity_base_value_from_popup(severity)

        # Navigate to required tab ('Hosts'/'Vulnerabilities') for verification
        self.navigate_to_host_or_vulnerability_tab(scan_result_tab=scan_result_tab)

        vuln_list = VulnerabilityList()
        vuln_list.loaded()
        vuln_list.vulnerability_setting.click()
        vuln_list.click_on_group_enable_disable(enable=False)
        self.wait_till_vulnerability_loaded(vuln_name=plugin_details)
        original_severity = vuln_list.get_severity_against_plugin(plugin_list=[plugin_details])[0]
        original_cvss_score = vuln_list.get_cvss_score_for_given_vulnerability(plugin_details)
        modify_vulns = ModifyVulnerability()
        modify_vulns.modify_vulnerability(vulnerabilities_list=[plugin_details],
                                          severity=Nessus.Scan.Severity.CRITICAL)
        self.wait_till_vulnerability_loaded(plugin_details)
        updated_severity = vuln_list.get_severity_against_plugin(plugin_list=[plugin_details])[0]

        # Verify that plugin severity modified successfully.
        assert updated_severity.capitalize() == Nessus.Scan.Severity.CRITICAL, \
            "Plugin's severity did not updated successfully."
        assert original_severity != updated_severity, "Updated severity and original severity both are same."

        cvss_score_after_severity_modified = vuln_list.get_cvss_score_for_given_vulnerability(plugin_details)

        # Verify that modifying plugin severity does not change cvss score.
        assert original_cvss_score == cvss_score_after_severity_modified, \
            "CVSS score modified after updating plugin severity."


    @pytest.mark.xray(test_key='NES-15011')
    @pytest.mark.nessus_expert
    @pytest.mark.usefixtures('nessus_api_login', 'login')
    @pytest.mark.parametrize('import_scan_via_api', [
        {'file_name': 'Basic_Network_Scan_Result.db', 'file_path': 'nessus/tests/ui/scans/test_data/',
         'password': 'nessus', 'create_folder': True, 'encrypted': True}], indirect=True)
    @pytest.mark.parametrize('plugin_details', [{'name': 'SSL 64-bit Block Size Cipher Suites Supported (SWEET32)',
                                                 'cvss_score_4_0': '3.7 *', 'cvss_score_3_0': '3.7'}])
    @pytest.mark.parametrize('scan_result_tab', [Nessus.Scan.Results.Tabs.VULNERABILITIES_TAB])
    def test_verify_score_showing_as_per_severity_base_on_vuln_page(self, import_scan_via_api, scan_result_tab,
                                                                    plugin_details):
        """
        NES-15011 : Verify that score is showing proper as per the severity base on vuln page.

        Scenario Tested:
            [x] Verify that cvss score is updated in vulnerabilities table when user changes severity base value.
        """
        self.navigate_to_host_or_vulnerability_tab_for_imported_scan(imported_scan_details=import_scan_via_api)
        self.navigate_to_host_or_vulnerability_tab(scan_result_tab=scan_result_tab)

        vuln_list = VulnerabilityList()
        vuln_list.loaded()

        scan_view_page = ScanViewPage()
        severity = 'CVSS v3.0'
        scan_view_page.change_severity_base_value_from_popup(severity)

        vuln_list.vulnerability_setting.click()
        vuln_list.click_on_group_enable_disable(enable=False)
        self.wait_till_vulnerability_loaded(vuln_name=plugin_details.get('name'))

        assert plugin_details.get('cvss_score_3_0') == vuln_list.get_cvss_score_for_given_vulnerability(
            plugin_details.get('name')), "CVSS score is not set as per severity base v3.0"

        if scan_result_tab == Nessus.Scan.Results.Tabs.HOSTS_TAB:
            scan_view_page.back_link.click()
        severity = 'CVSS v4.0'
        scan_view_page.change_severity_base_value_from_popup(severity)

        self.navigate_to_host_or_vulnerability_tab(scan_result_tab=scan_result_tab)
        self.wait_till_vulnerability_loaded(vuln_name=plugin_details.get('name'))

        assert plugin_details.get('cvss_score_4_0') == vuln_list.get_cvss_score_for_given_vulnerability(
            plugin_details.get('name')), \
            "CVSS score is not updated in vulnerabilities table after modifying severity base."

    @pytest.mark.xray(test_key='NES-17375')
    @pytest.mark.usefixtures('nessus_api_login', 'login')
    @pytest.mark.parametrize('import_scan_via_api', [
        {'file_name': 'Basic_Network_Scan_Result.db', 'file_path': 'nessus/tests/ui/scans/test_data/',
         'password': 'nessus', 'create_folder': True, 'encrypted': True}], indirect=True)
    @pytest.mark.parametrize('plugin_details', [{'name': 'SSL 64-bit Block Size Cipher Suites Supported (SWEET32)',
                                                 'cvss_score_3_0': '3.7', 'cvss_score_2_0': '2.6'}])
    @pytest.mark.parametrize('scan_result_tab', [Nessus.Scan.Results.Tabs.HOSTS_TAB])
    @pytest.mark.nessus_expert
    def test_verify_score_showing_as_per_severity_base_on_host_page(self, import_scan_via_api, scan_result_tab,
                                                                    plugin_details):
        """
            NES-17375 : Verify that score is showing proper as per the severity base on host page.

            Scenario Tested:
            [x] Verify that cvss score is updated in vulnerabilities table when user changes severity base value.
        """
        self.navigate_to_host_or_vulnerability_tab_for_imported_scan(imported_scan_details=import_scan_via_api)
        # self.navigate_to_host_or_vulnerability_tab(scan_result_tab=scan_result_tab)

        scan_details_page = ScanViewPage()
        wait(lambda: scan_details_page.is_element_present('vulnerability_tab'), waiting_for='scan results to load')

        # Navigate to required tab ('Hosts'/'Vulnerabilities') for verification
        scan_details_page.host_tab.click()
        wait(lambda: scan_details_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

        vuln_list = VulnerabilityList()
        vuln_list.loaded()

        scan_view_page = ScanViewPage()
        severity = 'CVSS v3.0'
        scan_view_page.change_severity_base_value_from_popup(severity)

        if scan_result_tab == Nessus.Scan.Results.Tabs.HOSTS_TAB:
            hosts_list = ScansHostList()
            hosts_list.click_on_host(host_name=hosts_list.get_host_names()[0])

        LoadingCircle(WAIT_NORMAL)
        vuln_list.vulnerability_setting.click()
        vuln_list.click_on_group_enable_disable(enable=False)
        self.wait_till_vulnerability_loaded(vuln_name=plugin_details.get('name'))
        assert plugin_details.get('cvss_score_3_0') == vuln_list.get_cvss_score_for_given_vulnerability(
            plugin_details.get('name')), "CVSS score is not set as per severity base v3.0"

        scan_view_page.back_link.click()
        severity = 'CVSS v2.0'
        scan_view_page.change_severity_base_value_from_popup(severity)

        self.navigate_to_host_or_vulnerability_tab(scan_result_tab=scan_result_tab)
        self.wait_till_vulnerability_loaded(vuln_name=plugin_details.get('name'))

        assert plugin_details.get('cvss_score_2_0') == vuln_list.get_cvss_score_for_given_vulnerability(
            plugin_details.get('name')), \
            "CVSS score is not updated in vulnerabilities table after modifying severity base."

    @pytest.mark.xray(test_key='NES-18124')
    @pytest.mark.usefixtures('nessus_api_login', 'import_scan_via_api', 'login')
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'cvssv4_test_plugin_scan.nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/'}], indirect=True)
    @pytest.mark.nessus_expert
    def test_plugin_details_on_scan_result_vuln_page(self, import_scan_via_api):
        """

        NES-18124 : Verify plugin details in scan result showing the cvss v4 data.

        Scenario Tested:
            [x] cvss v4 plugin data is showing up on scan results page.

        """

        # Import the cvssv4 scan result file
        scan_name = import_scan_via_api[0]
        SideNav().scan_tab_on_header.click()
        scan_view_page = ScanViewPage()
        scan_view_page.refresh()
        scan_list = ScanList()

        # Wait and click on scan once available
        wait(lambda: visibility_of_element_located(scan_list.object_table),
             waiting_for='Wait for Scan lists to appear.')
        scan_list.click_on_scan(scan_name=scan_name)

        wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
             waiting_for='Vulnerability tab to appear on page')

        # Open the vuln tab
        scan_view_page.vulnerability_tab.click()
        wait(lambda: scan_view_page.is_element_present('search_box'),
             waiting_for="Vulnerabiliies to get loaded properly.")

        # search for the cvssv4 vuln
        vuln_name = Nessus.Scan.Vulnerability.CVSSV4_VULN
        scan_view_page.search_box.value = vuln_name
        sleep(WAIT_NORMAL, reason="wait for matching vuln. results to get")

        # Click on vuln
        VulnerabilityList().click_on_vulnerability(vulnerability_name=vuln_name)
        vuln_desc = VulnerabilityDescription()
        wait(lambda: vuln_desc.is_element_present("plugin_header"),
             waiting_for="vulnerability details to get displayed")

        # Verify headers of plugins
        assert vuln_desc.plugin_header.text == Nessus.Scan.Vulnerability.CVSSV4_VULN, "CVSS v4 header is mismatched"
        assert scan_view_page.right_column_header.text == Nessus.Scan.Results.RightColumnHeader.PLUGIN_DETAILS, "Plugin detail header mismatched"

        # getting text for risk info element
        risk_info_details = [element.text for element in vuln_desc.risk_info_details]
        expected_label = ['CVSS v2.0 Base Score', 'CVSS v2.0 Temporal Score', 'CVSS v3.0 Base Score',
                          'CVSS v3.0 Temporal Score', 'CVSS v2.0 Temporal Vector', 'CVSS v3.0 Temporal Vector',
                          'CVSS v4.0 Base Score', 'CVSS v4.0 Threat Vector', 'CVSS v4.0 Vector']

        # Verify the risk info.
        assert any([option in info_option for info_option in risk_info_details for option in expected_label]), \
            "Risk info is not matched with expected info or missing some info"

        # getting text for plugin info element
        plugin_info_details = [element.text for element in vuln_desc.plugin_info_details]
        expected_plugins_info = ['Severity:', 'Critical', 'ID:', '900000', 'Family:', 'Misc.', 'Type:', 'combined']

        # Verify the plugin info.
        assert any(
            [option in plugin_option for plugin_option in plugin_info_details for option in expected_plugins_info]), \
            "Plugin info is not matched with expected info or missing some info"

    @pytest.mark.xray(test_key='NES-18271')
    @pytest.mark.usefixtures('nessus_api_login', 'import_scan_via_api', 'login')
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_-_CVSS_av5q3j.nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/'}], indirect=True)
    @pytest.mark.nessus_expert
    def test_CVSS_score_values_on_report_generation_page(self, import_scan_via_api):
        """
        NES-18271 : [E2E][UI] Verify CVSSv4 options available on CVS report generation.
        Scenario Tested:
            [x] All the report options of the group 2 on report generation is available.
        """

        scan_name = import_scan_via_api[0]
        SideNav().scan_tab_on_header.click()
        scan_view_page = ScanViewPage()
        scan_view_page.refresh()
        scan_list = ScanList()

        wait(lambda: visibility_of_element_located(scan_list.object_table),
             waiting_for='Scan lists to load')
        scan_list.click_on_scan(scan_name=scan_name)

        wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
             waiting_for='Vulnerabilities to get loads')

        scan_view_page.report_button.click()
        wait(lambda: scan_view_page.is_element_present('csv_radio_button'),
             waiting_for="Report generation page to get load.")
        scan_view_page.csv_radio_button.click()

        wait(lambda: scan_view_page.is_element_present('select_all_link'), waiting_for="csv option to get load.")
        list_options = [options.text for options in scan_view_page.csv_column_options]

        assert Nessus.CustomizedReports.GROUP2_REPORT_OPTIONS == list_options, 'Group2 Options on report generation page is not as expected.'

    @pytest.mark.xray(test_key='NES-18313')
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER,
                                              'host_ip': Nessus.Scan.Target.LOCALHOST}], indirect=True)
    def test_severity_after_change_from_setting_and_run_the_scan(self, create_scan, nessus_api_login, login):
        """
        NES-18313: [E2E][UI] Run scan after updating the 'severity_basis' default to cvss_v4

        Scenario Tested:
            [x] Verify that severity_basis is changed default to cvss4.
            [x] Verify scan should run and on scan result page default severity should be cvssv4.
        """
        # save the created scan
        ScansPage().save_button.click()
        scan_list = ScanList()
        scan_list.loaded()

        # Go to the settings page to change the severity
        advanced_setting = AdvancedSettingsPage()
        advanced_setting.open()
        advanced_setting_list = AdvancedSettingsList()

        # getting value before change
        setting_tab = Nessus.AdvancedSettings.SCANNING_TAB
        setting_value_before_change = advanced_setting_list.get_settings_value(setting_tab=setting_tab,
                                                                               setting_name='severity_basis')

        wait(lambda: advanced_setting.is_element_present('search_textbox'),
             waiting_for="Advanced settings page to get loaded.")
        advanced_setting.search_textbox.value = 'severity_basis'

        try:
            wait(lambda: Nessus.AdvancedSettings.SEVERITY_BASIS in advanced_setting_list.get_all_settings_name(),
                 waiting_for='"{}" advanced setting to get loaded.'.format(Nessus.AdvancedSettings.SEVERITY_BASIS))
        except TimeoutExpired:
            raise AssertionError("'{}' does not found in advanced settings.".format(
                Nessus.AdvancedSettings.SEVERITY_BASIS))

        # Change the severity to cvssv4 if not
        if setting_value_before_change[0] != Nessus.AdvancedSettings.CVSS_V4:

            # Open the edit severity popup
            setting_modal = AddAdvancedSettingModal()
            setting_modal.find_specific_setting_name(setting_name='severity_basis').click()
            try:
                wait(lambda: setting_modal.is_element_present('modal'),
                     waiting_for='Modal to appear for changing severity base setting.')
            except TimeoutExpired:
                raise AssertionError("Severity base pop up is not visible after clicking on setting.")

            setting_modal.allow_post_scan_edit_dropdown.select_by_visible_text(Nessus.AdvancedSettings.CVSS_V4)
            setting_modal.action_button.click()
            setting_modal.wait_for_modal_closed()
            sleep(WAIT_NORMAL, reason="Setting value takes little bit time to get updated.")

            setting_value_after_change = advanced_setting_list.get_settings_value(setting_tab=setting_tab,
                                                                                  setting_name='severity_basis')

            # verify that severity is changed properly
            assert setting_value_after_change[
                       0] == Nessus.AdvancedSettings.CVSS_V4, 'CVSS v4 value is not updated to cvssv4 after change.'

        SideNav().scan_tab_on_header.click()
        scan_list = ScanList()
        scan_list.loaded()

    @pytest.mark.xray(test_key='NES-18123')
    @pytest.mark.nessus_expert
    @pytest.mark.parametrize('add_advance_setting', [
        {'payload': {"setting.0.id": "", "setting.0.name": "severity_basis",
                     "setting.0.value": "cvss_v4", "setting.0.action": "edit"}, "remove_added_setting": True}], indirect=True)
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER,
                                              'host_ip': Nessus.Scan.Target.LOCALHOST}], indirect=True)
    def test_plugin_info_dialog_shows_cvssv4_data(self, nessus_api_login, login, create_scan, add_advance_setting):
        """
        NES-18123 : [E2E][UI] Verify the plugin info dialog shows the cvss v4 data.
        Steps:
            [1] Create a scan with localhost and save it.
            [2] Access the cvssv4 test nasl file from s3 bucket
            [3] Place the file to plugin directory
            [4] Reload and compile all the plugins
            [5] Restart the Nessus to get all the changes
            [6] Lunch the created scan and wait for it to complete
            [7] Open the scan and click on configure
            [8] Click on filter and apply the cvss v4 filter
            [9] Open the applied plugin
            [10] Click on the plugin and check the cvssv4 data

        Scenarios Tested:
            [x] On plugins list page cvssv4 plugin is available
            [x] Plugin data is available for cvssv4 on plugins details page.
        """
        remote_path = None

        ScansPage().save_button.click()

        payload = add_advance_setting
        self.cat.api.settings.update(payload)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        # TODO : (This part seems not require as of now so commenting, might need in future as an when CVSS score changes)
        # with SSH() as ssh:
        #     # get the test  file from s3 bucket
        #     cvssv4_test_file = S3Client.get_local_path('nessus/tests/ui/scans/test_data/cvssv4_test.nasl')
        #
        #     # define the remote file location to upload the file
        #     json_path = os.path.join(NESSUS_PLUGIN_DIR, 'cvssv4_test.nasl')
        #     if get_default_nessus_dir() == '/opt/nessus':
        #         remote_path = json_path.replace("\\", "/")
        #
        #     # upload the file to remote from local
        #     upload(cvssv4_test_file, remote_path)
        #
        #     # reload and re-compile the nessus plugin directory
        #     output_ssh = ssh.execute("{} -R".format(path_join(path_dir_list=[NESSUS_SBIN_DIR,
        #                                                                      'nessusd'])))
        #
        #     # Verify that all the plugins are done compiling
        #     assert "All plugins loaded" in output_ssh[3]
        #
        #     # Restart the nessusd service and re-login to nessus UI
        #     restart_scanner(nessus_api_login)
        #     get_driver().refresh()
        #     wait(lambda: visibility_of_element_located(LoginPage().username_field))
        #     LoginPage().login_with_defaults()
        #     LoadingCircle(WAIT_NORMAL)

        SideNav().scan_tab_on_header.click()
        scan_list = ScanList()

        # triggered the saved scan to get cvssv4 plugin to get hit
        scan_list.launch_scan_and_wait_for_status(scan_name=create_scan, status=API.Scan.Status.COMPLETED)

        wait(lambda: visibility_of_element_located(scan_list.object_table),
             waiting_for='Scan lists to load')

        # open the scan result page
        scan_list.click_on_scan(scan_name=create_scan)

        scan_view_page = ScanViewPage()
        wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
             waiting_for='Vulnerabilities to get loads')

        # open the vuln. tab
        scan_view_page.vulnerability_tab.click()
        wait(lambda: scan_view_page.is_element_present('search_box'),
             waiting_for="Vulnerability page to properly load.")

        # verify after the scan, cvssv4 is updated.
        assert scan_view_page.severity_base_value.text == Nessus.AdvancedSettings.CVSS_V4, 'Severity base value is not changed on scan results page.'

        wait(lambda: visibility_of_element_located(scan_view_page.configure_button),
             waiting_for='Configure button to appear on the page after on scan results page.')

        # Open the configure page
        scan_view_page.configure_button.click()
        wait(lambda: visibility_of_element_located(scan_view_page.plugin_tab),
             waiting_for='Plugins tab to get load properly after clicking on configure scan button.')

        # Click on plugins tab
        scan_view_page.plugin_tab.click()
        wait(lambda: visibility_of_element_located(scan_view_page.filter_link),
             waiting_for='Filter link to get available on the page after clicking on plugins tab.')

        # Open the plugin filter
        scan_view_page.filter_link.click()

        action_modal = ActionCloseModal()
        wait(lambda: action_modal.is_element_present('modal'))

        # apply the filter
        label = 'CVSS v4.0 Base Score'
        scan_view_page.apply_filter(key=label, operator=Nessus.Filter.FilterOperators.IS_LESS_THAN,
                                    value=str(2), apply=False)
        scan_view_page.apply_button.click()

        # Verify the plugin family
        wait(lambda: visibility_of_element_located(scan_view_page.plugin_family_data),
             waiting_for='Vulnerabilities to get loads')
        assert visibility_of_element_located(
            scan_view_page.plugin_family_data), "Plugin having cvssv4 is not found after applying filter on the page."

        # Verify the data on plugin details popup
        plugin_details = {'plugin_family': 'Misc.', 'plugin_name': 'Linux Distros Unpatched Vulnerability : CVE-2025-54080'}
        PluginsList().click_on_plugins(plugin_details["plugin_family"], plugin_details["plugin_name"])

        assert PluginDetailsWindow().details_window_title == plugin_details[
            "plugin_name"], "Title of plugin is not matched after opening the plugin detail popup."

        # Gathering all the data from the page.
        plugin_page_data = PluginDetailsWindow().get_section_data()

        # Verifying all the data with the expected result.
        assert plugin_page_data[
                   'Risk Information'] == Nessus.Scan.Results.PlugInDetailsLevels.CVSSV4_RISK_INFO, "CVSSV4 risk information is not matched as expected."
        assert plugin_page_data[
                   'Synopsis'] == Nessus.Scan.Results.PlugInDetailsLevels.CVSSV4_SYNOPSIS, "CVSSV4 Synopsis is not matched as expected."
        assert plugin_page_data[
                   'Plugin Information'] == Nessus.Scan.Results.PlugInDetailsLevels.CVSSV4_PLUGIN_INFO, "CVSSV4 Plugin Information is not matched as expected."
        assert plugin_page_data[
                   'Solution'] == Nessus.Scan.Results.PlugInDetailsLevels.CVSSV4_SOLUTION, "CVSSV4 Plugin solution is not matched as expected."
        assert plugin_page_data[
                   'See Also'] == Nessus.Scan.Results.PlugInDetailsLevels.CVSSV4_SEE_ALSO, "CVSSV4 Plugin see also is not matched as expected."

        # modal close
        ActionCloseModal().close_button.click()
        ActionCloseModal().wait_for_modal_closed()
        wait(lambda: visibility_of_element_located(Plugin().filter), waiting_for='Vulnerabilities to get loads')

    @pytest.mark.xray(test_key='NES-18125')
    @pytest.mark.usefixtures('nessus_api_login', 'import_scan_via_api', 'login')
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'cvssv4_test_plugin_scan.nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/'}],
                             indirect=True)
    @pytest.mark.nessus_expert
    def test_cvssv4_filter_options_on_scan_results_page(self, import_scan_via_api):
        """

        NES-18125 : Verify the cvss v4 filters are showing up and working correctly.
        Scenario Tested:
            [x] cvss v4 filter options are available on the scan results page.

        """

        # Import the cvssv4 scan result file
        scan_name = import_scan_via_api[0]
        SideNav().scan_tab_on_header.click()
        scan_view_page = ScanViewPage()
        scan_view_page.refresh()
        scan_list = ScanList()

        # Wait and click on scan once available
        wait(lambda: visibility_of_element_located(scan_list.object_table),
             waiting_for='Wait for Scan lists to appear.')
        scan_list.click_on_scan(scan_name=scan_name)

        wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
             waiting_for='Vulnerability tab to appear on page')

        # Open the vuln tab
        scan_view_page.vulnerability_tab.click()
        wait(lambda: scan_view_page.is_element_present('search_box'),
             waiting_for="Vulnerabiliies to get loaded properly.")

        # click on filter link
        scan_view_page.filter_link.click()

        # open the filter options
        scan_view_page.open_filter.click()

        # getting the text for filter options
        options = scan_view_page.filter_key_dropdowns
        filter_option = []
        for option in options:
            filter_option.append(option.text)

        # Verifying the filter options
        assert (all(x in filter_option for x in Nessus.Filter.CVSSV4_FILTER_OPTION))
        scan_view_page.close_filter.click()

        # deleting the scan
        HeaderBasePage().scan_link.click()
        scan_list.refresh()
        ScanList().delete_scan(scan_name=scan_name)
        ScansTrashPage().delete_scan_from_trash(scan_name=scan_name)
