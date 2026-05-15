""""
Nessus test cases related to EPSS score verification on scan results page.

:copyright: Tenable Network Security, 2024
:date: May 17, 2024
:last_modified: Dec 17, 2024
:author: @mdabra
"""

import pytest
from catium.lib.const import TIME_THIRTY_MINUTES
from catium.helpers.sleep_lib import sleep
from catium.lib.const.base_constants import WAIT_SHORT, WAIT_NORMAL
from catium.lib.util import random_name
from catium.lib.webium.wait import wait
from nessus.helpers.polling_ui import polling_ui
from nessus.helpers.waiters import wait_scan_state
from nessus.lib.const import Nessus
from nessus.pageobjects.scans.scan_view_page import ScanViewPage, VulnerabilityList
from nessus.pageobjects.scans.scans_page import ScanList, ScansPage
from nessus.pageobjects.sidenav.sidenav import SideNav
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.lib.const.constants import SortOrder, API
from nessus.helpers.scan import get_scan_id, click_on_scan_and_go_to_vulnerabilities_tab
from nessus.helpers.sort import sort_on_column_values
from nessus.pageobjects.shared.loading import LoadingCircle
from catium.lib.log import create_logger
from selenium.webdriver.support.expected_conditions import visibility_of_element_located

log = create_logger()


@pytest.mark.nessus_expert
@pytest.mark.nessus_manager
@pytest.mark.scanning
@pytest.mark.usefixtures('nessus_api_login', 'login')
class TestVerifyEpssScoreOnScanResultsPage:
    cat = None

    @staticmethod
    def go_to_scan_result_and_verify_that_epss_column_exist(scan_name: str, scan_result_tab: str) -> None:
        """
        This method go to scan result page and verifies that 'EPSS' column is present on
        'Vulnerability' tab of scan result page.

        :param str scan_name: Name of the scan
        :param str scan_result_tab: 'Vulnerabilities' tab
        :return: None
        """
        scan_list = ScanList()
        scan_list.loaded()

        scan_list.click_on_scan(scan_name=scan_name)
        scan_details_page = ScanViewPage()
        wait(lambda: scan_details_page.is_element_present('vulnerability_tab'), waiting_for='scan results to load')

        if scan_result_tab == Nessus.Scan.Results.Tabs.VULNERABILITIES_TAB:
            scan_details_page.vulnerability_tab.click()

        vuln_list = VulnerabilityList()
        vuln_list.loaded()
        vuln_list.vulnerability_setting.click()
        vuln_list.click_on_group_enable_disable(enable=False)

        assert vuln_list.columns[4].text == "EPSS", "Column for EPSS score is not present on {} tab". \
            format(scan_result_tab)

    @pytest.mark.xray(test_key='NES-18187')
    @pytest.mark.xray(test_key='NES-18185')
    @pytest.mark.xray(test_key='NES-18184')
    @pytest.mark.usefixtures('nessus_api_login', 'login')
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'folder': Nessus.Scan.Folder.MY_SCANS.split(' (')[0], 'target_ip': Nessus.Scan.Target.PUB_TARGET_4,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED))}]}], indirect=True)
    @pytest.mark.parametrize('scan_result_tab', [Nessus.Scan.Results.Tabs.VULNERABILITIES_TAB])
    def test_verify_epss_column_visibility_for_completed_scan(self, create_scans, scan_result_tab):
        """
        NES-18184 : [UI-Automation] : [E2E] Validate EPSS column is visible on a scan result page
        NES-18185 : [UI-Automation] : [E2E] Validate EPSS score is getting populated for a scan result
        NES-18187 : [UI-Automation] : [E2E] Validate EPSS score can be filtered in scan result page
        Scenario Tested:
            [1] Run an Advance network scan and wait for the scan result.
            [2] Go to scan result > Vulnerabilities
            [3] Check EPSS column should be present in the Vulnerabilities tab.
            [4] Validate EPSS score is getting populated for a scan result.
            [5] Validate EPSS score can be filtered in scan result page
        """
        try:
            scan_name = create_scans[0]
            scan_list = ScanList()
            scan_list.loaded()
            scan_id = get_scan_id(api_object=self.cat.api, scan_name=scan_name)
            self.cat.api.scans.launch(scan_id)
            with polling_ui():
                wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                timeout=TIME_THIRTY_MINUTES)
            ScansPage().refresh()
            self.go_to_scan_result_and_verify_that_epss_column_exist(scan_name, scan_result_tab)
            ScansPage().refresh()
            scan_view_page = ScanViewPage()
            scan_view_page.clear_filter()
            scan_view_page.filter_link.click()
            action_modal = ActionCloseModal()
            wait(lambda: action_modal.is_element_present('modal'))
            scan_view_page.apply_filter(key='EPSS Score', operator=Nessus.Filter.FilterOperators.IS_MORE_THAN,
                                        value='0.0001', apply=False)
            action_modal.accept_action()
            action_modal.wait_for_modal_closed()
            sleep(2, reason='Waiting for scan filtered page to load')
            assert scan_view_page.total_records_count != 0, 'Filtered EPSS scores are empty for more than operator'
            scan_view_page.clear_filter()
            scan_view_page.filter_link.click()
            scan_view_page.apply_filter(key='EPSS Score', operator=Nessus.Filter.FilterOperators.IS_LESS_THAN,
                                        value='0.99', apply=False)
            action_modal.accept_action()
            action_modal.wait_for_modal_closed()
            sleep(2, reason='Waiting for scan filtered page to load')
            assert scan_view_page.total_records_count != 0, 'Filtered EPSS scores are empty for less than operator'
        finally:
            SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.ALL_SCANS).click()
            for scan in scan_list.get_all_scans():
                scan_list.delete_scan(scan_name=scan)
                LoadingCircle(WAIT_SHORT)
            SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.xray(test_key='NES-18197')
    @pytest.mark.xray(test_key='NES-18186')
    @pytest.mark.parametrize('import_scan_via_api', [
        {'file_name': 'Basic_Network_Scan_Result.db', 'file_path': 'nessus/tests/ui/scans/test_data/',
         'password': 'nessus', 'encrypted': True}], indirect=True)
    @pytest.mark.parametrize('sort', SortOrder.VALID_ORDERS)
    @pytest.mark.parametrize('column_to_sort', ['EPSS'])
    def test_sorting_of_epss_column_for_imported_scan(self, import_scan_via_api, sort, column_to_sort):
        """
        NES-18197 [E2E] Validate Import of scan db should display EPSS score properly.
        NES-18186 [E2E] Validate EPSS score column can be sorted in ascending & descending order
        Scenario Tested:
        [x] Verify that importing of exported scan db of 'EPSS Score' working properly.
        [x] Verify that sorting of 'EPSS Score' column is working properly.
        """
        click_on_scan_and_go_to_vulnerabilities_tab(scan_name=import_scan_via_api[0])
        vulnerability_list = VulnerabilityList()
        vulnerability_list.vulnerability_setting.click()
        vulnerability_list.click_on_group_enable_disable(enable=False)
        sleep(WAIT_SHORT, reason="Takes little bit time to get loaded the vulnerabilities after enable/Disable group")
        scan_view_page = ScanViewPage()
        scan_view_page.clear_filter()
        scan_view_page.filter_link.click()
        action_modal = ActionCloseModal()
        wait(lambda: action_modal.is_element_present('modal'))
        scan_view_page = ScanViewPage()
        scan_view_page.apply_filter(key='EPSS Score', operator=Nessus.Filter.FilterOperators.IS_MORE_THAN, value='0.01',
                                    apply=False)
        action_modal.accept_action()
        action_modal.wait_for_modal_closed()
        sleep(5, reason='Waiting for scan filtered page to load')
        column_mapping = {'EPSS': {'attribute': 'epss_score_value', 'key': float}}
        map_attribute = column_mapping[column_to_sort]['attribute']
        map_key = column_mapping[column_to_sort]['key']
        vulnerabilities_list = VulnerabilityList()
        expected_list = sorted([getattr(vulnerability, map_attribute) for vulnerability in
                                vulnerabilities_list.rows], key=map_key, reverse=(sort == SortOrder.DESCENDING))
        LoadingCircle(WAIT_NORMAL)
        rendered_list = sort_on_column_values(page_class_instance=vulnerabilities_list, sort=sort,
                                              column_name=column_to_sort)
        sleep(5, reason='Waiting for scan result')
        assert expected_list == [getattr(vulnerability, map_attribute) for vulnerability in rendered_list], \
            "{} is not sorted in {} order".format(column_to_sort, sort)
        scan_view_page.back_link.click()

    @pytest.mark.xray(test_key='NES-18188')
    @pytest.mark.parametrize('import_scan_via_api', [
        {'file_name': 'Basic_Network_Scan_Result.db', 'file_path': 'nessus/tests/ui/scans/test_data/',
         'password': 'nessus', 'encrypted': True}], indirect=True)
    def test_epss_info_in_risk_info_section(self, import_scan_via_api):
        """
        NES-18188 [E2E] Validate Exploit Prediction Scoring System info is displayed in Plugin details section
        """
        click_on_scan_and_go_to_vulnerabilities_tab(scan_name=import_scan_via_api[0])
        vulnerability_list = VulnerabilityList()
        vulnerability_list.vulnerability_setting.click()
        vulnerability_list.click_on_group_enable_disable(enable=False)
        sleep(WAIT_SHORT, reason="Takes time to get loaded the vulnerabilities after enable/Disable group")
        scan_view_page = ScanViewPage()
        scan_view_page.clear_filter()
        scan_view_page.filter_link.click()
        action_modal = ActionCloseModal()
        wait(lambda: action_modal.is_element_present('modal'))
        scan_view_page = ScanViewPage()
        scan_view_page.apply_filter(key='EPSS Score', operator=Nessus.Filter.FilterOperators.IS_MORE_THAN, value='0.01',
                                    apply=False)
        action_modal.accept_action()
        action_modal.wait_for_modal_closed()
        sleep(5, reason='Waiting for scan filtered page to load')
        plugins_name = vulnerability_list.get_plugin_names()
        log.debug("Plugin name :: {}".format(plugins_name))
        vulnerability_list.click_on_vulnerability(vulnerability_name=plugins_name[0])
        wait(lambda: visibility_of_element_located(scan_view_page.right_column_header),
             waiting_for='Vulnerability details to get loads')
        assert visibility_of_element_located(scan_view_page.epss_risk_information), \
            "Exploit Prediction Scoring System (EPSS) attribute is not visible"
