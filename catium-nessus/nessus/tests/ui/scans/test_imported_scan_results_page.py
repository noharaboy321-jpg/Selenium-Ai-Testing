""""
Nessus test cases related to Scan results page

:copyright: Tenable Network Security, 2019
:date: March 27, 2018
:last_modified: May 16, 2023
:author: @rdutta, @dkothari, @yshah, @kpanchal, @krpatel.ctr, @sacharya
"""
import os
import random
import time
from datetime import datetime, timedelta
from http import HTTPStatus

import pytest
from selenium.webdriver.support.expected_conditions import visibility_of_element_located
from waiting import TimeoutExpired

from catium.helpers.sleep_lib import sleep
from catium.helpers.testdata import get_file_path
from catium.lib.const import WAIT_SHORT, WAIT_NORMAL, TIME_THREE_SECONDS
from catium.lib.const.base_constants import TIME_TWENTY_SECONDS, TIME_THIRTY_SECONDS, TIME_SIXTY_SECONDS, \
    TIME_TEN_SECONDS, TIME_THIRTY_MINUTES
from catium.lib.log import create_logger
from catium.lib.util import random_name
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from catium.lib.webium.windows_handler import WindowsHandler
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.polling_ui import polling_ui
from nessus.helpers.scan import get_scan_id, click_on_scan_and_go_to_vulnerabilities_tab, create_scan_helper, \
    download_and_save_exported_scan_file, click_on_scan_and_go_to_hosts_tab
from nessus.helpers.sort import sort_on_column_values
from nessus.helpers.system import is_manager
from nessus.helpers.waiters import wait_scan_state
from nessus.lib.config import NessusConfig
from nessus.lib.const import Nessus
from nessus.lib.const.constants import OperatingSystems, SortOrder, API
from nessus.lib.message.messages import Messages
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications, close_pendo_guide_container_banner_for_nessus_pro
from nessus.pageobjects.header.user_menu import UserMenu
from nessus.pageobjects.login.login_page import LoginPage
from nessus.pageobjects.scans.new_scan_form import NewScanForm, ScanType, ScanTemplatePage
from nessus.pageobjects.scans.scan_trash_page import ScansTrashPage
from nessus.pageobjects.scans.scan_view_page import ScanViewPage, VulnerabilityList, ScanRemediationsList, \
    ScansHostList, VulnerabilityDescription, HostDetailsPage, ScanRemediations, ScanVulnerabilities, \
    ScanDashboardPage, ModifyVulnerability, HDScanHostsList, ThreatLevelVulnerabilityList
from nessus.pageobjects.scans.scans_page import ScansPage, ScanList
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav

log = create_logger()


def navigated_to_imported_scan(folder: str, scan_name: str) -> None:
    """
    Navigated to the folder where the imported scan listed and
    Click on the scan to view scan_results_page
    :param str folder: folder where scan has imported
    :param str scan_name: scan name
    """
    scan_page = ScansPage()
    scan_page.refresh()
    wait(lambda: scan_page.is_element_present("scan_searchbox") or scan_page.is_element_present(
        "create_a_new_scan_link"), waiting_for="Scan page gets loaded properly")

    SideNav().get_sidenav_element(element_name=folder).click()
    scan_list = ScanList()
    scan_list.loaded()
    wait(lambda: scan_page.is_element_present("scan_searchbox"))

    scan_list.click_on_scan(scan_name=scan_name)
    wait(lambda: ScanViewPage().is_element_present('header_element', timeout=TIME_THIRTY_SECONDS),
         waiting_for='Scan header to become visible')


def navigated_to_scan_result(scan_name: str) -> None:
    """
    Navigated to the folder where the imported scan listed and
    Click on the scan to view scan_results_page
    :param str scan_name: scan name
    """
    scan_page = ScansPage()
    scan_page.refresh()
    wait(lambda: scan_page.is_element_present("scan_searchbox") or scan_page.is_element_present(
        "create_a_new_scan_link"), waiting_for="Scan page gets loaded properly")

    scan_list = ScanList()
    scan_list.loaded()
    wait(lambda: scan_page.is_element_present("scan_searchbox"))

    scan_list.click_on_scan(scan_name=scan_name)
    wait(lambda: ScanViewPage().is_element_present('header_element', timeout=TIME_THIRTY_SECONDS),
         waiting_for='Scan header to become visible')


def grouping_enable_disable(enabled: bool) -> None:
    """
    Enabled or disable the grouping from Vulnerability list
    :param bool enabled : If True click ‘Enable Groups’ else click ‘Disable Groups’ option under vulnerability setting
    """
    vulnerability_list = VulnerabilityList()
    vulnerability_list.vulnerability_setting.click()
    if vulnerability_list.is_element_present("enable_disable_groups"):
        vulnerability_list.click_on_group_enable_disable(enable=enabled)


@pytest.mark.scans_2
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login', 'login')
@pytest.mark.parametrize('import_scan_via_api', [
    {'file_name': 'Basic_Network_Scan_Result.db', 'file_path': 'nessus/tests/ui/scans/test_data/',
     'password': 'nessus', 'create_folder': False, 'encrypted': True}], indirect=True)
class TestSpeCharacterScan:
    """
    Covers special character scan name import and upload from CS issue.
    """
    cat = None

    def test_configure_scan_name_and_export(self, import_scan_via_api):
        """
        CS-59893: Test to configure a scan name from scan_result page and export.
        1. Login to the Nessus
        2. On main scan page, verify scan list or empty scan.
        3. Import basic scan file on page and confirm
        4. Click on the imported file and go to scan result page
        5. Click on configure button and go to edit page
        6. Change the scan name to add / and ()
        7. Click on save and go back to scan result
        8. Confirm that scan name is changed
        9. Using API call, export the scan and check the response.
        """
        imported_scan_name, scan_id = import_scan_via_api
        navigated_to_scan_result(scan_name=imported_scan_name)

        scan_result_page = ScanViewPage()
        # go to edit page by clicking on configure button
        scan_result_page.configure_button.click()
        LoadingCircle(TIME_THREE_SECONDS)

        scan_form = NewScanForm()
        assert all([(scan_form.page_heading == '{} / Configuration'.format(imported_scan_name)),
                    (scan_form.back_link.text == 'Back to Scan Report'), scan_form.is_element_present('back_link')]), \
            "Header elements are not visible or mismatched"

        # Change the scan name to add unique signs
        configured_scan_name = "{}(172.26.17.0/18)".format(imported_scan_name)
        scan_form.name_field.value = configured_scan_name

        # Save the change and confirm.
        scan_form.save_button.click()
        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            "Success notifications for scan saved is mismatched or missing."

        scan_form.back_link.click()

        # export scan
        export = self.cat.api.scans.export(scan_id=scan_id,
                                           export_format=API.Scan.ExportFormats.FORMAT_DB,
                                           password='a')

        # Get the export status and verify 200 response
        export_status = self.cat.api.scans.export_status(scan_id, export[0])
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Verify export status was retrieved
        assert export_status, "Export status was not retrieved."

        # wait for to get ready state and max wait for 30 sec
        wait(lambda: self.cat.api.scans.export_status(scan_id,
                                                      export[0]) == API.Status.READY,
             timeout_seconds=30, waiting_for='Scan to go state %s' % API.Status.READY, sleep_seconds=WAIT_NORMAL)

        # Delete the imported scan
        self.cat.api.scans.delete(scan_id)


@pytest.mark.scans_2
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login', 'login')
@pytest.mark.parametrize('import_scan_via_api', [
    {'file_name': 'Basic_Network_Scan_Result.db', 'file_path': 'nessus/tests/ui/scans/test_data/',
     'password': 'nessus', 'create_folder': True, 'encrypted': True}], indirect=True)
class TestImportedScanResults:
    """
    Covers Scan details page related test cases in Scans page.
    # NQA-1069 : Automation tests for Scans - Results.
    Sub-part: All test with imported scan.
    Pre-requisite: There should be a successfully imported scan exist.
    # NES-8931 : Fix scans related skipped test cases
    """
    cat = None
    filter_values = [(datetime.today().date() - timedelta(days=700)),
                     'Nessus', '48.2', '000', Nessus.Scan.Severity.MEDIUM]
    mapping_filter_data = \
        {'Single_filter': [{Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_NAME,
                            Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.CONTAINS,
                            Nessus.Filter.VALUE: filter_values[1]}],
         'Multiple_filter': [{Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_MODIFICATION_DATE,
                              Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.EARLIER_THAN,
                              Nessus.Filter.VALUE: filter_values[0]},
                             {Nessus.Filter.KEY: Nessus.Filter.FilterKeys.HOSTNAME,
                              Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.CONTAINS,
                              Nessus.Filter.VALUE: filter_values[2]},
                             {Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_ID,
                              Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.NOT_CONTAINS,
                              Nessus.Filter.VALUE: filter_values[3]},
                             {Nessus.Filter.KEY: Nessus.Filter.FilterKeys.SEVERITY,
                              Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.EQUAL_TO,
                              Nessus.Filter.VALUE: filter_values[4]}]}

    def test_visibility_of_back_link_and_schedule_column_value(self, import_scan_via_api):
        """
        NES-13053 [Automation]: Verify a scan can be created by selecting single/multiple host from an imported scan

        Scenario Tested:
        [x] Verify for an imported scan the schedule is marked as "Disabled"
        [x] Verify “Back to <folder_name>” link is present.

        1. Import a scan file and Click on the scan to view the results page.
        2. Verify “Back to <folder_name>” is available.
        3. Click the link, it should take you back to the folder the scan is listed.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_result_page = ScanViewPage()
        wait(lambda: scan_result_page.is_element_present("host_tab"), waiting_for="scan results get loaded")

        assert all([scan_result_page.is_element_present('back_link'),
                    (scan_result_page.back_link.text == "Back to {}".format(created_folder_name))]), \
            "'Back to {}' link is invisible or link text is not as expected.".format(created_folder_name)

        scan_result_page.back_link.click()
        scan_list = ScanList()
        scan_list.loaded()

        assert imported_scan_name in scan_list.get_all_scans(), \
            "{} not listed under {} folder.".format(imported_scan_name, created_folder_name)

        assert [scan.schedule.text for scan in scan_list.rows if scan.name.text == imported_scan_name][
                   0] == API.Status.DISABLED, "'Schedule' column is empty or mismatch for imported scan."

    @pytest.mark.xray(test_key='NES-14287')
    def test_visibility_of_default_elements(self, import_scan_via_api):
        """
        NES-14287 : Verify "Audit Trail" and "Launch" buttons are not displayed for an imported scan

        Verify visibility of default elements.
        1. Import a scan file and Click on the scan to view the results page.
        2. Verify the presence of “Configure”/ “Export”/ “Audit Trail”/ “Launch” button available in top right header.
        3. Also verify the presence of “Hosts”/ “Vulnerabilities”/ “History” tab.
           Visibility of “Remediations”/“Notes” tabs are depending on scan targets have been chosen.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_result_page = ScanViewPage()
        wait(lambda: scan_result_page.is_element_present('export_button'),
             waiting_for="waiting for all buttons to get loaded")
        assert all([scan_result_page.is_element_present('configure_button'),
                    scan_result_page.is_element_present('export_button'),
                    scan_result_page.is_element_present('report_button'),
                    scan_result_page.is_element_present('host_tab'),
                    scan_result_page.is_element_present('vulnerability_tab'),
                    scan_result_page.is_element_present('remediation_tab')]), "All default elements are invisible."

        scan_result_page.back_link.click()

    def test_invisibility_of_history_tab_and_launch_dropdown(self, import_scan_via_api):
        """
        Verify “Launch” button dropdown and “History” tab is absent.
        1. Import a scan file and Click on the scan to view the results page.
        2. Verify there is no “Launch” button dropdown available in header.
        3. Also verify the absence of “History” tab.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_details_page = ScanViewPage()
        assert all([(not scan_details_page.is_element_present('history_tab')),
                    (not scan_details_page.is_element_present('launch_dropdown'))]), \
            "'History' tab or 'Launch' dropdown is visible."

        scan_details_page.back_link.click()

    @pytest.mark.parametrize("test_data", [{"file_path": 'nessus/tests/ui/agents/test_data/',
                                            "file_name": 'NQA-386_-_Malware_Scan.nessus'}])
    def test_availability_of_audit_trail_button_only_for_imported_db_file(self, import_scan_via_api, test_data):
        """
        Verify “Audit Trail” button is available only if you import a “.db” file.
        1. Import a scan file apart from “.db” format.
        2. Click on the imported scan (not with “.db” extension) to view the results page.
        3. Verify the absence of “Audit Trail” button in page header.
        4. Go back to folder and click on the imported scan with “.db” format.
        5. Verify “Audit Trail” button is visible now in page header.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_details_page = ScanViewPage()
        assert scan_details_page.is_element_present(element_name='audit_trail_button'), \
            "'Audit Trail' button is invisible."

        scan_details_page.back_link.click()
        file_uploaded = self.cat.api.file.upload(file=get_file_path(test_data['file_path'] + test_data['file_name']))
        response = self.cat.api.scans.import_scan(file_uploaded, folder_id=created_folder_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        scan_list = ScanList()
        scan_list.refresh()
        LoadingCircle(WAIT_NORMAL)

        scan_list.click_on_scan(scan_name=response['scan']['name'])
        LoadingCircle(WAIT_NORMAL)
        assert not scan_details_page.is_element_present(element_name='audit_trail_button'), \
            "'Audit Trail' button is visible."

        scan_details_page.back_link.click()
        self.cat.api.scans.delete(response['scan']['id'])

    def test_accuracy_for_remediation_count(self, import_scan_via_api):
        """
        # NQA-413 : UI-Scans-Verify Remediation Count is accurate.
        Test case to verify remediation count is accurate after scan.
        1. Import a scan with vulnerabilities.
        2. Check and make sure the remediation tab is present.
        3. Verify the vulnerabilities count and host count.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_details_page = ScanViewPage()
        LoadingCircle(WAIT_NORMAL)
        assert all([(scan_details_page.page_header == imported_scan_name),
                    scan_details_page.remediation_tab.is_displayed()]), \
            "Scan name in page header and Remediations tab are not visible."

        scan_details_page.remediation_tab.click()
        remediation_list = ScanRemediationsList()
        assert ScanRemediations().get_data_count() == remediation_list.get_total_rows(), \
            "Total remediations count is mismatched."

        LoadingCircle(WAIT_NORMAL)
        while True:
            for action in remediation_list.rows:
                assert all([action.vulnerabilities.is_displayed(),
                            action.hosts.is_displayed()]), "Vulns and Hosts for this remediation action is not visible."
            if remediation_list.object_table.table_wrapper.is_button_enabled('next_page_button'):
                remediation_list.object_table.table_wrapper.next_page_button.click()
            else:
                break

        scan_details_page.back_link.click()

    def test_vulnerabilities_chart_in_page_sidebar(self, import_scan_via_api):
        """
        Verify vulnerabilities chart in side bar.
        1. Import a scan file and Click on the scan to view the results page.
        2. Hover on the any severity level in the chart.
        3. Verify a numbered percentage will be visible.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        found = False
        scan_result_page = ScanViewPage()
        scan_result_page.host_tab.click()
        wait(lambda: scan_result_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

        for level in Nessus.Scan.Severity.SEVERITY_LEVELS:
            element_of_chart = scan_result_page.get_levels_element_of_chart(level.upper())
            element_of_chart.location_once_scrolled_into_view
            element_of_chart.click()
            LoadingCircle(WAIT_SHORT)
            if scan_result_page.is_element_present('percentile_in_chart'):
                found = True
                value_of_percentage_count = scan_result_page.percentage_count.text
                assert all([('%' in value_of_percentage_count), (int(value_of_percentage_count[:-1]) > 0),
                            (int(value_of_percentage_count[:-1]) <= 100)]), \
                    "Vulnerabilities count or percentile character is missing."
            else:
                log.info("No vulnerabilities count available with '%s' severity level.", level)

        assert found, "No vulnerability percentage count found with any of the severity level in scan_results page."

        scan_result_page.js_scroll_into_view(element=scan_result_page.back_link)
        scan_result_page.back_link.click()

    @pytest.mark.parametrize('count_of_filter', ['Single_filter', 'Multiple_filter'])
    def test_filter_on_hosts_tab(self, import_scan_via_api, count_of_filter):
        """
        Verify list are gets filter according to applied filter values on 'Hosts' tab in scan_result page.
        1. Import a scan file and Click on the scan to view the results page.
        2. Navigate to any of the above tab, click “Filter” link.
        3. Filter window should pop-up, put some filter values and “Apply” it.
        4. The filter count should be visible in the left side of “Filter” link.
        5. Verify the list got filtered against filter value.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_result_page = ScanViewPage()
        scan_result_page.host_tab.click()
        wait(lambda: scan_result_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

        for data in self.mapping_filter_data[count_of_filter]:
            scan_result_page.apply_filter(key=data.get(Nessus.Filter.KEY), operator=data.get(Nessus.Filter.OPERATOR),
                                          value=data.get(Nessus.Filter.VALUE))
            LoadingCircle(TIME_THREE_SECONDS)

        assert all([(len(self.mapping_filter_data[count_of_filter]) == scan_result_page.filter_count),
                    (scan_result_page.applied_filter_count == scan_result_page.filter_count)]), \
            "Applied filter count is mismatched with visible filter count."

        scan_result_page.host_tab.click()
        wait(lambda: scan_result_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")
        scan_host_list = ScansHostList()
        host_list = scan_host_list.rows

        for row in range(len(host_list)):
            host_list[row].click()
            LoadingCircle(TIME_THREE_SECONDS)

            scan_vulns_list = VulnerabilityList()
            scan_vulns_list.move_to_element(scan_result_page.vulnerability_tab)
            grouping_enable_disable(enabled=False)
            wait(lambda: visibility_of_element_located(scan_result_page.search_icon),
                 waiting_for="Vulnerability list to populate", timeout_seconds=WAIT_NORMAL)
            if count_of_filter == 'Single_filter':
                assert all([self.filter_values[1] in plugin for plugin in scan_vulns_list.get_plugin_names()]), \
                    "filter value: '{}' doesn't exists in filtered list data.".format(self.filter_values[1])
            else:
                assert self.filter_values[2] in scan_result_page.get_levels_value_of_details_section(
                    Nessus.Scan.Results.HostDetailsLevels.HOST_IP).text, \
                    "filter value: '{}' doesn't exists in filtered list data.".format(self.filter_values[2])
                vulns_list = scan_vulns_list.rows
                for vulnerability in range(len(vulns_list)):
                    vulns_list[vulnerability].click()
                    LoadingCircle(TIME_THREE_SECONDS)
                    assert all([(self.filter_values[3] not in
                                 scan_result_page.get_levels_value_of_details_section(
                                     Nessus.Scan.Results.PlugInDetailsLevels.PLUGIN_ID).text),
                                (self.filter_values[0] > (datetime.strptime(
                                    scan_result_page.get_levels_value_of_details_section(
                                        Nessus.Scan.Results.PlugInDetailsLevels.PLUGIN_MODIFIED_DATE).text, '%B %d, %Y')
                                ).date()),
                                (self.filter_values[4] == scan_result_page.get_levels_value_of_details_section(
                                    Nessus.Scan.Results.PlugInDetailsLevels.PLUGIN_SEVERITY).text)]), \
                        "filter values mismatched or doesn't exists in filtered list data."
                    VulnerabilityDescription().back_to_vulnerabilities.click()
                    wait(lambda: visibility_of_element_located(scan_result_page.search_icon),
                         waiting_for="Vulnerability list to populate", timeout_seconds=WAIT_NORMAL)
                    vulns_list = scan_vulns_list.rows
                    LoadingCircle(TIME_THREE_SECONDS)

            HostDetailsPage().back_to_hosts.click()
            LoadingCircle(TIME_THREE_SECONDS)
            host_list = scan_host_list.rows

        scan_result_page.clear_filter()
        LoadingCircle(TIME_THREE_SECONDS)

        scan_result_page.back_link.click()

    @pytest.mark.parametrize('count_of_filter', ['Single_filter', 'Multiple_filter'])
    def test_filter_on_vulnerabilities_tab(self, import_scan_via_api, count_of_filter):
        """
        Verify list are gets filter according to applied filter values on 'Vulnerabilities' tab in scan_result page.
        1. Import a scan file and Click on the scan to view the results page.
        2. Navigate to any of the above tab, click “Filter” link.
        3. Filter window should pop-up, put some filter values and “Apply” it.
        4. The filter count should be visible in the left side of “Filter” link.
        5. Verify the list got filtered against filter value.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_result_page = ScanViewPage()
        scan_result_page.vulnerability_tab.click()
        LoadingCircle(TIME_THREE_SECONDS)

        for data in self.mapping_filter_data[count_of_filter]:
            scan_result_page.apply_filter(key=data.get(Nessus.Filter.KEY), operator=data.get(Nessus.Filter.OPERATOR),
                                          value=data.get(Nessus.Filter.VALUE))
            LoadingCircle(TIME_THREE_SECONDS)

        assert all([(len(self.mapping_filter_data[count_of_filter]) == scan_result_page.filter_count),
                    (scan_result_page.applied_filter_count == scan_result_page.filter_count)]), \
            "Applied filter count is mismatched with visible filter count."

        scan_vulns_list = VulnerabilityList()
        grouping_enable_disable(enabled=False)
        LoadingCircle(WAIT_SHORT)
        vulns_list = scan_vulns_list.rows
        for vulnerability in range(len(vulns_list)):
            if count_of_filter == 'Single_filter':
                assert all([self.filter_values[1] in plugin for plugin in scan_vulns_list.get_plugin_names()]), \
                    "filter value: '{}' doesn't exists in filtered list data.".format(self.filter_values[1])
                break
            else:
                vulns_list[vulnerability].click()
                LoadingCircle(TIME_THREE_SECONDS)
                plugin_details = VulnerabilityDescription().get_output_details()
                LoadingCircle(TIME_THREE_SECONDS)
                assert all([(self.filter_values[3] not in
                             scan_result_page.get_levels_value_of_details_section(
                                 Nessus.Scan.Results.PlugInDetailsLevels.PLUGIN_ID).text),
                            (self.filter_values[4] == scan_result_page.get_levels_value_of_details_section(
                                Nessus.Scan.Results.PlugInDetailsLevels.PLUGIN_SEVERITY).text),
                            (self.filter_values[0] > (datetime.strptime(
                                scan_result_page.get_levels_value_of_details_section(
                                    Nessus.Scan.Results.PlugInDetailsLevels.PLUGIN_MODIFIED_DATE
                                ).text, '%B %d, %Y')).date()),
                            (all([self.filter_values[2] in plugin_details[key]['hosts']
                                  for key in plugin_details.keys()]))]), \
                    "filter values mismatched or doesn't exists in filtered list data."

                VulnerabilityDescription().back_to_vulnerabilities.click()

            vulns_list = scan_vulns_list.rows

        scan_result_page.clear_filter()
        LoadingCircle(TIME_THREE_SECONDS)
        grouping_enable_disable(enabled=True)
        scan_result_page.back_link.click()

    @pytest.mark.parametrize('tabs_to_check', [Nessus.Scan.Results.Tabs.HOSTS_TAB,
                                               Nessus.Scan.Results.Tabs.VULNERABILITIES_TAB,
                                               Nessus.Scan.Results.Tabs.NOTES_TAB,
                                               Nessus.Scan.Results.Tabs.REMEDIATION_TAB])
    def test_records_count_visible_next_to_searchbox(self, import_scan_via_api, tabs_to_check):
        """
        Test to match records count visible next to searchbox in different tabs of scans_result page with list count.
        1. Import a scan file and Navigate to "History" tab.
        2. Get the count of record list and verify it is same with the count visible next to searchbox in the page.
        3. Put some search string in searchbox and repeat step 2.
        4. Check some of filtered records from list and repeat step 2.
        5. Repeat above steps for all other tabs.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_result_page = ScanViewPage()

        if tabs_to_check == Nessus.Scan.Results.Tabs.VULNERABILITIES_TAB:
            scan_result_page.vulnerability_tab.click()
            records_list = VulnerabilityList()
        elif tabs_to_check == Nessus.Scan.Results.Tabs.NOTES_TAB:
            scan_result_page.notes_tab.click()
            records_list = ScanList()
        elif tabs_to_check == Nessus.Scan.Results.Tabs.REMEDIATION_TAB:
            scan_result_page.remediation_tab.click()
            records_list = ScanRemediationsList()
        else:
            scan_result_page.host_tab.click()
            wait(lambda: scan_result_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")
            records_list = ScansHostList()

        assert scan_result_page.total_records_count == len(records_list.object_table.table_wrapper.
                                                           get_table_contents()), \
            "Visible total records count is mismatched with total record list count."

        LoadingCircle(WAIT_SHORT)
        scan_result_page.apply_search(search_string="1")
        LoadingCircle(TIME_THREE_SECONDS)
        assert scan_result_page.filtered_records_count == len(records_list.object_table.table_wrapper.
                                                              get_table_contents()), \
            "Visible searched records count is mismatched with record list count after searching."

        selected_records = 0
        if tabs_to_check not in [Nessus.Scan.Results.Tabs.NOTES_TAB, Nessus.Scan.Results.Tabs.REMEDIATION_TAB]:
            records_list.rows[0].checkbox.check()
            selected_records += 1
            LoadingCircle(WAIT_SHORT)

            assert scan_result_page.selected_records_count == selected_records, \
                "Visible selected records count is mismatched with selected record count in list."

        scan_result_page.back_link.click()

    @pytest.mark.parametrize("sort", SortOrder.VALID_ORDERS)
    @pytest.mark.parametrize('column_to_sort', ['Host', 'Auth', 'Vulnerabilities'])
    def test_sort_hosts_list_on_column_values(self, import_scan_via_api, sort, column_to_sort):
        """
        Verify list sorting on column values of "Hosts" tab in scan_result page.
        1. Import a scan file and Click on the scan to view the results page and navigate to “Hosts” tab.
        2. Click on the "Sort" icon (ascending/descending) against any column from the list.
        3. Verify list is sorted according to the order you choose above.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)
        column_mapping = {'Host': {'attribute': 'host_name', 'key': lambda k: tuple(map(int, k.split('.')))},
                          'Vulnerabilities': {'attribute': 'host_vulnerabilities', 'key': int},
                          'Auth':{'attribute':'auth_check','key': lambda k: k.lower()}}

        map_attribute = column_mapping[column_to_sort]['attribute']
        map_key = column_mapping[column_to_sort]['key']

        scan_view_page = ScanViewPage()
        scan_view_page.host_tab.click()
        wait(lambda: scan_view_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

        hosts_list = ScansHostList()
        expected_hosts_list = sorted([getattr(host, map_attribute) for host in hosts_list.rows],
                                     key=map_key, reverse=(sort == SortOrder.DESCENDING))

        rendered_hosts_list = sort_on_column_values(page_class_instance=hosts_list, sort=sort,
                                                    column_name=column_to_sort)
        assert expected_hosts_list == [getattr(host, map_attribute) for host in rendered_hosts_list], \
            "{} is not sorted in {} order".format(column_to_sort, sort)

        scan_view_page.back_link.click()

    @pytest.mark.parametrize("sort", SortOrder.VALID_ORDERS)
    @pytest.mark.parametrize('column_to_sort', ['Sev', 'Family', 'Count',
                                                pytest.param('Name', marks=pytest.mark.xfail(reason='NES-7417'))])
    def test_sort_vulnerabilities_list_on_column_values(self, import_scan_via_api, sort, column_to_sort):
        """
        Verify list sorting on column values of "Vulnerabilities" tab in scan_result page.
        1. Import a scan file and Click on the scan to view the results page and navigate to “Vulnerabilities” tab.
        2. Click on the "Sort" icon (ascending/descending) against any column from the list.
        3. Verify list is sorted according to the order you choose above.
        """
        filter_values_to_apply = [{Nessus.Filter.KEY: Nessus.Filter.FilterKeys.HOSTNAME,
                                   Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.EQUAL_TO,
                                   Nessus.Filter.VALUE: '172.26.48.25'},
                                  {Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_DESCRIPTION,
                                   Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.CONTAINS,
                                   Nessus.Filter.VALUE: 'nessus'}]
        column_mapping = {'Sev': {'attribute': 'severity_value', 'key': int},
                          'Name': {'attribute': 'vulnerability_plugin_name', 'key': lambda k: k.lower()},
                          'Family': {'attribute': 'vulnerability_plugin_family', 'key': lambda k: k.lower()},
                          'Count': {'attribute': 'vulnerabilities_count', 'key': int}}

        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)
        scan_result_page = ScanViewPage()
        scan_result_page.vulnerability_tab.click()
        LoadingCircle(TIME_THREE_SECONDS)
        for values in filter_values_to_apply:
            scan_result_page.apply_filter(key=values.get(Nessus.Filter.KEY), value=values.get(Nessus.Filter.VALUE),
                                          operator=values.get(Nessus.Filter.OPERATOR))
            LoadingCircle(TIME_THREE_SECONDS)

        map_attribute = column_mapping[column_to_sort]['attribute']
        map_key = column_mapping[column_to_sort]['key']
        vulnerabilities_list = VulnerabilityList()
        expected_list = sorted([getattr(vulnerability, map_attribute) for vulnerability in
                                vulnerabilities_list.rows], key=map_key, reverse=(sort == SortOrder.DESCENDING))

        LoadingCircle(WAIT_NORMAL)
        rendered_list = sort_on_column_values(page_class_instance=vulnerabilities_list, sort=sort,
                                              column_name=column_to_sort)
        LoadingCircle(WAIT_NORMAL)
        assert expected_list == [getattr(vulnerability, map_attribute) for vulnerability in rendered_list], \
            "{} is not sorted in {} order".format(column_to_sort, sort)

        scan_result_page.back_link.click()

    @pytest.mark.parametrize("sort", SortOrder.VALID_ORDERS)
    @pytest.mark.parametrize('column_to_sort', ['Scan Notes'])
    def test_sort_notes_list_on_column_values(self, import_scan_via_api, sort, column_to_sort):
        """
        Verify list sorting on column values of "Notes" tab in scan_result page.
        1. Import a scan file and Click on the scan to view the results page and navigate to “Notes” tab if present.
        2. Click on the "Sort" icon (ascending/descending) against any column from the list.
        3. Verify list is sorted according to the order you choose above.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)
        column_mapping = {"Scan Notes": "scan_notes"}
        mapped_column_attribute = column_mapping[column_to_sort]

        scan_result_page = ScanViewPage()
        scan_result_page.notes_tab.click()
        LoadingCircle(TIME_THREE_SECONDS)

        notes_list = ScanList()
        expected_list = sorted([getattr(note, mapped_column_attribute) for note in notes_list.rows],
                               key=lambda k: k.lower(), reverse=(sort == SortOrder.DESCENDING))

        rendered_list = sort_on_column_values(page_class_instance=notes_list, sort=sort, column_name=column_to_sort)
        assert expected_list == [getattr(note, mapped_column_attribute) for note in rendered_list], \
            "{} is not sorted in {} order".format(column_to_sort, sort)

        scan_result_page.back_link.click()

    @pytest.mark.parametrize("sort", SortOrder.VALID_ORDERS)
    @pytest.mark.parametrize('column_to_sort', ['Hosts', 'Vulns'])
    def test_sort_remediations_list_on_column_values(self, import_scan_via_api, sort, column_to_sort):
        """
        Verify list sorting on column values of "Remediations" tab in scan_result page.
        1. Import a scan file and Click on the scan to view the results page and navigate to “Remediations” tab.
        2. Click on the "Sort" icon (ascending/descending) against any column from the list.
        3. Verify list is sorted according to the order you choose above.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)
        column_mapping = {"Vulns": "vulnerability_remediation", "Hosts": "host_remediation"}
        mapped_column_attribute = column_mapping[column_to_sort]

        scan_result_page = ScanViewPage()
        scan_result_page.remediation_tab.click()
        LoadingCircle(TIME_THREE_SECONDS)

        remediations_list = ScanRemediationsList()
        expected_list = sorted([getattr(row, mapped_column_attribute) for row in remediations_list.rows],
                               key=int, reverse=(sort == SortOrder.DESCENDING))
        rendered_list = sort_on_column_values(page_class_instance=remediations_list, sort=sort,
                                              column_name=column_to_sort)

        assert expected_list == [getattr(row, mapped_column_attribute) for row in rendered_list], \
            "{} is not sorted in {} order".format(column_to_sort, sort)

        scan_result_page.back_link.click()

    @pytest.mark.parametrize('tabs_to_apply_search', [Nessus.Scan.Results.Tabs.HOSTS_TAB,
                                                      Nessus.Scan.Results.Tabs.VULNERABILITIES_TAB,
                                                      Nessus.Scan.Results.Tabs.NOTES_TAB,
                                                      Nessus.Scan.Results.Tabs.REMEDIATION_TAB])
    def test_search_list_of_different_tabs(self, import_scan_via_api, tabs_to_apply_search):
        """
        Search and verify search string is found in searched list of different tabs in scan_result page.
        1. Import a scan file and Click on the scan to view the results page and navigate to any of the above tab.
        2. Verify “search_icon” is visible in the search box.
        3. Enter some search string.
        4. Verify “search_icon” is invisible and “remove_search” icon is visible.
        5. Verify the filtered list contains your search string.
        6. Click the “remove_search” icon.
        7. Verify “remove_search” is invisible and “search_icon” icon is visible.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        search_strings = ["48.2", "Nessus", "the", "6"]
        scan_result_page = ScanViewPage()
        if tabs_to_apply_search == Nessus.Scan.Results.Tabs.VULNERABILITIES_TAB:
            scan_result_page.vulnerability_tab.click()
            LoadingCircle(TIME_THREE_SECONDS)
            scan_result_page.result_per_page_dropdown.select_by_visible_text('200')
            LoadingCircle(TIME_THREE_SECONDS)
            records_list = VulnerabilityList()
        elif tabs_to_apply_search == Nessus.Scan.Results.Tabs.NOTES_TAB:
            scan_result_page.notes_tab.click()
            records_list = ScanList()
        elif tabs_to_apply_search == Nessus.Scan.Results.Tabs.REMEDIATION_TAB:
            scan_result_page.remediation_tab.click()
            records_list = ScanRemediationsList()
        else:
            records_list = ScansHostList()

        records_count_before_search = len(records_list.rows)
        assert all([scan_result_page.search_box.is_displayed(),
                    scan_result_page.search_icon.is_displayed()]), "Searchbox with search icon is invisible."

        for string_name in search_strings:
            scan_result_page.apply_search(search_string=string_name)
            LoadingCircle(TIME_THREE_SECONDS)
            assert all([(not scan_result_page.search_icon.is_displayed()),
                        scan_result_page.clear_search_icon.is_displayed()]), \
                "Search_icon is visible and clear_search_icon is invisible."
            assert scan_result_page.filtered_records_count == len(records_list.rows), \
                "Visible searched records count is mismatched with record list count after searching."
            assert scan_result_page.verify_search_result(search_string=string_name, records_list_object=records_list), \
                "Search failed with provided search string."

            scan_result_page.clear_search_icon.click()
            LoadingCircle(TIME_THREE_SECONDS)
            assert all([(records_count_before_search == len(records_list.rows)),
                        (not scan_result_page.clear_search_icon.is_displayed()),
                        scan_result_page.search_icon.is_displayed()]), \
                "Search_icon is invisible or clear_search_icon is visible or all data not loaded after removing search."

        assert records_count_before_search == len(records_list.rows), \
            "Data count mismatched, all data not loaded after clearing search box."

        scan_result_page.back_link.click()

    def test_verify_remediation_details_for_imported_scan(self, import_scan_via_api):
        """
        NES-10648 : Verify the remediation details for imported scan

        Scenario Tested:
            [x] Verify remediations for imported scan result

        Steps:
        1. Login to Nessus.
        2. Import scan and go to scan result page.
        3. Verify that remediations details are as expected.
        4. Logout from Nessus
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_result_page = ScanViewPage()

        wait(lambda: scan_result_page.is_element_present("remediation_tab"),
             waiting_for="scan result page to load properly")
        scan_result_page.remediation_tab.click()
        remediations_list = ScanRemediationsList()
        remediations_list.loaded()
        assert remediations_list.get_all_remediations() == API.Scan.RemediationsDetails.REMEDIATIONS, \
            "Scan remediations are populated incorrectly."

    @pytest.mark.parametrize('tabs_to_check', [Nessus.Scan.Results.Tabs.HOSTS_TAB,
                                               Nessus.Scan.Results.Tabs.VULNERABILITIES_TAB])
    def test_clear_selected_items_link(self, import_scan_via_api, tabs_to_check):
        """
        Verify “Clear Selected Items” link of different tabs in scan_result page.
        1. Import a scan file and Click on the scan to view the results page.
        2. Navigate to any of the above tab.
        3. Verify “Clear Selected Items” link should be invisible.
        4. Select (Checked the checkbox) some records among them.
        5. Link “Clear Selected Items” should be visible now, click on the link.
        6. Verify checked records become Unchecked.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_result_page = ScanViewPage()
        if tabs_to_check == Nessus.Scan.Results.Tabs.VULNERABILITIES_TAB:
            scan_result_page.vulnerability_tab.click()
            records_list = VulnerabilityList()
        else:
            scan_result_page.host_tab.click()
            wait(lambda: scan_result_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")
            records_list = ScansHostList()

        assert not scan_result_page.is_element_present('clear_selected_item_link'), \
            "'clear_selected_item' link is visible."

        records_list.rows[0].checkbox.check()
        LoadingCircle(WAIT_SHORT)
        assert scan_result_page.is_element_present('clear_selected_item_link'), \
            "'clear_selected_item' link is invisible."

        scan_result_page.clear_selected_item_link.click()
        LoadingCircle(TIME_THREE_SECONDS)
        assert not records_list.rows[0].checkbox.is_selected(), "Selected record(s) are not unchecked yet."

        scan_result_page.back_link.click()

    @pytest.mark.parametrize("vulnerability_count", ["Single_vulnerability", "Multiple_vulnerabilities"])
    def test_modify_vulnerabilities_from_vulnerabilities_tab(self, import_scan_via_api, vulnerability_count):
        """
        Test to modify vulnerability(s) from “Vulnerabilities” tab in scan_result page.
        1. Import a scan file and Click on the scan to view the results page.
        2. Navigate to the tab, and verify “Modify” button is invisible in header.
        3. For "Single_vulnerability", click “modify” (pen icon) against your desired vulnerability from the list.
           Select (checked the corresponding checkbox) for more than one vulnerabilities from the list and click on
           “Modify” button in the header.
        4. “Modify vulnerability” pop-up should come up.
        5. Select a severity level from the dropdown and click on “Save”.
        6. Record should save with a success notification as “Vulnerability modified successfully.”.
        7. Record should listed in the list with modified severity value.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_result_page = ScanViewPage()
        scan_result_page.vulnerability_tab.click()
        LoadingCircle(TIME_THREE_SECONDS)
        assert not scan_result_page.is_element_present('modify_button'), "“Modify” button is visible in the header."
        selected_plugins = []
        vulnerability_list = VulnerabilityList()
        grouping_enable_disable(enabled=False)

        if vulnerability_count == "Single_vulnerability":
            selected_plugins = [vulnerability_list.get_plugin_names()[1]]
            notification_text = Messages.NotificationMessages.ScanResults.vulnerability_modified
        else:
            for row, vulnerability in enumerate(vulnerability_list.rows, start=1):
                if row < 6:
                    vulnerability.checkbox.check()
                    LoadingCircle(WAIT_SHORT)
                    selected_plugins.append(vulnerability.plugin_name.text)
                else:
                    break
            notification_text = Messages.NotificationMessages.ScanResults.vulnerabilities_modified

        ModifyVulnerability().modify_vulnerability(vulnerabilities_list=selected_plugins,
                                                   severity=Nessus.Scan.Severity.CRITICAL, apply_on_future_scan=True,
                                                   expiration_date=(datetime.today().date() + timedelta(days=7)))

        assert Notifications().successes[-1] == notification_text, \
            "Success notifications for vulnerability(s) modified is mismatched or missing."

        scan_result_page.refresh()
        LoadingCircle(WAIT_NORMAL)
        assert vulnerability_list.check_severity_against_plugin(severity=Nessus.Scan.Severity.CRITICAL.upper(),
                                                                plugin_list=selected_plugins), \
            "Vulnerability(s) has not been modified to expected severity level."

        grouping_enable_disable(enabled=True)
        scan_result_page.back_link.click()

    def test_vulnerabilities_count_against_hosts(self, import_scan_via_api):
        """
        Verify vulnerabilities count against hosts in scan_result page.
        Note: More than one hosts required.
        1. Import a scan file and Click on the scan to view the results page and navigate to “Vulnerabilities” tab.
        2. Apply a filter with “Hostname”, value should be one of the host listed in your “Hosts” tab and
            get the vulnerabilities count.
        3. Navigate to “Hosts” tab and click on the host (same as above) from the list in that tab.
        4. Verify “Back to Hosts” link is visible.
        5. Verify this page will contains only “vulnerabilities” tab in it and header contains its name as
            “scan_name / host” (e.g. test_1041 / 172.26.17.86)
        6. Verify the count is same as you got from filter in “vulnerabilities” tab.
        7. Change the host from the dropdown in right corner of the page and repeat above steps to verify the count.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_result_page = ScanViewPage()
        scan_result_page.host_tab.click()
        wait(lambda: scan_result_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

        host_list = ScansHostList()
        host_name_list = host_list.get_host_names()

        scan_result_page.vulnerability_tab.click()
        LoadingCircle(TIME_THREE_SECONDS)

        vulnerability_count = {}
        for host in host_name_list:
            scan_result_page.apply_filter(key=Nessus.Filter.FilterKeys.HOSTNAME,
                                          operator=Nessus.Filter.FilterOperators.EQUAL_TO, value=host)
            LoadingCircle(TIME_THREE_SECONDS)
            vulnerability_count.update({host: scan_result_page.total_records_count})
            scan_result_page.clear_filter()
            LoadingCircle(TIME_THREE_SECONDS)

        scan_result_page.host_tab.click()
        host_list.rows[0].click()

        host_details = HostDetailsPage()
        for host in host_name_list:
            host_details.switch_host.select_by_visible_text(host)
            LoadingCircle(TIME_THREE_SECONDS)
            assert all([host_details.is_element_present('back_to_hosts'),
                        host_details.is_element_present('vulnerability_tab'),
                        (host_details.back_to_hosts.text == 'Back to Hosts'),
                        (host_details.page_header == "{} / {}".format(imported_scan_name, host))]), \
                "Page header text mismatched with expected text or “Vulnerabilities” tab " \
                "or “Back to Hosts” link is absent."

            LoadingCircle(WAIT_SHORT)
            assert scan_result_page.total_records_count == vulnerability_count.get(host), \
                "Vulnerability count is mismatched with filtered vulnerabilities count against host."

        scan_result_page.back_link.click()
        LoadingCircle(WAIT_SHORT)

    def test_page_navigation_in_vulnerabilities_description_page(self, import_scan_via_api):
        """
        Verify page navigation in vulnerabilities description page.
        1. Import a scan file and Click on the scan to view the results page.
        2. Navigate to “Vulnerabilities” tab and click on any of the vulnerability listed in that tab.
        3. Verify “previous (<) / next (>)” icon is visible.
        4. Click on any navigation and check it works accordingly.
        5. If you clicked on the first scan from the list then “previous (<)” icon should invisible and
            “next (>)” will visible only.
        6. Verify the vice-versa of above for the last vulnerability in the list.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_result_page = ScanViewPage()
        scan_result_page.vulnerability_tab.click()
        LoadingCircle(TIME_THREE_SECONDS)

        scan_result_page.result_per_page_dropdown.select_by_visible_text('100')
        grouping_enable_disable(enabled=False)
        vulnerabilities_list = VulnerabilityList()
        all_plugins = vulnerabilities_list.get_plugin_names()
        LoadingCircle(WAIT_NORMAL)

        vulnerabilities_list.rows[0].click()
        vulnerability_description_page = VulnerabilityDescription()
        wait(lambda: visibility_of_element_located(vulnerability_description_page.next_icon),
             waiting_for="Vulnerability Description page", timeout_seconds=WAIT_SHORT)
        assert all([vulnerability_description_page.is_element_present('next_icon'),
                    (not vulnerability_description_page.is_element_present('previous_icon'))])

        for plugin in all_plugins[1:]:
            vulnerability_description_page.next_icon.click()
            LoadingCircle(WAIT_SHORT)
            assert vulnerability_description_page.plugin_details_header == plugin, \
                "Clicking on 'next' pagination icon doesn't take you to next plugin."

        assert all([vulnerability_description_page.is_element_present('previous_icon'),
                    (not vulnerability_description_page.is_element_present('next_icon'))])

        vulnerability_description_page.back_to_vulnerabilities.click()
        LoadingCircle(TIME_THREE_SECONDS)

        scan_result_page.result_per_page_dropdown.select_by_visible_text('100')
        vulnerabilities_list.rows[-1].click()

        wait(lambda: visibility_of_element_located(vulnerability_description_page.previous_icon),
             waiting_for="Vulnerability Description page to load", timeout_seconds=WAIT_SHORT)
        vulnerability_description_page = VulnerabilityDescription()
        assert all([vulnerability_description_page.is_element_present('previous_icon'),
                    (not vulnerability_description_page.is_element_present('next_icon'))])

        for plugin in all_plugins[::-1][1:]:
            vulnerability_description_page.previous_icon.click()
            LoadingCircle(TIME_THREE_SECONDS)
            assert vulnerability_description_page.plugin_details_header == plugin, \
                "Clicking on 'previous' pagination icon doesn't take you to previous plugin."

        assert all([vulnerability_description_page.is_element_present('next_icon'),
                    (not vulnerability_description_page.is_element_present('previous_icon'))])

        vulnerability_description_page.back_to_vulnerabilities.click()
        grouping_enable_disable(enabled=True)
        scan_result_page.back_link.click()

    @pytest.mark.parametrize("vulnerability_count", ["Single_vulnerability", "Multiple_vulnerabilities"])
    def test_modify_vulnerabilities_from_hosts_tab(self, import_scan_via_api, vulnerability_count):
        """
        Test to modify single vulnerability from “Hosts” tab in scan_result page.
        Note: More than one hosts required.
        1. Import a scan file and Click on the scan to view the results page and navigate to “Hosts” tab.
        2. Click on any of the host listed in that tab.
        3. Verify this page header contains its name as “scan_name / host” (e.g. test_1041 / 172.26.17.86)
        4. For "Single_vulnerability", click “modify” (pen icon) against your desired vulnerability from the list.
           Otherwise select (checked the corresponding checkbox) for more than one vulnerabilities from the list and
           click on “Modify” button in the header.
        5. “Modify vulnerability” pop-up should come up.
        6. Select a severity level from the dropdown and host (for which you want to change the severity level) and
            click on “Save”.
        7. Record should save with a success notification as “Vulnerability modified successfully.”
        8. Record should listed with modified severity value against selected host.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)
        scan_result_page = ScanViewPage()
        scan_result_page.host_tab.click()
        wait(lambda: scan_result_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")
        hosts_list = ScansHostList()
        wait(lambda: visibility_of_element_located(scan_result_page.search_icon), waiting_for="Host list to populate",
             timeout_seconds=WAIT_NORMAL)
        hosts = hosts_list.get_host_names()

        hosts_list.click_on_host(hosts[0])
        LoadingCircle(TIME_THREE_SECONDS)

        host_details_page = HostDetailsPage()
        wait(lambda: visibility_of_element_located(scan_result_page.search_icon),
             waiting_for="Host Details Page to load", timeout_seconds=WAIT_NORMAL)
        assert host_details_page.page_header == "{} / {}".format(imported_scan_name, hosts[0]), \
            "Host Name is invisible in the header."

        selected_plugins = {}
        vulnerability_list = VulnerabilityList()
        grouping_enable_disable(enabled=False)
        wait(lambda: visibility_of_element_located(scan_result_page.search_icon),
             waiting_for="Vulnerability list to populate.", timeout_seconds=WAIT_NORMAL)
        if vulnerability_count == "Single_vulnerability":
            selected_plugins.update(
                {vulnerability_list.rows[1].vulnerability_plugin_name: vulnerability_list.rows[1].severity_name})
            notification_text = Messages.NotificationMessages.ScanResults.vulnerability_modified
        else:
            for row, vulnerability in enumerate(vulnerability_list.rows, start=1):
                if row < 6:
                    vulnerability.checkbox.check()
                    LoadingCircle(WAIT_SHORT)
                    selected_plugins.update({vulnerability.vulnerability_plugin_name: vulnerability.severity_name})
                else:
                    break
            notification_text = Messages.NotificationMessages.ScanResults.vulnerabilities_modified

        ModifyVulnerability().modify_vulnerability(vulnerabilities_list=list(selected_plugins.keys()), host=hosts[1],
                                                   severity=Nessus.Scan.Severity.LOW, apply_on_future_scan=True,
                                                   expiration_date=(datetime.today().date() + timedelta(days=7)))

        assert Notifications().successes[-1] == notification_text, \
            "Success notifications for vulnerability(s) modified is mismatched or missing."

        host_details_page.refresh()
        LoadingCircle(WAIT_NORMAL)
        for plugin in selected_plugins.keys():
            assert vulnerability_list.check_severity_against_plugin(severity=selected_plugins.get(plugin),
                                                                    plugin_list=[plugin]), \
                "Vulnerability(s) has been modified to expected severity level against existing host."

        host_details_page.switch_host.select_by_visible_text(hosts[1])
        LoadingCircle(TIME_THREE_SECONDS)
        assert vulnerability_list.check_severity_against_plugin(severity=Nessus.Scan.Severity.LOW.upper(),
                                                                plugin_list=list(selected_plugins.keys())), \
            "Vulnerability(s) has not been modified to expected severity level against specified host."
        grouping_enable_disable(enabled=True)
        ScanViewPage().back_link.click()

    def test_vulnerabilities_description_page(self, import_scan_via_api):
        """
        Test to verify vulnerabilities description page.
        1. Import a scan file and Click on the scan to view the results page.
        2. Navigate to “Vulnerabilities” tab and click on any of the vulnerability listed in that tab.
        3. Verify “Back to Vulnerabilities” link is visible in page header.
        4. Verify this page header contains its name as “scan_name / Plugin #*****” (e.g. test_1041 / Plugin #57608).
        5. Also verify vulnerability name is visible in tab header.
        6. Click on “Back to Vulnerabilities” link and verify it'll back to “Vulnerabilities” tab in scan details page.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_result_page = ScanViewPage()
        scan_result_page.vulnerability_tab.click()

        grouping_enable_disable(enabled=False)
        vulnerability = VulnerabilityList().rows[0]

        plugin_id, plugin_name, plugin_family, severity = vulnerability.vulnerability_plugin_id, vulnerability. \
            vulnerability_plugin_name, vulnerability.vulnerability_plugin_family, vulnerability.severity_name
        mapping_element_value = {Nessus.Scan.Results.PlugInDetailsLevels.PLUGIN_ID: plugin_id,
                                 Nessus.Scan.Results.PlugInDetailsLevels.PLUGIN_FAMILY: plugin_family,
                                 Nessus.Scan.Results.PlugInDetailsLevels.PLUGIN_SEVERITY: severity.title()}

        vulnerability.click()
        LoadingCircle(TIME_THREE_SECONDS)
        vulnerability_description_page = VulnerabilityDescription()
        assert all([vulnerability_description_page.is_element_present('back_to_vulnerabilities'),
                    (vulnerability_description_page.back_to_vulnerabilities.text == 'Back to Vulnerabilities'),
                    (vulnerability_description_page.page_header == "{} / Plugin #{}".format(imported_scan_name,
                                                                                            plugin_id)),
                    (vulnerability_description_page.plugin_details_header == plugin_name),
                    (vulnerability_description_page.right_column_header.text == Nessus.Scan.Results.RightColumnHeader.
                     PLUGIN_DETAILS)]), \
            "Page headers mismatched against expected element or Plugin Details header is missing in right column " \
            "of vulnerability description page."

        for level in Nessus.Scan.Results.PlugInDetailsLevels.DEFAULT_LEVELS:
            mapped_element = mapping_element_value[level]
            time.sleep(3)
            assert mapped_element == vulnerability_description_page.get_levels_value_of_details_section(level).text, \
                "Level value is mismatched or not found according to level param."

        vulnerability_description_page.back_to_vulnerabilities.click()
        LoadingCircle(TIME_THREE_SECONDS)
        assert scan_result_page.page_header == imported_scan_name, \
            "Click on “Back to Vulnerabilities” link doesn't take you back to “Vulnerabilities” tab."
        grouping_enable_disable(enabled=True)
        scan_result_page.back_link.click()

    def test_page_navigation_from_vulnerabilities_description_page_to_host_details_page(self, import_scan_via_api):
        """
        Verify clicking on “host” from vulnerabilities description page, will take you to the host details page.
        1. Import a scan file and Click on the scan to view the results page.
        2. Navigate to “Vulnerabilities” tab and click on any of the vulnerability from the list.
        3. Click on any host highlighted in output section in that page.
        4. Verify it’ll take you to hosts details page, and “Back to Hosts” link is visible.
        5. Again verify page header contains its name as “scan_name / host” (e.g. test_1041 / 172.26.17.86).
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_result_page = ScanViewPage()
        scan_result_page.vulnerability_tab.click()
        wait(lambda: scan_result_page.is_element_present("filter_link"), waiting_for="vulnerabilities to get loaded")

        grouping_enable_disable(enabled=False)
        vulnerability_list = VulnerabilityList()
        vulnerability_list.loaded()
        vulnerability_list.rows[2].click()

        vulnerability_description_page = VulnerabilityDescription()
        wait(lambda: visibility_of_element_located(vulnerability_description_page.output_blocks),
             waiting_for="Vulnerability Description Details")

        all_hosts = vulnerability_description_page.get_host_element_from_output_details()
        listed_hosts = all_hosts[list(all_hosts.keys())[0]]

        for key in listed_hosts.keys():
            host_name = listed_hosts[key].text
            listed_hosts[key].click()

            host_details_page = HostDetailsPage()
            wait(lambda: visibility_of_element_located(host_details_page.back_to_hosts),
                 waiting_for="Host Details page")

            assert all([(host_details_page.page_header == "{} / {}".format(imported_scan_name, host_name)),
                        (host_details_page.back_to_hosts.text == 'Back to Hosts')]), \
                "You are not navigated to host details page."

            host_details_page.back()
            wait(lambda: visibility_of_element_located(vulnerability_description_page.output_blocks),
                 waiting_for="Vulnerability Description Details")

            all_hosts = vulnerability_description_page.get_host_element_from_output_details()
            listed_hosts = all_hosts[list(all_hosts.keys())[0]]

        scan_result_page.back_link.click()
        grouping_enable_disable(enabled=True)

    def test_download_link_in_host_details_page(self, import_scan_via_api):
        """
        Verify download link to download host details from host details page.
        1. Import a scan file and Click on the scan to view the results page and navigate to “Hosts” tab.
        2. Click on any of the host listed in that tab.
        3. Verify “Download” link is present in Host Details section and download it.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_view_page = ScanViewPage()
        scan_view_page.host_tab.click()
        wait(lambda: scan_view_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

        ScansHostList().rows[1].click()
        LoadingCircle(TIME_THREE_SECONDS)

        host_details_page = HostDetailsPage()

        assert all([host_details_page.is_element_present('host_details_file'),
                    (host_details_page.host_details_file.text == "Download")]), \
            "“Download” link is not present in Host Details section"

        host_details_page.host_details_file.click()

        wait(lambda: not WindowsHandler().is_alert_present(), timeout_seconds=TIME_THIRTY_SECONDS,
             sleep_seconds=WAIT_NORMAL)

        assert not WindowsHandler().is_alert_present(), 'Failed to download host details file.'

        scan_view_page.back_link.click()

    def test_delete_host_from_host_details_page(self, import_scan_via_api):
        """
        Test to delete host from host details page.
        1. Import a scan file and Click on the scan to view the results page and navigate to “Hosts” tab.
        2. Click on any of the host listed in that tab.
        3. Verify this page header contains its name as “scan_name / host” (e.g. test_1041 / 172.26.17.86)
        4. Click on “Delete_icon” in the right corner of the page.
        5. Click on “Delete” button on confirmation pop-up.
        6. Host should delete with a success notification as “Host deleted successfully.”
        7. Host should not listed in “Hosts” tab anymore.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_view_page = ScanViewPage()
        scan_view_page.host_tab.click()
        wait(lambda: scan_view_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

        host_list = ScansHostList()
        host_name = host_list.rows[1].host_name
        host_list.click_on_host(host_name=host_name)
        wait(lambda: scan_view_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")
        host_details_page = HostDetailsPage()

        assert all([(host_details_page.page_header == "{} / {}".format(imported_scan_name, host_name)),
                    host_details_page.is_element_present('delete_icon')]), \
            "Host name mismatched in header or 'Delete' icon is missing in right column header of host details page."

        host_details_page.delete_host()

        assert Notifications().successes[-1] == Messages.NotificationMessages.ScanResults.host_deleted, \
            "Success notifications for host deletion is mismatched or missing."

        scan_view_page.host_tab.click()
        wait(lambda: scan_view_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

        assert host_name not in host_list.get_host_names(), "Deletion failed: Host still exists in host_list."

        scan_view_page.back_link.click()

    def test_delete_host_through_x_icon(self, import_scan_via_api):
        """
        Test to delete a single host from “Hosts” tab.
        1. Import a scan file and Click on the scan to view the results page.
        2. Navigate to any of the above tab, click “X” icon against your desired host from the list.
        3. Click on “Delete” button on confirmation pop-up.
        4. Host should delete with a success notification as “Host deleted successfully.”
        5. Host should not listed in the host_ist anymore.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_view_page = ScanViewPage()
        scan_view_page.host_tab.click()
        wait(lambda: scan_view_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

        host_list = ScansHostList()
        host_name = host_list.rows[1].host_name

        host_list.delete_host(host_name=host_name)
        assert Notifications().successes[-1] == Messages.NotificationMessages.ScanResults.host_deleted, \
            "Success notifications for host deletion is mismatched or missing."

        LoadingCircle(WAIT_NORMAL)
        assert host_name not in host_list.get_host_names(), "Deletion failed: Host still exists in host_list."

        scan_view_page.back_link.click()

    def test_delete_multiple_hosts(self, import_scan_via_api):
        """
        Test to delete multiple host from “Hosts” tab.
        1. Import a scan file and Click on the scan to view the results page.
        2. Navigate to “Hosts” tab, and verify “Delete” button is invisible in header.
        3. Select (checked the corresponding checkbox) more than one record from list of hosts and
            verify “Delete” button is visible now in the header and click on it.
        4. Click on “Delete” button on confirmation pop-up.
        5. Hosts should delete with a success notification as “Hosts deleted successfully.”
        6. Hosts should not listed in the list of the corresponding tab anymore.
        """
        selected_hosts = []
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_result_page = ScanViewPage()
        assert not scan_result_page.is_element_present('more_dropdown'), "More actions dropdown is present"
        scan_result_page.host_tab.click()
        wait(lambda: scan_result_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")
        host_list = ScansHostList()
        for row, host in enumerate(host_list.rows, start=1):
            if row % 2 == 0:
                host.checkbox.check()
                selected_hosts.append(host.host_name)
        assert scan_result_page.is_element_present('more_dropdown'), "More actions dropdown is not present"

        scan_result_page.more_dropdown.click()
        assert scan_result_page.is_element_present('delete_host'), "Delete button is invisible."

        scan_result_page.delete_host.click()
        ActionCloseModal().accept_action()
        assert Notifications().successes[-1] == Messages.NotificationMessages.ScanResults.hosts_deleted, \
            "Success notifications for host deletion is mismatched or missing."

        LoadingCircle(WAIT_NORMAL)
        current_host_list = host_list.get_host_names()
        assert all([host_name not in current_host_list for host_name in selected_hosts]), \
            "Deletion failed: Hosts still exists in host_list."

        ScanViewPage().back_link.click()

    def test_configure_scan(self, import_scan_via_api):
        """
        Test to configure a scan from scan_result page.
        1. Import a scan file and Click on the scan to view the results page and click on “Configure” button.
        2. It should navigate to scan configuration page.
        3. Verify “Back to Scan Report” link is visible in page header.
        4. Verify this page header contains its name as “scan_name / Configuration”.
        5. Modify some values and save it.
        6. Scan should save with a success notification as “Scan saved successfully.”
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_result_page = ScanViewPage()
        scan_result_page.configure_button.click()
        LoadingCircle(TIME_THREE_SECONDS)

        scan_form = NewScanForm()
        assert all([(scan_form.page_heading == '{} / Configuration'.format(imported_scan_name)),
                    (scan_form.back_link.text == 'Back to Scan Report'), scan_form.is_element_present('back_link')]), \
            "Header elements are not visible or mismatched"

        configured_scan_name = "{} - configured".format(imported_scan_name)
        scan_form.name_field.value = configured_scan_name
        scan_form.save_button.click()
        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            "Success notifications for scan saved is mismatched or missing."

        scan_form.back_link.click()
        scan_result_page.back_link.click()
        LoadingCircle(TIME_THREE_SECONDS)

        current_scan_list = ScanList().get_all_scans()
        assert all([(configured_scan_name in current_scan_list), (imported_scan_name not in current_scan_list)]), \
            "Modified details haven't saved during configuration."

    def test_search_in_audit_trail(self, import_scan_via_api):
        """
        Test to apply and verify search in audit_trail option in scan_result page.
        1. Import a scan file and Click on the scan to view the results page and click on the “Audit Trail” button.
        2. Put values for either “Plugin ID” /”Host” or both and click “Search” button.
        3. Verify search results against your values.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_result_page = ScanViewPage()
        scan_result_page.host_tab.click()
        wait(lambda: scan_result_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")
        host_names = ScansHostList().get_host_names()
        search_strings = [['50705', ''], ['', host_names[0]], ['14272', host_names[3]]]

        scan_result_page.audit_trail_button.click()
        LoadingCircle(WAIT_SHORT)
        assert scan_result_page.audit_trail_section_header.text == 'Audit Trail', "Audit Trail section is invisible."

        for value in search_strings:
            scan_result_page.apply_search_on_audit_trail(plugin_id=value[0], host=value[1])
            LoadingCircle(WAIT_NORMAL)

            assert (value[0] and value[1]) in scan_result_page.audit_content.text, \
                "Search string not found in searched content."

        scan_result_page.audit_trail_section_close_icon.click()
        scan_result_page.back_link.click()

    def test_visibility_of_filter_in_vulnerability(self, import_scan_via_api):
        """
        CS-28983: UI test for CS-27999

        1. Run (or import?) a scan with vulnerabilities
        2. Add a filter that will not match, such as host = 'non-matching-host' or
           plugin_publication_date > '2099-01-01'
        3. Verify that the filter box is still visible on page
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_result_page = ScanViewPage()
        scan_result_page.vulnerability_tab.click()

        scan_result_page.apply_filter(key=Nessus.Filter.FilterKeys.PLUGIN_PUBLICATION_DATE,
                                      operator=Nessus.Filter.FilterOperators.LATER_THAN,
                                      value=(datetime.today().date() - timedelta(days=1000)))

        filter_modal = ActionCloseModal()
        filter_modal.wait_for_modal_closed()

        assert scan_result_page.applied_filter_count == scan_result_page.filter_count, \
            "Applied filter count is mismatched with visible filter count."

        scan_result_page.filter_link.click()
        wait(lambda: filter_modal.modal, waiting_for='Filter modal to open')

        assert scan_result_page.is_element_present('match_dropdown'), 'Scan result filter match dropdown is not ' \
                                                                      'visible in vulnerabilities filter.'

        assert scan_result_page.is_element_present('filter_holder'), 'Applied scan result filter is not visible in ' \
                                                                     'vulnerabilities filter.'

        filter_modal.cancel_button.click()


@pytest.mark.scans_2
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login', 'login')
@pytest.mark.parametrize('import_scan_via_api', [
    {'file_name': 'Basic_Network_Scan_Result.db', 'file_path': 'nessus/tests/ui/scans/test_data/',
     'password': 'nessus', 'create_folder': True, 'encrypted': True}], indirect=True)
class TestDashboardForImportedScanResults:
    """
    Covers scan dashboard page related test cases in Scans Results page.
    # NQA-1069 : Automation tests for Scans - Results.
    Sub-part: All test with imported scan.
    Pre-requisite: There should be a successfully imported scan exist with dashboard link.
    # NES-8931 : Fix scans related skipped test cases
    """

    cat = None

    @pytest.mark.skip(reason="Refer JIRA ID: NES-10322")
    @pytest.mark.parametrize("test_data", [{"file_path": 'nessus/tests/ui/scans/test_data/',
                                            "file_name": 'large_ip_range_257_ips.nessus'}])
    def test_license_more_link(self, import_scan_via_api, test_data):
        """
        Click and Verify the link “License more” to limiting the records displayed.
        1. Import a scan file and Click on the scan to view the results page.
        2. Verify the link “License more” is present to limiting the records displayed and click it.
        3. It will take you to a new tab, navigate to the tab (if not automatically done).
        4. Verify the new tab URL should be "https://www.tenable.com/about-tenable/contact-tenable“.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)
        scan_details_page = ScanViewPage()
        scan_details_page.back_link.click()

        if self.cat.api.server.properties().get('license').get('ips') > 256:
            pytest.xfail(
                reason="“License more” link should invisible as product already licensed to 256 or greater host ips.")

        file_uploaded = self.cat.api.file.upload(file=get_file_path(test_data['file_path'] + test_data['file_name']))
        response = self.cat.api.scans.import_scan(file_uploaded, folder_id=created_folder_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        scan_list = ScanList()
        scan_list.refresh()
        LoadingCircle(WAIT_NORMAL)
        scan_list.click_on_scan(scan_name=response['scan']['name'])
        LoadingCircle(TIME_THREE_SECONDS)

        scan_details_page.vulnerability_tab.click()
        wait(lambda: scan_details_page.is_element_present('license_more_link'),
             waiting_for="'License more' link to be visible.", timeout_seconds=TIME_THIRTY_SECONDS)
        assert scan_details_page.license_more_link.is_displayed(), "'License more' link is not visible."

        windows_handler = WindowsHandler()
        parent_window = windows_handler.handles[0]
        scan_details_page.license_more_link.click()

        try:
            windows_handler.switch_to_window(window_handle=windows_handler.handles[1])
        except IndexError:
            log.error("Window handle haven't switched to new window.")
            raise

        wait(lambda: (parent_window != windows_handler.handles[1]), sleep_seconds=TIME_THREE_SECONDS,
             timeout_seconds=TIME_TWENTY_SECONDS, waiting_for="Switching windows")

        current_page_url = windows_handler._driver.current_url

        assert 'https://www.tenable.com/products/nessus/nessus-professional' in current_page_url, \
            "Current page url is mismatched with expected URL."

        windows_handler.switch_to_window(window_handle=parent_window)

    @pytest.mark.parametrize("scan_vulnerabilities", Nessus.Scan.Severity.SEVERITY_LEVELS)
    def test_vulnerabilities_are_filtered_with_severity_level(self, import_scan_via_api, scan_vulnerabilities):
        """
        Verify the vulnerabilities list is filtered with severity level when you click every
        vulnerabilities banner in dashboard page.
        1. Import a scan file and Click on the scan to view the results page.
        2. Enable the dashboard and click any of vulnerabilities banner visible in dashboard.
        3. It’ll take you to the “Vulnerabilities” tab
        4. Verify the list is filtered with that severity level you choose in dashboard page.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_view_page = ScanViewPage()
        scan_view_page.vulnerability_tab.click()
        wait(lambda: scan_view_page.is_element_present("search_box"))

        vulnerability_list = VulnerabilityList()
        grouping_enable_disable(enabled=False)
        ScanDashboardPage().enabling_dashboard()
        wait(lambda: scan_view_page.is_element_present("dashboard_tab"))

        scan_vulnerability = ScanVulnerabilities()
        LoadingCircle(WAIT_NORMAL)
        mapping_vulnerability = {Nessus.Scan.Severity.CRITICAL: scan_vulnerability.critical,
                                 Nessus.Scan.Severity.HIGH: scan_vulnerability.high,
                                 Nessus.Scan.Severity.INFO: scan_vulnerability.info,
                                 Nessus.Scan.Severity.LOW: scan_vulnerability.low,
                                 Nessus.Scan.Severity.MEDIUM: scan_vulnerability.medium}
        mapped_vulnerability = mapping_vulnerability[scan_vulnerabilities]

        num_of_vulnerability = scan_vulnerability.get_data_count(element=mapped_vulnerability)
        severity_name = scan_vulnerability.get_severity_name(element=mapped_vulnerability)
        data_severity = scan_vulnerability.get_data_severity(element=mapped_vulnerability)
        if num_of_vulnerability == 0:
            log.info("No vulnerabilities found with %s severity.", severity_name)
        else:
            mapped_vulnerability.click()
            LoadingCircle(WAIT_SHORT)
            assert all([(vulnerability_list.get_total_rows() == num_of_vulnerability),
                        ("sev: " + data_severity == scan_vulnerability.get_filter_value())]), \
                "'Vulnerabilities count' and 'filter value' is mismatched."
            get_driver_no_init().fullscreen_window()
            if num_of_vulnerability > 50:
                scan_vulnerability.result_per_page_dropdown.select_by_visible_text('100')
            assert vulnerability_list.check_severity_name(severity=severity_name), \
                "One or more severity value mismatched, it should be same for entire list."

        scan_vulnerability.js_scroll_into_view(element=scan_vulnerability.vulnerability_tab)
        LoadingCircle(WAIT_SHORT)
        grouping_enable_disable(enabled=True)
        scan_vulnerability.back_link.click()

    @pytest.mark.parametrize("scan_level", ["Vulnerabilities", "Operating Systems", "Authentication"])
    def test_percentile_chart_in_dashboard_page(self, import_scan_via_api, scan_level):
        """
        Verify the chart for vulnerabilities in dashboard page.
        1. Import a scan file and Click on the scan to view the results page.
        2. Enable the dashboard and navigate to “Dashboard” tab.
        3. Hover on the any severity level in the chart under “VULNERABILITIES” banner.
        4. Verify a numbered percentage will be visible and that severity value will be in bold
        5. Repeat above steps for “OPERATING SYSTEMS” and “AUTHENTICATION” banner.
        """
        level_mapping = {"Vulnerabilities": Nessus.Scan.Severity.SEVERITY_LEVELS,
                         "Authentication": Nessus.Scan.ComplianceAuthentication.VALID_AUTH_LEVELS,
                         "Operating Systems": [OperatingSystems.LINUX, OperatingSystems.WINDOWS, OperatingSystems.BSD,
                                               OperatingSystems.MAC_OS, OperatingSystems.OTHER]}

        mapped_attribute = level_mapping[scan_level]
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_view_page = ScanViewPage()
        scan_view_page.host_tab.click()
        wait(lambda: scan_view_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

        scan_dashboard_page = ScanDashboardPage()
        scan_dashboard_page.enabling_dashboard()
        wait(lambda: scan_view_page.is_element_present("dashboard_tab"))

        found = False
        for level in mapped_attribute:
            if level in Nessus.Scan.Severity.SEVERITY_LEVELS:
                element_of_chart = scan_dashboard_page.get_levels_element_of_chart(level.upper())
            else:
                element_of_chart = scan_dashboard_page.get_levels_element_of_chart(level)

            element_of_chart.location_once_scrolled_into_view
            element_of_chart.click()
            LoadingCircle(WAIT_SHORT)
            if scan_dashboard_page.is_element_present('percentile_in_chart'):
                found = True
                value_of_percentage_count = scan_dashboard_page.percentage_count.text
                assert all([('%' in value_of_percentage_count), (int(value_of_percentage_count[:-1]) > 0),
                            (int(value_of_percentage_count[:-1]) <= 100)]), "No count available for this level."
            else:
                log.info("No count available for %s level.", level)

        assert found, "No percentile count found for any of the levels under {} in dashboard page.".format(scan_level)

    def test_top_vulnerabilities_rows_in_dashboard_page(self, import_scan_via_api):
        """
        Click on any vulnerabilities in dashboard page and verify it’ll take you to the
        vulnerabilities description page.
        1. Import a scan file and Click on the scan to view the results page.
        2. Enable the dashboard and navigate to “Dashboard” tab.
        3. Click on any vulnerability under “TOP VULNERABILITIES” banner in bottom right corner.
        4. Verify it will take you to vulnerabilities description page by
            checking the visibility of the link “Back to Vulnerabilities” in page header.
        5. Also verify this page header contains its name.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_view_page = ScanViewPage()
        scan_view_page.host_tab.click()
        wait(lambda: scan_view_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

        scan_dashboard_page = ScanDashboardPage()
        scan_dashboard_page.enabling_dashboard()
        wait(lambda: scan_view_page.is_element_present("dashboard_tab"))

        get_driver_no_init().fullscreen_window()
        top_vulns = [row.text for row in scan_dashboard_page.get_top_vulnerabilities()]
        scan_vulnerability = VulnerabilityDescription()

        for vulnerability in top_vulns:
            scan_dashboard_page.click_top_vulnerability(vulnerability=vulnerability)
            LoadingCircle(TIME_THREE_SECONDS)
            assert all([(vulnerability == scan_vulnerability.plugin_details_header),
                        (scan_vulnerability.back_link.text == 'Back to Vulnerabilities')]), \
                "Failed to navigate to vulnerability description page."

            scan_vulnerability.dashboard_tab.click()
            scan_dashboard_page.js_scroll_into_view(element=scan_dashboard_page.get_top_vulnerabilities()[-1])

            LoadingCircle(WAIT_SHORT)

        scan_dashboard_page.back_link.click()

    def test_top_hosts_rows_in_dashboard_page(self, import_scan_via_api):
        """
        Click on any host in dashboard page and verify it’ll take you to the host details page.
        1. Import a scan file and Click on the scan to view the results page.
        2. Enable the dashboard and navigate to “Dashboard” tab.
        3. Click on any host under “TOP HOSTS” banner in bottom left corner.
        4. Verify it will take you to host details page by checking the visibility of the link
            “Back to Hosts” in page header.
        5. Also verify this page header contains its name as “scan_name / host” (e.g. test_1041 / 172.26.17.86).
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_dashboard_page = ScanDashboardPage()
        scan_dashboard_page.host_tab.click()
        wait(lambda: scan_dashboard_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")
        host_list = ScansHostList().get_host_names()

        scan_dashboard_page.enabling_dashboard()
        wait(lambda: scan_dashboard_page.is_element_present("dashboard_tab"))

        top_hosts = [row.text for row in scan_dashboard_page.get_top_hosts() if row.text in host_list]
        scan_host_vulns = ScanVulnerabilities()

        for host in top_hosts:
            scan_dashboard_page.click_top_host(host=host)
            LoadingCircle(WAIT_NORMAL)
            assert all([("{} / {}".format(imported_scan_name, host) == scan_host_vulns.page_header),
                        (scan_host_vulns.back_link.text == 'Back to Hosts')]), \
                "Failed to navigate to vulnerability list page for this host."

            scan_host_vulns.back_link.click()
            scan_host_vulns.dashboard_tab.click()
            LoadingCircle(WAIT_SHORT)

        scan_dashboard_page.back_link.click()

    def test_apply_plugin_family_filter_on_scan_results_page(self, import_scan_via_api):
        """
        NES-9649 - NES-9629 ‘Plugin Family’ filter is not working; It is showing ‘no result found’ outcome even though
        the vulnerability belong to that plugin family is exist on scan result page

        Scenarios tested:
            [x] Apply plugin family filter on scan result page should show relevant values.

        Steps:
        1. Import a scan.
        2. Click on imported scan and go to vulnerability.
        3. Apply filter using plugin family.
        4. Verify relevant results should be displayed.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api

        # Refresh to reflect the imported scan on UI
        scan_page = ScansPage()
        scan_page.refresh()
        SideNav().get_sidenav_element(element_name=created_folder_name).click()
        wait(lambda: scan_page.is_element_present('scan_searchbox'), timeout_seconds=TIME_TEN_SECONDS)
        ScanList().click_on_scan(scan_name=imported_scan_name)

        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present('vulnerability_tab'))
        scan_view_page.vulnerability_tab.click()

        vulnerability_list = VulnerabilityList()
        filter_word = vulnerability_list.get_plugin_family_names()[0]

        scan_view_page.filter_link.click()
        scan_view_page.key_dropdown.select_by_visible_text("Plugin Family")
        scan_view_page.value_dropdown.select_by_visible_text(filter_word)

        action_modal = ActionCloseModal()
        action_modal.action_button.click()
        action_modal.wait_for_modal_closed()

        # Verify the length of results should be greater than zero
        assert len(vulnerability_list.results) > 0, "No vulnerability details found after applying filter"

        # Verify the plugin family name should be same as 'filter word'
        assert {filter_word} == set(value for value in vulnerability_list.get_plugin_family_names())

    @pytest.mark.parametrize("operator_to_select", ['is equal to', 'is not equal to', 'contains', 'does not contain'])
    def test_filter_scan_results_with_multiple_plugin_ids(self, import_scan_via_api, operator_to_select):
        """
        CS-30703 - UI test for CS-30580 - Comma delimited id lists in plugin

        Scenarios:
            [x] Verify it should show relevant results when apply filter with multiple plugin id's using delimiter

        Steps:
        1. Import a scan
        2. Click on scan and go to vulnerability tab.
        3. Click on filter and apply filter by selecting key as Plugin ID and value as plugin ids with delimiter.
        4. Click on apply and verify it is showing relevant result.
        5. Repeat step #1-#4 for keys 'is not equal to', 'contains', 'does not contain' as well.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        ScanViewPage().vulnerability_tab.click()
        wait(lambda: VulnerabilityList().is_element_present('vulnerability_setting'), timeout_seconds=TIME_TEN_SECONDS)

        VulnerabilityList().vulnerability_setting.click()
        VulnerabilityList().enable_disable_groups.click() \
            if VulnerabilityList().enable_disable_groups.text == "Disable Groups" \
            else VulnerabilityList().vulnerability_setting.click()

        total_plugins_count = ScanViewPage().total_records_count
        plugins_id_list = [row.vulnerability_plugin_id for row in VulnerabilityList().rows]

        plugin_ids = plugins_id_list[:3]
        ScanVulnerabilities().apply_filter(key='Plugin ID', operator=operator_to_select, value='{},{},{}'
                                           .format(plugin_ids[0], plugin_ids[1], plugin_ids[2]))
        ActionCloseModal().wait_for_modal_closed()
        if operator_to_select == 'is equal to' or operator_to_select == 'contains':

            # Verify it is showing correct number of rows after applying the filter.
            assert VulnerabilityList().get_total_rows() == len(plugin_ids), \
                "Filter is not working correctly for operator '{}', it should show {} row/s but it is showing '{}' " \
                "row/s".format(operator_to_select, len(plugin_ids), VulnerabilityList().get_total_rows())

            # Verify all the plugin id's are available in the filtered plugins id list.
            assert [row.vulnerability_plugin_id for row in VulnerabilityList().rows] == plugin_ids, \
                "Displayed Plugin ID are not visible for operator {}".format(operator_to_select)
        else:
            # Verify it is showing correct number of rows after applying the filter.
            assert ScanViewPage().total_records_count == total_plugins_count - len(plugin_ids), \
                "Filter is not working correctly for operator '{}', it should show {} row/s but it is showing '{}' " \
                "row/s".format(operator_to_select, len(plugin_ids), VulnerabilityList().get_total_rows())

            # Verify not any of the plugin id's are available in the filtered plugins id list.
            assert any(plugin_ids) not in [row.vulnerability_plugin_id for row in VulnerabilityList().rows], \
                "Plugin id exist in result for operator '{}'".format(operator_to_select)

    @pytest.mark.parametrize('enable_dashboard', [False, True])
    def test_dashboard_can_be_enable_from_imported_scan(self, import_scan_via_api, enable_dashboard):
        """
        NES-13056 [Automation]: Verify Dashboard can be enable for imported scan

        Scenario Tested:
        [x] Verify enable dashboard message for an imported scan of NM.
        [x] Verify 'Enable Dashboard' popup UI.
        [x] Verify the cancel while enabling dashboard for imported scan from popup.
        [x] Verify Dashboard can be enabled for an imported scan.
        [x] Verify enable dashboard message not appear once dashboard view is enabled.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_result_page = ScanViewPage()
        wait(lambda: visibility_of_element_located(scan_result_page.host_tab), waiting_for='Scan results page to load')

        scan_result_page.host_tab.click()
        wait(lambda: scan_result_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

        assert scan_result_page.enable_dashboard_msg.text == Nessus.Scan.Results.ENABLE_DASHBOARD_MESSAGE, \
            "Enable dashboard message is missing or mismatch."

        assert scan_result_page.is_element_present("link_to_enable_dashboard"), \
            "'Click here' link is missing in enable dashboard message."

        scan_result_page.link_to_enable_dashboard.click()
        enable_dashboard_modal = ActionCloseModal()
        wait(lambda: enable_dashboard_modal.is_element_present("modal"),
             waiting_for="'Enable Dashboard' popup get appear")

        assert all([enable_dashboard_modal.modal_title.text == Nessus.Scan.Results.ENABLE_DASHBOARD,
                    enable_dashboard_modal.modal_content.text == Messages.NotificationMessages.ScanResults.
                   enable_dashboard_popup_content,
                    enable_dashboard_modal.action_button.text == Nessus.Scan.Results.ENABLE,
                    enable_dashboard_modal.is_element_present("cancel_button")]), "'Enable Dashboard' popup is missing."

        if enable_dashboard:
            enable_dashboard_modal.action_button.click()
            enable_dashboard_modal.wait_for_modal_closed()
            wait(lambda: visibility_of_element_located(scan_result_page.dashboard_tab),
                 waiting_for="Dashboard tab to get appears")

            assert scan_result_page.is_element_present('dashboard_tab'), \
                "Dashboard tab is not visible even after enabling from 'Enable Dashboard' popup."

            assert scan_result_page.current_url.endswith("/dashboard"), \
                "User does not navigate on 'Dashboard' tab after enabling the dashboard."

            scan_result_page.host_tab.click()
            wait(lambda: scan_result_page.is_element_present("filter_link"), waiting_for="Host tab get loaded")

            assert not scan_result_page.is_element_present("enable_dashboard_msg"), \
                "Enable dashboard message is appears even after getting enabled the dashboard."
        else:
            enable_dashboard_modal.cancel_button.click()

            assert not enable_dashboard_modal.is_element_present("modal"), \
                "'Enable Dashboard' popup is not getting disappear after clicking on 'Cancel' button."

            assert not scan_result_page.is_element_present("dashboard_tab"), \
                "Dashboard tab is displayed in scan results even after cancelling the enable dashboard popup."

    def test_verify_scan_configure_page_of_imported_scan(self, import_scan_via_api):
        """
        NES-13056 [Automation]: Verify Dashboard can be enable for imported scan

        Scenario Tested:
        [x] Verify scan configure page from imported scan.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_result_page = ScanViewPage()
        wait(lambda: visibility_of_element_located(scan_result_page.host_tab), waiting_for='Scan results page to load')

        assert scan_result_page.is_element_present("configure"), \
            "'Configure' button is missing on top right side in imported scan result page."

        scan_result_page.configure.click()
        scan_form = NewScanForm()
        wait(lambda: scan_form.is_element_present("name_field"), waiting_for="scan configure page get loaded")

        expected_config_url = "/config/settings/basic/general" if is_manager() else "/config/settings/basic"

        assert scan_result_page.current_url.endswith(expected_config_url), \
            "User does not navigate to scan configure page after clicking on 'Configure' button."

        assert scan_form.name_field.value != '', \
            "Scan name text field is empty while configuring scan which should not be empty."

        assert all([scan_form.is_element_present("name_field"), scan_form.is_element_present("description_textarea"),
                    scan_form.is_element_present("select_folder"), scan_form.is_element_present("select_dashboard")]), \
            "Something is missing on scan configure page for imported scan from 'Name', 'Description', 'Folder' " \
            "and 'Show Dashboard' checkbox."

        assert [option.text for option in scan_form.basic_settings_options] == [
            Nessus.Scan.SettingsBasicSubMenu.GENERAL, Nessus.Scan.SettingsBasicSubMenu.PERMISSIONS], \
            "'General' and 'Permission' options are missing in basic setting submenu for imported scan."

    def test_dashboard_view_can_be_disabled_from_imported_scan_configure_page(self, import_scan_via_api):
        """
        NES-13056 [Automation]: Verify Dashboard can be enable for imported scan

        Scenario Tested:
        [x] Verify Dashboard can be disabled for an imported scan
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_result_page = ScanViewPage()
        wait(lambda: visibility_of_element_located(scan_result_page.host_tab), waiting_for='Scan results page to load')

        scan_result_page.host_tab.click()
        wait(lambda: scan_result_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

        scan_result_page.link_to_enable_dashboard.click()
        enable_dashboard_modal = ActionCloseModal()
        wait(lambda: enable_dashboard_modal.is_element_present("modal"),
             waiting_for="'Enable Dashboard' popup get appear")

        enable_dashboard_modal.action_button.click()
        enable_dashboard_modal.wait_for_modal_closed()
        wait(lambda: visibility_of_element_located(scan_result_page.dashboard_tab),
             waiting_for="Dashboard tab to get appears")

        assert scan_result_page.is_element_present('dashboard_tab'), \
            "Dashboard tab is not visible even after enabling from 'Enable Dashboard' popup."

        scan_result_page.configure.click()
        scan_form = NewScanForm()
        wait(lambda: scan_form.is_element_present("name_field"), waiting_for="scan configure page get loaded")

        assert all([scan_form.select_dashboard.is_displayed(), scan_form.select_dashboard.is_selected()]), \
            "'Show Dashboard' checkbox is not getting selected even though the dashboard is enabled."

        scan_form.select_dashboard.uncheck()
        scan_form.save_button.click()
        notifications = Notifications()

        assert notifications.successes[-1] == Messages.NotificationMessages.save_scan, \
            "Success notification is missing after configuring the imported scan."

        scan_form.cancel_button.click()
        wait(lambda: visibility_of_element_located(scan_result_page.host_tab), waiting_for='Scan results page to load')

        assert not scan_result_page.is_element_present('dashboard_tab'), \
            "'Dashboard' tab is visible even after disabling it while configuring imported scan."

    @pytest.mark.xray(test_key='NES-14300')
    @pytest.mark.xfail(reason="Refer JIRA ID NES-10752")
    def test_verify_enable_dashboard_note_should_disappear_if_no_result_exist(self, import_scan_via_api):
        """
        NES-14300: Verify dashboard view notification message when all hosts deleted from imported scans

        Scenario Tested:
        [x] Verify that if no results exist under Hosts tab then enable dashboard note should get disappeared.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api

        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_result_page = ScanViewPage()
        wait(lambda: visibility_of_element_located(scan_result_page.host_tab), waiting_for='Scan results page to load')

        assert all([scan_result_page.is_element_present("enable_dashboard_msg"),
                    scan_result_page.is_element_present("link_to_enable_dashboard")]), \
            "Enable dashboard message is either missing or mismatch in Host tab."

        ScansHostList().select_all_checkbox.check()
        wait(lambda: scan_result_page.is_element_present("more_dropdown"), waiting_for="'More' dropdown get displayed")

        scan_result_page.more_dropdown.click()
        wait(lambda: scan_result_page.is_element_present('delete_host'),
             waiting_for="'delete' button get displayed in dropdown")

        scan_result_page.delete_host.click()
        delete_hosts_modal = ActionCloseModal()
        delete_hosts_modal.accept_action()
        delete_hosts_modal.wait_for_modal_closed()

        assert not all([scan_result_page.is_element_present("enable_dashboard_msg"),
                        scan_result_page.is_element_present("link_to_enable_dashboard")]), \
            "Enable dashboard message is still present even after deleting all hosts under 'Host' tab."


@pytest.mark.scans_2
@pytest.mark.nessus_home
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
class TestImportedScanWithAttachment:

    @pytest.mark.usefixtures("nessus_api_login", 'login')
    @pytest.mark.parametrize('import_scan_via_api', [
        {'file_name': 'Cisco_attachment.db', 'file_path': 'nessus/tests/ui/scans/test_data/', 'password': 'sapphire',
         "encrypted": True},
        {'file_name': 'Advanced_scan_plugins_attachment.db', 'file_path': 'nessus/tests/ui/scans/test_data/',
         'password': 'nessus', "encrypted": True}], indirect=True)
    def test_download_vulnerability_plugin_attachment(self, import_scan_via_api):
        """
        NES-9096: UI Test for downloading files attached to plugin results

        Scenarios tested:
        [x]  Verify attached files can be downloaded and can be visible in Chrome downloads

        Steps:
        1. Import Scan via api.
        2. Refresh the scans page to reflect the imported scan on the UI.
        3. Click on scan and then click on vulnerability tab.
        4. Find the attachment and click on it to download.
        5. Verify the attachment is downloaded successfully.
        """
        scan_name = import_scan_via_api[0]

        # Refresh the page to reflect the imported scan on UI
        scans_page = ScansPage()
        scans_page.refresh()

        scan_view_page = ScanViewPage()
        wait(lambda: scans_page.is_element_present("scan_searchbox"), timeout_seconds=TIME_SIXTY_SECONDS,
             waiting_for="Scan search box to be visible")

        ScanList().click_on_scan(scan_name=scan_name)
        wait(lambda: scan_view_page.is_element_present("vulnerability_tab"), timeout_seconds=TIME_SIXTY_SECONDS,
             waiting_for="Vulnerability tab to be visible")
        scan_view_page.vulnerability_tab.click()

        vulnerability_list = VulnerabilityList()
        vulnerability_list.find_vulnerability_by_id(
            plugin_id=919149 if scan_name == "Cisco RV320 direct check" else 84239).click()

        scan_view_page.js_scroll_into_view(element=scan_view_page.plugin_attachment)
        scan_view_page.plugin_attachment.click()
        sleep(sleep_time=WAIT_NORMAL, reason="waiting for page switch to new tab")

        driver_instance = get_driver_no_init()
        windows_handler = WindowsHandler(driver=driver_instance)
        windows_handler.switch_to_window(windows_handler.handles[-1])
        new_tab_url = driver_instance.current_url.split("/")

        # Verify attachment id is present in current url
        assert all([new_tab_url[3] == "tokens", new_tab_url[5] == "download"]), \
            "User does not navigate to new tab after clicking on attachment."

        # Verify the data is present in plugin file
        assert scan_view_page.plugin_attachment_data.text == getattr(
            API.Scan.VulnerabilitiesDetails, 'PLUGIN_FILE_DATA' if scan_name == "Cisco RV320 direct check"
            else 'PLUGIN_FILE_DATA_TYPE_TEXT')[0]

        windows_handler._driver.close()
        windows_handler.switch_to_window(windows_handler.handles[0])
        sleep(sleep_time=WAIT_NORMAL, reason="waiting for page switch back to active tab")


@pytest.mark.scans_2
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login', 'login')
class TestCreateScansFromScanResult:
    """ Covers tests for create scan from imported scan results host """

    cat = None

    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_network_scan_NES_9945.nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/',
                                                      'create_folder': True, 'encrypted': True}], indirect=True)
    def test_visibility_of_create_scan_option_on_scan_result(self, import_scan_via_api):
        """
        NES-9945 - Allow users to launch/configure a scan from another set of scan results(NES-9868)

        Scenarios:
            [x] Verify the visibility of "Create Scan" and "Delete" options on scan result page when hosts are selected.

        Steps:
        1. Login to Nessus.
        2. Import scan to Nessus and go to scan results page.
        3. Select a host available in Hosts tab and verify that Dropdown menu having name as "More" appears.
        4. Click on 'More' Dropdown.
        5. Verify that "Delete" and "Create Scan" options are available in the dropdown.
        6. Logout from Nessus.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        scan_result_page = ScanViewPage()

        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        wait(lambda: scan_result_page.is_element_present('configure'), waiting_for="Scan result page to properly load.")
        scan_result_page.host_tab.click()
        wait(lambda: scan_result_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")
        hosts_list = ScansHostList()
        hosts_names_list = hosts_list.get_host_names()

        assert hosts_names_list == [Nessus.Scan.Target.LOCALHOST, Nessus.Scan.Target.AWS_LINUX_TARGET_2,
                                    Nessus.Scan.Target.AWS_LINUX_TARGET_1], \
            "Hosts names are not same as given during scan creation"
        hosts_list.select_hosts(hosts_list=hosts_names_list[0])

        assert scan_result_page.is_element_present('more_dropdown'), \
            "Drop down having title as 'More' is not appearing on scan result page."
        scan_result_page.more_dropdown.click()
        assert scan_result_page.is_element_present('delete_host'), \
            "Delete option is not appearing after clicking on 'More' drop down."
        assert scan_result_page.is_element_present('create_scan_option'), \
            "Create Scan option is not appearing after clicking on 'More' drop down."

    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_network_scan_NES_9945.nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/',
                                                      'create_folder': True, 'encrypted': True}], indirect=True)
    def test_create_scan_from_scan_results_by_selecting_hosts_and_scan_template(self, import_scan_via_api):
        """
        NES-9945 - Allow users to launch/configure a scan from another set of scan results(NES-9868)

        Scenarios:
            [x] Create/Launch new scan from scan results page by selecting hosts and required scan template.

        Steps:
        1. Login to Nessus.
        2. Import scan to Nessus and go to scan results page.
        3. Select couple of hosts available in Hosts tab.
        4. Select "Create Scan" option from the dropdown.
        5. Select a scan template.
        6. Verify that targets field auto populated as selected hosts on scan result page above.
        7. Create and Launch scan. Wait till scan get completed.
        8. Delete the scan and logout from Nessus.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        scan_result_page = ScanViewPage()

        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        wait(lambda: scan_result_page.is_element_present('configure'), waiting_for="Scan result page to properly load.")
        scan_result_page.host_tab.click()
        wait(lambda: scan_result_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")
        hosts_list = ScansHostList()

        hosts_list.select_hosts(hosts_list=hosts_list.get_host_names()[:2])
        scan_result_page.more_dropdown.click()
        scan_result_page.create_scan_option.click()

        scan_page = ScansPage()
        wait(lambda: scan_page.is_element_present('scanner'), waiting_for='Scan templates to load properly')
        close_pendo_guide_container_banner_for_nessus_pro()

        scan_type = ScanType()
        scan_type.select_scan_type(type_of_scan=API.Permissions.Types.SCANNER)
        scan_type.click_by_scan(scan_text=Nessus.TemplateNames.ADVANCED)

        create_new_scan = NewScanForm()
        wait(lambda: create_new_scan.is_element_present('name_field'), waiting_for='New scan form to load properly')

        # Verifying that targets field auto-populated with proper value.
        assert create_new_scan.targets_textarea.value == "{}, {}".format(Nessus.Scan.Target.LOCALHOST,
                                                                         Nessus.Scan.Target.AWS_LINUX_TARGET_2), \
            "Target field value is either not auto populated or it is not same as hosts selected from scan result page."

        new_scan_name = (random_name(prefix='Scan_NES-9945-'))[:20]
        create_new_scan.name_field.value = new_scan_name

        create_new_scan.save_button.click()
        scan_list = ScanList()

        try:
            wait(lambda: scan_page.is_element_present('new_scan_button'),
                 waiting_for="Scan main page to load properly.")
            SideNav().get_sidenav_element(element_name=created_folder_name).click()
            scan_list.loaded()
            assert scan_list.launch_scan_and_wait_for_status(scan_name=new_scan_name), \
                "Scan has not been completed successfully"

        finally:
            scan_list.delete_scan(scan_name=new_scan_name)
            ScansTrashPage().delete_selected_scan(scan_list=[new_scan_name])

    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_Scan_for_NES-13053_pfx4mo.nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/',
                                                      'encrypted': True}], indirect=True)
    @pytest.mark.parametrize('no_of_host', ['single', 'multiple'])
    def test_scan_can_be_created_from_imported_scan_results_host(self, import_scan_via_api, no_of_host):
        """
        NES-13053 [Automation]: Verify a scan can be created by selecting single/multiple host from an imported scan

        Scenario Tested:
        [x] Verify a scan can be created by selecting single host from an imported scan result hosts
        [x] Verify a scan can be created by selecting multiple host from an imported scan result hosts
        """
        imported_scan_name = import_scan_via_api[0]

        scan_list = ScanList()
        scan_list.refresh()
        scan_list.loaded()

        scan_list.click_on_scan(scan_name=imported_scan_name)
        scan_result_page = ScanViewPage()
        wait(lambda: visibility_of_element_located(scan_result_page.host_tab), waiting_for='Scan results page to load')
        scan_result_page.host_tab.click()
        wait(lambda: scan_result_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")
        hosts_list = ScansHostList()
        host_names = hosts_list.get_host_names()

        random_host_count = 1 if no_of_host == "single" else int(len(host_names) / 2)
        host_list_to_be_selected = random.sample(host_names, k=random_host_count)

        hosts_list.select_hosts(hosts_list=host_list_to_be_selected)
        wait(lambda: visibility_of_element_located(scan_result_page.more_dropdown),
             waiting_for="'More' dropdown to be appear'")

        assert scan_result_page.is_element_present("more_dropdown"), \
            "'More' dropdown is not appearing on top right side in header after selecting host."

        scan_result_page.more_dropdown.click()

        assert [element.text for element in scan_result_page.more_dropdown_options] == [
            Nessus.Scan.Results.DELETE, Nessus.Scan.Results.CREATE_SCAN], \
            'Few of options are missing under time range drop-down.'

        scan_result_page.create_scan_option.click()
        scan_template_page = ScanTemplatePage()
        wait(lambda: scan_template_page.is_element_present('vuln_template_section'),
             waiting_for='scan templates to load properly.')
        close_pendo_guide_container_banner_for_nessus_pro()

        assert scan_template_page.current_url.endswith("/scans/reports/new?targets=true"), \
            "After clicking on 'Create Scan' option from 'More' dropdown, It does not navigate to scan template page."

        scan_template_page.click_by_scan(scan_text=Nessus.TemplateNames.ADVANCED)
        new_scan_form = NewScanForm()
        wait(lambda: new_scan_form.is_element_present('name_field'), waiting_for='New scan form to load properly')

        assert new_scan_form.is_element_present('name_field'), \
            "After selecting scan template, It does not navigate to scan creation page."

        new_scan_name = random_name(prefix='Scan_NES-13053-')

        try:
            new_scan_form.name_field.value = new_scan_name

            assert new_scan_form.targets_textarea.text != "", "Scan targets textarea is not found pre-filled."

            new_scan_form.save_button.click()

            assert Notifications().successes[-1] == "Scan saved successfully.", \
                'Success notification is missing after creating the scan from imported scan result host.'

            scan_list.loaded()

            assert new_scan_name in scan_list.get_all_scans(), "Failed to create scan from imported scan result host."

            assert scan_list.launch_scan_and_wait_for_status(scan_name=new_scan_name), \
                'Scan has not been completed successfully.'
        finally:
            scan_id = get_scan_id(api_object=self.cat.api, scan_name=new_scan_name)
            self.cat.api.scans.delete(scan_id=scan_id)


@pytest.mark.scans_2
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login', 'login')
@pytest.mark.parametrize('import_scan_via_api', [
    {'file_name': 'Host_Discovery_Table_NES_9988.db', 'file_path': 'nessus/tests/ui/scans/test_data/',
     'password': 'test', 'create_folder': True, 'encrypted': True}], indirect=True)
class TestHostDiscoveryTable:

    @pytest.mark.parametrize('total_host', [17])
    def test_verify_host_discovery_table_contents(self, import_scan_via_api, total_host):
        """
        NES-9988 - UI Automation: Host Discovery Table

        Scenarios:
            [x] Verify the host discovery table content

        Steps:
        1. Login to Nessus.
        2. Import a scan with template "Host Discovery"
        3. Verify the columns of Host Discovery Table in scan results page.
        4. Verify the number of hosts in Host Discovery Table.
        5. Drilldown to any one host and verify the Host, DNS and OS name values.
        6. Delete scan and logout from Nessus.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        scan_result_page = ScanViewPage()

        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)
        scan_result_page.host_tab.click()
        wait(lambda: scan_result_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")
        hd_scan_hosts = HDScanHostsList()

        wait(lambda: scan_result_page.is_element_present("search_box"), waiting_for="Scan result to load properly.")

        hd_scan_column_names = [column_name.text for column_name in hd_scan_hosts.columns]

        # Verifying Host discovery Table column Names
        assert all([getattr(Nessus.Scan.Results.HostDiscoveryTable, key) == hd_scan_column_names[index]
                    for index, key in enumerate(('HOST', 'FQDN', 'OPERATING_SYSTEM'), 1)]), \
            'Column names for host discovery table are not matching.'

        # Verifying Number of hosts in Host discovery Table.
        assert len(hd_scan_hosts.get_all_hosts()) == total_host, "Number of hosts is not matching."

        host_name = hd_scan_hosts.rows[-1].host_name
        dns_name = hd_scan_hosts.rows[-1].dns_name
        os_name = hd_scan_hosts.rows[-1].os_name
        hd_scan_hosts.rows[-1].click()

        wait(lambda: scan_result_page.is_element_present("vulnerability_tab"))

        # Verifying Host name in Host details section after clicking on host
        assert host_name == scan_result_page.get_levels_value_of_details_section(
            Nessus.Scan.Results.HostDetailsLevels.HOST_IP).text, \
            "After drilldown to host, host name is not matching with host name in host discovery table."

        # Verifying DNS name in Host details section after clicking on host
        assert dns_name == scan_result_page.get_levels_value_of_details_section(
            Nessus.Scan.Results.HostDetailsLevels.HOST_DNS).text, \
            "After drilldown to host, DNS name is not matching with DNS name in host discovery table."

        # Verifying OS name in Host details section after clicking on host
        assert os_name == scan_result_page.get_levels_value_of_details_section(
            Nessus.Scan.Results.HostDetailsLevels.HOST_OS).text, \
            "After drilldown to host, os name is not matching with OS name in host discovery table."

    @pytest.mark.parametrize("sort", SortOrder.VALID_ORDERS)
    @pytest.mark.parametrize("column_to_sort", ["Host", "FQDN", "Operating System", pytest.param(
        "Ports", marks=pytest.mark.xfail(reason='Refer Jira ID NES-10069'))])
    def test_sort_host_discovery_table_columns(self, import_scan_via_api, sort, column_to_sort):
        """
        NES-9988 - UI Automation: Host Discovery Table

        Scenarios:
            [x] Verify the sorting feature in Host Discovery Table.

        Steps:
        1. Login to Nessus.
        2. Import a scan with template "Host Discovery"
        3. Sort different columns of Host Discovery Table and verify the values.
        4. Delete scan and logout from Nessus.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)
        wait(lambda: ScanViewPage().is_element_present("search_box"), waiting_for="Scan result to load properly.")

        column_mapping = {"Host": "host_name", "FQDN": "dns_name", "Operating System": "os_name", "Ports": "port"}
        map_attribute = column_mapping[column_to_sort]

        scan_result_page = ScanViewPage()
        scan_result_page.host_tab.click()
        wait(lambda: scan_result_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

        hd_scan_hosts = HDScanHostsList()
        expected_hosts_list = sorted([getattr(host, map_attribute) for host in hd_scan_hosts.rows],
                                     key=lambda k: k.lower(), reverse=(sort == SortOrder.DESCENDING))

        rendered_hosts_list = sort_on_column_values(page_class_instance=hd_scan_hosts, sort=sort,
                                                    column_name=column_to_sort)

        # Verifying if the values are as expected after sorting (ascending/descending)
        assert expected_hosts_list == [getattr(host, map_attribute) for host in rendered_hosts_list], \
            "{} is not sorted in {} order".format(column_to_sort, sort)

        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()

    def test_delete_host_from_host_discovery_table(self, import_scan_via_api):
        """
        NES-9988 - UI Automation: Host Discovery Table

        Scenarios:
            [x] Delete host from Host Discovery Table.

        Steps:
        1. Login to Nessus.
        2. Import a scan with template "Host Discovery"
        3. Delete a host from Host Discovery Table and verify the count of hosts decreased by one.
        4. Delete scan and logout from Nessus.
        """
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api
        navigated_to_imported_scan(folder=created_folder_name, scan_name=imported_scan_name)

        scan_result_page = ScanViewPage()
        wait(lambda: scan_result_page.is_element_present("search_box"), waiting_for="Scan result to load properly.")

        scan_result_page.host_tab.click()
        wait(lambda: scan_result_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

        hd_scan_hosts = HDScanHostsList()
        total_host = len(hd_scan_hosts.get_all_hosts())
        hd_scan_hosts.delete_host_from_table(host_name=hd_scan_hosts.rows[0].host_name)

        # Verifying the host delete success notification.
        assert Notifications().successes[-1] == Messages.NotificationMessages.ScanResults.host_deleted, \
            "Success notifications for host deletion is mismatched or missing."

        # Verify the total hosts in Host Discovery Table.
        assert len(hd_scan_hosts.get_all_hosts()) == total_host - 1, \
            "Number of hosts is not matching after deleting host."


@pytest.mark.scans_2
class TestThreatLevelTabForImportedScan:
    """Tests to verify new VPR details in imported scan result"""

    __test__ = False
    cat = None

    @staticmethod
    def get_highest_vpr_top_threat_severity_and_score(scan_name: str) -> tuple:
        """
        Returns highest "VPR Top Threats" severity level and score

        :rparam str scan_name: scan name
        :return: Plugin severity level and it's score
        :rtype: tuple
        """
        scan_list = ScanList()
        scan_list.click_on_scan(scan_name=scan_name)

        scan_view_page = ScanViewPage()
        wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
             waiting_for='Vulnerabilities to get loads')

        scan_view_page.threat_level_tab.click()
        wait(lambda: visibility_of_element_located(scan_view_page.threat_level_description),
             waiting_for='Threat level tab to get loaded')

        threat_level_vulnerability_list = ThreatLevelVulnerabilityList()
        vpr_severity_list = threat_level_vulnerability_list.get_plugin_vpr_severity()
        vpr_score_list = threat_level_vulnerability_list.get_plugin_vpr_score()

        return vpr_severity_list, vpr_score_list

    @pytest.mark.usefixtures('nessus_api_login', 'import_scan_via_api', 'login')
    @pytest.mark.parametrize('import_scan_via_api', [
        {'file_name': 'Basic_Network_-_CVSS_av5q3j.nessus', 'file_path': 'nessus/tests/ui/scans/test_data/'},
        {'file_name': 'Basic_Network_-_CVSS_561gkp.db', 'file_path': 'nessus/tests/ui/scans/test_data/',
         'password': 'nessus', 'encrypted': True}], indirect=True)
    def test_verify_vpr_details_for_imported_scan(self, import_scan_via_api):
        """
        NES-12603: [Automation] Verify VPR data is processed for a newly imported scan

        Scenario Tested:
            [x] Verify that VPR data is processed for newly imported scan.
        """
        scan_name = import_scan_via_api[0]
        scan_list = ScanList()
        scan_list.click_on_scan(scan_name=scan_name)
        scan_view_page = ScanViewPage()
        wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
             waiting_for='Vulnerabilities to get loads')

        # Verify that threat level tab is present on scan results
        assert scan_view_page.is_element_present('threat_level_tab'), \
            "Threat level tab is not present in imported scan result."

        scan_view_page.threat_level_tab.click()
        wait(lambda: visibility_of_element_located(scan_view_page.threat_level_description),
             waiting_for='Threat level tab to get loaded')

        threat_level_vulnerability_list = ThreatLevelVulnerabilityList()
        assert Nessus.Scan.Results.ThreatLevelTab.COLUMN_LIST == [
            column.text for column in threat_level_vulnerability_list.columns], \
            "Column names are incorrect in VPR table for imported scan result"

        assert threat_level_vulnerability_list.get_total_rows() <= 10, \
            "Vulnerabilities in threat level tab are not correct in threat level tab."

        # Verify basic details for VPR pop up on threat level tab in imported scan.
        vulnerability = threat_level_vulnerability_list.get_plugin_names()[0]
        threat_level_vulnerability_list.click_on_vulnerability(vulnerability_name=vulnerability)
        vpr_pop_up = ActionCloseModal()
        assert vpr_pop_up.is_element_present('modal'), "Modal does not appear on VPR pop up."
        assert vpr_pop_up.modal_title.text.split('\n')[1] == vulnerability, \
            "Vulnerability name should be present on vulnerability pop up title."
        vpr_pop_up.close_button.click()
        vpr_pop_up.wait_for_modal_closed()
        HeaderBasePage().scan_link.click()

    @pytest.mark.usefixtures('nessus_api_login', 'import_scan_via_api', 'login')
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_-_CVSS_av5q3j.nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/'}], indirect=True)
    @pytest.mark.parametrize('sort', SortOrder.VALID_ORDERS)
    @pytest.mark.parametrize('column_to_sort', ['Name', 'Reasons', 'VPR Score'])
    def test_verify_sorting_for_threat_level_tab_in_imported_scan(self, column_to_sort, sort, import_scan_via_api):
        """
        NES-12575: [Automation] Verify sorting on "Threat Level" table

        Scenario Tested:
            [x] Verify sorting on "Threat Level" table by Plugin names, Reasons and VPR score
        """
        scan_name = import_scan_via_api[0]
        column_mapping = {'Name': 'vulnerability_plugin_name', 'Reasons': 'vulnerability_plugin_reason',
                          'VPR Score': 'vulnerability_vpr_score'}
        scan_list = ScanList()

        # Click on scan
        scan_list.click_on_scan(scan_name)
        scan_view_page = ScanViewPage()
        wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
             waiting_for='Vulnerabilities to get loads')

        scan_view_page.threat_level_tab.click()
        wait(lambda: visibility_of_element_located(scan_view_page.threat_level_description),
             waiting_for='Threat level tab to get loaded')

        threat_level_vulnerability_list = ThreatLevelVulnerabilityList()
        map_attribute = column_mapping[column_to_sort]
        expected_sorted_vulnerability_list = sorted([float(getattr(
            history, map_attribute)) if column_to_sort == "VPR Score" else getattr(
            history, map_attribute) for history in threat_level_vulnerability_list.rows],
                                                    reverse=(sort == SortOrder.DESCENDING))

        LoadingCircle(TIME_THREE_SECONDS)
        rendered_vulnerability_list = sort_on_column_values(page_class_instance=threat_level_vulnerability_list,
                                                            sort=sort, column_name=column_to_sort)

        rendered_sorted_vulnerability_list = [float(getattr(
            history, map_attribute)) if column_to_sort == "VPR Score" else getattr(
            history, map_attribute) for history in rendered_vulnerability_list]

        # Verify that after sorting, user is getting expected order for vulnerabilities
        assert expected_sorted_vulnerability_list == rendered_sorted_vulnerability_list, \
            "{} is not sorted in {} order".format(column_to_sort, sort)
        HeaderBasePage().scan_link.click()

    @pytest.mark.usefixtures('nessus_api_login', 'import_scan_via_api', 'login')
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_-_CVSS_av5q3j.nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/'}], indirect=True)
    def test_verify_vulnerability_popup_in_threat_level_tab_in_imported_scan(self, import_scan_via_api):
        """
        NES-12576: [Automation] Verify details view pop-up of vulnerability
        NES-12706: [Automation] Verify visibility of required elements under VPR top threat tab

        Scenario Tested:
            [x] Verify vulnerability pop up for threat level tab.
            [x] Verify on clicking ‘x’, pop-up should get closed
            [x] Verify the content shown under pop-up page
        """
        scan_list = ScanList()

        # Click on scan
        scan_list.click_on_scan(import_scan_via_api)
        scan_view_page = ScanViewPage()
        wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
             waiting_for='Vulnerabilities to get loads')

        scan_view_page.threat_level_tab.click()
        wait(lambda: visibility_of_element_located(scan_view_page.threat_level_description),
             waiting_for='Threat level tab to get loaded')

        threat_level_vulnerability_list = ThreatLevelVulnerabilityList()
        vulnerability_name = threat_level_vulnerability_list.get_plugin_names()[0]

        threat_level_vulnerability_list.click_on_vulnerability(vulnerability_name=vulnerability_name)
        vulnerability_pop_up = ActionCloseModal()

        try:
            try:
                wait(lambda: vulnerability_pop_up.is_element_present('modal'), waiting_for='Popup to get opened.')
            except TimeoutExpired:
                raise AssertionError("Vulnerability pop up does not appear after clicking on the same")

            # Verify details on VPR details pop up are correct.
            assert vulnerability_pop_up.modal_title.text.split('\n')[1] == vulnerability_name, \
                "Vulnerability name should be present on vulnerability pop up."

            assert "localhost ({})".format(Nessus.Scan.Target.LOCALHOST) in [
                detail.text for detail in threat_level_vulnerability_list.vulnerability_details], \
                "Host is incorrect on vulnerability detail pop up."

            plugin_details_content_labels = [column_name.text.split('(')[0].rstrip() for column_name in
                                             threat_level_vulnerability_list.plugin_details_content_label]

            assert plugin_details_content_labels.sort() == Nessus.Scan.Results.ThreatLevelTab. \
                PLUGIN_DETAILS_CONTENT_LABELS.sort(), "Content labels are incorrect in plugins details content pop-up."

            vulnerability_pop_up.close_button.click()
            vulnerability_pop_up.wait_for_modal_closed()

            assert not vulnerability_pop_up.is_element_present("modal"), \
                "Plugin details pop-up is not getting closed after clicking on 'X'."
        finally:
            if vulnerability_pop_up.is_element_present("modal"):
                vulnerability_pop_up.close_button.click()
                vulnerability_pop_up.wait_for_modal_closed()

            HeaderBasePage().scan_link.click()

    @pytest.mark.usefixtures('nessus_api_login', 'import_scan_via_api', 'login')
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_-_CVSS_av5q3j.nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/'}], indirect=True)
    def test_verify_host_hyperlink_in_the_vpr_details_popup(self, import_scan_via_api):
        """
        NES-12577: [Automation] Verify hosts hyperlinks in the VPR details view pop-up

        Scenario Tested:
            [x] Verify host hyperlink works properly on vpr details pop up
        """
        scan_list = ScanList()

        # Click on scan
        scan_list.click_on_scan(import_scan_via_api)
        scan_view_page = ScanViewPage()
        wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
             waiting_for='Vulnerabilities to get loads')
        scan_view_page.threat_level_tab.click()
        wait(lambda: visibility_of_element_located(scan_view_page.threat_level_description),
             waiting_for='Threat level tab to get loaded')
        threat_level_vulnerability_list = ThreatLevelVulnerabilityList()
        vulnerability = threat_level_vulnerability_list.get_plugin_names()[0]
        threat_level_vulnerability_list.click_on_vulnerability(vulnerability_name=vulnerability)
        wait(lambda: ActionCloseModal().is_element_present('modal'), waiting_for='Popup to get opened.')
        scan_view_page.threat_level_host_link[0].click()

        # Verify that Vulnerability pop up appears after clicking on host hyperlink.
        try:
            wait(lambda: scan_view_page.is_element_present('vulnerability_tab'))
        except TimeoutExpired:
            raise AssertionError("Error while navigating to vulnerabilities of host")

        # Verify that host/remediation or history tab does not appear on screen.
        assert not (scan_view_page.is_element_present('host_tab') and scan_view_page.is_element_present(
            'remediation_tab') and scan_view_page.is_element_present('history_tab')), \
            "Host/Remediation/History tab is present on screen after clicking on host hyperink."
        scan_view_page.back_link.click()

        # Verify that threat level tab loads properly after clicking on back link.
        try:
            wait(lambda: visibility_of_element_located(scan_view_page.threat_level_description),
                 waiting_for='Threat level tab to get loaded')
        except TimeoutExpired:
            raise AssertionError("Error while coming back to threat level tab from host vulnerabilities page.")

    @pytest.mark.usefixtures('nessus_api_login', 'import_scan_via_api', 'login')
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_-_CVSS_av5q3j.nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/'}], indirect=True)
    def test_applied_plugin_rule_does_not_affect_to_vpr_score(self, import_scan_via_api):
        """
        NES-12743: Verify applied plugin rules will not affect VPR score

        Scenario Tested:
        [x] Verify that applied plugin rule does not affect to VPR score.
        """
        scan_list = ScanList()
        scan_name = import_scan_via_api[0]

        before_severity, before_score = self.get_highest_vpr_top_threat_severity_and_score(scan_name=scan_name)
        log.debug("VPR severity before recasting plugin rule :: {}".format(before_severity))
        log.debug("VPR Score before recasting plugin rule :: {}".format(before_score))

        threat_level_vulnerability_list = ThreatLevelVulnerabilityList()
        vulnerability_name = threat_level_vulnerability_list.get_plugin_names()[0]
        vpr_severity = threat_level_vulnerability_list.get_plugin_vpr_severity()[0]
        threat_level_vulnerability_list.click_on_vulnerability(vulnerability_name=vulnerability_name)

        vulnerability_pop_up = ActionCloseModal()
        plugin_id_content = threat_level_vulnerability_list.plugin_id_from_content.text
        plugin_id = plugin_id_content.split(": ")[1].split("\n")[0]
        vulnerability_pop_up.close_button.click()

        HeaderBasePage().scan_link.click()
        scan_list.loaded()

        severity_details = {"CRITICAL": API.Severity.CRITICAL, "HIGH": API.Severity.HIGH,
                            "MEDIUM": API.Severity.MEDIUM, "LOW": API.Severity.LOW}

        plugin_rule_payload = {"host": Nessus.Scan.Target.AWS_LINUX_TARGET_1, "plugin_id": plugin_id,
                               "type": severity_details[vpr_severity]}
        log.debug("Plugin rule data payload :: {}".format(plugin_rule_payload))

        self.cat.api.plugins.add_plugin_rules(data=plugin_rule_payload)

        HeaderBasePage().scan_link.click()
        scan_list.loaded()

        after_severity, after_score = self.get_highest_vpr_top_threat_severity_and_score(scan_name=scan_name)

        assert all([before_severity == after_severity, before_score == after_score]), \
            "VPR severity and it's score is getting changed after recasting plugin rule."

    @pytest.mark.usefixtures('login')
    @pytest.mark.parametrize("create_users", [
        {"user_details": {"Basic": {'user_name': API.User.Users.BASIC_USER, 'full_name': 'Basic user',
                                    'email': API.User.Users.TEST_EMAIL, 'password': 'admin',
                                    'role': API.User.Role.BASIC},
                          "Standard": {'user_name': API.User.Users.STANDARD_USER, 'full_name': 'Standard user',
                                       'email': API.User.Users.TEST_EMAIL, 'password': 'admin',
                                       'role': API.User.Role.STANDARD},
                          "Administrator": {'user_name': API.User.Users.ADMIN_USER, 'full_name': 'Admin user',
                                            'email': API.User.Users.TEST_EMAIL, 'password': 'admin',
                                            'role': API.User.Role.ADMIN}}, 'unique_username': True,
         "check_login": False}], indirect=True)
    def test_vpr_data_for_different_users(self, create_users):
        """
        NES-12714: [UI-Automation] Verify VPR data in different users of Nessus Manager

        Scenario Tested:
        [x] Verify that "VPR Top Threats" tab and data should be visible to all users like standard, system admin,
            admin and basic.
        """
        scan_list = ScanList()
        scan_view_page = ScanViewPage()
        login_user = LoginPage()
        user_menu = UserMenu()
        threat_level_vulnerability_list = ThreatLevelVulnerabilityList()
        vpr_pop_up = ActionCloseModal()
        nessus_api = NessusAPI()

        for user_name in create_users.values():
            user_menu.logout()
            wait(lambda: login_user.username_field, waiting_for='Login page to load properly')

            login_user.login_with_credentials(username=user_name['user_name'], password=user_name['password'])
            wait(lambda: ScansPage().is_element_present('title_in_header'),
                 waiting_for="My Scans page to load properly", timeout_seconds=TIME_THIRTY_SECONDS)

            nessus_api.login(username=user_name['user_name'], password=user_name['password'])
            file = get_file_path('nessus/tests/ui/scans/test_data/' + 'Basic_Network_-_CVSS_av5q3j.nessus')
            filename = nessus_api.file.upload(file=file)
            scan = nessus_api.scans.import_scan(filename)['scan']

            assert scan['id'], "Scan does not imported successfully in nessus."

            scan_list.refresh()
            scan_list.loaded()

            scan_list.click_on_scan(scan_name=scan['name'])
            wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
                 waiting_for='Vulnerabilities to get loads')

            assert scan_view_page.is_element_present('threat_level_tab'), \
                "'VPR Top Threats' tab is present in scan results."

            scan_view_page.threat_level_tab.click()
            wait(lambda: visibility_of_element_located(scan_view_page.threat_level_description),
                 waiting_for='Threat level tab to get loaded')

            assert Nessus.Scan.Results.ThreatLevelTab.COLUMN_LIST == [
                column.text for column in threat_level_vulnerability_list.columns], \
                "Column names are incorrect in VPR table for imported scan result"

            assert threat_level_vulnerability_list.get_total_rows() <= 10, \
                "Vulnerabilities in threat level tab are not correct in threat level tab."

            # Verify basic details for VPR pop up on threat level tab in an imported scan.
            vulnerability = threat_level_vulnerability_list.get_plugin_names()[0]
            threat_level_vulnerability_list.click_on_vulnerability(vulnerability_name=vulnerability)

            assert vpr_pop_up.is_element_present('modal'), "Modal does not appear on VPR pop up."

            assert vpr_pop_up.modal_title.text.split('\n')[1] == vulnerability, \
                "Vulnerability name should be present on vulnerability pop up title."

            vpr_pop_up.close_button.click()
            vpr_pop_up.wait_for_modal_closed()
            nessus_api.scans.delete(scan_id=scan['id'])


@pytest.mark.scans_2
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
@pytest.mark.usefixtures('nessus_api_login', 'login')
class TestSeverityBaseFeatures:
    """Tests to verify modifying scan result severity base"""

    cat = None

    @staticmethod
    def update_severity_using_modify_button() -> dict:
        """This function update the severity of the first vulnerability from the given vulnerabilities list"""
        vulnerability_list = VulnerabilityList()
        scan_view_page = ScanViewPage()

        # Get plugin name and it's severity before modify
        plugin_name = vulnerability_list.get_plugin_names()[0]
        severity_before_modify = vulnerability_list.get_severity_against_plugin(plugin_name)[0]

        # Modify plugin severity
        severity_levels = list(Nessus.Scan.Severity.SEVERITY_LEVELS)
        severity_levels.append(Nessus.Scan.Severity.MIXED)
        severity_value = [severity_level for severity_level in severity_levels if severity_level !=
                          severity_before_modify.capitalize()][0]

        vulnerability_list.select_vulnerabilities(vulnerabilities_list=[plugin_name])
        scan_view_page.modify_button.click()
        modify_vulnerability = ModifyVulnerability()
        modify_vulnerability.severity.select_by_visible_text(severity_value)
        modify_vulnerability.accept_action()
        modify_vulnerability.wait_for_modal_closed()

        return {'plugin_name': plugin_name, 'severity_before_modify': severity_before_modify,
                'expected_severity': severity_value}

    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_-_CVSS_av5q3j.nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/'}], indirect=True)
    @pytest.mark.parametrize('update_host_vulnerabilities', [True, False])
    def test_verify_plugin_severity_can_be_updated_using_modify_button(self, import_scan_via_api,
                                                                       update_host_vulnerabilities):
        """
        NES-12727: [UI-Automation] : Verify scan vulnerability's severity can be changed using 'modify' button

        Scenario Tested:
            [x] Verify that scan's vulnerability can be modified from vulnerabilities page using 'modify' button.
            [x] Verify that scan's vulnerability can be modified from particular host's vulnerability page
                and using 'modify' button.
        """
        scan_name = import_scan_via_api[0]

        ScansPage().refresh()
        scan_list = ScanList()
        scan_list.loaded()
        scan_list.click_on_scan(scan_name=scan_name)

        scan_view_page = ScanViewPage()
        wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
             waiting_for='Vulnerabilities to get loads')

        if update_host_vulnerabilities:
            scan_view_page.host_tab.click()
            wait(lambda: scan_view_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")
            hosts_list = ScansHostList()
            hosts_list.loaded()
            hosts_list.click_on_host(host_name=hosts_list.get_host_names()[0])
        else:
            scan_view_page.vulnerability_tab.click()

        vulnerability_list = VulnerabilityList()
        wait(lambda: visibility_of_element_located(vulnerability_list.vulnerability_setting),
             waiting_for='vulnerability list to populate')
        vulnerability_list.loaded()
        plugin_details = self.update_severity_using_modify_button()

        severity_after_modify = vulnerability_list.get_severity_against_plugin(plugin_details.get('plugin_name'))[0]

        # Verify plugin severity value after modify
        assert all([plugin_details.get('severity_before_modify') != severity_after_modify, severity_after_modify ==
                    plugin_details.get('expected_severity').upper()]), "Modification of severity wasn't successful."

        HeaderBasePage().scan_link.click()
        scan_list.loaded()

    @pytest.mark.parametrize('import_scan_via_api', [
        {'file_name': 'Basic_Network_Scan_Result.db', 'file_path': 'nessus/tests/ui/scans/test_data/',
         'password': 'nessus', 'encrypted': True}], indirect=True)
    @pytest.mark.parametrize('tab_name', ['Hosts', 'Vulnerabilities'])
    def test_visibility_of_column_order_in_vulnerabilities_tab(self, import_scan_via_api, tab_name):
        """
        NES-13166 [Automation]: Verify that the column order should be like Sev, Score, etc. for Vulnerabilities tabs

        Scenario Tested:
            [x] Verify that the column order should be like Sev, Score, etc. for 'Vulnerabilities' tabs.
            [x] Verify that the column order should be like Sev, Score, etc. for 'Vulnerabilities' tabs after
                navigating from 'Hosts' tab by clicking on any host.
        """
        scan_name = import_scan_via_api[0]

        scan_list = ScanList()
        scan_list.refresh()
        scan_list.loaded()
        scan_list.click_on_scan(scan_name=scan_name)

        scan_view_page = ScanViewPage()
        wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
             waiting_for='Vulnerabilities to get loads')

        if tab_name == "Hosts":
            scan_view_page.host_tab.click()
            wait(lambda: scan_view_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

            scan_host_list = ScansHostList()
            random_host_name = random.sample(scan_host_list.get_host_names(), k=1)[0]
            scan_host_list.click_on_host(host_name=random_host_name)
        else:
            scan_view_page.vulnerability_tab.click()

        vulnerability_list = VulnerabilityList()
        wait(lambda: visibility_of_element_located(vulnerability_list.vulnerability_setting),
             waiting_for='vulnerability list to populate')

        vulnerability_column_names = vulnerability_list.get_visible_column_names()
        expected_column_titles = ["Sev", "CVSS", "VPR", "EPSS", "Name", "Family", "Count"]

        assert list(filter(None, vulnerability_column_names)) == expected_column_titles, \
            "Vulnerabilities columns are not displayed in proper order like 'Sev', 'Score', ...etc."

    @pytest.mark.parametrize('import_scan_via_api', [
        {'file_name': 'Basic_Network_Scan_Result.db', 'file_path': 'nessus/tests/ui/scans/test_data/',
         'password': 'nessus', 'encrypted': True}], indirect=True)
    @pytest.mark.skip(reason="complex locator, not able to catch in testrun")
    def test_visibility_of_score_for_grouped_vulnerabilities_in_scan_results(self, import_scan_via_api):
        """
        NES-13167 [Automation]: Verify when the vulnerabilities are in grouped then score is showing '...'

        Scenario Tested:
            [x] Verify that score is showing "..." for grouped vulnerabilities.
            [x] Verify that the column order should be like Sev, Score, etc. for 'Vulnerabilities' tabs after
                navigating from 'Hosts' tab by clicking on any host.
        """
        settings_details = [{"setting_name": Nessus.AdvancedSettings.SCAN_VULNERABILITY_GROUPS, "setting_value": "Yes"},
                            {"setting_name": Nessus.AdvancedSettings.SCAN_VULNERABILITY_GROUPS_MIXED,
                             "setting_value": "Yes"}]

        for setting_detail in settings_details:
            setting_payload = {"setting.0.name": setting_detail["setting_name"], "setting.0.value": setting_detail[
                "setting_value"], "setting.0.action": "edit"}

            self.cat.api.settings.update(settings=setting_payload)

        click_on_scan_and_go_to_vulnerabilities_tab(scan_name=import_scan_via_api[0])

        vulnerability_list = VulnerabilityList()
        vulnerability_list.vulnerability_setting.click()
        vulnerability_list.click_on_group_enable_disable(enable=True)
        vulnerability_list.vulnerability_setting.click()

        grouped_vulnerability_details = vulnerability_list.get_grouped_vulnerabilities_name_and_family()
        scan_view_page = ScanViewPage()

        for plugin_name, plugin_family in grouped_vulnerability_details.items():
            score_element = vulnerability_list.get_grouped_vulnerabilities_score_element(
                plugin_name=plugin_name, plugin_family=plugin_family)
            vulnerability_list.js_scroll_into_view(element=vulnerability_list.get_grouped_vulnerabilities_score_element
                (plugin_name=plugin_name, plugin_family=plugin_family))

            assert score_element.text == "...", "CVSS score is missing or mismatched or not showing '...' for '{}' " \
                                                "grouped vulnerabilities.".format(plugin_name)

            score_element.click()
            wait(lambda: scan_view_page.is_element_present("search_box"), waiting_for="vulnerabilities to get loaded")

            for row in vulnerability_list.results:
                assert row.cvss_base_score.is_displayed(), "CVSS score is not visible on next page after clicking " \
                                                           "on '{}' grouped vulnerability.".format(plugin_name)

                assert row.cvss_score_value != "...", "CVSS score is showing '...' or empty for single vulnerability " \
                                                      "after clicking on '{}' grouped vulnerability.". \
                    format(plugin_name)

            vulnerability_list.back_to_vulnerabilities.click()
            wait(lambda: scan_view_page.is_element_present("filter_link"), waiting_for="vulnerabilities to get loaded")

    @pytest.mark.parametrize('import_scan_via_api', [
        {'file_name': 'Basic_Network_Scan_Result.db', 'file_path': 'nessus/tests/ui/scans/test_data/',
         'password': 'nessus', 'encrypted': True}], indirect=True)
    @pytest.mark.parametrize('sort', SortOrder.VALID_ORDERS)
    @pytest.mark.parametrize('column_to_sort', ['CVSS'])
    @pytest.mark.parametrize('enable_group', [pytest.param(True, marks=pytest.mark.xfail(
        reason='Refer Jira ID NES-13136')), False])
    def test_sorting_of_score_column_for_grouped_and_ungrouped_vulnerabilities(self, import_scan_via_api, sort,
                                                                               column_to_sort, enable_group):
        """
        NES-13168 [Automation]: Verify that sorting of score column is working properly for grouped and ungrouped
                                vulnerabilities

        Scenario Tested:
        [x] Verify that sorting of 'Score' column is working properly when vulnerabilities are in group.
        [x] Verify that sorting of 'Score' column is working properly when vulnerabilities are not in group.
        """
        click_on_scan_and_go_to_vulnerabilities_tab(scan_name=import_scan_via_api[0])

        vulnerability_list = VulnerabilityList()
        vulnerability_list.vulnerability_setting.click()
        vulnerability_list.click_on_group_enable_disable(enable=enable_group)
        sleep(WAIT_SHORT, reason="Takes little bit time to gets loaded the vulnerabilities after enable/Disable group")

        scan_view_page = ScanViewPage()
        scan_view_page.result_per_page_dropdown.select_by_visible_text('100')

        column_mapping = {'CVSS': 'cvss_score_value'}
        map_attribute = column_mapping[column_to_sort]

        expected_score_values = [getattr(vulnerability, map_attribute).split()[0].rstrip('*') if '*' in getattr(
            vulnerability, map_attribute) else getattr(vulnerability, map_attribute) for vulnerability in
                                 vulnerability_list.rows]
        expected_list = sorted(list(filter(lambda x: x != '...', list(filter(None, expected_score_values)))),
                               key=float, reverse=(sort == SortOrder.DESCENDING))

        rendered_list = sort_on_column_values(page_class_instance=vulnerability_list, sort=sort,
                                              column_name=column_to_sort)
        rendered_score_values = [getattr(vulnerability, map_attribute).split()[0].rstrip('*') if '*' in getattr(
            vulnerability, map_attribute) else getattr(vulnerability, map_attribute) for vulnerability in rendered_list]

        assert expected_list == list(filter(lambda x: x != '...', list(filter(None, rendered_score_values)))), \
            "{} is not sorted in {} order".format(column_to_sort, sort)

        scan_view_page.back_link.click()

    @pytest.mark.parametrize('import_scan_via_api', [
        {'file_name': 'Basic_Network_Scan_Result.db', 'file_path': 'nessus/tests/ui/scans/test_data/',
         'password': 'nessus', 'encrypted': True}], indirect=True)
    @pytest.mark.parametrize("grouped_vulnerability", [True, False])
    def test_visibility_of_cvss_score_for_info_level_severity_ungrouped(self, import_scan_via_api,
                                                                        grouped_vulnerability):
        """
        NES-13193 [Automation] Verify that score is blank for INFO level vulnerabilities.

        Scenario Tested:
            [x] Verify that score is blank for INFO level ungrouped vulnerabilities.
        """
        click_on_scan_and_go_to_vulnerabilities_tab(scan_name=import_scan_via_api[0])

        vulnerability_list = VulnerabilityList()

        if not grouped_vulnerability:
            for vulnerability in vulnerability_list.rows:
                if vulnerability.get_attribute("title").startswith("Plugin ID") and vulnerability.get_attribute(
                        "data-severity") == "0":
                    assert all([vulnerability.cvss_score_value != "...", vulnerability.cvss_score_value == ""]), \
                        "CVSS score is not blank for for 'INFO' level vulnerability."

    @pytest.mark.parametrize('import_scan_via_api', [
        {'file_name': 'Basic_Network_Scan_Result.db', 'file_path': 'nessus/tests/ui/scans/test_data/',
         'password': 'nessus', 'encrypted': True}], indirect=True)
    def test_visibility_of_tool_tip_for_cvss_score_in_scan_results(self, import_scan_via_api):
        """
        NES-13194 [Automation] Verify tool-tip is not available for all normal cvss score.

        Scenario Tested:
            [x] Verify tool-tip is not available for all normal cvss score.
        """
        click_on_scan_and_go_to_vulnerabilities_tab(scan_name=import_scan_via_api[0])

        vulnerability_list = VulnerabilityList()
        vulnerability_list.vulnerability_setting.click()
        vulnerability_list.click_on_group_enable_disable(enable=False)

        for vulnerability in vulnerability_list.rows:
            score_value = vulnerability.cvss_score_value

            if "*" in score_value:
                assert all(["add-tip" in vulnerability.cvss_base_score.get_css_classes(),
                            vulnerability.cvss_base_score.get_attribute("title")]), \
                    "Tooltip is not showing for '{}' vulnerability.".format(vulnerability.vulnerability_plugin_name)
            else:
                assert all(["add-tip" not in vulnerability.cvss_base_score.get_css_classes(),
                            not vulnerability.cvss_base_score.get_attribute("title")]), \
                    "Tooltip is showing for '{}' vulnerability which should not be shown.".format(
                        vulnerability.vulnerability_plugin_name)

    @pytest.mark.parametrize('import_scan_via_api', [
        {'file_name': 'Basic_Network_Scan_Result.db', 'file_path': 'nessus/tests/ui/scans/test_data/',
         'password': 'nessus', 'encrypted': True}], indirect=True)
    def test_visibility_of_cvss_score_column_in_scan_results_from_trash_folder(self, import_scan_via_api):
        """
        NES-13195 [Automation] Verify cvss score column is available for trash scan results also

        Scenario Tested:
            [x] Verify cvss score column is available for trash scan results also
        """
        click_on_scan_and_go_to_vulnerabilities_tab(scan_name=import_scan_via_api[0])
        scan_view_page = ScanViewPage()
        scan_view_page.back_link.click()

        scan_list = ScanList()
        scan_list.delete_scan(scan_name=import_scan_via_api[0])
        wait(lambda: Notifications().successes, waiting_for="Notification list to populate")

        side_nav = SideNav()
        side_nav.get_sidenav_element(element_name=Nessus.Scan.Folder.TRASH).click()

        scan_trash_page = ScansTrashPage()
        wait(lambda: scan_trash_page.is_element_present("scan_searchbox"), waiting_for="Scan trash page gets loaded")
        scan_list.click_on_scan(scan_name=import_scan_via_api[0])
        wait(lambda: scan_view_page.is_element_present("vulnerability_tab"), waiting_for='Vulnerabilities to get loads')

        scan_view_page.vulnerability_tab.click()
        vulnerability_list = VulnerabilityList()
        vulnerability_list.loaded()

        assert ScanViewPage().is_element_present("cvss_score_column"), \
            "CVSS score column is not showing in scan results after moving into trash folder."

    @pytest.mark.parametrize('scan_data_file', [
        (get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'), 'advanced')])
    @pytest.mark.parametrize('export_format', [API.Scan.ExportFormats.FORMAT_NESSUS, API.Scan.ExportFormats.FORMAT_DB])
    def test_visibility_of_cvss_score_column_in_imported_scan_results_after_export(self, scan_data_file, export_format):
        """
        NES-13202 [Automation] Verify CVSS score column is visible when export and import scan itself.

        Scenario Tested:
            [x] Verify CVSS score column is visible when export and import scan itself.
        """
        scan_details = create_scan_helper(self.cat.api, file_name=scan_data_file[0], template_title=scan_data_file[1],
                                          change_scan_name=True)
        scan_id, scan_name = scan_details[0]['scan']['id'], scan_details[0]['scan']['name']

        scan_list = ScanList()
        scan_list.refresh()
        scan_list.loaded()

        self.cat.api.scans.launch(scan_id)

        with polling_ui():
            wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                            timeout=TIME_THIRTY_MINUTES)

        export_import_password = "nessus" if export_format == API.Scan.ExportFormats.FORMAT_DB else None

        export = self.cat.api.scans.export(scan_id=scan_id, export_format=export_format,
                                           password=export_import_password)

        # wait for to get ready state and max wait for 30 sec
        wait(lambda: self.cat.api.scans.export_status(scan_id, export[0]) == API.Status.READY,
             timeout_seconds=TIME_SIXTY_SECONDS, waiting_for='export status to get %s' % API.Status.READY,
             sleep_seconds=WAIT_NORMAL)

        file_name = os.path.join(NessusConfig.CAT_NESSUS_DB_DIRECTORY, 'exported_file_{}'.format(scan_id))

        download_and_save_exported_scan_file(file_path=file_name, api=self.cat.api, file_format="." + export_format,
                                             scan_id=scan_id, file_id=export[0])

        file_uploaded_nessus = self.cat.api.file.upload(file=file_name + "." + export_format, encrypted=True)

        try:
            import_scan = self.cat.api.scans.import_scan(file_uploaded_nessus, folder_id=None,
                                                         password=export_import_password)

            assert import_scan['scan']['id'], "Scan does not imported successfully in nessus"

            scan_id = import_scan['scan']['id']
            click_on_scan_and_go_to_vulnerabilities_tab(scan_name=import_scan['scan']['name'])

            assert ScanViewPage().is_element_present("cvss_score_column"), \
                "CVSS score column is not present in imported scan after exporting in '{}' format.".format(
                    export_format)
        finally:
            self.cat.api.scans.delete(scan_id=scan_id)


@pytest.mark.scans_2
@pytest.mark.nessus_expert
@pytest.mark.usefixtures('nessus_api_login', 'login')
class TestImportNonStandardScans:
    """ Test Import of Scans that are not the System set of scans, like ASD"""

    cat = None

    @pytest.mark.xray(test_key='NES-16772')
    @pytest.mark.parametrize('export_format', [
        API.Scan.ExportFormats.FORMAT_NESSUS,
        API.Scan.ExportFormats.FORMAT_DB,
    ])
    def test_asd_import(self, export_format):
        """
        NES-16772 - Validate importing of an ASD scan


        Steps:
        1. Login to Nessus.
        2. Create and Launch an ASD scan
        3. Export the Scan when completed
        4. Import the scan
        5. Validate the data was imported through the UI
        """

        from nessus.tests.api.scan.test_asd_scans import AsdHelper
        scan_id = None
        asd_helper = AsdHelper(api=self.cat.api)
        try:
            # Creating the payload, the scan, and then launching the scan and waiting till it is finished
            payload = asd_helper.get_asd_payload()
            scan_id = asd_helper.create_and_launch(payload=payload)
            password = "nessus" if export_format == API.Scan.ExportFormats.FORMAT_DB else None

            file_name = asd_helper.export_and_download_to_file(
                scan_id=scan_id,
                export_format=export_format,
                password=password
            )
            assert file_name, "Exporting and downloading to a file did not return a filename to us."
            self.cat.api.scans.delete(scan_id=scan_id)  # deleting it so we do not have duplicate entries after import

            file_name = f'{file_name}.{export_format}'
            imported_scan = asd_helper.import_asd_scan(file_name=file_name, password=password)
            imported_scan_id = imported_scan['scan']['id']
            scan_id = imported_scan_id

            click_on_scan_and_go_to_hosts_tab(scan_name=imported_scan['scan']['name'])
            assert len(
                ScansHostList().results) > 0, f"Something went wrong, could not find any results for the Records page"
        finally:
            self.cat.api.scans.delete(scan_id=scan_id)
