""""
Nessus test cases related to Scan results page of created scan

:copyright: Tenable Network Security, 2017
:date: April 03, 2018
:last_modified: May 23, 2024
:author: @rdutta, @dkothari, @kpanchal, @krpatel
"""
# pylint: disable=undefined-variable
import csv
import os
import time
from datetime import datetime, timedelta

import pytest
import pytz
from selenium.webdriver import ChromeOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.support.expected_conditions import visibility_of_element_located
from waiting import TimeoutExpired

from catium.helpers.sleep_lib import sleep
from catium.helpers.testdata import get_file_path, load_testdata
from catium.helpers.util import get_browser_download_file_path
from catium.lib.config import Config
from catium.lib.const import HTTPStatus
from catium.lib.const.base_constants import WAIT_SHORT, WAIT_NORMAL, TIME_THREE_SECONDS, TIME_TEN_SECONDS, \
    TIME_THIRTY_MINUTES, TIME_FIFTEEN_SECONDS, TIME_THIRTY_SECONDS, TIME_TEN_MINUTES, GRID_BROWSER_DOWNLOAD_PATH, \
    TIME_SIXTY_SECONDS, TIME_FIVE_MINUTES, TIME_THREE_MINUTES, WAIT_LONG
from catium.lib.log import create_logger
from catium.lib.util import random_name
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from catium.lib.webium.windows_handler import WindowsHandler
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.advanced_settings import get_color_code_of_ui_element
from nessus.helpers.nessus_ui.settings import modify_existing_advanced_setting
from nessus.helpers.policy import create_policy_helper
from nessus.helpers.polling_ui import polling_ui
from nessus.helpers.scan import get_scan_id, launch_scan_and_go_to_debugging_log_report_vuln, \
    download_and_save_exported_scan_file
from nessus.helpers.scan import get_scan_results_export_options, \
    click_on_scan_and_go_to_vulnerabilities_tab, create_scan_helper
from nessus.helpers.sort import sort_on_column_values
from nessus.helpers.utility import get_downloaded_files_chrome
from nessus.helpers.waiters import wait_scan_state
from nessus.lib.config import NessusConfig
from nessus.lib.const.constants import Nessus, API, SortOrder
from nessus.lib.message.messages import Messages
from nessus.models.scan import ScanModel
from nessus.pageobjects.advanced_settings.advanced_settings_page import AdvancedSettingsPage, AdvancedSettingsList, \
    AddAdvancedSettingModal
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications, close_pendo_guide_container_banner_for_nessus_pro
from nessus.pageobjects.plugins.plugins_page import Plugin, PluginFamilyList
from nessus.pageobjects.scans.new_scan_form import NewScanForm
from nessus.pageobjects.scans.scan_basic_settings_page import AssessmentSetting
from nessus.pageobjects.scans.scan_view_page import ScanViewPage, ScanHistoryList, VulnerabilityList, \
    ModifyVulnerability, ScanExportPage, ThreatLevelVulnerabilityList, VulnerabilityDescription
from nessus.pageobjects.scans.scan_view_page import ScansHostList
from nessus.pageobjects.scans.scans_page import ScansPage, ScanList
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav

log = create_logger()
timestamped_path = 'exported_scan_' + str(int(time.time()))  # use timestamp to differentiate test


@pytest.fixture()
def chrome_options():
    """Set download path for Chrome."""
    options = ChromeOptions()

    if Config.CAT_USE_GRID:
        directory = os.path.join(GRID_BROWSER_DOWNLOAD_PATH, timestamped_path)
    else:
        directory = os.path.join(Config.CAT_LOCAL_BROWSER_DOWNLOAD_PATH, timestamped_path)

    prefs = {'download.default_directory': directory}
    options.add_experimental_option('prefs', prefs)
    return options


def search_for_debugging_log_report_vuln_and_verify_list_view(scan_target: str, scan_format: str = None) -> None:
    """
    Search for "Debugging Log Report" vulnerability and verifies list view

    :param str scan_target: host that used into created scan as scan target
    :param str scan_format: imported scan format like nessus/db.
    :return: None
    """
    vuln_name = Nessus.Scan.Vulnerability.DEBUGGING_LOG_REPORT
    ScanViewPage().search_box.value = vuln_name
    sleep(WAIT_NORMAL, reason="waiting for matching vulnerability results")

    VulnerabilityList().click_on_vulnerability(vulnerability_name=vuln_name)
    vuln_desc = VulnerabilityDescription()
    wait(lambda: vuln_desc.is_element_present("plugin_header"), waiting_for="vulnerability details get displayed")

    if scan_format is not None and scan_format == API.Scan.ExportFormats.FORMAT_NESSUS:
        assert not vuln_desc.is_element_present("plugin_output_table"), \
            "Plugin debug log(s) table is getting visible for imported '{}' scan format which should not be.".format(
                scan_format)
    else:
        assert all([vuln_desc.is_element_present("plugin_output_table"), len(vuln_desc.debug_log_hosts_row) > 0]), \
            "Plugin debug log(s) does not appear in list/table view."

        expected_columns = [Nessus.Scan.Vulnerability.PLUGIN_OUTPUT_HOSTS, Nessus.Scan.Vulnerability.PLUGIN_OUTPUT_PORT]

        assert all([column.text.strip() in expected_columns for column in vuln_desc.plugin_output_header_columns]), \
            "Getting incorrect columns in Plugin debug log(s) output table."

        plugin_debug_log_row = vuln_desc.debug_log_hosts_row[0]
        debug_log_hosts_columns = plugin_debug_log_row.find_elements(By.TAG_NAME, "td")
        file_icon = debug_log_hosts_columns[1].find_element(By.TAG_NAME, "i")

        assert all([debug_log_hosts_columns[0].text == scan_target, len(debug_log_hosts_columns[1].text) > 0,
                    visibility_of_element_located(file_icon), len(debug_log_hosts_columns[2].text) > 0,
                    "down-arrow" in debug_log_hosts_columns[3].get_attribute('class')]), \
            "Hosts columns are either missing or mismatched under Plugin debug log(s) output table."


def verify_plugin_debugging_log_output_table(scan_name: str, scan_target: str, go_from_host: bool = False,
                                             scan_format: str = None) -> None:
    """
    Verifies "Plugin debug log(s)" output table under "Debugging Log Report" vulnerability

    :param str scan_name: name of created scan
    :param str scan_target: host that used into created scan as scan target
    :param bool go_from_host: True if wanna go from clicking on host under "Host" tab else False
    :param str scan_format: imported scan format like nessus/db
    :return: None
    """
    scan_page = ScansPage()
    scan_page.refresh()
    wait(lambda: scan_page.is_element_present("scan_searchbox"), waiting_for="scan list gets loaded")
    ScanList().click_on_scan(scan_name=scan_name)

    scan_view_page = ScanViewPage()
    wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
         waiting_for='Vulnerabilities to load')

    if go_from_host:
        scan_view_page.host_tab.click()
        wait(lambda: scan_view_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

        scan_host_list = ScansHostList()
        scan_host_list.click_on_host(scan_host_list.get_host_names()[0])
    else:
        scan_view_page.vulnerability_tab.click()

    wait(lambda: visibility_of_element_located(scan_view_page.search_icon),
         waiting_for="Host Details Page to load", timeout_seconds=WAIT_NORMAL)

    search_for_debugging_log_report_vuln_and_verify_list_view(scan_target=scan_target, scan_format=scan_format)


@pytest.mark.scanning
@pytest.mark.nessus_home
@pytest.mark.nessus_pro
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login', 'login')
class TestCreatedScanResults:
    """
    Covers Scan details page related test cases in Scans page.
    # NQA-1069 : Automation tests for Scans - Results.
    Sub-part: All tests with created scan.
    Pre-requisite: There should be a successfully completed scan exist.
    # NES-8931 : Fix scans related skipped test cases
    """

    cat = None
    scan_file_path = get_file_path('nessus/tests/api/scan/test_data/test_scan_with_packet_capture.json')

    @staticmethod
    def configure_and_launch_scan(scan_name: str, alt_targets: list = None, add_configuration: bool = False,
                                  plugin_families_to_scan: list = ['Settings'], relaunch_count: int = 1,
                                  navigate_to_scan_result: bool = True) -> dict:
        """
        1. Launch the scan through api and wait for its completion.
        2. Navigated to the 'My Scans' folder where created scan listed after completion of its run
        3. Click on the scan to view scan_results_page
        :param str scan_name: name of created scan
        :param list alt_targets: If specified, these targets will be scanned instead of the default
        :param bool add_configuration: True if further configurations need to be added
        :param list plugin_families_to_scan: list of plugin families to enable for scan
        :param int relaunch_count: count to relaunch the scan
        :param bool navigate_to_scan_result: True if you want to navigate to scan result page after scan completion
        :return: scan_details
        :rtype: dict
        """
        scan_details = None
        # Add scan configurations if required
        if add_configuration:
            plugins_page = Plugin()
            LoadingCircle(TIME_THREE_SECONDS)
            plugins_page.disable_all.click()
            PluginFamilyList().toggle_plugin_family(plugin_family_list=plugin_families_to_scan)
            plugins_page.save_button.click()

        LoadingCircle(WAIT_NORMAL)
        scan_id = get_scan_id(api_object=__class__.cat.api, scan_name=scan_name)
        scan_completed_status = False

        # Launch the scan through api and wait for its completion.
        for _ in range(relaunch_count):
            LoadingCircle(WAIT_NORMAL)
            __class__.cat.api.scans.launch(scan_id=scan_id, alt_targets=alt_targets)
            if __class__.cat.api.http_status_code == HTTPStatus.OK:
                with polling_ui():
                    scan_completed_status = wait_scan_state(api=__class__.cat.api, end_state=API.Scan.Status.COMPLETED,
                                                            scan_id=scan_id, timeout=(TIME_TEN_MINUTES * 2))
                    scan_details = __class__.cat.api.scans.details(scan_id)
            else:
                log.debug('Expected 200, got %s instead.' % __class__.cat.api.http_status_code)

        # Click on the scan to view scan_results_page if scan is completed
        if scan_completed_status:
            ScansPage().refresh()
            scan_list = ScanList()
            scan_list.loaded()

            if navigate_to_scan_result:
                scan_list.click_on_scan(scan_name=scan_name)
            return scan_details
        else:
            # Skipping the test if scan took more than 20 minutes to be in completed state
            pytest.xfail(
                reason="Scan running for more than 20 minutes and still not completed, hence no scan result found.")
            __class__.cat.api.scans.stop(scan_id)
            wait_scan_state(api=__class__.cat.api, end_state=API.Scan.Status.CANCELED, scan_id=scan_id,
                            timeout=TIME_FIFTEEN_SECONDS)

    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'folder': Nessus.Scan.Folder.MY_SCANS.split(' (')[0], 'target_ip': 'localhost',
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         'keep_original_scan_name': True, 'add_configuration': True}]}], indirect=True)
    @pytest.mark.nessus_expert
    def test_visibility_of_history_tab_and_launch_dropdown(self, create_scans):
        """
        Verify “Launch” button drop-down and “History” tab is present.
        1. Create a scan and Click on the scan to view the results page.
        2. Verify “Launch” button drop-down available in header.
        3. Click on it and verify its sub-options as 'Custom/Default'
        4. Also verify the presence of “History” tab.
        """
        self.__class__.configure_and_launch_scan(scan_name=create_scans[0], add_configuration=True)

        scan_details_page = ScanViewPage()
        wait(lambda: visibility_of_element_located(scan_details_page.history_tab), waiting_for='scan results to load')

        assert all([scan_details_page.is_element_present('history_tab'),
                    scan_details_page.is_element_present('launch_dropdown')]), \
            "'History' tab and 'Launch' drop-down are invisible."

        close_pendo_guide_container_banner_for_nessus_pro()
        scan_details_page.host_tab.click()
        wait(lambda: scan_details_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

        ScansHostList().select_hosts(hosts_list=['localhost'])
        LoadingCircle(TIME_THREE_SECONDS)

        scan_details_page.launch_dropdown.click()
        LoadingCircle(WAIT_SHORT)

        assert all([scan_details_page.default_launch_option.is_displayed(),
                    scan_details_page.selected_launch_option.is_displayed(),
                    scan_details_page.custom_launch_option.is_displayed()]), \
            "'Custom/Selected/Default' sub-option under Launch dropdown are invisible."

        scan_details_page.back_link.click()

    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'folder': Nessus.Scan.Folder.MY_SCANS.split(' (')[0], 'target_ip': Nessus.Scan.Target.LOCALHOST,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         'keep_original_scan_name': True, 'add_configuration': True}]}], indirect=True)
    @pytest.mark.nessus_expert
    def test_scan_details_section(self, create_scans):
        """
        Verify scan details section in middle right portion of scan_result page.
        1. Click on the scan to view the results page.
        2. Verify “Scan Details” section is visible in the middle right portion of the page.
        3. Verify the section contains some value for these (“Name”/ “Status”/ “Policy”/ “Start”) parameters.
        """
        scan_details = self.__class__.configure_and_launch_scan(scan_name=create_scans[0], add_configuration=True)
        scan_start_time = "Today {}".format(time.strftime('at %-I:%M %p', time.strptime(str(datetime.utcfromtimestamp(
            scan_details.get('info').get('scan_start'))), "%Y-%m-%d %H:%M:%S")))
        scan_end_time = "Today {}".format(time.strftime('at %-I:%M %p', time.strptime(str(datetime.utcfromtimestamp(
            scan_details.get('info').get('scan_end'))), "%Y-%m-%d %H:%M:%S")))

        scan_result_page = ScanViewPage()
        wait(lambda: scan_result_page.is_element_present('vulnerability_tab'), waiting_for='scan results to load')

        scan_result_page.host_tab.click()
        wait(lambda: scan_result_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

        assert Nessus.Scan.Results.RightColumnHeader.SCAN_DETAILS == scan_result_page.right_column_header.text, \
            "Scan Details header is mismatch or not found in right column of scan result page."

        mapping_element_value = {Nessus.Scan.Results.ScanDetailsLevels.SCAN_STATUS: API.Scan.Status.COMPLETED.title(),
                                 Nessus.Scan.Results.ScanDetailsLevels.SCAN_POLICY: Nessus.TemplateNames.ADVANCED,
                                 Nessus.Scan.Results.ScanDetailsLevels.SCAN_START_TIME: scan_start_time,
                                 Nessus.Scan.Results.ScanDetailsLevels.SCAN_END_TIME: scan_end_time}

        for level in Nessus.Scan.Results.ScanDetailsLevels.DEFAULT_LEVELS:
            mapped_element_value = mapping_element_value[level]

            assert mapped_element_value == scan_result_page.get_levels_value_of_details_section(level).text, \
                "Level value is mismatched or not found according to level param."

        scan_result_page.back_link.click()

    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'folder': Nessus.Scan.Folder.MY_SCANS.split(' (')[0], 'target_ip': Nessus.Scan.Target.LOCALHOST,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         'keep_original_scan_name': True, 'add_configuration': True}]}], indirect=True)
    @pytest.mark.nessus_expert
    def test_associated_tag_and_elements_of_running_scan(self, create_scans):
        """
        Verify visibility of "current" tag and other elements in scan_result page of a running scan.
        1. Click on the scan to view the results page.
        2. Verify “Export”/ “Audit Trail”/ “Launch” button is visible.
        3. Click on “Launch” button and select “Default/Custom” option to relaunch the scan.
        4. Wait until it’s in “running” state.
        5. Verify “Export”/ “Audit Trail”/ “Launch” button is invisible now.
        6. Go to “History” tab and verify the current scan is listed with a prefix tag “Current” and
            the checkbox is inaccessible against it.
        7. Wait still the scan get completed.
        8. Verify “Export”/ “Audit Trail”/ “Launch” button is visible now.
        """
        scan_name = create_scans[0]
        self.__class__.configure_and_launch_scan(scan_name=scan_name, add_configuration=True,
                                                 plugin_families_to_scan=['General', 'Settings'])

        scan_result_page = ScanViewPage()
        wait(lambda: scan_result_page.is_element_present('vulnerability_tab'), waiting_for='scan results to load')

        assert all([scan_result_page.is_element_present('configure_button'),
                    scan_result_page.is_element_present('audit_trail_button'),
                    scan_result_page.is_element_present('launch_dropdown'),
                    scan_result_page.is_element_present('export_button')]), \
            "Default elements are invisible in scan_result page."

        scan_result_page.launch_scan(launch_type=Nessus.Scan.Results.LaunchTypes.DEFAULT)
        history_list = ScanHistoryList()
        wait(lambda: (history_list.rows[0].scan_status == API.Scan.Status.RUNNING.title()),
             waiting_for='Scan to be in running state', timeout_seconds=WAIT_NORMAL)

        if history_list.rows[0].scan_status == API.Scan.Status.RUNNING.title():
            assert all([scan_result_page.is_element_present('configure_button'),
                        (not scan_result_page.is_element_present('audit_trail_button')),
                        (not scan_result_page.is_element_present('launch_dropdown')),
                        (not scan_result_page.is_element_present('export_button')),
                        (history_list.rows[0].scan_start_time.startswith(Nessus.Scan.Results.CURRENT_TAG)),
                        (all([scan.disabled_checkbox.get_attribute('aria-disabled') == 'true'
                              for scan in history_list.rows]))]), \
                "'Current' prefix tag of running scan is mismatched or not found/"
        else:
            pytest.xfail(
                reason="Scan might gets completed or not started yet. Test can be done only with running scan.")

        with polling_ui():
            scan_completed = wait_scan_state(api=__class__.cat.api,
                                             scan_id=get_scan_id(api_object=__class__.cat.api, scan_name=scan_name),
                                             end_state=API.Scan.Status.COMPLETED, timeout=TIME_THIRTY_MINUTES)

        scan_result_page.refresh()
        wait(lambda: history_list.rows[0].scan_status == API.Scan.Status.COMPLETED.title(),
             waiting_for='Scan to get completed on UI.', timeout_seconds=TIME_FIVE_MINUTES,
             sleep_seconds=WAIT_NORMAL)
        wait(lambda: scan_result_page.is_element_present('export_button'), waiting_for='element to be visible')

        if scan_completed:
            assert all([scan_result_page.is_element_present('configure_button'),
                        scan_result_page.is_element_present('audit_trail_button'),
                        scan_result_page.is_element_present('launch_dropdown'),
                        scan_result_page.is_element_present('export_button'),
                        (all([scan.checkbox.is_displayed() for scan in history_list.rows]))]), \
                "Default elements are invisible in scan_result page after scan completion."

        scan_result_page.back_link.click()

    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.HOST_DISCOVERY, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "folder": Nessus.Scan.Folder.MY_SCANS.split(' (')[0], "target_ip": Nessus.Scan.Target.LOCALHOST,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.HOST_DISCOVERY))}]}], indirect=True)
    @pytest.mark.nessus_expert
    def test_records_count_visible_next_to_searchbox_in_history_tab(self, create_scans):
        """
        Test to match records count visible next to search box in "History" tab of scans_result page with list count.
        1. Navigate to "History" tab.
        2. Get the count of record list and verify it is same with the count visible next to search box in the page.
        3. Put some search string in search box and repeat step 2.
        4. Check some of filtered records from list and repeat step 2.
        """
        selected_records = 0
        scan_name = create_scans[0]
        self.__class__.configure_and_launch_scan(scan_name=scan_name, relaunch_count=3)

        scan_result_page = ScanViewPage()
        wait(lambda: scan_result_page.is_element_present('history_tab'), waiting_for='scan results to load')
        scan_result_page.history_tab.click()
        history_list = ScanHistoryList()
        assert scan_result_page.total_records_count == len(history_list.rows), \
            "Visible total records count is mismatched with total record list count."

        LoadingCircle(WAIT_SHORT)
        scan_result_page.apply_search(search_string="Today")
        LoadingCircle(TIME_THREE_SECONDS)
        assert scan_result_page.filtered_records_count == len(history_list.rows), \
            "Visible searched records count is mismatched with record list count after searching."

        history_list.rows[0].checkbox.check()
        selected_records += 1
        LoadingCircle(WAIT_SHORT)
        assert scan_result_page.selected_records_count == selected_records, \
            "Visible selected records count is mismatched with selected record count in list."

        scan_result_page.back_link.click()
        LoadingCircle(TIME_THREE_SECONDS)

    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.HOST_DISCOVERY, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "folder": Nessus.Scan.Folder.MY_SCANS.split(' (')[0], "target_ip": Nessus.Scan.Target.LOCALHOST,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.HOST_DISCOVERY))}]}], indirect=True)
    @pytest.mark.nessus_expert
    def test_clear_selected_items_link_for_history_tab(self, create_scans):
        """
        Verify “Clear Selected Items” link for "History" tab in scan_result page.
        1. Click on the scan to view the results page.
        2. Navigate to "History" tab.
        3. Verify “Clear Selected Items” link should be invisible.
        4. Select (Checked the checkbox) some records among them.
        5. Link “Clear Selected Items” should be visible now, click on the link.
        6. Verify checked records become Unchecked.
        """
        scan_name = create_scans[0]
        self.__class__.configure_and_launch_scan(scan_name=scan_name, relaunch_count=3)

        scan_result_page = ScanViewPage()
        wait(lambda: scan_result_page.is_element_present('history_tab'), waiting_for='scan results to load')
        scan_result_page.history_tab.click()
        history_list = ScanHistoryList()
        assert not scan_result_page.is_element_present('clear_selected_item_link'), \
            "'clear_selected_item' link is visible."

        history_list.rows[0].checkbox.check()
        LoadingCircle(WAIT_SHORT)
        assert scan_result_page.is_element_present('clear_selected_item_link'), \
            "'clear_selected_item' link is invisible."

        scan_result_page.clear_selected_item_link.click()
        assert not history_list.rows[0].checkbox.is_selected(), "Selected record(s) are not unchecked yet."

        scan_result_page.back_link.click()
        ScanList().loaded()

    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.HOST_DISCOVERY, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "folder": Nessus.Scan.Folder.MY_SCANS.split(' (')[0], "target_ip": Nessus.Scan.Target.LOCALHOST,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.HOST_DISCOVERY))}]}], indirect=True)
    @pytest.mark.nessus_expert
    def test_search_history_list(self, create_scans):
        """
        Search and verify search string is found in searched list of "History" tab in scan_result page.
        1. Click on the scan to view the results page and navigate to any of the above tab.
        2. Verify “search_icon” is visible in the search box.
        3. Enter some search string.
        4. Verify “search_icon” is invisible and “remove_search” icon is visible.
        5. Verify the filtered list contains your search string.
        6. Click the “remove_search” icon.
        7. Verify “remove_search” is invisible and “search_icon” icon is visible.
        """
        search_strings = [((datetime.now() - timedelta(seconds=100)).strftime('%I:%M')[1:]), "Current", "today"]
        scan_name = create_scans[0]

        self.__class__.configure_and_launch_scan(scan_name=scan_name, relaunch_count=3)
        scan_result_page = ScanViewPage()
        wait(lambda: scan_result_page.is_element_present('history_tab'), waiting_for='scan results to load')
        scan_result_page.history_tab.click()

        history_list = ScanHistoryList()
        history_count_before_search = len(history_list.rows)

        assert all([scan_result_page.search_box.is_displayed(),
                    scan_result_page.search_icon.is_displayed()]), "Search box with search icon is invisible."

        for string_name in search_strings:
            scan_result_page.apply_search(search_string=string_name)
            LoadingCircle(WAIT_SHORT)
            assert all([(not scan_result_page.search_icon.is_displayed()),
                        scan_result_page.clear_search_icon.is_displayed()]), \
                "Search_icon is visible and clear_search_icon is invisible."

            assert scan_result_page.filtered_records_count == len(history_list.get_all_histories()), \
                "Visible searched records count is mismatched with record list count after searching."

            assert scan_result_page.verify_search_result(search_string=string_name, records_list_object=history_list), \
                "Search failed with provided search string."

            scan_result_page.clear_search_icon.click()
            LoadingCircle(TIME_THREE_SECONDS)
            assert all([(history_count_before_search == len(history_list.rows)),
                        (not scan_result_page.clear_search_icon.is_displayed()),
                        scan_result_page.search_icon.is_displayed()]), \
                "Search_icon is invisible or clear_search_icon is visible or all data not loaded after removing search."

        assert history_count_before_search == len(history_list.rows), \
            "Data count mismatched, all data not loaded after clearing search box."

    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.HOST_DISCOVERY, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "folder": Nessus.Scan.Folder.MY_SCANS.split(' (')[0], "target_ip": Nessus.Scan.Target.LOCALHOST,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.HOST_DISCOVERY))}]}], indirect=True)
    @pytest.mark.parametrize('sort', SortOrder.VALID_ORDERS)
    @pytest.mark.parametrize('column_to_sort', ['Start Time', 'Last Scanned'])
    @pytest.mark.nessus_expert
    def test_sort_history_list_on_column_values(self, create_scans, sort, column_to_sort):
        """
        Verify list sorting on column values of "History" tab in scan_result page.
        1. Click on the scan to view the results page and navigate to “History” tab.
        2. Click on the "Sort" icon (ascending/descending) against any column from the list.
        3. Verify list is sorted according to the order you choose above.
        """
        scan_name = create_scans[0]
        column_mapping = {'Start Time': 'scan_start_epoch_time', 'Last Scanned': 'scan_end_epoch_time'}
        self.__class__.configure_and_launch_scan(scan_name=scan_name, relaunch_count=3)

        scan_result_page = ScanViewPage()
        wait(lambda: scan_result_page.is_element_present('history_tab'), waiting_for='scan results to load')
        scan_result_page.history_tab.click()

        history_list = ScanHistoryList()
        map_attribute = column_mapping[column_to_sort]
        expected_sorted_history_list = sorted([getattr(history, map_attribute) for history in history_list.rows],
                                              key=lambda k: time.localtime(int(k)),
                                              reverse=(sort == SortOrder.DESCENDING))

        LoadingCircle(TIME_THREE_SECONDS)
        rendered_history_list = sort_on_column_values(page_class_instance=history_list, sort=sort,
                                                      column_name=column_to_sort)

        rendered_sorted_history_list = [getattr(history, map_attribute) for history in rendered_history_list]
        assert expected_sorted_history_list == rendered_sorted_history_list, \
            "{} is not sorted in {} order".format(column_to_sort, sort)

        scan_result_page.back_link.click()
        LoadingCircle(WAIT_NORMAL)

    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,

         'folder': Nessus.Scan.Folder.MY_SCANS.split(' (')[0], 'target_ip': Nessus.Scan.Target.PUB_TARGET_1,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED))}]}], indirect=True)
    @pytest.mark.parametrize('relaunch_type', [
        pytest.param(Nessus.Scan.Results.LaunchTypes.DEFAULT, marks=pytest.mark.nessus_legacy),
        pytest.param(Nessus.Scan.Results.LaunchTypes.CUSTOM, marks=pytest.mark.nessus_legacy),
        Nessus.Scan.Results.LaunchTypes.SELECTED])
    @pytest.mark.nessus_expert
    def test_launch_created_scan(self, create_scans, relaunch_type):
        """
        Test to re-launched a scan with default configurations in scan_result page.
        1. Create a scan with default value.
        2. Click on the scan to view the results page.
        3. Click on “Launch” button and select “Default” option.
        4. Navigate to “Hosts” tab and verify the real time update on hosts against vulnerabilities count.
        5. Also verify hosts are listed there as per type selection.
        6. Repeat above steps for "Custom" and "Selected" options
        """
        scan_name = create_scans[0]

        scan_target_mapping = {
            Nessus.Scan.Results.LaunchTypes.DEFAULT: "{}".format(Nessus.Scan.Target.PUB_TARGET_1),
            Nessus.Scan.Results.LaunchTypes.CUSTOM: "{}, {}, {}".format(
                Nessus.Scan.Target.PUB_TARGET_1, Nessus.Scan.Target.PUB_TARGET_3, Nessus.Scan.Target.PUB_TARGET_4),
            Nessus.Scan.Results.LaunchTypes.SELECTED: "{}, {}".format(
                Nessus.Scan.Target.PUB_TARGET_1, Nessus.Scan.Target.PUB_TARGET_4)}

        self.__class__.configure_and_launch_scan(scan_name=scan_name, alt_targets=[
            Nessus.Scan.Target.PUB_TARGET_1, Nessus.Scan.Target.PUB_TARGET_3, Nessus.Scan.Target.PUB_TARGET_4])

        scan_id = get_scan_id(api_object=__class__.cat.api, scan_name=scan_name)

        scan_result_page = ScanViewPage()
        wait(lambda: scan_result_page.is_element_present('vulnerability_tab'), waiting_for='scan results to load')

        scan_result_page.launch_scan(launch_type=relaunch_type, scan_targets=scan_target_mapping.get(relaunch_type))
        wait(lambda: (self.cat.api.scans.get_status(scan_id=scan_id) == API.Scan.Status.RUNNING),
             waiting_for='Scan to be in running state', timeout_seconds=TIME_FIFTEEN_SECONDS)

        scan_result_page.host_tab.click()
        wait(lambda: scan_result_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")
        host_list = ScansHostList()

        input_list = scan_target_mapping.get(relaunch_type).split(', ')
        wait(lambda: host_list.get_total_rows() == len(input_list), sleep_seconds=WAIT_NORMAL,
             timeout_seconds=TIME_THREE_MINUTES, waiting_for="host list to be visible")

        def all_hosts_shown():
            return len(host_list.get_hosts_percentage().keys()) == len(input_list)

        wait(all_hosts_shown, waiting_for='All target host listed in host list.', sleep_seconds=WAIT_LONG,
             timeout_seconds=TIME_THREE_MINUTES)

        def all_hosts_progressed():
            return all([host_progress > 0 for host_progress in host_list.get_hosts_percentage().values()])

        wait(all_hosts_progressed, waiting_for='All hosts to show progress.', sleep_seconds=WAIT_LONG,
             timeout_seconds=TIME_THREE_MINUTES)

        current_scan_progress = host_list.get_hosts_percentage()
        log.debug("Progress percentage against host: %s", current_scan_progress)

        verified_hosts = []
        for host, progress in current_scan_progress.items():
            if progress > 0:
                verified_hosts.append(host)

        assert set(input_list) == set(verified_hosts), \
            "Failed to launch scan on {} hosts, " \
            "Scanned host list and current host list mismatched.".format(relaunch_type)

        scan_result_page.back_link.click()

        if self.cat.api.scans.get_status(scan_id=scan_id) == API.Scan.Status.RUNNING:
            self.cat.api.scans.stop(scan_id=scan_id)

        wait(lambda: (self.cat.api.scans.get_status(scan_id=scan_id) in [API.Scan.Status.CANCELED,
                                                                         API.Scan.Status.COMPLETED]),
             waiting_for="Delete icon to be visible after stop/completion of scan", timeout_seconds=TIME_THIRTY_SECONDS)

    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.HOST_DISCOVERY, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'folder': Nessus.Scan.Folder.MY_SCANS.split(' (')[0], 'target_ip': Nessus.Scan.Target.LOCALHOST,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.HOST_DISCOVERY))}]}], indirect=True)
    @pytest.mark.nessus_expert
    def test_delete_history_through_x_icon(self, create_scans):
        """
        Test to delete a single history from “History” tab.
        1. Click on the scan to view the results page.
        2. Navigate to “History” tab, click “X” icon against your desired history from the list.
        3. Click on “Delete” button on confirmation pop-up.
        4. History should delete with a success notification as “Result deleted successfully.”
        5. History should not listed in the list of the “History” tab anymore.
        """
        self.__class__.configure_and_launch_scan(scan_name=create_scans[0])

        scan_result_page = ScanViewPage()
        wait(lambda: scan_result_page.is_element_present('history_tab'), waiting_for='scan results to load')
        scan_result_page.history_tab.click()

        history_list = ScanHistoryList()
        start_time = history_list.rows[0].start_time
        end_time = history_list.rows[0].end_time

        history_list.delete_history(start_time=start_time, end_time=end_time)
        LoadingCircle(TIME_TEN_SECONDS)
        assert (start_time and end_time) not in history_list.get_all_histories(), \
            "Deletion failed: a row with start-time: {} and end-time: {}, " \
            "still exists in history_list.".format(start_time, end_time)

        scan_result_page.back_link.click()

    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.HOST_DISCOVERY, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'folder': Nessus.Scan.Folder.MY_SCANS.split(' (')[0], 'target_ip': Nessus.Scan.Target.LOCALHOST,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.HOST_DISCOVERY))}]}], indirect=True)
    @pytest.mark.nessus_expert
    def test_delete_multiple_histories(self, create_scans):
        """
        Test to delete multiple history from “History” tab.
        1. Click on the scan to view the results page.
        2. Navigate to “History” tab, and verify “Delete” button is invisible in header.
        3. Select (checked the corresponding checkbox) more than one record from list of history and
            verify “Delete” button is visible now in the header and click on it.
        4. Click on “Delete” button on confirmation pop-up.
        5. History should delete with a success notification as “Results deleted successfully.”
        6. Records should not listed in the list of the “History” tab anymore.
        """
        selected_history = []
        scan_name = create_scans[0]
        self.__class__.configure_and_launch_scan(scan_name=scan_name, relaunch_count=4)

        scan_result_page = ScanViewPage()
        wait(lambda: scan_result_page.is_element_present('history_tab'), waiting_for='scan results to load')
        scan_result_page.history_tab.click()

        assert not scan_result_page.is_element_present('delete_history'), "Delete button is visible."

        history_list = ScanHistoryList()
        for row, history in enumerate(history_list.rows, start=1):
            if row % 4 != 0:
                history.checkbox.check()
                selected_history.append((history.scan_start_time, history.scan_end_time))

        assert scan_result_page.is_element_present('delete_history'), "Delete button is invisible."

        scan_result_page.delete_history.click()
        ActionCloseModal().accept_action()
        assert Notifications().successes[-1] == Messages.NotificationMessages.ScanResults.history_deleted, \
            "Success notifications for history deletion is mismatched or missing."

        LoadingCircle(WAIT_NORMAL)
        current_history_list = history_list.get_all_histories()
        assert all([history not in current_history_list for history in selected_history]), \
            "Deletion failed: Histories still exists in history_list."

        scan_result_page.back_link.click()
        LoadingCircle(WAIT_NORMAL)

    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'folder': Nessus.Scan.Folder.MY_SCANS.split(' (')[0], 'target_ip': 'localhost',
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED))}]}], indirect=True)
    @pytest.mark.parametrize('enable_group', [True, False])
    def test_modify_vulnerability_of_created_scan_results(self, create_scans, enable_group):
        """
        NES-9783: UI Automation: Scan | Verify that user should be able to modify vulnerabilities like eg. change
                  severity of vulnerability

        Steps:
        1. Login with a valid credential in NM/NP
        2. Create one scan and launch it.
        3. After completed successfully, open scan and go to vulnerabilities tab.
        4. Go to modify option for any vulnerabilities
        5. Change the severity of vulnerabilities

        Scenario Tested:
        [x] Verify that user should be able to modify(severity of vulnerabilities)any of vulnerabilities
        """
        scan_list = ScanList()

        # Launching created scan and waiting to be completed
        assert scan_list.launch_scan_and_wait_for_status(create_scans[0]), "launch of created scan wasn't successful"

        # Click on scan and go to vulnerability tab
        scan_list.click_on_scan(create_scans[0])
        scan_view_page = ScanViewPage()

        wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
             waiting_for='Vulnerabilities to load')
        scan_view_page.vulnerability_tab.click()

        # Enable/Disable vulnerability group
        vulnerability_list = VulnerabilityList()
        vulnerability_list.vulnerability_setting.click()
        vulnerability_list.click_on_group_enable_disable(enable=enable_group)

        vulnerability_list.refresh()
        wait(lambda: visibility_of_element_located(vulnerability_list.vulnerability_setting),
             waiting_for='vulnerability list to populate')

        # Get plugin name and it's severity before modify
        plugin_name = vulnerability_list.get_plugin_names()[1]
        severity_before_modify = vulnerability_list.get_severity_against_plugin(plugin_name)[0]

        # Modify plugin severity
        severity_levels = Nessus.Scan.Severity.SEVERITY_LEVELS
        severity_levels.append(Nessus.Scan.Severity.MIXED)
        severity_value = [severity_level for severity_level in severity_levels if severity_level !=
                          severity_before_modify.capitalize()][0]

        ModifyVulnerability().modify_vulnerability(severity=severity_value, vulnerabilities_list=[plugin_name])
        notification = Notifications()

        if enable_group:
            assert notification.successes[-1] == Messages.NotificationMessages.ScanResults. \
                vulnerabilities_modified, 'Notification for modifying vulnerabilities is incorrect or did not appear.'
        else:
            assert notification.successes[-1] == Messages.NotificationMessages.ScanResults. \
                vulnerability_modified, 'Notification for modifying vulnerability is incorrect or did not appear.'

        severity_after_modify = vulnerability_list.get_severity_against_plugin(plugin_name)[0]

        # Verify plugin severity value after modify
        assert all([severity_before_modify != severity_after_modify, severity_after_modify ==
                    severity_value.upper()]), "Modification of severity wasn't successful."

        if enable_group:
            # Verify plugin severity value of vulnerability group after modifying
            assert vulnerability_list.check_severity_against_plugin(
                severity=severity_value, plugin_list=vulnerability_list.get_plugins_under_vulnerability(
                    vulnerability=plugin_name.split("\n")[1].split(" ")[0])), \
                'Plugin severity value is not getting changed after modifying the severity of vulnerability group.'

        HeaderBasePage().scan_link.click()
        scan_list.loaded()

    @pytest.mark.browser_file_download
    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'folder': Nessus.Scan.Folder.MY_SCANS.split(' (')[0], 'target_ip': Nessus.Scan.Target.LOCALHOST,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED))}]}], indirect=True)
    @pytest.mark.nessus_expert
    def test_visibility_of_new_replaced_cvss_v2(self, create_scans):
        """
        NES-12506: [Automation] Verify "cvss" reference is replaced by "cvss v2.0"
        NES-12691: [Automation]: Verify severity base score should be visible in bold in risk information section of
                   plugin details page.

        Scenario Tested:
        [x] Verify "cvss" reference is replaced by "cvss v2.0"
            - Scan report exported file
            - Filter dropdown
            - Plugin (vulnerability) details view
        [x] Verify severity base score should be visible in bold in risk information section
        """
        scan_list = ScanList()

        # Launching created scan and waiting to be completed
        assert scan_list.launch_scan_and_wait_for_status(create_scans[0]), "launch of created scan wasn't successful"

        # Click on scan and go to vulnerability tab
        scan_list.click_on_scan(create_scans[0])
        scan_view_page = ScanViewPage()
        wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
             waiting_for='Vulnerabilities to get loads')

        scan_view_page.vulnerability_tab.click()
        scan_view_page.filter_link.click()

        action_modal = ActionCloseModal()
        wait(lambda: action_modal.is_element_present('modal'))
        scan_view_page.key_dropdown_arrow.click()

        expected_label = ['CVSS v2.0 Base Score', 'CVSS v2.0 Temporal Score', 'CVSS v3.0 Base Score',
                          'CVSS v3.0 Temporal Score', 'CVSS v2.0 Temporal Vector', 'CVSS v3.0 Temporal Vector']

        for label in expected_label:
            scan_view_page.select2_searchbox.value = label

            assert scan_view_page.search_result_options[0].text == label, \
                "'{}' option is not present in filter dropdown options.".format(label)

        scan_view_page.key_dropdown_arrow.click()
        action_modal.cancel_button.click()
        current_value = scan_view_page.severity_base_value.text

        vulnerability_list = VulnerabilityList()
        vulnerability_list.vulnerability_setting.click()
        vulnerability_list.click_on_group_enable_disable(enable=False)

        plugins_name = vulnerability_list.get_plugin_names()
        log.debug("Plugin name :: {}".format(plugins_name))

        vulnerability_list.click_on_vulnerability(vulnerability_name=plugins_name[0])
        wait(lambda: visibility_of_element_located(scan_view_page.right_column_header),
             waiting_for='Vulnerability details to get loads')

        severity_base_score_element = scan_view_page.get_element_from_risk_information_section(value=' '.join(
            [current_value, 'Base Score']))

        assert 'bold' in severity_base_score_element.get_css_classes(), \
            "Severity '{}' base score is not visible in bold in risk information section.".format(current_value)

        vulnerability_desc = VulnerabilityDescription()
        risk_info_details = [element.text for element in vulnerability_desc.risk_info_details]

        assert any([option in info_option for info_option in risk_info_details for option in expected_label]), \
            "'CVSS' label was not replaced with 'CVSS v2.0' label in risk information details."

        scan_view_page.report_button.click()
        wait(lambda: action_modal.is_element_present("modal"), waiting_for='Export modal to open')

        scan_view_page.get_element_for_report_format_radio_button(report_format=API.Scan.UIExportFormats.
                                                                  FORMAT_CSV).click()
        scan_export_page = ScanExportPage()
        wait(lambda: scan_export_page.is_element_present("clear_link"), waiting_for="CSV report options get displayed")
        options_name = [element.text for element in scan_export_page.csv_columns_name]

        assert all([option in options_name for option in expected_label[:-2]]), \
            "'CVSS' label was not replaced with 'CVSS v2.0' label under export report modal custom options."

        scan_export_page.select_all_link.click()
        scan_export_page.generate_report_button.click()
        action_modal.wait_for_modal_closed()

        sleep(sleep_time=TIME_FIFTEEN_SECONDS, reason='waiting for file to download')
        downloaded_files = get_downloaded_files_chrome(filename=create_scans[0].replace(' ', '_'))
        log.debug("Downloaded file path :: :: %s", downloaded_files)

        file_name = downloaded_files[0].split('//')[1].split('/')[-1]
        assert file_name, "Scan results does not exported successfully."

        directory = os.path.join(Config.CAT_LOCAL_BROWSER_DOWNLOAD_PATH, timestamped_path, file_name)
        source_path = get_browser_download_file_path(directory)

        with open(file=source_path, mode='rt') as csv_file:
            raw_data = csv.reader(csv_file, delimiter=',')
            csv_column_header = list(raw_data)[0]
            log.debug("Columns in exported CSV file :: {}".format(csv_column_header))

            assert all([header in csv_column_header for header in expected_label[:-2]]), \
                "'CVSS' label was not replaced with 'CVSS v2.0' label in exported report's column header."

        HeaderBasePage().scan_link.click()

    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.BASIC_NETWORK, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'target_ip': Nessus.Scan.Target.LOCALHOST,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.BASIC_NETWORK)),
         'keep_original_scan_name': True}]}], indirect=True)
    @pytest.mark.nessus_expert
    def test_verify_invisibility_of_summary_tab_for_scanner_scan(self, create_scans):
        """
        NES - 13224 : [UI - Automation] : Verify summary tab visibility in different types of scans

        Scenario Tested:
            [x] Verify the invisibility of summary tab for scanner scan.
        """
        scans_list = ScanList()
        scans_list.loaded()
        scans_list.launch_scan_and_wait_for_status(launch_scan=True, scan_name=create_scans[0])
        scans_list.click_on_scan(scan_name=create_scans[0])
        scan_details_page = ScanViewPage()
        wait(lambda: scan_details_page.is_element_present('vulnerability_tab'), waiting_for='scan results to load')

        # Verify the invisibility of summary tab for scanner scan.
        assert not scan_details_page.is_element_present('summary_tab'), "Summary tab is present for scanner scan."

    @pytest.mark.xray(test_key='NES-15579')
    @pytest.mark.xray(test_key='NES-15577')
    @pytest.mark.xray(test_key='NES-15575')
    @pytest.mark.xray(test_key='NES-15574')
    @pytest.mark.parametrize('create_scan_with_enable_plugin_debugging', [{"scan_file_path": scan_file_path,
                                                                           "scan_template": 'basic'}], indirect=True)
    @pytest.mark.parametrize('setting_value', [Nessus.AdvancedSettings.DARK_MODE, Nessus.AdvancedSettings.LIGHT_MODE])
    @pytest.mark.parametrize('multiple_target', [True, False])
    @pytest.mark.nessus_expert
    def test_verify_debugging_log_report_showing_in_list_view_in_created_scan(
            self, create_scan_with_enable_plugin_debugging, setting_value, multiple_target):
        """
        NES-15574: Verify 'Debugging Log Report' is now showing with list view/ table view in place of icons only
        NES-15575: Verify List view columns for 'Debugging Log Report'
        NES-15577: Verify list view in light and dark mode
        NES-15579: Verify list view in all types of scans

        Scenario Tested:
        [x] Verify 'Debugging Log Report' should be appear in list/table view in place of icons only.
        [x] Verify plugin debugging report table columns.
        [x] Verify 'Debugging Log Report' should be appear in list/table view in dark mode of Nessus too.
        [x] Verify 'Debugging Log Report' should be appear in list/table view in scan with multiple targets.
        """
        modify_existing_advanced_setting(setting_tab=Nessus.AdvancedSettings.USER_INTERFACE_TAB,
                                         setting_name=Nessus.AdvancedSettings.UI_THEME, setting_value=setting_value)
        sleep(WAIT_LONG, reason="It takes little bit time to get impact of 'ui_theme' setting")

        HeaderBasePage().scan_link.click()
        wait(lambda: ScansPage().is_element_present("scan_searchbox"), waiting_for="scan list get loaded")

        api_object = self.cat.api
        scan_id, scan_name, scan_target = create_scan_with_enable_plugin_debugging

        if multiple_target:
            scan_targets = "{}, {}, {}".format(Nessus.Scan.Target.PUB_TARGET_4, Nessus.Scan.Target.AWS_LINUX_TARGET_1,
                                               Nessus.Scan.Target.AWS_LINUX_TARGET_2)

            scan_details_dict = {"folder_id": "3", "text_targets": scan_targets, "name": scan_name,
                                 "enable_plugin_debugging": "yes"}

            payload = load_testdata(self.scan_file_path)
            payload.get('settings').update(scan_details_dict)

            api_object.scans.configure(scan_id=scan_id, payload=payload, stream=True)

            scan_target = scan_targets.split(",")[1].strip()

        api_object.scans.launch(scan_id=scan_id)

        with polling_ui():
            is_scan_completed = wait_scan_state(api=api_object, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                                timeout=TIME_THIRTY_MINUTES)

        assert is_scan_completed, "Failed to get completed the scan with plugin debugging enabled."

        verify_plugin_debugging_log_output_table(scan_name=scan_name, scan_target=scan_target)

    @pytest.mark.xray(test_key='NES-15576')
    @pytest.mark.parametrize('create_scan_with_enable_plugin_debugging', [{"scan_file_path": scan_file_path,
                                                                           "scan_template": 'basic'}], indirect=True)
    @pytest.mark.nessus_expert
    def test_verify_it_opens_details_in_new_tab_after_clicking_on_list_row(
            self, create_scan_with_enable_plugin_debugging):
        """
        NES-15576: Verify download option is working
        NES-15743: Verify the error while refreshing the page with same token of scan attachment

        Scenario Tested:
        [x] Verify that after clicking on Plugin debug log(s) output table row, New tab should get open with details.
        [x] Verify that User should get the error message while refreshing the page with same attachment token.
        """
        close_pendo_guide_container_banner_for_nessus_pro()
        launch_scan_and_go_to_debugging_log_report_vuln(nessus_api=self.cat.api,
                                                        scan_details=create_scan_with_enable_plugin_debugging)

        # wait for to get ready state and max wait for 30 sec
        VulnerabilityDescription().debug_log_hosts_row[0].click()
        sleep(sleep_time=WAIT_NORMAL, reason="It takes little bit time to open new tab after clicking")

        driver_instance = get_driver_no_init()
        windows_handler = WindowsHandler(driver=driver_instance)
        windows_handler.switch_to_window(windows_handler.handles[-1])
        sleep(sleep_time=WAIT_SHORT, reason="waiting for page switch")

        split_url = driver_instance.current_url.split("/")

        # Verify click on link text is redirecting to correct url
        assert all([split_url[3] == "tokens", split_url[5] == "download"]), \
            "New tab does not open with details after clicking on Plugin debug log(s) output table row."

        driver_instance.refresh()
        sleep(sleep_time=WAIT_SHORT, reason="waiting for the error")

        assert '{"error":"The requested file was not found."}' == driver_instance.find_element(By.TAG_NAME,
                                                                                               "pre").text.strip(), "User cannot get the error even after refreshing the page with same attachment token."

        windows_handler.switch_to_window(windows_handler.handles[0])
        sleep(sleep_time=WAIT_SHORT, reason="waiting for page switch")

    @pytest.mark.xray(test_key='NES-15578')
    @pytest.mark.parametrize('create_scan_with_enable_plugin_debugging', [{"scan_file_path": scan_file_path,
                                                                           "scan_template": 'basic'}], indirect=True)
    @pytest.mark.parametrize('export_format', [API.Scan.ExportFormats.FORMAT_DB, pytest.param(
        API.Scan.ExportFormats.FORMAT_NESSUS, marks=pytest.mark.xfail(reason="Refer JIRA ID NES-15631"))])
    @pytest.mark.nessus_expert
    def test_verify_debugging_log_report_showing_in_list_view_in_imported_scan(
            self, create_scan_with_enable_plugin_debugging, export_format):
        """
        NES-15578: Verify list view in imported scans

        Scenario Tested:
        [x] Verify 'Debugging Log Report' should be appear in list/table view in imported scan too.
        [x] Verify plugin debugging report table columns in imported scan.
        """
        scan_id, scan_name, scan_target = create_scan_with_enable_plugin_debugging

        self.cat.api.scans.launch(scan_id=scan_id)

        with polling_ui():
            wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                            timeout=TIME_THIRTY_MINUTES)

        scan_page = ScansPage()
        scan_page.refresh()
        wait(lambda: scan_page.is_element_present("scan_searchbox"), waiting_for="scan list gets loaded")
        export_import_password = "nessus" if export_format == API.Scan.ExportFormats.FORMAT_DB else None

        export = self.cat.api.scans.export(scan_id=scan_id, export_format=export_format,
                                           password=export_import_password)

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

            assert import_scan['scan']['id'], "Scan does not imported successfully in nessus."

            scan_id, imported_scan_name = import_scan['scan']['id'], import_scan['scan']['name']

            verify_plugin_debugging_log_output_table(scan_name=imported_scan_name, scan_target=scan_target,
                                                     scan_format=export_format)
        finally:
            self.cat.api.scans.delete(scan_id=scan_id)

    @pytest.mark.xray(test_key='NES-15582')
    @pytest.mark.parametrize('create_scan_with_enable_plugin_debugging', [{"scan_file_path": scan_file_path,
                                                                           "scan_template": 'basic'}], indirect=True)
    @pytest.mark.nessus_expert
    def test_verify_list_view_of_debugging_log_report_from_different_paths(
            self, create_scan_with_enable_plugin_debugging):
        """
        NES-15582: Verify list view from different paths

        Scenario Tested:
        [x] Verify 'Debugging Log Report' should be appear in list/table view from different paths
            - Host > debugging log report
            - vuln > debugging log report
            - vuln > debugging log report > click host hyperlink > open debugging log report
        """
        scan_id, scan_name, scan_target = create_scan_with_enable_plugin_debugging

        launch_scan_and_go_to_debugging_log_report_vuln(nessus_api=self.cat.api,
                                                        scan_details=create_scan_with_enable_plugin_debugging)

        for path in ["from_host_tab", "from_vuln_tab", "from_vuln_host"]:
            HeaderBasePage().scan_link.click()
            wait(lambda: ScansPage().is_element_present("scan_searchbox"), waiting_for="scan list gets loaded")

            if path == "from_vuln_host":
                ScanList().click_on_scan(scan_name=scan_name)
                scan_view_page = ScanViewPage()
                wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
                     waiting_for='Vulnerabilities to load')

                scan_view_page.vulnerability_tab.click()
                wait(lambda: visibility_of_element_located(scan_view_page.search_icon),
                     waiting_for="Host Details Page to load", timeout_seconds=WAIT_NORMAL)

                vuln_name = Nessus.Scan.Vulnerability.DEBUGGING_LOG_REPORT
                scan_view_page.search_box.value = vuln_name
                sleep(WAIT_NORMAL, reason="waiting for matching vulnerability results")

                VulnerabilityList().click_on_vulnerability(vulnerability_name=vuln_name)
                vuln_desc = VulnerabilityDescription()
                wait(lambda: vuln_desc.is_element_present("plugin_header"),
                     waiting_for="vulnerability details get displayed")

                vuln_desc.get_element_of_plugin_debug_log_host(host=scan_target).click()

                search_for_debugging_log_report_vuln_and_verify_list_view(scan_target=scan_target)
            else:
                go_from_path = True if path == "from_host_tab" else False

                verify_plugin_debugging_log_output_table(scan_name=scan_name, scan_target=scan_target,
                                                         go_from_host=go_from_path)

    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         "target_ip": Nessus.Scan.Target.LINUX_TARGET, 'add_configuration': True}]}], indirect=True)
    @pytest.mark.nessus_expert
    def test_web_application_settings_configurable_under_scan_assessment(self, create_scans):
        """
        NES-15740 [UI-Automation]: Verify that user is able to configure "Application Test Settings" under Web
                                   Application Settings of Assessment

        Scenario Tested:
        [x] Verify that user can configure the "Application Test Settings" under Web Application Settings of
            Web Applications under Assessment tab
        """
        scan_name = create_scans[0]

        assessment_setting = AssessmentSetting()
        assessment_setting.click_link_inside_link(
            setting_value=API.PoliciesSettings.SettingsTypes.ASSESSMENT,
            link_text=API.PoliciesSettings.SettingsTypes.Assessment.WEB_APPLICATIONS)
        wait(lambda: assessment_setting.is_element_present("scan_web_app_switch"))

        assessment_setting.scan_web_app_switch.click()
        wait(lambda: assessment_setting.is_element_present("enable_generic_webapp_tests"))

        assessment_setting.enable_generic_webapp_tests.check()
        scan_form = NewScanForm()
        scan_form.save_button.click()

        scan_list = ScanList()
        wait(lambda: scan_name in scan_list.get_all_scans())
        scan_list.launch_scan_and_wait_for_status(scan_name=scan_name)

        if ActionCloseModal().is_element_present('container_close_icon'):
            ActionCloseModal().container_close_icon.click()
            sleep(WAIT_SHORT * 3, reason="It takes little bit time to get UI settled")

        scan_list.click_on_scan(scan_name=scan_name)
        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present('vulnerability_tab'))

        scan_view_page.js_scroll_into_view(element=scan_view_page.configure_button)
        scan_view_page.configure_button.click()
        wait(lambda: scan_form.is_element_present("name_field"))

        assessment_setting.click_link_inside_link(
            setting_value=API.PoliciesSettings.SettingsTypes.ASSESSMENT,
            link_text=API.PoliciesSettings.SettingsTypes.Assessment.WEB_APPLICATIONS)
        wait(lambda: assessment_setting.is_element_present("scan_web_app_switch"))

        for element_id in ["abort_generic_webapp_if_login_fails", "try_all_http_methods", "http_param_pollution",
                           "test_embedded_web_servers", "combo_arg_values", "stop_at_first_flaw", "url_for_rfi",
                           "generic_webapp_tests_max_time"]:
            assert assessment_setting.get_element_of_application_test_settings(data_input_id=element_id).is_enabled(), \
                "Setting for '{}' does not getting enabled while configuring scan.".format(element_id)

        HeaderBasePage().scan_link.click()
        wait(lambda: ScansPage().is_element_present("scan_searchbox"))


@pytest.mark.skip(reason='VPR tab removed per NES-12519')
@pytest.mark.usefixtures('wait_for_plugin_families_to_be_available', 'nessus_api_login', 'login')
class TestThreatLevelTabFeatures:
    """ Tests related to Threat Level tab in scan result page """

    cat = None

    @staticmethod
    def verify_vpr_top_threats_tab_present(nessus_api: NessusAPI(), scan_id: int) -> None:
        """
        Verifies that "VPR Top Threats" tab is present in scan results

        :param nessus_api: NessusAPI object
        :param int scan_id: created scan Id
        :return: None
        """
        scan_details = nessus_api.scans.details(scan_id=scan_id)

        assert "vpr_score" not in scan_details, \
            "'VPR Top Threats' tab is present in scan results."

    @pytest.mark.skip(reason='VPR tab removed per NES-12519')
    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'folder': Nessus.Scan.Folder.MY_SCANS.split(' (')[0], 'target_ip': Nessus.Scan.Target.AWS_LINUX_TARGET_1,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED))}]}], indirect=True)
    def test_predictive_prioritization_link_redirects_to_correct_url(self, create_scans):
        """
        NES-12707: [Automation] Verify predictive prioritization link from description redirects to correct URL

        Scenario Tested:
        [x] Verify that "Predictive Prioritization" link is present in description under VPR top threat tab.
        [x] Verify that "Predictive Prioritization" link redirects to the correct URL
            (https://www.tenable.com/predictive-prioritization).
        """
        scan_list = ScanList()

        # Launching created scan and waiting to be completed
        assert scan_list.launch_scan_and_wait_for_status(create_scans[0]), "launch of created scan wasn't successful"

        # Click on scan
        scan_list.click_on_scan(create_scans[0])
        scan_view_page = ScanViewPage()
        wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
             waiting_for='Vulnerabilities to get loads')

        scan_view_page.threat_level_tab.click()
        wait(lambda: visibility_of_element_located(scan_view_page.predictive_prioritization_link),
             waiting_for='Threat level tab page to get loads')

        assert scan_view_page.is_element_present("predictive_prioritization_link"), \
            "Predictive prioritization link is missing in description."

        scan_view_page.predictive_prioritization_link.click()

        windows_handler = WindowsHandler(driver=get_driver_no_init())
        windows_handler.switch_to_window(windows_handler.handles[-1])
        sleep(sleep_time=WAIT_NORMAL, reason="waiting for page switch")

        # Verify click on link text is redirecting to correct url
        assert Nessus.Scan.Results.ThreatLevelTab.PREDICTIVE_PRIORITIZATION_LINK_URL == get_driver_no_init(). \
            current_url, "Click on '{}' link is not being redirecting to '{}' link page".format(
            scan_view_page.predictive_prioritization_link.text, Nessus.Scan.Results.ThreatLevelTab.
            PREDICTIVE_PRIORITIZATION_LINK_URL)

        windows_handler.switch_to_window(windows_handler.handles[0])
        sleep(sleep_time=WAIT_NORMAL, reason="waiting for page switch")

        HeaderBasePage().scan_link.click()

    @pytest.mark.skip(reason='VPR tab removed per NES-12519')
    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'folder': Nessus.Scan.Folder.MY_SCANS.split(' (')[0], 'target_ip': '{}, {}, {}, {}'.format(
            Nessus.Scan.Target.PUB_TARGET_3, Nessus.Scan.Target.AWS_LINUX_TARGET_1, Nessus.Scan.Target.PUB_TARGET_4,
            Nessus.Scan.Target.AWS_LINUX_TARGET_2),
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED))}]}], indirect=True)
    def test_vpr_top_threat_tab_not_present_in_running_or_paused_scan(self, create_scans):
        """
        NES-12710: [UI-Automation] Verify 'VPR Top Threats' tab should not be visible in running or paused scan

        Scenario Tested:
        [x] Verify 'VPR Top Threats' tab should not be visible in running or paused scan
        """
        scan_name = create_scans[0]
        scan_list = ScanList()
        scan_id = scan_list.get_scan_id(scan_name=scan_name)

        scan_list.refresh()
        scan_list.loaded()

        with polling_ui():
            try:
                self.cat.api.scans.launch(scan_id=scan_id)
                wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.RUNNING,
                                timeout=TIME_SIXTY_SECONDS)

                self.verify_vpr_top_threats_tab_present(nessus_api=self.cat.api, scan_id=scan_id)

                self.cat.api.scans.pause(scan_id=scan_id)
                wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.PAUSED,
                                timeout=TIME_SIXTY_SECONDS)

                self.verify_vpr_top_threats_tab_present(nessus_api=self.cat.api, scan_id=scan_id)

                self.cat.api.scans.resume(scan_id=scan_id)
                wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.RUNNING,
                                timeout=TIME_SIXTY_SECONDS)

                self.verify_vpr_top_threats_tab_present(nessus_api=self.cat.api, scan_id=scan_id)
            finally:
                scan_status = self.cat.api.scans.details(scan_id)['info']['status']

                try:
                    if scan_status not in [API.Scan.Status.COMPLETED, API.Scan.Status.CANCELED,
                                           API.Scan.Status.ABORTED]:
                        self.cat.api.scans.stop(scan_id)
                        wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.CANCELED,
                                        timeout=TIME_SIXTY_SECONDS)
                except Exception as e:
                    log.warning("Scan was not stopped successfully. Exception is : {}".format(e))

                    if self.cat.api.scans.details(scan_id)['info']['status'] != API.Scan.Status.COMPLETED:
                        raise Exception("Unable to stop scan!")

    @pytest.mark.skip(reason='VPR tab removed per NES-12519')
    @pytest.mark.parametrize('scan_type', ['policy_scan', 'scheduled_scan'])
    def test_visibility_of_vpr_tab_for_policy_or_schedule_scan(self, get_policy_templates, scan_type):
        """
        NES-12715: [UI-Automation] Verify VPR details availability for all types of scans - Policy scans, Normal scans,
                    Scans from Scan result

        Scenario Tested:
        [x] Verify that "VPR Top Threats" tab is present for policy scan.
        [x] Verify that "VPR Top Threats" tab is present for scheduled scan.
        """
        if scan_type == 'policy_scan':
            policy_details = create_policy_helper(self.cat.api, get_policy_templates, policy_type='advanced',
                                                  policy_name=random_name(prefix="advanced-policy-"))

            config = {'policy_id': policy_details['policy_id'], 'text_targets': Nessus.Scan.Target.LOCALHOST}
        else:
            timezone = 'America/New_York'
            start_time = (pytz.utc.localize(datetime.utcnow()) + timedelta(minutes=2)).astimezone(
                pytz.timezone(timezone)).strftime("%Y%m%dT%H%M00")

            config = {'enabled': True, 'starttime': start_time, 'timezone': timezone, 'launch': 'ONETIME',
                      'rrules': 'FREQ=ONETIME', 'description': 'Created by Automation',
                      'text_targets': Nessus.Scan.Target.LOCALHOST}

        scan_details = self.cat.api.scans.create(ScanModel(name=random_name(prefix="automation-scan-"), **config))
        scan_id, scan_name = scan_details['scan']['id'], scan_details['scan']['name']

        try:
            scan_list = ScanList()
            scan_list.refresh()
            scan_list.loaded()

            if scan_type == 'policy_scan':
                self.cat.api.scans.launch(scan_id=scan_id)
            else:
                wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.RUNNING,
                                timeout=TIME_FIVE_MINUTES)

            wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                            timeout=TIME_THIRTY_MINUTES)

            scan_list.click_on_scan(scan_name=scan_name)

            scan_view_page = ScanViewPage()
            wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
                 waiting_for='Vulnerabilities to get loads')

            assert scan_view_page.is_element_present('threat_level_tab'), \
                "'VPR Top Threats' tab is not present in completed scan results."

            scan_view_page.threat_level_tab.click()
            wait(lambda: visibility_of_element_located(scan_view_page.threat_level_description),
                 waiting_for='Threat level tab to get loaded')

            threat_level_vulnerability_list = ThreatLevelVulnerabilityList()

            assert Nessus.Scan.Results.ThreatLevelTab.COLUMN_LIST == [column.text for column in
                                                                      threat_level_vulnerability_list.columns], \
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
        finally:
            self.cat.api.scans.delete(scan_id=scan_id)

    @pytest.mark.skip(reason='VPR tab removed per NES-12519')
    @pytest.mark.parametrize('threat_level', [
        Nessus.Scan.Severity.CRITICAL, Nessus.Scan.Severity.HIGH, Nessus.Scan.Severity.MEDIUM,
        Nessus.Scan.Severity.LOW, Nessus.Scan.Severity.NONE])
    def test_vpr_tab_icon_and_color_based_on_threats_level(self, threat_level):
        """
        NES-12716: [UI-Automation] Verify in VPR Top Threats tab, value for Assessed Threat Level, color of shield
                    icon in description as well as on Tab title itself should be matched

        Scenario Tested:
        [x] Verify that "VPR Top Threats" tab icon, description icon and it's color should be based on threat level.
        [x] Verify that if no vulnerability available then "No prioritized vulnerabilities found" message should be
            display.
        """
        severity_values = {Nessus.Scan.Severity.LOW: '1', Nessus.Scan.Severity.MEDIUM: '2',
                           Nessus.Scan.Severity.HIGH: '3', Nessus.Scan.Severity.CRITICAL: '4',
                           Nessus.Scan.Severity.NONE: 'none'}

        threat_level_details = {
            Nessus.Scan.Severity.CRITICAL: {"file_name": "Basic_Network_Scan_for_VPR_dcb3mn.nessus",
                                            "color": "#91243E"},
            Nessus.Scan.Severity.HIGH: {"file_name": "PCI_Internal_Scan_for_VPR_lkjme5.nessus",
                                        "color": "#DD4B50"},
            Nessus.Scan.Severity.MEDIUM: {"file_name": "Advanced_Dynamic_Scan_for_VPR_gcb0j6.nessus",
                                          "color": "#F18C43"},
            Nessus.Scan.Severity.LOW: {"file_name": "Advanced_scan_for_VPR_nm12hp.nessus",
                                       "color": "#F8C851"},
            Nessus.Scan.Severity.NONE: {"file_name": "Host_Discovery_Scan_for_VPR_7503c2.nessus",
                                        "color": "#A3C772"}}

        file_path = get_file_path("nessus/tests/api/scan/test_data/" + threat_level_details[threat_level]["file_name"])
        file_uploaded = self.cat.api.file.upload(file=get_file_path(file_path), encrypted=True)

        imported_scan_details = self.cat.api.scans.import_scan(file_uploaded)
        scan_id, scan_name = imported_scan_details['scan']['id'], imported_scan_details['scan']['name']

        try:
            scan_list = ScanList()
            scan_list.refresh()
            scan_list.loaded()
            scan_list.click_on_scan(scan_name=scan_name)

            scan_view_page = ScanViewPage()
            wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
                 waiting_for='Vulnerabilities to get loads')

            assert scan_view_page.is_element_present('threat_level_tab'), \
                "'VPR Top Threats' tab is not present in completed scan results."

            scan_view_page.threat_level_tab.click()
            wait(lambda: visibility_of_element_located(scan_view_page.threat_level_description),
                 waiting_for='Threat level tab to get loaded')

            tab_icon = scan_view_page.get_element_for_vpr_tab_or_description_icon(
                element_for="tab", threat_index=severity_values[threat_level])

            assert visibility_of_element_located((tab_icon.we_by, tab_icon.we_value))(get_driver_no_init()), \
                "Tab icon is missing next to 'VPR Top Threats' tab for '{}' threat level.".format(threat_level)

            description_icon = scan_view_page.get_element_for_vpr_tab_or_description_icon(threat_index=severity_values[
                threat_level])

            assert visibility_of_element_located((description_icon.we_by, description_icon.we_value))(
                get_driver_no_init()), "Description icon is missing next to 'VPR Top Threats' description content " \
                                       "tab for '{}' threat level.".format(threat_level)

            assert visibility_of_element_located(scan_view_page.assessed_threat_level_value), \
                "Assessed threat level value is missing in description."

            expected_assessed_threat_level_value = scan_view_page.assessed_threat_level_value.text

            assert expected_assessed_threat_level_value == threat_level, \
                "Assessed threat level value is incorrect. Expected :: {}, Got :: {}".format(
                    threat_level, expected_assessed_threat_level_value)

            if threat_level == Nessus.Scan.Severity.NONE:
                assert visibility_of_element_located(scan_view_page.empty_results), \
                    "VPR data table is getting visible for '{}' severity which should not be.".format(threat_level)

                assert get_color_code_of_ui_element(element=tab_icon, css_property='fill') == \
                       get_color_code_of_ui_element(element=description_icon, css_property='fill') == \
                       threat_level_details[threat_level]['color'], "Tab and Description icons colors are different " \
                                                                    "for '{}' severity.".format(threat_level)
            else:
                threat_level_vulnerability_list = ThreatLevelVulnerabilityList()
                severity_value = threat_level_vulnerability_list.get_plugin_vpr_severity()[0]

                assert severity_value == threat_level.upper(), "Getting incorrect highest VPR Severity. Expected :: " \
                                                               "{}, Got :: {}".format(threat_level, severity_value)

                vpr_severity = scan_view_page.get_element_for_vpr_severity_from_table(threat_index=severity_values[
                    threat_level])

                assert get_color_code_of_ui_element(element=tab_icon, css_property='fill') == \
                       get_color_code_of_ui_element(element=description_icon, css_property='fill') == \
                       get_color_code_of_ui_element(element=vpr_severity, css_property='background') == \
                       threat_level_details[threat_level]['color'], "Tab and Description icons colors and color of " \
                                                                    "got highest VPR Severity are different for " \
                                                                    "'{}'.".format(threat_level)
        finally:
            self.cat.api.scans.delete(scan_id)

    @pytest.mark.skip(reason='VPR tab removed per NES-12519')
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_Scan_for_VPR_dcb3mn.nessus',
                                                      'file_path': 'nessus/tests/api/scan/test_data/',
                                                      'encrypted': True}], indirect=True)
    def test_vpr_data_shows_top_highest_vulns_as_per_vpr_score(self, import_scan_via_api):
        """
        NES-12742: Verify that VPR data shows only top highest vulnerabilities as per VPR score

        Scenario Tested:
        [x] Verify that VPR data shows only top highest vulnerabilities as per VPR score
        [x] Verify that the format for int-only VPR score
        """
        scan_name = import_scan_via_api[0]

        scan_list = ScanList()
        scan_list.refresh()
        scan_list.loaded()

        try:
            scan_list.click_on_scan(scan_name=scan_name)

            scan_view_page = ScanViewPage()
            wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
                 waiting_for='Vulnerabilities to get loads')

            scan_view_page.threat_level_tab.click()
            wait(lambda: visibility_of_element_located(scan_view_page.threat_level_description),
                 waiting_for='Threat level tab to get loaded')

            severity_with_score = {}
            threat_level_vulnerability_list = ThreatLevelVulnerabilityList()

            for row in threat_level_vulnerability_list.rows:
                severity_with_score[row.severity_name] = row.vulnerability_vpr_score

                assert isinstance(float(row.vulnerability_vpr_score), float), \
                    "VPR score should not be in 'int' format in VPR table data."

            severity_range = {Nessus.Scan.Severity.CRITICAL: [9.0, 10.0], Nessus.Scan.Severity.HIGH: [7.0, 8.9],
                              Nessus.Scan.Severity.MEDIUM: [4.0, 6.9], Nessus.Scan.Severity.LOW: [0.1, 3.9]}

            for key, value in severity_with_score.items():
                expected_severity_range = severity_range[key.capitalize()]

                assert expected_severity_range[0] <= float(value) <= expected_severity_range[1], \
                    "VPR score for '{}' severity is not between expected score range.".format(key)

            HeaderBasePage().scan_link.click()
        finally:
            scan_list.delete_scan(scan_name=scan_name)


@pytest.mark.scanning
@pytest.mark.nessus_home
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('nessus_api_login', 'login')
class TestSeverityBaseChange:
    """Tests related to severity base change for created scan"""

    cat = None

    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'folder': Nessus.Scan.Folder.MY_SCANS.split(' (')[0], 'target_ip': Nessus.Scan.Target.AWS_LINUX_TARGET_1,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED))}]}], indirect=True)
    def test_severity_base_change_from_created_scan_result_page(self, create_scans):
        """
        NES-12650 : [UI-Automation] Verify severity_base change feature inside created scan

        Scenario Tested:
            [x] Verify that user can change severity base from created scan result page.
            [x] Verify that severity base change pop up displayed with correct title and drop down values.
        """
        scan_list = ScanList()

        # Launching created scan and waiting to be completed
        assert scan_list.launch_scan_and_wait_for_status(create_scans[0]), "launch of created scan wasn't successful"

        # Click on scan
        scan_list.click_on_scan(create_scans[0])
        scan_view_page = ScanViewPage()
        wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
             waiting_for='Vulnerabilities to get loads')

        scan_view_page.host_tab.click()
        wait(lambda: scan_view_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

        # Verify that pencil icon is visible and clickable in created scan result page.
        assert scan_view_page.is_element_present('severity_base_change_icon'), \
            "Pencil icon is not present for severity base change."
        scan_view_page.severity_base_change_icon.click()

        cvss_pop_up = ActionCloseModal()
        # Verify severity base change pop up
        assert cvss_pop_up.is_element_present('modal'), "Severity Base change pop up does not appear."
        assert cvss_pop_up.modal_title.text == 'Change Severity Rating Base', \
            "Severity base change pop up title is incorrect."
        assert scan_view_page.is_element_present('severity_base_dropdown'), \
            "Drop down is not present to change severity base."
        assert {'CVSS v2.0', 'CVSS v3.0'}.issubset(set([option.get(
            'label') for option in scan_view_page.severity_base_dropdown.option_values])), \
            "User can not switch to CVSS v2.0 or CVSS v3.0 from drop down inside scan result"

    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'folder': Nessus.Scan.Folder.MY_SCANS.split(' (')[0], 'target_ip': Nessus.Scan.Target.AWS_LINUX_TARGET_1,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED))}]}], indirect=True)
    @pytest.mark.parametrize('severity_base', [
        Nessus.AdvancedSettings.CVSS_V4, Nessus.AdvancedSettings.CVSS_V2, Nessus.AdvancedSettings.CVSS_V3])
    def test_verify_severity_value_in_bold_letters_when_default_value_overridden(self, create_scans, severity_base):
        """
        NES-12677 : [UI-Automation] : Severity base value will be bold when override the system default
                    during switching from scan details.

        Scenario Tested:
            [x] Verify that Severity base value will be bold when override the system default
                during switching from scan details.
        """
        scan_list = ScanList()

        # Launching created scan and waiting to be completed
        assert scan_list.launch_scan_and_wait_for_status(create_scans[0]), "launch of created scan wasn't successful"

        # Click on scan
        scan_list.click_on_scan(create_scans[0])
        scan_view_page = ScanViewPage()
        wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
             waiting_for='Vulnerabilities to get loads')

        scan_view_page.host_tab.click()
        wait(lambda: scan_view_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

        # Verify that initially default value is selected for severity_basis and hence it is not in bold letters.
        assert not scan_view_page.is_element_present('cvss_in_bold'), ""

        new_value = scan_view_page.change_severity_base_value_from_popup(severity_base)

        # Verify the newly updated value appears in bold letters on UI.
        try:
            wait(lambda: scan_view_page.is_element_present('cvss_in_bold'),
                 waiting_for='New severity_basis value to show in bold letters')
        except TimeoutExpired:
            raise AssertionError("New severity value is not in bold letters.")

        assert scan_view_page.cvss_in_bold.text == new_value, "New cvss value does not populated in bold letters."

    @pytest.mark.usefixtures('nessus_api_login', 'import_scan_via_api', 'login')
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_-_CVSS_av5q3j.nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/'}], indirect=True)
    @pytest.mark.nessus_expert
    def test_severity_base_for_scan_created_from_scan_result_page(self, import_scan_via_api):
        """
        NES-12866: [UI-Automation] Verify that severity base is visible/can be changed for scans created
                   from scan result
        Scenario Tested:
            [x] Verify that severity base is visible/can be changed for scans created from scan result
        """
        scan_name = import_scan_via_api[0]
        scan_list = ScanList()
        scan_list.click_on_scan(scan_name=scan_name)
        scan_view_page = ScanViewPage()
        wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
             waiting_for='Vulnerabilities to get loads')

        scan_view_page.host_tab.click()
        wait(lambda: scan_view_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

        hosts_list = ScansHostList()
        hosts_list.select_hosts(['localhost'])
        scan_view_page.more_dropdown.click()
        scan_view_page.create_scan_option.click()
        new_scan_name = random_name(prefix="new_scan_")
        scans_page = ScansPage()
        scans_page.create_new_scan(scan_template=Nessus.TemplateNames.ADVANCED,
                                   scan_type=Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                                   scan_name=new_scan_name, new_scan_button=False)
        try:
            scan_list.loaded()
            assert scan_list.launch_scan_and_wait_for_status(new_scan_name), ""
            scan_list.click_on_scan(new_scan_name)
            wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
                 waiting_for='Vulnerabilities to get loads')
            scan_view_page.host_tab.click()
            wait(lambda: scan_view_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")
            assert scan_view_page.is_element_present('severity_base_value'), \
                "Severity base value is not visible."
            original_severity_base_value = scan_view_page.severity_base_value.text

            # Verify that pencil icon is visible and clickable in created scan result page.
            assert scan_view_page.is_element_present('severity_base_change_icon'), \
                "Pencil icon is not present for severity base change."
            severity = 'CVSS v2.0'
            scan_view_page.change_severity_base_value_from_popup(severity)
            setting_modal = AddAdvancedSettingModal()
            setting_modal.wait_for_modal_closed()

            assert scan_view_page.severity_base_value.text != original_severity_base_value, \
                "Severity Base value did not change."
        finally:
            HeaderBasePage().scan_link.click()
            scan_list.loaded()
            scan_list.delete_scan(scan_name=new_scan_name)

    @pytest.mark.xray(test_key='NES-18312')
    @pytest.mark.usefixtures('nessus_api_login', 'import_scan_via_api', 'login')
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_-_CVSS_av5q3j.nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/'}], indirect=True)
    @pytest.mark.nessus_expert
    def test_severity_v4_on_imported_scan_result_page(self, import_scan_via_api):
        """
        NES-18312 -: [E2E][UI] Verify the default severity value should be updated on scan result page after changing 'severity_basis' default to cvss_v4
        Scenario Tested:
            [x] severity base is showing default on imported scan result page when change from advanced settings
        """
        advanced_setting = AdvancedSettingsPage()
        advanced_setting.open()
        advanced_setting_list = AdvancedSettingsList()
        setting_tab = Nessus.AdvancedSettings.SCANNING_TAB
        setting_value_before_change = advanced_setting_list.get_settings_value(setting_tab=setting_tab,
                                                                               setting_name='severity_basis')
        setting_modal = AddAdvancedSettingModal()
        setting_modal.find_specific_setting_name(setting_name='severity_basis').click()

        if setting_value_before_change[0] != Nessus.AdvancedSettings.CVSS_V4:
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

            assert setting_value_after_change[
                       0] == Nessus.AdvancedSettings.CVSS_V4, 'CVSS v4 value is not updated from CVSS v3 to v4 after change.'

            setting_modal.find_specific_setting_name(setting_name='severity_basis').click()

        setting_modal.cancel_button.click()
        setting_modal.wait_for_modal_closed()
        sleep(WAIT_NORMAL, reason="Setting value takes little bit time to get updated.")

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

        scan_view_page.vulnerability_tab.click()
        wait(lambda: scan_view_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

        assert scan_view_page.severity_base_value.text == Nessus.AdvancedSettings.CVSS_V4, 'Severity base value is not changed on scan results page.'

    @pytest.mark.browser_file_download
    @pytest.mark.parametrize('severity_base_value', ['cvss_v2', 'cvss_v3'])
    @pytest.mark.parametrize("format_type", [API.Scan.UIExportFormats.FORMAT_CSV])
    @pytest.mark.nessus_expert
    def test_custom_report_can_be_exported_with_different_severity_base(self, severity_base_value, format_type):
        """
        NES-12869: [UI-Automation]: Verify report can be exported with different severity basis for "custom" report
                    option.

        Scenario Tested:
        [x] Verify CVSS 3.0 options are working at PDF report generation and should give appropriate result
        [x] Verify CVSS 3.0 options are working at HTML report generation and should give appropriate result
        [x] Verify CVSS 3.0 options are working at CSV report generation and should give appropriate result
        [x] Verify CVSS 2.0 options are working at PDF report generation and should give appropriate result
        [x] Verify CVSS 2.0 options are working at HTML report generation and should give appropriate result
        [x] Verify CVSS 2.0 options are working at CSV report generation and should give appropriate result
        """
        base_value = severity_base_value.split('_')
        expected_severity_base_value = ' '.join([base_value[0].upper(), base_value[1] + '.0'])

        scan_file = get_file_path('nessus/tests/ui/scans/test_data/' + 'Test_Advanced_scan_j6wpm1.db')
        file_uploaded = self.cat.api.file.upload(file=scan_file, encrypted=True)
        imported_scan = self.cat.api.scans.import_scan(file_uploaded, password='nessus')['scan']
        scan_name, scan_id = imported_scan['name'], imported_scan['id']

        ScansPage().refresh()
        scan_list = ScanList()
        scan_list.loaded()

        try:
            self.cat.api.scans.update_severity_base(scan_id=scan_id, payload={"severity_base": severity_base_value})

            scan_list.click_on_scan(scan_name=scan_name)

            scan_view_page = ScanViewPage()
            wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
                 waiting_for='Scan results page to load')

            assert scan_view_page.severity_base_value.text == expected_severity_base_value, \
                "Severity base is not getting updated to '{}'".format(expected_severity_base_value)

            scan_view_page.report_button.click()
            options_name = get_scan_results_export_options(format_type=format_type)
            scan_export_page = ScanExportPage()
            scan_export_page.clear_link.click()

            options_name = [option_name for option_name in options_name if 'cvss' in option_name]
            scan_export_page.select_and_deselect_all_options(option_name=options_name, flag=True)
            expected_options = [element.text for element in scan_export_page.csv_columns_name]

            expected_options = [option_name for option_name in expected_options if 'CVSS ' in option_name]
            log.debug("expected options :: {}".format(expected_options))

            scan_export_page.generate_report_button.click()
            ActionCloseModal().wait_for_modal_closed()

            downloaded_files = get_downloaded_files_chrome(filename="Test_Advanced_scan")
            log.debug("Downloaded file path :: :: %s", downloaded_files)

            # Verify that generated pdf report file is downloaded successfully
            file_name = downloaded_files[0].split('//')[1].split('/')[-1]
            assert file_name, "Scan results does not exported successfully."

            directory = os.path.join(Config.CAT_LOCAL_BROWSER_DOWNLOAD_PATH, timestamped_path, file_name)
            downloaded_file_path = get_browser_download_file_path(directory)

            with open(downloaded_file_path, mode='rt') as file_obj:
                raw_data = csv.reader(file_obj, delimiter=',')
                csv_column_header = list(raw_data)[0]
                log.debug("CSV column headers :: {}".format(csv_column_header))

                assert all([column in csv_column_header for column in expected_options]), \
                    'Selected CSV columns from export csv model and CSV columns from exported file are different.'
        finally:
            self.cat.api.scans.delete(scan_id=scan_id)

    def test_visibility_of_cvss_score_column_for_user_defined_scan_results(self, get_policy_templates):
        """
        NES-13196 [Automation] Verify score column is also shown for completed scans with user-defined polices

        Scenario Tested:
            [x] Verify CVSS score column is also shown for completed scans with user-defined policies
        """
        policy_details = create_policy_helper(self.cat.api, get_policy_templates, policy_type='advanced',
                                              policy_name=random_name(prefix="advanced-policy-"))

        config = {'policy_id': policy_details['policy_id'], 'text_targets': Nessus.Scan.Target.PUB_TARGET_1}

        scan_id = self.cat.api.scans.create(ScanModel(name=random_name(prefix="automation-scan-"), **config))[
            'scan']['id']

        self.cat.api.scans.launch(scan_id)

        wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                        timeout=TIME_THIRTY_MINUTES)

        scan_name = self.cat.api.scans.details(scan_id=scan_id)['info']['name']
        click_on_scan_and_go_to_vulnerabilities_tab(scan_name=scan_name)

        assert ScanViewPage().is_element_present("cvss_score_column"), \
            "CVSS score column is not present in user defined scan results."

    @pytest.mark.parametrize('scan_data_file', [
        (get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'), 'advanced')])
    def test_visibility_of_cvss_score_column_in_running_scan_results(self, scan_data_file):
        """
        NES-13203 [Automation] Verify CVSS score column is visible for running (In-Process) scans as well

        Scenario Tested:
        [x] Verify CVSS score column is visible for running (In-Progress) scans as well
        """
        scan_details = create_scan_helper(self.cat.api, file_name=scan_data_file[0], template_title=scan_data_file[1],
                                          change_scan_name=True)
        scan_id, scan_name = scan_details[0]['scan']['id'], scan_details[0]['scan']['name']

        scan_list = ScanList()
        scan_list.refresh()
        scan_list.loaded()

        self.cat.api.scans.launch(scan_id)

        wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.RUNNING,
                        timeout=TIME_SIXTY_SECONDS)
        sleep(WAIT_LONG * 3, reason="Takes little bit time to get vulnerabilities after scan started.")

        click_on_scan_and_go_to_vulnerabilities_tab(scan_name=scan_name)

        assert ScanViewPage().is_element_present("cvss_score_column"), \
            "CVSS score column is not present in running scan's results."
