"""
Nessus test cases related to Export Scan results page of created scan

:copyright: Tenable Network Security, 2019
:date: Jan 10, 2019
:last_modified: March 09, 2021
:last_modified: Aug 11, 2021
:author: @yshah, @kpanchal
"""
import csv
import os
import time
from http import HTTPStatus

import pytest
from selenium.webdriver import ChromeOptions
from selenium.webdriver.support.expected_conditions import invisibility_of_element_located, \
    visibility_of_element_located

from catium.helpers.sleep_lib import sleep
from catium.helpers.testdata import get_file_path
from catium.helpers.util import get_browser_download_file_path
from catium.lib.config import Config
from catium.lib.const.base_constants import WAIT_SHORT, WAIT_NORMAL, TIME_THREE_SECONDS, TIME_TEN_MINUTES, \
    TIME_TEN_SECONDS, TIME_FIFTEEN_SECONDS, GRID_BROWSER_DOWNLOAD_PATH, WAIT_LONG, TIME_THIRTY_SECONDS, \
    TIME_TWENTY_SECONDS, TIME_SIXTY_SECONDS, TIME_FIVE_SECONDS
from catium.lib.log import create_logger
from catium.lib.webium.wait import wait
from catium.lib.webium.windows_handler import WindowsHandler
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.polling_ui import polling_ui
from nessus.helpers.scan import download_and_save_exported_scan_file, get_scan_results_export_options, \
    revert_save_as_default_option_to_system
from nessus.helpers.scan import get_scan_id
from nessus.helpers.utility import get_downloaded_files_chrome
from nessus.helpers.waiters import wait_scan_state
from nessus.lib.config import NessusConfig
from nessus.lib.const import Nessus, random_name
from nessus.lib.const.constants import API
from nessus.lib.message.messages import Messages
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import NotificationActions, Notifications
from nessus.pageobjects.header.user_menu import UserMenu
from nessus.pageobjects.login.login_page import LoginPage
from nessus.pageobjects.plugins.plugins_page import Plugin, PluginFamilyList
from nessus.pageobjects.scans.scan_view_page import ScanViewPage, ScanExportPage, ScansHostList, VulnerabilityList, \
    ScanHistoryList, ThreatLevelVulnerabilityList
from nessus.pageobjects.scans.scans_page import ScanList, ScansPage
from nessus.pageobjects.shared.loading import LoadingCircle

log = create_logger()
timestamped_path = 'exported_scan' + str(int(time.time()))  # use timestamp to differentiate test


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


@pytest.mark.scanning
@pytest.mark.nessus_home
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('wait_for_plugin_families_to_be_available', 'nessus_api_login', 'login')
class TestCreatedScanResults:
    """ Test case for Export scan results page of created scan. """

    cat = None

    # Disable __class__ warnings as they are valid python but pylint can't handle them properly
    # pylint: disable=undefined-variable
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
            LoadingCircle(TIME_TEN_SECONDS)
            if navigate_to_scan_result:
                ScanList().click_on_scan(scan_name=scan_name)
                LoadingCircle(WAIT_NORMAL)
            return scan_details
        else:
            # Skipping the test if scan took more than 20 minutes to be in completed state
            pytest.xfail(
                reason="Scan running for more than 20 minutes and still not completed, hence no scan result found.")
            __class__.cat.api.scans.stop(scan_id)
            wait_scan_state(api=__class__.cat.api, end_state=API.Scan.Status.CANCELED, scan_id=scan_id,
                            timeout=TIME_FIFTEEN_SECONDS)

    @pytest.mark.parametrize("format_type", [API.Scan.UIExportFormats.FORMAT_HTML, API.Scan.UIExportFormats.FORMAT_PDF,
                                             API.Scan.UIExportFormats.FORMAT_CSV])
    @pytest.mark.parametrize("select_type", ["Host", "Vulnerabilities"])
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_Scan_Result.db', 'password': 'nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/',
                                                      'encrypted': True}], indirect=True)
    def test_display_the_number_of_host_or_vul_selected_for_filtered_report(self, import_scan_via_api, select_type,
                                                                            format_type):
        """
        NES-9255: UI Automated Tests for filtered scan reports

        Scenarios tested:
        [x] Selecting any option in the report dropdown must display the number of host/vulnerability if selected.
        [x] Report dropdown contains PDF, HTML, CSV.

        Steps:
        1. Import a scan.
        2. Select Hosts/Vulnerabilities and click on Report dropdown.
        3. Verify the selected Hosts/Vulnerabilities display in the modal title, i.e. 2 Hosts/ 2 Vulnerabilities based
           on Host or Vulnerabilities selected in step #2
        """
        scan_name = import_scan_via_api[0]
        ScansPage().refresh()

        # Click on scan
        ScanList().click_on_scan(scan_name=scan_name)
        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present("header_element", timeout=TIME_THIRTY_SECONDS),
             waiting_for="Scan header to visible")
        vulnerability_list = VulnerabilityList()

        if select_type == "Vulnerabilities":
            scan_view_page.vulnerability_tab.click()
            vulnerability_list.vulnerability_setting.click()
            vulnerability_list.enable_disable_groups.click() \
                if vulnerability_list.enable_disable_groups.text == "Disable Groups" else vulnerability_list. \
                vulnerability_setting.click()
            LoadingCircle(WAIT_NORMAL)

            # Select vulnerabilities as mentioned in list
            vulnerability_list.select_vulnerabilities(vulnerabilities_list=API.Scan.VulnerabilitiesDetails.
                                                      Vulnerability_selected_in_basic_network_scan)
        else:
            scan_view_page.host_tab.click()
            wait(lambda: scan_view_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

            # Select hosts as mentioned in list
            ScansHostList().select_hosts(hosts_list=API.Scan.VulnerabilitiesDetails.Host_selected_in_basic_network_scan)

        scan_view_page.report_button.click()
        action_modal = ActionCloseModal()
        wait(lambda: action_modal.is_element_present('modal', timeout=TIME_THIRTY_SECONDS),
             waiting_for='modal to appear.')

        # Verify the modal title must contain the correct digit with host/vulnerability selected before click on report
        # dropdown.
        assert action_modal.modal_title.text.split('-')[1].rsplit(" ", 1)[0].strip() == "2 Hosts" \
            if select_type == "Host" else "2 Vulnerabilities", "Host/Vulnerability with count is missing"

        action_modal.close_button.click()

    @pytest.mark.browser_file_download
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_Scan_Result.db', 'password': 'nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/',
                                                      'encrypted': True}], indirect=True)
    def test_verification_of_csv_exported_data_for_host_using_advance_filter(self, import_scan_via_api):
        """
        NES-9255: UI Automated Tests for filtered scan reports

        Scenarios tested:
        [x] Selecting any option in report dropdown must display the number of host/vulnerability if selected.
        [x] Report dropdown contains PDF, HTML, CSV.

        Steps:
        1. Import a scan.
        2. Select Hosts/Vulnerabilities and click on Report dropdown.
        3. Verify the selected Hosts/Vulnerabilities display in the title of the modal, i.e. 2 Hosts/ 2 Vulnerabilities
           based on Host or Vulnerabilities selected in step #2
        """
        host = API.Scan.VulnerabilitiesDetails.Host_selected_in_basic_network_scan[0]
        scan_name = import_scan_via_api[0]
        ScansPage().refresh()
        ScanList().click_on_scan(scan_name=scan_name)

        scan_view_page = ScanViewPage()
        LoadingCircle(WAIT_LONG)
        scan_view_page.vulnerability_tab.click()

        NotificationActions().remove_all()

        # Apply advanced filter
        scan_view_page.apply_filter(key=Nessus.Filter.FilterKeys.HOSTNAME,
                                    operator=Nessus.Filter.FilterOperators.EQUAL_TO,
                                    value=host)
        LoadingCircle(WAIT_LONG)

        scan_view_page.report_button.click()
        action_modal = ActionCloseModal()
        wait(lambda: action_modal.is_element_present("modal"), waiting_for='CSV export modal to open')

        scan_view_page.get_element_for_report_format_radio_button(
            report_format=API.Scan.UIExportFormats.FORMAT_CSV).click()
        scan_export_page = ScanExportPage()
        wait(lambda: scan_export_page.is_element_present("clear_link"),
             waiting_for="Selected report options get displayed")

        scan_export_page.generate_report_button.click()
        action_modal.wait_for_modal_closed()
        sleep(sleep_time=TIME_FIFTEEN_SECONDS, reason='waiting for file to download')

        downloaded_file_name = get_downloaded_files_chrome(filename="Basic_Network_Scan")
        log.info("Downloaded file path :: :: %s", downloaded_file_name)
        file_name = downloaded_file_name[0].split('//')[1].split('/')[-1]

        directory = os.path.join(Config.CAT_LOCAL_BROWSER_DOWNLOAD_PATH, timestamped_path, file_name)
        log.info("Downloaded file directory :: :: %s", directory)
        source_path = get_browser_download_file_path(directory)

        count = 0
        with open(file=source_path, mode='rt') as csv_file:
            raw_data = csv.reader(csv_file, delimiter=',')

            assert next(raw_data, None), 'Exported scan CSV file should not be blank.'

            for row in raw_data:
                count += 1
                # Verify the host value in CSV file should be filtered host value
                assert row[4] == host, 'Host value in CSV file data of exported scan is different ' \
                                       'for {} host filter.'.format(host)
            assert count > 0, 'The CSV file does not have 2 or more rows.'

    @pytest.mark.grid_only
    @pytest.mark.browser_file_download
    @pytest.mark.parametrize("select_type", ["Host", "Vulnerabilities"])
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_Scan_Result.db', 'password': 'nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/',
                                                      'encrypted': True}], indirect=True)
    def test_verification_of_csv_exported_data_for_filtered_host_or_vuln(self, import_scan_via_api, select_type):
        """
        NES-9255: UI Automated Tests for filtered scan reports

        Scenarios tested:
        [x] Selecting host or vulnerability on scan result page should be reported in the title of the report modal

        Steps:
        1. Import a scan.
        2. Select Hosts/Vulnerabilities  and click on Report dropdown.
        3. Verify selected host or vulnerability on scan result page must match the host/vulnerability in CSV reported
        file.
        """
        scan_name = import_scan_via_api[0]
        ScansPage().refresh()
        ScanList().click_on_scan(scan_name=scan_name)

        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present("header_element", timeout=TIME_THIRTY_SECONDS),
             waiting_for="Scan header to visible")
        vulnerability_list = VulnerabilityList()

        if select_type == "Vulnerabilities":
            scan_view_page.vulnerability_tab.click()
            vulnerability_list.vulnerability_setting.click()
            vulnerability_list.enable_disable_groups.click() \
                if vulnerability_list.enable_disable_groups.text == "Disable Groups" else VulnerabilityList(). \
                vulnerability_setting.click()
            LoadingCircle(WAIT_NORMAL)

            # Select vulnerabilities as mentioned in list
            vulnerability_list.select_vulnerabilities(vulnerabilities_list=API.Scan.VulnerabilitiesDetails.
                                                      Vulnerability_selected_in_basic_network_scan)
        else:
            # Select hosts as mentioned in list
            ScansHostList().select_hosts(hosts_list=API.Scan.VulnerabilitiesDetails.Host_selected_in_basic_network_scan)

        scan_view_page.report_button.click()
        action_modal = ActionCloseModal()
        wait(lambda: action_modal.is_element_present("modal"), waiting_for='CSV export modal to open')

        scan_view_page.get_element_for_report_format_radio_button(
            report_format=API.Scan.UIExportFormats.FORMAT_CSV).click()
        scan_export_page = ScanExportPage()
        wait(lambda: scan_export_page.is_element_present("clear_link"),
             waiting_for="Selected report options get displayed")

        scan_export_page.generate_report_button.click()
        action_modal.wait_for_modal_closed()
        sleep(sleep_time=TIME_FIFTEEN_SECONDS, reason='waiting for file to download')

        downloaded_file_name = get_downloaded_files_chrome(filename="Basic_Network_Scan")
        log.info("Downloaded file path :: :: %s", downloaded_file_name)
        file_name = downloaded_file_name[0].split('//')[1].split('/')[-1]

        directory = os.path.join(Config.CAT_LOCAL_BROWSER_DOWNLOAD_PATH, timestamped_path, file_name)
        log.info("Downloaded file directory :: :: %s", directory)
        source_path = get_browser_download_file_path(directory)

        with open(file=source_path, mode='rt') as csv_file:
            raw_data = csv.reader(csv_file, delimiter=',')

            assert next(raw_data, None), 'Exported scan CSV file should not be blank.'

            for row in raw_data:
                if select_type == "Host":
                    # Verify the host value in CSV must exist in the selected host list
                    assert row[4] in API.Scan.VulnerabilitiesDetails.Host_selected_in_basic_network_scan, \
                        "Different host {} is found than host selected before exporting".format(row[4])
                else:
                    # Verify the vulnerability value in CSV must exist in the selected vulnerability list
                    assert row[7] in API.Scan.VulnerabilitiesDetails.Vulnerability_selected_in_basic_network_scan, \
                        "Different vulnerability {} is found than vulnerability selected before exporting"

    @pytest.mark.browser_file_download
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_Scan_Result.db', 'password': 'nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/',
                                                      'encrypted': True}], indirect=True)
    @pytest.mark.parametrize('host_vuln', [
        # any host or single vuln in the scan results will work
        {'vuln': API.Scan.VulnerabilitiesDetails.Vulnerability_id_in_basic_network_scan[0]},
        {'host': API.Scan.VulnerabilitiesDetails.Host_selected_in_basic_network_scan[1]},
        {'vuln': API.Scan.VulnerabilitiesDetails.Vulnerability_id_in_basic_network_scan[0],
         'host': API.Scan.VulnerabilitiesDetails.Host_selected_in_basic_network_scan[1]}
    ])
    def test_report_drilldown(self, import_scan_via_api, host_vuln):
        """
        NES-8794: Filter Scan Reports by Checkbox

        Scenarios tested:
        [x] Generating a report after selecting a host only reports that host
        [x] Generating a report after selecting a vuln only reports that vuln

        Steps:
        1. Import a scan.
        2. Click a Host and/or Vulnerability.
        3. Generate report and verify it only contains the data for that page.
        """
        scan_name = import_scan_via_api[0]
        ScansPage().refresh()
        ScanList().click_on_scan(scan_name=scan_name)

        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present("vulnerability_tab"))

        if 'host' in host_vuln and 'vuln' in host_vuln:
            host = host_vuln['host']
            vuln_id = host_vuln['vuln']
            scans_host_list = ScansHostList()
            scans_host_list.click_on_host(host)
            wait(lambda: scan_view_page.is_element_present("search_box"))

            vulnerability_list = VulnerabilityList()
            vulnerability_list.find_vulnerability_by_id(vuln_id).click()
            wait(lambda: vulnerability_list.is_element_present("output_header"))

        elif 'vuln' in host_vuln:
            vuln_id = host_vuln['vuln']
            scan_view_page.vulnerability_tab.click()
            wait(lambda: scan_view_page.is_element_present("search_box"))

            vulnerability_list = VulnerabilityList()
            vulnerability_list.find_vulnerability_by_id(vuln_id).click()
            wait(lambda: vulnerability_list.is_element_present("output_header"))

        elif 'host' in host_vuln:
            host = host_vuln['host']
            scans_host_list = ScansHostList()
            scans_host_list.click_on_host(host)
            wait(lambda: scan_view_page.is_element_present("search_box"))

        def verify_modal_title():
            scan_view_page.report_button.click()
            action_modal = ActionCloseModal()
            wait(lambda: action_modal.is_element_present('modal', timeout=TIME_THIRTY_SECONDS),
                 waiting_for='modal to appear.')
            selection = action_modal.modal_title.text.split('-')[1].strip()

            if 'vuln' in host_vuln:
                assert selection == '1 Vulnerability Selected'
            else:
                assert selection == '1 Host Selected'

            action_modal.close_button.click()
            action_modal.wait_for_modal_closed()

        verify_modal_title()
        scan_view_page.export_scan_in_format(format_type=API.Scan.UIExportFormats.FORMAT_CSV, report_flag=True)

        downloaded_files = get_downloaded_files_chrome(filename="Basic_Network_Scan")
        log.debug("Downloaded file urls: %s", downloaded_files)
        downloaded_file = downloaded_files[0].split('//')[1].split('/')[-1]
        downloaded_file = os.path.join(Config.CAT_LOCAL_BROWSER_DOWNLOAD_PATH, timestamped_path, downloaded_file)
        downloaded_file = get_browser_download_file_path(downloaded_file)
        log.debug("Local filename: %s", downloaded_file)

        def verify_csv():
            # Check the "Plugin ID" and "Host" columns of a CSV download against filters
            with open(downloaded_file) as csv_file:
                csv_reader = csv.reader(csv_file, delimiter=',', quotechar='"', escapechar='\\')
                _ = next(csv_reader)
                for line in csv_reader:
                    vuln = int(line[0])
                    host = line[4]
                    if 'vuln' in host_vuln:
                        assert vuln == host_vuln['vuln'], \
                            "CSV contained a plugin id not filtered for: %s" % vuln
                    if 'host' in host_vuln:
                        assert host == host_vuln['host'], \
                            "CSV contained a host not filtered for: %d" % host

        verify_csv()

    @pytest.mark.browser_file_download
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_Scan_Result.db', 'password': 'nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/',
                                                      'encrypted': True}], indirect=True)
    @pytest.mark.parametrize('host_drilldown', [True, False])
    def test_report_grouped_vulns(self, import_scan_via_api, host_drilldown):
        """
        NES-8794: Filter Scan Reports by Checkbox

        Scenarios tested:
        [x] Generating a report for a vulnerability group only contains that group's vulns
        [x] Generating a report for a host and vulnerability group only contains that host+group's vulns

        Steps:
        1. Import a scan.
        2. Optionally click a host in that scan
        2. Click a grouped Vulnerability
        3. Generate report and verify it only contains the data for that group (and host if applicable).
        """
        report_format = API.Scan.UIExportFormats.FORMAT_CSV
        scan_name = import_scan_via_api[0]
        ScansPage().refresh()
        ScanList().click_on_scan(scan_name=scan_name)

        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present("vulnerability_tab"), waiting_for='Vulnerabilities to get loads')

        scan_view_page.vulnerability_tab.click()
        wait(lambda: scan_view_page.is_element_present("search_box"), waiting_for='Vulnerabilities to get loads')

        vulnerability_list = VulnerabilityList()
        vulnerability_list.vulnerability_setting.click()
        vulnerability_list.click_on_group_enable_disable(enable=True)

        vulnerability_list.refresh()
        wait(lambda: visibility_of_element_located(vulnerability_list.vulnerability_setting),
             waiting_for='vulnerability list to populate')

        expected_vulns = None

        def click_on_grouped_vulnerabilities(vuln_name: str):
            for vulnerability in vulnerability_list.rows:
                if vulnerability.cvss_score_value == "..." and vuln_name in vulnerability.plugin_name.text:
                    vulnerability.click()
                    break

        if host_drilldown:
            # click into a host, then a vulnerability group
            scan_view_page.host_tab.click()
            wait(lambda: scan_view_page.is_element_present("search_box"), waiting_for='Vulnerabilities to get loads')

            ScansHostList().click_on_host(host_name=API.Scan.VulnerabilitiesDetails.Grouped_vulnerability_one_host)
            wait(lambda: scan_view_page.is_element_present("search_box"), waiting_for='Vulnerabilities to get loads')

            expected_vulns = API.Scan.VulnerabilitiesDetails.Grouped_vulnerability_one_host_results
            grouped_vulnerability_details = vulnerability_list.get_grouped_vulnerabilities_name_and_family()

            scan_view_page.move_to_element(element=scan_view_page.vulnerability_tab)
            click_on_grouped_vulnerabilities(vuln_name=list(grouped_vulnerability_details.keys())[1])
            wait(lambda: scan_view_page.is_element_present("search_box"), waiting_for='Vulnerabilities to get loads')
        else:
            # click into a vulnerability group
            scan_view_page.vulnerability_tab.click()
            wait(lambda: scan_view_page.is_element_present("search_box"), waiting_for='Vulnerabilities to get loads')

            expected_vulns = API.Scan.VulnerabilitiesDetails.Grouped_vulnerability_ids
            grouped_vulnerability_details = vulnerability_list.get_grouped_vulnerabilities_name_and_family()

            scan_view_page.move_to_element(element=scan_view_page.vulnerability_tab)
            click_on_grouped_vulnerabilities(vuln_name=list(grouped_vulnerability_details.keys())[0])
            wait(lambda: scan_view_page.is_element_present("search_box"), waiting_for='Vulnerabilities to get loads')

        scan_export_page = ScanExportPage()

        def verify_modal_title():
            scan_view_page.report_button.click()
            action_modal = ActionCloseModal()
            wait(lambda: action_modal.is_element_present('modal', timeout=TIME_THIRTY_SECONDS),
                 waiting_for='modal to appear.')

            scan_view_page.get_element_for_report_format_radio_button(report_format=report_format).click()
            wait(lambda: scan_export_page.is_element_present("clear_link"),
                 waiting_for="CSV report options get displayed")
            selection = action_modal.modal_title.text.split('-')[1].strip()

            assert selection == '%d Vulnerabilities Selected' % len(set(expected_vulns))

        verify_modal_title()
        scan_export_page.generate_report_button.click()
        ActionCloseModal().wait_for_modal_closed()

        downloaded_files = get_downloaded_files_chrome(filename="Basic_Network_Scan")
        log.debug("Downloaded file urls: %s", downloaded_files)

        downloaded_file = downloaded_files[0].split('//')[1].split('/')[-1]
        downloaded_file = os.path.join(Config.CAT_LOCAL_BROWSER_DOWNLOAD_PATH, timestamped_path, downloaded_file)
        downloaded_file = get_browser_download_file_path(downloaded_file)
        log.debug("Local filename: %s", downloaded_file)

        def verify_csv():
            # Check the "Plugin ID" columns of a CSV download against filters
            with open(downloaded_file) as csvfile:
                csvreader = csv.reader(csvfile, delimiter=',', quotechar='"', escapechar='\\')
                _ = next(csvreader)
                found_vulns = []
                for line in csvreader:
                    vuln = int(line[0])
                    found_vulns.append(vuln)
                assert sorted(found_vulns) == sorted(expected_vulns)

        verify_csv()

    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.BASIC_NETWORK, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'folder': Nessus.Scan.Folder.MY_SCANS.split(' (')[0], 'target_ip': Nessus.Scan.Target.LOCALHOST,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.WANNACRY))}]}], indirect=True)
    def test_export_scan_in_different_format(self, create_scans):
        """
        Test to export scan in different formats from scan_result page.
        1. Click on the scan to view the results page.
        2. Click on the “Export” drop-down and choose a format to export.
        3. It might ask you for password depending upon which format you have chosen to export.
        4. Click on “Export” button on confirmation pop-up.
        """
        self.__class__.configure_and_launch_scan(scan_name=create_scans[0])
        scan_result_page = ScanViewPage()
        LoadingCircle(WAIT_SHORT)

        for export_format in API.Scan.UIExportFormats.VALID_FORMATS:
            scan_result_page.export_scan_in_format(format_type=export_format)
            wait(lambda: not WindowsHandler().is_alert_present(), timeout_seconds=TIME_THIRTY_SECONDS,
                 sleep_seconds=TIME_FIVE_SECONDS)
            assert not WindowsHandler().is_alert_present(), 'Export has failed.'

        scan_result_page.back_link.click()

    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_Scan_Result.db', 'password': 'nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/',
                                                      'encrypted': True}], indirect=True)
    @pytest.mark.parametrize("format_type", [API.Scan.UIExportFormats.FORMAT_HTML, API.Scan.UIExportFormats.FORMAT_PDF,
                                             API.Scan.UIExportFormats.FORMAT_CSV])
    @pytest.mark.parametrize("flag", [True, False])
    def test_export_scan_with_select_deselect_export_options(self, import_scan_via_api, format_type, flag):
        """
        NES-8592: [Testing] Automation Testing for the UI changes

        Scenarios tested:
        [x] Select All data points displayed in Vulnerabilities Details and verify user should be able to export the
        report ( we will not be verifying the content. We will just verify that report has been exported)
        [x] Uncheck ALL data points displayed in Vulnerabilities Details section and verify that report should be
        exported successfully.

        NES-8998: Automation UI for Nessus .csv Export

        Scenarios tested:
        [x] Select all CSV column options displayed in model section and verify that scan report should be exported
            successfully. (we will not be verifying the content. We will just verify that report has been exported)
        [x] Uncheck all CSV column options displayed in model section and verify that scan report should not be
            exported and gives error message "Error: No columns selected for CSV export.".
        """
        scan_name = import_scan_via_api[0]
        ScansPage().refresh()
        ScanList().click_on_scan(scan_name=scan_name)

        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present("report_button"))

        scan_view_page.report_button.click()
        wait(lambda: ActionCloseModal().modal, waiting_for='CSV export modal to open')
        scan_export_page = ScanExportPage()

        scan_view_page.get_element_for_report_format_radio_button(report_format=format_type).click()
        wait(lambda: scan_export_page.is_element_present("clear_link") or scan_export_page.is_element_present(
            "template_description_label"), waiting_for="Selected report options get displayed")

        if format_type == API.Scan.UIExportFormats.FORMAT_CSV:
            options_name = scan_export_page.get_text_from_custom_option_check_box(
                element=scan_export_page.export_csv_options)

            scan_export_page.select_and_deselect_all_options(option_name=options_name, flag=flag)
        scan_export_page.generate_report_button.click()
        if format_type == API.Scan.UIExportFormats.FORMAT_CSV and not flag:
            notification = Notifications()

            assert notification.errors[-1] == Messages.NotificationMessages.export_csv_error, \
                "Error notification is mismatched or missing while export scan in CSV format with no columns."

            scan_export_page.cancel_button.click()
        else:
            wait(lambda: not ActionCloseModal().is_element_present('modal'), waiting_for='export modal to close.')

            sleep(sleep_time=TIME_TWENTY_SECONDS, reason='waiting for file to download')
            downloaded_files = get_downloaded_files_chrome()
            log.info("Downloaded file path :: :: %s", downloaded_files)

            file_name = scan_name.split(".")[0]

            assert file_name in downloaded_files, "Scan results does not exported successfully."

        scan_view_page.back_link.click()

    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_Scan_Result.db', 'password': 'nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/',
                                                      'encrypted': True}], indirect=True)
    @pytest.mark.parametrize("format_type", [API.Scan.UIExportFormats.FORMAT_CSV])
    def test_export_format_options_checkbox_on_initial_load(self, import_scan_via_api, format_type):
        """
        NES-8592: [Testing] Automation Testing for the UI changes
        NES-8998: Automation UI for Nessus .csv Export

        Scenarios tested:
        [x] Upon initial load, ALL data points displayed in Vulnerabilities Details section should be checked.
        [x] Upon initial load, First 13 CSV column options displayed in model section should be checked and rest of the
            CSV column options should be unchecked.
        """
        scan_name = import_scan_via_api[0]
        ScansPage().refresh()
        ScanList().click_on_scan(scan_name=scan_name)

        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present("report_button"))

        scan_view_page.report_button.click()
        wait(lambda: ActionCloseModal().modal, waiting_for='CSV export modal to open')

        scan_export_page = ScanExportPage()
        scan_view_page.get_element_for_report_format_radio_button(report_format=format_type).click()
        wait(lambda: scan_export_page.is_element_present("clear_link") or scan_export_page.is_element_present(
            "hide_system_template_checkbox"), waiting_for="Selected report options get displayed")

        options_name = scan_export_page.get_text_from_custom_option_check_box(
            element=scan_export_page.export_csv_options)

        for option in options_name:
            if option in options_name[13::]:
                assert not scan_export_page.get_custom_option_checkbox(option_name=option).is_selected(), \
                    'Export option {} under {} is selected on initial load.'.format(option, format_type)

        scan_export_page.cancel_button.click()
        scan_view_page.back_link.click()

    @pytest.mark.grid_only
    @pytest.mark.browser_file_download
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_Scan_Result.db', 'password': 'nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/',
                                                      'encrypted': True}], indirect=True)
    @pytest.mark.parametrize('severity_value', [Nessus.Scan.Severity.CRITICAL, Nessus.Scan.Severity.HIGH,
                                                Nessus.Scan.Severity.MEDIUM, Nessus.Scan.Severity.LOW])
    def test_exported_csv_data(self, import_scan_via_api, severity_value):
        """ NES-8786: Create Automation Test: Client's CSV Export is missing Critical Results

        Scenarios Tested:
        [x] Verify exported CSV file data is not missing after filtering the vulnerabilities of scan.
        """
        scan_name = import_scan_via_api[0]
        ScansPage().refresh()
        ScanList().click_on_scan(scan_name=scan_name)

        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present("vulnerability_tab"))
        scan_view_page.vulnerability_tab.click()

        NotificationActions().remove_all()
        scan_view_page.apply_filter(key=Nessus.Filter.FilterKeys.SEVERITY,
                                    operator=Nessus.Filter.FilterOperators.EQUAL_TO, value=severity_value)
        LoadingCircle(WAIT_LONG)

        scan_view_page.report_button.click()
        wait(lambda: ActionCloseModal().modal, waiting_for='CSV export modal to open')

        scan_view_page.get_element_for_report_format_radio_button(
            report_format=API.Scan.UIExportFormats.FORMAT_CSV).click()
        scan_export_page = ScanExportPage()
        wait(lambda: scan_export_page.is_element_present("clear_link"), waiting_for="CSV report options get displayed")

        scan_export_page.generate_report_button.click()
        ActionCloseModal().wait_for_modal_closed()

        downloaded_file_name = get_downloaded_files_chrome(filename="Basic_Network_Scan")
        log.info("Downloaded file path :: :: %s", downloaded_file_name)
        file_name = downloaded_file_name[0].split('//')[1].split('/')[-1]

        directory = os.path.join(Config.CAT_LOCAL_BROWSER_DOWNLOAD_PATH, timestamped_path, file_name)
        log.info("Downloaded file directory :: :: %s", directory)
        source_path = get_browser_download_file_path(directory)

        count = 0
        with open(file=source_path, mode='rt') as csv_file:
            raw_data = csv.reader(csv_file, delimiter=',')

            assert next(raw_data, None), 'Exported scan CSV file should not be blank.'

            for row in raw_data:
                count += 1
                assert row[3] == severity_value, 'Severity value in CSV file data of exported scan is different ' \
                                                 'for {} severity filter.'.format(severity_value)
            assert count > 0, 'The CSV file does not have 2 or more rows.'

    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_Scan_Result.db', 'password': 'nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/',
                                                      'encrypted': True}], indirect=True)
    def test_select_all_clear_and_system_link_for_csv_export_model(self, import_scan_via_api):
        """
        NES-8998: Automation UI for Nessus .csv Export

        Scenarios Tested:
        [x] Verify that "Select All" link should select all the CSV column options.
        [x] Verify that "Clear" link should clear all the CSV column options.
        [x] Verify that when all the CSV column options are selected, "Select All" should become text only (not link).
        [x] Verify that when no CSV column options are selected, "Reset" should become text only (not link).
        [x] Verify that "System" link should reset to default all CSV column options.
        """
        scan_name = import_scan_via_api[0]
        ScansPage().refresh()
        ScanList().click_on_scan(scan_name=scan_name)

        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present("report_button"))

        scan_view_page.report_button.click()
        wait(lambda: ActionCloseModal().modal, waiting_for='CSV export modal to open')

        scan_view_page.get_element_for_report_format_radio_button(
            report_format=API.Scan.UIExportFormats.FORMAT_CSV).click()
        scan_export_page = ScanExportPage()
        wait(lambda: scan_export_page.is_element_present("clear_link"), waiting_for="CSV report options get displayed")

        csv_column_options = scan_export_page.get_text_from_custom_option_check_box(
            element=scan_export_page.export_csv_options)

        select_all_link = scan_export_page.get_select_all_and_clear_link_element(
            element_name=API.Scan.VulnerabilitiesDetails.SELECT_ALL.lower().replace(" ", "-"))
        select_all = scan_export_page.get_select_all_and_clear_text_element(
            element_name=API.Scan.VulnerabilitiesDetails.SELECT_ALL.lower().replace(" ", "-"))

        clear_link = scan_export_page.get_select_all_and_clear_link_element(
            element_name=API.Scan.VulnerabilitiesDetails.CLEAR.lower())
        clear = scan_export_page.get_select_all_and_clear_text_element(
            element_name=API.Scan.VulnerabilitiesDetails.CLEAR.lower())

        system_link = scan_export_page.get_select_all_and_clear_link_element(element_name='reset')
        system = scan_export_page.get_select_all_and_clear_text_element(element_name='reset')

        scan_export_page.clear_link.click()

        for option in csv_column_options:
            assert not scan_export_page.get_custom_option_checkbox(option_name=option).is_selected(), \
                "Export CSV column option '{}' is still selected after click on 'Clear' link.".format(option)

        assert invisibility_of_element_located(clear_link) and clear.is_displayed(), \
            "'Clear' is still displayed as link after uncheck all checkbox from CSV export model."

        assert scan_export_page.select_all_link.is_displayed() and scan_export_page.system_link.is_displayed(), \
            "'Select All' and 'System' is not displayed as a link."

        scan_export_page.select_and_deselect_all_options(option_name=csv_column_options[1::2], flag=True)

        assert scan_export_page.clear_link.is_displayed() and invisibility_of_element_located(clear), \
            "'Clear' is still displayed as text after selecting few of checkboxes from CSV export model."

        scan_export_page.clear_link.click()

        for option in csv_column_options:
            assert not scan_export_page.get_custom_option_checkbox(option_name=option).is_selected(), \
                "Export CSV column option '{}' is still selected after click on 'Clear' link.".format(option)

        scan_export_page.select_all_link.click()

        for option in csv_column_options:
            assert scan_export_page.get_custom_option_checkbox(option_name=option).is_selected(), \
                "Export CSV column option '{}' is not selected after click on 'Select All' link".format(option)

        assert invisibility_of_element_located(select_all_link) and select_all.is_displayed(), \
            "'Select All' is still displayed as link after selecting all checkboxes from CSV export model."

        assert scan_export_page.clear_link.is_displayed() and scan_export_page.system_link.is_displayed(), \
            "'Clear' and 'System' is not displayed as a link."

        scan_export_page.select_and_deselect_all_options(option_name=csv_column_options[1::2], flag=False)

        assert invisibility_of_element_located(select_all) and scan_export_page.select_all_link.is_displayed(), \
            "'Select All' is still displayed as text after uncheck all checkboxes from CSV export model."

        scan_export_page.select_all_link.click()

        for option in csv_column_options:
            assert scan_export_page.get_custom_option_checkbox(option_name=option).is_selected(), \
                "Export CSV column option '{}' is not selected after click on 'Select All' link".format(option)

        scan_export_page.system_link.click()

        for option in csv_column_options:
            if option in csv_column_options[13::]:
                assert not scan_export_page.get_custom_option_checkbox(option_name=option).is_selected(), \
                    "Export CSV column option '{}' is selected after click on 'Select All' link".format(option)
            else:
                assert scan_export_page.get_custom_option_checkbox(option_name=option).is_selected(), \
                    "Export CSV column option '{}' is not selected after click on 'Select All' link".format(option)

        assert invisibility_of_element_located(system_link) and system.is_displayed(), \
            "'System' is still displayed as link after checked system default checkbox from CSV export modal."

        assert scan_export_page.select_all_link.is_displayed() and scan_export_page.clear_link.is_displayed(), \
            "'Select All' and 'Clear' is not displayed as a link."

        scan_export_page.select_and_deselect_all_options(option_name=csv_column_options[:5], flag=False)

        assert invisibility_of_element_located(system) and scan_export_page.system_link.is_displayed(), \
            "'System' is not displayed as link after unchecked few checkbox from system default checkbox."

        scan_export_page.cancel_button.click()

    @pytest.mark.grid_only
    @pytest.mark.browser_file_download
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_Scan_Result.db', 'password': 'nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/',
                                                      'encrypted': True}], indirect=True)
    def test_export_scan_with_few_selected_csv_column_options(self, import_scan_via_api):
        """
        NES-8998: Automation UI for Nessus .csv Export

        Scenarios tested:
        [x] Select few of CSV column options displayed in model section and verify that report should be
            exported successfully.
        [x] Select few of CSV column options displayed in model section and verify that selected CSV columns should be
            present in exported CSV file.
        """
        scan_name = import_scan_via_api[0]
        ScansPage().refresh()
        ScanList().click_on_scan(scan_name=scan_name)

        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present("report_button"))

        scan_view_page.report_button.click()
        wait(lambda: ActionCloseModal().modal, waiting_for='CSV export modal to open')

        scan_view_page.get_element_for_report_format_radio_button(
            report_format=API.Scan.UIExportFormats.FORMAT_CSV).click()
        scan_export_page = ScanExportPage()
        wait(lambda: scan_export_page.is_element_present("clear_link"), waiting_for="CSV report options get displayed")

        csv_columns = scan_export_page.get_name_of_export_option(element=scan_export_page.export_csv_options)[:18]
        options_name = scan_export_page.get_text_from_custom_option_check_box(
            element=scan_export_page.export_csv_options)[:18]

        scan_export_page.system_link.click()

        scan_export_page.select_all_link.click()
        scan_export_page.select_and_deselect_all_options(option_name=options_name[::2], flag=False)
        scan_export_page.generate_report_button.click()
        ActionCloseModal().wait_for_modal_closed()

        sleep(sleep_time=TIME_FIFTEEN_SECONDS, reason='waiting for file to download')
        downloaded_files = get_downloaded_files_chrome(filename="Basic_Network_Scan")
        log.info("Downloaded file path :: :: %s", downloaded_files)

        file_name = downloaded_files[0].split('//')[1].split('/')[-1]
        assert file_name, "Scan results does not exported successfully."

        directory = os.path.join(Config.CAT_LOCAL_BROWSER_DOWNLOAD_PATH, timestamped_path, file_name)
        source_path = get_browser_download_file_path(directory)

        with open(file=source_path, mode='rt') as csv_file:
            raw_data = csv.reader(csv_file, delimiter=',')
            csv_column_header = list(raw_data)[0]

            assert all([column in csv_column_header for column in csv_columns[1::2]]), \
                'Selected CSV columns from export csv model and CSV columns from exported file are different.'

        scan_view_page.back_link.click()

    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_Scan_Result.db', 'password': 'nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/',
                                                      'encrypted': True}], indirect=True)
    @pytest.mark.parametrize("save_as_default", [False, True])
    def test_export_csv_options_after_save_as_default(self, import_scan_via_api, save_as_default):
        """
        NES-8998: Automation UI for Nessus .csv Export

        Scenarios tested:
        [x] Verify that when "Save as Default" checkbox is checked, the selected columns will be saved and when next
            time the Modal shows up, the saved selections will be loaded.
        """
        export_format_type = API.Scan.UIExportFormats.FORMAT_CSV
        scan_name = import_scan_via_api[0]
        ScansPage().refresh()
        ScanList().click_on_scan(scan_name=scan_name)

        try:
            scan_view_page = ScanViewPage()
            wait(lambda: scan_view_page.is_element_present("report_button"))

            scan_view_page.report_button.click()
            wait(lambda: ActionCloseModal().modal, waiting_for='CSV export modal to open')

            scan_view_page.get_element_for_report_format_radio_button(report_format=export_format_type).click()
            scan_export_page = ScanExportPage()
            wait(lambda: scan_export_page.is_element_present("clear_link") or scan_export_page.is_element_present(
                "hide_system_template_checkbox"), waiting_for="Selected report options get displayed")

            assert scan_export_page.save_as_default.is_displayed() and not \
                scan_export_page.save_as_default.is_selected(), \
                "'Save as default' checkbox is not selected by-default or 'Save as default' checkbox is invisible."

            csv_columns = scan_export_page.get_text_from_custom_option_check_box(
                element=scan_export_page.export_csv_options)[:13]

            scan_export_page.select_and_deselect_all_options(option_name=csv_columns[1::2], flag=False)
            scan_export_page.save_as_default.check() if save_as_default else scan_export_page.save_as_default.uncheck()
            sleep(sleep_time=1, reason='Waiting for checks to get completed')
            scan_export_page.generate_report_button.click()
            sleep(sleep_time=1, reason='Waiting for Generate button to get clicked')
            ActionCloseModal().wait_for_modal_closed()

            downloaded_files = get_downloaded_files_chrome()

            log.info("Downloaded file path :: :: %s", downloaded_files)
            file_name = scan_name.split(".")[0]

            assert file_name in downloaded_files, "Scan results does not exported successfully."

            scan_view_page.report_button.click()
            wait(lambda: ActionCloseModal().modal, waiting_for='CSV export modal to open')

            scan_view_page.get_element_for_report_format_radio_button(report_format=export_format_type).click()
            wait(lambda: scan_export_page.is_element_present("clear_link") or scan_export_page.is_element_present(
                "hide_system_template_checkbox"), waiting_for="Selected report options get displayed")

            for option in csv_columns[1::2]:
                if save_as_default:
                    assert not scan_export_page.get_custom_option_checkbox(option_name=option).is_selected(), \
                        'Export CSV column option {} is still selected after save as default true.'.format(option)
                else:
                    assert scan_export_page.get_custom_option_checkbox(option_name=option).is_selected(), \
                        'Export CSV column option {} is not selected after save as default false.'.format(option)

            scan_export_page.cancel_button.click()
        finally:
            if save_as_default:
                revert_save_as_default_option_to_system(scan_name=scan_name, export_format=export_format_type)

    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_Scan_Result.db', 'password': 'nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/',
                                                      'encrypted': True}], indirect=True)
    def test_verify_tool_tip_message_for_csv_column_option(self, import_scan_via_api):
        """
        NES-8998: Automation UI for Nessus .csv Export

        Scenarios tested:
        [x] Verify that tooltip message appears when we hover mouse on 'System' link and 'References',
            'Plugin Information' and 'Exploitable With' csv column options.
        """
        scan_name = import_scan_via_api[0]
        ScansPage().refresh()

        scan_list = ScanList()
        scan_list.loaded()
        scan_list.click_on_scan(scan_name=scan_name)

        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present('vulnerability_tab'), waiting_for='scan results to load')
        scan_view_page.report_button.click()
        wait(lambda: ActionCloseModal().modal, waiting_for='CSV export modal to open')

        scan_view_page.get_element_for_report_format_radio_button(
            report_format=API.Scan.UIExportFormats.FORMAT_CSV).click()
        scan_export_page = ScanExportPage()
        wait(lambda: scan_export_page.is_element_present("clear_link") or scan_export_page.is_element_present(
            "hide_system_template_checkbox"), waiting_for="Selected report options get displayed")

        scan_export_page.move_to_element(element=scan_export_page.system_link)

        assert scan_export_page.get_tool_tip_message(
            element=scan_export_page.system_link) == Messages.ToolTip.system_link_tool_tip, \
            "Tooltip message did not appear for 'System' link."

        option_name_message_dict = {'references': Messages.ToolTip.references,
                                    'plugin_information': Messages.ToolTip.plugin_information,
                                    'exploitable_with': Messages.ToolTip.exploitable_with}

        for option_name, tooltip_message in option_name_message_dict.items():
            web_element = scan_export_page.get_tool_tip_element(option_name=option_name)
            web_element.location_once_scrolled_into_view
            web_element.click()

            assert scan_export_page.get_tool_tip_message(element=web_element) == tooltip_message, \
                'Tooltip message did not appear for {} CSV column option.'.format(option_name)

        scan_export_page.cancel_button.click()

    @pytest.mark.grid_only
    @pytest.mark.browser_file_download
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_Scan_Result.db', 'password': 'nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/',
                                                      'encrypted': True}], indirect=True)
    @pytest.mark.parametrize('csv_column_option', [Nessus.Scan.Results.Export.PLUGIN_INFORMATION,
                                                   Nessus.Scan.Results.Export.EXPLOITABLE_WITH,
                                                   Nessus.Scan.Results.Export.REFERENCES])
    def test_exported_csv_columns_for_plugin_info_exploitable_with_and_references(self, import_scan_via_api,
                                                                                  csv_column_option):
        """
        NES-9747: UI Automation: Scan | Verify that in exported report, Plugin Information is distributed in 2 columns
                  – Plugin Publication Date and Plugin Modification Date
        NES-9748: UI Automation: Scan | Verify that in exported report, ‘Exploitable With’ data is distributed in 3
                  columns – Metasploit, Core Impact and CANVAS
        NES-9754: UI Automation: Scan | Verify that in exported report, ‘Reference’ data is distributed in 3 columns –
                  BID, XREF and MSKB

        Scenario Tested:
        [x] Verify that Plugin Information column should be displayed in two separate columns – Plugin Publication Date
            and Plugin Modification Date in exported CSV report.
        [x] Verify that Exploitable With column should be displayed in three separate columns – Metasploit, Core Impact
            and CANVAS in exported CSV report.
        [x] Verify that References column should be displayed in three separate columns – BID, XREF and MSKB in
            exported CSV report.
        """
        # Import scan and click on that
        scan_name = import_scan_via_api[0]
        ScansPage().refresh()
        ScanList().click_on_scan(scan_name=scan_name)

        # Click on 'Report' dropdown on top right corner and select 'CSV' format
        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present("report_button"))

        scan_view_page.report_button.click()
        export_modal = ActionCloseModal()
        wait(lambda: export_modal.modal, waiting_for='CSV export modal to open')

        scan_view_page.get_element_for_report_format_radio_button(
            report_format=API.Scan.UIExportFormats.FORMAT_CSV).click()
        scan_export_page = ScanExportPage()
        wait(lambda: scan_export_page.is_element_present("clear_link") or scan_export_page.is_element_present(
            "hide_system_template_checkbox"), waiting_for="Selected report options get displayed")

        # Select on 'Clear' link and check column option
        scan_export_page.clear_link.click()
        scan_export_page.get_custom_option_checkbox(option_name=csv_column_option.lower().replace(" ", "_")).click()

        # Click on 'Generate Report' button
        scan_export_page.generate_report_button.click()
        export_modal.wait_for_modal_closed()

        downloaded_files = get_downloaded_files_chrome(filename="Basic_Network_Scan")
        log.info("Downloaded file path :: :: %s", downloaded_files)

        # Verify CSV report is downloaded successfully
        file_name = downloaded_files[0].split('//')[1].split('/')[-1]
        assert file_name, "Scan results does not exported successfully."

        directory = os.path.join(Config.CAT_LOCAL_BROWSER_DOWNLOAD_PATH, timestamped_path, file_name)
        source_path = get_browser_download_file_path(directory)

        csv_column_details = {
            Nessus.Scan.Results.Export.PLUGIN_INFORMATION: Nessus.Filter.FilterKeys.VALUE_DATEPICKER,
            Nessus.Scan.Results.Export.EXPLOITABLE_WITH: Nessus.Scan.Results.Export.EXPLOITABLE_WITH_COLUMNS,
            Nessus.Scan.Results.Export.REFERENCES: Nessus.Scan.Results.Export.REFERENCES_COLUMNS}

        # Read CSV report and Verify columns for 'Plugin Information', 'Exploitable With' and 'References' option
        with open(file=source_path, mode='rt') as csv_file:
            raw_data = csv.reader(csv_file, delimiter=',')
            csv_column_header = list(raw_data)[0]

            assert all([column in csv_column_header for column in csv_column_details.get(csv_column_option)]), \
                '\'{}\' columns are not present in exported CSV report for {} column.'.format(
                    csv_column_details.get(csv_column_option), csv_column_option)

        scan_view_page.back_link.click()

    @pytest.mark.browser_file_download
    @pytest.mark.parametrize('import_scan_via_api', [
        {"file_name": 'advanced_scan_gxxyl6.db', "file_path": 'nessus/tests/api/scan/test_data/', "encrypted": True,
         "password": "test1234"},
        {"file_name": 'Audit_Cloud_Infrastructure_jxzvxk.db', "file_path": 'nessus/tests/api/scan/test_data/',
         "encrypted": True, "password": "test1234"},
        {"file_name": 'basic_network_scan_ld9por.db', "file_path": 'nessus/tests/api/scan/test_data/',
         "encrypted": True, "password": "test1234"},
        {"file_name": 'credential_Patch_audit_k20m5i.db', "file_path": 'nessus/tests/api/scan/test_data/',
         "encrypted": True, "password": "test1234"},
        {"file_name": 'host_discovery_scan_fkzerx.db', "file_path": 'nessus/tests/api/scan/test_data/',
         "encrypted": True, "password": "test1234"},
        {"file_name": 'intel_amt_security_bypass_scan_mh34kw.db', "file_path": 'nessus/tests/api/scan/test_data/',
         "encrypted": True, "password": "test1234"},
        {"file_name": 'internal_pci_network_scan_ht9d9w.db', "file_path": 'nessus/tests/api/scan/test_data/',
         "encrypted": True, "password": "test1234"},
        {"file_name": 'malware_scan_k03jtm.db', "file_path": 'nessus/tests/api/scan/test_data/', "encrypted": True,
         "password": "test1234"},
        {"file_name": 'mdm_config_audit_scan_arjq1m.nessus', "file_path": 'nessus/tests/api/scan/test_data/'},
        {"file_name": 'mobile_device_scan_mr21e2.nessus', "file_path": 'nessus/tests/api/scan/test_data/'},
        {"file_name": 'offline_config_audit_scan_rb06f6.nessus', "file_path": 'nessus/tests/api/scan/test_data/'},
        {"file_name": 'pci_quarterly_external_scan_s4hruv.nessus', "file_path": 'nessus/tests/api/scan/test_data/'},
        {"file_name": 'policy_compliance_auditing_jsp7c7.nessus', "file_path": 'nessus/tests/api/scan/test_data/'},
        {"file_name": 'scap_and_oval_auditing_scan_udk5xk.nessus', "file_path": 'nessus/tests/api/scan/test_data/'},
        {"file_name": 'wannacry_ransomware_0bnkcb.nessus', "file_path": 'nessus/tests/api/scan/test_data/'},
        {"file_name": 'advanced-agent-scan_dbvmrn.nessus', "file_path": 'nessus/tests/api/scan/test_data/'},
        {"file_name": 'agent-malware-scan_l21i7k.nessus', "file_path": 'nessus/tests/api/scan/test_data/'},
        {"file_name": 'agent-policy-compliance-auditing_j05qpb.db', "file_path": 'nessus/tests/api/scan/test_data/',
         "encrypted": True, "password": "test1234"},
        {"file_name": 'basic-agent-scan_3aufg9.db', "file_path": 'nessus/tests/api/scan/test_data/', "encrypted": True,
         "password": "test1234"}], indirect=True)
    def test_visibility_of_custom_csv_export_modal(self, import_scan_via_api):
        """
        NES-9757: Verify that custom csv export model is displayed for all type of scans (different scan templates for
                  Normal scans, Policy scans, Agent scans)

        Scenario Tested:
        [x] Verify that custom csv export model is displayed for all type of scans
        """
        scan_name = import_scan_via_api[0]
        scan_page = ScansPage()
        scan_page.refresh()
        scan_list = ScanList()

        # Verify that scan is imported successfully
        assert scan_name in scan_list.get_all_scans() and scan_page.get_scan_import_status(scan_name).is_displayed(), \
            'Scan is not imported successfully.'

        scan_list.click_on_scan(scan_name=scan_name)
        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present("report_button"), waiting_for="Report button get displayed")

        scan_view_page.report_button.click()
        action_modal = ActionCloseModal()
        wait(lambda: action_modal.is_element_present("modal"), waiting_for='CSV export modal to open')

        scan_view_page.get_element_for_report_format_radio_button(
            report_format=API.Scan.UIExportFormats.FORMAT_CSV).click()
        scan_export_page = ScanExportPage()
        wait(lambda: scan_export_page.is_element_present("clear_link"),
             waiting_for="Selected report options get displayed")

        # Verify that export CSV modal is displayed
        assert action_modal.is_element_present('modal'), \
            "'Generate CSV Report' modal is not displayed for {} scan template.".format(scan_name)

        # Verify the title of export CSV modal
        assert action_modal.modal_title.text == Nessus.Scan.Results.Export.EXPORT_CSV_MODAL_TITLE, \
            'Getting incorrect modal title. Expected is: {}'.format(
                Nessus.Scan.Results.Export.EXPORT_CSV_MODAL_TITLE)

        # Verify that 'Generate Report' button is displayed on export CSV modal
        assert scan_export_page.is_element_present('generate_report_button'), \
            "'Generate Report' button is not present on export CSV modal."

        # Verify that 'Cancel' button is displayed next to 'Generate Report' button
        assert action_modal.is_element_present('cancel_button'), \
            "'Cancel' button is not displayed next to 'Generate Report' button in export CSV modal."

        # Verify that 'Save as default' checkbox is displayed on export CSV modal
        assert scan_export_page.is_element_present('save_as_default'), \
            "'Save as default' checkbox is not displayed in export CSV modal."

        default_columns = scan_export_page.get_name_of_export_option(element=scan_export_page.export_csv_options,
                                                                     default=True)
        scan_export_page.generate_report_button.click()
        action_modal.wait_for_modal_closed()

        downloaded_files = get_downloaded_files_chrome(filename=scan_name.replace(" ", "_"))
        log.info("Downloaded file path :: :: %s", downloaded_files)

        # Verify CSV report is downloaded successfully
        file_name = downloaded_files[0].split('//')[1].split('/')[-1]
        assert file_name, "Scan results did not export successfully."

        directory = os.path.join(Config.CAT_LOCAL_BROWSER_DOWNLOAD_PATH, timestamped_path, file_name)
        source_path = get_browser_download_file_path(directory)

        # Verify that columns are present in exported CSV report which are selected by default in export CSV modal
        with open(file=source_path, mode='rt') as csv_file:
            raw_data = csv.reader(csv_file, delimiter=',')
            csv_column_header = list(raw_data)[0]

            assert set(default_columns).issubset(set(csv_column_header)), \
                'Default selected CSV columns are not present in exported CSV report.'


@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login', 'login')
class TestSaveAsDefaultPersist:
    """ Test case for "Save as Default" functionality of export scan results of created scan. """

    @pytest.mark.parametrize("create_users", [
        {"user_details": {"Basic": {'user_name': API.User.Users.BASIC_USER, 'full_name': 'Basic user',
                                    'email': API.User.Users.TEST_EMAIL, 'password': 'admin',
                                    'role': API.User.Role.BASIC},
                          "Standard": {'user_name': API.User.Users.STANDARD_USER, 'full_name': 'Standard user',
                                       'email': API.User.Users.TEST_EMAIL, 'password': 'admin',
                                       'role': API.User.Role.STANDARD},
                          "Administrator": {'user_name': API.User.Users.ADMIN_USER, 'full_name': 'Admin user',
                                            'email': API.User.Users.TEST_EMAIL, 'password': 'admin',
                                            'role': API.User.Role.ADMIN},
                          "System Administrator": {'user_name': API.User.Users.SYS_ADMIN_USER,
                                                   'full_name': 'SysAdmin user', 'email': API.User.Users.TEST_EMAIL,
                                                   'password': 'admin', 'role': API.User.Role.SYS_ADMIN}},
         'unique_username': True, "check_login": False}], indirect=True)
    @pytest.mark.parametrize('import_scan_via_api', [
        {'file_name': 'Basic_Network_Scan_Result.db', 'password': 'nessus', 'encrypted': True,
         'file_path': 'nessus/tests/ui/scans/test_data/'}], indirect=True)
    @pytest.mark.parametrize("format_type", [API.Scan.UIExportFormats.FORMAT_CSV])
    def test_verify_save_as_default_persist_only_for_same_user(self, create_users, import_scan_via_api, format_type):
        """
        NES-9763: UI Automation:Scans | Verify that ‘Save as Default’ selection persists only for same user. It should
                  not affect other user

        Steps:
        1. Login with a valid credential in NM.
        2. Create one scan and after completed go to the "Report" option.
        3. Open HTML, PDF, and CSV report type and configure base on user requirement and export it.
        4. Now Login with another type of user like admin, sysadmin, standard, and basic.
        5. Create one scan and launch it and after completed open Report option.

        Scenario Tested:
        [x] Verify that ‘Save as Default’ selection persists only for the same user. It should not affect other users.
        """
        # Import scan
        scan_name = import_scan_via_api[0]
        HeaderBasePage().scan_link.click()

        # Click on imported scan and click on 'Report' drop-down from scan results page
        scan_list = ScanList()
        scan_list.click_on_scan(scan_name=scan_name)
        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present("report_button"))

        scan_view_page.report_button.click()
        action_modal = ActionCloseModal()
        wait(lambda: action_modal.is_element_present("modal"), waiting_for='CSV export modal to open')

        # Select report format type, uncheck few vulnerability details options and save it as default
        scan_export_page = ScanExportPage()
        options_name = get_scan_results_export_options(format_type=format_type)
        scan_export_page.select_and_deselect_all_options(option_name=options_name[1::2], flag=False)
        scan_export_page.save_as_default.check()
        scan_export_page.generate_report_button.click()

        action_modal.wait_for_modal_closed()
        login_user = LoginPage()
        user_menu = UserMenu()

        for user_name in create_users.values():
            user_menu.logout()
            wait(lambda: login_user.username_field, waiting_for='Login page to load properly')
            login_user.login_with_credentials(username=user_name['user_name'], password=user_name['password'])

            wait(lambda: ScansPage().is_element_present('title_in_header'),
                 waiting_for="My Scans page to load properly", timeout_seconds=TIME_THIRTY_SECONDS)

            # Import scan file from different users
            nessus_api = NessusAPI()
            nessus_api.login(username=user_name['user_name'], password=user_name['password'])

            scan_file = get_file_path('nessus/tests/ui/scans/test_data/' + 'Basic_Network_Scan_Result.db')
            file_uploaded = nessus_api.file.upload(file=scan_file, encrypted=True)
            nessus_api.scans.import_scan(file_uploaded, password='nessus')

            assert nessus_api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % nessus_api.http_status_code

            scan_list.refresh()
            scan_list.loaded()

            # Click on imported scan and click on 'Report' drop-down from scan results page
            scan_list.click_on_scan(scan_name=scan_name)
            NotificationActions().remove_all()

            wait(lambda: scan_view_page.is_element_present("report_button"))
            scan_view_page.report_button.click()
            wait(lambda: action_modal.is_element_present("modal"), waiting_for='CSV export modal to open')
            options_name = get_scan_results_export_options(format_type=format_type)

            if format_type == API.Scan.UIExportFormats.FORMAT_CSV:
                # Verify that 'Save as Default' should not be persist for different users
                for option in options_name[:13]:
                    assert scan_export_page.get_custom_option_checkbox(option_name=option).is_selected(), \
                        'Export column option \'{}\' is not selected after save as default for \'{}\' user.'.format(
                            option, user_name)

            scan_export_page.cancel_button.click()


@pytest.mark.nessus_home
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login', 'login')
class TestReportOptionsForManagerHome:
    """ Tests related to report drop-down options """

    @pytest.mark.parametrize('import_scan_via_api', [
        {'file_name': 'Basic_Network_Scan_Result.db', 'password': 'nessus',
         'file_path': 'nessus/tests/ui/scans/test_data/', 'encrypted': True}], indirect=True)
    @pytest.mark.parametrize("format_type", [API.Scan.UIExportFormats.FORMAT_HTML, API.Scan.UIExportFormats.FORMAT_PDF])
    def test_top_10_report_option_not_present_in_manager_and_home(self, import_scan_via_api, format_type):
        """
        NES-12752: [UI-Automation] Verify that C level report should not appear in NM/Essentials

        Scenario Tested:
        [x] Verify that below report options are not visible in Manager and Home.
            - Exploitable Vulnerabilities
            - Top 10 Vulnerabilities
            - Hosts with Vulnerabilities
            - Default/Known Accounts
            - OS Detections
            - Unsupported Software
            - Vulnerabilities > 1 Year Old
        """
        scan_name = import_scan_via_api[0]

        ScansPage().refresh()
        ScanList().click_on_scan(scan_name=scan_name)

        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present("report_button"))

        scan_view_page.report_button.click()
        wait(lambda: ActionCloseModal().modal, waiting_for='Export report modal to open')

        scan_view_page.get_element_for_report_format_radio_button(report_format=format_type).click()
        scan_export_page = ScanExportPage()
        wait(lambda: scan_export_page.is_element_present("clear_link") or scan_export_page.is_element_present(
            "template_description_label"), waiting_for="Selected report options get displayed")

        assert all([report_option not in scan_export_page.get_system_templates_name() for report_option in
                    API.Scan.ReportTypes.PRO_REPORT_TEMPLATES]), \
            "'Top 10 Vulnerabilities' option or other report option from '{}' is present in Manager and Home.".format(
                API.Scan.ReportTypes.PRO_REPORT_TEMPLATES)


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('nessus_api_login', 'login')
class TestTop10ReportForExportScanResults:
    """ Test case for 'Top 10 Vulnerabilities' export report. """

    cat = None

    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'folder': Nessus.Scan.Folder.MY_SCANS.split(' (')[0], 'target_ip': Nessus.Scan.Target.AWS_LINUX_TARGET_1,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED))}]}], indirect=True)
    @pytest.mark.parametrize("format_type", [API.Scan.UIExportFormats.FORMAT_HTML, API.Scan.UIExportFormats.FORMAT_PDF])
    def test_top_10_report_can_be_generated_from_history_tab(self, create_scans, format_type):
        """
        NES-12773: [UI-Automation] : C level report can be generated from History tab with PDF/HTML format

        Scenario Tested:
        [x] Verify that 'Top 10 Vulnerabilities' report can be generated for PDF/HTML format from 'History' tab
        """
        scan_name = create_scans[0]
        wait(lambda: ScansPage().is_element_present("scan_searchbox"), waiting_for="scan list gets loaded")

        scan_id = get_scan_id(api_object=self.cat.api, scan_name=scan_name)
        scan_list = ScanList()

        for _ in range(2):
            self.cat.api.scans.launch(scan_id=scan_id)

            wait(lambda: (self.cat.api.scans.get_status(scan_id=scan_id) == API.Scan.Status.COMPLETED),
                 waiting_for="'X' icon to be visible after complete the scan", timeout_seconds=TIME_TEN_MINUTES * 3)

            scan_list.refresh()
            scan_list.loaded()

        try:
            scan_list.click_on_scan(scan_name=scan_name)

            scan_view_page = ScanViewPage()
            wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
                 waiting_for='Vulnerabilities to load')

            scan_view_page.history_tab.click()

            assert not ScanHistoryList().is_empty(), 'Scan history is getting empty.'

            scan_view_page.report_button.click()
            wait(lambda: ActionCloseModal().modal, waiting_for='Export report modal to open')

            scan_view_page.get_element_for_report_format_radio_button(report_format=format_type).click()
            scan_export_page = ScanExportPage()
            wait(lambda: scan_export_page.is_element_present("clear_link") or scan_export_page.is_element_present(
                "hide_system_template_checkbox"), waiting_for="Selected report options get displayed")

            scan_export_page.select_report_template_from_generate_report_modal(
                template_name=API.Scan.ReportTypes.TOP_10_VULNERABILITIES)
            sleep(WAIT_SHORT, reason="waiting for report template get selected")
            scan_export_page.generate_report_button.click()
            ActionCloseModal().wait_for_modal_closed()

            downloaded_files = get_downloaded_files_chrome()

            log.info("Downloaded file path :: :: %s", downloaded_files)
            file_name = scan_name.split(".")[0]

            assert file_name in downloaded_files, "Scan results does not exported successfully."

        finally:
            HeaderBasePage().scan_link.click()


class TestThreatLevelTabForExportedScan:
    """ Tests to verify new VPR details in exported scan result """

    cat = None

    @pytest.mark.usefixtures('nessus_api_login', 'import_scan_via_api', 'login')
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_-_CVSS_av5q3j.nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/'}], indirect=True)
    @pytest.mark.parametrize('export_format', [API.Scan.ExportFormats.FORMAT_NESSUS, API.Scan.ExportFormats.FORMAT_DB])
    def test_verify_threat_level_tab_visibility_in_exported_scan_result(self, export_format, import_scan_via_api):
        """
        NES-12708: [UI-Automation] Verify VPR top threat tab data for exported file in .nessus and .db file

        Scenario Tested:
        [x] Verify that VPR Top Threats Tab is present in exported (.nessus and .db) scan result.
        """
        scan_name = import_scan_via_api[0]

        scan_id = get_scan_id(api_object=self.cat.api, scan_name=scan_name)

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

        import_scan = self.cat.api.scans.import_scan(file_uploaded_nessus, folder_id=None,
                                                     password=export_import_password)

        assert import_scan['scan']['id'], "Scan does not imported successfully in nessus"

        self.cat.api.scans.delete(scan_id)
        scan_list = ScanList()

        scan_list.refresh()
        scan_list.loaded()
        scan_list.click_on_scan(scan_name=import_scan['scan']['name'])

        scan_view_page = ScanViewPage()
        wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
             waiting_for='Vulnerabilities to get loads')

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
