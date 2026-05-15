"""
Nessus UI test cases related to Scan summary tab under scan result page

:copyright: Tenable Network Security, 2017
:date: Apr 08, 2022
:last_modified: Apr 22, 2022
:author: @kpanchal.ctr, @krpatel
"""
import random

import pytest
from selenium.webdriver.support.expected_conditions import visibility_of_element_located

from catium.helpers.sleep_lib import sleep
from catium.lib.const.base_constants import TIME_SIXTY_SECONDS, TIME_THIRTY_MINUTES, WAIT_NORMAL
from catium.lib.log.log import create_logger
from catium.lib.util.util import random_name, random_string
from catium.lib.webium.wait import wait
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.polling_ui import polling_ui
from nessus.helpers.scan import create_scan_helper, import_scan_helper, get_scan_id
from nessus.helpers.sort import sort_on_column_values
from nessus.helpers.system import is_home
from nessus.helpers.waiters import wait_scan_state
from nessus.lib.const import Nessus, API, SortOrder
from nessus.lib.message.messages import Messages
from nessus.pageobjects.header.notifications import close_pendo_guide_container_banner_for_nessus_pro
from nessus.pageobjects.scans.scan_view_page import ScanViewPage, ScanSummaryPage, PluginFamiliesEnabledDisabledList, \
    ScanNotesList, PluginRulesAppliedList, ScansHostList
from nessus.pageobjects.scans.scans_page import ScanList, ScansPage

log = create_logger()


@pytest.mark.scanning
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login', 'login')
class TestScanSummaryTabInScanResults:
    """ Test cases to cover UI functionality related to scan summary tab under scan result Page """

    cat = None

    def create_and_launch_scan(self, file_path: str, scan_template: str):
        """
        Creates and launch scan and wait until it gets completed

        :param str file_path: file path where created or imported to be placed
        :param str scan_template: scan template name
        :return: created or imported scan name
        :rtype: str
        """
        created_scan_details = create_scan_helper(api_handler=self.cat.api, file_name=file_path,
                                                  template_title=scan_template)

        scan_name = created_scan_details[0]['scan']['name']

        # Launching created scan and waiting to be completed
        assert ScanList().launch_scan_and_wait_for_status(scan_name=scan_name), \
            "launch of created scan wasn't successful"

        return scan_name

    @staticmethod
    def delete_created_or_imported_scan(scan_name: str) -> None:
        """
        Deletes given created or imported scan from scans list

        :param str scan_name: scan name
        :return: None
        """
        nessus_api = NessusAPI()
        nessus_api.login()

        scan_id = get_scan_id(api_object=nessus_api, scan_name=scan_name)
        nessus_api.scans.delete(scan_id=scan_id)

    @staticmethod
    def verify_scan_summary_tab_present_in_scan_results(nessus_api: NessusAPI(), scan_id: int) -> None:
        """
        Verifies that "Scan Summary" tab is present in scan results

        :param nessus_api: NessusAPI object
        :param int scan_id: created scan Id
        :return: None
        """
        scan_details = nessus_api.scans.details(scan_id=scan_id)

        assert "summary" not in scan_details, "'Scan Summary' tab is present in scan results which should not be."

    @staticmethod
    def get_plugin_family_row_data_from_all_pages(column_to_sort: str) -> list:
        """
        Returns all plugin families row data according to given column name

        :param str column_to_sort: sorting order like ascending or descending
        :return: plugin families row data
        :rtype: list
        """
        plugin_data = []
        scan_summary_page = ScanSummaryPage()
        plugin_family_list = PluginFamiliesEnabledDisabledList()
        is_next_button_enabled = True

        while is_next_button_enabled:
            if column_to_sort == "Status":
                plugin_row_data = plugin_family_list.get_plugin_family_status()
            else:
                plugin_row_data = plugin_family_list.get_plugin_family_name()

            plugin_data.extend(plugin_row_data)
            is_next_button_enabled = "disabled" not in scan_summary_page.pagination_next_arrow.get_css_classes()

            if is_next_button_enabled:
                scan_summary_page.pagination_next_arrow.click()

        return plugin_data

    @pytest.mark.xray(test_key='NES-15848')
    @pytest.mark.xray(test_key='NES-15845')
    @pytest.mark.xray(test_key='NES-15842')
    @pytest.mark.xray(test_key='NES-15840')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.parametrize('scan_type', ['created_scan', 'imported_scan'])
    def test_visibility_of_scan_summary_tab_in_scanner_scan_results(self, scan_type):
        """
        NES-15840: Verify summary tab in Nessus Pro & Eval Pro
        NES-15848: Verify Summary tab for imported scans
        NES-15842: Verify Summary tab for non-agent scans in Nessus Manager
        NES-15845: Verify Summary tab for Managed Scanner and Nessus Essentials

        Scenario Tested:
        [x] Verify that "Scan Summary" tab should be available in created scan results page.
        [x] Verify that "Scan Summary" tab should be displayed in imported scan results page.
        [x] Verify that "Scan Summary" tab should be available for non-agent (scanner) scans.
        [x] Verify that "Scan Summary" tab should be displayed in Nessus Essential.
        """
        scan_name = None

        try:
            if scan_type == "created_scan":
                scan_name = self.create_and_launch_scan(
                    file_path='nessus/tests/api/scan/test_data/advanced_scan_for_scan_summary.json',
                    scan_template='advanced')
            else:
                imported_scan_details = import_scan_helper(api_handler=self.cat.api,
                                                           scan_file_name='Basic_Network_Scan_mlv2zq.nessus',
                                                           scan_file_path='nessus/tests/api/scan/test_data/')

                scan_name = imported_scan_details

            scan_page = ScansPage()
            scan_page.refresh()
            wait(lambda: scan_page.is_element_present("scan_searchbox"))

            ScanList().click_on_scan(scan_name=scan_name)
            scan_view_page = ScanViewPage()
            wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
                 waiting_for='Vulnerabilities to get loads')

            is_scan_summary_tab_visible = scan_view_page.is_element_present("scan_summary_tab")

            if not is_home():
                assert is_scan_summary_tab_visible, "'Scan Summary' tab is not available in '{}' results page.".format(
                    scan_type)
            else:
                assert not is_scan_summary_tab_visible, "'Scan Summary' tab is available for Nessus Essential in " \
                                                        "'{}' results page which should not be.".format(scan_type)
        finally:
            self.delete_created_or_imported_scan(scan_name=scan_name)

    @pytest.mark.xray(test_key='NES-15848')
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Advanced_agent_scan_lqq5zk.nessus',
                                                      'file_path': 'nessus/tests/api/scan/test_data/',
                                                      'encrypted': True}], indirect=True)
    def test_visibility_of_scan_summary_tab_in_imported_agent_scan_results(self, import_scan_via_api):
        """
        NES-15848: Verify Summary tab for imported scans

        Scenario Tested:
        [x] Verify that "Scan Summary" tab should not be displayed in imported agent scan results page.
        """
        scan_page = ScansPage()
        scan_page.refresh()
        wait(lambda: scan_page.is_element_present("scan_searchbox"))

        ScanList().click_on_scan(scan_name=import_scan_via_api[0])
        scan_view_page = ScanViewPage()
        wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
             waiting_for='Vulnerabilities to get loads')

        assert not scan_view_page.is_element_present("scan_summary_tab"), \
            "'Scan Summary' tab is getting visible in imported agent scan results page."

    @pytest.mark.xray(test_key='NES-15846')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'folder': Nessus.Scan.Folder.MY_SCANS.split(' (')[0], 'target_ip': '{}, {}, {}, {}'.format(
            Nessus.Scan.Target.PUB_TARGET_3, Nessus.Scan.Target.AWS_LINUX_TARGET_1, Nessus.Scan.Target.PUB_TARGET_4,
            Nessus.Scan.Target.AWS_LINUX_TARGET_2),
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED))}]}], indirect=True)
    @pytest.mark.parametrize("scan_state", ["completed", "not_completed"])
    def test_scan_summary_tab_is_displayed_for_completed_scan_only(self, create_scans, scan_state):
        """
        NES-15846: Verify Summary tab shows only for completed scans

        Scenario Tested:
        [x] Verify that "Scan Summary" tab should be visible in completed scan only.
        """
        scan_name = create_scans[0]
        scan_list = ScanList()
        scan_id = scan_list.get_scan_id(scan_name=scan_name)

        scan_list.refresh()
        scan_list.loaded()

        try:
            if scan_state == "not_completed":
                self.cat.api.scans.launch(scan_id=scan_id)
                wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.RUNNING,
                                timeout=TIME_SIXTY_SECONDS)

                self.verify_scan_summary_tab_present_in_scan_results(nessus_api=self.cat.api, scan_id=scan_id)

                self.cat.api.scans.pause(scan_id=scan_id)
                wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.PAUSED,
                                timeout=TIME_SIXTY_SECONDS)

                self.verify_scan_summary_tab_present_in_scan_results(nessus_api=self.cat.api, scan_id=scan_id)

                self.cat.api.scans.resume(scan_id=scan_id)
                wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.RUNNING,
                                timeout=TIME_SIXTY_SECONDS)

                self.verify_scan_summary_tab_present_in_scan_results(nessus_api=self.cat.api, scan_id=scan_id)

                self.cat.api.scans.stop(scan_id)
                wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.CANCELED,
                                timeout=TIME_SIXTY_SECONDS)
            else:
                with polling_ui():
                    self.cat.api.scans.launch(scan_id=scan_id)
                    wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                    timeout=TIME_THIRTY_MINUTES)

            if self.cat.api.scans.get_status(scan_id) in [API.Scan.Status.COMPLETED, API.Scan.Status.CANCELED]:
                scan_list.click_on_scan(scan_name=scan_name)
                scan_view_page = ScanViewPage()
                wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
                     waiting_for='Vulnerabilities to get loads')

                assert scan_view_page.is_element_present("scan_summary_tab"), \
                    "'Scan Summary' tab is not available in '{}' results page.".format(scan_state)
        finally:
            scan_status = self.cat.api.scans.get_status(scan_id)

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

            self.delete_created_or_imported_scan(scan_name=scan_name)

    @pytest.mark.xray(test_key='NES-15849')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('scan_type', ['created_scan', 'imported_scan'])
    def test_verify_timing_data_section_under_scan_summary_tab(self, scan_type):
        """
        NES-15849: Verify Timing Data section under scan summary tab

        Scenario Tested:
        [x] Verify timing data section under "Scan Summary" tab.
        """
        scan_name = None

        try:
            if scan_type == "created_scan":
                scan_name = self.create_and_launch_scan(
                    file_path='nessus/tests/api/scan/test_data/advanced_scan_for_scan_summary.json',
                    scan_template='advanced')
            else:
                imported_scan_details = import_scan_helper(api_handler=self.cat.api,
                                                           scan_file_name='Basic_Network_Scan_mlv2zq.nessus',
                                                           scan_file_path='nessus/tests/api/scan/test_data/')

                scan_name = imported_scan_details

            scan_page = ScansPage()
            scan_page.refresh()
            wait(lambda: scan_page.is_element_present("scan_searchbox"))

            ScanList().click_on_scan(scan_name=scan_name)
            wait(lambda: visibility_of_element_located(ScanViewPage().vulnerability_tab),
                 waiting_for='Vulnerabilities to get loads')

            scan_summary_page = ScanSummaryPage()

            assert all([scan_summary_page.is_element_present("scan_duration_section"),
                        scan_summary_page.is_element_present("scan_duration_section_label"),
                        scan_summary_page.scan_duration_section_label.text == Nessus.Scan.Results.ScanSummaryTab.
                       SCAN_DURATION_SECTION_LABEL, scan_summary_page.is_element_present("scan_duration_time_label"),
                        scan_summary_page.scan_duration_time_label.text == Nessus.Scan.Results.ScanSummaryTab.
                       SCAN_DURATION_TIME_LABEL, scan_summary_page.is_element_present("scan_duration_time_value"),
                        scan_summary_page.scan_duration_time_value.text is not None,
                        len(scan_summary_page.scan_duration_time_value.text) > 0,
                        scan_summary_page.is_element_present("scan_median_time_label"),
                        scan_summary_page.scan_median_time_label.text == Nessus.Scan.Results.ScanSummaryTab.
                       MEDIAN_SCAN_TIME_LABEL, scan_summary_page.is_element_present("scan_median_time_value"),
                        scan_summary_page.scan_median_time_value.text is not None,
                        len(scan_summary_page.scan_median_time_value.text) > 0,
                        scan_summary_page.is_element_present("max_scan_time_label"),
                        scan_summary_page.max_scan_time_label.text == Nessus.Scan.Results.ScanSummaryTab.
                       MAX_SCAN_TIME_LABEL, scan_summary_page.is_element_present("max_scan_time_value"),
                        scan_summary_page.max_scan_time_value.text is not None,
                        len(scan_summary_page.max_scan_time_value.text) > 0,
                        scan_summary_page.is_element_present("scan_duration_export_button")]), \
                "'Scan Duration' section is either missing or not visible properly for '{}'.".format(scan_type)
        finally:
            self.delete_created_or_imported_scan(scan_name=scan_name)

    @pytest.mark.xray(test_key='NES-15894')
    @pytest.mark.xray(test_key='NES-15851')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('scan_type', ['created_scan', 'imported_scan'])
    def test_verify_policy_data_section_under_scan_summary_tab(self, scan_type):
        """
        NES-15851: Verify Policy/Settings Data section under scan summary tab
        NES-15894: Verify that Policy detail section is expandable and collapsable

        Scenario Tested:
        [x] Verify "Policy Details" section under "Scan Summary" tab.
        [x] Verify that System should allow user to collapse/expand Policy Details section. By default it should get
            displayed in expanded mode.
        """
        scan_name = None

        try:
            if scan_type == "created_scan":
                scan_name = self.create_and_launch_scan(
                    file_path='nessus/tests/api/scan/test_data/advanced_scan_for_scan_summary.json',
                    scan_template='advanced')
            else:
                imported_scan_details = import_scan_helper(api_handler=self.cat.api,
                                                           scan_file_name='Basic_Network_Scan_mlv2zq.nessus',
                                                           scan_file_path='nessus/tests/api/scan/test_data/')

                scan_name = imported_scan_details

            scan_page = ScansPage()
            scan_page.refresh()
            wait(lambda: scan_page.is_element_present("scan_searchbox"))

            ScanList().click_on_scan(scan_name=scan_name)
            wait(lambda: visibility_of_element_located(ScanViewPage().vulnerability_tab),
                 waiting_for='Vulnerabilities to get loads')

            scan_summary_page = ScanSummaryPage()
            expand_arrow_element_class = scan_summary_page.expand_collapse_arrow.get_css_classes()

            assert all([scan_summary_page.is_element_present("expand_collapse_arrow"),
                        "closed" in expand_arrow_element_class, "next" not in expand_arrow_element_class,
                        len(scan_summary_page.policy_details_containers_title) != 0]), \
                "'Policy Details' section is not getting expanded by default."

            assert all([scan_summary_page.is_element_present("policies_details_section"),
                        scan_summary_page.is_element_present("export_full_policy_down_arrow"),
                        scan_summary_page.is_element_present("policy_details_container")]), \
                "'Scan Duration' section is either missing or not visible properly for '{}'.".format(scan_type)

            assert sorted(scan_summary_page.get_policy_details_container_titles()) == sorted(
                Nessus.Scan.Results.ScanSummaryTab.POLICY_DETAILS_SECTION_LABEL), "Policy details containers title " \
                                                                                  "are either missing or mismatched."

            scan_summary_page.expand_collapse_arrow.click()
            wait(lambda: not scan_summary_page.is_element_present("policy_details_containers_title"))
            collapse_arrow_element_class = scan_summary_page.expand_collapse_arrow.get_css_classes()

            assert all([scan_summary_page.is_element_present("expand_collapse_arrow"),
                        "closed" not in collapse_arrow_element_class, "next" in collapse_arrow_element_class,
                        len(scan_summary_page.policy_details_containers_title) == 0]), \
                "Unable to collapse 'Policy Details' section even after clicking on arrow next to section title."
        finally:
            self.delete_created_or_imported_scan(scan_name=scan_name)

    @pytest.mark.xray(test_key='NES-15852')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_Scan_Result.db', 'password': 'nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/',
                                                      'encrypted': True}], indirect=True)
    def test_verify_os_distribution_section_under_scan_summary_page(self, import_scan_via_api):
        """
        NES-15852: Verify OS Distribution section under scan summary tab

        Scenario Tested:
        [x] Verify that 'OS Distribution' section should have below listed fields:
                - pie chart with top 5 OS versions.
        """
        scan_page = ScansPage()
        scan_page.refresh()
        wait(lambda: scan_page.is_element_present("scan_searchbox"))

        ScanList().click_on_scan(scan_name=import_scan_via_api[0])
        scan_view_page = ScanViewPage()
        wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
             waiting_for='Vulnerabilities to get loads')

        scan_summary_page = ScanSummaryPage()

        assert all([scan_summary_page.is_element_present("pie_chart_section"),
                    scan_summary_page.is_element_present("os_distribution_section_title"),
                    scan_summary_page.os_distribution_section_title.text == Nessus.Scan.Results.ScanSummaryTab.
                   OS_DISTRIBUTION_SECTION_TITLE, scan_summary_page.is_element_present("detected_os_list"),
                    len(scan_summary_page.detected_os_list) > 0]), \
            "'OS Distribution' section is either not present or not visible properly under scan summary tab."

        found = False

        for os_name_element in scan_summary_page.detected_os_list:
            scan_summary_page.move_to_element(element=os_name_element)

            if scan_view_page.is_element_present('percentile_in_chart'):
                found = True
                value_of_percentage_count = scan_summary_page.percentage_count.text

                assert all([('%' in value_of_percentage_count), (int(value_of_percentage_count[:-1]) > 0),
                            (int(value_of_percentage_count[:-1]) <= 100)]), \
                    "percentile character for '{}' OS is either missing or mismatched.".format(os_name_element.text)
            else:
                log.warning("No detected OS percentage count available for '{}' OS.".format(os_name_element.text))

        assert found, "No detected OS percentage count found in scan summary page."

    @pytest.mark.xray(test_key='NES-15887')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('scan_type', ['created_scan', 'imported_scan'])
    def test_verify_plugins_family_enabled_disabled_section_under_scan_summary_page(self, scan_type):
        """
        NES-15887: Verify Plugin Families Enabled/Disabled section

        Scenario Tested:
        [x] Verify 'Plugin Families' used to configure selected scan are being listed with search bar on top.
        """
        scan_name = None

        try:
            if scan_type == "created_scan":
                scan_name = self.create_and_launch_scan(
                    file_path='nessus/tests/api/scan/test_data/advanced_scan_for_scan_summary.json',
                    scan_template='advanced')
            else:
                imported_scan_details = import_scan_helper(api_handler=self.cat.api,
                                                           scan_file_name='advance_scan_c7kspv.nessus',
                                                           scan_file_path='nessus/tests/api/scan/test_data/')

                scan_name = imported_scan_details

            scan_page = ScansPage()
            scan_page.refresh()
            wait(lambda: scan_page.is_element_present("scan_searchbox"))

            close_pendo_guide_container_banner_for_nessus_pro()
            ScanList().click_on_scan(scan_name=scan_name)
            wait(lambda: visibility_of_element_located(ScanViewPage().vulnerability_tab),
                 waiting_for='Vulnerabilities to get loads')

            scan_summary_page = ScanSummaryPage()

            assert all([scan_summary_page.is_element_present("plugin_families_section_label"),
                        scan_summary_page.plugin_families_section_label.text.strip() == Nessus.Scan.Results.
                       ScanSummaryTab.PLUGIN_FAMILY_SECTION_TITLE, scan_summary_page.is_element_present(
                    "search_plugin_families_field"), scan_summary_page.search_plugin_families_field.get_attribute(
                    "placeholder") == Nessus.Scan.Results.ScanSummaryTab.PLUGIN_FAMILY_SEARCH_FIELD_PLACEHOLDER,
                        scan_summary_page.is_element_present("search_plugin_families_icon"),
                        scan_summary_page.is_element_present("total_search_plugin_families"),
                        len(scan_summary_page.total_search_plugin_families.text) > 0,
                        scan_summary_page.is_element_present("plugin_families_table"),
                        scan_summary_page.is_element_present("results_per_page_dropdown"),
                        scan_summary_page.is_element_present("results_per_page_label"),
                        scan_summary_page.results_per_page_label.text.split("\n")[0] ==
                        Nessus.Scan.Results.ScanSummaryTab.RESULTS_PER_PAGE_LABEL, scan_summary_page.is_element_present(
                    "pagination_first_arrow"), "disabled" in scan_summary_page.pagination_first_arrow.get_css_classes(),
                        scan_summary_page.is_element_present("pagination_previous_arrow"),
                        "disabled" in scan_summary_page.pagination_previous_arrow.get_css_classes(),
                        scan_summary_page.is_element_present("pagination_next_arrow"),
                        scan_summary_page.pagination_next_arrow.is_enabled(),
                        scan_summary_page.is_element_present("pagination_last_arrow"),
                        scan_summary_page.pagination_last_arrow.is_enabled()]), \
                "'Plugin Families' section is not present under scan summary page."
        finally:
            self.delete_created_or_imported_scan(scan_name=scan_name)

    @pytest.mark.xray(test_key='NES-15847')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('scan_type', ['created_scan', 'imported_scan'])
    def test_verify_authentication_and_credentials_info_hosts_section_under_scan_summary_page(self, scan_type):
        """
        NES-15847: Verify Authentication/Credential Info under Summary tab

        Scenario Tested:
        [x] Verify "Authentication/Credential Info (Hosts)" section should be available with 2 tables below it:
                - SUCCEEDED (Number of hosts scanned credentialed)
                - FAILED (Number of hosts where credentials failed)
        """
        scan_name = None

        try:
            if scan_type == "created_scan":
                scan_name = self.create_and_launch_scan(
                    file_path='nessus/tests/api/scan/test_data/advanced_scan_for_scan_summary.json',
                    scan_template='advanced')
            else:
                imported_scan_details = import_scan_helper(api_handler=self.cat.api,
                                                           scan_file_name='Basic_Network_Scan_mlv2zq.nessus',
                                                           scan_file_path='nessus/tests/api/scan/test_data/')

                scan_name = imported_scan_details

            scan_page = ScansPage()
            scan_page.refresh()
            wait(lambda: scan_page.is_element_present("scan_searchbox"))

            ScanList().click_on_scan(scan_name=scan_name)
            wait(lambda: visibility_of_element_located(ScanViewPage().vulnerability_tab),
                 waiting_for='Vulnerabilities to get loads')

            scan_summary_page = ScanSummaryPage()

            assert all([scan_summary_page.is_element_present("auth_credential_info_section"),
                        scan_summary_page.is_element_present("auth_credential_info_section_label"),
                        scan_summary_page.auth_credential_info_section_label.text.strip() ==
                        Nessus.Scan.Results.ScanSummaryTab.AUTHENTICATION_CREDENTIALS_INFO_SECTION_LABEL,
                        scan_summary_page.is_element_present("succeeded_hosts_with_creds_label"),
                        scan_summary_page.succeeded_hosts_with_creds_label.text.strip() == Nessus.Scan.Results.
                       ScanSummaryTab.SUCCEEDED_HOST_LABEL, scan_summary_page.is_element_present(
                    "failed_hosts_creds_label"), scan_summary_page.failed_hosts_creds_label.text.strip() ==
                        Nessus.Scan.Results.ScanSummaryTab.FAILED_HOST_LABEL,
                        int(scan_summary_page.succeeded_hosts_with_creds_value.text.strip()) >= 0,
                        int(scan_summary_page.failed_hosts_creds_value.text.strip()) >= 0]), \
                "'Authentication / Credential Info (Hosts)' section is not present under scan summary page."
        finally:
            self.delete_created_or_imported_scan(scan_name=scan_name)

    @pytest.mark.xray(test_key='NES-15888')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("search_with", ["by_status", "by_family_name", "random_string"])
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'advance_scan_c7kspv.nessus',
                                                      'file_path': 'nessus/tests/api/scan/test_data/'}], indirect=True)
    def test_verify_plugin_families_search_functioning_properly(self, search_with, import_scan_via_api):
        """
        NES-15888: Verify searching plugin families

        Scenario Tested:
        [x] Verify that search result should get retrieved for the given search text
        """
        scan_page = ScansPage()
        scan_page.refresh()
        wait(lambda: scan_page.is_element_present("scan_searchbox"))

        ScanList().click_on_scan(scan_name=import_scan_via_api[0])
        wait(lambda: visibility_of_element_located(ScanViewPage().vulnerability_tab),
             waiting_for='Vulnerabilities to get loads')

        plugin_family_list = PluginFamiliesEnabledDisabledList()
        available_status = list(set(plugin_family_list.get_plugin_family_status()))
        plugin_families_name_list = plugin_family_list.get_plugin_family_name()
        keyword_to_be_search = None

        if search_with in ["by_status", "by_family_name"]:
            random_keyword = random.choices(available_status if search_with == "by_status" else
                                            plugin_families_name_list, k=1)[0]
            keyword_to_be_search = random_keyword[random.randint(0, int(len(random_keyword) / 2)): random.randint(
                int(len(random_keyword) / 2 + 1), len(random_keyword) - 1)]
        else:
            random_keyword = random_string()

        scan_summary_page = ScanSummaryPage()
        expected_keyword_list = [random_keyword] if search_with == "random_string" else \
            [keyword_to_be_search, random_keyword]

        for keyword in expected_keyword_list:
            scan_summary_page.search_plugin_families_field.clear()
            scan_summary_page.search_plugin_families_field.value = keyword
            sleep(sleep_time=WAIT_NORMAL, reason="Search results takes some time to get populated")

            if len(expected_keyword_list) == 1:
                assert scan_summary_page.no_record_found.text == Messages.NotificationMessages.AdvancedSettings. \
                    no_record_found, "'No records found.' message is missing or mismatch when no search results found."
            else:
                for result in plugin_family_list.rows:
                    assert keyword in result.text.strip(), "Search plugins families is not functioning properly."

    @pytest.mark.xray(test_key='NES-15889')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('sort', SortOrder.VALID_ORDERS)
    @pytest.mark.parametrize('column_to_sort', ['Status', 'Family Name'])
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'advance_scan_c7kspv.nessus',
                                                      'file_path': 'nessus/tests/api/scan/test_data/'}], indirect=True)
    def test_verify_plugin_families_sorting_functioning_properly(self, sort, column_to_sort, import_scan_via_api):
        """
        NES-15889: Verify sorting of plugin families

        Scenario Tested:
        [x] Verify that sorting in 'ascending' and 'descending' order should work for both status and family name
            columns.
        """
        scan_page = ScansPage()
        scan_page.refresh()
        wait(lambda: scan_page.is_element_present("scan_searchbox"))

        close_pendo_guide_container_banner_for_nessus_pro()
        ScanList().click_on_scan(scan_name=import_scan_via_api[0])
        wait(lambda: visibility_of_element_located(ScanViewPage().vulnerability_tab),
             waiting_for='Vulnerabilities to get loads')

        before_plugin_data = self.get_plugin_family_row_data_from_all_pages(column_to_sort=column_to_sort)
        expected_plugin_families_list = sorted(before_plugin_data, key=lambda k: k.lower(), reverse=(
                sort == SortOrder.DESCENDING))

        ScanSummaryPage().pagination_first_arrow.click()
        plugin_family_list = PluginFamiliesEnabledDisabledList()

        sort_on_column_values(page_class_instance=plugin_family_list, sort=sort, column_name=column_to_sort)
        after_plugin_statuses = self.get_plugin_family_row_data_from_all_pages(column_to_sort=column_to_sort)

        assert expected_plugin_families_list == after_plugin_statuses, \
            "'{}' column is not getting sorted in '{}' order".format(column_to_sort, sort)

    @pytest.mark.xray(test_key='NES-15890')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'advance_scan_c7kspv.nessus',
                                                      'file_path': 'nessus/tests/api/scan/test_data/'}], indirect=True)
    def test_verify_results_per_page_dropdown_functioning_in_plugin_families_section(self, import_scan_via_api):
        """
        NES-15890: Verify pagination of Plugin Families section

        Scenario Tested:
        [x] Verify that Number of plugin families should displayed as per dropdown value selected.
        """
        scan_page = ScansPage()
        scan_page.refresh()
        wait(lambda: scan_page.is_element_present("scan_searchbox"))

        ScanList().click_on_scan(scan_name=import_scan_via_api[0])
        wait(lambda: visibility_of_element_located(ScanViewPage().vulnerability_tab),
             waiting_for='Vulnerabilities to get loads')

        scan_summary_page = ScanSummaryPage()
        plugin_family_list = PluginFamiliesEnabledDisabledList()
        results_per_page_dropdown_options = [option['value'] for option in
                                             scan_summary_page.results_per_page_dropdown.option_values]

        assert int(results_per_page_dropdown_options[0].strip()) == int(scan_summary_page.results_per_page_dropdown.
                                                                        get_value_selected()), \
            "Getting incorrect default value of 'Results per page' dropdown. Expected value is not '10'."

        is_next_button_enabled = True

        for option in results_per_page_dropdown_options:
            scan_summary_page.results_per_page_dropdown.select_by_visible_text(option)
            sleep(sleep_time=WAIT_NORMAL, reason="Plugin families row data takes time to populated")

            while is_next_button_enabled:
                assert len(plugin_family_list.rows) <= int(option), \
                    "Number of plugin families are not getting displayed as per the value selected from " \
                    "'Results per page' dropdown."

                is_next_button_enabled = "disabled" not in scan_summary_page.pagination_next_arrow.get_css_classes()

                if is_next_button_enabled:
                    scan_summary_page.pagination_next_arrow.click()

            scan_summary_page.pagination_first_arrow.click()

    @pytest.mark.xray(test_key='NES-15890')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'advance_scan_c7kspv.nessus',
                                                      'file_path': 'nessus/tests/api/scan/test_data/'}], indirect=True)
    def test_verify_pagination_is_functioning_properly_in_plugin_families_section(self, import_scan_via_api):
        """
        NES-15890: Verify pagination of Plugin Families section

        Scenario Tested:
        [x] Verify that Number of plugin families should displayed as per dropdown value selected.
        """
        scan_page = ScansPage()
        scan_page.refresh()
        wait(lambda: scan_page.is_element_present("scan_searchbox"))

        ScanList().click_on_scan(scan_name=import_scan_via_api[0])
        wait(lambda: visibility_of_element_located(ScanViewPage().vulnerability_tab),
             waiting_for='Vulnerabilities to get loads')

        scan_summary_page = ScanSummaryPage()
        plugin_family_list = PluginFamiliesEnabledDisabledList()
        is_next_button_enabled = True

        while is_next_button_enabled:
            previous_plugin_families_names = plugin_family_list.get_plugin_family_name()
            scan_summary_page.pagination_next_arrow.click()
            next_plugin_families_names = plugin_family_list.get_plugin_family_name()

            assert sorted(previous_plugin_families_names) != sorted(next_plugin_families_names), ""

            if "disabled" in scan_summary_page.pagination_next_arrow.get_css_classes():
                break

        scan_summary_page.pagination_first_arrow.click()

    @pytest.mark.xray(test_key='NES-15850')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_Scan_Result.db', 'password': 'nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/',
                                                      'encrypted': True}], indirect=True)
    def test_verify_scan_notes_section_under_scan_summary_page(self, import_scan_via_api):
        """
        NES-15850: Verify Scan Notes section under scan summary tab

        Scenario Tested:
        [x] Verify that 'Scan notes' section should be available under scan summary page.
        [ ] Verify 'Scan notes' section should have below listed fields:
                - host died in middle of scan (if any)
                - excluded assets due to plugins rules
                - hosts with > 1024 open ports
        """
        scan_page = ScansPage()
        scan_page.refresh()
        wait(lambda: scan_page.is_element_present("scan_searchbox"))

        ScanList().click_on_scan(scan_name=import_scan_via_api[0])
        wait(lambda: visibility_of_element_located(ScanViewPage().vulnerability_tab),
             waiting_for='Vulnerabilities to get loads')

        scan_summary_page = ScanSummaryPage()

        assert all([scan_summary_page.is_element_present("scan_notes_section"),
                    scan_summary_page.is_element_present("scan_notes_section_label"),
                    scan_summary_page.scan_notes_section_label.text.strip() == Nessus.Scan.Results.ScanSummaryTab.
                   SCAN_NOTES_SECTION_LABEL, scan_summary_page.is_element_present("search_notes_field"),
                    scan_summary_page.is_element_present("search_notes_icon"), scan_summary_page.is_element_present(
                "total_search_notes"), scan_summary_page.total_search_notes.text.strip() is not None,
                    len(scan_summary_page.total_search_notes.text) > 0]), \
            "'Scan Notes' section is not present under scan summary page."

    @pytest.mark.xray(test_key='NES-15903')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_Scan_Result.db', 'password': 'nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/',
                                                      'encrypted': True}], indirect=True)
    @pytest.mark.parametrize("search_with", ["by_title", "by_description", "random_string"])
    def test_verify_scan_notes_search_functioning_properly(self, import_scan_via_api, search_with):
        """
        NES-15903: Verify searching for Notes section

        Scenario Tested:
        [x] Verify that System should display accurate result under notes section based on given search input and the
            search count should also get updated accordingly.
        """
        scan_page = ScansPage()
        scan_page.refresh()
        wait(lambda: scan_page.is_element_present("scan_searchbox"))

        ScanList().click_on_scan(scan_name=import_scan_via_api[0])
        wait(lambda: visibility_of_element_located(ScanViewPage().vulnerability_tab),
             waiting_for='Vulnerabilities to get loads')

        scan_notes_list = ScanNotesList()
        scan_notes_titles = list(set(scan_notes_list.get_scan_notes_title()))
        scan_notes_descriptions = scan_notes_list.get_scan_notes_description()
        keyword_to_be_search = None

        if search_with in ["by_title", "by_description"]:
            random_keyword = random.choices(scan_notes_titles if search_with == "by_title" else
                                            scan_notes_descriptions, k=1)[0]
            keyword_to_be_search = random_keyword[random.randint(0, int(len(random_keyword) / 2)): random.randint(
                int(len(random_keyword) / 2 + 1), len(random_keyword) - 1)]
        else:
            random_keyword = random_string()

        scan_summary_page = ScanSummaryPage()
        expected_keyword_list = [random_keyword] if search_with == "random_string" else \
            [keyword_to_be_search, random_keyword]

        for keyword in expected_keyword_list:
            scan_summary_page.search_notes_field.clear()
            scan_summary_page.search_notes_field.value = keyword
            sleep(sleep_time=WAIT_NORMAL, reason="Search results takes some time to get populated")

            if len(expected_keyword_list) == 1:
                assert scan_summary_page.no_record_found.text == Messages.NotificationMessages.AdvancedSettings. \
                    no_record_found, "'No records found.' message is missing or mismatch when no search results found."
            else:
                for result in scan_notes_list.rows:
                    assert keyword in result.text.strip(), "Search scan notes is not functioning properly."

    @pytest.mark.xray(test_key='NES-15891')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('create_plugin_rules', [
        {'plugin_list': [{"host": "", "plugin_id": 82828, "type": "recast_critical"},
                         {"host": "", "plugin_id": 42873, "type": "recast_high"},
                         {"host": "", "plugin_id": 51192, "type": "recast_medium"},
                         {"host": "", "plugin_id": 65821, "type": "recast_low"},
                         {"host": "", "plugin_id": 64814, "type": "recast_info"}]}], indirect=True)
    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'target_ip': Nessus.Scan.Target.AWS_LINUX_TARGET_1, 'scan_name': random_name(prefix="{} - ".format(
            Nessus.TemplateNames.ADVANCED))}]}], indirect=True)
    def test_verify_plugin_rules_applied_section_under_scan_summary_page(self, create_plugin_rules, create_scans):
        """
        NES-15891: Verify Plugin Rules applied section

        Scenario Tested:
        [x] Verify that applied plugin rule is displayed under Plugin Rule Applied section with below details:
                - Host (on which rule applied)
                - Plugin ID (on which rule applied)
                - Severity (severity given in rule)
        """
        scan_name = create_scans[0]
        scan_list = ScanList()
        wait(lambda: scan_name in scan_list.get_all_scans())
        scan_id = get_scan_id(api_object=self.cat.api, scan_name=scan_name)

        with polling_ui():
            self.cat.api.scans.launch(scan_id=scan_id)
            wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                            timeout=TIME_THIRTY_MINUTES)

        scan_page = ScansPage()
        scan_page.refresh()
        wait(lambda: scan_page.is_element_present("scan_searchbox"))

        scan_list.click_on_scan(scan_name=scan_name)
        wait(lambda: visibility_of_element_located(ScanViewPage().vulnerability_tab),
             waiting_for='Vulnerabilities to get loads')

        scan_summary_page = ScanSummaryPage()

        assert all([scan_summary_page.is_element_present("plugin_rules_applied_section"),
                    scan_summary_page.is_element_present("plugin_rules_applied_section_label"),
                    scan_summary_page.plugin_rules_applied_section_label.text.strip() == Nessus.Scan.Results.
                   ScanSummaryTab.PLUGIN_RULES_APPLIED_SECTION_LABEL, scan_summary_page.is_element_present(
                "search_plugin_rules_field"), scan_summary_page.search_plugin_rules_field.get_attribute(
                "placeholder") == Nessus.Scan.Results.ScanSummaryTab.PLUGIN_RULES_SEARCH_FIELD_PLACEHOLDER,
                    scan_summary_page.is_element_present("total_search_plugin_rules"),
                    scan_summary_page.total_search_plugin_rules.text.strip() is not None,
                    len(scan_summary_page.total_search_plugin_rules.text) > 0,
                    scan_summary_page.is_element_present("search_plugin_rules_icon"),
                    scan_summary_page.is_element_present("plugin_rules_applied_table")]), \
            "'Plugin Rules Applied' section is not present under scan summary page."

    @pytest.mark.xray(test_key='NES-15892')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('create_plugin_rules', [
        {'plugin_list': [{"host": "", "plugin_id": 82828, "type": "recast_critical"},
                         {"host": "", "plugin_id": 42873, "type": "recast_high"},
                         {"host": "", "plugin_id": 51192, "type": "recast_medium"},
                         {"host": "", "plugin_id": 65821, "type": "recast_low"},
                         {"host": "", "plugin_id": 64814, "type": "recast_info"}]}], indirect=True)
    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'target_ip': Nessus.Scan.Target.AWS_LINUX_TARGET_1, 'scan_name': random_name(prefix="{} - ".format(
            Nessus.TemplateNames.ADVANCED))}]}], indirect=True)
    @pytest.mark.parametrize("search_with", ["by_host", "by_plugin_id", "by_severity", "random_string"])
    def test_verify_plugin_rules_applied_search_is_functioning_properly(self, create_plugin_rules, create_scans,
                                                                        search_with):
        """
        NES-15892: Verify searching plugin rule

        Scenario Tested:
        [x] Verify that search result should be retrieved for given host, plugin ID and severity.
        """
        scan_name = create_scans[0]
        scan_list = ScanList()
        wait(lambda: scan_name in scan_list.get_all_scans())
        scan_id = get_scan_id(api_object=self.cat.api, scan_name=scan_name)

        with polling_ui():
            self.cat.api.scans.launch(scan_id=scan_id)
            wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                            timeout=TIME_THIRTY_MINUTES)

        scan_page = ScansPage()
        scan_page.refresh()
        wait(lambda: scan_page.is_element_present("scan_searchbox"))

        scan_list.click_on_scan(scan_name=scan_name)
        wait(lambda: visibility_of_element_located(ScanViewPage().vulnerability_tab),
             waiting_for='Vulnerabilities to get loads')

        plugin_rules_list = PluginRulesAppliedList()
        keyword_to_be_search = None
        list_of_data = []

        if search_with == "by_host":
            list_of_data = list(set(plugin_rules_list.get_plugin_rules_host()))
        elif search_with == "by_plugin_id":
            list_of_data = list(set(plugin_rules_list.get_plugin_rules_id()))
        elif search_with == "by_severity":
            list_of_data = list(set(plugin_rules_list.get_plugin_severity()))

        if search_with in ["by_host", "by_plugin_id", "by_severity"]:
            random_keyword = random.choices(list_of_data, k=1)[0]
            keyword_to_be_search = random_keyword[random.randint(0, int(len(random_keyword) / 2)): random.randint(
                int(len(random_keyword) / 2 + 1), len(random_keyword) - 1)]
        else:
            random_keyword = random_string()

        scan_summary_page = ScanSummaryPage()
        expected_keyword_list = [random_keyword] if search_with == "random_string" else \
            [keyword_to_be_search, random_keyword]

        for keyword in expected_keyword_list:
            scan_summary_page.search_plugin_rules_field.clear()
            scan_summary_page.search_plugin_rules_field.value = keyword
            sleep(sleep_time=WAIT_NORMAL, reason="Search results takes some time to get populated")

            if len(expected_keyword_list) == 1:
                assert scan_summary_page.no_record_found.text == Messages.NotificationMessages. \
                    AdvancedSettings.no_record_found, "'No records found.' message is missing or mismatch " \
                                                      "when no search results found."
            else:
                for result in plugin_rules_list.plugin_rules_data_rows:
                    assert keyword in result.text.strip(), "Search plugins rules is not functioning properly."

    @pytest.mark.xray(test_key='NES-15893')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('create_plugin_rules', [
        {'plugin_list': [{"host": "", "plugin_id": 82828, "type": "recast_critical"},
                         {"host": "", "plugin_id": 42873, "type": "recast_high"},
                         {"host": "", "plugin_id": 51192, "type": "recast_medium"},
                         {"host": "", "plugin_id": 65821, "type": "recast_low"},
                         {"host": "", "plugin_id": 64814, "type": "recast_info"}]}], indirect=True)
    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'target_ip': Nessus.Scan.Target.AWS_LINUX_TARGET_1, 'scan_name': random_name(prefix="{} - ".format(
            Nessus.TemplateNames.ADVANCED))}]}], indirect=True)
    @pytest.mark.parametrize('sort', SortOrder.VALID_ORDERS)
    @pytest.mark.parametrize('column_to_sort', ['Host', 'Plugin ID', 'Severity'])
    def test_verify_plugin_rules_sorting_functioning_properly(self, create_plugin_rules, create_scans, sort,
                                                              column_to_sort):
        """
        NES-15893: Verify sorting of plugin rules

        Scenario Tested:
        [x] Verify that sorting functionality should work for available all columns Host, Plugin ID, Severity.
        """
        scan_name = create_scans[0]
        scan_list = ScanList()
        wait(lambda: scan_name in scan_list.get_all_scans())
        scan_id = get_scan_id(api_object=self.cat.api, scan_name=scan_name)

        with polling_ui():
            self.cat.api.scans.launch(scan_id=scan_id)
            wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                            timeout=TIME_THIRTY_MINUTES)

        scan_page = ScansPage()
        scan_page.refresh()
        wait(lambda: scan_page.is_element_present("scan_searchbox"))

        scan_list.click_on_scan(scan_name=scan_name)
        wait(lambda: visibility_of_element_located(ScanViewPage().vulnerability_tab),
             waiting_for='Vulnerabilities to get loads')

        column_mapping = {'Host': 'host', 'Plugin ID': 'plugin_id', 'Severity': 'severity'}
        map_attribute = column_mapping[column_to_sort]

        plugin_rules_list = PluginRulesAppliedList()
        expected_plugin_rules_list = sorted([getattr(plugin_rule, map_attribute) for plugin_rule in
                                             plugin_rules_list.plugin_rules_data_rows], key=lambda k: k.lower(),
                                            reverse=(sort == SortOrder.DESCENDING))

        for column in plugin_rules_list.plugin_rules_table_columns:
            if column.text == column_to_sort:
                if sort == SortOrder.DESCENDING:
                    column.sort_descending()
                else:
                    column.sort_ascending()

        sorted_plugin_rules_list = [getattr(plugin_rule, map_attribute) for plugin_rule in
                                    plugin_rules_list.plugin_rules_data_rows]

        assert expected_plugin_rules_list == sorted_plugin_rules_list, \
            "'{}' column is not getting sorted in '{}' order".format(column_to_sort, sort)

    @pytest.mark.xray(test_key='NES-15847')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_scans", [
        {'scans_details': [
            {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
             "scan_name": random_name(prefix="{} - ".format('Scan Summary without credential')),
             "keep_original_scan_name": True, "target_ip": Nessus.Scan.Target.PUB_TARGET_4}]},
        {'scans_details': [
            {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
             "scan_name": random_name(prefix="{} - ".format('Scan Summary with localhost')),
             "keep_original_scan_name": True, "target_ip": Nessus.Scan.Target.LOCALHOST}]}], indirect=True)
    def test_create_scan_without_credential_with_host_under_scan_summary_page(self, create_scans):
        """
        NES-15847: Verify Authentication/Credential Info under Summary tab

        Scenario Tested:
        [x] Create a scan without giving credential while configuration and run it (other than localhost)
        [x] Create a scan with localhost and do not give credential while configuring scan. Run it
        """

        for create_scan in create_scans:
            scan_list = ScanList()
            scan_list.launch_scan_and_wait_for_status(scan_name=create_scan, status=API.Scan.Status.COMPLETED)
            scan_list.click_on_scan(create_scan)
            scan_summary_page = ScanSummaryPage()
            succeeded_hosts = int(scan_summary_page.succeeded_hosts_with_creds_value.text.strip())
            failed_hosts = int(scan_summary_page.failed_hosts_creds_value.text.strip())
            assert succeeded_hosts == 1 \
                if "localhost" in create_scan else succeeded_hosts == 0
            scan_view_page = ScanViewPage()
            scan_view_page.host_tab.click()
            scan_host = ScansHostList()
            assert failed_hosts == 0 if "localhost" in create_scan else failed_hosts == 1
            if "localhost" in create_scan:
                assert len(scan_host.results) == succeeded_hosts


    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_scan", [
        {'template_name': 'Advanced Scan', 'scan_type': API.Permissions.Types.SCANNER,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED_NAME)),
            'host_ip': Nessus.Scan.Target.LOCALHOST}], indirect=True)
    def test_verify_able_to_create_scan_with_slash(self, create_scan):
        """
        CS-58841: Create and run a scan with slash in scan name.
        1. Login to Nessus
        2. Go to scan main page
        3. Create a scan with unique name
        4. launch the scan
        5. click on scan
        6. verify the results.
        """
        scan_name = create_scan
        scan_page = ScansPage()
        scan_page.save_button.click()
        wait(lambda: scan_page.is_element_present("scan_searchbox"), waiting_for="scans list get loaded")

        scan_list = ScanList()
        scan_list.launch_scan(scan_name=scan_name)
        scan_id = get_scan_id(api_object=self.cat.api, scan_name=scan_name)

        with polling_ui():
            wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                            timeout=TIME_THIRTY_MINUTES)

        scan_page = ScansPage()
        scan_page.refresh()
        wait(lambda: scan_page.is_element_present("scan_searchbox"))

        scan_list.click_on_scan(scan_name=scan_name)
        wait(lambda: visibility_of_element_located(ScanViewPage().vulnerability_tab),
             waiting_for='Vulnerabilities tab to visible.')

        assert ScanViewPage().is_element_present('vulnerability_tab'), "scan is not completed successfully."

        ScanViewPage().vulnerability_tab.click()

        wait(lambda: visibility_of_element_located(ScanViewPage().filter_link),
             waiting_for='Vulnerabilities to get loads')
        assert ScanViewPage().is_element_present('filter_link'), "scan results are not generated sucessfully."

