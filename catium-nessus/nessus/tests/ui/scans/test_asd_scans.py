from datetime import datetime

import pytest
from catium.lib.api.base_api_object import ResponseObject
from catium.lib.const import WAIT_NORMAL, TIME_FIVE_MINUTES, TIME_THIRTY_MINUTES, TIME_THREE_SECONDS
from catium.lib.util import random_name
from catium.lib.webium.wait import wait
from nessus.pageobjects.shared.loading import LoadingCircle

from nessus.apiobjects.nessus_api import NessusAPI

from nessus.helpers.scan import click_on_scan_and_go_to_hosts_tab, go_to_scan, wait_for_scan_id, \
    launch_scan_and_wait_for_completion, delete_scan_by_scan_id
from nessus.pageobjects.scans.scan_view_page import ScanHistoryList, ScanViewPage

from nessus.helpers.waiters import wait_scan_state
from nessus.helpers.polling_ui import polling_ui
from nessus.lib.const.constants import Nessus, API

from nessus.pageobjects.generic.generic_modals import FilterModal
from nessus.pageobjects.scans.scan_view_page import ScansASDHostsList
from nessus.tests.api.scan.test_asd_scans import AsdHelper


@pytest.mark.nessus_expert
@pytest.mark.usefixtures('nessus_api_login', 'login')
class TestASDScans:
    """ Test cases to cover UI functionality for filtering ASD scans """

    cat = None

    @pytest.mark.xray(test_key='NES-16777')
    @pytest.mark.parametrize("filter_scan", [
        {'filter_operator': Nessus.Filter.FilterOperators.EQUAL_TO,
         'filter_value': "www.tenablenetworksecurity.com",
         'result_found': "www.tenablenetworksecurity.com",
         'not_result_found': "tenablenetworksecurity.com"},
        {'filter_operator': Nessus.Filter.FilterOperators.NOT_EQUAL_TO,
         'filter_value': "www.tenablenetworksecurity.com",
         'result_found': "tenablenetworksecurity.com",
         'not_result_found': "www.tenablenetworksecurity.com"},
        {'filter_operator': Nessus.Filter.FilterOperators.CONTAINS,
         'filter_value': "www",
         'result_found': "www.tenablenetworksecurity.com",
         'not_result_found': "tenablenetworksecurity.com"},
        {'filter_operator': Nessus.Filter.FilterOperators.NOT_CONTAINS,
         'filter_value': "www",
         'result_found': "tenablenetworksecurity.com",
         'not_result_found': "www.tenablenetworksecurity.com"},
    ])
    def test_ASD_scan_details(self, filter_scan) -> None:
        """
        NES-16777: Validate filtering of completed ASD scan - hostname

        Scenario Tested:
        Create and Launch ASD scan
        Wait for completed ASD scan
        Open ASD scan
        Add filters for hostname
        Validate filtered data

        """
        scan_id = None
        filter_type = Nessus.Filter.FilterKeys.HOSTNAME
        asd_helper = AsdHelper(api=self.cat.api)
        try:
            scan = asd_helper.create_completed_scan(api=self.cat.api, hostname='tenablenetworksecurity.com')
            scan_id = scan['scan']['id']
            scan_name = scan['scan']['name']

            click_on_scan_and_go_to_hosts_tab(scan_name=scan_name)

            FilterModal.add_and_apply_to_filter(
                key=filter_type,
                operator=filter_scan["filter_operator"],
                value=filter_scan["filter_value"]
            )

            host_list = ScansASDHostsList()
            rows = host_list.get_all()

            result = str(filter_scan["result_found"])
            bad_result = str(filter_scan["not_result_found"])
            data = [row[Nessus.Filter.FilterKeys.HOSTNAME] for row in rows]
            assert result in data, f"Could not find the result '{result}' in the list of results"
            assert bad_result not in data, f"Should not have found the result '{bad_result}' in the list of results"
        finally:
            delete_scan_by_scan_id(api_object=self.cat.api, scan_id=scan_id)

    @pytest.mark.xray(test_key='NES-16777')
    @pytest.mark.parametrize("search_scan", [
        {'hostname': "tenablenetworksecurity.com",
         'search_value': 'NS',
         'results_found': ["tenablenetworksecurity.com"],
         'not_results_found': ["www.tenablenetworksecurity.com"]},
        {'hostname': "tenablenetworksecurity.com",
         'search_value': 'ns-415',
         'results_found': ["tenablenetworksecurity.com"],
         'not_results_found': ["www.tenablenetworksecurity.com"]}
    ])
    def test_ASD_search_of_records(self, search_scan) -> None:
        """
        NES-16777: Validate search of completed ASD scan

        Scenario Tested:
        Create and Launch ASD scan
        Wait for completed ASD scan
        Open ASD scan
        Add search through the records
        Validate data

        """
        scan_id = None
        try:
            search_value = search_scan["search_value"]
            hostname = "water.com"
            if 'hostname' in search_scan:
                hostname = search_scan["hostname"]

            scan: ResponseObject = AsdHelper.create_completed_scan(api=self.cat.api, hostname=hostname)

            scan_id = scan['scan']['id']
            scan_name = scan['scan']['name']

            click_on_scan_and_go_to_hosts_tab(scan_name=scan_name)

            scan_result_page = ScanViewPage()
            scan_result_page.apply_search(search_string=search_value)
            LoadingCircle(TIME_THREE_SECONDS)
            host_list = ScansASDHostsList()

            error_values = list()
            _, not_found = scan_result_page.search_results(search_list=search_scan["results_found"],
                                                           records_list_object=host_list)
            if not_found:
                error_values.append(f"Could not find these items '{not_found}' when searching for '{search_value}'")

            found, _ = scan_result_page.search_results(search_list=search_scan["not_results_found"],
                                                       records_list_object=host_list)
            if found:
                error_values.append(f"Found these items '{found}' when searching for '{search_value}'")

            assert len(error_values) == 0, f"Errors found: {error_values}"

        finally:
            delete_scan_by_scan_id(api_object=self.cat.api, scan_id=scan_id)

    @pytest.mark.xray(test_key='NES-16777')
    @pytest.mark.parametrize("search_scan", [
        {'hostname': "tenable.com",
         'search_value': 'acas',
         'result_found': "acas-provisioning-staging.tenable.com",
         'result_not_found': "account-staging.tenable.com",
         'column': Nessus.Filter.FilterKeys.HOSTNAME},
        {'hostname': "tenable.com",
         'search_value': 'acas-provisioning-staging.tenable.com',
         'result_found': "104.16.48.5",
         'result_not_found': "127.0.0.1",
         'column': Nessus.Filter.FilterKeys.IP_ADDRESS},
        {'hostname': "tenable.com",
         'search_value': '8080',
         'result_found': "8080",
         'result_not_found': "9999",
         'column': Nessus.Filter.FilterKeys.PORT},
        {'hostname': "tenable.com",
         'search_value': '8080',
         'result_found': "2086",
         'result_not_found': "9999",
         'column': Nessus.Filter.FilterKeys.PORT},
        {'hostname': "tenable.com",
         'search_value': '8080',
         'result_found': "80, 443, 2082, 2083, 2086, 2087, 8080, 8443",
         'result_not_found': "9999",
         'column': Nessus.Filter.FilterKeys.PORT},
        {'hostname': "tenable.com",
         'search_value': 'MX',
         'result_found': "MX",
         'result_not_found': "CNAME",
         'column': Nessus.Filter.FilterKeys.RECORD_TYPE},
        {'hostname': "tenable.com",
         'search_value': 'cloudflare.net',
         'result_found': "acas-provisioning-staging.tenable.com.cdn.cloudflare.net",
         'result_not_found': "appliance.cloud.tenable.com",
         'column': Nessus.Filter.FilterKeys.TARGET_HOSTNAME},
    ])
    def test_ASD_search_of_records_by_column(self, search_scan) -> None:
        """
        NES-16777: Validate search of completed ASD scan

        Scenario Tested:
        Create and Launch ASD scan
        Wait for completed ASD scan
        Open ASD scan
        Add search through the records in a specific column
        Validate data

        """
        scan_id = None
        try:
            search_value = search_scan["search_value"]
            hostname = "water.com"
            if 'hostname' in search_scan:
                hostname = search_scan["hostname"]

            scan: ResponseObject = AsdHelper.create_completed_scan(api=self.cat.api, hostname=hostname)

            scan_id = scan['scan']['id']
            scan_name = scan['scan']['name']

            click_on_scan_and_go_to_hosts_tab(scan_name=scan_name)

            scan_result_page = ScanViewPage()
            scan_result_page.apply_search(search_string=search_value)
            LoadingCircle(TIME_THREE_SECONDS)
            host_list = ScansASDHostsList()
            result_found = search_scan['result_found']
            this_is_not_the_result_you_are_looking_for__move_along__move_along = search_scan['result_not_found']
            column = search_scan['column']
            assert host_list.validate_value_in_column(item=result_found, column=column), \
                f"Did not find '{result_found}' in column '{column}'"
            assert not host_list.validate_value_in_column(
                item=this_is_not_the_result_you_are_looking_for__move_along__move_along, column=column), \
                f"Found '{this_is_not_the_result_you_are_looking_for__move_along__move_along}' in column '{column}'"

        finally:
            delete_scan_by_scan_id(api_object=self.cat.api, scan_id=scan_id)

    @pytest.mark.xray(test_key='NES-16777')
    @pytest.mark.parametrize("filter_scan", [
        {'filter_operator': Nessus.Filter.FilterOperators.EQUAL_TO,
         'filter_value': "tenablenetworksecurity.com",
         'result_found': "tenablenetworksecurity.com"},
        {'filter_operator': Nessus.Filter.FilterOperators.EQUAL_TO,
         'filter_value': "webpagetest.org",
         'result_found': "webpagetest.org"}
    ])
    def test_ASD_two_domains(self, filter_scan) -> None:
        """
        NES-16777: Validate ASD scan for two top level domains
        Scenario Tested:
        Create and Launch ASD scan with two top level domains
        Wait for completed ASD scan
        Open ASD scan
        Add search through the records
        Validate data
        """
        scan_id = None
        filter_type = Nessus.Filter.FilterKeys.HOSTNAME
        asd_helper = AsdHelper(api=self.cat.api)
        try:
            scan = asd_helper.create_completed_scan(api=self.cat.api, hostname='tenablenetworksecurity.com, '
                                                                               'webpagetest.org')
            scan_id = scan['scan']['id']
            scan_name = scan['scan']['name']

            click_on_scan_and_go_to_hosts_tab(scan_name=scan_name)

            FilterModal.add_and_apply_to_filter(
                key=filter_type,
                operator=filter_scan["filter_operator"],
                value=filter_scan["filter_value"]
            )

            host_list = ScansASDHostsList()
            rows = host_list.get_all()

            result = str(filter_scan["result_found"])
            data = [row[Nessus.Filter.FilterKeys.HOSTNAME] for row in rows]
            assert result in data, f"Could not find the result '{result}' in the list of results"
        finally:
            delete_scan_by_scan_id(api_object=self.cat.api, scan_id=scan_id)


@pytest.mark.nessus_expert
@pytest.mark.usefixtures('nessus_api_login', 'login')
class TestCreatedScanResultsForASD:
    """
    Covers Scan details page for ASD scans
    """

    cat = None

    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ATTACK_SURFACE_DISCOVERY,
         'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix=f"{Nessus.TemplateNames.ATTACK_SURFACE_DISCOVERY} - "),
         'domain_name': 'tenable.com',
         'keep_original_scan_name': True, 'add_configuration': False}
    ], 'ret_details': True}], indirect=True)
    def test_associated_tag_and_elements_of_running_ASD_scan(self, create_scans):
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
        scan_id = None
        scan = create_scans[0]
        scan_name = scan.get('scan_name')

        api: NessusAPI = self.cat.api
        try:
            scan_id = wait_for_scan_id(api_object=api, scan_name=scan_name)
            launch_scan_and_wait_for_completion(api_object=api, scan_id=scan_id)
            scan_result_page = go_to_scan(scan_name=scan_name)

            assert all([
                scan_result_page.is_element_present('configure_button'),
                scan_result_page.is_element_present('audit_trail_button'),
                scan_result_page.is_element_present('launch_dropdown'),
                scan_result_page.is_element_present('export_button')
            ]), "Default elements are invisible in scan_result page."

            scan_result_page.launch_scan(launch_type=Nessus.Scan.Results.LaunchTypes.DEFAULT)
            history_list = ScanHistoryList()
            wait(lambda: (history_list.rows[0].scan_status == API.Scan.Status.RUNNING.title()),
                 waiting_for='Scan to be in running state', timeout_seconds=WAIT_NORMAL)

            if history_list.rows[0].scan_status == API.Scan.Status.RUNNING.title():
                assert all([
                    scan_result_page.is_element_present('configure_button'),
                    (not scan_result_page.is_element_present('audit_trail_button')),
                    (not scan_result_page.is_element_present('launch_dropdown')),
                    (not scan_result_page.is_element_present('export_button')),
                    (history_list.rows[0].scan_start_time.startswith(Nessus.Scan.Results.CURRENT_TAG)),
                    (all([scan.disabled_checkbox.get_attribute('aria-disabled') == 'true'
                          for scan in history_list.rows]))
                ]), "'Current' prefix tag of running scan is mismatched or not found/"
            else:
                pytest.xfail(
                    reason="Scan might gets completed or not started yet. Test can be done only with running scan.")

            with polling_ui():
                scan_completed = wait_scan_state(api=self.cat.api, scan_id=scan_id,
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
        finally:
            delete_scan_by_scan_id(api_object=api, scan_id=scan_id)

    def test_ASD_scan_details_section(self):
        """
        Verify scan details section in middle right portion of scan_result page.
        1. Click on the scan to view the results page.
        2. Verify “Scan Details” section is visible in the middle right portion of the page.
        3. Verify the section contains some value for these (“Name”/ “Status”/ “Policy”/ “Start”) parameters.
        """
        scan_id = None
        api: NessusAPI = self.cat.api
        asd_helper = AsdHelper(api=self.cat.api)
        scan_detail_levels = Nessus.Scan.Results.ScanDetailsLevels
        try:
            # GIVEN - using the API to setup
            scan = asd_helper.create_completed_scan(api=self.cat.api, hostname="tenable.com")
            scan_id = scan['scan']['id']
            scan_name = scan['scan']['name']
            scan_details = api.scans.details(scan_id=scan_id)

            scan_start_time = f"Today at {datetime.fromtimestamp(scan_details['info']['scan_start']).strftime('%I:%M %p')}"
            scan_end_time = f"Today at {datetime.fromtimestamp(scan_details['info']['scan_start']).strftime('%I:%M %p')}"

            # WHEN - Get the Scan Details
            click_on_scan_and_go_to_hosts_tab(scan_name=scan_name)
            scan_result_page = ScanViewPage()

            scan_header = scan_result_page.right_column_header.text
            scan_status = scan_result_page.get_levels_value_of_details_section(scan_detail_levels.SCAN_STATUS).text
            scan_policy = scan_result_page.get_levels_value_of_details_section(scan_detail_levels.SCAN_POLICY).text
            scan_start = scan_result_page.get_levels_value_of_details_section(scan_detail_levels.SCAN_START_TIME).text
            scan_start_lst = scan_start.split('at')
            scan_start = scan_start_lst[1].strip()
            scan_end = scan_result_page.get_levels_value_of_details_section(scan_detail_levels.SCAN_END_TIME).text
            scan_end_lst = scan_end.split('at')
            scan_end = scan_end_lst[1].strip()

            # THEN - Validate the Scan Details
            assert all([
                scan_header == Nessus.Scan.Results.RightColumnHeader.SCAN_DETAILS,
                scan_status == API.Scan.Status.COMPLETED.title(),
                scan_policy == Nessus.TemplateNames.ATTACK_SURFACE_DISCOVERY,
                scan_start in scan_start_time,
                scan_end in scan_end_time,
            ])
        finally:
            delete_scan_by_scan_id(api_object=api, scan_id=scan_id)


@pytest.mark.nessus_expert
@pytest.mark.usefixtures('nessus_api_login', 'login')
class TestASDScanResultsFiltering:
    """ Test cases to cover UI functionality for filtering ASD scans """

    cat = None

    @pytest.mark.xray(test_key='NES-16777')
    @pytest.mark.parametrize("filter_scan", [
        {'filter_operator': Nessus.Filter.FilterOperators.EQUAL_TO,
         'filter_value': "tenablenetworksecurity.com",
         'result_found': "tenablenetworksecurity.com",
         'not_result_found': "www.tenablenetworksecurity.com"},
        {'filter_operator': Nessus.Filter.FilterOperators.NOT_EQUAL_TO,
         'filter_value': "tenablenetworksecurity.com",
         'result_found': "www.tenablenetworksecurity.com",
         'not_result_found': "tenablenetworksecurity.com"},
        {'filter_operator': Nessus.Filter.FilterOperators.CONTAINS,
         'filter_value': "www",
         'result_found': "www.tenablenetworksecurity.com",
         'not_result_found': "tenablenetworksecurity.com"},
        {'filter_operator': Nessus.Filter.FilterOperators.NOT_CONTAINS,
         'filter_value': "www",
         'result_found': "tenablenetworksecurity.com",
         'not_result_found': "www.tenablenetworksecurity.com"},
    ])
    def test_ASD_filtering_of_hostname(self, filter_scan) -> None:
        """
        NES-16777: Validate filtering of completed ASD scan - hostname

        Scenario Tested:
        Create and Launch ASD scan
        Wait for completed ASD scan
        Open ASD scan
        Add filters for hostname
        Validate filtered data

        """
        scan_id = None
        filter_type = Nessus.Filter.FilterKeys.HOSTNAME
        asd_helper = AsdHelper(api=self.cat.api)
        try:
            scan = asd_helper.create_completed_scan(api=self.cat.api, hostname='tenablenetworksecurity.com')
            scan_id = scan['scan']['id']
            scan_name = scan['scan']['name']

            click_on_scan_and_go_to_hosts_tab(scan_name=scan_name)

            FilterModal.add_and_apply_to_filter(
                key=filter_type,
                operator=filter_scan["filter_operator"],
                value=filter_scan["filter_value"]
            )

            host_list = ScansASDHostsList()
            rows = host_list.get_all()

            result = str(filter_scan["result_found"])
            bad_result = str(filter_scan["not_result_found"])
            data = [row[Nessus.Filter.FilterKeys.HOSTNAME] for row in rows]
            assert result in data, f"Could not find the result '{result}' in the list of results"
            assert bad_result not in data, f"Should not have found the result '{bad_result}' in the list of results"
        finally:
            delete_scan_by_scan_id(api_object=self.cat.api, scan_id=scan_id)

    @pytest.mark.xray(test_key='NES-16777')
    @pytest.mark.parametrize("filter_scan", [
        {'filter_operator': Nessus.Filter.FilterOperators.EQUAL_TO,
         'filter_value': "80",
         'result_found': "tenablenetworksecurity.com",
         'not_result_found': "www.tenable@networksecurity.com"},
        {'filter_operator': Nessus.Filter.FilterOperators.NOT_EQUAL_TO,
         'filter_value': "443",
         'result_found': "tenablenetworksecurity.com",
         'not_result_found': "www.tenable@networksecurity.com"},
        {'filter_operator': Nessus.Filter.FilterOperators.CONTAINS,
         'filter_value': "80",
         'result_found': "tenablenetworksecurity.com",
         'not_result_found': "www.tenable@networksecurity.com"},
        {'filter_operator': Nessus.Filter.FilterOperators.NOT_CONTAINS,
         'filter_value': "443",
         'result_found': "tenablenetworksecurity.com",
         'not_result_found': "www.tenable@networksecurity.com"},
    ])
    def test_ASD_filtering_of_ports(self, filter_scan) -> None:
        """
        NES-16777: Validate filtering of completed ASD scan - Ports

        Scenario Tested:
        Create and Launch ASD scan
        Wait for completed ASD scan
        Open ASD scan
        Add filters for Ports
        Validate filtered data

        """
        scan_id = None
        filter_type = Nessus.Filter.FilterKeys.PORT
        asd_helper = AsdHelper(api=self.cat.api)
        try:
            scan = asd_helper.create_completed_scan(api=self.cat.api, hostname='tenablenetworksecurity.com')
            scan_id = scan['scan']['id']
            scan_name = scan['scan']['name']

            click_on_scan_and_go_to_hosts_tab(scan_name=scan_name)

            FilterModal.add_and_apply_to_filter(
                key=filter_type,
                operator=filter_scan["filter_operator"],
                value=filter_scan["filter_value"]
            )

            host_list = ScansASDHostsList()
            rows = host_list.get_all()

            result = str(filter_scan["result_found"])
            bad_result = str(filter_scan["not_result_found"])
            data = [row[Nessus.Filter.FilterKeys.HOSTNAME] for row in rows]
            assert result in data, f"Could not find the result '{result}' in the list of results"
            assert bad_result not in data, f"Should not have found the result '{bad_result}' in the list of results"
        finally:
            delete_scan_by_scan_id(api_object=self.cat.api, scan_id=scan_id)

    @pytest.mark.xray(test_key='NES-16777')
    @pytest.mark.parametrize("filter_scan", [
        {'hostname': "tenable.com",
         'filter_operator': Nessus.Filter.FilterOperators.EQUAL_TO,
         'filter_value': Nessus.Filter.FilterRecordTypes.AAAA,
         'result_found': Nessus.Filter.FilterRecordTypes.AAAA,
         'not_result_found': Nessus.Filter.FilterRecordTypes.CNAME,
         'filter_key': Nessus.Filter.FilterKeys.RECORD_TYPE},
        {'hostname': "tenable.com",
         'filter_operator': Nessus.Filter.FilterOperators.NOT_EQUAL_TO,
         'filter_value': Nessus.Filter.FilterRecordTypes.CNAME,
         'result_found': Nessus.Filter.FilterRecordTypes.A,
         'not_result_found': Nessus.Filter.FilterRecordTypes.CNAME,
         'filter_key': Nessus.Filter.FilterKeys.RECORD_TYPE},
        {'hostname': "tenable.com",
         'filter_operator': Nessus.Filter.FilterOperators.EQUAL_TO,
         'filter_value': Nessus.Filter.FilterRecordTypes.SOA,
         'result_found': Nessus.Filter.FilterRecordTypes.SOA,
         'not_result_found': Nessus.Filter.FilterRecordTypes.CNAME,
         'filter_key': Nessus.Filter.FilterKeys.RECORD_TYPE},
        {'hostname': "tenable.com",
         'filter_operator': Nessus.Filter.FilterOperators.NOT_CONTAINS,
         'filter_value': Nessus.Filter.FilterRecordTypes.A,
         'result_found': Nessus.Filter.FilterRecordTypes.NS,
         'not_result_found': Nessus.Filter.FilterRecordTypes.AAAA,
         'filter_key': Nessus.Filter.FilterKeys.RECORD_TYPE},
    ])
    def test_ASD_filtering_of_record_types(self, filter_scan) -> None:
        """
        NES-16777: Validate filtering of completed ASD scan - Record Type

        Scenario Tested:
        Create and Launch ASD scan
        Wait for completed ASD scan
        Open ASD scan
        Add filters for Record Type
        Validate filtered data

        """
        scan_id = None
        filter_type = Nessus.Filter.FilterKeys.RECORD_TYPE
        try:
            hostname = "water.com"
            if 'hostname' in filter_scan:
                hostname = filter_scan["hostname"]

            filter_key = Nessus.Filter.FilterKeys.HOSTNAME
            if 'filter_key' in filter_scan:
                filter_key = filter_scan["filter_key"]
                if filter_key == "Port":
                    filter_key = "Ports"
                elif filter_key == "Record Type":
                    filter_key = "Type"

            scan: ResponseObject = AsdHelper.create_completed_scan(api=self.cat.api, hostname=hostname)

            scan_id = scan['scan']['id']
            scan_name = scan['scan']['name']

            click_on_scan_and_go_to_hosts_tab(scan_name=scan_name)

            FilterModal.add_and_apply_to_filter(
                key=filter_type,
                operator=filter_scan["filter_operator"],
                value=filter_scan["filter_value"]
            )

            host_list = ScansASDHostsList()
            rows = host_list.get_all()

            result = str(filter_scan["result_found"])
            bad_result = str(filter_scan["not_result_found"])
            data = [row[filter_key] for row in rows]
            assert result in data, f"Could not find the result '{result}' in the list of results"
            assert bad_result not in data, f"Should not have found the result '{bad_result}' in the list of results"
        finally:
            delete_scan_by_scan_id(api_object=self.cat.api, scan_id=scan_id)
