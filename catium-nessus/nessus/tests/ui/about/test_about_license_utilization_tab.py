""""
Nessus test cases related to License Utilization tab on About page

:copyright: Tenable Network Security, 2019
:date: August 12, 2018
:last_modified: Apr 26, 2023
:author: @vsoni, @krpatel.ctr, @sacharya, @mdabra

"""
import re

import pytest
from selenium.webdriver.support.expected_conditions import visibility_of_element_located

from catium.helpers.sleep_lib import sleep
from catium.lib import const
from catium.lib.const import WAIT_LONG, TIME_FIVE_SECONDS
from catium.lib.log import create_logger
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.helpers.sort import sort_on_column_values
from nessus.lib.const import API, Nessus, SortOrder, random_name
from nessus.pageobjects.about.about_page import OverView, HostsList, LicenseUtilization
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import NotificationActions
from nessus.pageobjects.scans.scans_page import ScansPage, ScanList

log = create_logger()


@pytest.mark.usefixtures('login')
@pytest.mark.nessus_settings_1
@pytest.mark.nessus_home
class TestAboutLicenseUtilization:
    """Test cases related to License consumption visibility (NES-9865)"""

    cat = None

    @pytest.mark.xray(test_key='NES-14201')
    @pytest.mark.nessus_smoke
    def test_visibility_and_navigation_of_license_utilization_tab(self):
        """
        NES-9914 : License consumption visibility (NES-9865)

        Scenarios:
            [x] Verify the visibility of License Utilization tab

        Steps:
        1. Login to Nessus.
        2. Go to Overview tab on About page.
        3. Verify that License Utilization tab is visible on About page.
        4. click on hyperlink given for used hosts
        5. Verify that License Utilization tab is opened.
        6. Logout from Nessus
        NES-14201: Verify about page
        """
        about_page = OverView()
        about_page.open()
        wait(lambda: about_page.is_element_present('used_hosts'), timeout_seconds=const.TIME_THIRTY_SECONDS,
             waiting_for='OverView tab to be displayed.')

        # Verify that License Utilization tab is visible on About page.
        assert visibility_of_element_located((about_page.license_utilization_tab.we_by,
                                              about_page.license_utilization_tab.we_value))(get_driver_no_init()), \
            "License Utilization Tab is invisible."

        about_page.used_hosts.click()
        license_utilization_tab = LicenseUtilization()
        wait(lambda: license_utilization_tab.is_element_present("license_utilization_description"),
             waiting_for='License Utilization tab to be displayed.')

        assert license_utilization_tab.is_element_present("license_utilization_description"), \
            "used_hosts hyperlink is not navigated to License Utilization tab"

    @pytest.mark.xray(test_key='NES-13984')
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER,
                                              'host_ip': Nessus.Scan.Target.NO_SCAN_RESULT_TARGET}], indirect=True)
    def test_verify_license_utilization_scan_with_no_result(self, create_scan):
        """
        NES-13984 : Verify license utilization for scan with no result

        Scenarios:
            [x] Verify license utilization for scan with no result

        Steps:
        1. Login to Nessus.
        2. Create and run scan with invalid target or 0 scan result
        3. Verify that used hosts count is NOT increased by one in overview tab of about page.
        4. Verify that host is NOT added in hosts list on License Utilization tab.
        5. Delete scan and logout from Nessus.
        """

        ScansPage().save_button.click()
        scan_list = ScanList()
        scan_list.loaded()
        about_page = OverView()
        about_page.open()
        wait(lambda: about_page.is_element_present('used_hosts'), timeout_seconds=const.TIME_THIRTY_SECONDS,
             waiting_for='OverView tab to be displayed.')
        utilized_scanned_host_count = int(about_page.used_hosts.text.split(' of')[0])

        about_page.used_hosts.click()
        wait(lambda: LicenseUtilization().license_utilization_description, timeout_seconds=const.TIME_THIRTY_SECONDS,
             waiting_for='License Utilization tab to be displayed.')

        header_base_page = HeaderBasePage()
        header_base_page.scan_link.click()
        scan_list.loaded()
        scan_list.launch_scan_and_wait_for_status(scan_name=create_scan, status=API.Scan.Status.COMPLETED)

        about_page.open()
        wait(lambda: about_page.is_element_present('used_hosts'), timeout_seconds=const.TIME_THIRTY_SECONDS,
             waiting_for='OverView tab to be displayed.')

        # Verify that used hosts count is NOT increased by one in overview tab of about page.
        assert utilized_scanned_host_count == int(about_page.used_hosts.text.split(' of')[0]), \
            "host count is increased by one on overview tab after creating scan for new host"

        header_base_page.scan_link.click()
        scan_list.loaded()

    @pytest.mark.xray(test_key='NES-13893')
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER,
                                              'host_ip': Nessus.Scan.Target.AWS_LINUX_TARGET_1}], indirect=True)
    def test_verify_license_utilization_scan_with_infolevelvul_result(self, create_scan):
        """
        NES-13893 : Verify license utilization for scan result with 1 info level vul

        Scenarios:
            NES-13893 Verify license utilization for scan result with 1 info level vul
        Steps:
        1. Login to Nessus.
        2. Create and run a scan which retrieves only one vulnerability which is info level
        3. Verify that used hosts count is increased by one in overview tab of about page.
        4. Verify that host(INFO_LEVEL_TARGET) is added in hosts list on License Utilization tab.
        5. Delete scan and logout from Nessus.
        """

        ScansPage().save_button.click()
        scan_list = ScanList()
        scan_list.loaded()
        about_page = OverView()
        about_page.open()
        wait(lambda: about_page.is_element_present('used_hosts'), timeout_seconds=const.TIME_THIRTY_SECONDS,
             waiting_for='OverView tab to be displayed.')
        utilized_scanned_host_count = int(about_page.used_hosts.text.split(' of')[0])

        about_page.used_hosts.click()
        wait(lambda: LicenseUtilization().license_utilization_description, timeout_seconds=const.TIME_THIRTY_SECONDS,
             waiting_for='License Utilization tab to be displayed.')

        header_base_page = HeaderBasePage()
        header_base_page.scan_link.click()
        scan_list.loaded()
        scan_list.launch_scan_and_wait_for_status(scan_name=create_scan, status=API.Scan.Status.COMPLETED)

        about_page.open()
        wait(lambda: about_page.is_element_present('used_hosts'), timeout_seconds=const.TIME_THIRTY_SECONDS,
             waiting_for='OverView tab to be displayed.')

        # Verify that used hosts count is increased by one in overview tab of about page.
        assert utilized_scanned_host_count + 1 == int(about_page.used_hosts.text.split(' of')[0]), \
            "host count is increased by one on overview tab after creating scan for new host"

        header_base_page.scan_link.click()
        scan_list.loaded()

    @pytest.mark.xray(test_key='NES-13759')
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER,
                                              'host_ip': Nessus.Scan.Target.PUB_TARGET_3}], indirect=True)
    def test_verify_license_utilization_count_increases_with_new_target_scan(self, create_scan):
        """
        NES-9914 : License consumption visibility (NES-9865)
        NES-13759 : Verify asset table

        Scenarios:
            [x] Verify that used hosts count increases when new scan is created and completed for new host

        Steps:
        1. Login to Nessus.
        2. Create a scan, launch it and wait till it gets completed.
        3. Verify that used hosts count is increased by one in overview tab of about page.
        4. Verify that host is added in hosts list on License Utilization tab.
        5. Delete scan and logout from Nessus.
        """

        ScansPage().save_button.click()
        scan_list = ScanList()
        scan_list.loaded()
        about_page = OverView()
        about_page.open()
        wait(lambda: about_page.is_element_present('used_hosts'), timeout_seconds=const.TIME_THIRTY_SECONDS,
             waiting_for='OverView tab to be displayed.')
        utilized_scanned_host_count = int(about_page.used_hosts.text.split(' of')[0])

        about_page.used_hosts.click()
        wait(lambda: LicenseUtilization().license_utilization_description, timeout_seconds=const.TIME_THIRTY_SECONDS,
             waiting_for='License Utilization tab to be displayed.')

        header_base_page = HeaderBasePage()
        hosts_list = HostsList()

        # Skip the testcase if scan has already been created for given target.
        if hosts_list.is_target_in_list(Nessus.Scan.Target.PUB_TARGET_3):
            header_base_page.scan_link.click()
            scan_list.loaded()
            pytest.xfail(reason="Scan has already been created for given target so skipping the testcase")

        header_base_page.scan_link.click()
        scan_list.loaded()
        scan_list.launch_scan_and_wait_for_status(scan_name=create_scan, status=API.Scan.Status.COMPLETED)

        about_page.open()
        wait(lambda: about_page.is_element_present('used_hosts'), timeout_seconds=const.TIME_THIRTY_SECONDS,
             waiting_for='OverView tab to be displayed.')

        # Verify that used hosts count is increased by one in overview tab of about page.
        assert utilized_scanned_host_count + 1 == int(about_page.used_hosts.text.split(' of')[0]), \
            "host count is not increased by one on overview tab after creating scan for new host"

        about_page.used_hosts.click()
        wait(lambda: LicenseUtilization().license_utilization_description, timeout_seconds=const.TIME_THIRTY_SECONDS,
             waiting_for='License Utilization tab to be displayed.')

        # Verify that host is added in hosts list on License Utilization tab.
        assert hosts_list.is_target_in_list(Nessus.Scan.Target.PUB_TARGET_3), \
            "host is not present in hosts list on License Utilization tab"

        header_base_page.scan_link.click()
        scan_list.loaded()

    @pytest.mark.xray(test_key='NES-13734')
    @pytest.mark.parametrize('sort', SortOrder.VALID_ORDERS)
    @pytest.mark.parametrize('column_to_sort', ['IP', 'Name', 'First Scanned', 'Last Scanned'])
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.BASIC_NETWORK, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.BASIC_NETWORK)),
         "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1},
        {"scan_template": Nessus.TemplateNames.BASIC_NETWORK, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.BASIC_NETWORK)),
         "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_2}]}], indirect=True)
    def test_verify_sorting_on_license_utilization_table(self, sort, column_to_sort, create_scans):
        """
        NES-13734: Verify sorting in asset table

        Scenario Tested:
        [x] Name column can be sorted on table
        [x] IP column can be sorted on table
        [x] First scanned column can be sorted on table
        [x] Last scanned column can be sorted on table
        """
        # remove any unnecessary notifications
        notification_actions = NotificationActions()
        notification_actions.remove_all()

        # Launch the created scans and wait for hosts to reflect on license utilization table
        scan_list = ScanList()
        scan_list.launch_scan(scan_name=create_scans[0])
        scan_list.launch_scan(scan_name=create_scans[1])
        sleep(WAIT_LONG * 3, reason="It takes little bit time to reflect host data on license utilization page")

        # Go to settings about page
        about_page = OverView()
        about_page.open()
        wait(lambda: about_page.is_element_present('used_hosts'), timeout_seconds=const.TIME_THIRTY_SECONDS,
             waiting_for='OverView tab to be displayed.')

        utilized_scanned_host_count = int(about_page.used_hosts.text.split(' of')[0])
        # Used host count for debugging purpose
        log.info(utilized_scanned_host_count)

        # Go to license utilization page from about tab
        hosts_list = HostsList()
        about_page.used_hosts.click()
        wait(lambda: LicenseUtilization().license_utilization_description, timeout_seconds=const.TIME_THIRTY_SECONDS,
             waiting_for='License Utilization tab to be displayed.')

        # mapping of properties
        column_mapping = {"IP": "ip", "Name": "name", "First Scanned": "first_scanned", "Last Scanned": "last_scanned"}
        map_attribute = column_mapping[column_to_sort]

        expected_list = sorted([getattr(user, map_attribute) for user in hosts_list.rows],
                               key=lambda k: k.lower(), reverse=(sort == SortOrder.DESCENDING))
        rendered_list = sort_on_column_values(page_class_instance=hosts_list, column_name=column_to_sort,
                                              sort=sort)

        # Final verification.
        if LicenseUtilization().is_element_present('no_results'):
            pytest.xfail(reason="Results not found somehow")
        else:
            assert expected_list == [getattr(user, map_attribute) for user in rendered_list], \
                "{} is not sorted in {} order".format(column_to_sort, sort)

        # Clean-up task: delete the scans
        try:
            scan_page = ScansPage()
            scan_page.my_scans_tab.click()
            wait(lambda: scan_page.is_element_present('scan_searchbox'), timeout_seconds=const.TIME_THIRTY_SECONDS,
                 waiting_for='Scan page to be displayed properly.')
            scan_list.stop_scan(scan_name=create_scans[0])
            scan_list.stop_scan(scan_name=create_scans[1])
            scan_list.delete_scan(scan_name=create_scans[0])
            scan_list.delete_scan(scan_name=create_scans[1])
        except Exception:
            log.info(msg="scan seems to be deleted already")

    @pytest.mark.xray(test_key='NES-13831')
    @pytest.mark.usefixtures('delete_all_scans_in_nessus', 'login', "import_bulk_scan", "nessus_api_login")
    @pytest.mark.parametrize("import_bulk_scan", [{'scan_count': 2, 'import_scan': False}],
                             indirect=True)
    def test_license_utilization_after_importing_scan(self):
        """
        NES-13831 : Verify license utilization for imported scan
        """

        about_page = OverView()
        about_page.open()
        wait(lambda: about_page.is_element_present('used_hosts'), timeout_seconds=const.TIME_THIRTY_SECONDS,
             waiting_for='OverView tab to be displayed.')

        host_usage_info = about_page.used_hosts.text

        # Verify that "used hosts" information is available with proper format.
        assert re.match(r'(\d{1,2}(?!\d)) of (\d{1,2}(?!\d)) used', host_usage_info), \
            "Used hosts information is not in proper format"

        scanned_host_no = int(host_usage_info.split(' of')[0])
        max_host_scanned = int(host_usage_info.split(' of ')[1].split(' used')[0])

        no_of_used_hosts = self.cat.api.server.properties()['used_ip_count']

        # Verify that host is still 0 after creating HD scan
        assert scanned_host_no == no_of_used_hosts, "used hosts is increased and is used toward licence limit"

        # Verify Max host count is 16
        assert max_host_scanned == 16, "Max host count is not 16"

        license_page = LicenseUtilization()
        license_page.open()

        if scanned_host_no == 0:
            assert license_page.no_results.text == Nessus.Essentials.NO_HOST_USED

        scan_page = ScansPage()
        scan_page.my_scans_tab.click()

        wait(lambda: scan_page.is_element_present("trash_link")), "Checking to see trash link is available."

    @pytest.mark.xray(test_key='NES-13841')
    @pytest.mark.usefixtures('delete_all_scans_in_nessus', 'login')
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER,
                                              'host_ip': Nessus.Scan.Target.AWS_LINUX_TARGET_1}], indirect=True)
    def test_search_on_licence_utilization_page(self, create_scan):
        """
        NES-13841 Verify searching in asset table
        """
        scan_page = ScansPage()
        scan_page.save_button.click()

        scan_list = ScanList()

        # Launching created scan and waiting to be completed
        scan_list.launch_scan_and_wait_for_status(create_scan)
        scan_list.refresh()

        license_page = LicenseUtilization()
        license_page.open()

        wait(lambda: license_page.is_element_present('search_box'), timeout_seconds=TIME_FIVE_SECONDS)
        license_page.search_box.send_keys(Nessus.Scan.Target.AWS_LINUX_TARGET_1)
        # wait(timeout_seconds=TIME_FIVE_SECONDS, waiting_for='Search result to get loaded')

        assert HostsList().is_target_in_list(Nessus.Scan.Target.AWS_LINUX_TARGET_1)
