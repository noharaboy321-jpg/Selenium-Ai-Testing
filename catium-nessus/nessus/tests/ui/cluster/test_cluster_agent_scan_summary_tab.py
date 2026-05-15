""""
Test cases for summary table in agent cluster scan

:copyright: Tenable Network Security, 2021
:created: July 21, 2021
:last_modified: July 30, 2021
:author: @vsoni.ctr, @kpanchal.ctr
"""
from http import HTTPStatus

import pytest
from selenium.webdriver.support.expected_conditions import visibility_of_element_located
from waiting import TimeoutExpired

from catium.lib.const import TIME_THIRTY_MINUTES, TIME_THIRTY_SECONDS
from catium.lib.const.base_constants import WAIT_NORMAL
from catium.lib.log import create_logger
from catium.lib.util import random_name
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.nessuscli.helper import stop_nessus, start_nessus
from nessus.helpers.scanner import wait_for_scanner_to_be_ready
from nessus.helpers.server import expect_http_error
from nessus.helpers.waiters import wait_scan_state
from nessus.lib.const import SortOrder, Nessus, API
from nessus.models.scan import ScanModel
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.header.user_menu import UserMenu
from nessus.pageobjects.login.login_page import LoginPage
from nessus.pageobjects.scans.new_scan_form import NewScanForm
from nessus.pageobjects.scans.scan_basic_settings_page import BasicSetting
from nessus.pageobjects.scans.scan_view_page import ClusterScanSummaryList, ScanViewPage, ScanHistoryList
from nessus.pageobjects.scans.scan_view_page import ScansHostList
from nessus.pageobjects.scans.scans_page import ScanList, ScansPage

log = create_logger()


@pytest.mark.cluster_manager
@pytest.mark.parametrize('create_manager_cluster', [{'total_nodes': 2, 'total_agents': 3}], indirect=True)
@pytest.mark.parametrize('perform_cluster_agent_scan', [{'create_scan': True, 'launch_scan': True}], indirect=True)
@pytest.mark.usefixtures('perform_cluster_agent_scan', 'login')
class TestClusterScanSummaryTab:
    """ Covers Cluster Scan summary tab related test cases """

    cat = None

    @staticmethod
    def sort_given_column_in_cluster_scan_summary_table(column_name: str, summary_list: ClusterScanSummaryList,
                                                        sort: str):
        """
        This method sort the given column in cluster scan summary table

        :param str column_name : Name of the column which needs to be sorted
        :param ClusterScanSummaryList summary_list: Instance of ClusterScanSummaryList class
        :param str sort: Order of sorting (Ascending/Descending)
        """
        column_element = summary_list.get_column_header_element(column_name=column_name)
        column_sort_order = column_element.get_attribute("aria-sort")

        def click_on_column_and_wait_till_list_loaded():
            column_element.click()
            summary_list.loaded()

        if column_sort_order is None:
            for i in range(2 if sort == SortOrder.DESCENDING else 1):
                click_on_column_and_wait_till_list_loaded()
        elif (SortOrder.ASCENDING in column_sort_order and sort == SortOrder.DESCENDING) or \
                (SortOrder.DESCENDING in column_sort_order and sort == SortOrder.ASCENDING):
            click_on_column_and_wait_till_list_loaded()

    @staticmethod
    def go_to_scan_and_change_permission(scan_name: str, scan_permission: str):
        """
        This method clicks on given scan and change the permission as per given permission

        :param str scan_name: Name of scan which needs to be changed permission
        :param str scan_permission: scan permission (Can view, Can edit, No access, etc.)
        """
        ScanList().click_on_scan(scan_name=scan_name)
        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present("vulnerability_tab"), waiting_for='scan view page to load')

        scan_view_page.js_scroll_into_view(element=scan_view_page.configure_button)
        scan_view_page.configure_button.click()
        scan_form = NewScanForm()
        wait(lambda: scan_form.is_element_present('name_field'), timeout_seconds=TIME_THIRTY_SECONDS,
             sleep_seconds=WAIT_NORMAL, waiting_for="Scan configure page to get loaded properly.")

        basic_setting = BasicSetting()
        basic_setting.click_link_inside_link(setting_value=API.PoliciesSettings.SettingsTypes.BASIC,
                                             link_text=Nessus.Scan.SettingsBasicSubMenu.PERMISSIONS)
        basic_setting.select_user_permission.select_by_visible_text(text=scan_permission)

        scan_form.save_button.click()
        wait(lambda: Notifications().successes, waiting_for="Notification list to populate")

    def test_verify_counts_are_node_wise_in_cluster_summary_table(self, perform_cluster_agent_scan):
        """
        NES-13213 [Automation]: Verify that all counts in the table are node wise

        Scenario Tested:
        [x] Verify that scan summary table shows node wise linked agents count.
        """
        node_agent_details = perform_cluster_agent_scan['node_agent_details']

        ScanList().click_on_scan(scan_name=perform_cluster_agent_scan['scan_name'])
        wait(lambda: ScanViewPage().is_element_present("summary_tab"), waiting_for="summary tab gets loaded properly")

        scan_summary_list = ClusterScanSummaryList()
        node_names_in_summary_table = scan_summary_list.get_node_names()

        assert len(node_agent_details.keys()) == len(node_names_in_summary_table), \
            "Summary table does not show the rows of node status as we set."

        for node_name in node_agent_details.keys():
            agent_count = scan_summary_list.get_agents_count_for_given_status(node_name=node_name,
                                                                              status=API.Scan.Status.COMPLETED)

            log.debug("Node name :: {} and linked agent count :: {} from fixture".format(
                node_name, len(node_agent_details[node_name])))
            log.debug("Node name :: {} and linked agent count :: {} from summary table".format(agent_count, node_name))

            assert all([node_name in node_names_in_summary_table, len(node_agent_details[node_name]) == agent_count]), \
                "Linked agents count is getting mismatch as per node."

    @pytest.mark.parametrize('create_users_using_api', [
        [API.Permissions.User.SYSTEM_ADMINISTRATOR, API.Permissions.User.ADMINISTRATOR,
         API.Permissions.User.STANDARD, API.Permissions.User.BASIC]], indirect=True)
    def test_visibility_of_summary_tab_in_cluster_scan_result_for_other_users(
            self, perform_cluster_agent_scan, create_users_using_api):
        """
        NES-13214 [Automation]: Verify that tab should be visible for other users

        Scenario Tested:
        [x] Verify that "Summary" tab should also be visible to other users in cluster scan result.
        """
        created_user = create_users_using_api
        scan_name = perform_cluster_agent_scan['scan_name']
        shared_scan_name = "Shared\n{}".format(scan_name)
        user_menu = UserMenu()

        try:
            self.go_to_scan_and_change_permission(scan_name=scan_name,
                                                  scan_permission=Nessus.Scan.UserPermissions.CAN_VIEW)
            scan_view_page = ScanViewPage()

            for user_detail in created_user:
                user_menu.logout()
                LoginPage().login_with_credentials(username=user_detail['name'], password=user_detail['password'])

                ScanList().click_on_scan(scan_name=shared_scan_name)
                wait(lambda: scan_view_page.is_element_present("node_column"), waiting_for="summary tab gets loaded")

                assert scan_view_page.is_element_present("summary_tab"), \
                    "'Summary' tab is not visible in cluster scan result for '{}' user.".format("")
        finally:
            user_menu.logout()
            LoginPage().login_with_defaults()

            self.go_to_scan_and_change_permission(scan_name=shared_scan_name,
                                                  scan_permission=Nessus.Scan.UserPermissions.NO_ACCESS)

    def test_verify_total_count_of_individual_column_in_cluster_summary_table(self, perform_cluster_agent_scan):
        """
        NES-13215 [Automation]: Verify last row of the table is 'Total' which show total of individual column's entries

        Scenario Tested:
        [x] Verify last row of the table is 'Total' which shows total of individual row's entries
        """
        ScanList().click_on_scan(scan_name=perform_cluster_agent_scan['scan_name'])
        wait(lambda: ScanViewPage().is_element_present("summary_tab"), waiting_for="summary tab gets loaded properly")

        scan_summary_list = ClusterScanSummaryList()
        node_details = perform_cluster_agent_scan['nodes']

        for column_name in ['not_started', 'in_progress', 'completed', 'aborted', 'failed', 'total']:
            node_1_count = scan_summary_list.get_agents_count_for_given_status(node_name=node_details[0][0],
                                                                               status=column_name)

            node_2_count = scan_summary_list.get_agents_count_for_given_status(node_name=node_details[1][0],
                                                                               status=column_name)

            assert node_1_count + node_2_count == scan_summary_list.get_total_count_for_given_status(
                status=column_name), \
                "Last row 'Total' from scan summary table does not show the total of individual column entries."

    def test_verify_total_count_of_individual_row_in_cluster_summary_table(self, perform_cluster_agent_scan):
        """
        NES-13216 [Automation]: Verify last column of the table id 'Total' which indicated total counts for each nodes

        Scenario Tested:
        [x] Verify last column of the table is 'Total' which shows total of individual column's entries
        """
        ScanList().click_on_scan(scan_name=perform_cluster_agent_scan['scan_name'])
        wait(lambda: ScanViewPage().is_element_present("summary_tab"), waiting_for="summary tab gets loaded properly")

        scan_summary_list = ClusterScanSummaryList()

        for node in perform_cluster_agent_scan['nodes']:
            node_name = node[0]
            status_count = 0

            for column_name in ['not_started', 'completed', 'aborted', 'failed']:
                node_status_count = scan_summary_list.get_agents_count_for_given_status(node_name=node_name,
                                                                                        status=column_name)
                status_count += node_status_count

            assert status_count == scan_summary_list.get_agents_count_for_given_status(
                node_name=node_name, status='total'), "Last row 'Total' from scan summary table does not show " \
                                                      "the total of individual column entries."

    def test_verify_total_count_of_row_and_column_in_cluster_summary_table(self, perform_cluster_agent_scan):
        """
        NES-13217 [Automation]: Verify that Total(row)=Total(column) always in cluster scan summary table

        Scenario Tested:
        [x] Verify that "Total(row)" is always equal to "Total(column)" in cluster scan summary table
        """
        ScanList().click_on_scan(scan_name=perform_cluster_agent_scan['scan_name'])
        wait(lambda: ScanViewPage().is_element_present("summary_tab"), waiting_for="summary tab gets loaded properly")

        scan_summary_list = ClusterScanSummaryList()

        total_status_count = 0
        total_node_count = 0
        total_count = scan_summary_list.get_total_count_for_given_status(status='total')

        for node in perform_cluster_agent_scan['nodes']:
            node_count = scan_summary_list.get_agents_count_for_given_status(node_name=node[0], status='total')

            total_node_count += node_count

        assert total_node_count == total_count, "Total count of individual node does not match with 'Total' count " \
                                                "that shows in summary table."

        for column_name in ['not_started', 'completed', 'aborted', 'failed']:
            row_status_count = scan_summary_list.get_total_count_for_given_status(status=column_name)

            total_status_count += row_status_count

        assert total_status_count == total_count, "Total count of all status does not match with 'Total' count " \
                                                  "that shows in summary table."

        assert total_status_count == total_node_count == total_count, \
            "Total count of individual node, Total count of all status and 'Total' count which shows in scan summary " \
            "table does not match with each other."

    def test_verify_total_count_of_completed_column_after_scan_completed(self, perform_cluster_agent_scan):
        """
        NES-13218 [Automation]: Verify that counts are showing correct when scan get completed

        Scenario Tested:
        [x] Verify that "Completed" status column count shows correct count after scan gets completed
        """
        ScanList().click_on_scan(scan_name=perform_cluster_agent_scan['scan_name'])

        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present("summary_tab"), waiting_for="summary tab gets loaded properly")

        for node in perform_cluster_agent_scan['nodes']:
            node_name, linked_agents = node[0], perform_cluster_agent_scan['node_agent_details'][node[0]]
            completed_status_count = ClusterScanSummaryList().get_agents_count_for_given_status(
                node_name=node_name, status=API.Scan.Status.COMPLETED)

            scan_view_page.host_tab.click()
            wait(lambda: scan_view_page.is_element_present("switch_node_drop_down"),
                 waiting_for="Scan host tab gets loaded properly")

            scan_view_page.switch_node_drop_down.select_by_visible_text(text=node_name)
            scan_host_list = ScansHostList()
            wait(lambda: scan_view_page.is_element_present("filter_link"), waiting_for="host list gets updated")

            assert len(scan_host_list.rows) == completed_status_count == len(linked_agents), \
                "Scan summary table shows incorrect count in 'Completed' status column after scan gets completed."

            scan_view_page.summary_tab.click()

    def test_verify_visibility_of_summary_tab(self, perform_cluster_agent_scan):
        """
        NES - 13224 : [UI - Automation] : Verify summary tab visibility in different types of scans

        Scenario Tested:
            [x] Verify the visibility of summary tab for agent cluster scan.
        """
        scans_list = ScanList()
        scans_list.loaded()
        scans_list.click_on_scan(scan_name=perform_cluster_agent_scan.get('scan_name'))
        scan_details_page = ScanViewPage()

        # Verify scan summary tab visibility.
        try:
            wait(lambda: scan_details_page.is_element_present('summary_tab'), waiting_for='scan results to load')
        except TimeoutExpired:
            raise AssertionError("Summary tab is not visible in Agent cluster scan.")

    @pytest.mark.parametrize('column_name', ['Node', 'Not Started', 'Completed', 'Aborted', 'Failed', 'Total'])
    @pytest.mark.parametrize("sort", SortOrder.VALID_ORDERS)
    def test_sorting_in_summary_tab(self, column_name, sort, perform_cluster_agent_scan):
        """
        NES-13223 : [UI-Automation] : Verify sorting in summary table for cluster agent scan

        Scenario Tested:
            [x] Verify that sorting in summary table works for all columns in cluster agent scan.
        """
        scans_list = ScanList()
        scans_list.loaded()
        scans_list.click_on_scan(scan_name=perform_cluster_agent_scan.get('scan_name'))
        scan_details_page = ScanViewPage()
        wait(lambda: scan_details_page.is_element_present('vulnerability_tab'), waiting_for='scan results to load')

        mapping = {"Node": 'node_name', 'Not Started': 'not_started', 'Completed': 'completed', 'Aborted': 'aborted',
                   'Failed': 'failed', 'Total': 'total'}

        summary_list = ClusterScanSummaryList()
        expected_summary_table_list = sorted([
            row.get_agent_count_element(scan_status=mapping[column_name], is_scan_completed=True).text
            if column_name != "Node" else getattr(row, mapping[column_name]) for row in
            summary_list.rows], reverse=(sort == SortOrder.DESCENDING))

        self.sort_given_column_in_cluster_scan_summary_table(column_name=column_name, summary_list=summary_list,
                                                             sort=sort)

        sorted_summary_list_on_ui = [row.get_agent_count_element(
            scan_status=mapping[column_name], is_scan_completed=True).text if column_name != "Node" else getattr(
            row, mapping[column_name]) for row in summary_list.rows]

        # Verify that given column sorted properly as per given order.
        assert expected_summary_table_list == sorted_summary_list_on_ui, \
            "Sorting is not working for {} column in summary table".format(column_name)


@pytest.mark.cluster_manager
@pytest.mark.parametrize('create_manager_cluster', [{'total_nodes': 2, 'total_agents': 3}], indirect=True)
@pytest.mark.parametrize('perform_cluster_agent_scan', [{'create_scan': False, 'launch_scan': False}], indirect=True)
@pytest.mark.usefixtures('perform_cluster_agent_scan', 'login')
class TestSummaryCountForDifferentUsers:
    """ Covers Cluster Scan summary tab related test cases """

    cat = None

    @pytest.mark.parametrize('create_users_using_api', [
        [API.Permissions.User.SYSTEM_ADMINISTRATOR, API.Permissions.User.ADMINISTRATOR, API.Permissions.User.STANDARD,
         API.Permissions.User.BASIC]], indirect=True)
    def test_verify_counts_in_summary_tab_from_scan_performed_by_different_users(
            self, perform_cluster_agent_scan, create_users_using_api):
        """
        NES-13219 [Automation]: Verify the counts for each node performed by different users (SysAdmin/Admin/Standard)

        Scenario Tested:
        [x] Verify that counts in "Summary" tab should be correct as per configuration for cluster scan performed by
            other users.
        """
        node_agent_details = perform_cluster_agent_scan['node_agent_details']
        created_user = create_users_using_api

        for user_detail in created_user:
            UserMenu().logout()
            LoginPage().login_with_credentials(username=user_detail['name'], password=user_detail['password'])

            nessus_api = NessusAPI()
            nessus_api.login(username=user_detail['name'], password=user_detail['password'])
            scan_name = random_name(prefix="{} - ".format(Nessus.TemplateNames.BASIC_AGENT))

            scan_model = ScanModel()
            scan_model.name = scan_name
            scan_model.default_template = Nessus.TemplateNames.BASIC_AGENT
            scan_model.agent_group_id = [perform_cluster_agent_scan['agent_group_id']]

            if user_detail['permissions'] == 16:
                with expect_http_error(code=HTTPStatus.FORBIDDEN,
                                       look_for="You are not authorized to perform this request"):
                    nessus_api.scans.create(scan_model)
            else:
                scan_id = nessus_api.scans.create(scan_model)['scan']['id']
                nessus_api.scans.launch(scan_id=scan_id)
                wait_scan_state(api=nessus_api, end_state=API.Scan.Status.COMPLETED, scan_id=scan_id,
                                timeout=TIME_THIRTY_MINUTES)

                ScansPage().refresh()
                ScanList().click_on_scan(scan_name=scan_name)

                scan_view_page = ScanViewPage()
                wait(lambda: scan_view_page.is_element_present("node_column"), waiting_for="summary tab gets loaded")

                assert scan_view_page.is_element_present("summary_tab"), \
                    "'Summary' tab is not visible in cluster scan result for '{}' user.".format("")

                scan_summary_list = ClusterScanSummaryList()
                node_names_in_summary_table = scan_summary_list.get_node_names()

                assert len(node_agent_details.keys()) == len(node_names_in_summary_table), \
                    "Summary table does not show the rows of node status as we set."

                for node_name in node_agent_details.keys():
                    agent_count = scan_summary_list.get_agents_count_for_given_status(node_name=node_name,
                                                                                      status=API.Scan.Status.COMPLETED)

                    assert all([node_name in node_names_in_summary_table,
                                len(node_agent_details[node_name]) == agent_count]), \
                        "Linked agents count is getting mismatch as per node."


@pytest.mark.parametrize('create_manager_cluster', [{'total_nodes': 2, 'total_agents': 3}], indirect=True)
@pytest.mark.parametrize('perform_cluster_agent_scan', [{'create_scan': False, 'launch_scan': False}], indirect=True)
@pytest.mark.usefixtures('perform_cluster_agent_scan', 'login')
@pytest.mark.cluster_manager
class TestScanSummaryTab:
    @staticmethod
    def create_agent_scan_and_wait_till_scan_completed(agent_group_id, run_scan) -> str:
        """
        This method creates agent scan and waits till it gets completed for given number of times.
        :param int agent_group_id: Agent group id to create agent scan.
        :param int run_scan: No. of times the scan needs to be executed.
        :return : Name of created agent scan
        :rtype: str
        """
        nessus_api = NessusAPI()
        nessus_api.login()
        scan_model = ScanModel()
        scan_name = random_name(prefix="{} - ".format(Nessus.TemplateNames.BASIC_AGENT))
        scan_model.name = scan_name
        scan_model.default_template = Nessus.TemplateNames.BASIC_AGENT
        scan_model.agent_group_id = [agent_group_id]
        agent_scan_id = nessus_api.scans.create(scan_model)['scan']['id']

        for i in range(run_scan):
            nessus_api.scans.launch(scan_id=agent_scan_id)
            wait_scan_state(api=nessus_api, end_state=API.Scan.Status.COMPLETED, scan_id=agent_scan_id,
                            timeout=TIME_THIRTY_MINUTES)
        return scan_name

    @staticmethod
    def verify_agent_count_configured_properly_in_summary_tab(cluster_agent_scan_details: dict) -> None:
        """
        This method verifies that agent count is as per configuration in summary table.
        :param dict cluster_agent_scan_details: Details of cluster configuration.
        :return: None
        """
        summary_list = ClusterScanSummaryList()
        wait(lambda: len(summary_list.rows) > 0)
        nodes = summary_list.get_node_names()
        assert len(nodes) == len(cluster_agent_scan_details.get('nodes')), \
            "Number of nodes are not matching in summary table for cluster scan."
        for node in nodes:
            assert summary_list.get_agents_count_for_given_status(
                node_name=node, status='completed') + summary_list.get_agents_count_for_given_status(
                node_name=node, status='failed') + summary_list.get_agents_count_for_given_status(
                node_name=node, status='aborted') == summary_list.get_agents_count_for_given_status(
                node_name=node, status='total') == len(cluster_agent_scan_details.get('node_agent_details')[node]), \
                "Summary table count is not as per configuration."

    @staticmethod
    def launch_scan_and_wait_till_scan_gets_running_status(scan_name: str) -> None:
        """
        Launches the scan and waits till scan gets running status.
        :param str scan_name: Name of scan.
        :return: None
        """
        scan_details_page = ScanViewPage()
        scan_details_page.refresh()
        scans_list = ScanList()
        scans_list.loaded()
        scans_list.launch_scan_and_wait_for_status(launch_scan=True,
                                                   scan_name=scan_name, status=API.Scan.Status.RUNNING)

    @pytest.mark.parametrize('history_count', [2])
    def test_verify_summary_table_count_for_multiple_history(self, perform_cluster_agent_scan, history_count):
        """
        NES - 13233 : [UI - Automation] : Verify agent count for executing cluster scan multiple times.

        Scenario Tested:
            [x] Verify that agent count is as per configuration in summary table of agent scan.
        """
        # Create agent scan and run the scan twice.
        scan_name = self.create_agent_scan_and_wait_till_scan_completed(agent_group_id=perform_cluster_agent_scan.get(
            'agent_group_id'), run_scan=history_count)
        scan_details_page = ScanViewPage()
        scan_details_page.refresh()
        scans_list = ScanList()
        scans_list.loaded()
        scans_list.click_on_scan(scan_name=scan_name)
        scan_details_page = ScanViewPage()
        wait(lambda: scan_details_page.is_element_present('vulnerability_tab'), waiting_for='scan results to load')
        history_list = ScanHistoryList()

        for i in range(history_count):
            scan_details_page.history_tab.click()
            history_list.loaded()
            wait(lambda: len(history_list.rows) > 0)
            history_list.rows[i].click()
            scan_details_page.summary_tab.click()

            # Verify that agent count in scan summary table is configured properly.
            self.verify_agent_count_configured_properly_in_summary_tab(
                cluster_agent_scan_details=perform_cluster_agent_scan)

    def test_cluster_scan_summary_table_if_nm_restarts_during_scan(self, perform_cluster_agent_scan):
        """
        NES - 13231 : [UI - Automation] : Verify agent count in summary table when NM restarts while scan is running

        Scenario Tested:
            [x] Verify that agent count is as per configuration in summary table even if nessus manager restarts
                while the scan is running.
        """
        scan_name = self.create_agent_scan_and_wait_till_scan_completed(agent_group_id=perform_cluster_agent_scan.get(
            'agent_group_id'), run_scan=0)

        # Launch scan and wait till scan gets running status.
        self.launch_scan_and_wait_till_scan_gets_running_status(scan_name=scan_name)

        # Restart Nessus Manager and wait till it becomes ready.
        stop_nessus()
        start_nessus()
        wait_for_scanner_to_be_ready(api=NessusAPI())

        # Login again to Nessus Manager.
        login_page = LoginPage()
        login_page.refresh()
        wait(lambda: login_page.is_element_present('username_field'))
        LoginPage().do_login()
        scans_list = ScanList()
        scans_list.loaded()

        # Wait till scan gets completed.
        scan_element = ScansPage().get_scan_status(scan_name=scan_name, scan_status=API.Scan.Status.COMPLETED)
        wait(lambda: visibility_of_element_located((scan_element.by, scan_element.f_value))(get_driver_no_init()),
             timeout_seconds=TIME_THIRTY_MINUTES, waiting_for="Waiting for scan to be completed.")

        scans_list.click_on_scan(scan_name)
        wait(lambda: ScanViewPage().is_element_present('vulnerability_tab'), waiting_for='scan results to load')

        # Verify that agent count in scan summary table is configured properly.
        self.verify_agent_count_configured_properly_in_summary_tab(
            cluster_agent_scan_details=perform_cluster_agent_scan)

    def test_scan_summary_tab_for_stopped_cluster_scan(self, perform_cluster_agent_scan):
        """
        NES - 13232 : [UI - Automation] : Verify agent count in summary table for aborted scan

        Scenario Tested:
            [x] When user stops the scan forcibly then verify that
                scan summary list is either empty or it has agent count properly configured for each node.
        """
        scan_name = self.create_agent_scan_and_wait_till_scan_completed(agent_group_id=perform_cluster_agent_scan.get(
            'agent_group_id'), run_scan=0)

        # Launch scan and wait till scan gets running status.
        self.launch_scan_and_wait_till_scan_gets_running_status(scan_name=scan_name)

        scans_page = ScansPage()

        # Stop scan and wait till scan gets stopped.
        scans_page.stop_scan(scan_list=[scan_name])
        scan_aborted_status = scans_page.get_scan_status(scan_name=scan_name,
                                                         scan_status=API.Scan.Status.ABORTED)
        wait(lambda: visibility_of_element_located((scan_aborted_status.by, scan_aborted_status.f_value))(
            get_driver_no_init()), timeout_seconds=TIME_THIRTY_SECONDS,
             waiting_for="Waiting for scan to be in 'aborted' status")
        ScanList().click_on_scan(scan_name)
        wait(lambda: ScanViewPage().is_element_present('vulnerability_tab'), waiting_for='scan results to load')

        # Verify that scan summary list is either empty or it has agent count properly configured for each node.
        try:
            assert len(ClusterScanSummaryList().rows) == 0, "Scan summary list is not empty."
        except AssertionError:
            log.info("Cluster scan table is not empty.")
            # Verify that agent count in scan summary table is configured properly.
            self.verify_agent_count_configured_properly_in_summary_tab(
                cluster_agent_scan_details=perform_cluster_agent_scan)
