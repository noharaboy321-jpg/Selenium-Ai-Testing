"""
Nessus agents group management related test cases

:copyright: Tenable Network Security, 2017
:created: August 8, 2017
:last_modified: Oct 19, 2020
:author: @ntarwani.ctr, @rdutta, @kpanchal, @krpatel, @sacharya
"""

import random
import re

import pytest
from selenium.webdriver.common.keys import Keys
from waiting import TimeoutExpired

from catium.helpers.sleep_lib import sleep
from catium.lib.const import WAIT_SHORT, WAIT_NORMAL, TIME_THREE_SECONDS, TIME_TEN_SECONDS, TIME_FIVE_SECONDS
from catium.lib.const.base_constants import TIME_SIXTY_SECONDS, WAIT_LONG
from catium.lib.errors import CatiumPageLoadError
from catium.lib.log.log import create_logger
from catium.lib.util import random_name
from catium.lib.webium.driver import get_driver
from catium.lib.webium.wait import wait
from nessus.lib.const import API
from nessus.lib.const import SortOrder
from nessus.lib.const.constants import Nessus
from nessus.lib.message.messages import Messages
from nessus.pageobjects.agents.agent_group_page import AgentGroupsPage, AgentGroupsList, CreateGroupWindowPage, \
    GroupDetail
from nessus.pageobjects.agents.agents_filter_page import FilterWindow
from nessus.pageobjects.agents.agents_page import AgentsPage, AgentsList, AgentDetail, AgentSettingsTab, \
    AddAgentGroupList, AgentsRecord
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav
from nessus.tests.ui.cluster.test_cluster_group_operations import \
    get_and_verify_total_selected_agents_and_its_count_from_page

log = create_logger()


@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
@pytest.mark.usefixtures('nessus_api_login')
class TestAgentGroups:
    """Test cases to cover UI functionality related to agents groups in agents page."""
    cat = None

    @staticmethod
    def sort_given_column_in_agent_group_table(column_name: str, agent_group_list: AgentGroupsList, sort: str):
        """
        This method sort the given column in agent group table
        :param str column_name : Name of the column which needs to be sorted
        :param AgentGroupsList agent_group_list: Instance of AgentGroupsList class
        :param str sort: Order of sorting (Ascending/Descending)
        """
        column_element = agent_group_list.get_column_header_element(column_name=column_name)
        column_sort_order = column_element.get_attribute("aria-sort")

        def click_on_column_and_wait_till_list_loaded():
            column_element.click()
            agent_group_list.loaded()

        if column_sort_order is None:
            for i in range(2 if sort == SortOrder.DESCENDING else 1):
                click_on_column_and_wait_till_list_loaded()
        elif (SortOrder.ASCENDING in column_sort_order and sort == SortOrder.DESCENDING) or \
                (SortOrder.DESCENDING in column_sort_order and sort == SortOrder.ASCENDING):
            click_on_column_and_wait_till_list_loaded()

    @staticmethod
    def fetch_agent_data_from_given_agent_record(agent_record: AgentsRecord) -> dict:
        """
        Return dict which contains agent_name, agent_status, agent_ip_address, agent_version and agent_platform details
        for given agent record.
        :param AgentsRecord agent_record: Agent record web-element
        :return dict: Values for agent_name, agent_status, agent_ip_address, agent_version and agent_platform
        :rtype: dict
        """
        return {'agent_name': agent_record.agent_name.text,
                'agent_status': agent_record.agent_status.text,
                'agent_ip': agent_record.agent_ip_address.text,
                'agent_version': agent_record.agent_version.text,
                'agent_platform': agent_record.agent_platform.text}

    @pytest.mark.xray(test_key='NES-13773')
    @pytest.mark.parametrize("create_agents", [{'no_of_agents': 7}], indirect=True)
    def test_group_creation_from_linked_agents_tab(self, create_agents):
        """
        NQA-983 : UI-Agent-Management-Groups - On the fly group creation
        NES-13773 : Verify Agent Groups
        Test case to create a new group from linked Agents tab.
        1. check some agents from linked agent tab
        2. create a new group 
        3. navigate to group page and verify group exists in group management page
        4. verify group exists with correct agents previously checked
        """
        new_group_name = random_name(prefix='LinkedAgents-group-')
        agents_list = create_agents
        group_list = AgentGroupsList()

        try:
            # select some agents to create a group
            agent_page = AgentsPage()
            agent_page.open()
            agent_list = AgentsList()
            agent_list.select_deselect_agents(agents_list=agents_list)
            agent_page.manage_button.click()

            # give group name and create it from linked agent tab
            agent_page.create_group(group_name=new_group_name)

            # check notification to verify group is created successfully

            assert Notifications().successes[-1] == Messages.NotificationMessages.Agents.AgentGroups.group_added, \
                "Success notifications for adding agent group is mismatched or missing."

            # navigate to group page and click on above created group from group management page
            agent_list.loaded()
            SideNav().get_sidenav_element(element_name=Nessus.SideNavResources.GROUPS).click()
            group_list.loaded()
            group_list.click_on_group(new_group_name)
            group_list.loaded()

            # fetch the agents list in current_list from the above selected group
            current_list = agent_list.get_all_agents_by_name()

            # verify the group exists with the correct agents.
            if len(current_list) == len(agents_list):
                for item in current_list:
                    assert item in agents_list, 'LinkedAgents list not matched with sent agents list. '

        except(CatiumPageLoadError, TimeoutError):
            log.debug('Failed to load the page. ')
            raise

        finally:
            # delete the above created group
            AgentGroupsPage().open()
            group_list = AgentGroupsList()
            group_list.loaded()
            group_list.delete_group(new_group_name)

            # verify above group is deleted successfully
            assert new_group_name not in group_list.get_all_groups(), 'Failed to delete selected group'

    @pytest.mark.parametrize("create_agents", [{'no_of_agents': 1}], indirect=True)
    def test_group_creation_from_agents_details_card(self, create_agents):
        """
        # NQA-984 : UI-Agent-Management-Groups-Add/Remove Agents to group from the Agent details card
        1. create two groups
        2. In the Linked Agents tab, select an agent to see it's details.
        3. From the Agent details card, near the bottom, add the agent to a group.
        4. navigate to group page and verify group exists with correct agents previously checked.
        5. Having two available groups, remove the agent from one group and place in another.
        6. Delete above created groups
        """
        # create agent groups
        group1 = random_name("AgentGroup1- ")
        group2 = random_name("AgentGroup2- ")

        group_page = AgentGroupsPage()

        try:
            group_page.open()
            group_window_page = CreateGroupWindowPage()
            group_window_page.create_group(group1)
            group_window_page.create_group(group2)

            # add agent and verify its existence in agents list
            agent_name = create_agents[0]
            agent_page = AgentsPage()
            agent_page.open()
            agent_list = AgentsList()
            assert agent_name in agent_list.get_all_agents_by_name(), 'Failed to create agent'

            # click on the agent to view agent detail card and add it to group
            agent_list.click_on_agent(agent_name=agent_name)
            LoadingCircle(WAIT_NORMAL)
            agent_details = AgentDetail()
            agent_details.add_group_to_agent(group_name=group1)
            LoadingCircle(WAIT_NORMAL)
            agent_details.back_to_agent.click()

            # verify agent is added successfully to group
            SideNav().get_sidenav_element(element_name=Nessus.SideNavResources.GROUPS).click()
            group_list = AgentGroupsList()
            group_list.loaded()
            group_list.click_on_group(group1)
            assert agent_name in [agent.agent_name.text for agent in agent_list.rows], 'agent is not added to group'

            # add another group to the agent
            agent_page.open()
            agent_list.click_on_agent(agent_name=agent_name)
            LoadingCircle(WAIT_SHORT)
            agent_details.add_group_to_agent(group_name=group2)

            # remove previous group from the agent detail card
            LoadingCircle(WAIT_SHORT)
            agent_details.remove_group_from_agent_details(group1)
            LoadingCircle(WAIT_NORMAL)
            agent_details.back_to_agent.click()

            # verify agent is present in another group
            SideNav().get_sidenav_element(element_name=Nessus.SideNavResources.GROUPS).click()
            group_list.click_on_group(group2)
            assert agent_name in [agent.agent_name.text for agent in agent_list.rows], 'agent is not added to group.'

            # verify agent is not present in previous group
            agent_details.back_to_agent.click()
            group_list.click_on_group(group1)
            assert agent_name not in [agent.agent_name.text for agent in agent_list.rows], 'Agent is still exists ' \
                                                                                           'in group.'

        except(CatiumPageLoadError, TimeoutError):
            log.debug('Failed to load the page. ')
            raise

        finally:
            group_page.open()
            LoadingCircle(WAIT_NORMAL)

            # delete the created groups and verify its deleted successfully
            group_list_page = AgentGroupsList()
            group_list_page.delete_group(group1)
            LoadingCircle(WAIT_SHORT)
            assert group1 not in group_list_page.get_all_groups(), 'Failed to delete selected group'

            group_list_page.delete_group(group2)
            LoadingCircle(WAIT_SHORT)
            assert group2 not in group_list_page.get_all_groups(), 'Failed to delete selected group'

    @pytest.mark.parametrize("create_agents", [{'no_of_agents': 8}], indirect=True)
    def test_agents_group_member_filtering(self, create_agents):
        """
        # NQA-985 : UI-Agent-Management-Groups-Group member filtering
        Test to ensure it is possible to remove filtered agents from groups on groups page.
        1. Create a group with some agents.
        2. Navigate to the Groups tab in the Agents page, and select created group.
        3. search/filter through the list using the search box.
        4. Select a few of the filtered member agents and remove them from the group.
        5. Clear the filter and check that the agents removed are truly gone.
        6. Delete the created group.
        """
        agents_list = create_agents
        search_string = "LinkedAgents - o"
        group_name = random_name(prefix='LinkedAgents-group-')

        try:
            # select some agents to create a group
            agent_page = AgentsPage()
            agent_page.open()
            LoadingCircle(WAIT_NORMAL)
            agent_list = AgentsList()
            agent_list.select_deselect_agents(agents_list=agents_list)
            agent_page.manage_button.click()

            # give group name and create it
            agent_page.create_group(group_name=group_name)

            # check notification to verify group has created successfully

            assert Notifications().successes[-1] == Messages.NotificationMessages.Agents.AgentGroups.group_added, \
                "Success notifications for adding agent group is mismatched or missing."

            # navigate to group page and click on above created group from group management page
            SideNav().get_sidenav_element(element_name=Nessus.SideNavResources.GROUPS).click()
            group_list = AgentGroupsList()
            group_list.loaded()
            group_list.click_on_group(group_name)

            # search some agents under the group by search string
            LoadingCircle(WAIT_NORMAL)
            group_details = GroupDetail()
            group_details.searchbox.send_keys(search_string)
            group_details.searchbox.send_keys(Keys.ENTER)
            sleep(sleep_time=WAIT_NORMAL, reason="Wait for list to load")
            searched_list = AgentsList().get_all_agents_by_name()

            # remove all agents those are evaluated by above search
            agent_list.select_deselect_agents(list(filter(None, searched_list)))
            group_details.remove.click()
            group_details.accept_action()
            LoadingCircle(TIME_THREE_SECONDS)

            # Clear the filter
            group_details.back_to_agent_group.click()
            sleep(sleep_time=WAIT_NORMAL, reason="Wait for agents group list to load")
            AgentGroupsList().click_on_group(group_name)
            group_details.searchbox.clear()

            # check that the agents removed are not exists anymore
            group_details.searchbox.send_keys(search_string)
            group_details.searchbox.send_keys(Keys.ENTER)
            sleep(sleep_time=WAIT_NORMAL, reason="Wait for agents list to load")
            assert len(agent_list.get_all_agents_by_name()) == 0, 'Failed to remove filtered agents, ' \
                                                                  'some of them still exists. '

            group_details.back_to_agent_group.click()
            sleep(sleep_time=WAIT_NORMAL, reason="Wait for agents group list to load")

        except(CatiumPageLoadError, TimeoutError):
            log.debug('Failed to load the page. ')
            raise

        finally:
            # delete the above created group
            group_list = AgentGroupsList()
            group_list.delete_group(group_name)
            assert group_name not in group_list.get_all_groups(), 'Failed to delete selected group'

    @pytest.mark.xray(test_key='NES-15462')
    @pytest.mark.xray(test_key='NES-13773')
    @pytest.mark.usefixtures('login', 'nessus_api_login', 'create_agents')
    @pytest.mark.parametrize("create_agents", [{'no_of_agents': 1}], indirect=True)
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),)],
                             indirect=True)
    def test_agent_group_details_page(self, create_agents, create_agent_group_with_new_endpoint):
        """
        NES-13064 : [UI - Automation] : Verify agent group "Details" and "Permissions" tabs function properly
        NES-15462 : Verify Group Details when agent added to group
        NES-13773 : Verify Agent Groups

        Scenario Tested:
            [x] Verify that agent details inside agent group details page is same as
                that of agent details in 'Linked Agents' tab.
            [x] Verify that 'filter' icon and 'search box' is present on agent group details page.
        """
        group_id = create_agent_group_with_new_endpoint[0]['id']
        agent_id = [agent['id'] for agent in self.cat.api.agents.get_agents(scanner_id=1)['agents'] if agent[
            'name'] == create_agents[0]][0]
        self.cat.api.agent_groups.add_agent(scanner_id=1, agent_id=agent_id, group_id=group_id)
        agents_page = AgentsPage()
        agents_page.open()
        agent_list = AgentsList()
        agent_list.loaded()
        agent_data_from_agents_list = self.fetch_agent_data_from_given_agent_record(
            agent_record=agent_list.get_agent_by_name(name=create_agents[0]))

        agent_group_page = AgentGroupsPage()
        agent_group_page.open()
        agent_group_list = AgentGroupsList()
        agent_group_list.loaded()

        agent_group_list.click_on_group(group_name=create_agent_group_with_new_endpoint[0]['name'])
        agent_list.loaded()

        agent_data_from_agent_group_details = self.fetch_agent_data_from_given_agent_record(
            agent_record=agent_list.get_agent_by_name(name=create_agents[0]))
        # Verify agent group details page.
        assert agent_data_from_agent_group_details == agent_data_from_agents_list, \
            "agent details inside agent group details page is not same as that of agent details in 'Linked Agents' tab."
        assert agent_group_page.is_element_present('search_box'), \
            "Search box is not present on agent group details page."
        assert agents_page.is_element_present('filter_link'), "Filter icon is not present on agent group details page."

    @pytest.mark.xray(test_key='NES-15462')
    @pytest.mark.usefixtures('login', 'nessus_api_login', 'create_users_using_api')
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),)],
                             indirect=True)
    @pytest.mark.parametrize('create_users_using_api', [[API.Permissions.User.BASIC, API.Permissions.User.ADMINISTRATOR,
                                                         API.Permissions.User.STANDARD]], indirect=True)
    def test_agent_group_permissions_tab_visibility(self, create_agent_group_with_new_endpoint):
        """
        NES-13064 : [UI - Automation] : Verify agent group "Details" and "Permissions" tabs function properly
        NES-15462 : Verify Group Details when agent added to group

        Scenario Tested:
            [x] Verify that elements displayed properly on 'Permissions' tab on agent group table.
            [x] Save and cancel button.
        """
        agent_group_page = AgentGroupsPage()
        agent_group_page.open()
        agent_group_list = AgentGroupsList()
        agent_group_list.loaded()

        agent_group_list.click_on_group(group_name=create_agent_group_with_new_endpoint[0]['name'])
        agent_group_details = GroupDetail()
        wait(lambda: agent_group_details.is_element_present('permissions_tab'),
             timeout_seconds=TIME_FIVE_SECONDS)
        agent_group_details.permissions_tab.click()
        try:
            wait(lambda: agent_group_details.is_element_present('add_user_group_input'),
                 timeout_seconds=TIME_FIVE_SECONDS)
        except TimeoutExpired:
            raise AssertionError("search user field is not available on 'permissions' tab.")

        assert [option['label'] for option in agent_group_details.select_user_permission.option_values] == \
               ['No access', 'Can use'], \
            "'No access' and 'Can use' options are not available on 'permissions' tab."

        assert agent_group_page.is_element_present('save_button'), 'Save button is visible'
        assert agent_group_page.is_element_present('cancel_button'), 'Cancel button is not visible'

    @pytest.mark.usefixtures('login', 'nessus_api_login', 'delete_all_agents_in_nessus_manager',
                             'delete_all_agents_groups_in_nessus_manager', 'create_agents')
    @pytest.mark.parametrize("create_agents", [{'no_of_agents': 1}], indirect=True)
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),)],
                             indirect=True)
    def test_add_to_group_button_pop_up(self, create_agents, create_agent_group_with_new_endpoint):
        """
        NES-13054: [UI- Automation] : Automation for 'Agent group' functionality

        Scenario Tested:
            [x] Verify that 'Add Group(s)' pop up displays with proper details.
        """
        agent_page = AgentsPage()
        agent_page.open()
        wait(lambda: agent_page.is_element_present('search_agent_input'), waiting_for="Agents page to get loaded.",
             timeout_seconds=TIME_TEN_SECONDS)
        agent_list = AgentsList()
        agent_name = agent_list.get_all_agents_by_name()[0]
        agent_list.select_deselect_agents(agents_list=[agent_name], select=True)
        agent_page.manage_button.click()
        agent_page.add_to_groups_button.click()
        add_to_group_modal = ActionCloseModal()
        add_agent_group_list = AddAgentGroupList()

        # Verify 'Add to Group(s)' pop up details.
        try:
            try:
                wait(lambda: add_to_group_modal.is_element_present('modal'), timeout_seconds=TIME_FIVE_SECONDS,
                     waiting_for="'Adding agents to agent group' modal to get displayed.")
            except TimeoutExpired:
                raise AssertionError("'Adding agents to agent group' modal did not appeared "
                                     "after clicking on 'Add Group(s)' button")
            assert [column.text for column in add_agent_group_list.modal_agent_group_columns] == \
                   ['Name', 'Agents', 'Last Modified'], \
                "Agent group list columns are incorrect inside  'Add to Group(s)' pop up."
            assert add_to_group_modal.action_button.text == "Add" and \
                   add_to_group_modal.cancel_button.text == 'Cancel', \
                "Add and Cancel buttons are not present in 'Add to Group(s)' pop up."
            assert add_to_group_modal.modal_title.text == Nessus.Agents.ADD_TO_GROUP, \
                "'Add to Group(s)' pop up title is incorrect."
        finally:
            add_to_group_modal.close_button.click()
            add_to_group_modal.wait_for_modal_closed()

    @pytest.mark.xray(test_key='NES-15338')
    @pytest.mark.usefixtures('login', 'nessus_api_login', 'delete_all_agents_in_nessus_manager',
                             'delete_all_agents_groups_in_nessus_manager', 'create_agents')
    @pytest.mark.parametrize("create_agents", [{'no_of_agents': 1}], indirect=True)
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),)],
                             indirect=True)
    def test_verify_add_agent_link_on_blank_agent_group(self, create_agents, create_agent_group_with_new_endpoint):
        """
        NES-15338 : Verify 'add agents' link of agent group page when agents are linked.
        """
        agent_group_page = AgentGroupsPage()
        agent_group_page.open()
        group_list = AgentGroupsList()
        group_list.loaded()
        group_list.click_on_group(group_name=create_agent_group_with_new_endpoint[0]['name'])
        agent_group_page.add_agent_link.click()
        add_agent_group_list = AddAgentGroupList()
        wait(lambda: add_agent_group_list.is_element_present('modal_agent_rows'),
             waiting_for='waiting for list to get loaded', timeout_seconds=10)
        all_available_agents = add_agent_group_list.get_all_agent_names()
        assert create_agents == all_available_agents, 'Agents not available in list'

    @pytest.mark.usefixtures('login', 'nessus_api_login', 'delete_all_agents_in_nessus_manager',
                             'delete_all_agents_groups_in_nessus_manager', 'create_agents')
    @pytest.mark.parametrize("create_agents", [{'no_of_agents': 1}], indirect=True)
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),),
                                                                      (random_name(prefix='agent-group-'),
                                                                       random_name(prefix='agent-group-'))],
                             indirect=True)
    def test_add_agent_using_add_to_group_button(self, create_agents, create_agent_group_with_new_endpoint):
        """
        NES-13054: [UI- Automation] : Automation for 'Agent group' functionality

        Scenario Tested:
            [x] Verify that agent can be added to single/multiple agent groups using 'Add to Group(s)' button.
        """
        agent_page = AgentsPage()
        agent_page.open()
        wait(lambda: agent_page.is_element_present('search_agent_input'), waiting_for="Agents page to get loaded.",
             timeout_seconds=TIME_TEN_SECONDS)

        agent_list = AgentsList()
        agent_name = agent_list.get_all_agents_by_name()[0]
        agent_list.select_deselect_agents(agents_list=[agent_name], select=True)
        agent_page.manage_button.click()
        agent_page.add_to_groups_button.click()
        add_to_group_modal = ActionCloseModal()
        wait(lambda: add_to_group_modal.is_element_present('modal'))

        add_agent_group_list = AddAgentGroupList()
        group_names = add_agent_group_list.get_all_agent_group_names()
        add_agent_group_list.select_agent_group_from_modal(group_names)
        add_to_group_modal.accept_action()

        # Verify that agent is linked to single / multiple agent groups successfully.

        assert Notifications().successes[-1] == Messages.NotificationMessages.Agents.AgentGroups. \
            agent_added_to_groups, \
            "Notification message for adding agent to agent group using 'Add to Group(s)' button is incorrect."
        add_to_group_modal.wait_for_modal_closed()
        assert agent_list.get_group_name_by_agent(agent_name=agent_name) == ", ".join(group_names), \
            "Agent group(s) associated with agent is incorrect."

    @pytest.mark.usefixtures('login', 'nessus_api_login', 'delete_all_agents_in_nessus_manager', 'create_agents')
    @pytest.mark.parametrize("create_agents", [{'no_of_agents': 1}], indirect=True)
    def test_verify_new_agent_group_pop_up(self):
        """
        NES-13054: [UI- Automation] : Automation for 'Agent group' functionality

        Scenario Tested:
            [x] Verify 'New Agent Group' button pop up elements.
            [x] Verify that process for creating new agent group using 'New Agent Group' pop up can be cancelled.
        """
        agent_page = AgentsPage()
        agent_page.open()
        wait(lambda: agent_page.is_element_present('search_agent_input'), waiting_for="Agents page to get loaded.",
             timeout_seconds=TIME_TEN_SECONDS)
        agent_list = AgentsList()
        agent_name = agent_list.get_all_agents_by_name()[0]
        agent_list.select_deselect_agents(agents_list=[agent_name], select=True)
        agent_page.manage_button.click()
        agent_page.new_group_button.click()
        new_group_modal = ActionCloseModal()
        # Verify 'New Agent Group' button's pop up elements.
        try:
            try:
                wait(lambda: new_group_modal.is_element_present('modal'), timeout_seconds=TIME_FIVE_SECONDS,
                     waiting_for="'Adding agents to agent group' modal to get displayed.")
            except TimeoutExpired:
                raise AssertionError("'Creating new agent group' modal did not appeared "
                                     "after clicking on 'New Group' button")
            assert new_group_modal.modal_title.text == Nessus.AgentGroups.NEW_AGENT_GROUP, \
                "'New Agent Group' button's pop up title is incorrect."
            assert new_group_modal.action_button.text == "Add" and \
                   new_group_modal.cancel_button.text == 'Cancel', \
                "'New Agent Group' button pop up does not have Add/Cancel buttons."
        finally:
            new_group_modal.close_button.click()
            new_group_modal.wait_for_modal_closed()
            # Verify that process for creating new agent group using 'New Agent Group' pop up can be cancelled.
            assert not new_group_modal.is_element_present('modal'), \
                "Process for creating new agent group using 'New Agent Group' pop up can not be cancelled."

    @pytest.mark.xray(test_key='NES-13773')
    @pytest.mark.usefixtures('login', 'nessus_api_login', 'delete_all_agents_groups_in_nessus_manager')
    def test_agent_group_page_when_no_groups_created(self):
        """
        NES-13054: [UI- Automation] : Automation for 'Agent group' functionality
        NES-13773 : Verify Agent Groups

        Scenario Tested:
            [x] Verify elements on agent group page when there is not any agent group created.
            [x] Verify 'Delete' button does not appear when there is not any agent group created.
        """
        agent_group_page = AgentGroupsPage()
        agent_group_page.open()
        wait(lambda: agent_group_page.is_element_present('description_link'),
             waiting_for="Agent group page to get loaded.", timeout_seconds=TIME_TEN_SECONDS)
        assert agent_group_page.is_element_present('empty_groups'), \
            "Element showing agent groups are empty is not present."
        assert agent_group_page.is_element_present('new_group_link'), "Link to create new agent group is not present."
        assert not agent_group_page.is_element_present('delete_button'), \
            "Delete button is present on agent groups page when there is not any agent group present."

    @pytest.mark.usefixtures('login', 'nessus_api_login', 'delete_all_agents_groups_in_nessus_manager')
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),)],
                             indirect=True)
    def test_verify_elements_visibility_on_agent_group_page(self, create_agent_group_with_new_endpoint):
        """
        NES-13054: [UI- Automation] : Automation for 'Agent group' functionality

        Scenario Tested:
            [x] Verify elements visibility on agent group page.
            [x] Verify 'Delete' button appears only when any agent group is selected.
        """
        agent_group_page = AgentGroupsPage()
        agent_group_page.open()
        wait(lambda: agent_group_page.is_element_present('description_link'),
             waiting_for="Agent group page to get loaded.", timeout_seconds=TIME_TEN_SECONDS)
        assert agent_group_page.agent_group_header.text == Nessus.AgentGroups.AGENT_GROUP_HEADER, \
            "Agent group page header is incorrect."
        assert agent_group_page.is_element_present('link_to_agents'), \
            "Hyperlink to navigate to linked agent page is not present on agent group page."
        assert not agent_group_page.is_element_present('delete_button'), \
            "Delete button is present on agent groups page when there is not any agent group selected."
        agent_group_list = AgentGroupsList()
        assert agent_group_list.is_element_present('columns') and agent_group_list.is_element_present('rows'), \
            "Agent group table is not present."
        assert create_agent_group_with_new_endpoint[0].get('name') in [group.split(
            "\n")[1] for group in AgentGroupsList().get_all_groups()], \
            "Created agent group is not present in agent group list."
        agent_group_list.select_deselect_agent_groups(group_list=[create_agent_group_with_new_endpoint[0].get('name')])
        assert agent_group_page.is_element_present('delete_button'), \
            "Delete button is not present on agent groups page when agent group is selected."
        agent_group_page.link_to_agents.click()
        try:
            wait(lambda: AgentsPage().is_element_present('linked_agents_description'),
                 waiting_for="Linked agents page to get loaded.", timeout_seconds=TIME_TEN_SECONDS)
        except TimeoutExpired:
            raise AssertionError("'linked' tab on agent group page did not navigate user to agents page.")

    @pytest.mark.usefixtures('login', 'nessus_api_login', 'delete_all_agents_groups_in_nessus_manager')
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),)],
                             indirect=True)
    def test_verify_agent_group_table_columns(self, create_agent_group_with_new_endpoint):
        """
        NES-13054: [UI- Automation] : Automation for 'Agent group' functionality

        Scenario Tested:
            [x] Verify Agent group table populated correctly.
        """
        agent_group_page = AgentGroupsPage()
        agent_group_page.open()
        wait(lambda: agent_group_page.is_element_present('search_box'),
             waiting_for="Agent group page to get loaded.", timeout_seconds=TIME_TEN_SECONDS)
        agent_group_list = AgentGroupsList()

        # Verify Agent group table column names.
        assert {'Name', 'Last Modified', 'Agents'}.issubset(set([column.text for column in agent_group_list.columns])), \
            "Agent group table columns are not correct."
        assert create_agent_group_with_new_endpoint[0]['name'] in [group.split('\n')[1] for group in
                                                                   agent_group_list.get_all_groups()], \
            "Agent group did not created successfully."

    @pytest.mark.usefixtures('login', 'nessus_api_login', 'delete_all_agents_groups_in_nessus_manager')
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [
        (random_name(prefix='agent-group-'), random_name(prefix='agent-group-'), random_name(prefix='agents-group-'),
         random_name(prefix='agents-group-'), random_name(prefix='agents-group-'))], indirect=True)
    @pytest.mark.parametrize('search_value', ['agents-group', 'agent-group'])
    def test_verify_agent_group_sorted_and_populated_as_per_search(self, create_agent_group_with_new_endpoint,
                                                                   search_value):
        """
        NES-13054: [UI- Automation] : Automation for 'Agent group' functionality

        Scenario Tested:
            [x] Verify that agent groups get populated/sorted as per search input.
        """
        agent_group_page = AgentGroupsPage()
        agent_group_page.open()
        wait(lambda: agent_group_page.is_element_present('search_box'),
             waiting_for="Agent group page to get loaded.", timeout_seconds=TIME_TEN_SECONDS)
        agent_group_page.search_box.value = search_value

        group_names = [group['name'] for group in create_agent_group_with_new_endpoint if search_value in group['name']]
        group_names.sort()

        agent_group_list = AgentGroupsList()

        # Verify that agent groups get populated as per search input
        try:
            wait(lambda: len(agent_group_list.get_all_groups()) == len(group_names),
                 waiting_for="Agent groups to get populated as per search input.", timeout_seconds=TIME_FIVE_SECONDS)
        except TimeoutExpired:
            raise AssertionError("While searching agent groups, incorrect number of agent groups found. Expected is : "
                                 "{} but actual is : {}".format(len(group_names),
                                                                len(agent_group_list.get_all_groups())))

        # Verify that agent groups are sorted correctly..
        assert [group.split('\n')[1] for group in agent_group_list.get_all_groups()] == group_names, \
            "Agent groups are not sorted correctly."

    @pytest.mark.usefixtures('login', 'nessus_api_login', 'delete_all_agents_groups_in_nessus_manager')
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [
        (random_name(prefix='agent-group-'), random_name(prefix='agent-group-'), random_name(prefix='agent-group-'),
         random_name(prefix='agent-group-'), random_name(prefix='agent-group-'))], indirect=True)
    @pytest.mark.parametrize('deselect_count', [3])
    def test_verify_agent_group_count(self, create_agent_group_with_new_endpoint, deselect_count):
        """
        NES-13054: [UI- Automation] : Automation for 'Agent group' functionality

        Scenario Tested:
            [x] Verify that agent group count is as expected.
            [x] Verify that selected agent group count gets updated as per agent group selected/deselected.
        """
        group_names = [group['name'] for group in create_agent_group_with_new_endpoint]
        agent_group_page = AgentGroupsPage()
        agent_group_page.open()
        wait(lambda: agent_group_page.is_element_present('search_box'),
             waiting_for="Agent group page to get loaded.", timeout_seconds=TIME_TEN_SECONDS)

        # Verify Agent group count
        assert int(agent_group_page.total_records.text.split(" Groups")[0]) == len(
            create_agent_group_with_new_endpoint), "Agent Groups count is incorrect."
        agent_group_list = AgentGroupsList()
        agent_group_list.select_deselect_agent_groups(group_list=group_names)

        # Verify selected agent group count increases/decreases as user selects/deselects them.
        assert int(re.search(r'\d{1,3}', agent_group_page.checked_groups.text).group()) == len(
            create_agent_group_with_new_endpoint), "Selected agent group count is incorrect."

        agent_group_list.select_deselect_agent_groups(group_list=group_names[:deselect_count])
        assert int(re.search(r'\d{1,3}', agent_group_page.checked_groups.text).group()) == \
               len(group_names) - deselect_count, "After deselecting agent groups, " \
                                                  "selected agent groups count did not decrease."

    @pytest.mark.xray(test_key='NES-13773')
    @pytest.mark.usefixtures('login', 'nessus_api_login', 'delete_all_agents_groups_in_nessus_manager')
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),)],
                             indirect=True)
    def test_edit_agent_group_name_using_pencil_icon(self, create_agent_group_with_new_endpoint):
        """
        NES-13054: [UI- Automation] : Automation for 'Agent group' functionality
        NES-13773 : Verify Agent Groups

        Scenario Tested:
            [x] Verify that agent group name can be edited/renamed successfully using pencil icon in agent group table.
        """
        agent_group_page = AgentGroupsPage()
        agent_group_page.open()
        wait(lambda: agent_group_page.is_element_present('search_box'),
             waiting_for="Agent group page to get loaded.", timeout_seconds=TIME_TEN_SECONDS)
        original_agent_group_name = create_agent_group_with_new_endpoint[0].get('name')
        new_agent_group_name = random_name(prefix='agent-group-')
        agent_group_list = AgentGroupsList()
        agent_group_list.edit_agent_group_name(original_group_name=original_agent_group_name,
                                               new_name=new_agent_group_name)
        # Verify that agent group name is edited/renamed successfully.

        assert Notifications().successes[-1] == Messages.NotificationMessages.Agents.AgentGroups. \
            edit_agent_group, "Notification message for editing agent group name is incorrect."
        wait(lambda: agent_group_page.is_element_present('search_box'))
        assert new_agent_group_name in [group.split("\n")[1] for group in AgentGroupsList().get_all_groups()], \
            "New Agent group name did not updated in agent groups table."

    @pytest.mark.usefixtures('login', 'nessus_api_login', 'delete_all_agents_groups_in_nessus_manager', 'create_agents')
    @pytest.mark.parametrize("create_agents", [{'no_of_agents': 1}], indirect=True)
    @pytest.mark.parametrize("sort", (["desc", "asc"]))
    @pytest.mark.parametrize("column_to_sort", ["Name"])
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [
        (random_name(prefix='agent-group-'), random_name(prefix='agent-group-'),
         random_name(prefix='agent-group-'))], indirect=True)
    def test_sorting_in_agent_group_table(self, create_agent_group_with_new_endpoint, create_agents, column_to_sort,
                                          sort):
        """
        NES-15513 : Verify sorting work for 'name' column of agent group table

        Scenario Tested:
            [x] Verify that "Name" column in agents group table can be sorted in ascending/descending order

        """

        agent_group_page = AgentGroupsPage()
        agent_group_page.open()
        agent_group_list = AgentGroupsList()
        agent_group_list.loaded()

        column_mapping = {"Name": "name", "Agents": "agents", "Last Modified": "last_modified_time"}
        map_attribute = column_mapping[column_to_sort]

        expected_agents_group_list = sorted([getattr(agent, map_attribute).strip(
            "Shared\n") for agent in agent_group_list.rows], key=lambda k: k.lower(),
            reverse=(sort == SortOrder.DESCENDING))

        self.sort_given_column_in_agent_group_table(column_name=column_to_sort,
                                                    agent_group_list=agent_group_list, sort=sort)

        sorted_agent_list_on_ui = [getattr(agent, map_attribute).strip("Shared\n") for agent in agent_group_list.rows]
        assert expected_agents_group_list == sorted_agent_list_on_ui, \
            "Agent group did not sorted for {}".format(column_to_sort)

    @pytest.mark.xray(test_key='NES-15427')
    @pytest.mark.usefixtures('login', 'nessus_api_login', 'delete_all_agents_groups_in_nessus_manager')
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),)],
                             indirect=True)
    def test_verify_edit_agent_group_pop_up(self, create_agent_group_with_new_endpoint):
        """
        NES-13061 : [UI-Automation] : Automate agent group editing and cancellation while editing
        NES-15427 : Verify 'Edit agent group' name popup appearance

        Scenario Tested:
            [x] Verify 'Edit Agent Group' pop up details.
            [x] Verify 'Edit Agent Group' pop up cancellation.
        """
        agent_group_page = AgentGroupsPage()
        agent_group_page.open()
        wait(lambda: agent_group_page.is_element_present('search_box'),
             waiting_for="Agent group page to get loaded.", timeout_seconds=TIME_TEN_SECONDS)
        agent_group_list = AgentGroupsList()
        agent_group_list.rows[0].edit.click()
        edit_agent_group_modal = ActionCloseModal()

        # Verify 'Edit Agent Group' pop up
        assert edit_agent_group_modal.modal_title.text == Nessus.AgentGroups.EDIT_AGENT_GROUP
        assert edit_agent_group_modal.action_button.text == "Save" and \
               edit_agent_group_modal.cancel_button.text == "Cancel", "'Save' and 'Cancel' buttons are not present " \
                                                                      "on 'Edit Agent Group' pop up."
        edit_agent_group_modal.cancel_button.click()
        try:
            edit_agent_group_modal.wait_for_modal_closed()
        except TimeoutExpired:
            raise AssertionError("Edit agent group pop up can not be closed successfully.")

    @pytest.mark.xray(test_key='NES-15527')
    @pytest.mark.usefixtures('login', 'nessus_api_login', 'delete_all_agents_in_nessus_manager',
                             'delete_all_agents_groups_in_nessus_manager', )
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),)],
                             indirect=True)
    def test_watermark_on_agent_group_page_when_no_agents_linked(self, create_agent_group_with_new_endpoint):
        """
        NES-15527 : Verify the watermark for agent group page when no agent linked to NM

        Scenario Tested:
        [x] Verify watermark on agent group page when there is no agent linked.
        """
        agent_group_page = AgentGroupsPage()
        agent_group_page.open()
        wait(lambda: agent_group_page.is_element_present('description_link'),
             waiting_for="Agent group page to get loaded.", timeout_seconds=TIME_TEN_SECONDS)
        agent_group_name = create_agent_group_with_new_endpoint[0].get('name')
        AgentGroupsList().click_on_group(group_name=agent_group_name)
        assert agent_group_page.empty_agent_watermark.text == Nessus.AgentGroups.WATERMARK_FOR_EMPTY_AGENT

    @pytest.mark.xray(test_key='NES-15500')
    @pytest.mark.usefixtures('login', 'nessus_api_login', 'delete_all_agents_in_nessus_manager',
                             'delete_all_agents_groups_in_nessus_manager', )
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),
                                                                       random_name(prefix='agent-group-'),
                                                                       random_name(prefix='agent-group-'))],
                             indirect=True)
    def test_edit_and_delete_button_display_for_each_agent_group_selected(self, create_agent_group_with_new_endpoint):
        """
        NES-15500 : Verify that Edit and Delete buttons are displayed for each group

        Scenario Tested:
        [x] Edit and Delete buttons for each agent group.
        """
        agent_group_page = AgentGroupsPage()
        agent_group_page.open()
        wait(lambda: agent_group_page.is_element_present('description_link'),
             waiting_for="Agent group page to get loaded.", timeout_seconds=TIME_TEN_SECONDS)
        for agent_group in create_agent_group_with_new_endpoint:
            agent_group_page.get_agent_group_checkbox_by_group_name(agent_group['name']).check()
            wait(lambda: agent_group_page.is_element_present('delete_button'), timeout_seconds=TIME_FIVE_SECONDS,
                 sleep_seconds=WAIT_SHORT)
            assert agent_group_page.is_element_present('delete_button')
            assert agent_group_page.is_element_present('edit_button')
            agent_group_page.get_agent_group_checkbox_by_group_name(agent_group['name']).check()
            wait(lambda: not agent_group_page.is_element_present('delete_button'), timeout_seconds=TIME_FIVE_SECONDS,
                 sleep_seconds=WAIT_SHORT)
            assert not agent_group_page.is_element_present('delete_button')
            assert not agent_group_page.is_element_present('edit_button')

    @pytest.mark.xray(test_key='NES-15433')
    @pytest.mark.usefixtures('login', 'nessus_api_login', 'delete_all_agents_groups_in_nessus_manager', 'create_agents')
    @pytest.mark.parametrize("create_agents", [{'no_of_agents': 1}], indirect=True)
    @pytest.mark.parametrize("sort", (["desc", "asc"]))
    @pytest.mark.parametrize("column_to_sort", ["Agents"])
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [
        (random_name(prefix='agent-group-'), random_name(prefix='agent-group-'),
         random_name(prefix='agent-group-'))], indirect=True)
    def test_agent_column_sorting_in_agent_group_table(self, create_agent_group_with_new_endpoint, create_agents,
                                                       column_to_sort, sort):
        """
        NES-15433 : Verify sorting work for 'agents' column of agent group table

        Scenario Tested:
            [x] Verify that "Agents"  columns in agents group table can be sorted in ascending/descending order

        """
        group_id = create_agent_group_with_new_endpoint[1]['id']

        agent_id = [agent['id'] for agent in self.cat.api.agents.get_agents(scanner_id=1)['agents'] if agent[
            'name'] == create_agents[0]][0]

        # Adding agent to agent group so that "Agent" column sorting can be verified on agent group table.
        if column_to_sort == "Agents":
            self.cat.api.agent_groups.add_agent(scanner_id=1, agent_id=agent_id, group_id=group_id)

        agent_group_page = AgentGroupsPage()
        agent_group_page.open()
        agent_group_list = AgentGroupsList()
        agent_group_list.loaded()

        column_mapping = {"Name": "name", "Agents": "agents", "Last Modified": "last_modified_time"}
        map_attribute = column_mapping[column_to_sort]

        expected_agents_group_list = sorted([getattr(agent, map_attribute).strip(
            "Shared\n") for agent in agent_group_list.rows], key=lambda k: k.lower(),
            reverse=(sort == SortOrder.DESCENDING))

        self.sort_given_column_in_agent_group_table(column_name=column_to_sort,
                                                    agent_group_list=agent_group_list, sort=sort)

        sorted_agent_list_on_ui = [getattr(agent, map_attribute).strip("Shared\n") for agent in agent_group_list.rows]
        assert expected_agents_group_list == sorted_agent_list_on_ui, \
            "Agent group did not sorted for {}".format(column_to_sort)

    @pytest.mark.xray(test_key='NES-15513')
    @pytest.mark.xray(test_key='NES-15467')
    @pytest.mark.usefixtures('login', 'nessus_api_login', 'delete_all_agents_groups_in_nessus_manager', 'create_agents')
    @pytest.mark.parametrize("create_agents", [{'no_of_agents': 1}], indirect=True)
    @pytest.mark.parametrize("sort", (["desc", "asc"]))
    @pytest.mark.parametrize("column_to_sort", ["Last Modified"])
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [
        (random_name(prefix='agent-group-'), random_name(prefix='agent-group-'),
         random_name(prefix='agent-group-'))], indirect=True)
    def test_sorting_in_agent_group_table(self, create_agent_group_with_new_endpoint, create_agents, column_to_sort,
                                          sort):
        """
        NES-15467 : Verify sorting work for 'Last modified' column of agent group table

        Scenario Tested: NES-13065
           [x] Verify that "Last Modified" column in agents group table can be sorted in ascending/descending order.

        """
        group_id = create_agent_group_with_new_endpoint[1]['id']

        agent_id = [agent['id'] for agent in self.cat.api.agents.get_agents(scanner_id=1)['agents'] if agent[
            'name'] == create_agents[0]][0]

        # Adding agent to agent group so that "Agent" column sorting can be verified on agent group table.
        if column_to_sort == "Agents":
            self.cat.api.agent_groups.add_agent(scanner_id=1, agent_id=agent_id, group_id=group_id)

        # Waiting for one minute and modifying agent group name so that
        # "Last Modified" can be verified on agent group table.
        elif column_to_sort == "Last Modified":
            sleep(TIME_SIXTY_SECONDS, reason="Waiting for one minute before changing agent group name so that "
                                             "last modified time can be different for created agent groups.")
            payload = {"name": random_name(prefix='edited-agent-group-')}
            self.cat.api.agent_groups.update_agent_group(group_id=group_id, data=payload)

        agent_group_page = AgentGroupsPage()
        agent_group_page.open()
        agent_group_list = AgentGroupsList()
        agent_group_list.loaded()

        column_mapping = {"Name": "name", "Agents": "agents", "Last Modified": "last_modified_time"}
        map_attribute = column_mapping[column_to_sort]

        expected_agents_group_list = sorted([getattr(agent, map_attribute).strip(
            "Shared\n") for agent in agent_group_list.rows], key=lambda k: k.lower(),
            reverse=(sort == SortOrder.DESCENDING))

        self.sort_given_column_in_agent_group_table(column_name=column_to_sort,
                                                    agent_group_list=agent_group_list, sort=sort)

        sorted_agent_list_on_ui = [getattr(agent, map_attribute).strip("Shared\n") for agent in agent_group_list.rows]
        assert expected_agents_group_list == sorted_agent_list_on_ui, \
            "Agent group did not sorted for {}".format(column_to_sort)

    @pytest.mark.xray(test_key='NES-16242')
    @pytest.mark.xray(test_key='NES-15508')
    @pytest.mark.usefixtures('login', 'nessus_api_login', 'delete_all_agents_in_nessus_manager',
                             'delete_all_agents_groups_in_nessus_manager', )
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),
                                                                       random_name(prefix='agent-group-'),
                                                                       random_name(prefix='agent-group-'))],
                             indirect=True)
    def test_only_delete_button_display_on_selecting_all_agent_group(self, create_agent_group_with_new_endpoint):
        """
        NES-16242 : Verify that Delete button is displayed for select all agent group
        NES-15508 : Verify if user selects multiple agent groups then "Edit" button does not disappear.

        Scenario Tested:
        [x] Delete button for select all agent group.
        [x] Edit button should disappear when select all agent group
        """
        agent_group_page = AgentGroupsPage()
        agent_group_page.open()
        wait(lambda: agent_group_page.is_element_present('description_link'),
             waiting_for="Agent group page to get loaded.", timeout_seconds=TIME_TEN_SECONDS)
        agent_group_page.select_all_checkbox.check()
        wait(lambda: agent_group_page.is_element_present('delete_button'), timeout_seconds=TIME_FIVE_SECONDS,
             sleep_seconds=WAIT_SHORT)
        assert agent_group_page.is_element_present('delete_button')
        assert not agent_group_page.is_element_present('edit_button')
        agent_group_page.select_all_checkbox.check()
        wait(lambda: not agent_group_page.is_element_present('delete_button'), timeout_seconds=TIME_FIVE_SECONDS,
             sleep_seconds=WAIT_SHORT)
        assert not agent_group_page.is_element_present('edit_button')

    @pytest.mark.xray(test_key='NES-15510')
    @pytest.mark.usefixtures('login', 'nessus_api_login', 'delete_all_agents_groups_in_nessus_manager')
    def test_cancel_the_agent_group_creation(self):
        """
        NES-15510: Cancel the creating agent group.

        Scenario Tested:
            [x] Verify on cancel Popup should disappear and process should stopped..
        """
        agent_group_page = AgentGroupsPage()
        agent_group_page.open()
        wait(lambda: agent_group_page.is_element_present('description_link'),
             waiting_for="Agent group page to get loaded.", timeout_seconds=TIME_TEN_SECONDS)
        agent_group_page.new_group_button.click()
        new_group_modal = ActionCloseModal()
        try:
            wait(lambda: new_group_modal.is_element_present('modal'), timeout_seconds=TIME_FIVE_SECONDS,
                 waiting_for="'Adding agents to agent group' modal to get displayed.")
        except TimeoutExpired:
            raise AssertionError("'Creating new agent group' modal did not appeared "
                                 "after clicking on 'New Group' button")
        new_group_modal.modal_cancel.click()
        new_group_modal.wait_for_modal_closed()
        # Verify that process for creating new agent group using 'New Agent Group' pop up can be cancelled.
        assert not new_group_modal.is_element_present('modal'), \
            "Process for creating new agent group using 'New Agent Group' pop up can not be cancelled."

    @pytest.mark.xray(test_key='NES-15474')
    @pytest.mark.usefixtures('login', 'nessus_api_login', 'delete_all_agents_groups_in_nessus_manager')
    def test_linked_hypertext_navigate_to_agents_page(self):
        """
        NES-15474: Verify that "linked" hyperlink works on agent group page.

        Scenario Tested:
            [x] Verify on linked hyperlink user should navigate to 'Linked agents' page.
        """
        agent_group_page = AgentGroupsPage()
        agent_group_page.open()
        wait(lambda: agent_group_page.is_element_present('description_link'),
             waiting_for="Agent group page to get loaded.", timeout_seconds=TIME_TEN_SECONDS)
        agent_group_page.description_link.click()
        wait(lambda: agent_group_page.is_element_present('agent_group_header'),
             waiting_for="Linked Agent page to get loaded.", timeout_seconds=TIME_TEN_SECONDS)
        assert agent_group_page.is_element_present('linked_agent_tab'), "User not navigated to Linked Agent page " \
                                                                        "by clicking on linked hypertext."

    @pytest.mark.xray(test_key='NES-15374')
    @pytest.mark.usefixtures('login', 'nessus_api_login', 'delete_all_agents_groups_in_nessus_manager')
    def test_cancel_editing_of_group_name(self):
        """
        NES-15374 : Cancel the editing of group name

        Scenario Tested:
            [x] Verify Agent group edit modal appears when clicking Pencil icon
            [x] Verify name of created group is shown in edit group modal
            [x] Verify Agent group edit modal dismisses when clicking Cancel button
        """

        new_group_name = random_name(prefix='Agents-group-')

        agent_group_page = CreateGroupWindowPage()
        agent_group_page.open()
        wait(lambda: agent_group_page.is_element_present('new_group_button'),
             waiting_for="New group button to get visible", timeout_seconds=TIME_TEN_SECONDS)

        agent_group_page.create_group(group_name=new_group_name)
        wait(lambda: agent_group_page.is_element_present('new_group_button'),
             waiting_for="New group button to get visible", timeout_seconds=TIME_TEN_SECONDS)

        agent_group_list = AgentGroupsList()
        agent_group_list.loaded()
        agent_group_list.rows[0].edit.click()
        edit_agent_group_modal = ActionCloseModal()
        wait(lambda: edit_agent_group_modal.is_element_present('modal'), timeout_seconds=TIME_FIVE_SECONDS,
             waiting_for="Edit Agent group modal to get displayed.")

        assert agent_group_list.new_agent_group_name.value == new_group_name, "Agent group name doesn't match"
        edit_agent_group_modal.modal_cancel.click()
        assert not edit_agent_group_modal.is_element_present('modal'), "Agent group edit modal is still open"

    @pytest.mark.xray(test_key='NES-15390')
    @pytest.mark.usefixtures('login', 'nessus_api_login', 'delete_all_agents_in_nessus_manager',
                             'delete_all_agents_groups_in_nessus_manager', )
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),
                                                                       random_name(prefix='agent-group-'),
                                                                       random_name(prefix='agent-group-'))],
                             indirect=True)
    def test_verify_edit_and_delete_button_disappear_when_clearing_group_selection(self,
                                                                                   create_agent_group_with_new_endpoint):
        """
        NES-15390 : Verify edit and delete button disappear when click on clear selected items.

        Tested Scenarios:
        [X] Verified that Edit and Delete buttons appear when selecting any Agent group
        [X] Verified that Edit and Delete buttons disappears when clicking Clear selected items link
        """
        agent_group_page = AgentGroupsPage()
        agent_group_page.open()
        wait(lambda: agent_group_page.is_element_present('description_link'),
             waiting_for="Agent group page to get loaded.", timeout_seconds=TIME_TEN_SECONDS)
        agent_group_list = AgentGroupsList()
        all_agent_groups = agent_group_list.get_all_groups()
        agent_group_list.select_deselect_agent_groups(group_list=all_agent_groups[0])
        wait(lambda: agent_group_page.is_element_present('delete_button'), timeout_seconds=TIME_FIVE_SECONDS,
             sleep_seconds=WAIT_SHORT)
        assert agent_group_page.is_element_present('delete_button')
        assert agent_group_page.is_element_present('edit_button')

        # Clear selection by clicking the link
        agent_group_page.clear_selected_item.click()
        assert not agent_group_page.is_element_present('delete_button'), 'Delete button is still visible'
        assert not agent_group_page.is_element_present('edit_button'), 'Edit button is still visible'


@pytest.mark.cluster_manager
@pytest.mark.parametrize('create_manager_cluster', [{'total_nodes': 1, 'total_agents': 0}], indirect=True)
@pytest.mark.parametrize('add_fake_cluster_agents', [{'total_no_of_agents': 500}], indirect=True)
@pytest.mark.usefixtures('create_manager_cluster', 'add_fake_cluster_agents', 'login')
class TestSelectDeselectInAgentGroups:
    """ Test cases to cover Select/Select-all/Deselect/Deselect-all functionality for agents in agent groups """

    @staticmethod
    def add_and_apply_linked_agent_filters(filters: list, clear_filter: bool = False) -> None:
        """
        Add on filter link and apply it for given param

        :param list filters: list of param for filter
        :param bool clear_filter: True if need to clear filter else False
        :return: None
        """
        agent_page = AgentsPage()
        filter_window = FilterWindow()

        if clear_filter:
            agent_page.filter_link.click()
            filter_window.clear_filters.click()

            ActionCloseModal().wait_for_modal_closed()
            AgentsList().loaded()

        for agent_filter in filters:
            filter_window.add_and_apply_filter(**agent_filter)

        wait(lambda: agent_page.is_element_present('search_agent_input'), timeout_seconds=TIME_SIXTY_SECONDS)

    @staticmethod
    def go_to_linked_agents_group_page():
        """ Click on 'Linked Agents' from side navigation panel """

        SideNav().get_sidenav_element(element_name=Nessus.SideNavResources.LINKED_AGENTS).click()
        AgentsList().loaded()

    @staticmethod
    def create_new_agent_group(new_group: bool, agent_group_name: str) -> None:
        """
        Creates new agent group

        :param bool new_group: creates new agent group if True else False
        :param str agent_group_name: name of agent
        :return: None
        """
        if not new_group:
            AgentGroupsPage().open()
            create_group_window_page = CreateGroupWindowPage()
            create_group_window_page.create_group(group_name=agent_group_name)
            create_group_window_page.wait_for_modal_closed()
            __class__.go_to_linked_agents_group_page()

    @staticmethod
    def click_on_group_in_agent_groups(new_group: bool, agent_group_name: str) -> None:
        """
        Click on given group from Agent Groups page

        :param bool new_group: False if click on existing group else True
        :param str agent_group_name: name of agent group
        :return: None
        """
        if not new_group:
            SideNav().get_sidenav_element(element_name=Nessus.SideNavResources.GROUPS).click()

            agent_groups_list = AgentGroupsList()
            agent_groups_list.loaded()
            agent_groups_list.click_on_group(group_name=agent_group_name)
            AgentsList().loaded()

    @staticmethod
    def delete_agent_group_and_verify(group_name: str) -> None:
        """
        Deletes given agent group from Agent Groups page and verify it's deleted or not

        :param str group_name: name of group to be deleted
        :return: None
        """
        SideNav().get_sidenav_element(element_name=Nessus.SideNavResources.GROUPS).click()

        agent_group_page = AgentGroupsPage()
        wait(lambda: agent_group_page.is_element_present('description_link'),
             waiting_for='Agent Groups page to load properly')

        if not agent_group_page.is_element_present('new_group_link'):
            agent_groups_list = AgentGroupsList()
            agent_groups_list.loaded()
            agent_groups_list.delete_group(group_name=group_name)

    @staticmethod
    def search_agent_name_and_verify(is_search_agent: bool, search_value: str) -> None:
        """
        Search agent and verify from the list

        :param bool is_search_agent: True if you wanna search agent else False
        :param str search_value: value to search the agents
        :return: None
        """
        agent_page = AgentsPage()
        agent_list = AgentsList()

        if is_search_agent:
            agent_page.search_agent_input.clear()
            agent_page.search_agent_input.value = search_value

            # Verifies that 'Search' icon is getting enabled after entering the value in search input field.
            assert agent_page.search_icon.is_enabled(), \
                "'Search' icon is not getting enabled after entering the value in search input field."

            agent_page.search_icon.click()
            agent_list.loaded()

            # Verifies that 'Search' icon is getting enabled after entering the value in search input field.
            assert agent_page.is_element_present('remove_search_icon'), \
                "Remove icon is not displayed after entering the value in search input field."

            # Verifies that all agent name contains the search value after applying the search
            assert all([search_value in agent_name for agent_name in agent_list.get_all_agents_by_name()])

    def search_or_filter_agent_and_return_random_agent_list(
            self, new_group: bool, agent_group_name: str, random_agent_count: int, search_value: str = None,
            search_agent: bool = False, check: bool = False, add_filter: bool = False, filters: list = None) -> tuple:
        """
        Search or Filter agent and return random agent list

        :param bool new_group: False if click on existing group else True
        :param str agent_group_name: name of agent group
        :param int random_agent_count: number to get random agent
        :param bool search_agent: search agent if True else False
        :param str search_value: name of agent to be searched
        :param bool check: select all agents if True else False
        :param bool add_filter: add and apply filter if True else False
        :param list filters: list of param for filter
        :return: random agent list
        :rtype: tuple
        """
        self.create_new_agent_group(new_group=new_group, agent_group_name=agent_group_name)

        if not get_driver().current_url.endswith('/sensors/agents'):
            AgentsPage().open()

        agent_list = AgentsList()
        agent_list.loaded()

        if search_agent:
            self.search_agent_name_and_verify(is_search_agent=search_agent, search_value=search_value)
        elif add_filter:
            self.add_and_apply_linked_agent_filters(filters=filters)

        agent_list.loaded()
        agent_name_list = agent_list.get_all_agents_by_name()

        if check:
            agent_list.select_all_checkbox.check()

        return random.sample(agent_name_list, k=random_agent_count), agent_name_list

    @staticmethod
    def go_to_linked_agents_page_and_search_agent(search_agent: bool, search_value: str):
        """
        Go to Linked agents page and search agent name

        :param bool search_agent: search agent if True else False
        :param str search_value: name of agent to be search
        :return: 
        """
        __class__.go_to_linked_agents_group_page()
        agent_page = AgentsPage()
        agent_list = AgentsList()

        if search_agent:
            if agent_page.is_element_present('remove_search_icon'):
                agent_page.remove_search_icon.click()
                agent_list.loaded()
            agent_page.search_agent_input.value = search_value
            agent_page.search_icon.click()
            agent_list.loaded()

    @staticmethod
    def delete_unlink_agents():
        """ Delete unlinked agents from linked agents list """
        unlink_agent_filter = [{'match_type': Nessus.Filter.FilterMatch.ALL, 'filter_key': Nessus.Agents.Filter.STATUS,
                                'filter_operator': Nessus.Agents.Filter.IS_EQUAL_TO, 'filter_value': 'Unlinked'}]

        __class__.add_and_apply_linked_agent_filters(filters=unlink_agent_filter, clear_filter=True)

        agent_list = AgentsList()
        agent_list.loaded()
        agent_list.select_all_checkbox.check()

        agent_page = AgentsPage()
        wait(lambda: agent_page.is_element_present('delete_button'), waiting_for='Delete button to be visible')

        agent_page.delete_button.click()
        delete_agent_modal = ActionCloseModal()
        delete_agent_modal.accept_action()
        delete_agent_modal.wait_for_modal_closed()

    @staticmethod
    def delete_agents_and_verify_its_deleted(expected_agents: list) -> None:
        """
        Deletes given list of agents and verifies that it's deleted successfully

        :param list expected_agents: list of agents to be deleted
        :return: None
        """
        agent_list = AgentsList()

        for agent in expected_agents:
            agent_list.delete_agent(agent_name=agent)

            notification = Notifications()

            # Verifies success notification message after deleting agent from agent group
            assert notification.successes[-1] == Messages.NotificationMessages.Agents.AgentGroups. \
                remove_agent, 'Success Notification is missing or mismatched after deleting agent from agent group.'

        agent_list.refresh()
        agent_list.loaded()

        # Verifies deleted agents are not present in group after deleting
        assert all([agent not in agent_list.get_all_agents_by_name() for agent in expected_agents]), \
            "Selected agents are still available in agent group after deleting those."

    @staticmethod
    def verify_unlink_agent_modal_and_feature() -> None:
        """ Verifies "Unlinked Agents" modal and it's functionality """

        AgentsPage().unlink_button.click()
        unlink_agent_modal = ActionCloseModal()
        wait(lambda: unlink_agent_modal.is_element_present('modal'), waiting_for='unlink agent modal to come')

        assert all([unlink_agent_modal.modal_title.text == Nessus.Agents.UNLINK_AGENTS,
                    unlink_agent_modal.modal_content.text == Nessus.Agents.UNLINK_AGENTS_WARNING,
                    unlink_agent_modal.is_element_present('action_button'),
                    unlink_agent_modal.is_element_present('cancel_button'),
                    unlink_agent_modal.is_element_present('close_button')]), \
            "'Unlink Agents' modal is missing or something mismatched inside the modal."

        unlink_agent_modal.accept_action()
        unlink_agent_modal.wait_for_modal_closed()

        notification = Notifications()

        assert notification.successes[-1] == Messages.NotificationMessages.Agents.unlink_agents, \
            'Success notification is missing or mismatch after unlinking the agent from list.'

    @staticmethod
    def verify_remove_agents_modal_and_feature() -> None:
        """ Verifies "Remove Agents" modal and it's functionality """

        group_details = GroupDetail()
        group_details.js_scroll_into_view(element=group_details.remove)
        group_details.remove.click()
        wait(lambda: group_details.is_element_present('modal'), waiting_for='remove agent modal to come')

        assert all([group_details.modal_title.text == Nessus.Agents.REMOVE_AGENTS,
                    group_details.modal_content.text == Nessus.Agents.REMOVE_AGENTS_WARNING,
                    group_details.is_element_present('action_button'),
                    group_details.is_element_present('cancel_button'),
                    group_details.is_element_present('close_button')]), \
            "'Remove Agents' modal is missing or something mismatched inside the modal."

        group_details.accept_action()
        group_details.wait_for_modal_closed()

        notification = Notifications()

        # Verifies success notification message after deleting agent from agent group
        assert notification.successes[-1] == Messages.NotificationMessages.Agents.AgentGroups. \
            remove_agents, 'Success Notification is missing or mismatched after removing agents from agent group.'

        sleep(WAIT_LONG, reason='Agent table takes a little bit time to get refreshed after removing agents')

    @staticmethod
    def remove_agents_and_verify_its_removed(select_all: bool) -> None:
        """
        Removes given list of agents and verifies that it's removed successfully

        :param bool select_all: Selects all agents from group if True else False
        :return: None
        """
        agent_list = AgentsList()
        agent_list.select_all_checkbox.click()

        agent_name_list_in_group = agent_list.get_all_agents_by_name()
        selected_agents_list_in_group = random.sample(agent_name_list_in_group, k=random.randint(7, 10))

        agent_list.select_all_checkbox.check() if select_all else agent_list.select_deselect_agents(
            agents_list=selected_agents_list_in_group)

        expected_agents_in_group = agent_name_list_in_group if select_all else selected_agents_list_in_group

        __class__.verify_remove_agents_modal_and_feature()

        # Verifies deleted agents are not present in group after deleting
        assert all([agent not in agent_list.get_all_agents_by_name() for agent in expected_agents_in_group]), \
            "Selected agents are still available in agent group after deleting those."

    @staticmethod
    def verify_visibility_of_elements_after_select_or_select_all_in_linked_agents(select_all: bool,
                                                                                  expected_agents: list) -> None:
        """
        Verifies the elements like buttons, links, counts, etc. visibility for agents in Linked agents after selecting
        agents from list.

        :param bool select_all: True if select all agents else False
        :param list expected_agents: list of agents need to be selected
        :return: None
        """
        agent_page = AgentsPage()

        # Verifies that agents are getting selected after clicking on checkbox on Linked Agents page
        assert AgentsList().is_agent_selected(agents_list=expected_agents), \
            "Agents are not getting selected on Linked Agents page after clicking on checkbox."

        # Verifies that 'Total' and 'Selected' agent count is visible after selecting agents from list
        assert all([agent_page.is_element_present('total_agents'),
                    agent_page.is_element_present('selected_agents')]), \
            "'Selected' agents count is visible even after deselecting all agents from list."

        # Verifies that 'Clear Selected Items' link is visible after selecting agents from list
        assert agent_page.is_element_present('clear_selected_item'), \
            "'Clear Selected Items' link is not showing up after selecting agents from list."

        is_count_same = agent_page.total_agents_count == agent_page.selected_agents_count

        # Verifies that total and selected agents count is getting same after selecting all agents from list.
        assert is_count_same if select_all else not is_count_same, \
            "Total and selected agents count is mismatch after selecting agents from list."

        # verifies that 'New Group', 'Delete' and 'Export' buttons are visible after selecting agents from list
        assert all([agent_page.is_element_present('new_group_button'), agent_page.is_element_present('delete_button'),
                    agent_page.is_element_present('export_button')]), \
            "'New Group', 'Delete' and 'Export' buttons are not visible after selecting agents from list."

    @staticmethod
    def verify_visibility_of_elements_after_select_or_select_all_in_agent_groups(select_all: bool,
                                                                                 expected_agents: list) -> None:
        """
        Verifies the elements like buttons, links, counts, etc. visibility for agents in Agent groups after selecting
        agents from list.

        :param bool select_all: True if select all agents else False
        :param list expected_agents: list of agents need to be selected
        :return: None
        """
        agent_page = AgentsPage()
        agent_list = AgentsList()

        # Verifies that selected agents are available into created group
        assert all([agent in agent_list.get_all_agents_by_name() for agent in expected_agents]), \
            "Selected agents are not available in the group after adding agents into the group."

        random_agent_count = 1 if len(expected_agents) < 5 else random.randint(3, 5)
        selected_agents_list_in_group = random.sample(expected_agents, k=random_agent_count)

        agent_list.select_all_checkbox.check() if select_all else agent_list.select_deselect_agents(
            agents_list=selected_agents_list_in_group, select=True)

        expected_agents_in_group = expected_agents if select_all else selected_agents_list_in_group

        # Verifies that agents are getting selected after clicking on checkbox on Linked Agents page
        assert agent_list.is_agent_selected(agents_list=expected_agents_in_group), \
            "Agents are not getting selected on Agent Groups page after clicking on checkbox."

        # Verifies that 'Total' and 'Selected' agent count is visible after selecting agents from list
        assert all([agent_page.is_element_present('total_agents'),
                    agent_page.is_element_present('selected_agents')]), \
            "'Selected' agents count is visible even after deselecting all agents from list."

        # Verifies that 'Clear Selected Items' link is visible after selecting agents from list
        assert agent_page.is_element_present('clear_selected_item'), \
            "'Clear Selected Items' link is not showing up after selecting agents from list."

        is_count_same = agent_page.total_agents_count == agent_page.selected_agents_count

        # Verifies that total and selected agents count is getting same after selecting all agents from list.
        assert is_count_same if select_all else not is_count_same, \
            "Total and selected agents count is mismatch after selecting agents from list."

        # Verifies that 'Remove' button is displayed after selecting agents from list
        assert GroupDetail().is_element_present('remove'), "'Remove' button is missing on Agent Groups details Page"

    @staticmethod
    def verify_visibility_of_elements_after_deselect_or_deselect_all_in_linked_agents(
            deselect_all: bool, expected_agents: list) -> None:
        """
        Verifies the elements like buttons, links, counts, etc. visibility for agents in Linked agents after deselecting
        agents from list.

        :param bool deselect_all: True if deselect all agents else False
        :param list expected_agents: list of agents need to be selected
        :return: None
        """
        agent_page = AgentsPage()

        # Verifies that agents are getting selected after clicking on checkbox on Linked Agents page
        assert not AgentsList().is_agent_selected(agents_list=expected_agents), \
            "Agents are getting selected on Linked Agents page after deselecting the checkbox."

        if deselect_all:
            # Verifies 'New Group' and 'Delete' buttons are not displayed after deselecting all agents from list
            assert all([not agent_page.is_element_present('new_group_button'),
                        not agent_page.is_element_present('delete_button'),
                        agent_page.is_element_present('export_button')]), \
                "'New Group' and 'Delete' buttons are displayed even after not selecting any single agent from list."

            # Verifies that 'Total' agent count is visible and 'Selected' agent count is not visible after
            # deselecting all agents from list
            assert all([agent_page.is_element_present('total_agents'),
                        not agent_page.is_element_present('selected_agents')]), \
                "'Selected' agents count is visible even after deselecting all agents from list."

            # Verifies that 'Clear Selected Items' link is not visible after deselecting all agents from list
            assert not agent_page.is_element_present('clear_selected_item'), \
                "'Clear Selected Items' link is showing up even after deselecting all agents from list."
        else:
            # Verifies 'New Group' and 'Delete' buttons are displayed after deselecting few agents from list
            assert all([agent_page.is_element_present('new_group_button'),
                        agent_page.is_element_present('delete_button'),
                        agent_page.is_element_present('export_button')]), \
                "'New Group' and 'Delete' button is not displayed after deselecting few agent from list."

            # Verifies that 'Total' and 'Selected' agent count is visible deselecting few agents from list
            assert all([agent_page.is_element_present('total_agents'),
                        agent_page.is_element_present('selected_agents')]), \
                "'Total' and 'Selected' agents count is not visible after deselecting few agents from list."

            # Verifies that 'Clear Selected Items' link is visible after deselecting few agents from list
            assert agent_page.is_element_present('clear_selected_item'), \
                "'Clear Selected Items' link is not showing up after deselecting few agents from list."

    @staticmethod
    def verify_visibility_of_elements_after_deselect_or_deselect_all_in_agent_groups(
            deselect_all: bool, expected_agents: list) -> None:
        """
        Verifies the elements like buttons, links, counts, etc. visibility for agents in Agent groups after deselecting
        agents from list.

        :param bool deselect_all: True if deselect all agents else False
        :param list expected_agents: list of agents need to be selected
        :return: None
        """
        agent_page = AgentsPage()
        agent_list = AgentsList()

        # Verifies that selected agents are available into created group
        assert all([agent not in agent_list.get_all_agents_by_name() for agent in expected_agents]), \
            "Deselected agents are available into the group even after deselecting the agents from list."

        agents_in_group = agent_list.get_all_agents_by_name()
        agent_list.select_all_checkbox.check()

        # Verifies that 'Total' and 'Selected' agent count is visible selecting all agents from list
        assert all([agent_page.is_element_present('total_agents'),
                    agent_page.is_element_present('selected_agents')]), \
            "'Selected' agents count is visible even after deselecting all agents from list."

        # Verifies that 'Clear Selected Items' link is visible after selecting agents from list
        assert agent_page.is_element_present('clear_selected_item'), \
            "'Clear Selected Items' link is not showing up after selecting agents from list."

        agent_group_details_page = GroupDetail()

        # Verifies that 'Remove' button is displayed after selecting agents from list
        assert agent_group_details_page.is_element_present('remove'), \
            "'Remove' button is missing after selecting all agents from list on Agent Groups details Page."

        random_agent_count = 1 if len(agents_in_group) < 5 else random.randint(3, 5)
        deselected_agents_list_in_group = random.sample(agents_in_group, k=random_agent_count)
        agent_list.select_all_checkbox.uncheck() if deselect_all else agent_list.select_deselect_agents(
            agents_list=deselected_agents_list_in_group, select=False)

        expected_agents_in_group = agents_in_group if deselect_all else deselected_agents_list_in_group

        # Verifies that agents are getting selected after clicking on checkbox on Linked Agents page
        assert not agent_list.is_agent_selected(agents_list=expected_agents_in_group), \
            "Agents are not getting selected on Agent Groups page after clicking on checkbox."

        is_selected_agent_count_visible = agent_page.is_element_present('selected_agents')

        # Verifies that 'Total' and 'Selected' agent count is visible selecting all agents from list
        assert all([agent_page.is_element_present('total_agents'),
                    is_selected_agent_count_visible if not deselect_all else not is_selected_agent_count_visible]), \
            "'Selected' agents count is visible even after deselecting all agents from list."

        is_clear_selected_item_link_visible = agent_page.is_element_present('clear_selected_item')

        # Verifies that 'Clear Selected Items' link is visible after selecting agents from list
        assert is_clear_selected_item_link_visible if not deselect_all else not is_clear_selected_item_link_visible, \
            "'Clear Selected Items' link is not showing up after selecting agents from list."

        is_remove_button_visible = agent_group_details_page.is_element_present('remove')

        assert is_remove_button_visible if not deselect_all else not is_remove_button_visible, \
            "'Remove' button is not visible after deselecting few agents from list."

    @pytest.mark.parametrize('search_agent', [True, False])
    @pytest.mark.parametrize('select_all', [True, False])
    @pytest.mark.parametrize('new_group', [True, False])
    def test_add_selected_agents_into_group_from_linked_agents(self, search_agent, select_all, new_group):
        """
        NES-11980: Automation: Add agents to group from Linked agents after Select/Un-select/Select-all/Un-select-all

        Steps:
        1. Select/Select All agents from linked agents.
        2. Added selected agents into new/existing group.
        3. Verify that all selected agents should be available into created group.
        4. Verify that group name should be displayed in the list of agents on Linked agents after adding agents into 
           the group.

        Scenario Tested:
        [x] Verify that all selected agents should be available into created group.
        [x] Verify that group name should be displayed in the list of agents on Linked agents after adding agents into
            the group.
        """
        agent_group_name = random_name(prefix='Agent_group-')
        search_value = random.sample(['Linux-', 'Windows-', 'MacOS-'], k=1)[0]

        try:
            selected_agents_list, agent_name_list = self.search_or_filter_agent_and_return_random_agent_list(
                new_group=new_group, agent_group_name=agent_group_name, search_agent=search_agent,
                search_value=search_value, random_agent_count=random.randint(15, 20))

            agent_list = AgentsList()
            agent_list.select_all_checkbox.check() if select_all else agent_list.select_deselect_agents(
                agents_list=selected_agents_list, select=True)

            expected_agents = agent_name_list if select_all else selected_agents_list
            self.verify_visibility_of_elements_after_select_or_select_all_in_linked_agents(
                select_all=select_all, expected_agents=expected_agents)

            agent_page = AgentsPage()
            agent_page.create_group(group_name=agent_group_name) if new_group else agent_page.add_agents_to_group(
                group_name=agent_group_name)
            agent_list.loaded()

            self.click_on_group_in_agent_groups(new_group=new_group, agent_group_name=agent_group_name)
            self.verify_visibility_of_elements_after_select_or_select_all_in_agent_groups(
                select_all=select_all, expected_agents=expected_agents)

            self.go_to_linked_agents_page_and_search_agent(search_agent=search_agent, search_value=search_value)

            if not select_all:
                # Verifies that group name is displayed after adding agent into the group
                assert all([agent_list.get_group_name_by_agent(agent_name=agent) == agent_group_name for agent in
                            expected_agents]), \
                    "Group name is not getting displayed even after adding agent into the group."
        finally:
            self.delete_agent_group_and_verify(group_name=agent_group_name)

    @pytest.mark.parametrize('search_agent', [True, False])
    @pytest.mark.parametrize('deselect_all', [True, False])
    @pytest.mark.parametrize('new_group', [True, False])
    def test_add_agents_into_group_after_deselect_from_linked_agents(self, search_agent, deselect_all, new_group):
        """
        NES-11980: Automation: Add agents to group from Linked agents after Select/Un-select/Select-all/Un-select-all

        Steps:
        1. Deselect/Deselect All agents from linked agents.
        2. Added selected agents into new/existing group.
        3. Verify that all deselected agents should not be available into created group.
        4. Verify that group name should not be displayed in the list of agents on Linked agents.

        Scenario Tested:
        [x] Verify that all deselected agents should not be available into created group.
        [x] Verify that group name should not be displayed in the list of agents on Linked agents.
        """
        agent_group_name = random_name(prefix='Agent_group-')
        search_value = random.sample(['Linux-', 'Windows-', 'MacOS-'], k=1)[0]

        try:
            deselected_agents_list, agent_name_list = self.search_or_filter_agent_and_return_random_agent_list(
                new_group=new_group, agent_group_name=agent_group_name, search_agent=search_agent,
                search_value=search_value, check=True, random_agent_count=random.randint(15, 20))

            agent_list = AgentsList()
            agent_list.select_all_checkbox.uncheck() if deselect_all else agent_list.select_deselect_agents(
                agents_list=deselected_agents_list, select=False)
            expected_agents = agent_name_list if deselect_all else deselected_agents_list

            self.verify_visibility_of_elements_after_deselect_or_deselect_all_in_linked_agents(
                deselect_all=deselect_all, expected_agents=expected_agents)

            if not deselect_all:
                agent_page = AgentsPage()
                agent_page.create_group(group_name=agent_group_name) if new_group else agent_page.add_agents_to_group(
                    group_name=agent_group_name)
                agent_list.loaded()

                self.click_on_group_in_agent_groups(new_group=new_group, agent_group_name=agent_group_name)
                self.verify_visibility_of_elements_after_deselect_or_deselect_all_in_agent_groups(
                    deselect_all=deselect_all, expected_agents=expected_agents)

                self.go_to_linked_agents_page_and_search_agent(search_agent=search_agent, search_value=search_value)

                # Verifies that group name is displayed after adding agent into the group
                assert all([agent_list.get_group_name_by_agent(agent_name=agent) == 'N/A' for agent in
                            expected_agents]), "Group name is displayed even after not adding agents into the group."
        finally:
            self.delete_agent_group_and_verify(group_name=agent_group_name)

    @pytest.mark.parametrize("linked_agent_filters", [
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ALL, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'Linux'}]},
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'Windows'},
                          {'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.STATUS,
                           'filter_operator': Nessus.Agents.Filter.IS_EQUAL_TO, 'filter_value': 'Offline'},
                          {'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.PLATFORM,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'Windows'}]},
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ALL, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'MacOS'},
                          {'match_type': Nessus.Filter.FilterMatch.ALL, 'filter_key': Nessus.Agents.Filter.PLATFORM,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'MacOS'}]},
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'MacOS'}]}])
    @pytest.mark.parametrize('select_all', [True, False])
    @pytest.mark.parametrize('new_group', [True, False])
    def test_add_selected_agents_into_group_after_applying_filter_from_linked_agents(self, linked_agent_filters,
                                                                                     select_all, new_group):
        """
        NES-11980: Automation: Add agents to group from Linked agents after Select/Un-select/Select-all/Un-select-all

        Steps:
        1. Select/Select All agents from linked agents.
        2. Added selected agents into new/existing group.
        3. Verify that all selected agents should be available into created group.
        4. Verify that group name should be displayed in the list of agents on Linked agents after adding agents into 
           the group.

        Scenario Tested:
        [x] Verify that all selected agents should be available into created group.
        [x] Verify that group name should be displayed in the list of agents on Linked agents after adding agents into
            the group.
        """
        agent_group_name = random_name(prefix='Agent_group-')

        try:
            selected_agents_list, agent_name_list = self.search_or_filter_agent_and_return_random_agent_list(
                new_group=new_group, agent_group_name=agent_group_name, add_filter=True,
                filters=linked_agent_filters['agent_filter'], random_agent_count=random.randint(15, 20))

            agent_list = AgentsList()
            agent_list.select_all_checkbox.check() if select_all else agent_list.select_deselect_agents(
                agents_list=selected_agents_list, select=True)

            agent_page = AgentsPage()
            selected_agents_count = agent_page.selected_agents_count if select_all else len(selected_agents_list)

            expected_agents = agent_name_list if select_all else selected_agents_list
            self.verify_visibility_of_elements_after_select_or_select_all_in_linked_agents(
                select_all=select_all, expected_agents=expected_agents)

            agent_page.create_group(group_name=agent_group_name) if new_group else agent_page.add_agents_to_group(
                group_name=agent_group_name)
            agent_list.loaded()

            self.click_on_group_in_agent_groups(new_group=new_group, agent_group_name=agent_group_name)
            self.verify_visibility_of_elements_after_select_or_select_all_in_agent_groups(
                select_all=select_all, expected_agents=expected_agents)

            self.go_to_linked_agents_group_page()

            agent_group_filter = [{'match_type': Nessus.Filter.FilterMatch.ALL,
                                   'filter_key': Nessus.Agents.Filter.MEMBER_OF_GROUP,
                                   'filter_operator': Nessus.Agents.Filter.IS_EQUAL_TO,
                                   'filter_value': agent_group_name}]

            self.add_and_apply_linked_agent_filters(filters=agent_group_filter)
            agent_list.loaded()

            # Verifies that selected agents are moved successfully into created agent group
            assert agent_page.total_agents_count == selected_agents_count, \
                "Selected agents are not getting moved properly in created agent group."
        finally:
            self.delete_agent_group_and_verify(group_name=agent_group_name)

    @pytest.mark.parametrize("linked_agent_filters", [
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ALL, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'Linux'}]},
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'Windows'},
                          {'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.STATUS,
                           'filter_operator': Nessus.Agents.Filter.IS_EQUAL_TO, 'filter_value': 'Offline'},
                          {'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.PLATFORM,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'Windows'}]},
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ALL, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'MacOS'},
                          {'match_type': Nessus.Filter.FilterMatch.ALL, 'filter_key': Nessus.Agents.Filter.PLATFORM,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'MacOS'}]},
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'MacOS'}]}])
    @pytest.mark.parametrize('deselect_all', [True, False])
    @pytest.mark.parametrize('new_group', [True, False])
    def test_add_agents_into_group_after_applying_filter_and_deselect_from_linked_agents(self, linked_agent_filters,
                                                                                         deselect_all, new_group):
        """
        NES-11980: Automation: Add agents to group from Linked agents after Select/Un-select/Select-all/Un-select-all

        Steps:
        1. Deselect/Deselect All agents from linked agents.
        2. Added selected agents into new/existing group.
        3. Verify that all deselected agents should not be available into created group.
        4. Verify that group name should not be displayed in the list of agents on Linked agents.

        Scenario Tested:
        [x] Verify that all deselected agents should not be available into created group.
        [x] Verify that group name should not be displayed in the list of agents on Linked agents.
        """
        agent_group_name = random_name(prefix='Agent_group-')

        try:
            agent_page = AgentsPage()
            agent_page.open()
            wait(lambda: agent_page.is_element_present('total_agents'), waiting_for='agents page to get load')
            total_linked_agent_count = agent_page.total_agents_count

            deselected_agents_list, agent_name_list = self.search_or_filter_agent_and_return_random_agent_list(
                new_group=new_group, agent_group_name=agent_group_name, add_filter=True, check=True,
                filters=linked_agent_filters['agent_filter'], random_agent_count=random.randint(15, 20))

            agent_list = AgentsList()
            agent_list.select_all_checkbox.uncheck() if deselect_all else agent_list.select_deselect_agents(
                agents_list=deselected_agents_list, select=False)
            expected_agents = agent_name_list if deselect_all else deselected_agents_list

            self.verify_visibility_of_elements_after_deselect_or_deselect_all_in_linked_agents(
                deselect_all=deselect_all, expected_agents=expected_agents)

            if not deselect_all:
                agent_page = AgentsPage()
                selected_agent_count = agent_page.selected_agents_count

                agent_page.create_group(group_name=agent_group_name) if new_group else agent_page.add_agents_to_group(
                    group_name=agent_group_name)
                agent_list.loaded()

                self.click_on_group_in_agent_groups(new_group=new_group, agent_group_name=agent_group_name)
                self.verify_visibility_of_elements_after_deselect_or_deselect_all_in_agent_groups(
                    deselect_all=deselect_all, expected_agents=expected_agents)

                self.go_to_linked_agents_group_page()

                agent_group_filter = [{'match_type': Nessus.Filter.FilterMatch.ALL,
                                       'filter_key': Nessus.Agents.Filter.MEMBER_OF_GROUP,
                                       'filter_operator': Nessus.Agents.Filter.IS_NOT_EQUAL_TO,
                                       'filter_value': agent_group_name}]

                self.add_and_apply_linked_agent_filters(filters=agent_group_filter)
                agent_list.loaded()

                # Verifies that selected agents are moved successfully into created agent group
                assert agent_page.total_agents_count == (total_linked_agent_count - selected_agent_count), \
                    "Selected agents are not getting moved properly in created agent group."
        finally:
            self.delete_agent_group_and_verify(group_name=agent_group_name)

    @pytest.mark.parametrize("cluster_agent_filter", [
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ALL, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'Linux'}],
         'search_agent': False},
        {'agent_filter': {}, 'search_agent': True},
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'Windows'},
                          {'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.STATUS,
                           'filter_operator': Nessus.Agents.Filter.IS_EQUAL_TO, 'filter_value': 'Offline'},
                          {'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.PLATFORM,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'Windows'}],
         'search_agent': False},
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ALL, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'MacOS'},
                          {'match_type': Nessus.Filter.FilterMatch.ALL, 'filter_key': Nessus.Agents.Filter.PLATFORM,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'MacOS'}],
         'search_agent': False},
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'Linux'}],
         'search_agent': False}])
    @pytest.mark.parametrize('select_all', [False, True])
    @pytest.mark.parametrize('new_group', [True, False])
    def test_remove_selected_agents_from_agents_group(self, cluster_agent_filter, select_all, new_group):
        """
        NES-11980: Automation: Add agents to group from Linked agents after Select/Un-select/Select-all/Un-select-all

        Steps:
        1. Create agent group.
        2. Select/Select-all agents from linked agents.
        3. Remove selected agents from linked agents.
        4. Verify that all selected agents should not be available into group after removing.

        Scenario Tested:
        [x] Verify that all selected agents should not be available into group after removing.
        """
        agent_group_name = random_name(prefix='Agent_group-')
        search_value = random.sample(['Linux-', 'Windows-', 'MacOS-'], k=1)[0]

        try:
            agent_page = AgentsPage()
            agent_page.open()

            self.create_new_agent_group(new_group=new_group, agent_group_name=agent_group_name)

            # Applying search or filter to cluster agents in the "Default cluster group"
            if cluster_agent_filter['agent_filter'] and not cluster_agent_filter['search_agent']:
                self.add_and_apply_linked_agent_filters(cluster_agent_filter['agent_filter'])
            else:
                self.search_agent_name_and_verify(is_search_agent=cluster_agent_filter['search_agent'],
                                                  search_value=search_value)

            agent_list = AgentsList()
            agent_list.loaded()
            agent_name_list = agent_list.get_all_agents_by_name()
            selected_agents_list = random.sample(agent_name_list, k=random.randint(15, 20))

            agent_list.select_all_checkbox.check() if select_all else agent_list.select_deselect_agents(
                agents_list=selected_agents_list)

            expected_agents = agent_name_list[:45] if select_all else selected_agents_list

            self.verify_visibility_of_elements_after_select_or_select_all_in_linked_agents(
                select_all=select_all, expected_agents=expected_agents)

            if select_all:
                agent_list.select_all_checkbox.uncheck()
                agent_list.select_deselect_agents(agents_list=expected_agents)

            agent_page.create_group(group_name=agent_group_name) if new_group else agent_page.add_agents_to_group(
                group_name=agent_group_name)
            agent_list.loaded()

            self.click_on_group_in_agent_groups(new_group=new_group, agent_group_name=agent_group_name)
            self.verify_visibility_of_elements_after_select_or_select_all_in_agent_groups(
                select_all=select_all, expected_agents=expected_agents)

            self.remove_agents_and_verify_its_removed(select_all=select_all)

            if select_all:
                assert all([agent_page.is_element_present('empty_agent_list'),
                            Nessus.Agents.EMPTY_AGENT_LIST_MESSAGE in agent_page.empty_agent_list.text]), \
                    "Agents are not getting deleted successfully."
        finally:
            self.delete_agent_group_and_verify(group_name=agent_group_name)

    @pytest.mark.parametrize("cluster_agent_filter", [
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ALL, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'Linux'}],
         'search_agent': False},
        {'agent_filter': {}, 'search_agent': True},
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'Windows'},
                          {'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.STATUS,
                           'filter_operator': Nessus.Agents.Filter.IS_EQUAL_TO, 'filter_value': 'Offline'},
                          {'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.PLATFORM,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'Windows'}],
         'search_agent': False},
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ALL, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'MacOS'},
                          {'match_type': Nessus.Filter.FilterMatch.ALL, 'filter_key': Nessus.Agents.Filter.PLATFORM,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'MacOS'}],
         'search_agent': False},
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'Linux'}],
         'search_agent': False}])
    @pytest.mark.parametrize('new_group', [True, False])
    def test_add_selected_agents_from_each_page_into_group_by_pagination_from_linked_agents(self, cluster_agent_filter,
                                                                                            new_group):
        """
        NES-12096: Automation: Add/Move selected agents into group from different pages by pagination

        Steps:
        1. Create agent group.
        2. Select agents from each page by using pagination from linked agents.
        3. Add selected agents from each page from linked agents.
        4. Verify that all selected agents from each page should be available into group after adding.

        Scenario Tested:
        [x] Verify that all selected agents from each page should be available into group after adding.
        """
        agent_group_name = random_name(prefix='Agent_group-')
        search_value = random.sample(['Linux-', 'Windows-', 'MacOS-'], k=1)[0]

        try:
            agent_page = AgentsPage()
            agent_page.open()

            self.create_new_agent_group(new_group=new_group, agent_group_name=agent_group_name)

            # Applying search or filter to cluster agents in the "Default cluster group"
            if cluster_agent_filter['agent_filter'] and not cluster_agent_filter['search_agent']:
                self.add_and_apply_linked_agent_filters(cluster_agent_filter['agent_filter'])
            else:
                self.search_agent_name_and_verify(is_search_agent=cluster_agent_filter['search_agent'],
                                                  search_value=search_value)

            agent_list = AgentsList()
            agent_list.loaded()

            list_of_selected_agent_from_each_page = get_and_verify_total_selected_agents_and_its_count_from_page()
            list_of_selected_agent_from_each_page.sort()

            agent_page.create_group(group_name=agent_group_name) if new_group else agent_page.add_agents_to_group(
                group_name=agent_group_name)
            agent_list.loaded()

            self.click_on_group_in_agent_groups(new_group=new_group, agent_group_name=agent_group_name)

            total_selected_agents_from_page = len(list_of_selected_agent_from_each_page)
            expected_agents = list_of_selected_agent_from_each_page[:45] if total_selected_agents_from_page > 50 else \
                list_of_selected_agent_from_each_page

            self.verify_visibility_of_elements_after_select_or_select_all_in_agent_groups(
                select_all=False, expected_agents=expected_agents)

            # Verifies that total agents count from group is getting same with the total agents selected from each page
            assert agent_page.total_agents_count == total_selected_agents_from_page, \
                "Agents selected from each page are not available in group."
        finally:
            self.delete_agent_group_and_verify(group_name=agent_group_name)

    @pytest.mark.parametrize("cluster_agent_filter", [
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ALL, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'Linux'}],
         'search_agent': False},
        {'agent_filter': {}, 'search_agent': True},
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'Windows'},
                          {'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.STATUS,
                           'filter_operator': Nessus.Agents.Filter.IS_EQUAL_TO, 'filter_value': 'Offline'},
                          {'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.PLATFORM,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'Windows'}],
         'search_agent': False},
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ALL, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'MacOS'},
                          {'match_type': Nessus.Filter.FilterMatch.ALL, 'filter_key': Nessus.Agents.Filter.PLATFORM,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'MacOS'}],
         'search_agent': False},
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'Linux'}],
         'search_agent': False}])
    @pytest.mark.parametrize('new_group', [True, False])
    def test_remove_selected_agents_from_each_page_into_group_by_pagination(self, cluster_agent_filter, new_group):
        """
        NES-12096: Automation: Add/Move selected agents into group from different pages by pagination

        Steps:
        1. Create agent group.
        2. Select agents from each page by pagination from created agent group.
        3. Remove selected agents.
        4. Verify that all selected agents should not be available into group after removing.

        Scenario Tested:
        [x] Verify that all selected agents should not be available into group after removing.
        """
        agent_group_name = random_name(prefix='Agent_group-')
        search_value = random.sample(['Linux-', 'Windows-', 'MacOS-'], k=1)[0]

        try:
            agent_page = AgentsPage()
            agent_page.open()

            self.create_new_agent_group(new_group=new_group, agent_group_name=agent_group_name)

            # Applying search or filter to cluster agents in the "Default cluster group"
            if cluster_agent_filter['agent_filter'] and not cluster_agent_filter['search_agent']:
                self.add_and_apply_linked_agent_filters(cluster_agent_filter['agent_filter'])
            else:
                self.search_agent_name_and_verify(is_search_agent=cluster_agent_filter['search_agent'],
                                                  search_value=search_value)

            agent_list = AgentsList()
            agent_list.loaded()

            total_agents_count_after_filter_or_search = agent_page.total_agents_count
            agent_list.select_all_checkbox.check()

            agent_page.create_group(group_name=agent_group_name) if new_group else agent_page.add_agents_to_group(
                group_name=agent_group_name)
            agent_list.loaded()

            self.click_on_group_in_agent_groups(new_group=new_group, agent_group_name=agent_group_name)

            list_of_selected_agent_from_each_page = get_and_verify_total_selected_agents_and_its_count_from_page()
            list_of_selected_agent_from_each_page.sort()

            self.verify_remove_agents_modal_and_feature()
            AgentsList().loaded()

            # Verifies that total agents count from group is getting same with the total agents selected from each page
            assert agent_page.total_agents_count == (total_agents_count_after_filter_or_search - len(
                list_of_selected_agent_from_each_page)), "Agents selected from each page are not available in group."
        finally:
            self.delete_agent_group_and_verify(group_name=agent_group_name)


@pytest.mark.cluster_manager
@pytest.mark.parametrize('create_manager_cluster', [{'total_nodes': 1, 'total_agents': 0}], indirect=True)
@pytest.mark.parametrize('add_fake_cluster_agents', [{'total_no_of_agents': 1000}], indirect=True)
@pytest.mark.usefixtures('create_manager_cluster', 'add_fake_cluster_agents', 'login')
class TestBulkAgentUnlink:
    """ Test cases to cover bulk agents unlink with select/select-all from linked agents """

    @staticmethod
    def edit_track_unlink_agents_setting():
        """ Check track_unlinked_agents checkbox from agent setting tab """

        agent_page = AgentsPage()
        agent_page.agent_settings_tab_link.click()

        agent_setting_tab = AgentSettingsTab()
        wait(lambda: agent_setting_tab.is_element_present('track_unlinked_agents_checkbox'),
             waiting_for='Agent settings tab page to load properly')

        if not agent_setting_tab.track_unlinked_agents_checkbox.is_selected():
            agent_setting_tab.track_unlinked_agents_checkbox.check()
            agent_setting_tab.save_button.click()

            notification = Notifications()

            assert notification.successes[-1] == Messages.NotificationMessages.Agents.AgentSettings. \
                edit_agent_setting, 'Success notification is missing or mismatch after changing the agent settings.'

        agent_page.linked_agents_tab_link.click()

    @staticmethod
    def clear_and_apply_filter_for_unlinked_agents():
        """ Clear existing filter and apply filter for 'Unlinked' agents """
        unlink_agent_filter = [{'match_type': Nessus.Filter.FilterMatch.ALL, 'filter_key': Nessus.Agents.Filter.STATUS,
                                'filter_operator': Nessus.Agents.Filter.IS_EQUAL_TO, 'filter_value': 'Unlinked'}]

        TestSelectDeselectInAgentGroups().add_and_apply_linked_agent_filters(filters=unlink_agent_filter,
                                                                             clear_filter=True)

        sleep(WAIT_LONG, reason='Agent table takes a little bit time to get refreshed after applying filter')
        AgentsList().loaded()

    @staticmethod
    def delete_unlink_agents():
        """ Delete unlinked agents from linked agents list """
        __class__.clear_and_apply_filter_for_unlinked_agents()

        AgentsList().select_all_checkbox.check()

        agent_page = AgentsPage()
        wait(lambda: agent_page.is_element_present('delete_button'), waiting_for='Delete button to be visible')

        agent_page.delete_button.click()
        delete_agent_modal = ActionCloseModal()
        delete_agent_modal.accept_action()
        delete_agent_modal.wait_for_modal_closed()

    @staticmethod
    def verify_unlink_agent_modal_and_feature(select_all: bool, agents_list: list) -> None:
        """
        Verifies "Unlinked Agents" modal and it's functionality

        :param bool select_all: Selects all agents if True else False
        :param list agents_list: list of agents to be unlinked
        :return: None
        """
        if select_all:
            agent_list = AgentsList()
            agent_list.select_all_checkbox.click()
            agent_list.select_deselect_agents(agents_list=agents_list)

        agent_page = AgentsPage()
        agent_page.js_scroll_into_view(element=agent_page.unlink_button)
        agent_page.unlink_button.click()

        unlink_agent_modal = ActionCloseModal()
        wait(lambda: unlink_agent_modal.is_element_present('modal'), waiting_for='unlink agent modal to come')

        assert all([unlink_agent_modal.modal_title.text == Nessus.Agents.UNLINK_AGENTS,
                    unlink_agent_modal.modal_content.text == Nessus.Agents.UNLINK_AGENTS_WARNING,
                    unlink_agent_modal.is_element_present('action_button'),
                    unlink_agent_modal.is_element_present('cancel_button'),
                    unlink_agent_modal.is_element_present('close_button')]), \
            "'Unlink Agents' modal is missing or something mismatched inside the modal."

        unlink_agent_modal.accept_action()
        unlink_agent_modal.wait_for_modal_closed()

        notification = Notifications()

        assert notification.successes[-1] == Messages.NotificationMessages.Agents.unlink_agents, \
            'Success notification is missing or mismatch after unlinking the agent from list.'

    @pytest.mark.parametrize("cluster_agent_filter", [
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ALL, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'Linux'}],
         'search_agent': False},
        {'agent_filter': {}, 'search_agent': True},
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'Windows'},
                          {'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.STATUS,
                           'filter_operator': Nessus.Agents.Filter.IS_EQUAL_TO, 'filter_value': 'Offline'},
                          {'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.PLATFORM,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'Windows'}],
         'search_agent': False},
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ALL, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'MacOS'},
                          {'match_type': Nessus.Filter.FilterMatch.ALL, 'filter_key': Nessus.Agents.Filter.PLATFORM,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'MacOS'}],
         'search_agent': False},
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'Linux'}],
         'search_agent': False}])
    @pytest.mark.parametrize('select_all', [False, True])
    def test_unlink_selected_agents_from_linked_agents(self, cluster_agent_filter, select_all):
        """
        NES-11980: Automation: Add agents to group from Linked agents after Select/Un-select/Select-all/Un-select-all

        Steps:
        1. Select/Select-all agents from linked agents.
        2. Unlink selected agents from linked agents.
        3. Verify that all selected agents should be unlinked.
        4. Verify that 'Unlinked' status should be displayed in the list of agents on Linked agents after unlinking.

        Scenario Tested:
        [x] Verify that all selected agents should be unlinked.
        [x] Verify that 'Unlinked' status should be displayed in the list of agents on Linked agents after unlinking.
        """
        search_value = random.sample(['Linux-', 'Windows-', 'MacOS-'], k=1)[0]

        try:
            agent_page = AgentsPage()
            agent_page.open()

            self.edit_track_unlink_agents_setting()

            agent_list = AgentsList()
            agent_list.loaded()
            select_deselect_agent_group = TestSelectDeselectInAgentGroups()

            # Applying search or filter to cluster agents in the "Default cluster group"
            if cluster_agent_filter['agent_filter'] and not cluster_agent_filter['search_agent']:
                select_deselect_agent_group.add_and_apply_linked_agent_filters(cluster_agent_filter['agent_filter'])
            else:
                select_deselect_agent_group.search_agent_name_and_verify(
                    is_search_agent=cluster_agent_filter['search_agent'], search_value=search_value)

            agent_list.loaded()
            agent_name_list = agent_list.get_all_agents_by_name()
            selected_agents_list = random.sample(agent_name_list, k=random.randint(5, 8))

            agent_list.select_all_checkbox.check() if select_all else agent_list.select_deselect_agents(
                agents_list=selected_agents_list)

            expected_agents = agent_name_list[:45] if select_all else selected_agents_list

            select_deselect_agent_group.verify_visibility_of_elements_after_select_or_select_all_in_linked_agents(
                select_all=select_all, expected_agents=expected_agents)

            assert agent_page.is_element_present('unlink_button'), \
                "'Unlink' button is not visible after selecting agents from list."

            self.verify_unlink_agent_modal_and_feature(select_all=select_all, agents_list=expected_agents)
            sleep(WAIT_LONG, reason='Agent table takes a little bit time to update the agent status after unlinking')

            if cluster_agent_filter['search_agent']:
                agent_page.remove_search_icon.click()
                agent_list.loaded()

            self.clear_and_apply_filter_for_unlinked_agents()
            sleep(WAIT_LONG, reason='Filter results take little bit time to get display')
            agent_list.loaded()

            # Verifies that the total unlinked agents count and the count of selected agents for unlink are same
            assert agent_page.total_agents_count == len(expected_agents), \
                "Selected agents are not getting unlinked successfully after unlinking it."

            if not select_all:
                # Verifies that agent status is displayed as 'Unlinked' after unlinking the agent from list
                assert all([agent_list.get_agent_status_by_agent(agent_name=agent) ==
                            Nessus.Agents.AgentStatus.UNLINKED for agent in expected_agents]), \
                    "Agent status is not displayed as 'Unlinked' after unlinking it."
        finally:
            self.delete_unlink_agents()


@pytest.mark.cluster_manager
@pytest.mark.parametrize('create_manager_cluster', [{'total_nodes': 1, 'total_agents': 0}], indirect=True)
@pytest.mark.parametrize('add_fake_cluster_agents', [{'total_no_of_agents': 2000}], indirect=True)
@pytest.mark.usefixtures('create_manager_cluster', 'add_fake_cluster_agents', 'login')
class TestBulkAgentDelete:
    """ Test cases to cover bulk delete agents with select/select-all from linked agents """

    @staticmethod
    def delete_agents_and_verify_its_deleted(select_all: bool, expected_agents: list) -> None:
        """
        Deletes given list of agents and verifies that it's deleted successfully

        :param bool select_all: Selects all agents if True else False
        :param list expected_agents: list of agents to be deleted
        :return: None
        """
        if select_all:
            agent_list = AgentsList()
            agent_list.select_all_checkbox.click()
            agent_list.select_deselect_agents(agents_list=expected_agents)

        agent_page = AgentsPage()
        agent_page.js_scroll_into_view(element=agent_page.delete_button)
        agent_page.delete_button.click()

        delete_agents_modal = ActionCloseModal()
        wait(lambda: delete_agents_modal.is_element_present('modal'), waiting_for='unlink agent modal to come')

        assert all([delete_agents_modal.modal_title.text == Nessus.Agents.DELETE_AGENTS,
                    delete_agents_modal.modal_content.text == Nessus.Agents.DELETE_AGENTS_WARNING,
                    delete_agents_modal.is_element_present('action_button'),
                    delete_agents_modal.is_element_present('cancel_button'),
                    delete_agents_modal.is_element_present('close_button')]), \
            "'Delete Agents' modal is missing or something mismatched inside the modal."

        delete_agents_modal.accept_action()
        delete_agents_modal.wait_for_modal_closed()

        notification = Notifications()

        assert notification.successes[-1] == Messages.NotificationMessages.Agents.delete_agents, \
            'Success notification is missing or mismatch after deleting the agents from list.'

        agent_list = AgentsList()
        agent_page.refresh()
        agent_page.loaded()

        # Verifies deleted agents are not present after deleting
        assert all([agent not in agent_list.get_all_agents_by_name() for agent in expected_agents]), \
            "Selected agents are still available in agent group after deleting those."

    @pytest.mark.xray(test_key='NES-13773')
    @pytest.mark.parametrize("cluster_agent_filter", [
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ALL, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'Linux'}],
         'search_agent': False},
        {'agent_filter': {}, 'search_agent': True},
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'Windows'},
                          {'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.STATUS,
                           'filter_operator': Nessus.Agents.Filter.IS_EQUAL_TO, 'filter_value': 'Offline'},
                          {'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.PLATFORM,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'Windows'}],
         'search_agent': False},
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ALL, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'MacOS'},
                          {'match_type': Nessus.Filter.FilterMatch.ALL, 'filter_key': Nessus.Agents.Filter.PLATFORM,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'MacOS'}],
         'search_agent': False},
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'Linux'}],
         'search_agent': False}])
    @pytest.mark.parametrize('select_all', [False, True])
    def test_delete_selected_agents_from_linked_agents(self, cluster_agent_filter, select_all):
        """
        NES-11980: Automation: Add agents to group from Linked agents after Select/Un-select/Select-all/Un-select-all
        NES-13773 : Verify Agent Groups

        Steps:
        1. Create agent group.
        2. Select/Select-all agents from linked agents.
        3. Delete selected agents from linked agents.
        4. Verify that all selected agents should not be available after deleting agents.

        Scenario Tested:
        [x] Verify that all selected agents should not be available after deleting agents.
        """
        search_value = random.sample(['Linux-', 'Windows-', 'MacOS-'], k=1)[0]
        select_deselect_agent_group = TestSelectDeselectInAgentGroups()

        AgentsPage().open()

        # Applying search or filter to cluster agents in the "Default cluster group"
        if cluster_agent_filter['agent_filter'] and not cluster_agent_filter['search_agent']:
            select_deselect_agent_group.add_and_apply_linked_agent_filters(cluster_agent_filter['agent_filter'])
        else:
            select_deselect_agent_group.search_agent_name_and_verify(
                is_search_agent=cluster_agent_filter['search_agent'], search_value=search_value)

        agent_list = AgentsList()
        agent_list.loaded()

        agent_name_list = agent_list.get_all_agents_by_name()
        selected_agents_list = random.sample(agent_name_list, k=random.randint(5, 8))

        agent_list.select_all_checkbox.check() if select_all else agent_list.select_deselect_agents(
            agents_list=selected_agents_list)

        expected_agents = agent_name_list if select_all else selected_agents_list

        select_deselect_agent_group.verify_visibility_of_elements_after_select_or_select_all_in_linked_agents(
            select_all=select_all, expected_agents=expected_agents)

        self.delete_agents_and_verify_its_deleted(select_all=select_all, expected_agents=expected_agents)
