"""
Cluster group operations related tests

:copyright: Tenable Network Security, 2020
:date: Sep 16, 2020
:last_modified: May 09, 2023
:author: @vsoni, @kpanchal, @krpatel.ctr
"""

import pytest
import random
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.expected_conditions import visibility_of_element_located
from waiting.exceptions import TimeoutExpired

from catium.lib.const import TIME_THIRTY_SECONDS
from catium.lib.const.base_constants import TIME_FIVE_SECONDS, TIME_SIXTY_SECONDS
from catium.lib.log import create_logger
from catium.lib.webium.wait import wait
from nessus.apiobjects.endpoints.scanners import random_alphanumeric_string_for_linking_key
from nessus.helpers.agent_cluster.agent_cluster import add_node_to_cluster_group, move_node_to_default_cluster_group, \
    move_agent_to_default_cluster_group, move_agents_to_other_cluster_group, navigate_to_cluster_group
from nessus.lib.const import Nessus
from nessus.pageobjects.agents.agents_filter_page import FilterWindow
from nessus.pageobjects.agents.agents_page import AgentsPage, AgentsList
from nessus.pageobjects.cluster.cluster_agent_page import ClusterAgentList
from nessus.pageobjects.cluster.cluster_group_page import ClusterGroupPage, ClusterGroupList, \
    ClusterGroupDetails, ClusterGroupAgentPage, ClusterGroupAgentList
from nessus.pageobjects.cluster.cluster_nodes_page import ClusterNodeList
from nessus.pageobjects.header.header_base import HeaderBasePage

log = create_logger()


def verify_visibility_of_elements_after_select_or_select_all_in_cluster_add_agents(select_all: bool) -> None:
    """
    Verifies the elements like buttons, links, counts, etc. visibility for agents after selecting agents from list.

    :param bool select_all: True if select all agents else False
    :return: None
    """
    agent_page = AgentsPage()

    # Verifies that 'Total' and 'Selected' agent count is visible after selecting agents from list
    assert all([agent_page.is_element_present('total_agents'),
                agent_page.is_element_present('selected_agents')]), \
        "'Selected' agents count is not visible after deselecting few agents from list."

    # Verifies that 'Clear Selected Items' link is visible after selecting agents from list
    assert agent_page.is_element_present('clear_selected_item'), \
        "'Clear Selected Items' link is not showing up after selecting agents from list."

    is_count_same = agent_page.total_agents_count == agent_page.selected_agents_count

    # Verifies that total and selected agents count is getting same after selecting all agents from list.
    assert is_count_same if select_all else not is_count_same, \
        "Total and selected agents count is mismatch after selecting agents from list."


def get_and_verify_total_selected_agents_and_its_count_from_page(add_agents: bool = False) -> list:
    """
    Returns total selected agents from each page and it's count as well by pagination

    :return: list of total selected agents and it's count
    :rtype: list
    """
    is_next_page_icon_enabled = True
    total_selected_agents = []

    cluster_group_agent_list = ClusterGroupAgentList()
    agents_page = AgentsPage()

    while is_next_page_icon_enabled:
        all_cluster_agent_name = cluster_group_agent_list.get_cluster_agent_name_from_modal() if add_agents else \
            ClusterAgentList().get_all_cluster_agent_names()

        random_agent_count = 1 if len(all_cluster_agent_name) <= 10 else random.randint(1, 10)
        expected_agents_to_select = random.sample(all_cluster_agent_name, k=random_agent_count)
        total_selected_agents += expected_agents_to_select

        cluster_group_agent_list.select_cluster_add_agents(agents_list=expected_agents_to_select) if add_agents \
            else AgentsList().select_deselect_agents(agents_list=expected_agents_to_select)

        is_agents_selected = cluster_group_agent_list.is_cluster_agent_selected(
            agents_list=expected_agents_to_select) if add_agents else AgentsList().is_agent_selected(
            agents_list=expected_agents_to_select)

        # Verifies that agents are getting selected after clicking on checkbox on add agents modal
        assert is_agents_selected, "Agents are not getting selected on Cluster group Agents page after clicking " \
                                   "on checkbox."

        verify_visibility_of_elements_after_select_or_select_all_in_cluster_add_agents(select_all=False)

        if 'disabled' not in agents_page.next_page_icon.get_css_classes():
            agents_page.next_page_icon.click()
            cluster_group_agent_list.loaded() if add_agents else AgentsList().loaded()
        else:
            is_next_page_icon_enabled = False

    return total_selected_agents


@pytest.mark.parametrize('create_manager_cluster', [{'total_nodes': 2, 'total_agents': 0}], indirect=True)
@pytest.mark.parametrize('add_fake_cluster_agents', [{'total_no_of_agents': 500}], indirect=True)
@pytest.mark.usefixtures('create_manager_cluster', 'add_fake_cluster_agents', 'login', 'create_cluster_group')
@pytest.mark.cluster_manager
class TestClusterGroupAgentsFilter:
    """Tests related to move agents using filters/select-all options"""

    @staticmethod
    def add_and_apply_linked_agent_filters(filters: list) -> None:
        """
        Add and apply filter for given param

        :param list filters: list of param for filter
        :return: None
        """
        filter_window = FilterWindow()

        for agent_filter in filters:
            filter_window.add_and_apply_filter(**agent_filter)

        wait(lambda: AgentsPage().is_element_present('search_agent_input'), timeout_seconds=TIME_SIXTY_SECONDS)

    @staticmethod
    def move_node_back_to_default_cluster_group(node_name: str) -> None:
        """
        Moves the node back to default cluster group

        :param str node_name: name node to be moved back to default cluster group
        :return: None
        """
        cluster_group_agent_page = ClusterGroupAgentPage()
        cluster_group_agent_page.nodes_tab.click()
        ClusterNodeList().loaded()

        move_node_to_default_cluster_group(node_name=node_name)
        cluster_group_agent_page.wait_for_modal_closed()

        cluster_group_details = ClusterGroupDetails()
        wait(lambda: cluster_group_details.is_element_present('back_to_cluster_group_link'))

        cluster_group_details.back_to_cluster_group_link.click()
        ClusterGroupList().loaded()

    @staticmethod
    def move_node_and_agents_back_to_default_cluster_group(expected_agents: list, node_name: str) -> None:
        """
        Moves the node and agents back to default cluster group

        :param list expected_agents: list of agents to be moved back to default cluster group
        :param str node_name: name node to be moved back to default cluster group
        :return: None
        """
        cluster_group_agent_page = ClusterGroupAgentPage()

        if cluster_group_agent_page.is_element_present('modal'):
            cluster_group_agent_page.cancel_button.click()

        if not cluster_group_agent_page.is_element_present('add_agents_link'):
            move_agent_to_default_cluster_group(agent_list=expected_agents, select_all=True)
            cluster_group_agent_page.wait_for_modal_closed()
            wait(lambda: cluster_group_agent_page.is_element_present('add_agents_link'))

        __class__.move_node_back_to_default_cluster_group(node_name=node_name)

    @staticmethod
    def search_agent_name_and_verify(is_search_agent: bool, search_value: str) -> None:
        """
        Search agent and verify it from the list

        :param bool is_search_agent: True if you wanna search agent else False
        :param str search_value: value to search the agents
        :return: None
        """
        cluster_group_agent_page = ClusterGroupAgentPage()
        cluster_group_agent_list = ClusterGroupAgentList()

        if is_search_agent:
            cluster_group_agent_page.add_agent_search_field.clear()
            cluster_group_agent_page.add_agent_search_field.value = search_value

            # Verifies that 'Search' icon is getting enabled after entering the value in search input field.
            assert cluster_group_agent_page.add_agent_search_icon.is_enabled(), \
                "'Search' icon is not getting enabled after entering the value in search input field."

            cluster_group_agent_page.add_agent_search_icon.click()
            cluster_group_agent_list.loaded()

            # Verifies that 'Search' icon is getting enabled after entering the value in search input field.
            assert cluster_group_agent_page.is_element_present('add_agent_remove_search_icon'), \
                "Remove icon is not displayed after entering the value in search input field."

            # Verifies that all agent name contains the search value after applying the search
            assert all([search_value in agent_name for agent_name in
                        cluster_group_agent_list.get_cluster_agent_name_from_modal()]), \
                'Cluster agent name is not getting started from search value after searching agent.'

    @staticmethod
    def search_or_filter_agents_in_cluster_group_agents_page(node_name: str, cluster_agent_filter: dict,
                                                             search_value: str) -> tuple:
        """
        Search or Filter agents from cluster group agents page

        :param str node_name: name of node
        :param dict cluster_agent_filter: param of cluster agent filters
        :param str search_value: value as agent name to be searched
        :return: counts of total linked agents after applying filter or search
        :rtype: tuple
        """
        add_node_to_cluster_group(node_name=node_name)
        ClusterGroupAgentPage().wait_for_modal_closed()

        cluster_node_list = ClusterNodeList()
        wait(lambda: node_name in cluster_node_list.get_all_node_names(), timeout_seconds=TIME_SIXTY_SECONDS,
             sleep_seconds=TIME_FIVE_SECONDS, waiting_for="Node to get linked to cluster group!!")

        cluster_group_details = ClusterGroupDetails()
        cluster_group_details.back_to_cluster_group_link.click()

        cluster_group_list = ClusterGroupList()
        cluster_group_list.loaded()

        default_cluster_group_name = cluster_group_list.current_default_group_name()
        cluster_group_list.click_on_group(group_name=default_cluster_group_name)
        cluster_node_list.loaded()

        cluster_group_details.agents_tab.click()
        cluster_agent_list = ClusterAgentList()
        cluster_agent_list.loaded()

        agents_page = AgentsPage()
        total_linked_agents = agents_page.total_agents_count

        # Applying search or filter to cluster agents in the "Default cluster group"
        if cluster_agent_filter['agent_filter'] and not cluster_agent_filter['search_agent']:
            __class__.add_and_apply_linked_agent_filters(cluster_agent_filter['agent_filter'])
        else:
            __class__.search_agent_name_and_verify(is_search_agent=cluster_agent_filter['search_agent'],
                                                   search_value=search_value)

        cluster_agent_list.loaded()
        agents_count_after_filter_or_search = agents_page.total_agents_count

        return total_linked_agents, agents_count_after_filter_or_search

    @staticmethod
    def move_agents_to_other_cluster_group_and_verify_remaining_agents_count(
            created_cluster_group: str, agent_filter: dict, search_agent: bool, count_after_filter_search: int,
            total_linked_agents: int, total_selected_agent_count: int) -> None:
        """
        Moves agents to another cluster group and verify the remaining agents count from default cluster group

        :param str created_cluster_group: name of created cluster group
        :param dict agent_filter: param of agent filter
        :param bool search_agent: search agent if True else False
        :param int count_after_filter_search: number of agent after searching agent
        :param int total_linked_agents: total number of linked agents
        :param int total_selected_agent_count: number of selected agents
        :return: None
        """
        agent_page = AgentsPage()

        move_agents_to_other_cluster_group(cluster_group_name=created_cluster_group)

        # Verifies the remaining agents count in default cluster group.
        if agent_filter:
            assert agent_page.total_agents_count == (count_after_filter_search - total_selected_agent_count), \
                "Remaining agents count is not getting matched after applying filter on 'Default Cluster Group' " \
                "agents page."
        elif search_agent:
            assert agent_page.total_agents_count == (total_linked_agents - total_selected_agent_count), \
                "Remaining agents count is not getting matched after applying search on 'Default Cluster Group' " \
                "agents page."

        cluster_group_details = ClusterGroupDetails()

        if agent_page.total_agents_count == 0:
            # Verifies that empty agent results message is visible if there is no agents available
            assert cluster_group_details.is_element_present('empty_agents'), \
                'Agents list is not empty after moving all agents to other cluster group.'

            # verifies that 'Add agents' link is visible if there is no agents available
            assert ClusterGroupAgentPage().is_element_present('add_agents_link'), \
                "'Add agents' link is not visible along with empty results message if there is no agents available."

        navigate_to_cluster_group(cluster_group_name=created_cluster_group)
        cluster_group_details.agents_tab.click()
        ClusterAgentList().loaded()

    @staticmethod
    def verify_visibility_of_elements_after_select_or_select_all_in_cluster_agent_groups(
            agents_count: int, select_all: bool, expected_agents: list) -> None:
        """
        Verifies the elements like buttons, links, counts, etc. visibility for agents in cluster agent groups after 
        selecting agents from list.

        :param int agents_count: selected agent count
        :param bool select_all: True if select all agents else False
        :param list expected_agents: list of agents need to be selected
        :return: None
        """
        agent_page = AgentsPage()
        agent_list = AgentsList()

        # Verifies that total and selected agents count is getting same after adding agents into cluster group.
        assert agent_page.total_agents_count == agents_count, \
            "Total and selected agents count is mismatch after selecting agents from add agents modal."

        # Verifies that selected agents are available into created cluster group
        assert all([agent in agent_list.get_all_agents_by_name() for agent in expected_agents]), \
            "Selected agents are not available in the group after adding agents into the group."

        random_agent_count = 1 if len(expected_agents) < 5 else random.randint(3, 5)
        selected_agents_list_in_group = random.sample(expected_agents, k=random_agent_count)

        agent_list.select_all_checkbox.check() if select_all else agent_list.select_deselect_agents(
            agents_list=selected_agents_list_in_group, select=True)

        expected_agents_in_group = expected_agents if select_all else selected_agents_list_in_group

        # Verifies that agents are getting selected after clicking on checkbox on cluster group Agents page
        assert agent_list.is_agent_selected(agents_list=expected_agents_in_group), \
            "Agents are not getting selected on Cluster Groups Agent page after clicking on checkbox."

        # Verifies that 'Total' and 'Selected' agent count is visible after selecting agents from list
        assert all([agent_page.is_element_present('total_agents'),
                    agent_page.is_element_present('selected_agents')]), \
            "'Total' and 'Selected' agents count is not visible after deselecting few agents from list."

        # Verifies that 'Clear Selected Items' link is visible after selecting agents from list
        assert agent_page.is_element_present('clear_selected_item'), \
            "'Clear Selected Items' link is not showing up after selecting agents from list."

        is_count_same = agent_page.total_agents_count == agent_page.selected_agents_count

        # Verifies that total and selected agents count is getting same after selecting the agents from list.
        assert is_count_same if select_all else not is_count_same, \
            "Total and selected agents count is mismatch after selecting agents from list."

        # Verifies that 'Move' button is displayed after selecting agents from list
        assert ClusterGroupDetails().is_element_present('move_agent_button'), \
            "'Move' button is not showing up on Cluster Groups Agent details Page."

        agent_list.select_all_checkbox.click()

    @staticmethod
    def verify_visibility_of_elements_after_deselect_or_deselect_all_in_cluster_add_agents(
            deselect_all: bool) -> None:
        """
        Verifies the elements like buttons, links, counts, etc. visibility for agents in Linked agents after deselecting
        agents from list.

        :param bool deselect_all: True if deselect all agents else False
        :return: None
        """
        agent_page = AgentsPage()

        is_selected_agents_visible = agent_page.is_element_present('selected_agents')

        # Verifies that 'Total' agent count is visible and 'Selected' agent count is not visible after
        # deselecting all agents from list
        assert all([agent_page.is_element_present('total_agents'),
                    is_selected_agents_visible if not deselect_all else not is_selected_agents_visible]), \
            "'Selected' agents count is visible even after deselecting all agents from list."

        is_clear_selected_item_link_visible = agent_page.is_element_present('clear_selected_item')

        # Verifies that 'Clear Selected Items' link is not visible after deselecting all agents from list
        assert is_clear_selected_item_link_visible if not deselect_all else not is_clear_selected_item_link_visible, \
            "'Clear Selected Items' link is showing up even after deselecting all agents from list."

    @staticmethod
    def verify_visibility_of_elements_after_deselect_or_deselect_all_in_cluster_agent_groups(
            agent_count: int, expected_agents: list) -> None:
        """
        Verifies the elements like buttons, links, counts, etc. visibility for agents in Agent groups after deselecting
        agents from list.

        :param int agent_count: selected agent count
        :param list expected_agents: list of agents need to be selected
        :return: None
        """
        agent_page = AgentsPage()
        agent_list = AgentsList()

        # Verifies that total and selected agents count is getting same after adding agents into cluster group.
        assert agent_page.total_agents_count == agent_count, \
            "Total and selected agents count is mismatch after selecting agents from add agents modal."

        # Verifies that only selected agents are available into created group
        assert all([agent not in agent_list.get_all_agents_by_name() for agent in expected_agents]), \
            "Deselected agents are available into the group even after deselecting the agents from list."

        agents_in_group = agent_list.get_all_agents_by_name()
        agent_list.select_all_checkbox.check()

        # Verifies that 'Total' and 'Selected' agent count is visible after selecting all agents from list
        assert all([agent_page.is_element_present('total_agents'),
                    agent_page.is_element_present('selected_agents')]), \
            "'Total' and 'Selected' agents count is not visible after selecting all agents from list."

        # Verifies that 'Clear Selected Items' link is visible after selecting agents from list
        assert agent_page.is_element_present('clear_selected_item'), \
            "'Clear Selected Items' link is not showing up after selecting agents from list."

        cluster_group_details_page = ClusterGroupDetails()

        # Verifies that 'Move' button is displayed after selecting agents from list
        assert cluster_group_details_page.is_element_present('move_agent_button'), \
            "'Move' button is missing after selecting the agents from list on Cluster Groups Agent details Page."

        deselected_agents_list_in_group = random.sample(agents_in_group, k=random.randint(5, 8))
        agent_list.select_deselect_agents(agents_list=deselected_agents_list_in_group, select=False)

        # Verifies that agents are not getting selected after deselecting checkbox on Cluster group Agents page
        assert not agent_list.is_agent_selected(agents_list=deselected_agents_list_in_group), \
            "Agents are not getting selected on Agent Groups page after clicking on checkbox."

        # Verifies that 'Total' and 'Selected' agent count is visible after deselecting the agents from list
        assert all([agent_page.is_element_present('total_agents'),
                    agent_page.is_element_present('selected_agents')]), \
            "'Selected' agents count is visible even after deselecting all agents from list."

        # Verifies that 'Clear Selected Items' link is visible after deselecting agents from list
        assert agent_page.is_element_present('clear_selected_item'), \
            "'Clear Selected Items' link is not showing up after selecting agents from list."

        # Verifies that 'Move' button is displayed after deselecting few agents from list
        assert cluster_group_details_page.is_element_present('move_agent_button'), \
            "'Move' button is not visible after deselecting few agents from list."

        agent_list.select_all_checkbox.click()

    @pytest.mark.parametrize("select_cluster_agent", [
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ALL, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'Linux'}],
         'uncheck_agents': True},
        {'agent_filter': {}, 'uncheck_agents': False}, {'agent_filter': {}, 'uncheck_agents': True},
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'Windows'},
                          {'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.STATUS,
                           'filter_operator': Nessus.Agents.Filter.IS_EQUAL_TO, 'filter_value': 'Offline'},
                          {'match_type': Nessus.Filter.FilterMatch.ANY, 'filter_key': Nessus.Agents.Filter.PLATFORM,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'Windows'}],
         'uncheck_agents': True},
        {'agent_filter': [{'match_type': Nessus.Filter.FilterMatch.ALL, 'filter_key': Nessus.Agents.Filter.NAME,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'MacOS'},
                          {'match_type': Nessus.Filter.FilterMatch.ALL, 'filter_key': Nessus.Agents.Filter.PLATFORM,
                           'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': 'MacOS'}],
         'uncheck_agents': False}])
    def test_move_agents_into_cluster_group_after_filter_and_select(self, create_manager_cluster, create_cluster_group,
                                                                    select_cluster_agent):
        """NES-11943 : UI Automation for NES-11903
           Select All agents and add to cluster group doest respect the filter (NES-11903)
        Scenario Tested:
            [x] Verify that cluster agents moves to new cluster group via
            single filter/multiple filter/select-all option/uncheck agents method

        Steps:
        1. Link fake cluster agents in bulk to node/cluster manager.
        2. Add a new cluster group and assign a node to it.
        3. Move newly added cluster agents to new cluster group via below methods
            - Using single filter to select few agents and uncheck few agents by de-selecting them. (ALL operator)
            - Using select-all checkbox.
            - Using select-all checkbox and then uncheck few agents by de-selecting them.
            - Using multiple filter to select few agent then uncheck few agents (ANY operator)
            - Using multiple filter to select few agents (ALL operator)
        4. Verify that remaining cluster agents in default group is correct as per the agents moved to other group.
        5. Verify that all moved cluster agents appear in new cluster group.
        6. Verify that already added agent does not appear in 'Add Agents' table for the new cluster group.
        """
        node_name = [node for node in create_manager_cluster['nodes']][0]['name']
        add_node_to_cluster_group(node_name=node_name)
        group_node_list = ClusterNodeList()
        wait(lambda: node_name in group_node_list.get_all_node_names(), timeout_seconds=TIME_SIXTY_SECONDS,
             sleep_seconds=TIME_FIVE_SECONDS, waiting_for="Node to get linked to cluster group!!")
        cluster_group_page = ClusterGroupPage()
        cluster_group_list = ClusterGroupList()
        cluster_group_details = ClusterGroupAgentPage()
        agent_list = ClusterAgentList()
        agent_filter_window = FilterWindow()
        agent_page = AgentsPage()
        try:
            cluster_group_page.open()
            cluster_group_list.loaded()
            default_cluster_group_name = cluster_group_list.current_default_group_name()
            cluster_group_list.click_on_group(group_name=default_cluster_group_name)
            group_node_list.loaded()

            cluster_group_details.agents_tab.click()
            agent_list.loaded()
            total_linked_agents = int(agent_page.total_agents.text.split(" Agent")[0])

            # Adding filter to cluster agents in the "Default cluster group"
            if select_cluster_agent['agent_filter']:
                for agent_filter in select_cluster_agent['agent_filter']:
                    agent_filter_window.add_and_apply_filter(**agent_filter)
            wait(lambda: cluster_group_details.is_element_present('select_all_checkbox'))
            cluster_group_details.select_all_checkbox.click()

            # Conditionally un_check few agents from the selected agents.
            if select_cluster_agent['uncheck_agents']:
                select_agent_list = random.sample(agent_list.get_all_cluster_agent_names()[:10],
                                                  random.randint(1, 5))
                agent_list.select_cluster_agents(agents_list=select_agent_list)
            agents_to_be_moved = int(agent_page.selected_agents.text.split('(')[1].split(" ")[0])

            move_agents_to_other_cluster_group(cluster_group_name=create_cluster_group)

            # Clear the filter to count the remaining cluster agents in the group.
            if select_cluster_agent['agent_filter'] and (total_linked_agents - agents_to_be_moved) != 0:
                agent_page.filter_link.click()
                agent_filter_window.clear_filters.click()
                cluster_group_details.wait_for_modal_closed()

            # Verify the remaining agents count in default cluster group.
            if total_linked_agents - agents_to_be_moved == 0:
                try:
                    wait(lambda: cluster_group_details.is_element_present('empty_agents'),
                         timeout_seconds=TIME_THIRTY_SECONDS, sleep_seconds=TIME_FIVE_SECONDS,
                         waiting_for="Agents to get empty list for cluster group")
                except TimeoutExpired:
                    raise AssertionError("Agents list is not empty after moving all agents to other cluster group.")
            else:
                assert int(agent_page.total_agents.text.split(" Agent")[0]) == \
                       (total_linked_agents - agents_to_be_moved), "Remaining cluster agents' count is not " \
                                                                   "matching as per the agents moved to other " \
                                                                   "group via filter."
            navigate_to_cluster_group(cluster_group_name=create_cluster_group)

            cluster_group_details = ClusterGroupAgentPage()
            cluster_group_details.agents_tab.click()
            agent_list.loaded()

            assert int(agent_page.total_agents.text.split(" Agents")[0]) == agents_to_be_moved, \
                "Total agents count inside new cluster group is nor correct."

            # verifying that already added cluster agents does not appear in "Add Agents" table.
            if cluster_group_details.is_element_present('add_agents_button'):
                already_present_agent = random.choice(agent_list.get_all_cluster_agent_names())
                cluster_group_details.add_agents_button.click()
                wait(lambda: agent_list.get_all_cluster_agent_names())
                cluster_group_details.searchbox.send_keys(already_present_agent)
                cluster_group_details.searchbox.send_keys(Keys.ENTER)
                try:
                    wait(lambda: cluster_group_details.is_element_present('empty_agents'),
                         timeout_seconds=TIME_THIRTY_SECONDS, sleep_seconds=TIME_FIVE_SECONDS,
                         waiting_for="Agents to get empty list after searching for already "
                                     "present agent in 'Add Agents' table.")
                except TimeoutExpired:
                    raise AssertionError("Already present agent found for 'Add Agents' Table.")
            else:
                # Verify that all agent have been transferred to current cluster group
                # when "Add Agents' button is not present.
                assert total_linked_agents - agents_to_be_moved == 0, "'Add Agents' button should be visible " \
                                                                      "when all cluster agents are not linked to " \
                                                                      "the cluster group"
        finally:
            if cluster_group_details.is_element_present('modal'):
                cluster_group_details.close_button.click()
                cluster_group_details.wait_for_modal_closed()
            # Removing all agents and nodes from the new cluster group.
            navigate_to_cluster_group(cluster_group_name=create_cluster_group)
            cluster_group_details.agents_tab.click()
            agent_list.loaded()
            if agent_list.get_all_cluster_agent_names() != []:
                cluster_group_details.select_all_checkbox.click()
                move_agents_to_other_cluster_group(cluster_group_name=default_cluster_group_name)
            move_node_to_default_cluster_group(node_name=node_name, cluster_group_name=create_cluster_group)
            wait(lambda: ClusterGroupDetails().is_element_present('add_node_button'))

    @pytest.mark.parametrize('search_agent', [True, False])
    @pytest.mark.parametrize('select_all', [True, False])
    def test_add_selected_agents_into_cluster_group(self, create_manager_cluster, search_agent, select_all):
        """
        NES-11981: Automation: Add/Move agents in group from cluster agents view after 
                   select/deselect/select-all/deselect-all

        Steps:
        1. Create new cluster group
        1. Select/Select-all agents from add agents to cluster group modal.
        2. Add selected agents into created cluster group.
        3. Verify that all selected agents should be available into created cluster group.

        Scenario Tested:
        [x] Verify that all selected agents should be available into created cluster group.
        """
        expected_agents = []
        node_name = [node for node in create_manager_cluster['nodes']][0]['name']
        search_value = random.sample(['Linux-', 'Windows-', 'MacOS-'], k=1)[0]
        cluster_group_agent_page = ClusterGroupAgentPage()

        try:
            add_node_to_cluster_group(node_name=node_name)
            cluster_group_agent_page.wait_for_modal_closed()
            wait(lambda: node_name in ClusterNodeList().get_all_node_names(), timeout_seconds=TIME_SIXTY_SECONDS,
                 sleep_seconds=TIME_FIVE_SECONDS, waiting_for="Node to get linked to cluster group!!")

            cluster_group_agent_page.agents_tab.click()
            wait(lambda: cluster_group_agent_page.is_element_present('add_agents_link'),
                 waiting_for='cluster agent page gets load properly.')

            cluster_group_agent_page.add_agents_button.click()
            cluster_group_agent_list = ClusterGroupAgentList()
            cluster_group_agent_list.loaded()

            self.search_agent_name_and_verify(is_search_agent=search_agent, search_value=search_value)

            all_cluster_agent_name = cluster_group_agent_list.get_cluster_agent_name_from_modal()

            expected_agents = all_cluster_agent_name if select_all else random.sample(all_cluster_agent_name,
                                                                                      k=random.randint(10, 15))

            cluster_group_agent_list.select_all_checkbox.check() if select_all else \
                cluster_group_agent_list.select_cluster_add_agents(agents_list=expected_agents)

            selected_agent_count = AgentsPage().selected_agents_count

            # Verifies that agents are getting selected after clicking on checkbox on add agents modal
            assert cluster_group_agent_list.is_cluster_agent_selected(agents_list=expected_agents), \
                "Agents are not getting selected on Cluster group Agents page after clicking on checkbox."

            verify_visibility_of_elements_after_select_or_select_all_in_cluster_add_agents(select_all=select_all)

            cluster_group_agent_page.accept_action()
            cluster_group_agent_page.wait_for_modal_closed()
            AgentsList().loaded()

            self.verify_visibility_of_elements_after_select_or_select_all_in_cluster_agent_groups(
                agents_count=selected_agent_count, select_all=select_all, expected_agents=expected_agents)
        finally:
            self.move_node_and_agents_back_to_default_cluster_group(expected_agents=expected_agents,
                                                                    node_name=node_name)

    @pytest.mark.usefixtures('nessus_api_login')
    def test_distinct_linking_key_for_child_nodes(self):
        """
        NES-17416 : Validate Distinct Linking Keys for child-nodes in UI.

        Scenario Tested:
        [x] Verify API and UI linking keys are same.

        Steps:
        1. Setting up Nessus Manager and converting to cluster
        2. Taking random 64 characters key to set
        3. using the set method of agent linking key
        4. Opening the sensors tab in browser UI
        5. Go to agent page and checking the keys
        6. Comparing the UI and API keys.
        """
        agent_page = AgentsPage()

        # Generating random 64 character keys
        node_key = random_alphanumeric_string_for_linking_key(64)

        # setting the new agent linking key to nessus manager
        self.cat.api.agent_groups.set_child_node_linking_key(node_key=node_key)

        HeaderBasePage().sensors_tab.click()
        wait(lambda: visibility_of_element_located(agent_page.linking_key_text),
             waiting_for="Sensors page to load properly")
        HeaderBasePage().cluster_page.click()

        # going to linked scanner page
        wait(lambda: visibility_of_element_located(agent_page.linking_key_text),
             waiting_for="Sensors page to load properly")
        key = agent_page.linking_key_text.text

        # Verify newly set linking key via API is reflected on UI
        assert node_key in key, "Linking key is not updated."

    @pytest.mark.parametrize('search_agent', [True, False])
    @pytest.mark.parametrize('deselect_all', [True, False])
    def test_add_agents_into_cluster_group_after_deselect(self, create_manager_cluster, search_agent, deselect_all):
        """
        NES-11981: Automation: Add/Move agents in group from cluster agents view after 
                   select/deselect/select-all/deselect-all

        Steps:
        1. Create new cluster group
        1. Deselect/Deselect-all agents from add agents to cluster group modal.
        2. Add only selected agents into cluster group.
        3. Verify that all deselected agents should not be available into created cluster group.

        Scenario Tested:
        [x] Verify that all deselected agents should not be available into created cluster group.
        """
        node_name = [node for node in create_manager_cluster['nodes']][0]['name']
        expected_agents = []
        search_value = random.sample(['Linux-', 'Windows-', 'MacOS-'], k=1)[0]
        cluster_group_agent_page = ClusterGroupAgentPage()

        try:
            add_node_to_cluster_group(node_name=node_name)
            cluster_group_agent_page.wait_for_modal_closed()
            wait(lambda: node_name in ClusterNodeList().get_all_node_names(), timeout_seconds=TIME_SIXTY_SECONDS,
                 sleep_seconds=TIME_FIVE_SECONDS, waiting_for="Node to get linked to cluster group!!")

            cluster_group_agent_page.agents_tab.click()
            wait(lambda: cluster_group_agent_page.is_element_present('add_agents_link'),
                 waiting_for='cluster agent page gets load properly.')

            cluster_group_agent_page.add_agents_button.click()
            cluster_group_agent_list = ClusterGroupAgentList()
            cluster_group_agent_list.loaded()

            self.search_agent_name_and_verify(is_search_agent=search_agent, search_value=search_value)

            all_cluster_agent_name = cluster_group_agent_list.get_cluster_agent_name_from_modal()

            expected_agents = all_cluster_agent_name if deselect_all else random.sample(all_cluster_agent_name,
                                                                                        k=random.randint(10, 15))
            cluster_group_agent_list.select_all_checkbox.check()

            cluster_group_agent_list.select_all_checkbox.uncheck() if deselect_all else \
                cluster_group_agent_list.select_cluster_add_agents(agents_list=expected_agents)

            # Verifies that agents are not getting selected after clicking on checkbox on Cluster group Agents page
            assert not cluster_group_agent_list.is_cluster_agent_selected(agents_list=expected_agents), \
                "Agents are not getting selected on Cluster group Agents page after clicking on checkbox."

            self.verify_visibility_of_elements_after_deselect_or_deselect_all_in_cluster_add_agents(
                deselect_all=deselect_all)

            if not deselect_all:
                selected_agent_count = AgentsPage().selected_agents_count

                cluster_group_agent_page.accept_action()
                cluster_group_agent_page.wait_for_modal_closed()
                AgentsList().loaded()

                self.verify_visibility_of_elements_after_deselect_or_deselect_all_in_cluster_agent_groups(
                    expected_agents=expected_agents, agent_count=selected_agent_count)
            else:
                cluster_group_agent_page.cancel_button.click()
        finally:
            self.move_node_and_agents_back_to_default_cluster_group(expected_agents=expected_agents,
                                                                    node_name=node_name)

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
    @pytest.mark.parametrize('select_all', [True, False])
    def test_move_selected_agents_into_cluster_group(self, create_manager_cluster, create_cluster_group,
                                                     cluster_agent_filter, select_all):
        """
        NES-11981: Automation: Add/Move agents in group from cluster agents view after 
                   select/deselect/select-all/deselect-all

        Steps:
        1. Create new cluster group
        2. Search for agents or apply filters for agents
        3. Select/Select-all agents from "Default Cluster Group" agents page.
        4. Move selected agents into created cluster group.
        5. Verify that all selected agents should be moved successfully into created cluster group.

        Scenario Tested:
        [x] Verify that all selected agents should be moved successfully into created cluster group.
        """
        node_name = [node for node in create_manager_cluster['nodes']][0]['name']
        expected_agents = []
        search_value = random.sample(['Linux-', 'Windows-', 'MacOS-'], k=1)[0]

        try:
            total_linked_agents, count_after_filter_search = self.search_or_filter_agents_in_cluster_group_agents_page(
                node_name=node_name, cluster_agent_filter=cluster_agent_filter, search_value=search_value)

            cluster_agent_list = ClusterAgentList()
            all_cluster_agent_name = cluster_agent_list.get_all_cluster_agent_names()

            expected_agents = all_cluster_agent_name if select_all else random.sample(all_cluster_agent_name,
                                                                                      k=random.randint(10, 15))

            agent_list = AgentsList()
            agent_list.select_all_checkbox.check() if select_all else agent_list.select_deselect_agents(
                agents_list=expected_agents)

            # Verifies that agents are getting selected after clicking on checkbox on cluster group Agents page
            assert agent_list.is_agent_selected(agents_list=expected_agents), \
                "Agents are not getting selected on Cluster Groups Agent page after clicking on checkbox."

            verify_visibility_of_elements_after_select_or_select_all_in_cluster_add_agents(select_all=select_all)
            total_selected_agent_count = AgentsPage().selected_agents_count

            self.move_agents_to_other_cluster_group_and_verify_remaining_agents_count(
                created_cluster_group=create_cluster_group, agent_filter=cluster_agent_filter['agent_filter'],
                search_agent=cluster_agent_filter['search_agent'], count_after_filter_search=count_after_filter_search,
                total_linked_agents=total_linked_agents, total_selected_agent_count=total_selected_agent_count)

            self.verify_visibility_of_elements_after_select_or_select_all_in_cluster_agent_groups(
                agents_count=total_selected_agent_count, select_all=select_all, expected_agents=expected_agents)
        finally:
            self.move_node_and_agents_back_to_default_cluster_group(expected_agents=expected_agents,
                                                                    node_name=node_name)

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
    @pytest.mark.parametrize('deselect_all', [True, False])
    def test_move_agents_into_cluster_group_after_deselect(self, create_manager_cluster, create_cluster_group,
                                                           cluster_agent_filter, deselect_all):
        """
        NES-11981: Automation: Add/Move agents in group from cluster agents view after 
                   select/deselect/select-all/deselect-all

        Steps:
        1. Create new cluster group
        2. Search for agents or apply filters for agents
        3. Deselect/Deselect-all agents from "Default Cluster Group" agents page.
        4. Move only selected agents into created cluster group.
        5. Verify that all deselected agents should not be moved into created cluster group.

        Scenario Tested:
        [x] Verify that all deselected agents should not be moved into created cluster group.
        """
        node_name = [node for node in create_manager_cluster['nodes']][0]['name']
        expected_agents = []
        search_value = random.sample(['Linux-', 'Windows-', 'MacOS-'], k=1)[0]

        try:
            total_linked_agents, count_after_filter_search = self.search_or_filter_agents_in_cluster_group_agents_page(
                node_name=node_name, cluster_agent_filter=cluster_agent_filter, search_value=search_value)

            cluster_agent_list = ClusterAgentList()
            all_cluster_agent_name = cluster_agent_list.get_all_cluster_agent_names()

            expected_agents = all_cluster_agent_name if deselect_all else random.sample(all_cluster_agent_name,
                                                                                        k=random.randint(10, 15))
            agent_list = AgentsList()
            agent_list.select_all_checkbox.check()

            agent_list.select_all_checkbox.uncheck() if deselect_all else agent_list.select_deselect_agents(
                agents_list=expected_agents, select=False)

            # Verifies that agents are getting deselected after clicking on checkbox on cluster group Agents page
            assert not agent_list.is_agent_selected(agents_list=expected_agents), \
                "Agents are getting selected on Cluster Groups Agent page after deselecting the checkbox."

            self.verify_visibility_of_elements_after_deselect_or_deselect_all_in_cluster_add_agents(
                deselect_all=deselect_all)

            if not deselect_all:
                total_selected_agent_count = AgentsPage().selected_agents_count

                self.move_agents_to_other_cluster_group_and_verify_remaining_agents_count(
                    created_cluster_group=create_cluster_group, agent_filter=cluster_agent_filter['agent_filter'],
                    search_agent=cluster_agent_filter['search_agent'],
                    count_after_filter_search=count_after_filter_search, total_linked_agents=total_linked_agents,
                    total_selected_agent_count=total_selected_agent_count)

                self.verify_visibility_of_elements_after_deselect_or_deselect_all_in_cluster_agent_groups(
                    expected_agents=expected_agents, agent_count=total_selected_agent_count)
        finally:
            if deselect_all:
                navigate_to_cluster_group(cluster_group_name=create_cluster_group)
                self.move_node_back_to_default_cluster_group(node_name=node_name)
            else:
                self.move_node_and_agents_back_to_default_cluster_group(expected_agents=expected_agents,
                                                                        node_name=node_name)

    @pytest.mark.parametrize('search_agent', [True, False])
    def test_add_selected_agents_from_each_page_into_cluster_group_by_pagination(self, create_manager_cluster,
                                                                                 search_agent):
        """
        NES-12096: Automation: Add/Move selected agents into group from different pages by pagination

        Steps:
        1. Create new cluster group
        2. Select agents from each pages by using pagination from add agents to cluster group modal.
        3. Add selected agents into created cluster group.
        4. Verify that all selected agents from each page should be available into created cluster group.

        Scenario Tested:
        [x] Verify that all selected agents from each page should be available into created cluster group.
        """
        list_of_selected_agent_from_each_page = []
        node_name = [node for node in create_manager_cluster['nodes']][0]['name']
        search_value = random.sample(['Linux-', 'Windows-', 'MacOS-'], k=1)[0]
        cluster_group_agent_page = ClusterGroupAgentPage()

        try:
            add_node_to_cluster_group(node_name=node_name)
            cluster_group_agent_page.wait_for_modal_closed()
            wait(lambda: node_name in ClusterNodeList().get_all_node_names(), timeout_seconds=TIME_SIXTY_SECONDS,
                 sleep_seconds=TIME_FIVE_SECONDS, waiting_for="Node to get linked to cluster group!!")

            cluster_group_agent_page.agents_tab.click()
            wait(lambda: cluster_group_agent_page.is_element_present('add_agents_link'),
                 waiting_for='cluster agent page gets load properly.')

            cluster_group_agent_page.add_agents_button.click()
            cluster_group_agent_list = ClusterGroupAgentList()
            cluster_group_agent_list.loaded()

            self.search_agent_name_and_verify(is_search_agent=search_agent, search_value=search_value)

            list_of_selected_agent_from_each_page = get_and_verify_total_selected_agents_and_its_count_from_page(
                add_agents=True)
            list_of_selected_agent_from_each_page.sort()

            cluster_group_agent_page.accept_action()
            cluster_group_agent_page.wait_for_modal_closed()
            AgentsList().loaded()

            total_selected_agents_from_page = len(list_of_selected_agent_from_each_page)
            expected_agents = list_of_selected_agent_from_each_page[:45] if total_selected_agents_from_page > 50 else \
                list_of_selected_agent_from_each_page

            self.verify_visibility_of_elements_after_select_or_select_all_in_cluster_agent_groups(
                agents_count=total_selected_agents_from_page, select_all=False, expected_agents=expected_agents)
        finally:
            self.move_node_and_agents_back_to_default_cluster_group(
                expected_agents=list_of_selected_agent_from_each_page, node_name=node_name)

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
    def test_move_selected_agents_from_each_page_into_cluster_group_by_pagination(
            self, create_manager_cluster, create_cluster_group, cluster_agent_filter):
        """
        NES-12096: Automation: Add/Move selected agents into group from different pages by pagination

        Steps:
        1. Create new cluster group
        2. Search for agents or apply filters for agents
        3. Select agents from each page by using pagination from "Default Cluster Group" agents page.
        4. Move selected agents from each page into created cluster group.
        5. Verify that all selected agents from each page should be moved successfully into created cluster group.

        Scenario Tested:
        [x] Verify that all selected agents from each page should be moved successfully into created cluster group.
        """
        list_of_selected_agent_from_each_page = []
        node_name = [node for node in create_manager_cluster['nodes']][0]['name']
        search_value = random.sample(['Linux-', 'Windows-', 'MacOS-'], k=1)[0]

        try:
            total_linked_agents, count_after_filter_search = self.search_or_filter_agents_in_cluster_group_agents_page(
                node_name=node_name, cluster_agent_filter=cluster_agent_filter, search_value=search_value)

            list_of_selected_agent_from_each_page = get_and_verify_total_selected_agents_and_its_count_from_page()
            list_of_selected_agent_from_each_page.sort()

            self.move_agents_to_other_cluster_group_and_verify_remaining_agents_count(
                created_cluster_group=create_cluster_group, agent_filter=cluster_agent_filter['agent_filter'],
                search_agent=cluster_agent_filter['search_agent'], count_after_filter_search=count_after_filter_search,
                total_linked_agents=total_linked_agents, total_selected_agent_count=len(
                    list_of_selected_agent_from_each_page))

            total_selected_agents_from_page = len(list_of_selected_agent_from_each_page)
            expected_agents = list_of_selected_agent_from_each_page[:45] if total_selected_agents_from_page > 50 else \
                list_of_selected_agent_from_each_page

            self.verify_visibility_of_elements_after_select_or_select_all_in_cluster_agent_groups(
                agents_count=total_selected_agents_from_page, select_all=False, expected_agents=expected_agents)
        finally:
            self.move_node_and_agents_back_to_default_cluster_group(
                expected_agents=list_of_selected_agent_from_each_page, node_name=node_name)
