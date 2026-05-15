"""
Sensor Manager cluster group management related test cases

:copyright: Tenable Network Security, 2019
:date: Nov 01, 2019
:last_modified: May 14, 2021
:author: @vsoni, @kpanchal
"""
import subprocess
from random import randint

import pytest
from selenium.webdriver.support.expected_conditions import visibility_of_element_located
from waiting.exceptions import TimeoutExpired

from catium.helpers.sleep_lib import sleep
from catium.helpers.testdata import get_file_path
from catium.lib.const import TIME_THIRTY_SECONDS
from catium.lib.const.base_constants import TIME_TWO_MINUTES, TIME_FIVE_SECONDS, TIME_TEN_MINUTES, TIME_THIRTY_MINUTES, \
    WAIT_NORMAL
from catium.lib.log import create_logger
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.agent_cluster.agent_cluster import add_node_to_cluster_group, move_node_to_default_cluster_group, \
    new_cluster_group, move_agent_to_default_cluster_group, unlink_child_node_from_parent_node, get_linked_node_count
from nessus.helpers.nessus_ui.settings import login_helper_after_server_restart
from nessus.helpers.scan import create_scan_helper
from nessus.helpers.scanner import wait_for_scanner_to_be_ready
from nessus.helpers.waiters import wait_scan_state
from nessus.lib.const import Nessus, random_name
from nessus.lib.const.constants import API
from nessus.lib.message.messages import Messages
from nessus.pageobjects.advanced_settings.advanced_settings_page import AdvancedSettingsPage, AdvancedSettingsList, \
    AddAdvancedSettingModal
from nessus.pageobjects.agents.agents_page import AgentsList, AgentDetail
from nessus.pageobjects.cluster.cluster_agent_page import ClusterAgentList, AgentClusterMigration
from nessus.pageobjects.cluster.cluster_group_page import ClusterGroupPage, ClusterGroupList, \
    ClusterGroupDetails, ClusterGroupAgentPage
from nessus.pageobjects.cluster.cluster_nodes_page import ClusterNodeList, NodeDetailsPage
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications, NotificationActions
from nessus.pageobjects.scans.scan_view_page import ScanViewPage, ThreatLevelVulnerabilityList
from nessus.pageobjects.scans.scans_page import ScanList
from nessus.pageobjects.sidenav.sidenav import SideNav
from nessus.tests.conftest import link_child_node_to_parent_node

log = create_logger()


def verify_cluster_group_page_elements() -> None:
    """
    This method is used to verify that all necessary web-elements present on cluster group page.
    """
    cluster_group = ClusterGroupPage()

    # Verify that node linking key is present.
    try:
        wait(lambda: cluster_group.is_element_present(element_name='node_linking_key'))
    except TimeoutExpired:
        raise AssertionError("Node linking key is not visible on cluster groups page.")

    # Verify that node linking key is not empty.
    assert cluster_group.node_linking_key.text, "Node linking key is empty."

    # Verifies that regenerate key icon is visible next to Linking Key id.
    assert cluster_group.is_element_present(element_name='regenerate_icon'), \
        'Regenerate key icon is not visible next to "Linking Key" text.'

    # Verifies that modify key icon is visible next to regenerate key icon.
    assert cluster_group.is_element_present(element_name='modify_icon'), \
        'Modify key icon is not visible next to regenerate key icon.'

    # Verifies that cluster group search box is visible.
    assert cluster_group.is_element_present(element_name='search_cluster_group'), \
        'Cluster group search box is missing on cluster group page.'

    # Verifies that total cluster group count is visible next to cluster group Search box.
    assert cluster_group.is_element_present(element_name='total_cluster_group_count'), \
        'Total cluster group count is not displayed next to cluster group Search box.'

    cluster_group_list = ClusterGroupList()
    default_cluster_group_name = cluster_group_list.current_default_group_name()

    # Verify that default cluster group is present on cluster group page.
    assert default_cluster_group_name, "Default cluster group is not present on cluster group list."

    cluster_group_list.select_cluster_group(group_name=default_cluster_group_name)
    wait(lambda: visibility_of_element_located(cluster_group.edit_button),
         waiting_for='Edit and Delete buttons to visible')

    # Verifies that 'Edit' and 'Delete' button is visible on top right corner after selecting cluster group
    assert all([cluster_group.is_element_present(element_name='edit_button'),
                cluster_group.is_element_present(element_name='delete_button')]), \
        '"Edit" and "Delete" button is not visible on top right corner after selecting cluster group.'


@pytest.mark.cluster_manager
@pytest.mark.usefixtures('create_manager_cluster', 'login', 'create_cluster_group')
class TestClusterGroups:
    """ Test cases to cover UI functionality related to cluster groups. """

    @staticmethod
    def move_node_and_back_to_cluster_group_list(node_name: str, group_name: str = None) -> None:
        """
        Moves node to given cluster group and clicks on back link to go to cluster group list

        :param str node_name: Name of node which is to be moved to given cluster group.
        :param str group_name: Name of cluster group.
        :return: None
        """
        # Moving node from the cluster group to default cluster group.
        move_node_to_default_cluster_group(node_name=node_name, cluster_group_name=group_name)

        notification = Notifications()

        # Verifies the success notification after moving node into cluster group
        assert notification.successes[-1] == Messages.NotificationMessages.Agents.AgentCluster. \
            move_node_to_group, 'Success notification is missing or mismatch after moving node into cluster group.'

        wait(lambda: ClusterGroupDetails().is_element_present('add_node_button'))
        NodeDetailsPage().back_link.click()
        ClusterGroupList().loaded()

    def test_verify_linked_agents_and_nodes_to_default_group(self, create_manager_cluster):
        """
        NES-10266: UI Automation for cluster groups

        Scenario Tested:
            [x] Verify that nodes and agents get assigned to default group.

        Steps:
        1. Verify nodes linked to sensor manager assigned to default cluster group
        2. Verify agents linked to sensor manager assigned to default cluster group
        """
        node_names = [node['name'] for node in create_manager_cluster['nodes']]
        agent_names = [agent['name'] for agent in create_manager_cluster['agents']]

        ClusterGroupPage().open()
        cluster_group_list = ClusterGroupList()
        cluster_group_list.loaded()

        # Getting the current default group name.
        default_cluster_group_name = cluster_group_list.current_default_group_name()
        cluster_group_list.click_on_group(group_name=default_cluster_group_name)

        group_node_list = ClusterNodeList()
        group_node_list.loaded()

        # Verifying if nodes created by create_manager_cluster fixture are present in default group.
        assert set(node_names).issubset(set(group_node_list.get_all_node_names())), \
            "Nodes are not assigned to default group."

        ClusterGroupDetails().agents_tab.click()
        agent_list = AgentsList()
        agent_list.loaded()

        # Verifying if agents created by create_manager_cluster fixture are present in default group.
        assert set(agent_names).issubset(set(agent_list.get_all_agents_by_name())), \
            "Agents are not assigned to default group."

    @pytest.mark.parametrize("new_cluster_group_name", ['random'])
    def test_create_and_modify_cluster_group_name(self, create_cluster_group, new_cluster_group_name):
        """
        NES-10266: UI Automation for cluster groups

        Scenario Tested:
            [x] Verify the cluster group creation and cluster group name modification

        Steps:
        1. Create a cluster group.
        2. Verify that cluster group is created successfully.
        3. Change cluster group name and verify that it reflects in cluster groups on UI.
        """
        if new_cluster_group_name == 'random':
            new_cluster_group_name = random_name(prefix='cluster-group-')

        notification = None
        cluster_group_list = ClusterGroupList()

        try:
            ClusterGroupPage().open()
            cluster_group_list.loaded()

            # Verifying that cluster group created successfully and populated in cluster group page.
            assert create_cluster_group in cluster_group_list.get_all_group_names(), \
                'Cluster group is not created successfully.'

            cluster_group_list.edit_cluster_group_name(current_group_name=create_cluster_group,
                                                       new_group_name=new_cluster_group_name)
            notification = Notifications()

            # Verifies the success notification after changing the cluster group name
            assert notification.successes[-1] == 'Cluster Group "{}" edited successfully!'.format(
                new_cluster_group_name), 'Success notification is missing or mismatch after editing cluster group name.'

            cluster_group_list.loaded()

            # Verifying that cluster group with modified name is populated  in cluster group page.
            assert new_cluster_group_name in cluster_group_list.get_all_group_names(), \
                "Cluster group name has not been changed."
        finally:
            # Reverting back the name of cluster group created.
            if create_cluster_group not in cluster_group_list.get_all_group_names():
                cluster_group_list.edit_cluster_group_name(current_group_name=new_cluster_group_name,
                                                           new_group_name=create_cluster_group)

                # Verifies the success notification after changing the cluster group name
                assert notification.successes[-1] == 'Cluster Group "{}" edited successfully!'.format(
                    create_cluster_group), 'Success notification is missing or mismatch after editing cluster group ' \
                                           'name.'

                cluster_group_list.loaded()

    def test_assign_node_to_created_cluster_group(self, create_manager_cluster):
        """
        NES-10266: UI Automation for cluster groups

        Scenario Tested:
            [x] Assign a cluster node to newly created cluster group.

        Steps:
        1. Create a cluster group.
        2. Assign a node to the cluster group created above.
        3. Verify if the cluster node is added successfully in cluster group.
        """
        node_name = [node['name'] for node in create_manager_cluster['nodes']][0]
        NotificationActions().remove_all()

        try:
            add_node_to_cluster_group(node_name=node_name)
            notification = Notifications()

            # Verifies the success notification after adding node into cluster group
            assert notification.successes[-1] == Messages.NotificationMessages.Agents.AgentCluster. \
                add_node_to_group, 'Success notification is missing or mismatch after adding node into cluster group.'

            cluster_node_list = ClusterNodeList()
            cluster_node_list.loaded()

            # Verifying that assigned node is present in the cluster group details page.
            assert node_name in cluster_node_list.get_all_node_names(), "Node is not assigned to new created group."
        finally:
            self.move_node_and_back_to_cluster_group_list(node_name=node_name)

    def test_set_newly_created_cluster_group_as_default(self, create_manager_cluster, create_cluster_group):
        """
        NES-10266: UI Automation for cluster groups

        Scenario Tested:
            [x] Set the newly created cluster group as default cluster group.

        Steps:
        1. Create a cluster group.
        2. Assign a node to the cluster group created above.
        3. Set the newly created cluster group as default group.
        4. Verify that default tag is added to the new cluster group."""
        node_name = [node['name'] for node in create_manager_cluster['nodes']][0]

        NotificationActions().remove_all()
        add_node_to_cluster_group(node_name=node_name)
        notification = Notifications()

        # Verifies the success notification after adding node into cluster group
        assert notification.successes[-1] == Messages.NotificationMessages.Agents.AgentCluster. \
            add_node_to_group, 'Success notification is missing or mismatch after adding node into cluster group.'

        ClusterNodeList().loaded()
        ClusterGroupPage().open()
        cluster_group_list = ClusterGroupList()
        cluster_group_list.loaded()

        default_cluster_group_name = cluster_group_list.current_default_group_name()
        cluster_group_list.make_cluster_group_to_default(group_name=create_cluster_group)

        # Verifies the success notification after changing the cluster group name
        assert notification.successes[-1] == 'Cluster Group "{}" edited successfully!'.format(
            create_cluster_group), 'Success notification is missing or mismatch after editing cluster group name.'

        cluster_group_list.loaded()

        # Verifying that new cluster group has been set as default cluster group
        assert cluster_group_list.current_default_group_name() == create_cluster_group, \
            "New cluster group is not default group yet."

        cluster_group_list.make_cluster_group_to_default(group_name=default_cluster_group_name)

        # Verifies the success notification after changing the cluster group name
        assert notification.successes[-1] == 'Cluster Group "{}" edited successfully!'.format(
            default_cluster_group_name), 'Success notification is missing or mismatch after editing cluster group name.'

        cluster_group_list.loaded()
        self.move_node_and_back_to_cluster_group_list(node_name=node_name, group_name=create_cluster_group)

    def test_default_group_can_not_be_deleted(self):
        """
        NES-10266: UI Automation for cluster groups

        Scenario Tested:
            [x] Verify that default cluster group can not be deleted

        Steps:
        1. Delete the default cluster group
        2. Verify that default group does not get deleted as nodes are assigned to it
        """
        default_tag = "Default\n"

        ClusterGroupPage().open()
        cluster_group_list = ClusterGroupList()
        cluster_group_list.loaded()

        default_cluster_group_name = cluster_group_list.current_default_group_name()
        cluster_group_list.delete_default_cluster_group(group_name=default_cluster_group_name)

        notification = Notifications()

        # Verifying error message when default cluster group is getting deleted.
        assert notification.errors[-1] == Messages.NotificationMessages.Agents.AgentCluster. \
            unable_to_delete_cluster_group, "Error notification is missing or mismatch when cluster group is " \
                                            "getting deleted while node is assigned "

        cluster_group_list.loaded()

        # Verifying the default group has not been deleted.
        assert default_tag + default_cluster_group_name in cluster_group_list.get_all_group_names(), \
            "Default cluster group has been deleted."

    def test_cluster_group_can_not_be_deleted_when_node_is_assigned(self, create_manager_cluster, create_cluster_group):
        """
        NES-10266: UI Automation for cluster groups

        Scenario Tested:
            [x] Verify that cluster group can not be deleted when node is assigned to it.

        Steps:
        1. Create a cluster group.
        2. Assign a node to the cluster group created above.
        3. Delete the new cluster group
        4. Verify that new cluster group does not get deleted as node is assigned to it
        """
        node_name = [node['name'] for node in create_manager_cluster['nodes']][0]
        NotificationActions().remove_all()

        try:
            add_node_to_cluster_group(node_name=node_name)
            notification = Notifications()

            # Verifies the success notification after adding node into cluster group
            assert notification.successes[-1] == Messages.NotificationMessages.Agents.AgentCluster. \
                add_node_to_group, 'Success notification is missing or mismatch after adding node into cluster group.'

            ClusterNodeList().loaded()
            ClusterGroupPage().open()
            cluster_group_list = ClusterGroupList()
            cluster_group_list.loaded()
            cluster_group_list.delete_cluster_group(group_name=create_cluster_group)
            ActionCloseModal().accept_action()

            # Verifying that cluster group can not be deleted when node is assigned to it.
            assert notification.errors[-1] == Messages.NotificationMessages.Agents.AgentCluster. \
                unable_to_delete_cluster_group, "Error notification is missing or mismatch when cluster group is " \
                                                "getting deleted while node is assigned "

            cluster_group_list.loaded()

            # Verifying cluster group has not been deleted.
            assert create_cluster_group in cluster_group_list.get_all_group_names(), \
                "Cluster group has been deleted even though nodes assigned to it."
        finally:
            self.move_node_and_back_to_cluster_group_list(node_name=node_name, group_name=create_cluster_group)

    def test_agent_can_not_be_assigned_to_group_without_nodes_assigned(self, create_manager_cluster):
        """
        NES-10266: UI Automation for cluster groups

        Scenario Tested:
            [x] Verify that agent can not be assigned to cluster group without nodes assigned to it.

        Steps:
        1. Create a cluster group.
        2. Assign agent to the cluster group created above.
        3. Verify that agent can not be assigned to cluster group without nodes assigned.
        """
        agent_name = [agent['name'] for agent in create_manager_cluster['agents']][0]

        cluster_group_details = ClusterGroupAgentPage()
        cluster_group_details.agents_tab.click()
        wait(lambda: cluster_group_details.is_element_present('add_agents_button'))
        cluster_group_details.add_agent_member_to_cluster_group(member_agent_list=[agent_name])

        notification = Notifications()

        # Verifying the error message when agent is assigned to cluster group with no nodes present in the group.
        assert notification.results[-1] == Messages.NotificationMessages.Agents.AgentCluster. \
            unable_to_assign_agents_to_group, "Error notification is missing or mismatch when agent is getting " \
                                              "assigned to cluster group without nodes assigned to it."

        cluster_group_details.cancel_button.click()

    def test_node_can_not_be_deleted_when_agent_is_present_in_cluster_group(self, create_cluster_group,
                                                                            create_manager_cluster):
        """
        NES-10266: UI Automation for cluster groups

        Scenario Tested:
            [x] Verify node can not be deleted from cluster group when agents are assigned to it.

        Steps:
        1. Create a cluster group.
        2. Assign a node and agent to the cluster group created above.
        3. Delete the node assigned and verify that node can not be deleted as agent is assigned to cluster group
        """
        node_name = [node['name'] for node in create_manager_cluster['nodes']][0]
        agent_name = [agent['name'] for agent in create_manager_cluster['agents']][0]
        NotificationActions().remove_all()

        add_node_to_cluster_group(node_name=node_name)
        notification = Notifications()

        # Verifies the success notification after adding node into cluster group
        assert notification.successes[-1] == Messages.NotificationMessages.Agents.AgentCluster. \
            add_node_to_group, 'Success notification is missing or mismatch after adding node into cluster group.'

        cluster_node_list = ClusterNodeList()
        cluster_node_list.loaded()

        cluster_group_details = ClusterGroupAgentPage()
        cluster_group_details.agents_tab.click()
        wait(lambda: cluster_group_details.is_element_present('add_agents_button'), timeout_seconds=TIME_THIRTY_SECONDS)

        cluster_group_details.add_agent_member_to_cluster_group(member_agent_list=[agent_name])

        # Verifies the success notification after adding agent into cluster group
        assert notification.successes[-1] == Messages.NotificationMessages.Agents.AgentCluster. \
            add_agent_to_group, 'Success notification is missing or mismatch after adding node into cluster group.'

        agent_list = ClusterAgentList()
        agent_list.loaded()
        cluster_group_details.nodes_tab.click()
        cluster_node_list.loaded()

        cluster_node_list.delete_cluster_node(node_name=node_name)
        cluster_group_details.accept_action()

        # Verifying the error message when node is getting deleted from the cluster group for which agents are present.
        assert notification.errors[-1] == Messages.NotificationMessages.Agents.AgentCluster. \
            unable_to_delete_node_from_group, "Error notification is missing or mismatch when node is getting " \
                                              "deleted with agent is present in cluster group."

        wait(lambda: NodeDetailsPage().is_element_present('back_link'),
             waiting_for='to get disappear "Delete Cluster Node" modal')

        cluster_group_details.agents_tab.click()
        agent_list.loaded()

        move_agent_to_default_cluster_group(agent_list=[agent_name])

        # Verifies the success notification after moving node into cluster group
        assert notification.successes[-1] == Messages.NotificationMessages.Agents.AgentCluster. \
            move_agent_to_group, 'Success notification is missing or mismatch after moving agent into cluster group.'

        cluster_group_details.nodes_tab.click()
        cluster_node_list.loaded()

        self.move_node_and_back_to_cluster_group_list(node_name=node_name, group_name=create_cluster_group)

    @pytest.mark.xfail(reason='Refer Jira ID NES-12003')
    def test_verify_change_cluster_group_associated_with_node(self, create_cluster_group, create_manager_cluster):
        """
        NES-10266: UI Automation for cluster groups

        Scenario Tested:
            [x] Change the cluster group associated with cluster node.

        Steps:
        1. Go to cluster node page and change the cluster group from the node details page.
        2. verify that cluster group associated with node has been modified.
        """
        node_name = [node['name'] for node in create_manager_cluster['nodes']][0]

        ClusterGroupPage().open()
        cluster_group_list = ClusterGroupList()
        cluster_group_list.loaded()

        # Getting the current cluster group name associated with node.
        default_cluster_group_name = cluster_group_list.current_default_group_name()
        cluster_group_list.click_on_group(group_name=default_cluster_group_name)

        group_node_list = ClusterNodeList()
        group_node_list.loaded()
        group_node_list.click_on_node(node_name=node_name)

        node_details_page = NodeDetailsPage()
        wait(lambda: node_details_page.is_element_present('node_details_tab'))
        default_cluster_group_name = node_details_page.current_cluster_group_name.text
        node_details_page.change_cluster_group_for_node(cluster_group_name=create_cluster_group)

        notification = Notifications()

        # Verifies the success notification after changing cluster group into node
        assert notification.successes[-1] == Messages.NotificationMessages.Agents.AgentCluster. \
            move_node_to_group, 'Success notification is missing or mismatch after changing cluster group into node.'

        # Verifying that cluster group name associated with node has been changed
        assert create_cluster_group == node_details_page.current_cluster_group_name.text, \
            "Cluster group associated with node has not been changed."

        # Reverting back the default cluster group of node.
        node_details_page.change_cluster_group_for_node(cluster_group_name=default_cluster_group_name)

        # Verifies the success notification after changing cluster group into node
        assert notification.successes[-1] == Messages.NotificationMessages.Agents.AgentCluster. \
            move_node_to_group, 'Success notification is missing or mismatch after changing cluster group into node.'

    def test_verify_change_cluster_group_associated_with_agent(self, create_cluster_group, create_manager_cluster):
        """
        NES-10266: UI Automation for cluster groups

        Scenario Tested:
            [x] Change the cluster group associated with agent.

        Steps:
        1. Go to linked agents page and change the cluster group from the agent details page.
        2. verify that cluster group associated with agent has been modified.
        """
        node_name = [node['name'] for node in create_manager_cluster['nodes']][0]
        agent_name = [agent['name'] for agent in create_manager_cluster['agents']][0]
        NotificationActions().remove_all()

        add_node_to_cluster_group(node_name=node_name)
        notification = Notifications()

        # Verifies the success notification after adding node into cluster group
        assert notification.successes[-1] == Messages.NotificationMessages.Agents.AgentCluster. \
            add_node_to_group, 'Success notification is missing or mismatch after adding node into cluster group.'

        ClusterNodeList().loaded()
        SideNav().get_sidenav_element(Nessus.SideNavResources.LINKED_AGENTS).click()

        agent_list = AgentsList()
        agent_list.loaded()
        agent_list.click_on_agent(agent_name=agent_name)

        agent_detail_page = AgentDetail()
        wait(lambda: agent_detail_page.is_element_present('back_to_agent'))
        default_cluster_group_name = agent_detail_page.current_cluster_group_name.text
        agent_detail_page.change_cluster_group_for_agent(cluster_group_name=create_cluster_group)
        notification = Notifications()

        # Verifies the success notification after changing cluster group into node
        assert notification.successes[-1] == Messages.NotificationMessages.Agents.AgentCluster. \
            change_cluster_group, 'Success notification is missing or mismatch after changing cluster group into node.'

        # Verifying that cluster group name associated with agent has been changed
        assert create_cluster_group == agent_detail_page.current_cluster_group_name.text, \
            "Cluster group associated with agent has not been changed."

        # Reverting back the default cluster group of agent.
        agent_detail_page.change_cluster_group_for_agent(cluster_group_name=default_cluster_group_name)

        # Verifies the success notification after changing cluster group into node
        assert notification.successes[-1] == Messages.NotificationMessages.Agents.AgentCluster. \
            change_cluster_group, 'Success notification is missing or mismatch after changing cluster group into node.'

        self.move_node_and_back_to_cluster_group_list(node_name=node_name, group_name=create_cluster_group)

    def test_create_new_option_in_move_agent_modal(self, create_manager_cluster):
        """
        NES-11882: Automation: Verify 'Create new...' option is available in "Move Agent" modal

        Steps:
        1. Go to cluster groups page.
        2. Click on default cluster group and select node.
        3. Click on move button and verify that "Create new .. " button is available in the dropdown list.
        4. Go to agents tab and select an agent.
        5. Click on move button and verify that "Create new .. " button is not available in the dropdown list.
        """
        node_name = [node['name'] for node in create_manager_cluster['nodes']][0]
        agent_name = [agent['name'] for agent in create_manager_cluster['agents']][0]
        ClusterGroupPage().open()

        cluster_group_list = ClusterGroupList()
        cluster_group_list.loaded()

        default_cluster_group_name = cluster_group_list.current_default_group_name()
        cluster_group_list.click_on_group(group_name=default_cluster_group_name)

        group_node_list = ClusterNodeList()
        group_node_list.loaded()
        group_node_list.select_cluster_node(node_name=node_name)

        cluster_group_details = ClusterGroupDetails()
        wait(lambda: cluster_group_details.is_element_present('move_node_button'))

        cluster_group_details.move_node_button.click()
        wait(lambda: cluster_group_details.is_element_present('modal'), waiting_for='Move node modal to come')

        cluster_group_details.move_cluster_group_drop_down.click()
        all_options = [options['label'] for options in cluster_group_details.move_cluster_group_drop_down.option_values]

        assert Nessus.Agents.Cluster.CREATE_NEW_OPTION in all_options, \
            "'{}' option is not available in the dropdown modal".format(Nessus.Agents.Cluster.CREATE_NEW_OPTION)

        ActionCloseModal().close_button.click()

        cluster_group_details.agents_tab.click()
        agent_list = AgentsList()
        agent_list.loaded()

        group_agent_list = ClusterAgentList()
        group_agent_list.loaded()
        group_agent_list.select_cluster_agents(agents_list=[agent_name])
        wait(lambda: cluster_group_details.is_element_present('move_agent_button'))

        cluster_group_details.move_agent_button.click()
        wait(lambda: cluster_group_details.is_element_present('modal'), waiting_for='Move agent modal to come')

        cluster_group_details.move_cluster_group_drop_down.click()
        all_options = [options['label'] for options in cluster_group_details.move_cluster_group_drop_down.option_values]

        assert Nessus.Agents.Cluster.CREATE_NEW_OPTION not in all_options, \
            "'{}' option is not available in the dropdown modal".format(Nessus.Agents.Cluster.CREATE_NEW_OPTION)

    def test_create_cluster_group_with_invalid_value(self, create_manager_cluster):
        """
        NES-11883: Automation: Verify validation messages for creating new cluster group with invalid values

        Steps:
        1. Go to cluster groups page.
        2. Click on create new cluster group button and try to create with invalid data and verify error message.
        3. Click on default cluster group and select node -> click on move button and verify the error message after 
            creating the cluster group with invalid data using "Create new .. " button.
        """
        node_name = [node['name'] for node in create_manager_cluster['nodes']][0]
        cluster_group = ClusterGroupPage()
        cluster_group.open()

        cluster_group.new_group_button.click()
        cluster_group.group_name_field.clear()
        cluster_group.add_button.click()

        notification = Notifications()

        assert notification.errors[-1] == Messages.NotificationMessages.Agents.AgentCluster. \
            create_cluster_group_error, 'Error message is not present after invalid name entered while creating ' \
                                        'cluster group.'

        cluster_group.group_name_field.value = " "
        cluster_group.add_button.click()

        assert notification.errors[-1] == Messages.NotificationMessages.Agents.AgentCluster. \
            create_cluster_group_error, 'Error message is not present after invalid name entered while creating ' \
                                        'cluster group.'

        cluster_group.cancel_button.click()

        cluster_group_list = ClusterGroupList()
        cluster_group_list.loaded()

        default_cluster_group_name = cluster_group_list.current_default_group_name()
        cluster_group_list.click_on_group(group_name=default_cluster_group_name)

        group_node_list = ClusterNodeList()
        group_node_list.loaded()
        group_node_list.select_cluster_node(node_name=node_name)

        cluster_group_details = ClusterGroupDetails()
        wait(lambda: cluster_group_details.is_element_present('move_node_button'))

        cluster_group_details.move_node_button.click()
        wait(lambda: cluster_group_details.is_element_present('modal'), waiting_for='Move node modal to come')

        cluster_group_details.move_cluster_group_drop_down.click()
        all_options = [options['label'] for options in cluster_group_details.move_cluster_group_drop_down.option_values]

        assert Nessus.Agents.Cluster.CREATE_NEW_OPTION in all_options, \
            "'{}' option is not available in the dropdown modal".format(Nessus.Agents.Cluster.CREATE_NEW_OPTION)

        cluster_group_details.move_cluster_group_drop_down.click()
        cluster_group_details.move_cluster_group_drop_down.select_by_visible_text('Create new ...')
        cluster_group.group_name_field.clear()
        cluster_group.add_button.click()

        assert notification.errors[-1] == Messages.NotificationMessages.Agents.AgentCluster. \
            empty_cluster_group_name, 'Error message is not present after invalid name entered while creating ' \
                                      'cluster group.'

        cluster_group.group_name_field.value = " "
        cluster_group.add_button.click()

        assert notification.errors[-1] == Messages.NotificationMessages.Agents.AgentCluster. \
            empty_cluster_group_name, 'Error message is not present after invalid name entered while creating ' \
                                      'cluster group.'

    def test_verify_cluster_node_count_after_linking_and_unlinking(self):
        """
        NES-11884: Automation: Verify nodes count is getting updated after linked or unlinked the node.	

        Scenario Tested:
            [x] Nodes count on Agent Clustering page should get updated automatically when any child node is 
                linked/unlinked without refreshing the page

        Steps:
        1. Login into SM with valid credentials
        2. Navigate to Sensors > Agent Clustering page
        3. Now link the child node to SM parent node
        4. Observe Nodes count of default cluster group
        5. Refresh the page and observe node count  
        6. Now unlink the child node and observe node count on clustering page
        7. Refresh the page and observe
        """
        child_node_name = None

        cluster_group_page = ClusterGroupPage()
        cluster_group_page.open()

        cluster_group_list = ClusterGroupList()
        cluster_group_list.loaded()

        try:
            default_cluster_group_name = cluster_group_list.current_default_group_name()
            node_count_before_linking_node = get_linked_node_count(cluster_group_name=default_cluster_group_name)
            log.info("Node count before linking new node :: {}".format(node_count_before_linking_node))

            child_node = link_child_node_to_parent_node()
            child_node_name = child_node['name']
            wait(lambda: get_linked_node_count(
                cluster_group_name=default_cluster_group_name) > node_count_before_linking_node,
                 timeout_seconds=TIME_TWO_MINUTES, waiting_for='Node count takes little bit time to get updated')

            node_count_after_linked_node = get_linked_node_count(cluster_group_name=default_cluster_group_name)
            log.info("Node count after linking new node :: {}".format(node_count_after_linked_node))

            # Verifies that the agent cluster node count is not same to the node count we get after linking the node.
            assert not node_count_before_linking_node == node_count_after_linked_node, \
                'Agent cluster node count is getting same after linking the new node.'

            # Verifies the agent cluster node count is getting updated after linking the node
            assert node_count_after_linked_node == node_count_before_linking_node + 1, \
                'Agent cluster node count is not getting updated after linking the node.'

            linked_node_count_before_page_refresh = node_count_after_linked_node
            cluster_group_page.refresh()
            cluster_group_list.loaded()
            linked_node_count_after_page_refresh = get_linked_node_count(cluster_group_name=default_cluster_group_name)

            # Verifies that linked agent cluster node count remains same after refreshing the page
            assert linked_node_count_before_page_refresh == linked_node_count_after_page_refresh, \
                'Agent cluster node count does not remain same after refreshing the page.'

            log.info("Node count before unlinking the node :: {}".format(node_count_after_linked_node))
            unlink_child_node_from_parent_node(node_name=child_node_name)
            wait(lambda: get_linked_node_count(
                cluster_group_name=default_cluster_group_name) < node_count_after_linked_node,
                 timeout_seconds=TIME_TWO_MINUTES, waiting_for='Node count takes little bit time to get updated')

            node_count_after_unlinked_node = get_linked_node_count(cluster_group_name=default_cluster_group_name)
            log.info("Node count after unlinking the node :: {}".format(node_count_after_unlinked_node))

            # Verifies that the agent cluster node count is not same to the node count we get after unlinking the node.
            assert not node_count_after_unlinked_node == node_count_after_linked_node, \
                'Agent cluster node count is not equal to the node exists in the list after unlinking the node.'

            # Verifies the agent cluster node count is getting updated after unlinking the node
            assert node_count_after_unlinked_node == node_count_before_linking_node, \
                'Agent cluster node count is not getting updated after unlinking the node.'

            unlinked_node_count_before_page_refresh = node_count_after_unlinked_node
            cluster_group_page.refresh()
            cluster_group_list.loaded()
            unlinked_node_count_after_page_refresh = get_linked_node_count(
                cluster_group_name=default_cluster_group_name)

            # Verifies that unlinked agent cluster node count remains same after refreshing the page
            assert unlinked_node_count_before_page_refresh == unlinked_node_count_after_page_refresh, \
                'Agent cluster node count does not remain same after refreshing the page.'
        finally:
            unlink_child_node_from_parent_node(node_name=child_node_name)

    def test_linked_agent_count_after_change_the_cluster_group(self, create_cluster_group, create_manager_cluster):
        """
        NES-11913: Create test case to change agent's cluster group

        Scenario Tested:
            [x] Verify linked agent count from usage column after changing the cluster group.
        """
        created_cluster_group_name = create_cluster_group
        node_name = [node['name'] for node in create_manager_cluster['nodes']][-1]
        agent = [agent for agent in create_manager_cluster['agents']][-1]
        agent_name = agent['name']

        api = NessusAPI()
        api.login()

        subprocess.check_output("docker exec {} supervisorctl restart nessusd".format(
            api.agents.get_agent_details(agent['id'])['node_name']).split(), stderr=subprocess.PIPE).decode(
            'utf-8')

        # Wait till agent become online
        wait(lambda: api.agents.get_agent_details(agent['id'])['status'] == 'online',
             timeout_seconds=TIME_TEN_MINUTES * 2, sleep_seconds=TIME_THIRTY_SECONDS,
             waiting_for='Cluster agent to get online status!!')

        try:
            add_node_to_cluster_group(node_name=node_name)
            notification = Notifications()

            # Verifies the success notification after adding node into cluster group
            assert notification.successes[-1] == Messages.NotificationMessages.Agents.AgentCluster. \
                add_node_to_group, 'Success notification is missing or mismatch after adding node into cluster group.'

            cluster_node_list = ClusterNodeList()
            cluster_node_list.loaded()

            side_nav = SideNav()
            side_nav.get_sidenav_element(element_name=Nessus.SideNavResources.AGENT_CLUSTERING).click()

            cluster_group_list = ClusterGroupList()
            cluster_group_list.loaded()

            cluster_group_list.click_on_group(group_name=created_cluster_group_name)
            cluster_node_list.loaded()

            def wait_until_count_get_updated(expected_count: int):
                log.info("Linked agent count is not getting updated yet to {}...".format(expected_count))
                if cluster_node_list.get_node_usage_count(node_name=node_name) == expected_count:
                    return True

                cluster_node_list.refresh()
                cluster_node_list.loaded()

            wait(lambda: wait_until_count_get_updated(expected_count=0), waiting_for='linked agent count get updated',
                 timeout_seconds=TIME_TEN_MINUTES, sleep_seconds=TIME_FIVE_SECONDS)

            current_node_usage_count = cluster_node_list.get_node_usage_count(node_name=node_name)
            log.info("Node usage count before agent moved :: {}".format(current_node_usage_count))

            # Verifies that linked agent count from node usage column is 0 when agent is not present in group
            assert current_node_usage_count == 0, \
                'Linked agent count from node usage column is not getting 0 when agent is not present in group.'

            cluster_group_details = ClusterGroupAgentPage()
            cluster_group_details.agents_tab.click()
            wait(lambda: cluster_group_details.is_element_present('add_agents_button'),
                 timeout_seconds=TIME_THIRTY_SECONDS)

            cluster_group_details.add_agent_member_to_cluster_group(member_agent_list=[agent_name])

            # Verifies the success notification after adding agent into cluster group
            assert notification.successes[-1] == Messages.NotificationMessages.Agents.AgentCluster. \
                add_agent_to_group, 'Success notification is missing or mismatch after adding node into cluster group.'

            ClusterAgentList().loaded()
            side_nav.get_sidenav_element(element_name=Nessus.SideNavResources.AGENT_CLUSTERING).click()

            cluster_group_list.loaded()
            cluster_group_list.click_on_group(group_name=created_cluster_group_name)
            cluster_node_list.loaded()

            wait(lambda: wait_until_count_get_updated(expected_count=1), waiting_for='linked agent count get updated',
                 timeout_seconds=TIME_TWO_MINUTES, sleep_seconds=TIME_FIVE_SECONDS)

            node_usage_count_after_agent_moved_to_group = cluster_node_list.get_node_usage_count(node_name=node_name)
            log.info("Node usage count after agent moved :: {}".format(node_usage_count_after_agent_moved_to_group))

            # NOTE :: Below two assert verifies on cluster node list
            # Verifies that used percentage is displayed as blue color in node usage column chart
            assert cluster_node_list.is_element_present('node_usage_percentage'), \
                'Node usage percentage is not getting displayed in node usage column chart.'

            # Verifies that linked agent count in node usage column is getting updated after moving agent into group
            assert node_usage_count_after_agent_moved_to_group == current_node_usage_count + 1, \
                'Linked agent count in node usage column is not getting updated after moving agent into group.'

            cluster_group_details.back_to_cluster_group_link.click()
            ClusterGroupList().loaded()

            # NOTE :: Below two assert verifies on cluster group page
            # Verifies that used percentage is displayed as blue color in node usage column chart
            assert cluster_node_list.is_element_present('node_usage_percentage'), \
                'Node usage percentage is not getting displayed in node usage column chart.'

            # Verifies that linked agent count in node usage column is getting updated after moving agent into group
            assert node_usage_count_after_agent_moved_to_group == current_node_usage_count + 1, \
                'Linked agent count in node usage column is not getting updated after moving agent into group.'
        finally:
            move_agent_to_default_cluster_group(agent_list=[agent_name], cluster_group_name=created_cluster_group_name)

            notification = Notifications()

            # Verifies the success notification after moving node into cluster group
            assert notification.successes[-1] == Messages.NotificationMessages.Agents.AgentCluster. \
                move_agent_to_group, 'Success notification is missing or mismatch after moving agent into cluster group'

            self.move_node_and_back_to_cluster_group_list(node_name=node_name, group_name=created_cluster_group_name)


@pytest.mark.parametrize('create_manager_cluster', [{'total_nodes': 1, 'total_agents': 1}], indirect=True)
@pytest.mark.usefixtures('create_manager_cluster', 'login')
@pytest.mark.cluster_manager
class TestClusterGroupsReOrg:
    """ Test cases to cover UI functionality related to cluster group reorg(NES-10440) """

    def test_verify_cluster_group_list_columns(self):
        """
        NES-10440: UI test for NES-10325 Clustering UI reorg

        Scenario Tested:
            [x] Verify that columns of cluster group list.

        Steps:
        1. Go to cluster groups page.
        2. Verify that all required columns are visible on cluster group list page.
        """
        ClusterGroupPage().open()
        cluster_group_list = ClusterGroupList()
        cluster_group_list.loaded()
        column_names = [column_name.text for column_name in cluster_group_list.columns]

        # Verify Cluster group table's columns
        assert all([column_name in column_names for column_name in Nessus.Scan.Results.
                   ClusterGroupTable.COLUMN_NAMES]), "Cluster group table does not have one or more columns."

    def test_verify_visibility_of_cluster_tab_on_side_navigation(self):
        """
        NES-10440: UI test for NES-10325 Clustering UI reorg

        Scenario Tested:
            [x] Verify that cluster tab is visible on side navigation.

        Steps:
        1. Go to cluster groups page.
        2. Verify that cluster tab is visible on side navigation.
        """
        header_page = HeaderBasePage()
        wait(lambda: header_page.is_element_present('sensors_tab'), timeout_seconds=TIME_THIRTY_SECONDS,
             waiting_for='Sensors tab to appear on Nessus main page headers')

        header_page.sensors_tab.click()

        # Verify that "Agent clustering" tab is present on side navigation.
        try:
            wait(lambda: Nessus.SideNavResources.AGENT_CLUSTERING in SideNav().get_all_sidenav_links())
        except TimeoutExpired:
            raise AssertionError("Agent clustering tab is not visible.")

    def test_verify_visibility_of_elements_on_cluster_groups_page(self):
        """
        NES-10440: UI test for NES-10325 Clustering UI reorg

        Scenario Tested:
            [x] Verify that node linking key is present and not empty on cluster group page.

        Steps:
        1. Go to cluster groups page.
        2. Verify that node linking key is present and not empty on cluster group page.
        """
        ClusterGroupPage().open()

        # Verify cluster group page elements
        verify_cluster_group_page_elements()

    def test_verify_navigation_to_node_and_agent_details_from_cluster_group(self, create_manager_cluster):
        """
        NES-10440: UI test for NES-10325 Clustering UI reorg

        Scenario Tested:
            [x] Verify that user can navigate to node and agent details from the cluster group page.

        Steps:
        1. Go to cluster groups page.
        2. Click on cluster group.
        3. Click on each node and verify that it navigates to node details.
        4. Go to agents tab.
        5. click on each agent and verify that it navigates to agent details.
        """
        ClusterGroupPage().open()
        cluster_group_list = ClusterGroupList()
        cluster_group_list.loaded()
        default_cluster_group_name = cluster_group_list.current_default_group_name()

        # Verify that default cluster group is present on cluster group page.
        assert default_cluster_group_name, "Default cluster group is not present on cluster group list."

        cluster_group_list.click_on_group(group_name=default_cluster_group_name)

        cluster_group_details = ClusterGroupAgentPage()
        node_details_page = NodeDetailsPage()

        for node_name in [node['name'] for node in create_manager_cluster['nodes']]:
            wait(lambda: cluster_group_details.is_element_present('node_usage_header'))
            node_list = ClusterNodeList()
            node_list.loaded()
            node_list.click_on_node(node_name=node_name)
            wait(lambda: node_details_page.is_element_present('back_link'))

            # Verify that user navigated to node details page.
            assert all([node_details_page.node_details_tab.is_displayed(),
                        node_details_page.settings_tab.is_displayed()]), \
                "User does not navigate to node details page after clicking on node from cluster group details."

            # On node details page, verify that cluster group associated with node is correct.
            assert node_details_page.current_cluster_group_name.text == default_cluster_group_name, \
                "Cluster group associated with node is not correct."

            node_details_page.back_link.click()

        wait(lambda: cluster_group_details.is_element_present('agents_tab'))
        cluster_group_details.agents_tab.click()

        agent_detail_page = AgentDetail()
        agent_list = AgentsList()

        for agent_name in [agent['name'] for agent in create_manager_cluster['agents']]:
            wait(lambda: cluster_group_details.is_element_present('agent_ip_header'))
            agent_list.loaded()
            agent_list.click_on_agent(agent_name=agent_name)
            wait(lambda: agent_detail_page.is_element_present('back_to_agent'))

            # Verify that user navigated to agent details page.
            assert cluster_group_details.agent_details_tab.is_displayed(), \
                "User does not navigate to agent details page after clicking on agent from cluster group details."

            # On agent details page, verify that cluster group associated with agent is correct.
            assert agent_detail_page.current_cluster_group_name.text == default_cluster_group_name, \
                "Cluster group associated with agent is not correct."

            agent_detail_page.back_to_agent.click()


@pytest.mark.parametrize('create_manager_cluster', [{'total_nodes': 1, 'total_agents': 0}], indirect=True)
@pytest.mark.usefixtures('create_manager_cluster', 'login')
@pytest.mark.cluster_manager
class TestVisibilityOfClusterGroupForDiffUserTypes:
    """ 'Sensors' tab and Cluster group's visibility related tests for Basic/Standard and Administrator user."""

    @pytest.mark.parametrize("create_user", [{'username': random_name(prefix=API.User.Users.BASIC_USER + ' - '),
                                              'full_name': 'Basic user', 'email': API.User.Users.TEST_EMAIL,
                                              'password': 'admin', 'role': API.User.Role.BASIC, 'do_login': True},
                                             {'username': random_name(prefix=API.User.Users.STANDARD_USER + ' - '),
                                              'full_name': 'Standard user', 'email': API.User.Users.TEST_EMAIL,
                                              'password': 'admin', 'role': API.User.Role.STANDARD,
                                              'do_login': True}], indirect=True)
    def test_sensor_tab_invisibility_for_basic_and_standard_user(self, create_user):
        """
        NES-12058: UI automation to cover functionality mentioned in NES-12033 and NES-12032
        Scenarios Tested:
                [x] Verify that "Basic" and "Standard" user not able to see "Sensors" tab on Nessus main page.
        """
        log.info("User has been created : {}".format(create_user[0]))
        header_page = HeaderBasePage()
        wait(lambda: header_page.is_element_present('scan_link'), timeout_seconds=TIME_THIRTY_SECONDS,
             waiting_for='Sensors tab to appear on Nessus main page headers')
        assert not header_page.is_element_present('sensors_tab'), \
            "Sensor tab is visible for : {}".format(create_user[0])

    @pytest.mark.parametrize("create_user", [{'username': random_name(prefix=API.User.Users.ADMIN_USER + ' - '),
                                              'full_name': 'Administrator user', 'email': API.User.Users.TEST_EMAIL,
                                              'password': 'admin', 'role': API.User.Role.ADMIN,
                                              'do_login': True}], indirect=True)
    def test_verify_basic_cluster_group_features_for_administrator_user(self, create_user):
        """
        NES-12058: UI automation to cover functionality mentioned in NES-12033 and NES-12032
        Scenarios Tested:
                [x] Verify that "Administrator" user can navigate to Sensors tab and
                    all cluster group page web-elements is visible on UI
        Steps:
            1. Verify that "Sensors" tab is visible to "Administrator" user.
            2. Go to cluster group page.
            3. Verify that all necessary web-elements are present on cluster group page.
            4. Verify that "Administrator" user can add a cluster group without any errors.
        """
        log.info("User has been created : {}".format(create_user[0]))
        header_page = HeaderBasePage()
        wait(lambda: header_page.is_element_present('scan_link'), timeout_seconds=TIME_THIRTY_SECONDS,
             waiting_for='Sensors tab to appear on Nessus main page headers')

        # Verify that "Sensor" tab is visible for "Administrator" user.
        assert header_page.is_element_present('sensors_tab'), \
            "Sensor tab is not visible for : {}".format(create_user[0])
        header_page.sensors_tab.click()
        side_nav = SideNav()
        # Verify that "Agent clustering" tab is present on side navigation for "Administrator" user.
        try:
            wait(lambda: Nessus.SideNavResources.AGENT_CLUSTERING in side_nav.get_all_sidenav_links())
        except TimeoutExpired:
            raise AssertionError("Agent clustering tab is not visible for {}".format(create_user[0]))
        side_nav.click_by_link_text(Nessus.SideNavResources.AGENT_CLUSTERING)

        # Verify that all necessary elements are present in cluster group page.
        verify_cluster_group_page_elements()
        cluster_group_list = ClusterGroupList()

        # Verify that "Administrator" user can add cluster group successfully.
        with new_cluster_group() as cluster_group_name:
            ClusterGroupPage().open()
            cluster_group_list.loaded()
            assert cluster_group_name in cluster_group_list.get_all_group_names(), \
                "Administrator user is not able to create custom cluster group."


@pytest.mark.cluster_manager
@pytest.mark.usefixtures('nessus_api_login', 'login')
@pytest.mark.parametrize('create_manager_cluster', [{'total_nodes': 1, 'total_agents': 0}], indirect=True)
class TestVPRTabInClusterAgentScan:
    """ Tests related to VPR Top Threats tab in cluster agent scan result page """

    cat = None

    @pytest.mark.usefixtures('link_agent_to_cluster')
    @pytest.mark.parametrize('scan_data_file', [
        (get_file_path('nessus/tests/api/scan/test_data/test_advanced_agent_scan.json'), 'agent_advanced')])
    def test_vpr_tab_not_present_in_agent_scan_for_clustered_manager(self, create_manager_cluster,
                                                                     link_agent_to_cluster, scan_data_file):
        """
        NES-12709: [UI-Automation] Verify VPR details should NOT be visible for Agent scans in Clustered and 
                    Non-Clustered NM

        Scenario Tested:
        [x] Verify that VPR Top Threats tab should not be present in agent scan for clustered NM.
        """
        agent_scan = create_scan_helper(api_handler=self.cat.api, file_name=scan_data_file[0],
                                        template_title=scan_data_file[1], change_scan_name=True,
                                        **{'agent_name': link_agent_to_cluster['agent_name'],
                                           'agent_status_check': False})[0]

        scan_id, scan_name = agent_scan['scan']['id'], agent_scan['scan']['name']

        try:
            scan_list = ScanList()
            scan_list.refresh()
            scan_list.loaded()

            self.cat.api.scans.launch(scan_id=scan_id)
            wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                            timeout=TIME_THIRTY_MINUTES)

            scan_list.click_on_scan(scan_name=scan_name)

            scan_view_page = ScanViewPage()
            wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
                 waiting_for='Vulnerabilities to get loads')

            assert not scan_view_page.is_element_present('threat_level_tab'), \
                "'VPR Top Threats' tab is present in scan results."
        finally:
            self.cat.api.scans.delete(scan_id=scan_id)

    @pytest.mark.parametrize('scan_data_file', [
        (get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'), 'advanced')])
    def test_vpr_tab_should_be_visible_in_normal_scan_for_clustered_manager(self, create_manager_cluster,
                                                                            scan_data_file):
        """
        NES-12746: Verify in clustered NM, VPR Top Threats should be displayed for non-agent scans

        Scenario Tested:
        [x] Verify that VPR Top Threats tab should be present in a normal scan for clustered NM.
        """
        non_agent_scan = create_scan_helper(api_handler=self.cat.api, file_name=scan_data_file[0],
                                            template_title=scan_data_file[1], change_scan_name=True)[0]

        scan_id, scan_name = non_agent_scan['scan']['id'], non_agent_scan['scan']['name']

        try:
            scan_list = ScanList()
            scan_list.refresh()
            scan_list.loaded()

            self.cat.api.scans.launch(scan_id=scan_id)
            wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                            timeout=TIME_THIRTY_MINUTES)

            scan_list.click_on_scan(scan_name=scan_name)

            scan_view_page = ScanViewPage()
            wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
                 waiting_for='Vulnerabilities to get loads')

            # Verify that threat level tab is present on scan results
            assert scan_view_page.is_element_present('threat_level_tab'), \
                "Threat level tab is not present in scan result."

            scan_view_page.threat_level_tab.click()
            wait(lambda: visibility_of_element_located(scan_view_page.threat_level_description),
                 waiting_for='Threat level tab to get loaded')

            # Verify that threat level tab description is correct.
            assert scan_view_page.threat_level_description[0].text.split(':')[0] == Nessus.Scan.Results. \
                ThreatLevelTab.ASSESSED_THREAT, "Threat Level description title is incorrect."

            assert scan_view_page.threat_level_description[1].text == Nessus.Scan.Results.ThreatLevelTab. \
                THREAT_LEVEL_DESCRIPTION, "Threat Level description is incorrect"

            assert scan_view_page.is_element_present("threat_level_icon"), \
                "Threat level icon is missing in description."

            threat_level_vulnerability_list = ThreatLevelVulnerabilityList()

            # Verify that total vulnerabilities on threat level tab are less than ten.
            assert threat_level_vulnerability_list.get_total_rows() <= 10, \
                "Total vulnerabilities on threat level tab are more than ten."

            assert Nessus.Scan.Severity.INFO.upper() not in threat_level_vulnerability_list.get_plugin_vpr_severity(), \
                "Info severity level vulnerabilities are getting listed in VPR Top Threats table."

            HeaderBasePage().scan_link.click()
        finally:
            self.cat.api.scans.delete(scan_id=scan_id)


@pytest.mark.cluster_manager
@pytest.mark.usefixtures('login')
class TestAdvancedSettingClusterTab:
    """ Tests related to settings available under Cluster tab in Advanced settings """

    @staticmethod
    def verify_error_notification_for_min_and_max_value_limitation(setting_name: str, setting_value: int,
                                                                   expected_error_msg: str) -> None:
        """
        Verifies the error notification message by entering invalid min or max value for the setting available under
        "Cluster" tab.

        :param str setting_name: Name of the setting available under "Cluster" tab
        :param int setting_value: Value of given setting
        :param str expected_error_msg: Error notification message
        :return: None
        """
        AdvancedSettingsPage().open()
        wait(lambda: AdvancedSettingsList().is_element_present("user_interface_tab"),
             waiting_for="User Interface tab to be visible")

        advanced_setting_modal = AddAdvancedSettingModal()
        advanced_setting_modal.fill_existing_setting_banner(setting_name=setting_name, setting_value=str(setting_value),
                                                            setting_tab=Nessus.AdvancedSettings.CLUSTER_TAB)

        notifications = Notifications()

        assert notifications.errors[-1] == expected_error_msg, \
            "Error notification is missing for invalid value for '{}' setting identifier.".format(setting_name)

        advanced_setting_modal.cancel_button.click()

    def test_verify_cluster_tab_is_showing_in_advanced_setting_after_enabling_cluster(self):
        """
        NES-13024: [Automation]: Verify max value limitation for the settings available under cluster tab

        Scenario Tested:
        [x] Verify that "Cluster" tab is appear in Advanced settings after enabling cluster.
        """
        HeaderBasePage().sensors_tab.click()

        side_nav = SideNav()
        wait(lambda: side_nav.get_sidenav_element(element_name=Nessus.SideNavResources.AGENT_CLUSTERING),
             waiting_for="'Agent Clustering' tab to get loaded")

        side_nav.get_sidenav_element(element_name=Nessus.SideNavResources.AGENT_CLUSTERING).click()
        agent_cluster_migration = AgentClusterMigration()

        if agent_cluster_migration.is_element_present("enable_cluster_checkbox"):
            assert all([agent_cluster_migration.is_element_present("cluster_migration_link"),
                        agent_cluster_migration.is_element_present("enable_cluster_checkbox"),
                        agent_cluster_migration.is_element_present("save_button")]), \
                "Required elements are missing on Cluster setup page."

            agent_cluster_migration.enable_cluster_checkbox.check()
            agent_cluster_migration.save_button.click()
            save_agent_setting_modal = ActionCloseModal()

            assert all([save_agent_setting_modal.modal_title.text == "Save Agent Settings",
                        save_agent_setting_modal.modal_content.text == Nessus.Agents.Cluster.ENABLE_CLUSTER_WARNING,
                        save_agent_setting_modal.is_element_present("action_button"),
                        save_agent_setting_modal.is_element_present("cancel_button")]), \
                "'Save Agent Settings' modal is missing or getting invalid modal."

            save_agent_setting_modal.accept_action()
            save_agent_setting_modal.wait_for_modal_closed()

            wait_for_scanner_to_be_ready(api=NessusAPI())
            login_helper_after_server_restart()
        else:
            log.warning("Cluster mode is enabled already.")

        advanced_setting_page = AdvancedSettingsPage()
        advanced_setting_page.open()
        wait(lambda: AdvancedSettingsList().is_element_present("user_interface_tab"),
             waiting_for="User Interface tab to be visible")

        cluster_tab_element = advanced_setting_page.get_settings_tab_element(
            setting_tab=Nessus.AdvancedSettings.CLUSTER_TAB)

        assert visibility_of_element_located((cluster_tab_element.we_by, cluster_tab_element.we_value))(
            get_driver_no_init()), "'Cluster' tab is missing in advanced settings after enabling cluster."

    @pytest.mark.parametrize('setting_identifier', ['agent_cluster_scan_cutoff', 'agent_blacklist_duration_days'])
    def test_max_value_limitation_for_settings_available_under_cluster_tab_in_advanced_settings(
            self, setting_identifier):
        """
        NES-13024: [Automation]: Verify max value limitation for the settings available under cluster tab

        Scenario Tested:
        [x] Verify that 'agent_cluster_scan_cutoff' setting does not allow the value more than 2147483647.
        [x] Verify that 'agent_blacklist_duration_days' setting does not allow the value more than 2147483647.
        """
        invalid_setting_value = randint(2147483648, 10000000000)

        self.verify_error_notification_for_min_and_max_value_limitation(
            setting_name=setting_identifier, setting_value=invalid_setting_value,
            expected_error_msg=Messages.NotificationMessages.Agents.AgentCluster.max_scan_cutoff_value_error)

    def test_agent_node_global_max_default_setting_does_not_allow_the_value_more_than_20000(self):
        """
        NES-13024: [Automation]: Verify max value limitation for the settings available under cluster tab

        Scenario Tested:
        [x] Verify that 'agent_node_global_max_default' setting does not allow the value more than 20000.
        """
        invalid_setting_value = randint(20001, 100000)

        self.verify_error_notification_for_min_and_max_value_limitation(
            setting_name='agent_node_global_max_default', setting_value=invalid_setting_value,
            expected_error_msg=Messages.NotificationMessages.Agents.AgentCluster.max_global_agent_node_error)

    def test_agent_cluster_scan_cutoff_setting_does_not_allow_the_value_less_than_300(self):
        """
        NES-13024: [Automation]: Verify max value limitation for the settings available under cluster tab

        Scenario Tested:
        [x] Verify that 'agent_cluster_scan_cutoff' setting does not allow the value less than 300.
        """
        invalid_setting_value = randint(1, 299)

        self.verify_error_notification_for_min_and_max_value_limitation(
            setting_name='agent_cluster_scan_cutoff', setting_value=invalid_setting_value,
            expected_error_msg=Messages.NotificationMessages.Agents.AgentCluster.min_scan_cutoff_value_error)

    @pytest.mark.parametrize('setting_identifier', ['agent_cluster_scan_cutoff', 'agent_blacklist_duration_days',
                                                    'agent_node_global_max_default'])
    def test_cluster_tab_settings_shows_default_values_after_resetting(self, setting_identifier):
        """
        NES-13024: [Automation]: Verify max value limitation for the settings available under cluster tab

        Scenario Tested:
        [x] Verify that settings available under "Cluster" tab are showing default value after resetting.
        """
        settings_details = {
            "agent_cluster_scan_cutoff": {"random_value": randint(301, 2147483646), "default_value": 3600},
            "agent_blacklist_duration_days": {"random_value": randint(1, 2147483646), "default_value": 7},
            "agent_node_global_max_default": {"random_value": randint(1, 19999), "default_value": 10000}}

        AdvancedSettingsPage().open()
        advanced_setting_list = AdvancedSettingsList()
        wait(lambda: advanced_setting_list.is_element_present("user_interface_tab"),
             waiting_for="User Interface tab to be visible")

        advanced_setting_modal = AddAdvancedSettingModal()
        advanced_setting_modal.fill_existing_setting_banner(
            setting_name=setting_identifier, setting_value=str(settings_details[setting_identifier]["random_value"]),
            setting_tab=Nessus.AdvancedSettings.CLUSTER_TAB)

        notifications = Notifications()

        assert notifications.successes[-1] == Messages.NotificationMessages.save_settings, \
            "Success notification is missing for '{}' setting identifier.".format(setting_identifier)

        sleep(WAIT_NORMAL, reason="It takes little bit time to get reflected the saved value")
        expected_setting_value = int(advanced_setting_list.get_settings_value(setting_name=setting_identifier)[0])

        assert expected_setting_value == settings_details[setting_identifier]["random_value"], \
            "It does not showing the value we set for '{}' setting identifier.".format(setting_identifier)

        advanced_setting_modal.reset_setting_banner(setting_name=setting_identifier)
        advanced_setting_modal.wait_for_modal_closed()

        sleep(WAIT_NORMAL, reason="It takes little bit time to get reflected the 'Default' value")
        setting_value_after_reset = int(advanced_setting_list.get_settings_value(setting_name=setting_identifier)[0])

        assert setting_value_after_reset == settings_details[setting_identifier]["default_value"], \
            "It does not showing the 'Default' value after resetting for '{}' setting identifier.".format(
                setting_identifier)
