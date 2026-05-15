"""
Agent Cluster group related Helpers

:copyright: Tenable Network Security, 2020
:date: Aug 07, 2020
:last_modified: Sept 29, 2020
:author: @kpanchal
"""
import subprocess

from contextlib import contextmanager

from selenium.webdriver.support.expected_conditions import visibility_of_element_located

from catium.lib.log.log import create_logger
from catium.lib.util.util import random_name
from catium.lib.webium.driver import get_driver
from catium.lib.webium.wait import wait
from nessus.helpers.nessuscli.helper import get_nessus_cli
from nessus.pageobjects.agents.agents_page import AgentsList
from nessus.pageobjects.cluster.cluster_agent_page import ClusterAgentList
from nessus.pageobjects.cluster.cluster_group_page import ClusterGroupList, ClusterGroupPage, ClusterGroupDetails, \
    ClusterGroupAgentPage
from nessus.pageobjects.cluster.cluster_nodes_page import ClusterNodeList
from nessus.pageobjects.generic.generic_modals import ActionCloseModal

log = create_logger()


def navigate_to_cluster_group(cluster_group_name: str) -> None:
    """
    This function will navigate to cluster group

    :param str cluster_group_name: Name of cluster group.
    :return: None
    """
    cluster_group_list = ClusterGroupList()

    if not get_driver().current_url.endswith('sensors/agent-cluster-groups'):
        ClusterGroupPage().open()
        cluster_group_list.loaded()

    cluster_group_list.click_on_group(group_name=cluster_group_name)
    wait(lambda: ClusterGroupDetails().is_element_present('nodes_tab'))


def delete_node_from_the_cluster_group(node_name: str, cluster_group_name: str = '') -> None:
    """
    This function will delete node from the cluster group.

    :param str node_name: Name of node which is to be deleted.
    :param str cluster_group_name: Name of cluster group.
    :return: None
    """
    cluster_node_list = ClusterNodeList()

    if cluster_group_name:
        navigate_to_cluster_group(cluster_group_name=cluster_group_name)
        cluster_node_list.loaded()

    cluster_node_list.delete_cluster_node(node_name=node_name)
    delete_node_modal = ActionCloseModal()
    delete_node_modal.accept_action()
    delete_node_modal.wait_for_modal_closed()


def add_node_to_cluster_group(node_name: str, cluster_group_name: str = '') -> None:
    """
    This function will assign node to the cluster group

    :param str node_name: Name of node which is to be added to cluster group.
    :param str cluster_group_name: Name of cluster group.
    :return: None
    """
    cluster_group_details = ClusterGroupDetails()

    if cluster_group_name:
        navigate_to_cluster_group(cluster_group_name=cluster_group_name)
        wait(lambda: cluster_group_details.is_element_present('add_node_button'))

    cluster_group_details.add_node_button.click()
    wait(lambda: cluster_group_details.is_element_present('member_nodes'))
    cluster_group_details.get_member_node_element(member_node_name=node_name).click()
    cluster_group_details.accept_action()


def delete_agent_from_cluster_group(agent_name: str, cluster_group_name: str = '') -> None:
    """
    This function will delete agent from the cluster group

    :param str agent_name: Name of agent which is to be deleted from cluster group.
    :param str cluster_group_name: Name of cluster group.
    :return: None
    """
    cluster_group_details = ClusterGroupAgentPage()

    if cluster_group_name:
        navigate_to_cluster_group(cluster_group_name=cluster_group_name)

        cluster_group_details.agents_tab.click()
        wait(lambda: cluster_group_details.is_element_present('add_agents_button'))

    AgentsList().delete_agent(agent_name=agent_name)
    action_modal = ActionCloseModal()
    action_modal.accept_action()
    action_modal.wait_for_modal_closed()
    wait(lambda: cluster_group_details.is_element_present('nodes_tab'))


def move_node_to_default_cluster_group(node_name: str, cluster_group_name: str = None) -> None:
    """
    This function will move the node from custom cluster group to the default cluster group

    :param str node_name: Name of node which is to be moved to default cluster group.
    :param str cluster_group_name: Name of cluster group.
    :return: None
    """
    group_node_list = ClusterNodeList()
    cluster_group_details = ClusterGroupDetails()

    if cluster_group_name:
        navigate_to_cluster_group(cluster_group_name=cluster_group_name)
        cluster_group_details.nodes_tab.click()
        group_node_list.loaded()

    group_node_list.select_cluster_node(node_name=node_name)
    wait(lambda: visibility_of_element_located(cluster_group_details.move_node_button),
         waiting_for='Move button to display after clicking on node')

    cluster_group_details.move_node_button.click()
    wait(lambda: cluster_group_details.is_element_present('modal'), waiting_for='Move node modal to come')

    cluster_group_details.move_cluster_group_drop_down.select_by_visible_text("Default Cluster Group")
    cluster_group_details.accept_action()


def move_agent_to_default_cluster_group(agent_list: list, cluster_group_name: str = None,
                                        select_all: bool = False) -> None:
    """
    This function will move the agent from custom cluster group to the default cluster group

    :param str agent_list: list of agent which is to be moved to default cluster group.
    :param str cluster_group_name: Name of cluster group.
    :param bool select_all: Select all agents if True else False
    :return: None
    """
    group_agent_list = ClusterAgentList()
    cluster_group_details = ClusterGroupDetails()

    if cluster_group_name:
        navigate_to_cluster_group(cluster_group_name=cluster_group_name)
        ClusterNodeList().loaded()

        cluster_group_details.agents_tab.click()
        group_agent_list.loaded()

    group_agent_list.select_all_checkbox.check() if select_all else group_agent_list.select_cluster_agents(
        agents_list=agent_list)
    wait(lambda: visibility_of_element_located(cluster_group_details.move_agent_button),
         waiting_for='Move button to display after clicking on node')

    cluster_group_details.move_agent_button.click()
    wait(lambda: cluster_group_details.is_element_present('modal'), waiting_for='Move agent modal to come')

    cluster_group_details.move_cluster_group_drop_down.select_by_visible_text("Default Cluster Group")
    cluster_group_details.accept_action()


def unlink_child_node_from_parent_node(node_name: str):
    """ Unlink child cluster node from parent node """

    cmnd = 'docker exec {} {} node unlink --force'.format(node_name, get_nessus_cli())

    try:
        log.debug("Executing: %s" % cmnd)
        subprocess.check_output(cmnd.split(), stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        log.error("Error, code %s" % e.returncode)
        stdout = e.output.decode('utf-8')
        stderr = e.stderr.decode('utf-8')

        if stdout:
            log.error(stdout)
            return stdout
        if stderr:
            log.error(stderr)


def move_agents_to_other_cluster_group(cluster_group_name: str) -> None:
    """
    This method will move already selected agents to given cluster group.
    :param cluster_group_name: Name of cluster group where agents to be moved!!
    :return: None
    """
    cluster_group_details = ClusterGroupAgentPage()
    cluster_group_details.move_agent_button.click()
    wait(lambda: cluster_group_details.is_element_present('modal'), waiting_for='Move agent modal to come')

    cluster_group_details.move_cluster_group_drop_down.select_by_visible_text(cluster_group_name)
    cluster_group_details.accept_action()
    cluster_group_details.wait_for_modal_closed()
    wait(lambda: ClusterGroupDetails().is_element_present('agents_tab'))


def get_linked_node_count(cluster_group_name: str) -> int:
    """
    Returns node count of given cluster group after linking or unlinking

    :param str cluster_group_name: cluster group name
    :return: node count
    :rtype: int
    """
    return ClusterGroupList().get_number_of_nodes_for_agent_group(group_name=cluster_group_name)


@contextmanager
def new_cluster_group()-> str:
    """
    This context manager will add a cluster group.
    :return: new cluster group name
    :rtype: str
    """
    cluster_group_name = random_name(prefix="cluster-group-")
    cluster_group = ClusterGroupPage()
    cluster_group_list = ClusterGroupList()

    if not get_driver().current_url.endswith('sensors/agent-cluster-groups'):
        cluster_group.open()
        cluster_group_list.loaded()
    cluster_group.new_group_button.click()
    cluster_group.group_name_field.value = cluster_group_name
    cluster_group.add_button.click()
    wait(lambda: ClusterGroupDetails().is_element_present('add_node_button'))
    log.info("New cluster group has been created successfully : {}".format(cluster_group_name))
    yield cluster_group_name

    if not get_driver().current_url.endswith('sensors/agent-cluster-groups'):
        cluster_group.open()
        cluster_group_list.loaded()
    cluster_group_list.delete_cluster_group(group_name=cluster_group_name)
    action_modal = ActionCloseModal()
    action_modal.accept_action()
    action_modal.wait_for_modal_closed()
