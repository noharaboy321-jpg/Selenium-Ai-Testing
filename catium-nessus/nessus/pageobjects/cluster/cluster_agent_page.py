"""
Nessus page object classes for cluster agent page

:copyright: Tenable Network Security, 2020
:date: Aug 14, 2020
:last_modified: Aug 24, 2020
:author: @kpanchal
"""
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
from waiting import wait

from catium.lib import const
from catium.lib.cat_registry import cat_registry
from catium.lib.log import create_logger
from catium.lib.webium import Find
from catium.lib.webium.controls.checkbox import Checkbox
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.link import Link
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.table import GenericTableRow
from catium.lib.webium.controls.text_field import TextField
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.generic.agent_object_list import AgentObjectList
from nessus.pageobjects.generic.generic_modals import ActionCloseModal

log = create_logger()


@cat_registry.route(r'sensors/agent-cluster-migration')
class AgentClusterMigration(NessusBasePage):
    """ Page class for Agent cluster Migration """

    settings_tab = Find(Clickable, by=By.CSS_SELECTOR, value='#tabs a[data-name="Cluster Settings"]')
    cluster_migration_link = Find(Link, by=By.CSS_SELECTOR, value='.description-copy a')
    enable_cluster_checkbox = Find(Checkbox, by=By.CSS_SELECTOR, value='div[data-name="Enable Cluster"]')
    enable_cluster_warning = Find(by=By.CSS_SELECTOR, value='span[class*="warning"]')
    save_button = Find(Clickable, by=By.CSS_SELECTOR, value='button[type="submit"]')
    cluster_migration_tab = Find(Clickable, by=By.CSS_SELECTOR, value='#tabs a[data-name="Cluster Migration"]')
    parent_node_host = Find(TextField, by=By.CSS_SELECTOR, value='input[data-domselect="cluster_host"]')
    parent_node_port = Find(TextField, by=By.CSS_SELECTOR, value='input[data-domselect="cluster_port"]')
    parent_node_linking_key = Find(TextField, by=By.CSS_SELECTOR, value='input[data-domselect="cluster_linking_key"]')
    enable_agent_migration = Find(Checkbox, by=By.CSS_SELECTOR, value='div[data-domselect="cluster_enable_migration"]')

    def __init__(self):
        super().__init__()
        self.required_elements = ['cluster_migration_link']

    def fill_cluster_information(self, node_host: str, node_port: str, node_linking_key: str,
                                 agent_migration: bool = False) -> None:
        """
        Fills the cluster information under cluster migration tab

        :param str node_host: parent node host
        :param str node_port: parent node port
        :param str node_linking_key: linking key of parent node
        :param bool agent_migration: True if enable agent migration else False
        :return: None
        """
        self.parent_node_host.value = node_host
        self.parent_node_port.value = node_port
        self.parent_node_linking_key.value = node_linking_key

        if agent_migration:
            self.enable_agent_migration.set_checked(value=agent_migration)


class ClusterAgentRecord(GenericTableRow):
    """ Defines the key names for Agent Records returned by ClusterAgentList. """

    select_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='td:nth-child(1)')
    agent_name = Find(by=By.CSS_SELECTOR, value='td:nth-child(2)')
    agent_status = Find(by=By.CSS_SELECTOR, value='td:nth-child(3)')
    agent_ip = Find(by=By.CSS_SELECTOR, value='td:nth-child(4)')


class ClusterAgentList(AgentObjectList):
    """ Returns a list containing agents displayed in Cluster Agent Page. """

    configure_button = None
    generics_map = {GenericTableRow: ClusterAgentRecord}

    def loaded(self, **kwargs):
        """
        waits for the list of agents to populate

        :return: None
        """
        self.is_element_present('rows', timeout=const.TIME_THIRTY_SECONDS)

    def get_all_cluster_agent_names(self) -> list:
        """
        get all agents and return a list by agent name in current page

        :return: list of agents name
        :rtype: list
        """
        try:
            return [row.agent_name.text for row in self.rows]
        except NoSuchElementException:
            return []

    def click_on_cluster_agent(self, agent_name: str) -> None:
        """
        Click on a particular agent

        :param str agent_name: name of the agent to be clicked.
        :return: None
        """
        for row in self.rows:
            if agent_name == row.agent_name.text:
                row.agent_name.click()
                break

    def select_cluster_agents(self, agents_list: list) -> None:
        """
        Select agent(s) listed in agent list in the linked agent page
        :param list agents_list: agent(s) to be selected.
        :return: None
        """
        for agent in self.rows:
            if agent.agent_name.text in agents_list:
                agent.select_checkbox.check()


class AgentDetailsPage(ActionCloseModal):
    """ Page class to retrieve cluster agent details card. """

    edit_cluster_group_icon = Find(Clickable, by=By.CSS_SELECTOR, value='i.edit')
    agent_details_tab = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="Agent Details"]')
    logs_tab = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="Logs"]')
    agent_activity_tab = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="Agent Activity"]')
    remote_settings_tab = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="remote-settings"]')
    cluster_group_drop_down = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-name="new-cluster-group"]')
    current_cluster_group_name = Find(Select2Dropdown, by=By.CSS_SELECTOR,
                                      value='span[data-name="current-cluster-group"]')
    back_link = Find(by=By.CSS_SELECTOR, value='.title-box a')
    add_to_profile_icon = Find(Clickable, by=By.CSS_SELECTOR, value='#add-to-profile-icon')
    current_agent_profile_name = Find(by=By.CSS_SELECTOR, value='span#remove-profile')

    def change_cluster_group_for_agent(self, cluster_group_name: str) -> None:
        """
        Change the cluster group associated with agent.

        :param cluster_group_name: Name of cluster group to which the agent is to be assigned.
        :return: None
        """
        self.edit_cluster_group_icon.click()
        wait(lambda: self.is_element_present('modal'), waiting_for='change cluster group modal')
        self.cluster_group_drop_down.select_by_visible_text(cluster_group_name)
        self.accept_action()
        self.wait_for_modal_closed()

    def get_profile_name(self) -> str:
        """
        Returns agent profile name of current agent

        :return: profile name
        :rtype: str
        """
        return self.current_agent_profile_name.text
