"""
Nessus page object classes for 'Cluster' tab under Agents page.

:copyright: Tenable Network Security, 2019
:date: May 15, 2019
:last_modified: June 17, 2019
:author: @kpanchal
"""

from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement

from catium.lib.cat_registry import cat_registry
from catium.lib.log.log import create_logger
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.table import GenericTableRow
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.find import Find, Finds
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.generic.object_list import ObjectList

log = create_logger()


@cat_registry.route(r'scans/cluster')
class AgentClusterPage(NessusBasePage):
    """ Page object class to defines the key names for agent cluster page """

    linking_key = Find(by=By.CSS_SELECTOR, value='.description-key')
    refresh_icon = Find(Clickable, by=By.ID, value='key-regen')
    search_box = Find(TextField, by=By.CSS_SELECTOR, value='input[data-domselect="searchInput"]')
    total_node_count = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Total Records"]')
    enable_button = Find(Clickable, by=By.ID, value='enable')
    disable_button = Find(Clickable, by=By.ID, value='disable')
    delete_button = Find(Clickable, by=By.ID, value='delete')
    rebalance_button = Find(Clickable, by=By.ID, value='rebalance')
    rebalance_node_notice = Find(by=By.CSS_SELECTOR, value='span.msg')

    @property
    def agent_cluster_node_count(self):
        """ Returns count of cluster nodes """
        return int(self.total_node_count.text.split(" ")[0])

    def rebalance_cluster_nodes(self) -> None:
        """
        Click on 'Rebalance Node' button

        :return: None 
        """
        self.rebalance_button.click()
        action_modal = ActionCloseModal()
        action_modal.accept_action()
        action_modal.wait_for_modal_closed()


class AgentClusterNodeRecords(GenericTableRow):
    """ Defines the key names for cluster node Records returned by AgentClusterNodeList """

    node_checkbox = Find(Clickable, by=By.CSS_SELECTOR, value='td:nth-child(1)')
    node_name_element = Find(by=By.CSS_SELECTOR, value='td:nth-child(2)')
    node_status_element = Find(by=By.CSS_SELECTOR, value='td:nth-child(3)')
    node_scans_element = Find(by=By.CSS_SELECTOR, value='td:nth-child(4)')
    node_usage_element = Find(by=By.CSS_SELECTOR, value='td:nth-child(5)')
    last_connected = Find(by=By.CSS_SELECTOR, value='td:nth-child(6)')
    delete = Find(Clickable, by=By.CSS_SELECTOR, value='td:nth-child(8)')
    node_usage_progress = Find(by=By.CSS_SELECTOR, value='div.used')
    enable_disable_tool_tip = Find(by=By.CSS_SELECTOR, value='i.fontawesome.add-tip')

    @property
    def agent_cluster_node_name(self):
        """ Returns the name of cluster node """
        return self.node_name_element.text

    @property
    def agent_cluster_node_status(self):
        """ Returns the status of cluster node """
        return self.node_status_element.text

    @property
    def agent_cluster_node_scans(self):
        """ Returns the count of scans """
        return int(self.node_scans_element.text)

    @property
    def agent_cluster_node_usage(self):
        """ Returns the usage of cluster node """
        return self.node_usage_element.text


class AgentClusterNodeList(ObjectList):
    """ Returns a list containing cluster nodes displayed on the Cluster Page under Agents """

    configure_button = None
    generics_map = {GenericTableRow: AgentClusterNodeRecords}

    @property
    def cluster_nodes_all_name(self) -> list:
        """ Returns a list of existing Agent cluster nodes name """
        return [node.agent_cluster_node_name for node in self.rows]

    def click_on_cluster_node(self, node_name: str) -> None:
        """
        Click on cluster node of specified node name

        :param str node_name: cluster node name
        :return: None
        """
        for nodes in self.rows:
            if nodes.node_name_element.text == node_name:
                nodes.node_name_element.click()
                break
        else:
            log.warning("Node: '%s' is not found in the node list", node_name)

    def get_node_usage_warning(self, node_name: str) -> list:
        """
        Returns node usage warning message of node under agent cluster page

        :param str node_name: node name
        :return: node usage warning
        :rtype: list
        """
        return [node.agent_cluster_node_usage for node in self.rows if node.agent_cluster_node_name == node_name]

    def get_node_usage_color(self, node_name: str) -> str:
        """
        Returns node usage progress bar color of node under agent cluster page

        :param str node_name: node name
        :return: node usage progress bar color
        :rtype: str
        """
        for node in self.rows:
            if node.agent_cluster_node_name == node_name:
                return node.node_usage_progress.value_of_css_property('background-color')
        else:
            log.warning("Node: '%s' is not found in the node list", node_name)

    def select_cluster_node(self, node_name: str) -> None:
        """
        Select cluster node of specified name

        :param str node_name: cluster node name
        :return: None
        """
        for node in self.rows:
            if node.agent_cluster_node_name == node_name:
                node.node_checkbox.click()
                break
        else:
            log.warning("Node: '%s' is not found in the node list", node_name)

    @staticmethod
    def enable_cluster_node() -> None:
        """
        Click on 'Enable' button from top right corner

        :return: None
        """
        AgentClusterPage().enable_button.click()
        action_modal = ActionCloseModal()
        action_modal.accept_action()
        action_modal.wait_for_modal_closed()


class AgentClusterNodePage(AgentClusterPage):
    """ Defines the key names for cluster node page """

    back_to_cluster_link = Find(Clickable, by=By.CSS_SELECTOR, value='.title-box a')
    node_details_link = Find(Clickable, by=By.CSS_SELECTOR, value='#tabs a[data-name="Node Details"]')
    node_settings_link = Find(Clickable, by=By.CSS_SELECTOR, value='#tabs a[data-name="Settings"]')


class AgentClusterNodeDetailsPage(AgentClusterNodePage):
    """ Page Object for node details tab in cluster node page under Cluster tab in Agents """

    cluster_header_name = Find(by=By.CSS_SELECTOR, value='#titlebar h1')
    general_software_labels = Finds(by=By.CSS_SELECTOR, value='div[class*="floatleft"]:nth-child(1) > div > label')
    connection_plugins_labels = Finds(by=By.CSS_SELECTOR, value='div[class*="floatleft"]:nth-child(2) > div > label')
    agent_count = Find(by=By.XPATH, value="//*[text()='Agents']/following-sibling::span")

    @property
    def total_agents_count(self):
        """ Returns the count of max agents of node """
        return int(self.agent_count.text.split(" ")[2])

    @property
    def linked_agents_count(self):
        """ Returns the count of max agents of node """
        return int(self.agent_count.text.split(" ")[0])

    @staticmethod
    def get_node_details_labels(element: WebElement) -> list:
        """
        Return the list of labels displayed in node details page.

        :param WebElement element: UI element of label
        :return: List of labels
        :rtype: list
        """
        return [label.text.strip() for label in element]


class AgentClusterNodeSettingsPage(AgentClusterNodePage):
    """ Page Object for settings tab in cluster node page under Cluster tab in Agents """

    max_agent_field = Find(TextField, by=By.CSS_SELECTOR, value='input.validate')
    save_button = Find(Clickable, by=By.CSS_SELECTOR, value='button[data-domselect="Save"]')

    def set_max_agent(self, agent: int) -> None:
        """
        Set max agents value

        :param int agent: Number of max agents to be set
        :return: None
        """
        self.max_agent_field.value = agent
        self.save_button.click()
