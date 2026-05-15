"""
Nessus page object classes for Nodes page

:copyright: Tenable Network Security, 2019
:date: Nov 01, 2019
:last_modified: Sept 02, 2019
:author: @vsoni, @kpanchal
"""

from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
from waiting import wait

from catium.lib import const
from catium.lib.cat_registry import cat_registry
from catium.lib.log import create_logger
from catium.lib.webium import Find
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.table import GenericTableRow
from catium.lib.webium.controls.text_field import TextField
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.generic.object_list import ObjectList

log = create_logger()


@cat_registry.route(r'sensors/agent-cluster')
class ClusterNodesPage(NessusBasePage):
    """ PageObject for cluster group page. """
    linking_key_text = Find(by=By.CSS_SELECTOR, value='span.no-edit')

    def __init__(self):
        super().__init__()


class ClusterNodeRecord(GenericTableRow):
    """ Defines the key names for Node Records returned by ClusterNodeList. """
    select = Find(by=By.CSS_SELECTOR, value='td:nth-child(1)')
    node_name = Find(by=By.CSS_SELECTOR, value='td:nth-child(2)')
    node_usage = Find(by=By.CSS_SELECTOR, value='td:nth-child(5)')
    remove_node = Find(Clickable, by=By.CSS_SELECTOR, value='td i.remove')
    enable_disable_node_element = Find(by=By.CSS_SELECTOR, value='.node-toggle i')
    enable_disable_tool_tip = Find(by=By.CSS_SELECTOR, value='i.fontawesome.add-tip')


class ClusterNodeList(ObjectList):
    """ Returns a list containing nodes displayed on the node Management Page. """
    configure_button = None
    generics_map = {GenericTableRow: ClusterNodeRecord}
    node_search_box = Find(TextField, by=By.CSS_SELECTOR, value='input[data-domselect="searchInput"]')
    total_node_count = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Total Records"] b')
    node_usage_percentage = Find(by=By.CSS_SELECTOR, value='div.used')

    @property
    def node_count(self) -> int:
        """
        Return count of cluster nodes.

        :return: count of cluster nodes.
        :rtype: int
        """
        return int(self.total_node_count.text)

    def loaded(self, **kwargs):
        """
        waits for the list of nodes to populate

        :return: None
        """
        self.is_element_present('rows', timeout=const.TIME_THIRTY_SECONDS)

    def get_all_node_names(self) -> list:
        """
        get all nodes and return a list by nodes name in current page

        :return: list of nodes
        :rtype: list
        """
        try:
            return [row.node_name.text for row in self.rows]
        except NoSuchElementException:
            return []

    def click_on_node(self, node_name: str) -> None:
        """
        Click on a particular node

        :param str node_name: name of the node to be clicked.
        :return: None
        """
        for row in self.rows:
            if node_name == row.node_name.text:
                row.node_name.click()
                break

    def select_cluster_node(self, node_name: str) -> None:
        """
        Select on a particular node

        :param str node_name: name of the node to be selected.
        :return: None
        """
        for row in self.rows:
            if node_name == row.node_name.text:
                row.select.click()

    def delete_cluster_node(self, node_name: str) -> None:
        """
        Delete particular node

        :param str node_name: name of the node to be deleted.
        :return: None
        """
        for row in self.rows:
            if node_name == row.node_name.text:
                row.remove_node.click()

    def enable_disable_cluster_node(self, node_name: str, enable: bool) -> None:
        """
        Click on disable link of specified cluster node name

        :param str node_name: cluster node name
        :param bool enable: click on enable if True else disable
        :return: None
        """
        for node in self.rows:
            if node.node_name.text == node_name:
                if enable:
                    if not node.enable_disable_node_element.is_enabled():
                        node.enable_disable_node_element.click()
                else:
                    if node.enable_disable_node_element.is_enabled():
                        node.enable_disable_node_element.click()
                break
        else:
            log.warning("Node: '%s' is not found in the node list", node_name)

    def get_enable_disable_tool_tip_text(self, node_name: str) -> str:
        """
        Returns tooltip text of enable/disable link of specified node name

        :param str node_name: cluster node name
        :return: None
        """
        for node in self.rows:
            if node.node_name.text == node_name:
                return node.enable_disable_tool_tip.get_attribute('title')
        else:
            log.warning("Node: '%s' is not found in the node list", node_name)

    def get_node_usage_count(self, node_name: str) -> int:
        """
        Returns linked agent count from node usage column

        :param str node_name: cluster node name
        :return: linked agent count
        :rtype: int
        """
        for node in self.rows:
            if node.node_name.text == node_name:
                self.move_to_element(element=node.node_usage)
                return int(node.node_usage.get_attribute('original-title').split()[0])
        else:
            log.warning("Node: '%s' is not found in the node list", node_name)


class NodeDetailsPage(ActionCloseModal, ClusterNodesPage):
    """ Page class to retrieve nodes details card. """
    edit_cluster_icon = Find(by=By.CSS_SELECTOR, value='i.edit')
    node_details_tab = Find(by=By.CSS_SELECTOR, value='a[data-name="Node Details"]')
    settings_tab = Find(by=By.CSS_SELECTOR, value='a[data-name="Settings"]')
    cluster_group_drop_down = Find(Select2Dropdown, by=By.CSS_SELECTOR,
                                   value='select[data-name="choose-cluster-group"]')
    current_cluster_group_name = Find(Select2Dropdown, by=By.CSS_SELECTOR,
                                      value='span[data-name="current-cluster-group"]')
    back_link = Find(by=By.CSS_SELECTOR, value='.title-box a')

    def change_cluster_group_for_node(self, cluster_group_name: str) -> None:
        """
        Change the cluster group associated with node.

        :param cluster_group_name: Name of cluster group to which the node is to be assigned.
        :return: None
        """
        self.edit_cluster_icon.click()
        wait(lambda: self.is_element_present('modal'))
        self.cluster_group_drop_down.select_by_visible_text(cluster_group_name)
        self.accept_action()
        self.wait_for_modal_closed()
