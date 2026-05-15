"""
Nessus page object classes for Cluster Group page

:copyright: Tenable Network Security, 2019
:date: Nov 01, 2019
:last_modified: Oct 12, 2020
:author: @vsoni, @kpanchal
"""

from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement

from catium.lib import const
from catium.lib.cat_registry import cat_registry
from catium.lib.log import create_logger
from catium.lib.webium import Find
from catium.lib.webium import Finds
from catium.lib.webium.controls.checkbox import Checkbox
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.link import Link
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.table import GenericTableRow
from catium.lib.webium.controls.text_field import TextField
from nessus.pageobjects.agents.agent_group_page import GroupDetail
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.generic.agent_object_list import AgentObjectList
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.generic.object_list import ObjectList

log = create_logger()


@cat_registry.route(r'sensors/agent-cluster-groups')
class ClusterGroupPage(NessusBasePage):
    """PageObject for cluster group page."""
    new_group_button = Find(Clickable, by=By.CSS_SELECTOR, value="a[data-domselect='create']")
    group_name_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-domselect="name"]')
    add_button = Find(Clickable, by=By.CSS_SELECTOR, value='a.modal-action')
    cancel_button = Find(Clickable, by=By.CSS_SELECTOR, value='a.modal-close')
    edit_button = Find(Clickable, by=By.CSS_SELECTOR, value="a[data-domselect='edit']")
    delete_button = Find(Clickable, by=By.CSS_SELECTOR, value="a[data-domselect='delete']")
    set_default_checkbox = Find(Clickable, by=By.CSS_SELECTOR, value="div.set-default")
    save_button = Find(Clickable, by=By.CSS_SELECTOR, value='a.modal-action')
    delete_option = Find(Clickable, by=By.CSS_SELECTOR, value='a.modal-action')
    search_cluster_group = Find(Clickable, by=By.CSS_SELECTOR, value='input[aria-label="Search"]')
    node_linking_key = Find(by=By.CSS_SELECTOR, value='span.key')
    regenerate_icon = Find(by=By.ID, value='key-regen')
    modify_icon = Find(by=By.ID, value='key-set')
    total_cluster_group_count = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Total Records"]')

    def __init__(self):
        super().__init__()
        self.required_elements = ['search_cluster_group']

    @property
    def agent_cluster_group_count(self):
        """ Returns count of cluster groups """

        return int(self.total_cluster_group_count.text.split(" ")[0])


class ClusterGroupRecord(GenericTableRow):
    """Defines the key names for Cluster group Records returned by ClusterGroupList."""
    select = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='td:nth-child(1)')
    group_name = Find(by=By.CSS_SELECTOR, value='td:nth-child(2)')
    num_of_nodes = Find(by=By.CSS_SELECTOR, value='td:nth-child(3)')
    num_of_agents = Find(by=By.CSS_SELECTOR, value='td:nth-child(4)')
    usage = Find(by=By.CSS_SELECTOR, value='td:nth-child(5)')
    scans = Find(by=By.CSS_SELECTOR, value='td:nth-child(6)')
    last_modified = Find(by=By.CSS_SELECTOR, value='td:nth-child(7)')
    delete_group = Find(Clickable, by=By.CSS_SELECTOR, value='td:nth-child(9)')


class ClusterGroupList(ActionCloseModal, ClusterGroupPage, ObjectList):
    """ Returns a list containing cluster group displayed on the cluster group management Page. """
    configure_button = None
    generics_map = {GenericTableRow: ClusterGroupRecord}

    def loaded(self, **kwargs) -> None:
        """
        Waits for the list of cluster groups to populate

        :return: None
        """
        self.is_element_present('rows', timeout=const.TIME_THIRTY_SECONDS)

    def get_all_group_names(self) -> list:
        """
        get all cluster groups and return a list by group name in current page

        :return: list of cluster groups.
        :rtype: list
        """
        try:
            return [row.group_name.text for row in self.rows]
        except NoSuchElementException:
            return []

    def get_number_of_nodes_for_agent_group(self, group_name: str) -> int:
        """
        get number of nodes associated with cluster group.

        :param str group_name: Name of the cluster group
        :return: Number of nodes associated with cluster group.
        :rtype: int
        """
        for row in self.rows:
            if group_name in row.group_name.text:
                return int(row.num_of_nodes.text)
        else:
            raise Exception("No group found with name {}".format(group_name))

    def get_number_of_agents_for_agent_group(self, group_name: str) -> int:
        """
        get number of agents associated with cluster group.

        :param str group_name: Name of the cluster group
        :return: Number of agents associated with cluster group.
        :rtype: int
        """
        for row in self.rows:
            if group_name in row.group_name.text:
                return int(row.num_of_agents.text)
        else:
            raise Exception("No group found with name {}".format(group_name))

    def click_on_group(self, group_name: str) -> None:
        """
        Click on a particular cluster group

        :param str group_name: name of the cluster group to be clicked.
        :return: None
        """
        for row in self.rows:
            if group_name in row.group_name.text:
                row.group_name.click()
                break

    def select_cluster_group(self, group_name: str) -> None:
        """
        Select on a particular cluster group.

        :param str group_name: name of the cluster group to be selected.
        :return: None
        """
        for row in self.rows:
            if group_name in row.group_name.text:
                row.select.click()

    def delete_cluster_group(self, group_name: str) -> None:
        """
        Delete the given cluster group.

        :param str group_name: name of the cluster group to be deleted.
        :return: None
        """
        for row in self.rows:
            if group_name in row.group_name.text:
                row.delete_group.click()

    def make_cluster_group_to_default(self, group_name: str) -> None:
        """
        Make the given cluster group as default.

        :param str group_name: name of the cluster group.
        :return: None
        """
        self.select_cluster_group(group_name=group_name)
        self.edit_button.click()
        self.set_default_checkbox.click()
        self.save_button.click()

    def current_default_group_name(self) -> str:
        """
        Returns default cluster group on page.

        :return: Name of the default cluster group name.
        :rtype: str
        """
        default_tag = "Default\n"
        for row in self.rows:
            if default_tag in row.group_name.text:
                return row.group_name.text.split(default_tag)[1]
        else:
            return ""

    def edit_cluster_group_name(self, current_group_name: str, new_group_name: str) -> None:
        """
        Change the name of the given cluster group.

        :param str current_group_name: current name of cluster group.
        :param str new_group_name: New cluster group name which is to be set.
        :return: None
        """
        self.select_cluster_group(group_name=current_group_name)
        self.edit_button.click()
        self.group_name_field.value = new_group_name
        self.save_button.click()
        self.wait_for_modal_closed()

    def delete_default_cluster_group(self, group_name: str) -> None:
        """
        Delete default cluster group.

        :param str group_name: name of the default cluster group to be deleted.
        :return: None
        """
        self.select_cluster_group(group_name=group_name)
        self.delete_button.click()
        self.save_button.click()


class ClusterGroupDetails(ActionCloseModal):
    """Page object for Cluster group details card."""
    add_node_button = Find(Clickable, by=By.CSS_SELECTOR, value='a.add-nodes')
    member_nodes = Finds(by=By.CSS_SELECTOR, value='tr.agent-node')
    nodes_tab = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="Nodes"]')
    agents_tab = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="Agents"]')
    remove_node = Find(Clickable, by=By.CSS_SELECTOR, value='td i.remove')
    remove_agent = Find(Clickable, by=By.CSS_SELECTOR, value='a.remove-agents')
    agent_ip_header = Find(by=By.CSS_SELECTOR, value='th[data-sort-by="ip"]')
    node_usage_header = Find(by=By.CSS_SELECTOR, value='th[aria-label^="Usage"]')
    move_node_button = Find(Clickable, by=By.CSS_SELECTOR, value="a[class~='move-nodes']")
    move_agent_button = Find(Clickable, by=By.CSS_SELECTOR, value="a[class~='move-agents']")
    move_cluster_group_drop_down = Find(Select2Dropdown, by=By.CSS_SELECTOR,
                                        value='select[data-name="choose-cluster-group"]')
    select_all_checkbox = Find(Checkbox, by=By.CLASS_NAME, value='select-all')
    back_to_cluster_group_link = Find(Link, by=By.CSS_SELECTOR, value='.title-box a')
    empty_agents = Find(by=By.CLASS_NAME, value="empty-results")

    def get_member_node_element(self, member_node_name: str) -> WebElement:
        """
        Get specific element from available member agent list window

        :param str member_node_name: node to be selected
        :return: locator of the specified element
        :rtype: WebElement
        """
        for agent in self.member_nodes:
            if agent.find_element(By.CSS_SELECTOR, 'td:nth-child(2)').text == member_node_name:
                return agent.find_element(By.CSS_SELECTOR, 'td.select')
        else:
            raise Exception('No such node : %s available in the visible list.', member_node_name)


class ClusterGroupAgentPage(ClusterGroupDetails, GroupDetail):
    """Page objects for agent tab in cluster group page."""
    add_agents_button = Find(Clickable, by=By.CSS_SELECTOR, value='#titlebar a[class*=add-agents]')
    add_agents_link = Find(Link, by=By.CSS_SELECTOR, value='span a.add-agents')
    agent_details_tab = Find(by=By.CSS_SELECTOR, value='a[data-name="Agent Details"]')
    agent_activity_tab = Find(by=By.CSS_SELECTOR, value='a[data-name="Agent Activity"]')
    empty_agents = Find(by=By.CLASS_NAME, value="empty-results")
    add_agent_search_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-domselect="searchInput"]')
    add_agent_search_icon = Find(by=By.CSS_SELECTOR, value='i[data-domselect="searchIcon"]')
    add_agent_remove_search_icon = Find(by=By.CSS_SELECTOR, value='i[data-domselect="removeSearchIcon"]')
    clear_selected_item_link = Find(Link, by=By.CSS_SELECTOR, value='a[data-domselect*="Clear Selected"]')

    def add_agent_member_to_cluster_group(self, member_agent_list: list) -> None:
        """
        select one or more agent member from available list and add them in group

        :param list member_agent_list: list of agents going to be added in group
        :return: None
        """
        self.add_agents_button.click()
        ClusterGroupAgentList().loaded()

        for member_agent in member_agent_list:
            self.get_member_agent_element(member_agent_name=member_agent).click()

        self.accept_action()


class ClusterGroupAgentRecord(GenericTableRow):
    """ Defines the key names for Agent Records returned by ClusterAgentList. """

    member_agents = Finds(by=By.CSS_SELECTOR, value='.modal tr.agent')
    select_all_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div.select-all')


class ClusterGroupAgentList(AgentObjectList):
    """ Returns a list containing agents displayed in Cluster Agent Page. """

    configure_button = None
    generics_map = {GenericTableRow: ClusterGroupAgentRecord}
    modal_agent_raws = Finds(by=By.CSS_SELECTOR, value='tr.agent')

    def loaded(self, **kwargs):
        """
        waits for the list of agents to populate

        :return: None
        """
        self.is_element_present('modal_agent_raws', timeout=const.TIME_THIRTY_SECONDS)

    def get_cluster_agent_name_from_modal(self) -> list:
        """
        get all agents and return a list by agents name from add cluster agent modal

        :return: list of agents
        :rtype: list
        """
        return [agent.find_element(By.CSS_SELECTOR, 'td:nth-child(2)').text for agent in self.modal_agent_raws]

    def is_cluster_agent_selected(self, agents_list: list) -> bool:
        """
        Verify if checkbox is checked against agent(s) under agent list in the agent page

        :param list agents_list: agent(s) to be selected.
        :return: True if specified scan is already selected
        :rtype: bool
        """
        return all(['true' in agent.find_element(By.CSS_SELECTOR, 'td.select div').get_attribute('aria-checked') for
                    agent in self.modal_agent_raws if agent.find_element(By.CSS_SELECTOR, 'td:nth-child(2)').text in
                    agents_list])

    def select_cluster_add_agents(self, agents_list: list) -> None:
        """
        Select agent(s) listed in agent list from add cluster agent modal

        :param list agents_list: agent(s) to be selected.
        :return: None
        """
        for agent in self.modal_agent_raws:
            if agent.find_element(By.CSS_SELECTOR, 'td:nth-child(2)').text in agents_list:
                agent.find_element(By.CSS_SELECTOR, 'td.select').click()
