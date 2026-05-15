""""
Nessus page object classes for AgentsGroups under Agents Tab.

:copyright: Tenable Network Security, 2017
:date: August 10, 2017
:last_modified: Sept 17, 2020
:author: @rdutta, @kpanchal, @krpatel.ctr
"""

from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement

from catium.lib.cat_registry import cat_registry
from catium.lib.const.base_constants import TIME_THREE_SECONDS, TIME_THIRTY_SECONDS
from catium.lib.log import create_logger
from catium.lib.webium.controls.checkbox import Checkbox
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.link import Link
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.table import GenericTableRow
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.find import Find, Finds
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.generic.agent_object_list import AgentObjectList
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.shared.loading import LoadingCircle

log = create_logger()


@cat_registry.route(r'sensors/agent-groups')
class AgentGroupsPage(NessusBasePage):
    """Page object class to defines the key names for agent groups page."""
    agent_group_header = Find(by=By.CSS_SELECTOR, value="h1")
    new_group_link = Find(Clickable, by=By.CSS_SELECTOR, value='a.agent-group-new')
    new_group_button = Find(Clickable, by=By.CSS_SELECTOR, value='#new')
    search_box = Find(TextField, by=By.CSS_SELECTOR, value='input[data-domselect="searchInput"]')
    edit_button = Find(Clickable, by=By.CSS_SELECTOR, value='#edit')
    delete_button = Find(Clickable, by=By.CSS_SELECTOR, value='#delete')
    select_all_checkbox = Find(Checkbox, by=By.CSS_SELECTOR, value='div.select-all')
    clear_selected_item = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-domselect="clear-all"]')
    description_link = Find(Link, by=By.CSS_SELECTOR, value='div[class~="description-copy"] a')
    empty_groups = Find(by=By.CSS_SELECTOR, value="span.empty-results")
    link_to_agents = Find(by=By.CSS_SELECTOR, value='a[href="#/sensors/agents"]')
    total_records = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Total Records"]')
    checked_groups = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Checked"]')
    empty_agent_watermark = Find(by=By.CSS_SELECTOR, value='.empty-results')
    linked_agent_tab = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="Linked Agents"]')
    save_button = Find(Clickable, by=By.CSS_SELECTOR, value='#agent-group-permissions-save')
    cancel_button = Find(Clickable, by=By.CSS_SELECTOR, value='#agent-group-permissions-save + a')
    add_agent_link = Find(by=By.CSS_SELECTOR, value=".agent-group-add")

    def __init__(self):
        super().__init__()
        self.required_elements = ['new_group_button']

    def get_agent_group_checkbox_by_group_name(self, group_name) -> Checkbox:
        """
        Return checkbox Web element for given group name.
        :param str group_name: Name of agent group name
        :return : Web element for agent group.
        :rtype: WebElement
        """
        return Find(Checkbox, by=By.CSS_SELECTOR, value="tr[data-name='{}'] div.checkbox".format(group_name),
                    context=self)


class GroupDetail(ActionCloseModal):
    """Page class to retrieve details of all linked agents listed under group."""
    searchbox = Find(TextField, by=By.CSS_SELECTOR, value='input[data-domselect="searchInput"]')
    search_icon = Find(Clickable, by=By.CSS_SELECTOR, value='.search')
    remove_search_icon = Find(Clickable, by=By.CSS_SELECTOR, value='#searchbox .remove')
    add_member = Find(Clickable, by=By.CSS_SELECTOR, value='#add')
    remove = Find(Clickable, by=By.CSS_SELECTOR, value='#remove')
    back_to_agent_group = Find(Clickable, by=By.CSS_SELECTOR, value='.title-box a')
    permissions_tab = Find(by=By.CSS_SELECTOR, value='a[data-name="Permissions"]')
    add_user_group_input = Find(by=By.CSS_SELECTOR, value='input.editor-input')
    select_user_permission = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[aria-label="Share Permissions"]')

    def __init__(self):
        super().__init__()

    def get_member_agent_element(self, member_agent_name: str) -> WebElement:
        """
        Get specific element from available member agent list window
        :param str member_agent_name: agent to be selected
        :return: locator of the specified element
        :rtype: WebElement
        """
        member_agents = Finds(by=By.CSS_SELECTOR, value='tr.agent', context=self)
        for agent in member_agents:
            if agent.find_element(By.CSS_SELECTOR, 'td:nth-child(2)').text == member_agent_name:
                return agent.find_element(By.CSS_SELECTOR, 'td.select')
        else:
            log.warning('No such agent : %s available in the visible list.', member_agent_name)

    def add_agent_member_to_agent_group(self, member_agent_list: list) -> None:
        """
        select one or more agent member from available list and add them in group
        :param list member_agent_list: list of agents going to be added in group
        :return: None
        """
        self.add_member.click()
        for member_agent in member_agent_list:
            self.get_member_agent_element(member_agent_name=member_agent).click()
        self.accept_action()
        LoadingCircle(TIME_THREE_SECONDS)
        self.back_to_agent_group.click()


class CreateGroupWindowPage(AgentGroupsPage, GroupDetail):
    """Page objects for group window page."""
    group_name_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-domselect="Name"]')
    add_button = Find(Clickable, by=By.CSS_SELECTOR, value='a.modal-action')
    cancel_button = Find(Clickable, by=By.CSS_SELECTOR, value='a.modal-close')

    def __init__(self):
        super().__init__()
        self.required_fields = ['group_name_field']

    def create_group(self, group_name: str, add_agents: bool = False) -> None:
        """
        Creates a new agent group
        :param str group_name: group name to be created
        :param bool add_agents: If true then return to add agents, otherwise back to agent group page.
        :return: None 
        """
        self.new_group_button.click()

        self.group_name_field.value = group_name
        self.add_button.click()
        if not add_agents:
            self.back_to_agent_group.click()


class AgentGroupsRecords(GenericTableRow):
    """Defines the key names for AgentGroups records returned by AgentGroupsList."""
    checkbox = Find(Clickable, by=By.CSS_SELECTOR, value='td:nth-child(1)')
    agents_group_name = Find(by=By.CSS_SELECTOR, value='td:nth-child(2)')
    count_of_agents = Find(by=By.CSS_SELECTOR, value='td:nth-child(3)')
    last_modified = Find(by=By.CSS_SELECTOR, value='td:nth-child(4)')
    edit = Find(by=By.CSS_SELECTOR, value='td:nth-child(5)')
    delete = Find(Clickable, by=By.CSS_SELECTOR, value='td:nth-child(6)')

    @property
    def name(self):
        """ Returns name attribute of a row """
        return self.agents_group_name.text

    @property
    def agents(self):
        """ Returns count_of_agents attribute of a row """
        return self.count_of_agents.text

    @property
    def last_modified_time(self):
        """ Returns last_modified attribute of a row """
        return self.last_modified.text


class AgentGroupsList(AgentObjectList, ActionCloseModal):
    """Returns a list containing agent_groups displayed on the Agent Groups Page."""
    configure_button = None
    generics_map = {GenericTableRow: AgentGroupsRecords}
    new_agent_group_name = Find(TextField, by=By.CSS_SELECTOR, value=".modal input.validate")

    def __init__(self):
        super().__init__()

    def loaded(self, **kwargs):
        """waits for the list of agent groups to populate"""
        self.is_element_present('rows', timeout=TIME_THIRTY_SECONDS)

    def get_all_groups(self) -> list:
        """
        Returns the list of all agent_groups
        :return: list of all agent groups
        :rtype: list
        """
        return [group.agents_group_name.text for group in self.rows]

    def click_on_group(self, group_name: str) -> None:
        """
        click on a particular group specified by group_name
        :param str group_name: group name to be clicked
        :return: None
        """
        for group in self.rows:
            current_group = 'Shared\n{}'.format(group_name)
            log.debug("Comparing '%s' to '%s'.", group.agents_group_name.text, current_group)
            if group.agents_group_name.text == current_group:
                group.agents_group_name.click()
                break
        else:
            log.warning("AgentGroup: %s not found in the agent group list", group_name)

    def delete_group(self, group_name: str) -> None:
        """
        delete a particular group specified by group_name
        :param str group_name: group name to delete
        :return: None
        """
        for group in self.rows:
            current_group = 'Shared\n{}'.format(group_name)
            log.debug("Comparing '%s' to '%s'.", group.agents_group_name.text, current_group)
            if group.agents_group_name.text == current_group:
                group.delete.click()
                self.accept_action()
                self.wait_for_modal_closed()
                break
        else:
            log.warning("Delete Failed: %s not found in the agent group list", group_name)

    def select_deselect_agent_groups(self, group_list: list) -> None:
        """
        This function select/deselect given list of agent groups.
        :param list group_list: List of agent groups which needs to be selected or deselected
        :return : None
        """
        for group in self.rows:
            if group.agents_group_name.text.split('\n')[1] in group_list:
                group.checkbox.click()

    def edit_agent_group_name(self, original_group_name: str, new_name: str) -> None:
        """
        This function edits given agent group name with new name.
        :param str original_group_name: Original agent group name
        :param str new_name: New agent group name
        :return : None
        """
        for group in self.rows:
            if group.agents_group_name.text.split('\n')[1] == original_group_name:
                group.edit.click()
                self.new_agent_group_name.value = new_name
                self.accept_action()
                self.wait_for_modal_closed()
                break
        else:
            log.warning("Agent group having name - {} was not found.".format(original_group_name))

    def get_column_header_element(self, column_name: str) -> WebElement:
        """
        Return Web element for given column name header.
        :param str column_name: Name of column name
        :return : Web element for given column name header.
        :rtype: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value="th[aria-label*='{}']".format(column_name), context=self)
