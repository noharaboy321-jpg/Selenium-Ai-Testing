"""
Nessus page object classes for Agents page

:copyright: Tenable Network Security, 2017
:date: July 25, 2017
:last_modified: Sept 30, 2020
:author: @smadan, @rdutta, @ntarwani, @kpanchal, @krpatel
"""

from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement

from catium.lib.cat_registry import cat_registry
from catium.lib.const.base_constants import TIME_THIRTY_SECONDS
from catium.lib.log import create_logger
from catium.lib.webium import Find, Finds
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.table import GenericTableRow
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.wait import wait
from nessus.pageobjects.agents.agent_group_page import CreateGroupWindowPage
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.generic.agent_object_list import AgentObjectList
from nessus.pageobjects.generic.generic_modals import ActionCloseModal

log = create_logger()


@cat_registry.route(r'sensors/agents')
class AgentsPage(NessusBasePage):
    """Page Object for Agents Page in Nessus Manager"""
    agent_settings_tab_link = Find(Clickable, by=By.CSS_SELECTOR, value='#tabs a[data-name="Agent Settings"]')
    linked_agents_tab_link = Find(Clickable, by=By.CSS_SELECTOR, value='#tabs a[data-name="Linked Agents"]')
    bw_settings_tab_link = Find(Clickable, by=By.CSS_SELECTOR, value='#tabs a[data-name="Blackout Window Settings"]')
    linking_key_text = Find(by=By.CSS_SELECTOR, value='span[class="no-edit key"]')
    add_to_groups_button = Find(Clickable, by=By.CSS_SELECTOR, value='#add-to-group')
    new_group_button = Find(Clickable, by=By.CSS_SELECTOR, value='#new-group')
    agents_menu_button = Find(Clickable, by=By.CSS_SELECTOR, value='#agents-menu')
    unlink_button = Find(Clickable, by=By.CSS_SELECTOR, value='#unlink-bulk')
    clear_selected_item = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-domselect*="Clear Selected"]')
    result_per_page_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='.select2-hidden-accessible')
    total_agents = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Total Records"]')
    selected_agents = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Table Api Selected"]')
    filter_link = Find(Clickable, by=By.CSS_SELECTOR, value='.advanced-search')
    export_button = Find(Clickable, by=By.CSS_SELECTOR, value='#scans-show-export')
    cluster_tab_link = Find(Clickable, by=By.CSS_SELECTOR, value='#tabs a[data-name="Cluster"]')
    delete_button = Find(Clickable, by=By.ID, value='delete-bulk')
    search_agent_input = Find(TextField, by=By.CSS_SELECTOR, value='input[data-domselect="searchInput"]')
    search_icon = Find(Clickable, by=By.CSS_SELECTOR, value='i[data-domselect="searchIcon"]')
    remove_search_icon = Find(Clickable, by=By.CSS_SELECTOR, value='i[data-domselect="removeSearchIcon"]')
    empty_agent_list = Find(by=By.CLASS_NAME, value='empty-results')
    next_page_icon = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-position="next"]')
    last_page_icon = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-position="last"]')
    showing_page_results = Find(Clickable, by=By.CSS_SELECTOR, value='div[data-domselect="Table Api Pager"] span')
    linked_agents_description = Find(by=By.CSS_SELECTOR, value='.description-copy')
    regenerate_key = Find(by=By.CSS_SELECTOR, value='#key-regen')
    pencil_icon = Find(by=By.CSS_SELECTOR, value='#key-set')
    agents_setup_instructions = Find(Clickable, by=By.CSS_SELECTOR, value="#agents-setup-instructions")
    next_agents_page = Find(by=By.CSS_SELECTOR, value="a.add-tip[data-position='next']")
    last_agents_page = Find(by=By.CSS_SELECTOR, value="a.add-tip[data-position='last']")
    manage_button = Find(Clickable, by=By.CSS_SELECTOR, value='#agents-menu span')
    add_to_profile_manage_button = Find(Clickable, by=By.CSS_SELECTOR, value='#add-to-profile')
    remove_from_profile_manage_button = Find(Clickable, by=By.CSS_SELECTOR, value='#bulk-remove-from-profile')
    linked_agents = Find(Clickable, by=By.CSS_SELECTOR, value='a[title="Linked Agents"]')
    linked_scanner = Find(Clickable, by=By.CSS_SELECTOR, value='a[title = "Scanners"]')

    def __init__(self):
        super().__init__()
        self.required_elements = ['linking_key_text']

    @property
    def total_agents_count(self):
        """ Return count of total agents shows in linked agents table header. """
        return int(self.total_agents.text.split()[0])

    @property
    def selected_agents_count(self):
        """ Return count of selected agents shows in linked agents table header. """
        return int(self.selected_agents.text.split()[0].lstrip('('))

    def create_group(self, group_name: str) -> None:
        """
        creates a new group from linked agents page
        :param str group_name: group name to be created
        :return: None
        """
        self.new_group_button.click()

        new_group_window = CreateGroupWindowPage()
        new_group_window.group_name_field.value = group_name
        new_group_window.add_button.click()
        new_group_window.wait_for_modal_closed()

    def add_agents_to_group(self, group_name: str) -> None:
        """
        Add agents into group

        :param str group_name: Group name
        :return: None
        """
        self.add_to_groups_button.click()
        agent_detail = AgentDetail()
        agent_detail.get_member_group_element(agent_group_name=group_name).click()
        agent_detail.accept_action()
        agent_detail.wait_for_modal_closed()


class AgentsRecord(GenericTableRow):
    """Defines the key names for Agents Records returned by AgentsList."""
    agent_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div.checkbox')
    agent_name = Find(by=By.CSS_SELECTOR, value='td:nth-child(2)')
    agent_status = Find(by=By.CSS_SELECTOR, value='td:nth-child(3)')
    agent_ip_address = Find(by=By.CSS_SELECTOR, value='td:nth-child(4)')
    agent_platform = Find(by=By.CSS_SELECTOR, value='td:nth-child(5)')
    agent_profile = Find(by=By.CSS_SELECTOR, value='td:nth-child(6)')
    agent_group = Find(by=By.CSS_SELECTOR, value='td:nth-child(7)')
    agent_version = Find(by=By.CSS_SELECTOR, value='td:nth-child(8)')
    last_plugin_update = Find(by=By.CSS_SELECTOR, value='td:nth-child(9)')
    last_scanned = Find(by=By.CSS_SELECTOR, value='td:nth-child(10)')
    unlink = Find(Clickable, by=By.CSS_SELECTOR, value='td:nth-child(11)')
    delete = Find(Clickable, by=By.CSS_SELECTOR, value='td:nth-child(12)')

    @property
    def name(self):
        """ Returns name attribute of a row """
        return self.agent_name.text

    @property
    def core_version(self):
        """ Returns version attribute of a row """
        return self.agent_version.text

    @property
    def status(self):
        """ Returns status attribute of a row """
        return self.agent_status.text

    @property
    def ip(self):
        """ Returns ip attribute of a row """
        return self.agent_ip_address.text

    @property
    def platform(self):
        """ Returns platform attribute of a row """
        return self.agent_platform.text


class AgentsList(AgentObjectList):
    """ Returns a list containing agents displayed on the Agent Management Page. """
    configure_button = None
    generics_map = {GenericTableRow: AgentsRecord}

    def __init__(self):
        super().__init__()
        wait(lambda: len(self.rows) > 0, waiting_for='Agents List to populate.')

    def loaded(self, **kwargs):
        """waits for the list of agent to populate"""
        self.is_element_present('rows', timeout=TIME_THIRTY_SECONDS)

    def get_all_agents_by_name(self) -> list:
        """
        get all agents and return a list by agents name in current page

        :return: list of agents
        :rtype: list
        """
        try:
            return [agent.agent_name.text for agent in self.rows]
        except NoSuchElementException:
            return []

    def get_all_agents_by_id(self) -> list:
        """
        get all agents and return a list by agents name in current page

        :return: list of agents
        :rtype: list
        """
        try:
            return [agent.data_id for agent in self.rows]
        except NoSuchElementException:
            return []

    def get_agent_by_name(self, name: str) -> AgentsRecord:
        """
        Return the agent record by name

        :param str name: agent name
        :return: agent's record
        :rtype: AgentsRecord
        """
        for agent in self.rows:
            if name == agent.agent_name.text:
                return agent
        else:
            raise ValueError("Row with agent name %s not found", name)

    def click_on_agent(self, agent_name: str) -> None:
        """
        Click on a particular agent

        :param str agent_name: name of the agent to be click
        :return: None
        """
        while True:
            for agent in self.rows:
                if agent.agent_name.text == agent_name:
                    agent.click()
                    return
            if self.agent_table.table_wrapper.is_button_enabled('next_page_button'):
                self.agent_table.table_wrapper.next_page_button.click()
            else:
                break

    def delete_agent(self, agent_name: str, accept_delete_modal: bool = False) -> None:
        """
        Delete an agent

        :param str agent_name: name of the agent to delete
        :param bool accept_delete_modal: True if delete modal needs to be accepted else False
        :return: None
        """
        while True:
            for agent in self.rows:
                if agent.agent_name.text == agent_name:
                    agent.delete.click()
                    if accept_delete_modal:
                        delete_modal = ActionCloseModal()
                        delete_modal.accept_action()
                        delete_modal.wait_for_modal_closed()
                    return
            if self.agent_table.table_wrapper.is_button_enabled('next_page_button'):
                self.agent_table.table_wrapper.next_page_button.click()
            else:
                break

    def select_deselect_agents(self, agents_list: list, select: bool = True) -> None:
        """
        Select agent(s) listed in agent list in the linked agent page

        :param list agents_list: agent(s) to be selected.
        :param bool select: True to select agent as False
        :return: None
        """
        for agent in self.rows:
            if agent.agent_name.text in agents_list:
                agent.agent_checkbox.check() if select else agent.agent_checkbox.uncheck()

    def is_agent_selected(self, agents_list: list) -> bool:
        """
        Verify if checkbox is checked against agent(s) under agent list in the agent page

        :param list agents_list: agent(s) to be selected.
        :return: True if specified scan is already selected
        :rtype: bool
        """
        return all([agent.agent_checkbox.is_selected() for agent in self.rows if agent.agent_name.text in agents_list])

    def get_group_name_by_agent(self, agent_name: str) -> str:
        """
        Returns agent group name of given agent

        :param str agent_name: name of the agent to get group name
        :return: group name
        :rtype: str
        """
        for agent in self.rows:
            if agent.agent_name.text == agent_name:
                return agent.agent_group.text

    def get_profile_name_by_agent(self, agent_name: str) -> str:
        """
        Returns profile name of given agent

        :param str agent_name: name of the agent
        :return: profile name
        :rtype: str
        """
        for agent in self.rows:
            if agent.agent_name.text == agent_name:
                agent_profile = agent.agent_profile.text
                return agent_profile

    def get_agent_status_by_agent(self, agent_name: str) -> str:
        """
        Returns agent status of given agent name

        :param str agent_name: name of the agent to get status
        :return: agent status
        :rtype: str
        """
        for agent in self.rows:
            if agent.agent_name.text == agent_name:
                return agent.agent_status.text

    def unlink_agent(self, agent_name: str, accept_unlink_modal: bool = False) -> None:
        """
        Unlink an agent

        :param str agent_name: name of the agent to unlink
        :param bool accept_unlink_modal: True if unlink modal needs to be accepted else False
        :return: None
        """
        for agent in self.rows:
            if agent.agent_name.text == agent_name:
                agent.unlink.click()
        if accept_unlink_modal:
            delete_modal = ActionCloseModal()
            delete_modal.accept_action()
            delete_modal.wait_for_modal_closed()

    def get_column_header_element(self, column_name: str) -> WebElement:
        """
        Return Web element for given column name header.
        :param str column_name: Name of column name
        :return : Web element for given column name header.
        :rtype: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value='th[data-sort-by="{}"]'.format(column_name), context=self)


class AddAgentGroupRecord(GenericTableRow):
    """ Defines the key names for Agent Group Records returned by AddAgentGroupList. """

    member_agents = Finds(by=By.CSS_SELECTOR, value='.modal tr.agent-group')
    select_all_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div.select-all')
    agents_group_name = Find(by=By.CSS_SELECTOR, value='td:nth-child(2)')


class AddAgentGroupList(AgentObjectList):
    """ Returns a list containing agent group displayed in Add agent group pop up. """
    configure_button = None
    generics_map = {GenericTableRow: AddAgentGroupRecord}
    modal_agent_group_rows = Finds(by=By.CSS_SELECTOR, value='tr.agent-group')
    modal_agent_group_columns = Finds(by=By.CSS_SELECTOR, value='th[aria-controls*="DataTables_Table"]')
    modal_agent_rows = Finds(by=By.CSS_SELECTOR, value='tr.agent')

    def get_all_agent_group_names(self):
        """
        This function returns all agent group names present in "Add Agent Group' modal.
        """
        return [group.find_element(By.CSS_SELECTOR, 'td:nth-child(2)').text for group in self.modal_agent_group_rows]

    def get_all_agent_names(self):
        """
        This function returns all agent group names present in "Add Agent Group' modal.
        """
        return [agent.find_element(By.CSS_SELECTOR, 'td:nth-child(2)').text for agent in self.modal_agent_rows]

    def select_agent_group_from_modal(self, group_names_list: list):
        """
        This function selects all agent groups given in the list.
        :param list group_names_list: List of group names which needs to be selected.
        """
        for agent_group in self.modal_agent_group_rows:
            if agent_group.find_element(By.CSS_SELECTOR, 'td:nth-child(2)').text in group_names_list:
                agent_group.find_element(By.CSS_SELECTOR, 'td:nth-child(1)').click()


class AgentDetail(ActionCloseModal):
    """Page class to retrieve agents details card."""
    add_to_group = Find(Clickable, by=By.CSS_SELECTOR, value='#add-to-group-icon')
    add_to_profile = Find(Clickable, by=By.CSS_SELECTOR, value='#add-to-profile-icon')
    remove_profile = Find(Clickable, by=By.CSS_SELECTOR, value='#remove-profile')
    update_profile = Find(Clickable, by=By.CSS_SELECTOR, value='#update_profile')
    back_to_agent = Find(Clickable, by=By.CSS_SELECTOR, value='.title-box a')
    group_list = Finds(by=By.CSS_SELECTOR, value='.no-edit-wrap span')
    unlinked_on = Find(by=By.XPATH, value=".//div[label[text()='Unlinked On']]/span")
    status = Find(by=By.XPATH, value=".//div[label[text()='Status']]/span")
    edit_cluster_icon = Find(by=By.CSS_SELECTOR, value='i.edit')
    cluster_group_drop_down = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-name="new-cluster-group"]')
    current_cluster_group_name = Find(Select2Dropdown, by=By.CSS_SELECTOR,
                                      value='span[data-name="current-cluster-group"]')

    def __init__(self):
        super().__init__()

    def get_member_group_element(self, agent_group_name: str) -> WebElement:
        """
        Get specific element from available group member list window
        :param str agent_group_name: specific to this group
        :return: locator of rows for available group
        :rtype: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value='td[data-order*= "{}"]'.format(agent_group_name), context=self)

    def add_group_to_agent(self, group_name: str) -> None:
        """
        select a group from available list and add the agent in it
        :param str group_name: group_name in which agent to be added
        :return: None
        """
        self.add_to_group.click()
        self.get_member_group_element(agent_group_name=group_name).click()
        self.accept_action()

    def remove_group_from_agent_details(self, group_name: str) -> None:
        """
        remove a group from agent details card
        :param str group_name: group name to be remove
        :return: None
        """
        for group in self.group_list:
            if group.text == group_name:
                group.click()
                self.accept_action()
                break
        else:
            log.warning('Group "%s" does not exists in available list', group_name)

    def change_cluster_group_for_agent(self, cluster_group_name: str) -> None:
        """
        Change the cluster group associated with agent.
        :param str cluster_group_name: Name of cluster group to which the agent is to be assigned.
        :return: None
        """
        self.edit_cluster_icon.click()
        wait(lambda: self.is_element_present('modal'))
        self.cluster_group_drop_down.select_by_visible_text(cluster_group_name)
        self.accept_action()
        self.wait_for_modal_closed()

    def select_profile(self, profile_name: str) -> None:
        """
        """
        profile_modal = SelectProfileModal()
        profile_modal.prof_selector.select_by_visible_text(profile_name)
        self.accept_action()

    def add_profile_to_agent(self, profile_name: str) -> None:
        """
        select a profile from available list for the agent
        :param str profile_name: profile_name in which agent to be added
        :return: None
        """
        self.add_to_profile.click()
        self.select_profile(profile_name=profile_name)

    def update_agent_profile(self, profile_name: str) -> None:
        """
        select a profile from available list for the agent
        :param str profile_name: profile_name in which agent to be added
        :return: None
        """
        self.update_profile.click()
        self.select_profile(profile_name=profile_name)

    def remove_agent_profile(self) -> None:
        """
        remove the agent's profile
        :return: None
        """
        self.remove_profile.click()
        self.accept_action()

class AgentSettingsTab(AgentsPage):
    """ Page Object class for Agents Settings tab """

    track_unlinked_agents_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR,
                                          value='div[data-domselect="track_unlinked_agents"]')
    auto_unlink_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div[data-domselect="auto_unlink"]')
    auto_unlink_time_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-domselect="auto_unlink_time"]')
    remove_inactive_agents_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR,
                                           value='div[data-name="Remove Inactive Agents"]')
    inactive_time_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-domselect="inactive-time"]')
    save_button = Find(Clickable, by=By.CSS_SELECTOR, value='button[data-domselect="Save"]')

class SelectProfileModal(ActionCloseModal):
    prof_selector = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-name="add_to_profile"]')
    def __init__(self):
        super().__init__()

