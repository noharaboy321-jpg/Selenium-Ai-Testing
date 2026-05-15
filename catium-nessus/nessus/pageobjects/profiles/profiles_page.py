"""
Nessus page object classes for Agent Profiles tab under Sensors.

:copyright: Tenable Network Security, 2024
:date: Feb 16, 2024
:last_modified: July 26, 2024
:author: @dancoppock @tyge @tkeyser @mdabra @krpatel

"""

from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement
from catium.lib import const
from catium.lib.cat_registry import cat_registry
from catium.lib.const.base_constants import TIME_THIRTY_SECONDS
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
from nessus.pageobjects.agents.agents_page import AgentsRecord
from catium.lib.webium.wait import wait
from catium.lib.const.base_constants import TIME_THIRTY_SECONDS, TIME_TEN_SECONDS
from catium.helpers.sleep_lib import sleep
from nessus.apiobjects.nessus_api import NessusAPI


log = create_logger()


@cat_registry.route(r'sensors/agent-profiles')
class ProfilesPage(NessusBasePage):
    """PageObject for agent profiles page."""
    profiles_left_nav = Find(Clickable, by=By.CSS_SELECTOR, value='a[title="Agent Profiles"]')
    new_profile_button = Find(by=By.CSS_SELECTOR, value="#new")
    delete_profile_button = Find(by=By.CSS_SELECTOR, value="#delete")
    new_profile_link = Find(Clickable, by=By.CSS_SELECTOR, value="a.agent-profile-new")
    search_profiles = Find(Clickable, by=By.CSS_SELECTOR, value='input[aria-label="Search"]')
    total_profiles_count = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Total Records"]')
    profile_description_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-domselect="Description"]')
    profile_name_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-domselect="Name"]')
    select_all_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div.select-all')
    eol_icon = Find(by=By.CSS_SELECTOR, value='span.eol')
    eol_warning_icon = Find(by=By.CSS_SELECTOR, value='i.eol-close')
    agent_profiles_header = Find(Clickable, by=By.CSS_SELECTOR, value='#titlebar h1')
    name_agent_profile = Find(TextField, by=By.CSS_SELECTOR, value='[data-domselect="Name"]')
    data_table_agent_profiles = Find(Clickable, by=By.XPATH, value='//*[@id="DataTables_Table_0"]')
    add_agent_profile_config = Find(Clickable, by=By.XPATH, value='//a[.="Add"]')
    agent_profiles_cancel_button = Find(Clickable, by=By.XPATH, value='//a[.="Cancel"]')
    description_agent_profile = Find(TextField, by=By.CSS_SELECTOR, value='[data-domselect="Description"]')

    def __init__(self):
        super().__init__()

    @property
    def agent_profiles_count(self):
        """ Returns count of profiles """

        return int(self.total_profiles_count.text.split(" ")[0])

    def create_agent_profile(self, profile_name: str, profile_description: str, expect_failure=False) -> None:
        """
        Creates a new agent profile using UI only
        :param str profile_name: The profile name to be created
        :param str profile_description: The profile Description to be created.
        :param bool expect_failure: Whether to wait for agent profiles table if we expect profile creation to fail
        :return: None
        """
        self.new_profile_button.click()
        wait(lambda: self.is_element_present('profile_name_field'),
             waiting_for="Agent Profiles page to get loaded.", timeout_seconds=TIME_TEN_SECONDS)
        self.profile_name_field.value = profile_name
        self.description_agent_profile.value = profile_description
        self.add_agent_profile_config.click()
        if not expect_failure:
            sleep(1, reason="waiting for profile to load")
            self.refresh()
            sleep(1, reason="waiting for profile to load")
            wait(lambda: self.is_element_present('data_table_agent_profiles'),
                 waiting_for="Agent Profiles page to get loaded.", timeout_seconds=TIME_TEN_SECONDS)

    def delete_all_profiles(self) -> None:
        """ Delete all """
        self.select_all_checkbox.click()
        self.delete_profile_button.click()
        ActionCloseModal().accept_action()


class ProfilesRecord(GenericTableRow):
    """Defines the key names for Profiles Records returned by ProfilesList."""
    select = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='td:nth-child(1)')
    profile_name = Find(by=By.CSS_SELECTOR, value='td:nth-child(2)')
    version = Find(by=By.CSS_SELECTOR, value='td:nth-child(3)')
    cpu_limit = Find(by=By.CSS_SELECTOR, value='td:nth-child(4)')
    description = Find(by=By.CSS_SELECTOR, value='td:nth-child(5)')
    created = Find(by=By.CSS_SELECTOR, value='td:nth-child(6)')
    updated = Find(by=By.CSS_SELECTOR, value='td:nth-child(7)')
    edit_profile = Find(by=By.CSS_SELECTOR, value='td[title="Edit"]')
    delete_profile = Find(Clickable, by=By.CSS_SELECTOR, value='td[title="Delete"]')


class ProfileList(ActionCloseModal, ProfilesPage, ObjectList):
    """ Returns a list containing profiles displayed on the Agent Profiles Page. """
    configure_button = None
    generics_map = {GenericTableRow: ProfilesRecord}

    def loaded(self, **kwargs) -> None:
        """
        Waits for the list of profiles to populate

        :return: None
        """
        self.is_element_present('rows', timeout=const.TIME_THIRTY_SECONDS)

    def get_all_profile_names(self) -> list:
        """
        get all profiles and return a list by name in current page

        :return: list of profiles.
        :rtype: list
        """
        try:
            return [row.profile_name.text for row in self.rows]
        except NoSuchElementException:
            return []

    def get_version_for_profile(self, profile_name: str) -> int:
        """
        get version associated with profile.

        :param str profile_name: Name of the profile
        :return: version associated with profile.
        :rtype: int
        """
        for row in self.rows:
            if profile_name in row.profile_name.text:
                return int(row.version.text)
        else:
            raise Exception("No profile found with name {}".format(profile_name))

    def get_description_for_profile(self, profile_name: str) -> int:
        """
        get description associated with profile.

        :param str profile_name: Name of the profile
        :return: description associated with profile.
        :rtype: int
        """
        for row in self.rows:
            if profile_name in row.profile_name.text:
                return row.description.text
        else:
            raise Exception("No profile found with name {}".format(profile_name))

    def click_on_profile(self, profile_name: str) -> None:
        """
        Click on a particular profile

        :param str profile_name: name of the profile to be clicked.
        :return: None
        """
        for row in self.rows:
            if profile_name in row.profile_name.text:
                row.profile_name.click()
                break

    def select_profile(self, profile_name: str) -> None:
        """
        Select on a particular profile.

        :param str profile_name: name of the profile to be selected.
        :return: None
        """
        for row in self.rows:
            if profile_name in row.profile_name.text:
                row.select.click()

    def delete_profile(self, profile_name: str) -> None:
        """
        Delete the given profile.

        :param str profile_name: name of the profile to be deleted.
        :return: None
        """
        for row in self.rows:
            if profile_name in row.profile_name.text:
                row.delete_profile.click()
                ActionCloseModal().accept_action()

    def edit_profile(self, current_profile_name: str, new_profile_name: str, new_description: str) -> None:
        """
        Change the name of the given profile.

        :param str current_profile_name: current name of profile.
        :param str new_profile_name: New profile name which is to be set.
        :return: None
        """
        self.select_profile(profile_name=current_profile_name)
        self.profile_name_field.value = new_profile_name
        self.profile_description_field.value = new_description
        self.save_button.click()
        self.wait_for_modal_closed()


class ProfileDetails(ActionCloseModal):
    """Page object for profile details."""
    update_version = Find(Clickable, by=By.CSS_SELECTOR, value='a.update-version')
    update_desc = Finds(by=By.CSS_SELECTOR, value='a.edit')
    back_to_agent_profiles = Find(Link, by=By.CSS_SELECTOR, value='.title-box a')
    profile_uuid = Find(Link, by=By.CSS_SELECTOR, value='div[label~="UUID"] span')
    profile_version = Find(Link, by=By.CSS_SELECTOR, value='div[label~="Version"] span')
    profile_description = Find(Link, by=By.CSS_SELECTOR, value='div[label~="Description"] span')
    profile_created_on = Find(Link, by=By.CSS_SELECTOR, value='div[label~="Created On"] span')
    profile_last_updated = Find(Link, by=By.CSS_SELECTOR, value='div[label~="Last Updated"] span')
    agents_tab = Find(by=By.CSS_SELECTOR, value='a[data-name="Agents"]')
    add_agents_button = Find(by=By.CSS_SELECTOR, value='a#add')
    add_agents_fresh_profile_button = Find(by=By.CSS_SELECTOR, value="a.agent-profiles-add")
    select_all_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div.select-all')
    remove_agents_button = Find(by=By.CSS_SELECTOR, value='a#remove')
    edit_profile_button = Find(by=By.CSS_SELECTOR, value='i.edit')

    def get_version_for_profile(self) -> int:
        """
        get version associated with profile.

        :return: version associated with profile.
        :rtype: int
        """
        return self.profile_version

    def get_uuid_for_profile(self) -> int:
        """
        get uuid associated with profile.

        :return: uuid associated with profile.
        :rtype: int
        """
        return self.profile_uuid

    def get_description_for_profile(self) -> int:
        """
        get description associated with profile.

        :return: description associated with profile.
        :rtype: int
        """
        return self.profile_description

    def get_created_on_for_profile(self) -> int:
        """
        get created on associated with profile.

        :return: created on associated with profile.
        :rtype: int
        """
        return self.profile_created_on
    
    def get_last_updated_for_profile(self) -> int:
        """
        get last updated associated with profile.

        :return: last updated associated with profile.
        :rtype: int
        """
        return self.profile_last_updated

    def get_list_of_agents(self) -> int:
        """
        get list of agents associated with profile.

        :return: list of agents associated with profile.
        :rtype: int
        """
        self.agents_tab.click()
        return [agent.agents_group_name.text for agent in self.rows]
        return self.rows.count


class ProfileAgentsRecords(GenericTableRow):
    """Defines the key names for Profile Agent records returned."""
    checkbox = Find(Clickable, by=By.CSS_SELECTOR, value='td:nth-child(1)')
    agent_name = Find(by=By.CSS_SELECTOR, value='td:nth-child(2)')
    status = Find(by=By.CSS_SELECTOR, value='td:nth-child(3)')
    ip_address = Find(by=By.CSS_SELECTOR, value='td:nth-child(4)')
    platform = Find(by=By.CSS_SELECTOR, value='td:nth-child(5)')
    groups = Find(Clickable, by=By.CSS_SELECTOR, value='td:nth-child(6)')
    version = Find(Clickable, by=By.CSS_SELECTOR, value='td:nth-child(7)')
    last_plugin_update = Find(Clickable, by=By.CSS_SELECTOR, value='td:nth-child(8)')
    last_scanned = Find(Clickable, by=By.CSS_SELECTOR, value='td:nth-child(9)')

    @property
    def name(self):
        """ Returns name attribute of a row """
        return self.agent_name.text

    @property
    def status(self):
        """ Returns status attribute of a row """
        return self.status.text

    @property
    def ip_address(self):
        """ Returns ip_address attribute of a row """
        return self.ip_address.text

    @property
    def platform(self):
        """ Returns platform attribute of a row """
        return self.platform.text
    
    @property
    def groups(self):
        """ Returns groups attribute of a row """
        return self.groups.text

    @property
    def version(self):
        """ Returns version attribute of a row """
        return self.version.text

    @property
    def last_plugin_update(self):
        """ Returns last_plugin_update attribute of a row """
        return self.last_plugin_update.text

    @property
    def last_scanned(self):
        """ Returns last_scanned attribute of a row """
        return self.last_scanned.text


class ProfileAgentsList(AgentObjectList, ActionCloseModal):
    """Returns a list containing agents displayed on the Agent Profile Agents Tab."""
    configure_button = None
    generics_map = {GenericTableRow: ProfileAgentsRecords}
    add_agents_button = Find(by=By.CSS_SELECTOR, value="#add")
    add_agents_link = Find(by=By.CSS_SELECTOR, value="a.agent-profiles-add")
    no_agents_added_text = Find(TextField, by=By.CSS_SELECTOR, value="span.empty-results")
    add_agents_modal = Find(Clickable, by=By.XPATH, value="//*[@class='modal-title']")
    modal_close_button = Find(Clickable, by=By.CSS_SELECTOR, value='div.modal-close .remove')
    modal_cancel_button = Find(Clickable, by=By.XPATH, value="//*[contains(text(), 'Cancel')]")
    add_agents_modal = Find(Clickable, by=By.XPATH, value="//*[@class='modal-title']")

    def __init__(self):
        super().__init__()

    def loaded(self, **kwargs):
        """waits for the list of agent to populate"""
        self.is_element_present('rows', timeout=TIME_THIRTY_SECONDS)

    def get_all_agents(self) -> list:
        """
        Returns the list of all agents names
        :return: list of all agents names
        :rtype: list
        """
        return [agents.agent_name.text for agents in self.rows]


class AddProfilesRecord(GenericTableRow):
    """Defines the key names for Profiles Records returned by ProfilesList."""
    profile_name_input = Find(TextField, by=By.CSS_SELECTOR, value='input[data-domselect="Name"]')
    description_input = Find(TextField, by=By.CSS_SELECTOR, value='input[data-domselect="Description"]')


class AddProfileModal(ActionCloseModal, AddProfilesRecord):
    def create_profile(self):
        self.profile_name_input.value = 'Test Profile'
        self.description_input.value = 'Test adding a profile'
        return self.action_button.click()


class AddAgentProfileRecord(GenericTableRow):
    """ Defines the key names for Agent Group Records returned by AddAgentGroupList. """

    member_agents = Finds(by=By.CSS_SELECTOR, value='.modal tr.agent-group')
    select_all_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div.select-all')
    select = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='td:nth-child(1)')


class AddAgentProfileList(AgentObjectList):
    """ Returns a list containing agent group displayed in Add agent group pop up. """
    configure_button = None
    generics_map = {GenericTableRow: AddAgentProfileRecord}
    modal_agent_profile_columns = Finds(by=By.CSS_SELECTOR, value='th[aria-controls*="DataTables_Table"]')
    modal_agent_rows = Finds(by=By.CSS_SELECTOR, value='tr.agent')
    modal_agent_first_row = Find(by=By.CSS_SELECTOR, value='tr:nth-child(1)')

    def get_all_agent_names(self):
        """
        This function returns all agent group names present in "Add Agent Group' modal.
        """
        return [agent.find_element(By.CSS_SELECTOR, 'td:nth-child(2)').text for agent in self.modal_agent_rows]
