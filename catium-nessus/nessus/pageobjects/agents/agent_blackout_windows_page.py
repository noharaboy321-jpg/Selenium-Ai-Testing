"""
Nessus agent related window page

Agent Blackout Windows classes

:copyright: Tenable Network Security, 2017
:date: July 25, 2017
:last_modified: Nov 23, 2020
:author: @smadan @rdutta, @kpanchal
"""

from selenium.webdriver.common.by import By
from waiting import wait

from catium.lib.cat_registry import cat_registry
from catium.lib.const import WAIT_SHORT
from catium.lib.log import create_logger
from catium.lib.pageobject_helper import get_element_text
from catium.lib.webium import Find, Finds
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.link import Link
from catium.lib.webium.controls.table import GenericTableRow, GenericTableColumn
from catium.lib.webium.controls.text_field import TextField
from nessus.lib.const.constants import API
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.generic.object_list import ObjectList
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.shared.loading import LoadingCircle

log = create_logger()


# Data constructs
class AgentBlackoutWindowRecord(GenericTableRow):
    """Defines the key names for Blackout Window Records returned by AgentBlackoutWindowList"""
    checkbox = Find(Clickable, by=By.CSS_SELECTOR, value='td:nth-child(1)')
    record_name_element = Find(by=By.CSS_SELECTOR, value='td:nth-child(2)')
    schedule_summary_element = Find(by=By.CSS_SELECTOR, value='td:nth-child(3)')
    last_modified_element = Find(by=By.CSS_SELECTOR, value='td:nth-child(4)')
    delete = Find(Clickable, by=By.CSS_SELECTOR, value='td:nth-child(5)')

    @property
    def agent_blackout_window_name(self):
        """ Retrieves the name of the blackout window. """
        return get_element_text(self.record_name_element)

    @property
    def agent_blackout_window_summary(self):
        """ Retrieves the text that describes the time period the blackout window covers. """
        return get_element_text(self.schedule_summary_element)

    @property
    def object_name(self):
        """ Returns the name of the blackout window. """
        return self.agent_blackout_window_name

    @property
    def schedule_text(self):
        """ Returns the text that describes the time period the blackout window covers. """
        return self.agent_blackout_window_summary

    @property
    def last_modified(self):
        """ Returns the timestamp at which the blackout window was last modified. """
        return int(self.last_modified_element.get_attribute('data-order'))

    @property
    def blackout_enabled(self):
        """ Returns a tr attribute that shows whether the blackout window is enabled or not. """
        return self.get_attribute('data-status') == API.Status.ENABLED


class AgentBlackoutWindowList(ObjectList):
    """Returns a list containing Agent Blackout Windows displayed on the Agent Blackout Window Management Page"""
    configure_button = None
    generics_map = {GenericTableRow: AgentBlackoutWindowRecord}

    @property
    def blackout_window_all_names(self) -> list:
        """Returns a list of  existing Agent Blackout Window Names"""
        return [row.record_name_element.text for row in self.rows]

    @property
    def blackout_window_last_modified_list(self) -> list:
        """Returns a list of  existing Agent Blackout Window last modified time"""
        return [row.last_modified_element.text for row in self.rows]

    def delete_blackout_windows(self, blackout_window_name: str, close_modal: bool = True) -> None:
        """
        Deletes the Agent Blackout window for the provided name
        
        :param str blackout_window_name:  Name of blackout window
        :param bool close_modal: True if modal needs to be closed else False
        """
        for row in self.rows:
            if row.record_name_element.text == blackout_window_name:
                row.delete.click()
                if close_modal:
                    ActionCloseModal().accept_action()
                    LoadingCircle(WAIT_SHORT)

    def click_on_created_window(self, new_blackout_window_name: str) -> None:
        """
        Method to click on the blackout window of the specified name
        
        :param str new_blackout_window_name: Name of blackout window
        """
        if not len(self.rows) == 0:
            for blackout_name in self.rows:
                if blackout_name.record_name_element.text == new_blackout_window_name:
                    blackout_name.record_name_element.click()
                    break

    def get_schedule_summary_of_created_window(self, edit_blackout_window_name: str, frequency: str) -> bool:
        """
        Returns true if the frequency specified matches to the frequency of the blackout window
        
        :param str edit_blackout_window_name: Name of blackout window
        :param str frequency: frequency for blackout window
        """
        for edited_list in self.rows:
            if edited_list.record_name_element.text == edit_blackout_window_name:
                if frequency.lower() in edited_list.schedule_summary_element.text.lower():
                    return True
        return False


class AgentBlackoutWindowColumn(ObjectList):
    """Page Object for Agent Blackout Windows Table Column in Nessus"""

    configure_button = None

    col_name = Find(GenericTableColumn, by=By.CSS_SELECTOR, value='.pointer.sorting_asc')
    col_date = Find(GenericTableColumn, by=By.CSS_SELECTOR, value='.pointer.w150.sorting')


@cat_registry.route(r'sensors/agent-freeze-windows')
class AgentBlackoutWindowsPage(NessusBasePage):
    """Page Object for Agent Blackout Windows Page in Nessus"""

    new_button = Find(Clickable, by=By.CSS_SELECTOR, value='#titlebar a[href="#/sensors/agent-freeze-windows/new"]')
    freeze_window_title = Find(by=By.CSS_SELECTOR, value='#titlebar h1')
    create_new_freeze_window = Find(by=By.CSS_SELECTOR, value='span a[href="#/sensors/agent-freeze-windows/new"]')
    freeze_window_tab = Find(by=By.CSS_SELECTOR, value='a[data-name="Blackout Windows"]')
    freeze_window_settings_tab = Find(by=By.CSS_SELECTOR, value='a[data-name="Blackout Window Settings"]')
    freeze_window_description = Find(by=By.CSS_SELECTOR, value='div.description-copy')
    new_link = Find(Link, by=By.CSS_SELECTOR, value='span.empty-results a')
    enable_button = Find(Clickable, by=By.CSS_SELECTOR, value='#enable')
    disable_button = Find(Clickable, by=By.CSS_SELECTOR, value='#disable')
    delete_button = Find(Clickable, by=By.CSS_SELECTOR, value='#delete')
    search_window = Find(TextField, by=By.CSS_SELECTOR, value='input[data-domselect="searchInput"]')
    setting_options = Finds(TextField, by=By.CSS_SELECTOR, value="span.no-edit.exclude-checkbox-warning")
    freeze_window_button_bar = Find(by=By.CSS_SELECTOR, value='ul.button-bar')
    summary_field = Find(by=By.CSS_SELECTOR, value='[data-name="Summary"]')
    back_to_freeze_window = Find(Clickable, by=By.CSS_SELECTOR, value='#titlebar [href="#/sensors/agent-freeze-windows"]')
    name_field = Find(by=By.CSS_SELECTOR, value='[aria-label="Name"]')
    enabled_toogle_field = Find(by=By.CSS_SELECTOR, value='[data-name="schedule-config"] label')
    enabled_toogle_button = Find(Clickable, by=By.CSS_SELECTOR, value='.toggle-switch')
    frequency_dropdown = Find(Clickable, by=By.CSS_SELECTOR, value='[title="Once"]')
    start_time_dropdown = Find(Clickable, by=By.CSS_SELECTOR, value='[data-name="Starts Times"]+span')
    end_time_dropdown = Find(Clickable, by=By.CSS_SELECTOR, value='[data-name="Ends Times"]+span')
    start_date_dropdown = Find(Clickable, by=By.CSS_SELECTOR, value='[name="startDate"]')
    end_date_dropdown = Find(Clickable, by=By.CSS_SELECTOR, value='[name="endDate"]')
    timezone_dropdown = Find(Clickable, by=By.CSS_SELECTOR, value='[data-name="Timezone"]+span')
    cancel_button = Find(Clickable, by=By.CSS_SELECTOR, value='[type = "submit"]+a')
    save_button = Find(Clickable, by=By.CSS_SELECTOR, value='[type = "submit"]')

    def __init__(self):
        super().__init__()

    def toggle_agent_blackout_window(self, blackout_window_name: str, option: str) -> None:
        """ 
        Enables or Disable the Agent Blackout Window
        
        :param str blackout_window_name: Name of blackout window
        :param str option: Disable or Enable option
        """
        agent_list = AgentBlackoutWindowList()
        for row in agent_list.rows:
            if blackout_window_name == row.record_name_element.text:
                row.checkbox.click()
                if option == API.Status.DISABLE:
                    self.disable_button.click()
                elif option == API.Status.ENABLE:
                    self.enable_button.click()
                ActionCloseModal().accept_action()

    def delete_blackout_window_list(self):
        """Delete the Agent Blackout Window list using select-all checkbox"""

        AgentBlackoutWindowList().select_all_checkbox.click()
        self.delete_button.click()
        ActionCloseModal().accept_action()


# Agent Blackout Window Settings route/view
@cat_registry.route(r'sensors/agent-freeze-windows/settings')
class AgentBlackoutWindowSettingsPage(NessusBasePage):
    """Page Object for Agent Blackout Window Settings Page in Nessus"""

    save_button = Find(Clickable, by=By.CSS_SELECTOR, value='button[data-domselect="Save"]')

    def __init__(self):
        super().__init__()

    def get_checkbox_element_for_blackout_window(self, data_name: str) -> CheckboxDiv:
        """
        Get checkbox element for blackout window settings
        :param str data_name: Value of data-name attribute of an element
        :return: Checkbox element
        :rtype: CheckboxDiv
        """
        return Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div[data-name*="{}"]'.format(data_name), context=self)

    def get_permanent_blackout_window_checkbox(self) -> CheckboxDiv:
        """
        This method will click on permanent_blackout_window checkbox element and save the agent settings
        :return: Checkbox element for permanent blackout window checkbox
        :rtype: CheckboxDiv
        """
        return self.get_checkbox_element_for_blackout_window(data_name="permanent blackout")

    def get_prevent_core_update_checkbox(self) -> CheckboxDiv:
        """
        This method will click on prevent_core_update checkbox element and save the agent settings
        :return: Checkbox element for prevent software update checkbox
        :rtype: CheckboxDiv
        """
        return self.get_checkbox_element_for_blackout_window(data_name="Prevent core updates")

    def enable_or_disable_agent_settings(self, option_list: list) -> None:
        """
        This method enables/disables given agent settings options.
        :param option_list: list of agent setting options that needs to be enabled/disabled
        :param action: enabled or disabled
        :return: None
        """
        self.open()
        wait(lambda: self.is_element_present('save_button'), waiting_for='Blackout windows page loads properly')

        for option_name in option_list:
            if option_name['setting_action'] == "enable":
                self.get_checkbox_element_for_blackout_window(data_name=option_name['setting_name']).check()
            elif option_name['setting_action'] == "disable":
                self.get_checkbox_element_for_blackout_window(data_name=option_name['setting_name']).uncheck()
        self.save_button.click()
        wait(lambda: Notifications().successes, waiting_for='notification list to populate')
