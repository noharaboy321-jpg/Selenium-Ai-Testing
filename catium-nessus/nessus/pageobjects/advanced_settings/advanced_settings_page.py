"""
Nessus advanced setting related window page
Advanced Settings Window Classes

:copyright: Tenable Network Security, 2017
:date: July 21, 2017
:last_modified: Nov 11, 2021
:author: @jamreliya, @smadan, @rdutta, @ntarwani, @yshah, @jchavda, @kpanchal
"""
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement

from catium.helpers.sleep_lib import sleep
from catium.lib.cat_registry import cat_registry
from catium.lib.const.base_constants import WAIT_NORMAL, WAIT_SHORT
from catium.lib.webium import Find, Finds
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.link import Link
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.table import GenericTableRow
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.wait import webium_wait as wait
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.generic.object_list import ObjectList


class NoticeAdvancedSettings(NessusBasePage):
    """ restart and discard button once advanced setting changed"""

    notice_restart = Find(Clickable, by=By.ID, value='advanced-settings-restart')
    notice_discard_changes = Find(Clickable, by=By.ID, value='advanced-settings-discard')
    connection_popup = Find(by=By.XPATH, value="//*[@id='modal-inside']/div/div/div[1]")

    def restart(self):
        """Restart Nessus and wait until its over."""
        self.notice_restart.click()
        wait(lambda: not self.is_element_present(self.connection_popup), timeout_seconds=WAIT_NORMAL)


class AdvancedSettingRecord(GenericTableRow):
    """Defines the key names for Settings Records returned by SettingsList"""
    setting = Find(Clickable, by=By.CSS_SELECTOR, value="th[aria-label*='Setting']")
    identifier = Find(Clickable, by=By.CSS_SELECTOR, value="th[aria-label*='Identifier']")
    setting_name_element = Find(by=By.CSS_SELECTOR, value='td.pointer:nth-child(1)')
    setting_identifier_element = Find(by=By.CSS_SELECTOR, value='td.pointer:nth-child(2)')
    setting_value_element = Find(by=By.CSS_SELECTOR, value='td.pointer:nth-child(3)')
    delete_button = Find(Clickable, by=By.CSS_SELECTOR, value='.glyphicons.bin')

    @property
    def setting_name(self):
        """Returns name of the settings."""
        return self.setting_name_element.text

    @property
    def setting_identifier(self):
        """Returns identifier of the settings."""
        return self.setting_identifier_element.text


class AdvancedSettingsList(ObjectList):
    """Returns a list containing Settings displayed on the Settings Management Page"""
    configure_button = None
    generics_map = {GenericTableRow: AdvancedSettingRecord}
    user_interface_tab = Find(Clickable, by=By.CSS_SELECTOR, value="#tabs-2 a[data-view='UI']")
    scanning_tab = Find(Clickable, by=By.CSS_SELECTOR, value="#tabs-2 a[data-view='Scanning']")
    logging_tab = Find(Clickable, by=By.CSS_SELECTOR, value="#tabs-2 a[data-view='Logging']")
    performance_tab = Find(Clickable, by=By.CSS_SELECTOR, value="#tabs-2 a[data-view='Performance']")
    security_tab = Find(Clickable, by=By.CSS_SELECTOR, value="#tabs-2 a[data-view='Security']")
    agents_and_scanners_tab = Find(Clickable, by=By.CSS_SELECTOR, value="#tabs-2 a[data-view='Agents_and_MS']")
    miscellaneous_tab = Find(Clickable, by=By.CSS_SELECTOR, value="#tabs-2 a[data-view='Misc']")
    custom_tab = Find(Clickable, by=By.CSS_SELECTOR, value="#tabs-2 a[data-view='Custom']")
    nessus_restart_settings = Finds(by=By.XPATH, value='.//*[@class="glyphicons info"]//preceding::td[3]')
    empty_advanced_settings = Find(by=By.CSS_SELECTOR, value='.dataTables_empty')

    def get_setting_remove_icon(self, setting_name: str) -> WebElement:
        """
        return the status locator specific to setting
        :param str setting_name: name of the setting
        :return: locator specific to setting
        :rtype: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value='tr[data-name="{}"] .glyphicons.remove'.format(setting_name),
                    context=self)

    def get_specific_setting_value(self, setting_name: str) -> WebElement:
        """
        Returns the web element of setting's value
        :param str setting_name: Name of the setting
        :return: web element of setting's value
        :rtype: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value='[data-name="{}"]>td:nth-child(3)'.format(setting_name),
                    context=self)

    def get_delete_icon(self, setting_name: str) -> WebElement:
        """
        Returns the web element of delete icon
        :param str setting_name: Name of the setting
        :return: web element of delete icon
        :rtype: WebElement
        """
        return Find(Clickable, by=By.CSS_SELECTOR,
                    value='tr[data-name="{}"]>td>.glyphicons.bin'.format(setting_name), context=self)

    def get_all_settings_name(self, setting_tab: str = None) -> list:
        """
        Return list of all advanced setting names

        :param str setting_tab: Name of setting tab
        :return: list of all settings name
        :rtype: list
        """
        if setting_tab:
            AdvancedSettingsPage().get_settings_tab_element(setting_tab=setting_tab).click()
            sleep(WAIT_NORMAL, reason="It takes little bit time to get settings loaded")

        try:
            return [row.setting_name_element.text for row in self.rows]
        except NoSuchElementException:
            return []
     

    def get_settings_value(self, setting_tab: str = None, setting_name: str = None) -> list:
        """
        Returns list containing values of given setting name

        :param str setting_tab: Name of setting tab
        :param str setting_name: Name of the setting
        :return: list containing values of settings value
        :rtype: list
        """
        if setting_tab:
            AdvancedSettingsPage().get_settings_tab_element(setting_tab=setting_tab).click()

        try:
            if setting_name is not None:
                return [self.get_specific_setting_value(setting_name=setting_name).text]
            else:
                return [row.setting_value_element.text for row in self.rows]
        except NoSuchElementException:
            return []

    def delete_setting(self, setting_name: str) -> None:
        """
        Deletes a particular advanced setting
        :param str setting_name: Name of advanced setting
        :return: None
        """
        AdvancedSettingsList.custom_tab.click()
        for setting in self.rows:
            if setting.setting_value_element.text == setting_name:
                setting.delete_button.click()
                ActionCloseModal().accept_action()
                break

    def delete_custom_setting(self, setting_name: str) -> None:
        """
        Delete the custom setting of specified setting name
        :param str setting_name: Name of the setting.
        :return: None
        """
        self.get_delete_icon(setting_name=setting_name).click()
        delete_modal = ActionCloseModal()
        delete_modal.accept_action()
        delete_modal.wait_for_modal_closed()

    def edit_or_add_setting(self, setting_name: str, setting_value: str) -> None:
        """
        Adds or edit setting with particular name and value        
        :param str setting_name: Name of advanced setting 
        :param str setting_value: Value for advanced setting
        :return: None
        """
        for setting in self.rows:
            if setting.setting_identifier_element.text == setting_name:
                setting.setting_name_element.click()
                AddAdvancedSettingModal().change_setting(setting_value)
                return
        AdvancedSettingsPage().new_button.click()
        AddAdvancedSettingModal().add_setting(setting_name, setting_value)

    def get_settings_names_by_tab(self, setting_tab: str = None) -> list:
        """
        Return list of all advanced setting names
        :param str setting_tab: Name of the setting
        :return: list of all setting name related to setting tab
        :rtype: list
        """
        try:
            if setting_tab is not None:
                AdvancedSettingsPage().get_settings_tab_element(setting_tab=setting_tab).click()
            return [row.setting_name_element.text for row in self.rows]
        except NoSuchElementException:
            return []

    def get_setting_name_requires_restart(self, setting_tab: str = None) -> list:
        """
        Return list of all advanced setting names which requires to restart

        :param str setting_tab: Name of the setting
        :return: setting names which requires to restart
        :rtype: list
        """
        try:
            if setting_tab:
                AdvancedSettingsPage().get_settings_tab_element(setting_tab=setting_tab).click()
            return [restart_setting.text for restart_setting in self.nessus_restart_settings]
        except NoSuchElementException:
            return []

    def get_setting_identifiers_by_tab(self, setting_tab: str = None) -> list:
        """
        Return list of all advanced setting identifiers
        :param str setting_tab: Name of the setting
        :return: List of all setting identifiers name
        :rtype: list
        """
        try:
            if setting_tab is not None:
                AdvancedSettingsPage().get_settings_tab_element(setting_tab=setting_tab).click()

            return [row.setting_identifier_element.text for row in self.rows]
        except NoSuchElementException:
            return []


@cat_registry.route(r'settings/advanced')
class AdvancedSettingsPage(NessusBasePage):
    """Advanced Settings of System Administrator View."""
    new_button = Find(Clickable, by=By.ID, value='advanced-settings-new')
    setting_search_box = Find(TextField, by=By.CSS_SELECTOR, value='#searchbox > input')
    search_textbox = Find(TextField, by=By.CSS_SELECTOR, value='input[data-search="search-advanced-settings"]')
    settings_count = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Total Records"]>b')
    advanced_setting_title = Find(by=By.CSS_SELECTOR, value="#titlebar>h1")
    settings_tabs_name = Finds(Clickable, by=By.CSS_SELECTOR, value="#tabs-2>a")
    setting_header = Find(by=By.CSS_SELECTOR, value='tr[role="row"]>th:nth-child(1)')
    identifier_header = Find(by=By.CSS_SELECTOR, value='tr[role="row"]>th:nth-child(2)')
    value_header = Find(by=By.CSS_SELECTOR, value='tr[role="row"]>th:nth-child(3)')
    reset_icon = Finds(by=By.CSS_SELECTOR, value='.glyphicons.refresh')
    info_icons = Finds(by=By.CSS_SELECTOR, value='.glyphicons.info')
    warn_message_for_restart = Find(by=By.CSS_SELECTOR, value='.warn-message')
    service_restart_link = Find(Clickable, by=By.CSS_SELECTOR, value='#advanced-settings-restart')
    search_box_clear_icon = Find(Clickable, by=By.CSS_SELECTOR, value='.glyphicons.remove')
    search_result_count = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Results"] > b')
    search_textbox_search_icon = Find(by=By.CSS_SELECTOR, value='.glyphicons.search')
    search_textbox_remove_icon = Find(by=By.CSS_SELECTOR, value='.glyphicons.remove')
    search_settings_count_label = Find(by=By.CSS_SELECTOR, value='[data-domselect="Advanced Searchbox"] > span')
    setting_tabs_section = Find(by=By.CSS_SELECTOR, value="#tabs-2")
    no_record_found = Find(by=By.CSS_SELECTOR, value='.dataTables_empty')

    def __init__(self):
        super().__init__()
        self.required_elements = ['setting_search_box']

    def get_dynamic_element_for_setting_name(self, setting_name: str) -> WebElement:
        """
        Returns web element for setting name
        :param str setting_name: setting name from the list of settings
        :return: Web element for setting name
        :rtype: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value='tr[data-name="{}"] td[class*="sorting"]'.format(setting_name),
                    context=self)

    def get_settings_tab_element(self, setting_tab: str) -> WebElement:
        """
        Returns the locator of settings tabs
        :param str setting_tab: Name of the setting
        :return: Locator of settings tabs
        :rtype: WebElement
        """
        sleep(WAIT_NORMAL, reason="It takes little bit time to click on load.")
        return Find(Link, by=By.CSS_SELECTOR, value='#tabs-2 a[data-view="{}"]'.format(setting_tab), context=self)

    def get_setting_search_results_count(self, setting_tab: str) -> WebElement:
        """
        Returns the search result count of settings from each setting tab

        :param str setting_tab: Name of the setting
        :return: Locator of search result count from each setting tab
        :rtype: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value='a[data-view="{}"]>span[data-domselect="Results"]'.format(setting_tab),
                    context=self)

    def get_list_of_all_tabs_name(self) -> list:
        """
        Returns the list of all settings sub tab names
        :return: list: list of all sub-tabs name i.e. ["User Interface", "Security"]
        :rtype: list
        """
        sleep(WAIT_NORMAL, reason="It takes little bit time to click on load.")
        tab_list = list(filter(None, [setting_tab.text.split("\n")[1] if "\n" in setting_tab.text else
                                      setting_tab.text for setting_tab in self.settings_tabs_name]))

        for setting_tab in tab_list:
            if setting_tab == "User Interface":
                tab_list[tab_list.index(setting_tab)] = "UI"
            elif setting_tab == "Agents & Scanners":
                tab_list[tab_list.index(setting_tab)] = "Agents_and_MS"
            elif setting_tab == "Miscellaneous":
                tab_list[tab_list.index(setting_tab)] = "Misc"

        return tab_list

    def get_all_settings_count(self) -> int:
        """
        Returns the total count of the settings
        :return: int: count of total settings including each sub tab.
        :rtype: int
        """
        count = 0
        for setting_tab in self.get_list_of_all_tabs_name():
            self.get_settings_tab_element(setting_tab=setting_tab).click()
            count += len(AdvancedSettingsList().get_settings_names_by_tab())
        return count

    def get_list_of_visible_tabs_name(self) -> list:
        """
        Returns the list of visible settings sub tab names

        :return: list of visible sub-tabs name i.e. ["User Interface", "Security"]
        :rtype: list
        """
        tab_list = []
        visible_tabs_list = [setting_tab.text for setting_tab in self.settings_tabs_name if "tab-visible" in
                             setting_tab.get_css_classes()]

        if len(visible_tabs_list) > 0:
            tab_list = [tab_name.split('\n')[1] if '\n' in tab_name else tab_name for tab_name in visible_tabs_list]

            for setting_tab in tab_list:
                if setting_tab == "User Interface":
                    tab_list[tab_list.index(setting_tab)] = "UI"
                elif setting_tab == "Agents & Scanners":
                    tab_list[tab_list.index(setting_tab)] = "Agents_and_MS"
                elif setting_tab == "Miscellaneous":
                    tab_list[tab_list.index(setting_tab)] = "Misc"

        return tab_list

    def get_setting_counts_after_applying_filter_each_tab(self, setting_tab: str) -> str:
        """
        Returns the counts of settings of each tab

        :param str setting_tab: Name of the setting
        :return: The counts of settings of each tab
        :rtype: str
        """
        return Find(by=By.CSS_SELECTOR, value='a[data-view="{}"] > span[data-domselect="Results"]'.format(setting_tab),
                    context=self).text


class AddAdvancedSettingModal(ActionCloseModal):
    """Page Object for creating Advanced Setting Modal Window"""
    name = Find(TextField, by=By.CSS_SELECTOR, value='input[data-domselect="Name"]')
    advanced_setting_value = Find(TextField, by=By.CSS_SELECTOR, value='input[data-domselect="Value"]')
    allow_post_scan_edit_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR,
                                         value='select[aria-label="Allowable Values"]')
    input_field_setting_banner = Find(TextField, by=By.CSS_SELECTOR, value=".validate")
    save_setting_banner = Find(TextField, by=By.CSS_SELECTOR, value="#advanced-settings-add")
    cancel_icon = Find(Clickable, by=By.CSS_SELECTOR, value=".inline-input-icon")
    custom_value_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-name="allowable_values"]')
    setting_description = Find(TextField, by=By.CSS_SELECTOR, value='.form-group.description')

    def __init__(self):
        super().__init__()

    def find_specific_setting_name(self, setting_name: str) -> WebElement:
        """
        Return the WebElement of setting row
        :param str setting_name: Name of the setting
        :return: Element of setting row
        :rtype: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value='tr[data-name="{}"]>td:nth-child(2)'.format(setting_name),
                    context=self)

    def get_reset_for_specific_setting(self, setting_name: str) -> WebElement:
        """
        Returns the WebElement of reset icon for specific setting name
        :param str setting_name: Name of the setting
        :return: Locator of reset icon for specific setting name
        :rtype: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value='tr[data-name="{}"] td .glyphicons.refresh'.format(setting_name),
                    context=self)

    def add_setting(self, setting_name: str, setting_value: str) -> None:
        """
        Add an advanced setting with particular name and value
        :param str setting_name: Name of advanced setting
        :param str setting_value: Value for advanced setting
        :return: None
        """
        self.name.value = setting_name
        self.advanced_setting_value.value = setting_value
        self.action_button.click()
        self.wait_for_modal_closed()

    def add_setting_value(self, setting_value: str) -> None:
        """
        Add an advanced setting with particular value only
        :param str setting_value: Value for advanced setting
        :return: None
        """
        self.advanced_setting_value.value = setting_value
        self.action_button.click()
        self.wait_for_modal_closed()

    def change_setting(self, setting_value: str) -> None:
        """
        Edit advanced setting by changing the previous value to another
        :param str setting_value: Value for advanced setting
        :return: None
        """
        self.allow_post_scan_edit_dropdown.select_by_visible_text(setting_value)
        self.action_button.click()
        self.wait_for_modal_closed()

    def fill_existing_setting_banner(self, setting_name: str, setting_value: str, setting_tab: str = None) -> None:
        """
        Fill the existing setting banner by providing the value of setting tab, setting name and setting value.

        :param str setting_name: Name of the setting i.e. "login_banner".
        :param str setting_value: Value of the setting i.e. "banner"
        :param str setting_tab: Setting sub tab name i.e. "Custom"
        :return: None
        """
        if setting_tab:
            AdvancedSettingsPage().get_settings_tab_element(setting_tab=setting_tab).click()

        self.find_specific_setting_name(setting_name=setting_name).click()
        self.input_field_setting_banner.clear()
        self.input_field_setting_banner.value = setting_value
        self.action_button.click()

    def select_value_from_setting_dropdown(self, setting_name: str, setting_value: str,
                                           setting_tab: str = None) -> None:
        """
        Select and set the dropdown value in setting banner for given setting name in given setting tab.
        :param str setting_name: Name of the setting i.e. "login_banner".
        :param str setting_value: Value of the setting i.e. "Yes/No"
        :param str setting_tab: Setting sub tab name i.e. "Custom"
        :return: None
        """
        if setting_tab:
            AdvancedSettingsPage().get_settings_tab_element(setting_tab=setting_tab).click()
        self.find_specific_setting_name(setting_name=setting_name).click()
        self.allow_post_scan_edit_dropdown.select_by_visible_text(setting_value)
        self.action_button.click()
        self.wait_for_modal_closed()

    def reset_setting_banner(self, setting_name: str) -> None:
        """
        Reset the banner to default value
        :param str setting_name: Name of the setting i.e. "login_banner".
        :return: None
        """
        self.get_reset_for_specific_setting(setting_name=setting_name).click()
        self.action_button.click()


class UIThemeSettingPage(NessusBasePage):
    """ Page Object for "ui_theme" Setting """

    side_nav_section = Find(by=By.ID, value='sidenav')
    layout_section = Find(by=By.ID, value='layout')
    header = Find(by=By.TAG_NAME, value='header')
