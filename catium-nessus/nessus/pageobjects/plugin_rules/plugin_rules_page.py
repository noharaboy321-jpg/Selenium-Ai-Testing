"""
Nessus page object class for plugin rules page

:copyright: Tenable Network Security, 2017
:date: September 16, 2017
:last_modified: Aug 19, 2019
:author: @rdutta, @kpanchal
"""

from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By

from catium.lib import const
from catium.lib.cat_registry import cat_registry
from catium.lib.const import WAIT_TINY, WAIT_SHORT
from catium.lib.log import create_logger
from catium.lib.webium import Find
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.date_picker import DatePicker
from catium.lib.webium.controls.link import Link
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.table import GenericTableRow, GenericBaseTable
from catium.lib.webium.controls.text_field import TextField
from nessus.helpers.date_selector import select_date_in_datepicker
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.generic.generic_modals import UnsavedChangesModal
from nessus.pageobjects.generic.object_list import ObjectList
from nessus.pageobjects.shared.loading import LoadingCircle

log = create_logger()


class NewRuleWindow(NessusBasePage):
    """ Page objects of new/edit rule window to add/modify plugin rule details."""
    host = Find(TextField, by=By.CSS_SELECTOR, value='.plugin-host')
    plugin_id = Find(TextField, by=By.CSS_SELECTOR, value='.validate.plugin-id')
    expiration_date = Find(Clickable, by=By.CSS_SELECTOR, value='.plugin-expiration.hasDatepicker')
    expiration_date_input = Find(TextField, by=By.CSS_SELECTOR, value='.form-group>input[aria-label="Expiration Date"]')
    severity = Find(Select2Dropdown, by=By.CSS_SELECTOR, value=".severity")
    select_date = Find(DatePicker, by=By.CSS_SELECTOR, value='div#ui-datepicker-div')
    current_date = Find(by=By.CSS_SELECTOR, value='.ui-datepicker-today')
    expiration_date_block = Find(by=By.CSS_SELECTOR, value='#ui-datepicker-div')
    select_all = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='.select-all')
    previous_date = Find(by=By.XPATH, value=".//*[contains(@class,'ui-datepicker-today')]//preceding::td[1]")

    def fill_rule_details(self, **kwargs) -> None:
        """
        set the values depending on kwargs
        :return: None
        """
        host_value = kwargs.get("host", '')
        plugin_id = kwargs.get("plugin_id", '')
        expiry_date = kwargs.get("expiry_date")
        severity = kwargs.get("severity", 'Hide this result')

        self.host.value = host_value
        LoadingCircle(WAIT_SHORT)

        self.plugin_id.value = plugin_id
        LoadingCircle(WAIT_SHORT)

        if expiry_date:
            if '/' in expiry_date:
                self.expiration_date_input.value = expiry_date
                UnsavedChangesModal().unsaved_changes_title.click()

            else:
                self.expiration_date.click()
                select_date_in_datepicker(page_class_instance=self, input_date=expiry_date)

        self.severity.select_by_visible_text(severity)


@cat_registry.route(r'scans/plugin-rules')
class PluginRulesPage(NewRuleWindow, ActionCloseModal, NessusBasePage):
    """ Defines properties and methods inherited by the Nessus plugin rules Page. """

    new_rule_button = Find(Clickable, by=By.CSS_SELECTOR, value='#add-plugin-rule')
    delete_button = Find(Clickable, by=By.CSS_SELECTOR, value='#delete-plugin-rule')
    search_rule = Find(TextField, by=By.CSS_SELECTOR, value='input[data-domselect="searchInput"]')
    remove_search_icon = Find(Clickable, by=By.CSS_SELECTOR, value='#searchbox .remove')
    new_plugin_rule_link = Find(Link, by=By.CLASS_NAME, value='add-plugin-rule')
    plugin_rule_description = Find(by=By.CLASS_NAME, value='description-group')
    plugin_rule_icon = Find(by=By.CSS_SELECTOR, value=".glyphicons.plugin-rules")

    def __init__(self):
        super().__init__()
        self.required_elements = ['new_rule_button']

    def add_new_plugin_rule(self, **kwargs) -> None:
        """
        Add a new plugIn rule by filling up rule details
        :param kwargs: details to create a plugin rule
        """
        self.js_scroll_into_view(self.new_rule_button)
        self.new_rule_button.click()
        self.fill_rule_details(**kwargs)
        self.accept_action()
        self.wait_for_modal_closed()

    def edit_plugin_rule(self, **kwargs) -> None:
        """
        Edit existing plugin rule.
        :param kwargs: details to edit plugin rule
        :return: None
        """
        PluginRulesList().click_on_plugin_rule(plugin_id=kwargs.get('plugin_id'))
        self.fill_rule_details(**kwargs)
        self.accept_action()
        self.wait_for_modal_closed()

    def delete_all_plugin_rules(self) -> None:
        """
        Delete all plugin rules

        :return: None 
        """
        self.select_all.click()
        self.js_scroll_into_view(element=self.delete_button)
        self.delete_button.click()
        action_modal = ActionCloseModal()
        action_modal.accept_action()
        action_modal.wait_for_modal_closed()


class PluginRulesRecord(GenericTableRow):
    """Defines the key names for plugins Records returned by PluginRulesList ."""

    plugin_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='td:nth-child(1) > div')
    plugin_host = Find(by=By.CSS_SELECTOR, value='td:nth-child(2)')
    plugin_id = Find(by=By.CSS_SELECTOR, value='td:nth-child(3)')
    expiration = Find(by=By.CSS_SELECTOR, value='td:nth-child(4)')
    severity = Find(by=By.CSS_SELECTOR, value='td:nth-child(5)')
    remove = Find(by=By.CSS_SELECTOR, value='i[class = "glyphicons remove"]')

    @property
    def host_name(self):
        """ Returns host of plugin rule """
        return self.plugin_host.text

    @property
    def plugin_rule_id(self):
        """ Returns plugin id of plugin rule """
        return self.plugin_id.text

    @property
    def expiration_date(self):
        """ Returns expiration date of plugin rule """
        return self.expiration.text

    @property
    def severity_level(self):
        """ Returns severity level of plugin rule """
        return self.severity.text


class PluginRulesList(ObjectList, PluginRulesPage):
    """ Returns a list containing plugin rules displayed on the plugin rules Management Page. """

    configure_button = None
    object_table = Find(GenericBaseTable, value="content")
    generics_map = {GenericTableRow: PluginRulesRecord}
    total_plugin_rule_count = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Total Records"] b')
    filtered_plugin_rule = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Results"] b')
    total_plugin_rule = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Total Records"]')
    selected_plugin_rule = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Checked"]')
    selected_plugin_rule_count = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Checked"] b')
    clear_selected_items_link = Find(Link, by=By.CSS_SELECTOR, value='a[data-domselect="clear-all"]')

    def __init__(self):
        super().__init__()
        self.loaded()

    def loaded(self, **kwargs):
        """waits for the list of plugin rules to populate"""
        self.is_element_present('rows', timeout=const.TIME_THIRTY_SECONDS)

    @property
    def filtered_plugin_rule_count(self) -> int:
        """
        Return count of plugin rules filtered with given search string shows in label next to searchbox.
        :return: count of filtered plugin rules.
        :rtype: int
        """
        return int(self.filtered_plugin_rule.text)

    def get_host_name(self) -> list:
        """Returns the list of host name for all plugin rules"""
        try:
            return [plugin.plugin_host.text for plugin in self.rows]
        except NoSuchElementException:
            return []

    def get_plugin_id(self) -> list:
        """Returns the list of plugin id of all rules"""
        try:
            return [plugin.plugin_id.text for plugin in self.rows]
        except NoSuchElementException:
            return []

    def apply_filter(self, filter_key: str) -> None:
        """
        apply a filter in plugin rule list
        :param str filter_key: substring for filter to apply
        """
        self.search_rule.clear()
        LoadingCircle(WAIT_TINY)
        self.search_rule.value = filter_key

    def verify_filter_result(self, filter_key: str) -> bool:
        """
        verify search string exists in any column data of rows in the list
        :param str filter_key: substring of applied filter
        :return: True or False
        :rtype: bool
        """
        for row in self.rows:
            return False if filter_key.lower() not in row.text.lower() else True

    def delete_plugin_rule(self, plugin_id: str) -> None:
        """
        Delete plugin rule of specified plugin id

        :param str plugin_id: id of plugin to be deleted
        :return: None
        """
        for row in self.rows:
            if plugin_id == row.plugin_id.text:
                row.remove.click()
                action_modal = ActionCloseModal()
                action_modal.accept_action()
                action_modal.wait_for_modal_closed()
        else:
            log.warning('Plugin Rule: {} not found in the list'.format(plugin_id))

    def click_on_plugin_rule(self, plugin_id: str) -> None:
        """
        Click on the plugin rule of specified plugin id

        :param str plugin_id: Id of the plugin to be selected
        :return: None
        """
        for plugin in self.rows:
            if plugin.plugin_id.text == plugin_id:
                plugin.click()
                break
        else:
            log.warning('Plugin Rule: {} not found in the list'.format(plugin_id))

    def select_plugin_rule(self, plugin_id: str) -> None:
        """
        Select the plugin rule of specified plugin id

        :param str plugin_id: Id of the plugin to be select
        :return: None
        """
        for plugin in self.rows:
            if plugin.plugin_id.text == plugin_id:
                plugin.plugin_checkbox.click()
                break
        else:
            log.warning('Plugin Rule: {} not found in the list'.format(plugin_id))
