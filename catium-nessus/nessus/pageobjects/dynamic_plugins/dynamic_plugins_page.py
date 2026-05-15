""""
Nessus Page Object classes for Dynamic Plugin tab.

:copyright: Tenable Network Security, 2018
:date: Oct 03, 2018
:last_modified: Dec 19, 2018
:author: @rdutta, @jchavda
"""
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement

from catium.helpers.sleep_lib import sleep
from catium.lib.const.base_constants import WAIT_LONG, WAIT_NORMAL, WAIT_SHORT, TIME_THREE_SECONDS, TIME_SIXTY_SECONDS
from catium.lib.webium import Find
from catium.lib.webium import Finds
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.date_picker import DatePicker
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.table import GenericTableRow, GenericBaseTable, GenericTable, GenericTableWrapper
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.helpers.date_selector import select_date_in_datepicker
from nessus.lib.const import Nessus
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.generic.object_list import ObjectList
from nessus.pageobjects.policies.new_policy_form import NewPolicyForm
from nessus.pageobjects.scans.new_scan_form import NewScanForm
from nessus.pageobjects.shared.loading import LoadingCircle


class DynamicPlugin(NewScanForm, NewPolicyForm):
    """Page Object class and related methods for dynamic plugin page"""
    preview_plugins = Find(Clickable, by=By.CSS_SELECTOR, value='.dynamic-plugins-apply-btn')

    # filter related locators and variable
    match_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='.filter-type-select')
    add_filter = Find(Clickable, by=By.XPATH, value='(//div[@class="add-filter"])[last()]')
    select_date = Find(DatePicker, by=By.CSS_SELECTOR, value='div#ui-datepicker-div')
    current_date = Find(by=By.CSS_SELECTOR, value='.ui-datepicker-today')
    select_family_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='#plugin-families select')
    filter_control_input = Find(TextField, by=By.CSS_SELECTOR,
                                value='span[data-function="filter-control-holder"] input')
    filter_name_dropdown= Find(Select2Dropdown, by=By.CSS_SELECTOR, value='[data-function="filter"]')

    # Pagination related locators
    results_per_page_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='.dataTables_length select')

    def __init__(self):
        super().__init__()
        self.required_elements = ['preview_plugins']
        self.dynamic_plugins.click()
        LoadingCircle(WAIT_NORMAL)

    def get_filter_dropdown_element(self, index_value: int, element_type: str) -> WebElement:
        """
        Get UI element for filter condition's dropdown depending on the element type and index of filter
        :param int index_value: index of filter
        :param str element_type: type of element
        :return: dropdown element of filter window
        :rtype: WebElement
        """
        return Find(Select2Dropdown, by=By.CSS_SELECTOR, value='.filter:nth-child({}) select[data-function="{}"]'
                    .format(index_value, element_type), context=self)

    def get_filter_value_text_element(self, index_value: int) -> WebElement:
        """
        Get UI element of filter value textfield
        :param int index_value: index of filter
        :return: text input element of filter window
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='.filter:nth-child({}) input'.format(index_value),
                    context=self)

    def get_filter_value_datepicker(self, index_value: int) -> WebElement:
        """
        Get UI element of filter value datepicker
        :param int index_value: index of filter
        :return: date input element of filter window
        :rtype: WebElement
        """
        return Find(Clickable, by=By.CSS_SELECTOR, value='.filter:nth-child({}) .date-picker'
                    .format(index_value), context=self)

    def get_filter_remove_element(self, index_value: int) -> WebElement:
        """
        Get UI element of filter remove ('x' icon element of a specific filter)
        :param int index_value: index of filter
        :return: remove filter element of a particular filter
        :rtype: WebElement
        """
        return Find(Clickable, by=By.XPATH, value='//*[@class="remove-filter"][position()={}]'
                    .format(index_value), context=self)

    def get_selected_filter_value(self, index_value: int) -> WebElement:
        """
        Get UI element of selected filter value
        :param int index_value: index of filter
        :return: element of selected filter value window
        :rtype: WebElement
        """
        filter_value_element = Find(by=By.CSS_SELECTOR,
                                    value='.filter:nth-child({}) span[data-function="filter-control-holder"]'
                                    .format(index_value), context=self)

        if len(filter_value_element.find_elements(By.TAG_NAME, 'select')) > 0:
            return Find(Select2Dropdown, by=By.CSS_SELECTOR,
                        value='.filter:nth-child({}) span[data-function="filter-control-holder"] select'
                        .format(index_value), context=self)
        elif len(filter_value_element.find_elements(By.TAG_NAME, 'input')) > 0:
            return Find(TextField, by=By.CSS_SELECTOR,
                        value='.filter:nth-child({}) span[data-function="filter-control-holder"] input'
                        .format(index_value), context=self)

    def get_added_plugins_filter(self) -> list:
        """
        Get the applied plugins filter and returns list of dictionary of filter (key:values)
        :return: list of dictionary of applied filters
        :rtype: dict
        """
        added_filters = []
        applied_filter_count = get_driver_no_init().find_elements(by=By.CSS_SELECTOR, value='.filter')
        for (itr, filter_element) in enumerate(applied_filter_count):
            filter_index = (4 * itr) + 1
            added_filters.append({Nessus.Filter.INDEX: itr + 1,
                                  Nessus.Filter.KEY: self.get_filter_dropdown_element(
                                      index_value=filter_index, element_type=Nessus.Filter.FILTER).value,
                                  Nessus.Filter.OPERATOR: self.get_filter_dropdown_element(
                                      index_value=filter_index, element_type=Nessus.Filter.QUALITY).value,
                                  Nessus.Filter.VALUE: self.get_selected_filter_value(index_value=filter_index).value})

        return added_filters

    def apply_filter(self, key: str, operator: str, value: str, filter_index: int=1,
                     match_type: str=Nessus.Filter.FilterMatch.ALL) -> None:
        """
        Apply particular filter for plugins
        :param str key: Key value to apply a filter
        :param str operator: Operator value to apply a filter
        :param str value: Value for the filter.
        :param int filter_index: count of filter
        :param str match_type: Match type for conditions.
        :return: None
        """
        index = (4 * (filter_index - 1)) + 1
        self.match_dropdown.select_by_visible_text(match_type)
        LoadingCircle(WAIT_SHORT)

        self.get_filter_dropdown_element(index_value=index,
                                         element_type=Nessus.Filter.FILTER).select_by_visible_text(key)
        self.get_filter_dropdown_element(index_value=index,
                                         element_type=Nessus.Filter.QUALITY).select_by_visible_text(operator)

        LoadingCircle(WAIT_SHORT)
        if key in Nessus.Filter.FilterKeys.VALUE_DROPDOWN:
            self.get_filter_dropdown_element(index_value=index,
                                             element_type=Nessus.Filter.VALUE).select_by_visible_text(value)
        elif key in Nessus.Filter.FilterKeys.VALUE_DATEPICKER:
            self.get_filter_value_datepicker(index_value=index).click()
            select_date_in_datepicker(page_class_instance=self, input_date=value)
        else:
            self.get_filter_value_text_element(index_value=index).clear()
            self.get_filter_value_text_element(index_value=index).send_keys(value)

    def preview_plugins_by_family(self, plugin_families_to_preview: list=None) -> dict:
        """
        Shows all plugins under selected plugins family(s) and update all plugins according to family in dictionary
        :param list plugin_families_to_preview: list of families whose plugins you want to view
        :return: dictionary of all plugins according to family as pair
        :rtype: dict
        """
        previewed_plugins_by_family = {}
        self.preview_plugins.click()
        wait(lambda: self.is_element_present('select_family_dropdown'), timeout_seconds=TIME_SIXTY_SECONDS,
             waiting_for="Waiting for plugin family dropdown to be visible")

        if not plugin_families_to_preview:
            plugin_families_to_preview = []
            for family in self.select_family_dropdown.option_values[1:]:
                sleep(sleep_time=WAIT_SHORT, reason='waiting for options values list gets populated')
                plugin_families_to_preview.append(family['label'])
            sleep(sleep_time=TIME_THREE_SECONDS, reason='waiting for plugin family list gets populated')

        for plugin_family in plugin_families_to_preview:
            sleep(sleep_time=WAIT_SHORT, reason='waiting to choose plugin family')
            self.select_family_dropdown.select_by_visible_text(text=plugin_family, exact=False)
            LoadingCircle(WAIT_LONG)
            previewed_plugins_by_family.update({plugin_family: PluginsListByFamily().get_all_listed_plugins()})

        return previewed_plugins_by_family

    def manage_dynamic_plugins(self, plugins_filter_list: list, add_plugins: bool=False, preview_plugins: bool=True,
                               plugin_family_to_preview: list=None) -> dict:
        """
        Add or modify one or more plugins by choosing filter and can preview selected plugins by family category
        :param list plugins_filter_list: list of filter to add or modify
        :param bool add_plugins: if true then will add plugins filter otherwise modify
        :param bool preview_plugins: if true then click on ‘Preview Plugin’ button
        :param list plugin_family_to_preview: list of plugin_family for previewing plugins
        :return: dictionary of plugins against plugin_family if preview_plugins is true.
        :rtype: dict
        """
        previewed_plugins = {}

        for plugin in plugins_filter_list:
            if add_plugins and plugin.get(Nessus.Filter.INDEX) > 1:
                self.add_filter.click()
                sleep(sleep_time=TIME_THREE_SECONDS, reason='Waiting for visibility of filter elements')

            self.apply_filter(**plugin)

        if preview_plugins:
            previewed_plugins.update(self.preview_plugins_by_family(plugin_family_to_preview))
            return previewed_plugins

    def delete_dynamic_plugin_filter(self, filter_index: int) -> None:
        """
        Delete the particular filter whose index has specified in filter_index
        :param int filter_index: index of the filter you want to delete
        :return: None
        """
        self.get_filter_remove_element(index_value=filter_index).click()


class PluginsRecordsByFamily(GenericTableRow):
    """Defines the key names for Plugins Records returned by PluginsListByFamily."""
    _name = Find(by=By.CSS_SELECTOR, value='.plugin-family-plugin-name')
    _id = Find(by=By.CSS_SELECTOR, value='.plugin-family-plugin-id')

    @property
    def plugin_id(self):
        """Returns ID of plugin."""
        return self._id.text

    @property
    def plugin_name(self):
        """Returns name of the plugin"""
        return self._name.text


class PluginsListByFamily(ObjectList):
    """Returns a list containing Plugins displayed depending upon selected plugin family in dynamic plugins page."""
    configure_button = None
    generics_map = {GenericTableRow: PluginsRecordsByFamily}

    def __init__(self):
        super().__init__()

    def get_all_listed_plugins(self) -> list:
        """
        Returns the list of all plugins under specified plugin family
        :return: list of plugin ID and plugin name as (key: value) pair
        :rtype: list
        """
        return [{row.plugin_id: row.plugin_name} for row in self.rows]


class PluginFiltersBaseTable(GenericBaseTable):
    """ Implements generic logic to work with Table UI elements. This finds the Plugin Filters table."""
    table_wrapper = Find(GenericTable, by=By.CSS_SELECTOR, value="table.readonly-filters-table")

    @property
    def rows(self) -> list:
        """
        Accessor for the rows in a Generic Table. If there is no table it returns empty list.
        """
        if not self.is_empty():
            if (len(self.table_wrapper.table_body.rows) == 1 and 'dataTables_empty' in self.table_wrapper.table_body.
                    rows[0].get_css_classes()):
                return []
            return self.table_wrapper.table_body.rows
        else:
            return []


class PluginFiltersObjectList(NessusBasePage):
    plugins_table = Find(PluginFiltersBaseTable, value="content")

    @property
    def rows(self):
        """ Returns rows from table. """
        return self.plugins_table.rows


class PluginFiltersRecord(PluginFiltersBaseTable):
    """Defines the key names for Plugin filters returned by PluginFiltersList."""

    filter_name = Find(by=By.CSS_SELECTOR, value='td:nth-child(1)')
    filter_operator = Find(by=By.CSS_SELECTOR, value='td:nth-child(2)')
    filter_value = Find(by=By.CSS_SELECTOR, value='td:nth-child(3)')


class PluginFiltersList(PluginFiltersObjectList):
    """ Returns a list containing Plugin filters displayed on the Dynamic Plugins Page."""

    configure_button = None
    generics_map = {GenericTableRow: PluginFiltersRecord}
