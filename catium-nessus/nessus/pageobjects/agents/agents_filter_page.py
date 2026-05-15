"""
Nessus page classes for agents filter window

:copyright: Tenable Network Security, 2018
:date: May 05, 2018
:last_modified: May 24, 2019
:author: @jgajjar.ctr, @kpanchal
"""

from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement

from catium.lib.cat_registry import cat_registry
from catium.lib.const import WAIT_SHORT
from catium.lib.webium import Find
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.date_picker import DatePicker
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.text_field import TextField
from nessus.helpers.date_selector import select_date_in_datepicker
from nessus.lib.const import Nessus
from nessus.pageobjects.agents.agents_page import AgentsPage
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.shared.loading import LoadingCircle


@cat_registry.route(r'sensors/agents')
class FilterWindow(NessusBasePage):
    """ Page class for Filter-Bar on Agents Page in Nessus Manager"""

    close_button = Find(Clickable, by=By.CSS_SELECTOR, value='div.modal-close i.glyphicons.remove')
    match_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='.filter-type-select')
    remove_filter = Find(Clickable, by=By.CSS_SELECTOR, value='div.remove-filter i.glyphicons.remove')
    add_filter = Find(Clickable, by=By.XPATH, value='(//div[@class="add-filter"])[last()]')
    clear_filters = Find(Clickable, by=By.CSS_SELECTOR, value='.clear-advanced-search')
    select_date = Find(DatePicker, by=By.CSS_SELECTOR, value='div#ui-datepicker-div')
    current_date = Find(by=By.CSS_SELECTOR, value='.ui-datepicker-today')

    filters_count = 0

    def __init__(self):
        super().__init__()

    def get_filter_dropdown_element(self, index_value: int, element_type: str) -> WebElement:
        """
        Get UI element for filter condition's dropdown depending on the element type and index of filter
        :param int index_value: index of filter
        :param str element_type: type of element
        :return: WebElement
        """
        element_type = 'op' if element_type == Nessus.Agents.Filter.OPERATOR else element_type
        return Find(Select2Dropdown, by=By.CSS_SELECTOR, value='.filter-container:nth-child({}) div.select-{} select'
                    .format(index_value, element_type), context=self)

    def get_filter_value_text_element(self, index_value: int) -> WebElement:
        """
        Get UI element of filter value textfield
        :param int index_value: index of filter 
        :return: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='.filter-container:nth-child({}) div.select-value input'
                    .format(index_value), context=self)

    def get_filter_value_datepicker(self, index_value: int) -> WebElement:
        """
        Get UI element of filter value datepicker
        :param int index_value: index of filter
        :return: WebElement
        """
        return Find(Clickable, by=By.CSS_SELECTOR, value='.filter-container:nth-child({}) div.select-value .date-picker'
                    .format(index_value), context=self)

    def add_and_apply_filter(self, match_type: str, filter_key: str, filter_operator: str, filter_value: str) -> None:
        """
        Add filter(s) and apply it on Agents List
        :param str match_type: Match type for conditions. 
        :param str filter_key: Key of filter condition. [e.g. 'IP Address']
        :param str filter_operator: Operator of filter condition. [e.g. 'is equal to']
        :param str filter_value: Value of filter condition. [e.g. '192.168.1.1']
        :return: None
        """
        AgentsPage().filter_link.click()
        self.filters_count += 1

        index = self.filters_count
        self.match_dropdown.select_by_visible_text(match_type)
        LoadingCircle(WAIT_SHORT)
        if self.filters_count > 1:
            self.add_filter.click()

        self.get_filter_dropdown_element(
            index_value=index, element_type=Nessus.Agents.Filter.KEY).select_by_visible_text(filter_key)
        self.get_filter_dropdown_element(
            index_value=index, element_type=Nessus.Agents.Filter.OPERATOR).select_by_visible_text(filter_operator)

        LoadingCircle(WAIT_SHORT)
        if filter_key in Nessus.Agents.Filter.FILTER_VALUE_TEXT_FIELD:
            self.get_filter_value_text_element(index_value=index).send_keys(filter_value)
        elif filter_key in Nessus.Agents.Filter.FILTER_VALUE_DATEPICKER:
            self.get_filter_value_datepicker(index_value=index).click()
            select_date_in_datepicker(page_class_instance=self, input_date=filter_value)
        else:
            self.get_filter_dropdown_element(
                index_value=index, element_type=Nessus.Agents.Filter.VALUE).select_by_visible_text(filter_value)
        action_close_model = ActionCloseModal()
        action_close_model.accept_action()
        action_close_model.wait_for_modal_closed()

    def clear_filter(self) -> None:
        """ 
        Clear any applied filter in filter window of Agents page.
        :return: None
        """
        agents_page = AgentsPage()
        agents_page.open()

        LoadingCircle(WAIT_SHORT)
        agents_page.filter_link.click()
        self.clear_filters.click()
        ActionCloseModal().wait_for_modal_closed()
        self.filters_count = 0
