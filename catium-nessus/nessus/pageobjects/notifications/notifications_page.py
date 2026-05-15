""""
Nessus page objects for notifications page in Settings

:copyright: Tenable Network Security, 2019
:date: June 27, 2019
:last_modified: Nov 19, 2020
:author: @yshah
"""
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By

from catium.lib import const
from catium.lib.cat_registry import cat_registry
from catium.lib.const import WAIT_SHORT
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.table import GenericTableRow, GenericBaseTable
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.find import Find, Finds
from nessus.helpers.date_selector import select_date_in_datepicker
from nessus.lib.const.constants import Nessus
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.generic.object_list import ObjectList
from nessus.pageobjects.scans.scan_view_page import ScanViewPage
from nessus.pageobjects.shared.loading import LoadingCircle


@cat_registry.route('settings/notifications')
class NotificationsPage(NessusBasePage):
    """ Page Object class for Notifications page in Nessus. """

    page_header = Find(by=By.CSS_SELECTOR, value='#titlebar')
    filter = Find(Clickable, by=By.CSS_SELECTOR, value='.advanced-search')
    notification_search_box = Find(TextField, by=By.CSS_SELECTOR, value='[aria-label="Search"]')
    total_notifications = Find(by=By.CSS_SELECTOR, value='[data-domselect="Total Records"]')
    filtered_notifications = Find(by=By.CSS_SELECTOR, value='[data-domselect="Results"]')
    filtered_count_with_total = Find(by=By.CSS_SELECTOR, value='#searchbox+span')
    empty_notification_list = Find(by=By.CSS_SELECTOR, value='.dataTables_empty')
    pagination_next = Find(Clickable, by=By.CSS_SELECTOR, value='.paginate_button.next')
    pagination_last = Find(Clickable, by=By.CSS_SELECTOR, value='.paginate_button.last')
    result_per_page = Find(by=By.CSS_SELECTOR, value='.dataTables_length')
    data_info = Find(by=By.CSS_SELECTOR, value='.dataTables_info')
    pagination_first = Find(Clickable, by=By.CSS_SELECTOR, value='.paginate_button.first')
    pagination_previous = Find(Clickable, by=By.CSS_SELECTOR, value='.paginate_button.previous')


class NotificationsRecord(GenericTableRow):
    """ Defines the key names for Notifications Records returned by NotificationsList. """

    displayed = Find(by=By.CSS_SELECTOR, value='th:nth-child(1)')
    acknowledged = Find(by=By.CSS_SELECTOR, value='[role="row"] td:nth-child(2)')
    messages = Find(by=By.CSS_SELECTOR, value='.pr10.message')
    status = Find(by=By.CSS_SELECTOR, value='td:nth-child(3)')
    status_tooltip = Find(by=By.CSS_SELECTOR, value='td:nth-child(3) i')
    displayed_date_value = Find(by=By.CSS_SELECTOR, value='td:nth-child(1)')


class NotificationsList(ObjectList):
    """ Returns a list containing Notifications displayed on the Notifications Page. """

    object_table = Find(GenericBaseTable, value="content")
    configure_button = None
    generics_map = {GenericTableRow: NotificationsRecord}

    def __init__(self):
        super().__init__()
        self.loaded()

    def loaded(self, **kwargs):
        """ waits for the list of notifications to populate """
        self.is_element_present('rows', timeout=const.TIME_THIRTY_SECONDS)

    def get_all_notifications(self) -> list:
        """
        Returns the list of notifications

        :return: list of notifications
        :rtype: list
        """
        try:
            return [notifications.messages.text for notifications in self.rows]
        except NoSuchElementException:
            return []

    def get_notification_status(self) -> list:
        """
         Returns the list of status of notifications

         :return: list of status of notifications
         :rtype: list
         """
        try:
            return [notifications.acknowledged.text for notifications in self.rows]
        except NoSuchElementException:
            return []

    def get_displayed_date_value(self):
        """
        Returns the list of displayed value of notifications

        :return: list of displayed value of notifications
        :rtype: list
        """
        try:
            return [notifications.displayed_date_value.text for notifications in self.rows]
        except NoSuchElementException:
            return []


class NotificationFilter(NotificationsPage):
    """ This class contains all the locators of notification filter pop-up """

    match_all_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='[aria-label="Match"]')
    select_key_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='.select-key.new-filter select')
    option_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='.select-op select')
    add_filter = Find(Clickable, by=By.CSS_SELECTOR, value='.glyphicons.add')
    remove_filter = Find(Clickable, by=By.CSS_SELECTOR, value='.filter-container .glyphicons.remove')
    clear_filter_link = Find(Clickable, by=By.CSS_SELECTOR, value='.clear-advanced-search')
    date_input = Find(TextField, by=By.CSS_SELECTOR, value='.select-value input')
    apply_button = Find(Clickable, by=By.CSS_SELECTOR, value='.modal-action')
    cancel_link = Find(by=By.CSS_SELECTOR, value='.modal-close')
    match_all = Find(by=By.CSS_SELECTOR, value='[title="All"]')
    select_key = Find(by=By.CSS_SELECTOR, value='[title="Displayed Date"]')
    select_option = Find(by=By.CSS_SELECTOR, value='#select2-my50-container')
    filter_count = Find(by=By.CSS_SELECTOR, value='.advanced-search span')
    filters_date_input_list = Finds(by=By.CSS_SELECTOR, value='.filter .validate.date-picker')
    acknowledge_value_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='.select-value select')
    message_input_box = Find(TextField, by=By.CSS_SELECTOR, value='input[title="TEXT"]')

    def apply_filter(self, key: str, operator: str, value: str, match_type: str = Nessus.Filter.FilterMatch.ALL,
                     apply: bool = True, applied_filter_count: int = 0) -> None:
        """
        Apply particular filter in scan result using advance filter

        :param str key: Key value to apply a filter
        :param str operator: Operator value to apply a filter
        :param str value: Value for the filter.
        :param str match_type: Match type for conditions.
        :param bool apply: Apply filter if True else just set filter values
        :param int applied_filter_count: Count of filters
        :return: None
        """
        if apply:
            self.filter.click()

        applied_filter_count += 1

        index = applied_filter_count
        self.match_all_dropdown.select_by_visible_text(match_type)
        LoadingCircle(WAIT_SHORT)
        if applied_filter_count > 1:
            self.add_filter.click()

        scan_view_page = ScanViewPage()
        scan_view_page.get_filter_dropdown_element(index_value=index, element_type=Nessus.Filter.KEY) \
            .select_by_visible_text(key)
        scan_view_page.get_filter_dropdown_element(index_value=index, element_type=Nessus.Filter.OPERATOR) \
            .select_by_visible_text(operator)

        LoadingCircle(WAIT_SHORT)
        if key in Nessus.Filter.FilterKeys.VALUE_DROPDOWN:
            scan_view_page.get_filter_dropdown_element(index_value=index, element_type=Nessus.Filter.VALUE) \
                .select_by_visible_text(value)
        elif key in Nessus.Filter.FilterKeys.VALUE_DATEPICKER:
            scan_view_page.get_filter_value_datepicker(index_value=index).click()
            select_date_in_datepicker(page_class_instance=self, input_date=value)
        else:
            scan_view_page.get_filter_value_text_element(index_value=index).clear()
            scan_view_page.get_filter_value_text_element(index_value=index).send_keys(value)

        if apply:
            ActionCloseModal().accept_action()
