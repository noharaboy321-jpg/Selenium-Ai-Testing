"""

Generic Object List Class from which object
lists should inherit from

:copyright: Tenable Network Security, 2017
:date: July 28, 2017
:last_modified: Jan 11, 2022
:author: @smadan , @rdutta, @kpanchal
"""
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from selenium.webdriver.remote.webelement import WebElement

from nessus.lib.const.constants import Nessus
from selenium.webdriver.common.by import By
from selenium.webdriver.support.expected_conditions import invisibility_of_element_located, visibility_of_element_located

from catium.lib.cat_registry.metadata_registry import register_page_object
from catium.lib.config import Config
from catium.lib.const import TIME_TWO_MINUTES, WAIT_SHORT
from catium.lib.log.log import create_logger
from catium.lib.webium import Find, Finds
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from catium.lib.webium.windows_handler import WindowsHandler
from nessus.pageobjects.basepage import NessusBasePage

log = create_logger()
is_upgrade_np_offer_modal_closed = False


@register_page_object()
class ActionCloseModal(NessusBasePage):
    """ Page Object for a generic modal with an action and cancel button in Nessus """

    modal = Find(by=By.CSS_SELECTOR, value='.modal')
    action_button = Find(Clickable, by=By.CSS_SELECTOR, value='.modal-action')
    cancel_button = Find(by=By.CSS_SELECTOR, value='.modal-close')
    close_button = Find(by=By.CSS_SELECTOR, value='div.modal-close .remove')
    modal_title = Find(by=By.CSS_SELECTOR, value=".modal-title")
    modal_content = Find(by=By.CSS_SELECTOR, value=".modal-text")
    modal_warning = Find(by=By.CSS_SELECTOR, value=".modal-warning-text")
    welcome_banner_title = Find(by=By.CSS_SELECTOR, value=".modal-title.pro-features")
    pendo_guide_container = Find(by=By.ID, value="pendo-guide-container")
    container_close_icon = Find(by=By.CLASS_NAME, value="_pendo-close-guide")
    modal_content_item = Find(by=By.CSS_SELECTOR, value=".modal-content")
    modal_cancel = Find(by=By.CSS_SELECTOR, value='a.modal-close')
    modal_content_radio = Finds(by=By.CSS_SELECTOR, value=".modal-text > div > span")

    def __init__(self):
        super().__init__()
        self.required_elements = ['modal']

    def accept_action(self):
        """Switch to the window and accepts the action"""
        window = WindowsHandler()
        if window.is_new_window_present():
            window.switch_to_new_window()
            self.action_button.click()

    def get_modal_radio_labels(self, element) -> list:
        """
        Return the list of radio button labels displayed on modal.
        :param element: page class element
        :return: List
        """
        return [span.text.strip() for span in element]

    def wait_for_modal_closed(self, timeout_seconds: float = TIME_TWO_MINUTES):
        """wait till modal is closed or time out occur"""
        if Config.CAT_USE_SAUCE:
            wait(lambda: not self.is_element_present("modal"), waiting_for="Modal get closed",
                 timeout_seconds=timeout_seconds)
        else:
            wait(lambda: invisibility_of_element_located((By.CSS_SELECTOR, '.modal'))(get_driver_no_init()),
                 waiting_for='Modal is closed', timeout_seconds=timeout_seconds)

    def close_upgrade_np_offer_modal_nessus_home(self) -> None:
        """ Close if Upgrade to NP offer modal appears. (Especially for Nessus Home) """
        global is_upgrade_np_offer_modal_closed

        if not is_upgrade_np_offer_modal_closed:
            try:
                if self.is_element_present("modal"):
                    log.info("Upgrade to NP/Expert offer modal is visible after fresh installation.")
                    self.close_button.click()
                    self.wait_for_modal_closed()
                else:
                    log.info("Upgrade to NP/Expert offer modal is either not visible or already closed...")
            except:
                log.info('Attempted to close Upgrade to NP/Expert offer modal if it appears.')
                pass

            is_upgrade_np_offer_modal_closed = True


class SetNameModal(ActionCloseModal):
    """Page Object for modal where a name can be set in Nessus"""

    name_field = Find(TextField, by=By.CSS_SELECTOR, value='.group-name')


class SetPasswordModal(ActionCloseModal):
    """Page Object for modal where a password can be set in Nessus"""

    password_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="Password"]')

    def set_password(self, password):
        """
        Sets the password in a modal.
        :param str password: password value
        """
        self.password_field.value = password
        self.action_button.click()


class SetExportPasswordModal(ActionCloseModal):
    """Page Object for modal where a exported report type can be set in Nessus."""
    password_field = Find(TextField, by=By.CSS_SELECTOR, value='input[class="export-nessusdb-password"]')
    export_button = Find(Clickable, by=By.CSS_SELECTOR, value='#export-save')
    save_report_button = Find(Clickable, by=By.CSS_SELECTOR, value='#report-save')

    def set_password(self, password: str) -> None:
        """ Sets the password in Nessus DB export modal.
        :param str password: password value
        """
        self.password_field.value = password
        self.export_button.click()


class UnsavedChangesModal(ActionCloseModal):
    """Page Object for modal when you leave a page with unsaved changes"""

    unsaved_changes_title = Find(by=By.CSS_SELECTOR, value='.modal-title')


class SetEmailModal(UnsavedChangesModal):
    """Page Object for modal where a email can be set in Nessus"""

    recipient_field = Find(TextField, by=By.CSS_SELECTOR, value='input[name="temp-modal-input"]')

    def set_email(self, email: str):
        """
        Sets the email in a modal.
        :param str email: email value
        """
        self.recipient_field.value = email
        self.action_button.click()


class FilterModal(ActionCloseModal):
    """Page Object for modal where advanced filters can be set."""
    applied_filter_count: int = 0

    match_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='.filter-type-select')
    add_filter = Find(Clickable, by=By.XPATH, value='(//div[@class="add-filter"])[last()]')
    filter_link = Find(Clickable, by=By.CSS_SELECTOR, value='#advanced-search')
    clear_filter_link = Find(Clickable, by=By.CSS_SELECTOR, value='.clear-advanced-search')
    count_of_filter_container = Finds(by=By.CSS_SELECTOR, value='.filter-container')

    def __init__(self):
        super().__init__()
        self.applied_filter_count = 0

    @staticmethod
    def add_and_apply_to_filter(
            *,
            match_type: str = Nessus.Filter.FilterMatch.ALL,
            key: str,
            operator: str,
            value: str
    ) -> 'FilterModal':
        if isinstance(value, int) or isinstance(value, float):
            value = str(value)

        filter_modal = FilterModal()
        filter_modal.open_modal()
        filter_modal.add_match_type_dropdown(match_type=match_type)
        filter_modal.add_key_dropdown(key=key)
        filter_modal.add_operator_dropdown(operator=operator)
        filter_modal.add_value_dropdown(value=value, key=key)
        filter_modal.apply_filter()
        return filter_modal

    def open_modal(self):
        self.filter_link.click()
        wait(lambda: visibility_of_element_located(self.modal))
        if self.applied_filter_count == 0:
            self.applied_filter_count = 1

    @property
    def apply(self):
        return self.action_button

    def clear_filter(self):
        self.filter_link.click()
        self.clear_filter_link.click()
        self.applied_filter_count = 0

    def get_filter_dropdown_element(self, *, index_value: int, element_type: str) -> WebElement:
        """
        Get UI element for filter condition's dropdown depending on the element type and index of filter
        :param int index_value: index of filter
        :param str element_type: type of element
        :return: dropdown element of filter window
        :rtype: WebElement
        """
        if element_type == Nessus.Filter.OPERATOR:
            element_type = 'op'
        return Find(Select2Dropdown, by=By.CSS_SELECTOR, value='.filter-container:nth-child({}) div.select-{} select'
                    .format(index_value, element_type), context=self)

    def get_filter_value_text_element(self, index_value: int = 1) -> WebElement:
        """
        Get UI element of filter value textfield
        :param int index_value: index of filter
        :return: text input element of filter window
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='.filter-container:nth-child({}) div.select-value input'
                    .format(index_value), context=self)

    def add_match_type_dropdown(self, match_type: str = Nessus.Filter.FilterMatch.ALL, wait_time: int = WAIT_SHORT):
        # Add the match type in the filter modal
        self.match_dropdown.select_by_visible_text(match_type)

    def add_key_dropdown(self, key: str, wait_time: int = WAIT_SHORT):
        # Add the key in the filter modal
        index = self.applied_filter_count
        element = self.get_filter_dropdown_element(
            index_value=index,
            element_type=Nessus.Filter.KEY)
        element.select_by_visible_text(key)

    def add_operator_dropdown(self, operator: str, wait_time: int = WAIT_SHORT):
        # Add the operator in the filter modal
        index = self.applied_filter_count
        element = self.get_filter_dropdown_element(
            index_value=index,
            element_type=Nessus.Filter.OPERATOR)
        element.select_by_visible_text(operator)

    def add_value_dropdown(self, value: str, key: str = None,  wait_time: int = WAIT_SHORT):
        # Add the value in the filter modal
        index = self.applied_filter_count

        if key in Nessus.Filter.FilterKeys.VALUE_DROPDOWN:
            # Using the dropdown
            element = self.get_filter_dropdown_element(
                index_value=index,
                element_type=Nessus.Filter.VALUE)
            element.select_by_visible_text(value)
        else:
            # Sending in Text for the value element
            self.get_filter_value_text_element (index_value=index).clear()
            self.get_filter_value_text_element(index_value=index).send_keys(value)

    def add_new_filter_item(self, wait_time: int = WAIT_SHORT):
        # Add data to the filtered object
        self.add_filter.click()
        self.applied_filter_count += self.applied_filter_count

    def apply_filter(self, timeout_seconds: float = TIME_TWO_MINUTES):
        # Apply the filter
        self.accept_action()
        self.wait_for_modal_closed(timeout_seconds=timeout_seconds)
