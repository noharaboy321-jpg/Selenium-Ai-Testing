"""
PageObject class for Linked Scanner Page

:copyright: Tenable Network Security, 2017
:date: Aug 10, 2017
:last_modified: Oct 25, 2021
:author: @jamreliya, @kpanchal, @krpatel.ctr
"""
import re

from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By

from catium.lib.cat_registry import cat_registry
from catium.lib.log import create_logger
from catium.lib.webium import Find, Finds
from catium.lib.webium.controls.checkbox import Checkbox
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.table import GenericBaseTable, GenericTableRow
from catium.lib.webium.controls.webium_element import WebiumWebElement
from catium.lib.webium.wait import wait
from nessus.pageobjects.basepage import NessusBasePage

log = create_logger()


class ScannersRecord(WebiumWebElement):
    """ Defines the key names for Scanner Records returned by ScannersList. """

    select = Find(Checkbox, by=By.CSS_SELECTOR, value='div.checkbox')
    name = Find(by=By.CSS_SELECTOR, value='table.scanners td.pr10')
    status = Find(by=By.CSS_SELECTOR, value='td.capitalize')
    scans = Find(by=By.CSS_SELECTOR, value='td:nth-child(4)')
    version = Find(by=By.CSS_SELECTOR, value='td:nth-child(5)')
    linked_on = Find(by=By.CSS_SELECTOR, value='td:nth-child(6)')
    last_modified = Find(by=By.CSS_SELECTOR, value='td:nth-child(7)')
    type = Find(by=By.CSS_SELECTOR, value='td.policy-type')
    remove = Find(by=By.CSS_SELECTOR, value='i[class = "glyphicons remove add-tip"]')

    @property
    def scanner_name(self):
        """
        Returns name of the scanner.
        """
        return self.name.text

    @property
    def scanner_status(self):
        """
        Returns status of the scanner.
        """
        return self.status.text

    @property
    def scanner_scans(self):
        """
        Returns scans of the scanner.
        """
        return self.scans.text

    @property
    def scanner_version(self):
        """
        Returns version of the scanner.
        """
        return self.version.text

    @property
    def linked_on_epoc_time(self):
        """
        Returns epoc time for scanner linked on time
        """
        return int(self.linked_on.get_attribute('data-order'))

    @property
    def last_modified_epoc_time(self):
        """
        Returns epoc time for scanner linked on time
        """
        return int(self.last_modified.get_attribute('data-order'))


class ScannerList(NessusBasePage):
    """ Returns a list containing Scanners displayed on the Scanners Page. """

    object_table = Find(GenericBaseTable, value="content")
    results = rows = Finds(ScannersRecord, by=By.CSS_SELECTOR, value='tr.scanner')
    result = Find(by=By.CSS_SELECTOR, value='tr.scanner')
    generics_map = {GenericTableRow: ScannersRecord}

    def __init__(self):
        super().__init__()
        wait(lambda: len(self.results) > 0, waiting_for='Scanners List to populate.')

    def get_all_scanners_in_nessus(self) -> list:
        """
        Returns all linked scanners in Nessus.
        """
        try:
            return [scanner.name.text for scanner in self.results]
        except NoSuchElementException:
            return []

    def click_on_scanner(self, scanner_name: str):
        """
        Click on given scanner name

        :param scanner_name: name of the scanner to click
        :return: None
        """
        scanner_list = self.results
        for scanner in scanner_list:
            if scanner.name.text == 'Shared\n' + scanner_name:
                scanner.click()
                break

    def delete_scanner(self, scanner_name: str):
        """
        Deletes given scanner name

        :param scanner_name: name of the scanner to be deleted
        :return: None
        """
        scanner_list = self.results
        for scanner in scanner_list:
            if scanner.name.text == 'Shared\n' + scanner_name:
                scanner.remove.click()
                break

    def select_scanners(self, scanners_list: list) -> None:
        """
        Select given list of scanners

        :param scanners_list: List of scanner names which needs to be selected.
        :return : None
        """
        for scanner in self.results:
            if scanner.name.text.split('Shared\n')[1] in scanners_list:
                scanner.select.click()


@cat_registry.route(r'sensors/scanners')
class ScannerPage(NessusBasePage):
    """
    Defines properties and methods inherited by the Nessus scanner Page.
    """
    linking_key_text = Find(by=By.CSS_SELECTOR, value='span.key')
    setup_description = Find(by=By.CSS_SELECTOR, value='div.description-copy')
    edit_key = Find(by=By.CSS_SELECTOR, value='i.edit')
    regenerate_key = Find(by=By.CSS_SELECTOR, value='i.update')
    total_scanners_count = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Total Records"]')
    scanners_search_box = Find(by=By.CSS_SELECTOR, value='input[data-domselect="searchInput"]')
    selected_scanners_count = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Results"]')
    checked_scanners_count = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Checked"')
    clear_selected_item_link = Find(by=By.CSS_SELECTOR, value='a[data-domselect="clear-all"]')
    regenerate_button = Find(by=By.CSS_SELECTOR, value='a.modal-action')
    disable_buttons = Finds(by=By.CSS_SELECTOR, value='i.enable.add-tip')
    delete_buttons = Finds(by=By.CSS_SELECTOR, value='i.remove.add-tip')
    scanner_detail_empty_msg = Find(by=By.CSS_SELECTOR, value='#content .empty-results')
    scanner_details_tab = Find(by=By.CSS_SELECTOR, value='[data-name="Scanner Details"]')
    scanner_permission_tab = Find(by=By.CSS_SELECTOR, value='[data-name="Permissions"]')
    scanner_details_labels = Finds(by=By.CSS_SELECTOR, value='.content-block .form-group label')
    add_user_group_input = Find(by=By.CSS_SELECTOR, value='input.editor-input')
    select_user_permission = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[aria-label="Share Permissions"]')
    save_button = Find(Clickable, by=By.CSS_SELECTOR, value='#scanner-permissions-save')
    cancel_button = Find(Clickable, by=By.CSS_SELECTOR, value='#scanner-permissions-save + a')
    available_user = Find(by=By.CSS_SELECTOR, value='#ui-id-2')
    added_user_permission = Find(by=By.CSS_SELECTOR, value='ul li:nth-child(3) span[title="Can use"]')

    def __init__(self):
        super().__init__()
        self.required_elements = ['linking_key_text']

    @property
    def total_scanners(self):
        """
        Returns total scanners linked to Nessus Manager.
        """
        return int(self.total_scanners_count.text.split(' Scanner')[0])

    @property
    def selected_scanners(self):
        """
        Returns the count of scanners searched using search box
        """
        return int(self.selected_scanners_count.text.split(' of')[0])

    @property
    def checked_scanners(self):
        """
        Returns the count of checked/selected scanners in NM.
        """
        return int(re.search(r'\d{0,2} Selected', self.checked_scanners_count.text).group().split('Selected')[0])

    def open_scanner_details(self, scanner_name):
        """
        Click on scanner from list
        """
        scanner_locator = Find(by=By.CSS_SELECTOR, value="tr.scanner[data-name={}]".format(scanner_name),
                               context=self)
        scanner_locator.click()
