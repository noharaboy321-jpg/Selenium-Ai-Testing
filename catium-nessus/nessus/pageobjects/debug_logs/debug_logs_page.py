"""
Nessus Page Object classes for Debug Logs page from Side navigation panel

:copyright: Tenable Network Security, 2017
:date: Sep 22, 2021
:author: @kpanchal.ctr, @krpatel.ctr
"""
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By

from catium.lib.cat_registry import cat_registry
from catium.lib.log.log import create_logger
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.table import GenericTableRow, GenericBaseTable
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.find import Find
from catium.lib.webium.wait import wait
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.generic.object_list import ObjectList

log = create_logger()


@cat_registry.route('settings/logs')
class DebugLogsPage(NessusBasePage):
    """ Page Object class for Debug logs page in Nessus """

    empty_debug_logs = Find(by=By.CSS_SELECTOR, value='span.empty-results')
    delete_button = Find(by=By.ID, value='delete')
    search_logs_field = Find(TextField, By.CSS_SELECTOR, value='input[data-domselect="searchInput"]')
    search_icon = Find(Clickable, by=By.CSS_SELECTOR, value='i[data-domselect="searchIcon"]')
    remove_search_icon = Find(Clickable, by=By.CSS_SELECTOR, value='i[data-domselect="removeSearchIcon"]')
    select_all_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div.select-all')
    total_logs = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Total Records"]')
    search_logs = Find(by=By.CSS_SELECTOR, value='div[data-domselect="Table Searchbox"] > span')
    empty_log_table = Find(by=By.CSS_SELECTOR, value='td.dataTables_empty')

    @property
    def total_logs_count(self):
        """ Returns total count of available logs in debug logs table """
        return int(self.total_logs.text.split()[0])


class DebugLogsRecord(GenericTableRow):
    """ Defines the key names for Debug Logs Records returned by Debug Logs List """

    select_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='td.select div')
    file_name = Find(by=By.CSS_SELECTOR, value='td:nth-child(2)')
    start_time = Find(by=By.CSS_SELECTOR, value='td:nth-child(3)')
    end_time = Find(by=By.CSS_SELECTOR, value='td:nth-child(4)')
    last_modified = Find(by=By.CSS_SELECTOR, value='td:nth-child(5)')
    download_icon = Find(by=By.CSS_SELECTOR, value='td:nth-child(6)')
    delete_icon = Find(by=By.CSS_SELECTOR, value='td:nth-child(7)')

    @property
    def pcap_file_name(self):
        """ Returns file name from packet capture debug logs list """
        return self.file_name.text

    @property
    def pcap_start_time(self):
        """ Returns start time from packet capture debug logs list """
        return self.start_time.text

    @property
    def pcap_end_time(self):
        """ Returns end time from packet capture debug logs list """
        return self.end_time.text

    @property
    def pcap_last_modified_time(self):
        """ Returns last modified time from packet capture debug logs list """
        return self.last_modified.text


class DebugLogsList(ObjectList):
    """Returns a list containing Scans displayed on the Scan Management Page."""

    object_table = Find(GenericBaseTable, value="content")
    configure_button = None
    generics_map = {GenericTableRow: DebugLogsRecord}
    last_modified_column = Find(by=By.CSS_SELECTOR, value='tr:nth-child(1) th:nth-child(5)')

    def __init__(self):
        super().__init__()
        self.loaded()

    def get_all_pcap_files_name(self) -> list:
        """
        Returns list of pcap file names

        :return: pcap file names
        :rtype: list
        """
        try:
            return [file.pcap_file_name for file in self.rows]
        except NoSuchElementException:
            return []

    def select_deselect_pcap_file(self, file_name: str, select: bool = True) -> None:
        """
        Select given file name from pcap file names in debug logs list

        :param str file_name: pcap file name to be selected
        :param bool select: True if need to select log from table else False to deselect
        :return: None
        """
        for row in self.rows:
            if row.pcap_file_name == file_name:
                if select:
                    row.select_checkbox.check()
                else:
                    row.select_checkbox.uncheck()
                break

    def download_pcap_file(self, file_name: str) -> None:
        """
        Downloads given file name from pcap file names in debug logs list

        :param str file_name: pcap file name to be downloaded
        :return: None
        """
        for row in self.rows:
            if row.pcap_file_name == file_name:
                row.download_icon.click()
                break

    def delete_pcap_file(self, file_name: str) -> None:
        """
        Deletes given file name from pcap file names in debug logs list

        :param str file_name: pcap file name to be deleted
        :return: None
        """
        for row in self.rows:
            if row.pcap_file_name == file_name:
                row.delete_icon.click()

                delete_log_modal = ActionCloseModal()
                wait(lambda: delete_log_modal.is_element_present("modal"),
                     waiting_for="'Delete Log' modal gets displayed")

                delete_log_modal.action_button.click()
                break

    def verify_logs_search_result(self, search_string: str) -> bool:
        """
        Verify search string exists in any column data of rows in the list

        :param str search_string: substring of applied filter
        :return: true if search key found
        :rtype: bool
        """
        return True if all(search_string.lower() in row.text.lower() for row in self.rows) else False
