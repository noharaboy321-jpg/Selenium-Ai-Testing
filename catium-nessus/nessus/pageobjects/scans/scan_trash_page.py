"""
Scans PageObject for the Trash Folder

:copyright: Tenable Network Security, 2017
:date: Sept 08, 2017
:last_modified: June 19, 2020
:author: @rdutta, @jamreliya, @kpanchal
"""
from selenium.webdriver.common.by import By

from catium.lib.cat_registry import cat_registry
from catium.lib.const import WAIT_SHORT, WAIT_NORMAL
from catium.lib.log import create_logger
from catium.lib.webium import Find
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.wait import wait
from nessus.lib.const import Nessus
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.notifications import NotificationActions
from nessus.pageobjects.scans.scans_page import ScanList
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav

log = create_logger()


@cat_registry.route(r'scans/folders/trash')
class ScansTrashPage(NessusBasePage):
    """ The page object of trash page for scan folders """
    empty_trash_button = Find(Clickable, by=By.CSS_SELECTOR, value='#scans-empty-trash')
    more_button = Find(by=By.CSS_SELECTOR, value='#scans-menu')
    delete_button = Find(by=By.CSS_SELECTOR, value='#scans-delete')
    clear_selected_item_link = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Checked"] a')
    empty_trash_message = Find(by=By.CSS_SELECTOR, value='span.empty-results')

    # Search related elements
    scan_searchbox = Find(TextField, by=By.CSS_SELECTOR, value='#searchbox input')
    search_icon = Find(by=By.CSS_SELECTOR, value='.glyphicons.search')
    clear_search_icon = Find(Clickable, by=By.CSS_SELECTOR, value='#searchbox .remove')
    select_all_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='.select-all')

    def __init__(self):
        super().__init__()

    def delete_scan_from_trash(self, scan_name: str) -> None:
        """
        delete scan specified by scan_name from Trash in Nessus sidenav
        :param scan_name: name of the scan to delete
        :return: None
        """
        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.TRASH).click()
        NotificationActions().remove_all()
        wait(lambda: self.is_element_present("empty_trash_message") or self.is_element_present("scan_searchbox"),
             waiting_for="scans list gets loaded in trash page")

        scan_list = ScanList()

        for scan in scan_list.rows:
            if scan.scan_name == scan_name:
                scan.delete_button.click()
                modal_window = ActionCloseModal()
                modal_window.action_button.click()
                modal_window.wait_for_modal_closed()
                break
        else:
            log.warning('Scan name "%s" not found in the list', scan_name)

    def apply_search_on_scans(self, search_string: str) -> None:
        """
        apply a search in scans list
        :param: str search_string: substring for search to apply
        :return: None
        """
        self.scan_searchbox.clear()
        LoadingCircle(WAIT_SHORT)
        self.scan_searchbox.value = search_string

    def verify_search_result(self, search_string: str) -> bool:
        """
        verify search string exists in any column data of rows in the list
        :param str search_string: substring of applied filter
        :return: True if search found
        :rtype: bool
        """
        return True if all(search_string.lower() in row.text.lower() for row in ScanList().rows) else False

    def delete_selected_scan(self, scan_list: list, select_all: bool = False) -> None:
        """
        Select scan(s) and delete them comes into scan_list 
        :param list scan_list: scan(s) to be deleted.
        :param bool select_all: If true then select_all checkbox will checked
        :return: None 
        """
        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.TRASH).click()

        scan_trash_page = ScansTrashPage()
        wait(lambda: scan_trash_page.is_element_present("scan_searchbox") or scan_trash_page.is_element_present(
            "empty_trash_message"), waiting_for='trash page to load')

        if scan_trash_page.is_element_present("scan_searchbox"):
            scan_trash_page.select_all_checkbox.check() if select_all else ScanList().select_scans(scans_list=scan_list)

            LoadingCircle(WAIT_NORMAL)
            scan_trash_page.js_scroll_into_view(scan_trash_page.more_button)
            scan_trash_page.more_button.click()
            scan_trash_page.delete_button.click()

            modal_window = ActionCloseModal()
            modal_window.accept_action()
            modal_window.wait_for_modal_closed()
        else:
            log.debug("No scans available in Trash folder.")
