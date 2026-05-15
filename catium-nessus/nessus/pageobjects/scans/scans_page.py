"""
Nessus page object class for Scan Page

:copyright: Tenable Network Security, 2019
:date: July 21, 2017
:last_modified: Aug 22, 2022
:author: @rdutta, @jamreliya, @mameta, @smadan, @ntarwani, @yshah, @kpanchal, krpatel.ctr
"""

import os
import time
from datetime import datetime, timedelta

from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement
from selenium.webdriver.support.expected_conditions import visibility_of_element_located
from waiting.exceptions import TimeoutExpired

from catium.helpers.sleep_lib import sleep
from catium.helpers.testdata import get_file_path
from catium.lib import const
from catium.lib.cat_registry import cat_registry
from catium.lib.config import Config
from catium.lib.const import WAIT_SHORT, TIME_FIVE_MINUTES, TIME_THIRTY_MINUTES, WAIT_LONG
from catium.lib.const.base_constants import TIME_FIFTEEN_SECONDS, TIME_THREE_SECONDS, TIME_THIRTY_SECONDS
from catium.lib.const.base_constants import WAIT_NORMAL
from catium.lib.log import create_logger
from catium.lib.webium import Find
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.table import GenericTableRow, GenericBaseTable
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.controls.upload_field import UploadField
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.helpers.polling_ui import polling_ui
from nessus.helpers.system import is_home, is_pro
from nessus.lib.const.constants import Nessus, API
from nessus.lib.message.messages import Messages
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.generic.generic_modals import SetPasswordModal, ActionCloseModal, UnsavedChangesModal
from nessus.pageobjects.generic.object_list import ObjectList
from nessus.pageobjects.header.notifications import NotificationActions, \
    close_pendo_guide_container_banner_for_nessus_pro
from nessus.pageobjects.scans.new_scan_form import NewScanForm, ScanType
from nessus.pageobjects.scans.scan_basic_settings_page import BasicSetting
from nessus.pageobjects.scans.scan_view_page import ScanViewPage
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav

log = create_logger()


class ScanFolderNameModalWindow(UnsavedChangesModal):
    """Page objects for name modal pop-up window."""
    name_field = Find(TextField, by=By.CSS_SELECTOR, value='.new-folder-name')


class CopyScanModalWindow(UnsavedChangesModal):
    """Page objects for copy a scan modal pop-up window."""
    scan_name_field = Find(TextField, by=By.CSS_SELECTOR, value='.scan-name')
    include_history_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='.checkbox.include-scan-history')


@cat_registry.route('scans')
class ScansPage(NewScanForm, ScanType, NessusBasePage):
    """Defines properties and methods inherited by the Nessus Scans Page."""

    title_in_header = Find(by=By.CSS_SELECTOR, value='#titlebar h1')
    back_to_folder = Find(Clickable, by=By.CSS_SELECTOR, value='.title-box a')
    resource_center = Find(Clickable, by=By.CSS_SELECTOR, value='[data-domselect="resource-menu"]')
    username = Find(Clickable, by=By.CSS_SELECTOR, value='.user-menu span')
    notification_icon = Find(Clickable, by=By.CSS_SELECTOR, value='.menu-notifications')
    my_scans = Find(Clickable, by=By.CSS_SELECTOR, value='[title="My Scans (S)"]')
    my_scans_tab = Find(Clickable, by=By.CSS_SELECTOR, value='header [href="#/scans/folders/my-scans"]')
    trash_link = Find(Clickable, by=By.CSS_SELECTOR, value='#sidenav a[title*="Trash"]')
    all_scans = Find(Clickable, by=By.CSS_SELECTOR, value='[title="All Scans "]')
    trash = Find(Clickable, by=By.CSS_SELECTOR, value='[title="Trash "]')
    policies_tab = Find(Clickable, by=By.CSS_SELECTOR, value='[title="Policies (P)"]')
    pluginrule_tab = Find(Clickable, by=By.CSS_SELECTOR, value='[title="Plugin Rules"]')
    reports_tab = Find(Clickable, by=By.CSS_SELECTOR, value='[title="Customized Reports"]')
    create_a_new_scan_link = Find(by=By.CSS_SELECTOR, value='.empty-results a')
    new_scan_button = Find(by=By.XPATH, value='.//a[@href="#/scans/reports/new" and contains(@class, "button")]')
    import_button = Find(by=By.CSS_SELECTOR, value='#scans-import')
    import_scan = Find(by=By.CSS_SELECTOR, value='input[class="scan-upload-form-input"]')
    new_folder_button = Find(by=By.CSS_SELECTOR, value='.add-folder.button.floatright')
    select_all_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='.select-all')

    # Bit Discovery specific locators
    bd_scan_summary_tab = Find(by=By.CSS_SELECTOR, value='a[id=scans-show-domain-discovery-summary]')
    bd_records_tab = Find(by=By.XPATH, value="//*[text()='Records ']")
    history_tab = Find(by=By.XPATH, value="//*[text()='History ']")
    bd_domain_name = Find(by=By.CSS_SELECTOR, value='.domain-summary-row td:nth-of-type(1)')
    bd_record_count = Find(by=By.CSS_SELECTOR, value='.domain-summary-row td:nth-of-type(6)')
    bd_record_tab_policy = Find(by=By.XPATH, value="//*[contains(text(),'Policy:')]/following::span[1]")
    bd_record_tab_scan_status = Find(by=By.XPATH, value="//*[contains(text(),'Status:')]/following::span[1]")
    bd_record_tab_license_status = Find(by=By.XPATH, value="//*[contains(text(),'License:')]/following::span[1]")
    bd_record_tab_records_value = Find(by=By.XPATH, value="//*[contains(text(),'Records:')]/following::span[1]")
    bd_scanner_tab = Find(by=By.CSS_SELECTOR, value='#tabs > a[data-view="scanner"]')

    # Elements under 'More' dropdown
    more_button = Find(by=By.CSS_SELECTOR, value='#scans-menu')
    configure_option = Find(by=By.CSS_SELECTOR, value='#scans-configure')
    copy_option = Find(by=By.CSS_SELECTOR, value='#scans-copy')
    move_option = Find(by=By.CSS_SELECTOR, value='#scans-move')
    delete_option = Find(by=By.CSS_SELECTOR, value='#scans-delete')
    new_folder_link_in_move_option = Find(by=By.CSS_SELECTOR, value='#scans-move ul li.add-folder')
    new_folder_link_in_copy_option = Find(by=By.CSS_SELECTOR, value='#scans-copy ul li.add-folder')
    trash_icon_link_in_move_option = Find(by=By.CSS_SELECTOR, value='#scans-move ul li[data-name="Trash"]')

    enable_option = Find(by=By.CSS_SELECTOR, value='#scans-enable')
    disable_option = Find(by=By.CSS_SELECTOR, value='#scans-disable')
    read_option = Find(by=By.CSS_SELECTOR, value='#scans-read')
    unread_option = Find(by=By.CSS_SELECTOR, value='#scans-unread')

    launch_option = Find(by=By.CSS_SELECTOR, value='#scans-launch')
    resume_option = Find(by=By.CSS_SELECTOR, value='#scans-resume')
    pause_option = Find(by=By.CSS_SELECTOR, value='#scans-pause')
    stop_option = Find(by=By.CSS_SELECTOR, value='#scans-stop')

    # Search related elements
    scan_searchbox = Find(TextField, by=By.CSS_SELECTOR, value='#searchbox input')
    search_icon = Find(by=By.CSS_SELECTOR, value='.glyphicons.search')
    clear_search_icon = Find(Clickable, by=By.CSS_SELECTOR, value='#searchbox .remove')
    total_scans_count = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Total Records"]')
    selected_scans_count = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Checked"]')
    filtered_scans_count = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Results"]')
    clear_selected_item_link = Find(by=By.CSS_SELECTOR, value='a[data-domselect="clear-all"]')
    live_results = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div[data-name="Live Results"]')
    show_dashboard = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div[data-name="Show Dashboard"]')
    server_error = Find(by=By.CSS_SELECTOR, value='h1.red')
    pagination_button_next = Find(by=By.CSS_SELECTOR, value='.paginate_button.next')
    pagination_button_previous = Find(by=By.CSS_SELECTOR, value='.paginate_button.previous')
    data_table_info = Find(by=By.CSS_SELECTOR, value='.dataTables_info')
    limit_schedule_scan_message = Find(by=By.CSS_SELECTOR, value=".schedule-note")
    owner_column = Find(by=By.XPATH, value="//*[text()='Owner']")
    upgrade_nessus_link = Find(by=By.XPATH, value='//a[@data-action = "buy-nessus-pro"]')

    def __init__(self):
        super().__init__()
        self.required_elements = ['new_scan_button']

    def get_scan_status(self, scan_name: str, scan_status: str) -> WebElement:
        """
        return the status locator specific to scan
        :param str scan_name: scan name
        :param str scan_status: context of status
        :return: locator of status icon
        :rtype: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value="tr[data-name = '{}'] .glyphicons.scan-status.{}.add-tip"
                    .format(scan_name, scan_status), context=self)

    def get_scan_force_stop_element(self, scan_name: str) -> WebElement:
        """
        return the force stop action locator for particular scan
        :param str scan_name: scan name
        :return: locator of force stop scan
        :rtype: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value="tr[data-name = '{}'] > td > i.kill".format(scan_name), context=self)

    def get_scan_import_status(self, scan_name: str) -> WebElement:
        """
        return the import status locator specific to scan
        :param str scan_name: scan name
        :return: locator of import status icon
        :rtype: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value='tr[data-name = "{}"] .glyphicons.scan-status.imported.add-tip'
                    .format(scan_name), context=self)

    def get_folder_element_from_available_list_option_under_more_dropdown(self, sub_option: str,
                                                                          folder_name: str) -> WebElement:
        """
        Return dynamic element for selecting folder under available list for scan move/copy.
        :param str sub_option: sub-option under 'more' dropdown.
        :param str folder_name: listed folders under sub-option.
        :return: locator of available folder options
        :rtype: WebElement
        """
        element = Find(by=By.CSS_SELECTOR, value='#scans-{} ul li[data-name="{}"]'.format(sub_option, folder_name),
                       context=self)
        try:
            if element.is_displayed():
                return element
        except NoSuchElementException:
            log.warning("%s not found to move in available list.", folder_name)

    def dynamic_element(self, element_name: str) -> WebElement:
        """
        returns dynamic element
        :param str element_name: element name
        :return: dynamic element
        :rtype: WebElement
        """
        return Find(by=By.XPATH, value='.//*[contains(text(), "{}")]'.format(element_name), context=self)

    @property
    def get_page_heading(self):
        """Return page title from header of your current nessus page."""
        return self.title_in_header.text

    @property
    def get_total_scans_count(self):
        """Return count of scans shows in scans table header."""
        return int(self.total_scans_count.text.split(" ")[0])

    @property
    def get_filtered_scans_count(self):
        """Return count of scans filtered with given search string shows in scans table header."""
        return int(self.filtered_scans_count.text.split(" ")[0])

    @property
    def get_selected_scans_count(self):
        """Return counted string shows in scans table header of scans selected in the list."""
        return int((self.selected_scans_count.text.split(" ")[0].split('(')[1]))

    def is_folder_list_visible_for_sub_options_under_more_dropdown(self, sub_option: str) -> bool:
        """
        Return true for availability of list for scan move/copy.
        :param str sub_option: folder options under sub_options in 'more' dropdown.
        :return: true if folder list visible
        :rtype: bool
        """
        try:
            if sub_option == Nessus.Scan.COPY_SCAN:
                self.move_to_element(element=self.copy_option)
            else:
                self.move_to_element(element=self.move_option)
            return (Find(by=By.CSS_SELECTOR, value='#scans-{} ul.folder-list'.format(sub_option),
                         context=self)).is_displayed()
        except NoSuchElementException:
            return False

    def apply_search_on_scans(self, search_string: str) -> None:
        """
        apply a search in scans list
        :param str search_string: substring for search to apply
        :return: None
        """
        self.scan_searchbox.clear()
        LoadingCircle(WAIT_SHORT)
        self.scan_searchbox.value = search_string

    def verify_search_result(self, search_string: str) -> bool:
        """
        verify search string exists in any column data of rows in the list
        :param str search_string: substring of applied filter
        :return: true if search key found
        :rtype: bool
        """
        return True if all(search_string.lower() in row.text.lower() for row in ScanList().rows) else False

    def create_new_folder(self, folder_name: str) -> None:
        """
        Creates a new folder.
        :param str folder_name: Name of the desired folder
        :return: None
        """
        self.new_folder_button.click()
        new_folder_window = ScanFolderNameModalWindow()
        new_folder_window.name_field.value = folder_name
        new_folder_window.accept_action()

    def create_new_scan(self, scan_type: str, scan_template: str, scan_name: str, target_ip: str = None,
                        new_scan_button: bool = True, **kwargs) -> None:
        """
        create a new scan
        :param str scan_type: includes types(scanner/agent/user-defined)
        :param str scan_template: type of the scan template
        :param str scan_name: scan name
        :param str target_ip: destination host ip
        :param bool new_scan_button: True if need to click on new scan button else False
        :param kwargs:
            str folder: scan will listed in this folder
            str dashboard: dashboard status
            str scanner: select remote scanner from available scanner list
            str agent_group: select agent group for agent scan
            str scan_window: set a window for agent scan
            str target_file: absolute path of target file
            str domain_name: domain name to be used
        :return: None
        """
        if new_scan_button:
            self.js_scroll_into_view(element=self.new_scan_button)
            self.new_scan_button.click()

        if is_home():
            ActionCloseModal().close_upgrade_np_offer_modal_nessus_home()
        elif is_pro():
            close_pendo_guide_container_banner_for_nessus_pro()

        wait(lambda: self.is_element_present('vuln_template_section'),
             waiting_for='Waiting for vulnerabilities section to get populated')

        self.select_scan_type(type_of_scan=scan_type)
        self.click_by_scan(scan_text=scan_template)

        if scan_type == Nessus.Scan.ScanTemplateTabs.WAS_TAB:
            target_url = kwargs.get('target_url')
            file_extension_exclusions = kwargs.get('file_extension_exclusions')
            url_list = kwargs.get('url_list')
            path_exclusions = kwargs.get('path_exclusions')
            self.fill_new_was_scan_detail(
                scan_name=scan_name, target_url=target_url, file_extension_exclusions=file_extension_exclusions,
                url_list=url_list, path_exclusions=path_exclusions
            )
        elif scan_template == Nessus.TemplateNames.ATTACK_SURFACE_DISCOVERY:
            domain_name = kwargs.get('domain_name')
            folder_name = kwargs.get('folder')
            self.fill_new_asd_scan_detail(scan_name=scan_name, domain_name=domain_name, folder_name=folder_name)
        else:
            self.fill_new_scan_detail(scan_name=scan_name, host_ip=target_ip, **kwargs)

            if kwargs.get('add_configuration'):
                return

        self.js_scroll_into_view(element=self.save_button)
        self.save_button.click()

    def create_schedule_scan(self, scan_type: str, scan_template: str, scan_name: str, target_ip: str = None) -> None:
        """
        create a new schedule scan
        :param str scan_type: includes types(scanner/agent/user-defined)
        :param str scan_template: type of the scan template
        :param str scan_name: scan name
        :param str target_ip: destination host ip
        :return: None
        """

        schedule_info = {'schedule_date': datetime.today().date() + timedelta(days=2),
                         'schedule_timezone': time.tzname[0],
                         'schedule_time': (datetime.today() + timedelta(hours=1)).time(),
                         'schedule_frequency': API.Schedule.Frequencies.FREQ_ONCE.title()}

        # Create scan with settings data
        self.create_new_scan(scan_template=scan_template, scan_name=scan_name, scan_type=scan_type, target_ip=target_ip,
                             description='Created a scan {}.'.format(scan_template),
                             add_configuration=True)

        # Add credentials and set schedule information if it is a scheduled scan
        BasicSetting().schedule_scan(**schedule_info)
        self.save_button.click()
        LoadingCircle(WAIT_SHORT)

    def import_scan_file(self, **kwargs) -> str:
        """
        import a scan file
        :param kwargs:  str scan_file_name: scan file name to be imported
                        str file_path: from where to import
                        str password: security password for the file to be imported.
        :return: imported file name
        :rtype: str
        """
        scan_file_name = kwargs.get('file_name')
        file_path = kwargs.get('scan_file_path')
        password = kwargs.get('password')

        scan_file = get_file_path(file_path + scan_file_name)
        scan_file_extension = os.path.splitext(scan_file_name)[1][1:]

        if Config.CAT_USE_GRID:
            self.import_scan.send_keys(scan_file)
        else:
            UploadField(self.import_scan).file = scan_file

        if scan_file_extension in API.Scan.ExportFormats.VALID_IMPORT_FORMATS:
            imported_file = os.path.splitext(scan_file_name)[0].replace("_", " ")

            if scan_file_extension == API.Scan.ExportFormats.FORMAT_DB:
                SetPasswordModal().set_password(password=password)

            wait(lambda: not ActionCloseModal().is_element_present("modal"),
                 waiting_for='upload file modal to get disappear')
            sleep(sleep_time=WAIT_NORMAL, reason="It takes little bit time to get the file in list")

            imported_scan = ScansPage().get_scan_import_status(scan_name=imported_file)
            wait(lambda: visibility_of_element_located((imported_scan.we_by, imported_scan.we_value))(
                get_driver_no_init()), timeout_seconds=TIME_FIVE_MINUTES,
                 waiting_for="scan file import to be successful")

            return imported_file
        else:
            log.error("Import failed: %s is unsupported file format.", scan_file_extension)
            return scan_file_name

    def copy_scan_to_selected_folder(self, scan_list: list, folder_name: str, new_folder: bool = False,
                                     select_all: bool = False, copied_scan_name: str = None,
                                     include_history: bool = False, select_all_records: bool = False) -> str:
        """
        Copy scan(s) to selected folder.
        :param list scan_list: scan(s) to be copied.
        :param str folder_name: where scan(s) to be copied.
        :param bool new_folder: Create new folder if True
        :param bool select_all: If true then select_all checkbox will checked
        :param str copied_scan_name: Name for the copied scan(s).
        :param bool include_history: include scan history if true
        :param bool select_all_records: if true then it will select all the checkbox of all the scans present
        :return: copied scan name, exists only if one scan copied(optional)
        :rtype: str
        """
        if not scan_list:
            log.warning("No scan found to copy.")
            return
        else:
            if copied_scan_name and len(scan_list) > 1:
                log.error("Can't specify a name against more than one scan.")
                return

            self.select_all_checkbox.check() if select_all else ScanList().select_scans(scans_list=scan_list)

            if select_all_records:
                ScanViewPage().select_all_records.click()

            LoadingCircle(WAIT_SHORT)
            self.js_scroll_into_view(element=self.more_button)
            self.more_button.click()
            self.move_to_element(self.copy_option)

            if new_folder:
                folder_element = None
            else:
                folder_element = self.get_folder_element_from_available_list_option_under_more_dropdown(
                    sub_option=Nessus.Scan.COPY_SCAN, folder_name=folder_name)

            if folder_element:
                folder_element.click()

                if include_history:
                    CopyScanModalWindow().include_history_checkbox.check()
            else:
                self.new_folder_link_in_copy_option.click()
                ScanFolderNameModalWindow().name_field.value = folder_name

            copy_scan_window = CopyScanModalWindow()

            if copied_scan_name:
                copy_scan_window.scan_name_field.clear()
                LoadingCircle(WAIT_SHORT)
                copy_scan_window.scan_name_field.value = copied_scan_name
                copied_scan_name = copy_scan_window.scan_name_field.get_attribute('value')

            copy_scan_window.accept_action()

            return copied_scan_name

    def move_scan_to_selected_folder(self, scan_list: list, folder_name: str, new_folder: bool = False,
                                     select_all: bool = False, select_all_records: bool = False) -> None:
        """
        Move scan(s) to selected folder.
        :param list scan_list: scan(s) to be moved.
        :param str folder_name: where scan(s) to be moved.
        :param bool select_all: If true then select_all checkbox will checked in that page
        :param bool select_all_records: if true then it will select all the checkbox of all the scans present
        :return: None
        """
        self.select_all_checkbox.check() if select_all else ScanList().select_scans(scans_list=scan_list)

        if select_all_records:
            ScanViewPage().select_all_records.click()

        LoadingCircle(WAIT_SHORT)
        self.js_scroll_into_view(element=self.more_button)
        self.more_button.click()
        self.move_to_element(self.move_option)
        if new_folder:
            folder_element = None
        else:
            folder_element = self.get_folder_element_from_available_list_option_under_more_dropdown(
                sub_option=Nessus.Scan.MOVE_SCAN, folder_name=folder_name)
        if folder_element:
            folder_element.click()
            cancel_scan_modal = ActionCloseModal()

            if cancel_scan_modal.is_element_present('modal'):
                cancel_scan_modal.accept_action()
                cancel_scan_modal.wait_for_modal_closed()
        else:
            self.new_folder_link_in_move_option.click()
            add_folder_window = ScanFolderNameModalWindow()
            add_folder_window.name_field.value = folder_name
            add_folder_window.accept_action()

    def launch_scan(self, scan_list: list, select_all: bool = False, select_all_records: bool = False) -> None:
        """
        Launch scan(s)
        :param list scan_list: scan(s) to be launched.
        :param bool select_all: If true then select_all checkbox will checked
        :param bool select_all_records: if true then it will select all the checkbox of all the scans present
        :return: None
        """
        self.select_all_checkbox.check() if select_all else ScanList().select_scans(scans_list=scan_list)

        if select_all_records:
            ScanViewPage().select_all_records.click()

        LoadingCircle(WAIT_NORMAL)
        self.js_scroll_into_view(element=self.more_button)
        self.more_button.click()
        self.launch_option.click()

        modal_window = ActionCloseModal()
        modal_window.action_button.click()
        modal_window.wait_for_modal_closed()

    def stop_scan(self, scan_list: list, select_all: bool = False, select_all_records: bool = False) -> None:
        """
        stop scan(s)
        :param list scan_list: scan(s) to be stopped.
        :param bool select_all: If true then select_all checkbox will checked
        :param bool select_all_records: if true then it will select all the checkbox of all the scans present
        :return: None
        """
        self.select_all_checkbox.check() if select_all else ScanList().select_scans(scans_list=scan_list)

        if select_all_records:
            ScanViewPage().select_all_records.click()

        LoadingCircle(WAIT_NORMAL)
        self.js_scroll_into_view(element=self.more_button)
        self.more_button.click()
        log.debug("Checking if stop option is available")
        if self.stop_option:
            log.debug("Attempting to stop scans")
            self.stop_option.click()
            modal_window = ActionCloseModal()
            modal_window.accept_action()
            modal_window.wait_for_modal_closed()

    def generate_scan_history(self, scan_name: str, relaunch_count: int = 1) -> None:
        """
        Relaunch and stop scan to generate scan history
        :param str scan_name: name of scan
        :param int relaunch_count: If specified, scan will relaunch with specified count
        :return: None
        """
        scan_list = ScanList()
        for _ in range(relaunch_count):
            LoadingCircle(WAIT_NORMAL)
            if scan_list.launch_scan_and_wait_for_status(scan_name=scan_name, status=API.Scan.Status.RUNNING):
                LoadingCircle(TIME_THREE_SECONDS)
                scan_list.stop_scan(scan_name=scan_name)
                stop_status = self.get_scan_status(scan_name=scan_name, scan_status=API.Scan.Status.CANCELED)
                wait(lambda: visibility_of_element_located((
                    stop_status.we_by, stop_status.we_value))(get_driver_no_init()),
                     waiting_for="scan to be stopped", timeout_seconds=TIME_FIFTEEN_SECONDS)

    def delete_all_scans_from_trash(self) -> None:
        """
        Delete all scans from trash folder
        :return: None
        """
        self.select_all_checkbox.click()
        self.js_scroll_into_view(element=self.more_button)
        self.more_button.click()
        self.delete_option.click()
        ActionCloseModal().accept_action()
        wait(lambda: ScanViewPage().empty_result.text == Messages.NotificationMessages.Scans.empty_trash,
             timeout_seconds=TIME_THIRTY_SECONDS)

    def delete_all_scans(self) -> None:
        """
        Delete scan from any folder and delete it permanently from trash folder
        :return: None
        """
        scan_list = ScanList().get_all_scans()
        self.move_scan_to_selected_folder(scan_list=scan_list, folder_name="Trash", select_all=True)
        wait(lambda: ScanViewPage().empty_result.text == Messages.NotificationMessages.Scans.empty_scan_page_message,
             timeout_seconds=TIME_THIRTY_SECONDS)
        side_nav = SideNav()
        side_nav.get_sidenav_element(element_name="Trash").click()
        wait(lambda: self.is_element_present('scan_searchbox', timeout=TIME_THIRTY_SECONDS),
             waiting_for="Visibility of search box")
        self.delete_all_scans_from_trash()


class ScanRecord(GenericTableRow):
    """Defines the key names for Scan Records returned by ScanList."""
    checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div.checkbox')
    disabled_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div.null-checkbox')
    notes = Find(by=By.CSS_SELECTOR, value='td:nth-child(1)')
    id = Find(by=By.CSS_SELECTOR, value='td:nth-child(2)')
    name = Find(by=By.CSS_SELECTOR, value='td[class*="scan-visible-name"]')
    schedule = Find(by=By.CSS_SELECTOR, value='td.scan-schedule')
    scan_status = Find(by=By.CSS_SELECTOR, value='td.scan-status')
    last_scan_time = Find(by=By.CSS_SELECTOR, value='td.scan-status-text')
    scan_status_in_text = Find(by=By.CSS_SELECTOR, value='td.scan-status-text')
    launch_action_button = Find(Clickable, by=By.CSS_SELECTOR, value='td.scan-action-1')
    scan_action_button = Find(Clickable, by=By.CSS_SELECTOR, value='td.scan-action-1 i')
    stop_button = Find(Clickable, by=By.CSS_SELECTOR, value='td.scan-action-2 i')
    delete_button = Find(Clickable, by=By.CSS_SELECTOR, value='td.scan-action-2')
    table_row = Find(by=By.CSS_SELECTOR, value='role="row"')
    scan_owner = Find(by=By.CSS_SELECTOR, value='td:nth-child(4)')
    user_scan_tool_tip = Find(by=By.CSS_SELECTOR, value='span.add-tip')

    @property
    def scan_notes(self):
        """Returns scan notes of the scan."""
        return self.notes.text

    @property
    def scan_name(self):
        """Returns name of the scan."""
        for _ in range(30):
            try:
                scan_name = self.name.text
                log.info("Scan name element found successfully.")
                return scan_name
            except NoSuchElementException:
                log.warning("Unable to locate scan name element.")
                sleep(1, reason="Scan name to get located properly.")

    @property
    def scan_schedule(self):
        """Returns schedule type of the scan."""
        return self.schedule.text

    @property
    def scan_last_scanned(self):
        """Returns last modified timing of the scan."""
        return self.last_scan_time.text

    @property
    def scan_last_scanned_epoch(self):
        """Returns last modified epoch timing of the scan."""
        return self.last_scan_time.get_attribute('data-order')

    @property
    def scan_owner_name(self):
        """ Returns the name of scan owner """
        return self.scan_owner.text


class ScanList(ObjectList):
    """Returns a list containing Scans displayed on the Scan Management Page."""

    object_table = Find(GenericBaseTable, value="content")
    configure_button = None
    generics_map = {GenericTableRow: ScanRecord}

    def __init__(self):
        super().__init__()
        self.loaded()

    def loaded(self, **kwargs):
        """waits for the list of scans to populate"""
        self.is_element_present('rows', timeout=const.TIME_THIRTY_SECONDS)

    def get_all_scans(self) -> list:
        """
        Returns the list of scans
        :return: list of scans
        :rtype: list
        """
        try:
            return [scan.scan_name for scan in self.rows]
        except NoSuchElementException:
            return []

    def select_scans(self, scans_list: list) -> None:
        """
        Select scan(s) listed in scans_list in the scans page
        :param list scans_list: scan(s) to be selected.
        :return: None
        """
        for row in self.rows:
            if row.scan_name in scans_list:
                row.checkbox.check()

    def unselect_scans(self, scans_list: list) -> None:
        """
        Select scan(s) listed in scans_list in the scans page
        :param list scans_list: scan(s) to be selected.
        :return: None
        """
        for row in self.rows:
            if row.scan_name in scans_list:
                row.checkbox.uncheck()

    def is_scan_selected(self, scans_list: list) -> bool:
        """
        Verify if checkbox is checked against scan(s) under scans_list in the scans page
        :param list scans_list: scan(s) to be selected.
        :return: True if specified scan is already selected
        :rtype: bool
        """
        return all(row.checkbox.is_selected() for row in self.rows if row.scan_name in scans_list)

    def click_on_scan(self, scan_name: str) -> None:
        """
        view scan detail by clicking on it
        :param str scan_name: scan name
        :return: None
        """
        for scan in self.rows:
            log.debug("Comparing '%s' to '%s'.", scan.scan_name, scan_name)
            if scan.scan_name == scan_name:
                scan.click()
                break
        else:
            log.warning("Scan: '%s' not found in the scan list", scan_name)

    def launch_scan(self, scan_name: str) -> None:
        """
        launch scan specified by scan_name
        :param str scan_name: name of the scan to launch
        :return: None
        """
        for scan in self.rows:
            if scan.scan_name == scan_name:
                scan.scan_action_button.click()
                break
        else:
            log.warning("Launch failed: '%s' not found in the scan list", scan_name)

    def stop_scan(self, scan_name: str) -> None:
        """
        stop a scan specified by scan_name
        :param str scan_name: name of the scan to stop
        :return: None
        """
        for scan in self.rows:
            if scan.scan_name == scan_name:
                log.debug("Checking if %s is stopped", scan_name)
                log.debug("Attempting to stop %s.", scan_name)
                scans_page = ScansPage()
                if scans_page.get_scan_status(scan_name=scan_name, scan_status=API.Scan.Status.RUNNING):
                    log.debug("Scan was running")
                    scan.stop_button.click()
                    ActionCloseModal().accept_action()
                    sleep(TIME_THIRTY_SECONDS, reason="Scan takes little bit time to get stopped")
                    break
        else:
            log.warning("Failed to stop: '%s' not found in the scan list", scan_name)

    def delete_scan(self, scan_name: str) -> None:
        """
        Delete a scan specified by scan_name
        :param str scan_name: name of the scan to delete
        :return: None
        """
        NotificationActions().remove_all()

        for scan in self.rows:
            log.debug("Comparing %s to %s.", scan.scan_name, scan_name)
            if scan.scan_name == scan_name:
                log.debug("Waiting for scan %s to be stopped.", scan_name)
                wait(lambda: len(scan.delete_button.find_elements(By.CLASS_NAME, 'trash')) > 0,
                     sleep_seconds=1, timeout_seconds=2 * TIME_FIFTEEN_SECONDS,
                     waiting_for='waiting for trash button to appear')
                log.debug("Attempting to delete %s.", scan_name)
                scan.delete_button.find_element(By.CLASS_NAME, 'trash').click()
                break
        else:
            log.warning("Failed to delete: '%s' not found in the scan list", scan_name)

    def pause_scan(self, scan_name: str) -> None:
        """
        pause scan specified by scan_name
        :param str scan_name: name of the scan to pause
        :return: None
        """
        for scan in self.rows:
            if scan.scan_name == scan_name:
                scan.scan_action_button.click()
                break
        else:
            log.warning("Pause failed: '%s' not found in the scan list", scan_name)

    def get_scan_id(self, scan_name: str) -> int:
        """
        Return scan id for the scan having scan_name
        :param str scan_name: name of the scan
        :return: scan_id of the corresponding scan
        :rtype: int
        """
        for scan in self.rows:
            if scan.scan_name == scan_name:
                return int(scan.id.get_attribute('data-order'))
        else:
            log.warning('scan id was not found for given scan name')

    def launch_scan_and_wait_for_status(self, scan_name: str, status: str = API.Scan.Status.COMPLETED,
                                        is_scheduled_scan: bool = False, launch_scan: bool = True,
                                        verify_running: bool = False) -> bool:
        """
        Method for launch the scan and wait for its status
        :param str scan_name: name of the scan to launch
        :param str status: status of the launched scan
        :param bool is_scheduled_scan: if true then scan will launch automatically at scheduled time
        :param bool launch_scan: if true then scan will launch separately otherwise will check the status only
        :param bool verify_running : if true then scan running status will be verified.
        :return: True if scan is in specified status
        :rtype: bool
        """
        scans_page = ScansPage()
        if is_scheduled_scan:
            _scan_element = scans_page.get_scan_status(scan_name=scan_name, scan_status=API.Scan.Status.RUNNING)
            try:
                wait(lambda: visibility_of_element_located((_scan_element.by,
                                                            _scan_element.f_value))(get_driver_no_init()),
                     timeout_seconds=TIME_FIVE_MINUTES, waiting_for="Waiting for scan to be in running status")
                LoadingCircle(WAIT_SHORT)

            except TimeoutExpired:
                log.error("Scan has not been launched in its scheduled time.")

        if launch_scan:
            self.launch_scan(scan_name)
            sleep(sleep_time=WAIT_LONG, reason='Waiting for scan gets launched properly.')

        scans_page.refresh()
        ScanList().loaded()
        wait(lambda: scans_page.is_element_present('scan_searchbox'), waiting_for="My Scans page to load properly",
             timeout_seconds=TIME_THIRTY_SECONDS)
        scan_element = scans_page.get_scan_status(scan_name=scan_name, scan_status=status)

        with polling_ui():
            try:
                # Waiting for running status when scan gets launched through this method.
                if verify_running:
                    scan_running_element = scans_page.get_scan_status(scan_name=scan_name,
                                                                      scan_status=API.Scan.Status.RUNNING)
                    wait(lambda: visibility_of_element_located((
                        scan_running_element.by, scan_running_element.f_value))(get_driver_no_init()),
                         timeout_seconds=TIME_FIVE_MINUTES, waiting_for="Waiting for scan to be in Running status")

                wait(lambda: visibility_of_element_located((
                    scan_element.by, scan_element.f_value))(get_driver_no_init()), timeout_seconds=TIME_THIRTY_MINUTES,
                     waiting_for="Waiting for scan to be in {} status".format(status))
                return True
            except TimeoutExpired:
                return False

    def scan_read_status(self, scan_name: str) -> bool:
        """
        verify scan read status. if unread return False otherwise True
        :param str scan_name: name of the scan
        :return: True if scan results data already read.
        :rtype: bool
        """
        for row in self.rows:
            if row.scan_name == scan_name:
                return eval(row.get_attribute('data-read').capitalize())
        log.warning('scan %s not found in the scan list', scan_name)

    def get_all_schedule_scans(self) -> list:
        """
        Returns the list of schedule scans
        :return: list of schedule scans
        :rtype: list
        """
        return [scan.scan_name for scan in self.rows if scan.schedule.text != "On Demand"]

    def get_bulk_scan_records(self) -> list:
        try:
            scans_page = ScansPage()
            scans_view_page = ScanViewPage()
            scans_page.refresh()
            wait(lambda: scans_page.is_element_present('scan_searchbox'), waiting_for="My Scans page to load properly",
                 timeout_seconds=TIME_THIRTY_SECONDS)
            LoadingCircle(WAIT_NORMAL)
            scans_view_page.result_per_page_dropdown.select_by_visible_text(text='200')
            all_scans = [scan.scan_name for scan in self.rows]
            while "disabled" not in scans_page.pagination_button_next.get_css_classes():
                scans_page.pagination_button_next.click()
                wait(lambda: scans_page.is_element_present('scan_searchbox'),
                     waiting_for="My Scans page to load properly", timeout_seconds=TIME_THIRTY_SECONDS)
                [all_scans.append(scan.scan_name) for scan in self.rows]
            scans_page.refresh()
            wait(lambda: scans_page.is_element_present('scan_searchbox'), waiting_for="My Scans page to load properly",
                 timeout_seconds=TIME_THIRTY_SECONDS)
            scans_view_page.result_per_page_dropdown.select_by_visible_text(text='200')
            return all_scans
        except NoSuchElementException:
            return []

    def get_scan_owner_name(self, scan_name: str) -> str:
        """
        Return scan owner name of specified scan name

        :param str scan_name: name of the scan
        :return: owner of scan
        :rtype: str
        """
        for scan in self.rows:
            if scan_name in scan.scan_name.split("\n"):
                return scan.scan_owner_name
        else:
            log.warning('scan %s not found in the scan list', scan_name)

    def get_user_scan_tool_tip_text(self, scan_name: str) -> str:
        """
        Returns tooltip message from 'User Scan' label

        :param str scan_name: name of the scan
        :return: tooltip message
        :rtype: str
        """
        for scan in self.rows:
            if scan_name in scan.scan_name.split("\n"):
                self.move_to_element(element=scan.user_scan_tool_tip)
                return scan.user_scan_tool_tip.get_attribute('original-title')
        else:
            log.warning('scan %s not found in the scan list', scan_name)
