""""
Nessus test cases related to Scans main page.

:copyright: Tenable Network Security, 2019
:date: February 09, 2018
:last_modified: Aug 25, 2023
:author: @rdutta, @yshah, @kpanchal, @sacharya, @krpatel.ctr
"""
import os
import time

import pytest
from selenium.webdriver.common.by import By
from selenium.webdriver.support.expected_conditions import invisibility_of_element_located, \
    visibility_of_element_located
from waiting.exceptions import TimeoutExpired

from catium.helpers.sleep_lib import sleep
from catium.lib.config import Config
from catium.lib.const import WAIT_SHORT, WAIT_NORMAL, TIME_SIXTY_SECONDS
from catium.lib.const.base_constants import WAIT_LONG, TIME_THREE_SECONDS, \
    TIME_TEN_MINUTES, TIME_THIRTY_SECONDS, TIME_TEN_SECONDS, TIME_FIVE_MINUTES, TIME_FIVE_SECONDS
from catium.lib.log.log import create_logger
from catium.lib.ssh.ssh import SSH
from catium.lib.util import random_name
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.nessuscli.helper import get_nessus_cli, path_join, get_nessus_var_dir, stop_nessus, start_nessus
from nessus.helpers.polling_ui import polling_ui
from nessus.helpers.scan import get_scan_id, delete_template_file, restart_server, \
    tamper_with_data_and_restart_server, update_plugins_and_restart_server
from nessus.helpers.scanner import wait_for_scanner_to_be_ready
from nessus.helpers.sort import sort_on_column_values
from nessus.helpers.system import is_manager, is_pro
from nessus.helpers.waiters import wait_scan_state
from nessus.lib.config.environment_variables import NESSUS_DATA_DIR
from nessus.lib.const import API, Nessus, SortOrder, NessusCli
from nessus.lib.message.messages import Messages
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications, NotificationActions
from nessus.pageobjects.header.user_menu import UserMenu
from nessus.pageobjects.login.login_page import LoginPage
from nessus.pageobjects.notifications.notifications_page import NotificationsPage, NotificationsList
from nessus.pageobjects.policies.policies_page import PoliciesPage
from nessus.pageobjects.scans.new_scan_form import ScanTemplatePage, NewScanForm
from nessus.pageobjects.scans.scan_trash_page import ScansTrashPage
from nessus.pageobjects.scans.scan_view_page import ScanViewPage
from nessus.pageobjects.scans.scans_page import ScansPage, ScanList, ScanFolderNameModalWindow
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav

log = create_logger()


@pytest.mark.scans_2
@pytest.mark.nessus_home
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_legacy
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestScansMainPage:
    """
    Covers Scans main page related test cases.
    # NQA-1063 : Automation tests for Scans-policies-Main Page.
    """
    cat = None

    @pytest.mark.xray(test_key='NES-14147')
    @pytest.mark.nessus_smoke
    def test_visibility_of_default_elements_in_scans_tab(self):
        """
        NES-14147 : Verify visibility of elements on main page.
        Test "My Scans" is default folder under Scans tab.
        1. Login and navigate to any other nessus page(e.g. Settings)
        2. Verify clicking on "Scans" tab, will open page having title ‘My Scans’.
        3. Also verify visibility of "Import"/"New folder"/"New scan" button.
        """
        assert get_driver_no_init().current_url == "{}/#/scans/folders/my-scans".format(Config.CAT_URL), \
            "You are not navigated to 'My Scans' page."

        header_page = HeaderBasePage()
        header_page.settings_link.click()
        LoadingCircle(WAIT_SHORT)
        assert header_page.scan_link.is_displayed(), "Scans tab is invisible."

        header_page.scan_link.click()
        LoadingCircle(WAIT_NORMAL)
        scans_page = ScansPage()
        assert all([(scans_page.get_page_heading == Nessus.Scan.Folder.MY_SCANS.split(' (')[0]),
                    scans_page.resource_center.is_displayed(), scans_page.username.is_displayed(),
                    scans_page.notification_icon.is_displayed(), scans_page.my_scans.is_displayed(),
                    scans_page.all_scans.is_displayed(), scans_page.trash.is_displayed(),
                    scans_page.new_scan_button.is_displayed(), scans_page.new_folder_button.is_displayed(),
                    scans_page.import_button.is_displayed()]), "All default elements are not visible in My Scans page."
        if is_pro():
            assert all([scans_page.policies_tab.is_displayed(), scans_page.pluginrule_tab.is_displayed(),
                        scans_page.reports_tab.is_displayed()]), "All default elements are not visible in My Scans page."
        if is_manager():
            assert all([scans_page.policies_tab.is_displayed(), scans_page.pluginrule_tab.is_displayed(),
                        scans_page.reports_tab.is_displayed()]), "All default elements are not visible in My Scans page."

    @pytest.mark.usefixtures('create_new_folder')
    def test_visibility_of_create_a_new_scan_link_in_empty_scanlist(self, create_new_folder):
        """
        Test "Create new scan" link is present if no scan listed in that folder.
        1. If no scans are present, then verify empty list showing proper message.
        2. also verify it will have ‘create a new scan’ link.

        NES-8919 Create New Folder and Test "Create new scan" link is present in that folder.
        """
        created_folder_name = create_new_folder[1]
        assert created_folder_name in SideNav().get_all_sidenav_folders_name(), "Folder is not created"

        SideNav().get_sidenav_element(created_folder_name).click()
        assert ScansPage().create_a_new_scan_link.is_displayed(), 'Create a new scan link is invisible.'
        assert ScanList().object_table.empty_results.text.rsplit(' ', 4)[0] == Messages.NotificationMessages.Scans. \
            empty_scan_list, 'Empty message is missing or mismatched'

    @pytest.mark.parametrize("create_scan", [{"template_name": Nessus.TemplateNames.ADVANCED,
                                              "scan_type": API.Permissions.Types.SCANNER}], indirect=True)
    def test_visibility_of_searchbox_with_non_empty_scans_list(self, create_scan):
        """
        Test "scans_searchbox" is present with non empty scans list in scans page.
        1. Navigate to "Scans" page and create at least 1 scan.
        2. Verify that the search box with search icon is present at the top.
        3. Enter some string and verify "search_icon" is invisible and "remove_search" icon visible now.
        4. Clear the search string and verify vice-versa of step 3.
        """
        created_scan_name = create_scan
        scan_page = ScansPage()
        scan_page.save_button.click()
        LoadingCircle(WAIT_SHORT)

        assert all([scan_page.scan_searchbox.is_displayed(),
                    scan_page.search_icon.is_displayed()]), "Searchbox with search icon is invisible."

        scan_page.apply_search_on_scans(search_string=created_scan_name)
        LoadingCircle(WAIT_SHORT)
        assert all([(not scan_page.search_icon.is_displayed()),
                    scan_page.clear_search_icon.is_displayed()]), \
            "Search_icon is visible and clear_search_icon is invisible."

        scan_page.clear_search_icon.click()
        LoadingCircle(WAIT_SHORT)
        assert all([scan_page.search_icon.is_displayed(),
                    (not scan_page.clear_search_icon.is_displayed())]), \
            "Search_icon is invisible and clear_search_icon is visible."

    @pytest.mark.parametrize("create_scan", [{"template_name": Nessus.TemplateNames.WEB_APP,
                                              "scan_type": API.Permissions.Types.SCANNER}], indirect=True)
    def test_clear_selected_item_link(self, create_scan):
        """
        Test "clear_selected_item" link.
        1. Navigate to "Scans" page and create at least 1 scan.
        2. Verify there is no "clear_selected_item" link.
        3. Check the created scan and verify visibility of "clear_selected_item" link.
        4. Click the link and verify scan is unchecked now and also repeat step 2.
        """
        scan_page = ScansPage()
        scan_page.save_button.click()
        LoadingCircle(WAIT_SHORT)
        assert invisibility_of_element_located((By.CSS_SELECTOR, 'a[data-domselect="clear-all"]'))(
            get_driver_no_init()), "'clear_selected_item' link is visible."

        scans_list = ScanList()
        scans_list.select_scans(scans_list=[create_scan])
        LoadingCircle(WAIT_SHORT)

        assert visibility_of_element_located((scan_page.clear_selected_item_link.we_by,
                                              scan_page.clear_selected_item_link.we_value))(get_driver_no_init()), \
            "'clear_selected_item' link is invisible."

        scan_page.clear_selected_item_link.click()
        assert not scans_list.is_scan_selected(scans_list=[create_scan]), "Scan(s) are not unchecked yet."

    @pytest.mark.usefixtures('create_new_folder')
    def test_invisibility_of_scan_searchbox_in_empty_scanlist(self, create_new_folder):
        """
        Test "scan_searchbox" is absent if no scan listed in that folder.
        1. If no scans are present, then scan searchbox should invisible.

        NES-8919: Create New Folder and Test "scan_searchbox" is absent in that folder.
        """
        LoadingCircle(WAIT_SHORT)
        created_folder_name = create_new_folder[1]
        assert created_folder_name in SideNav().get_all_sidenav_folders_name(), "Folder is not created"
        wait(lambda: SideNav().get_sidenav_element(created_folder_name),
             waiting_for='folder link for click')
        SideNav().get_sidenav_element(created_folder_name).click()
        sleep(WAIT_SHORT, reason="waiting for folder  create")
        assert not SideNav().is_element_present('search_box'), \
            "Scan search box is visible."

    @pytest.mark.usefixtures('create_new_folder')
    def test_create_new_scan_link(self, create_new_folder):
        """
        Test "Create a new scan" link in scans page.
        1. Click on the ‘create a new scan’ link (only appears in empty scan folders)
        2. Verify it will take you to the template selection page for scan creation.

        NES-8919: Create New Folder and Test "Create a new scan" link in that folder.
        """
        created_folder_name = create_new_folder[1]
        assert created_folder_name in SideNav().get_all_sidenav_folders_name(), "Folder is not created"

        SideNav().get_sidenav_element(created_folder_name).click()
        scan_page = ScansPage()
        if scan_page.create_a_new_scan_link.is_displayed():
            scan_page.create_a_new_scan_link.click()
            LoadingCircle(WAIT_SHORT)
            assert ScanTemplatePage().get_page_heading == Nessus.Scan.SCAN_TEMPLATE_PAGE_HEADER, \
                "You are not navigated to scan template page."

    @pytest.mark.parametrize("import_scan_file", [
        {"filename": 'Basic_Network_Scan_Result.db',
         "scan_file_path": 'nessus/tests/ui/scans/test_data/', "password": 'nessus'},
        {"filename": 'Agent_-_Basic.nessus', "scan_file_path": 'nessus/tests/ui/agents/test_data/'}], indirect=True)
    def test_import_scan(self, import_scan_file):
        """
        #NQA- 378 : Security - UI - XSS from Nessusdb import
        Test to import scan file of different valid format.
        1. Click on "import" button.
        2. Try to upload a file with .nessus or .db extensions.
        3. Verify it should throw you success notification.
        4. Also verify scan is listed in scan list with imported status icon.
        """
        imported_scan_file = import_scan_file
        ActionCloseModal().wait_for_modal_closed()

        assert ScansPage().get_scan_import_status(scan_name=imported_scan_file).is_displayed(), "Import failed."

        ScanList().click_on_scan(scan_name=imported_scan_file)
        scan_details_page = ScanViewPage()
        wait(lambda: scan_details_page.is_element_present('vulnerability_tab'), waiting_for='Scan details to load')

        assert scan_details_page.page_header == imported_scan_file, "Scan name is mismatched."

        scan_details_page.back_link.click()

    @pytest.mark.parametrize("invalid_scan_file_format", [
        {"filename": 'NQA_1063_TEXT.txt', "scan_file_path": 'nessus/tests/ui/scans/test_data/'},
        {"filename": 'NQA_1063.log', "scan_file_path": 'nessus/tests/ui/scans/test_data/'},
        {"filename": 'NQA_1063_PNG.png', "scan_file_path": 'nessus/tests/ui/scans/test_data/'},
        {"filename": 'NQA_1063_HTML.html', "scan_file_path": 'nessus/tests/ui/scans/test_data/'},
        {"filename": 'NQA_1063_CSV.csv', "scan_file_path": 'nessus/tests/ui/scans/test_data/'}])
    def test_import_scan_with_invalid_file_format(self, invalid_scan_file_format):
        """
        Test to import scan file of different invalid format.

        1. click on "import" button.
        2. Try to upload a file with any other format except .nessus or .db
        3. Verify it should throw you error notification.
        """
        ScansPage().import_scan_file(file_name=invalid_scan_file_format.get('filename'),
                                     scan_file_path=invalid_scan_file_format.get('scan_file_path'))

        assert Notifications().errors[-1] == Messages.NotificationMessages.Scans.invalid_import_format, \
            "Import error notifications for invalid file format is mismatched or missing."

        NotificationActions().remove_all()

    @pytest.mark.usefixtures('delete_all_scans_in_nessus', 'login', 'create_scan')
    @pytest.mark.parametrize("create_scan", [{"template_name": Nessus.TemplateNames.ACTIVE_DIRECTORY_STARTER,
                                              "scan_type": API.Permissions.Types.SCANNER}], indirect=True)
    def test_create_new_scan(self, create_scan):
        """
        Test to create a new policy.
        1. Click on "New Scan" button in"Scans" page
        2. Select a template and fill details, hit "Save".
        3. Verify success notifications.
        4. Verify scan is listed in scans list.
        """
        scan_page = ScansPage()
        scan_page.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            "Success notifications for saved scan is mismatched or missing."

        assert create_scan in ScanList().get_all_scans(), "Created scan is not listed in scans list."

    def test_create_new_folder(self):
        """
        Test to create a new folder from scans main page.
        1. Click on "New Folder" button, verify pop-up opens having name field.
        2. Enter a valid name, hit 'save' button and verify folder is created successfully.
        3. Also verify folder is present in the side navigation bar.
        """
        folder_name = (random_name(prefix="NQA-1063"))[:20]
        scans_page = ScansPage()
        scans_page.new_folder_button.click()
        folder_creation_window = ScanFolderNameModalWindow()

        assert all([(folder_creation_window.unsaved_changes_title.text == Nessus.Scan.Folder.
                     FOLDER_CREATION_WINDOW_TITLE), folder_creation_window.name_field.is_displayed()]), \
            "Folder creation window having name field doesn't popped up."

        folder_creation_window.name_field.value = folder_name
        folder_creation_window.accept_action()
        notification = Notifications()

        assert notification.successes[-1] == Messages.NotificationMessages.SideNavFolders.folder_added, \
            "Success notifications for new folder creation is mismatched or missing."

        NotificationActions().remove_all()
        side_nav = SideNav()
        folder_element = side_nav.get_sidenav_element(element_name=folder_name)
        assert visibility_of_element_located((folder_element.we_by, folder_element.we_value))(get_driver_no_init()), \
            "Created folder is absent in the side navigation bar."

        scans_page.refresh()
        wait(lambda: scans_page.is_element_present('new_folder_button'), waiting_for="Scan page to get loaded.",
             timeout_seconds=TIME_THIRTY_SECONDS, sleep_seconds=WAIT_SHORT)
        side_nav.get_sidenav_element(element_name=folder_name).click()
        side_nav.delete_custom_folder(folder_name=folder_name)

        assert notification.successes[-1] == Messages.NotificationMessages.SideNavFolders.delete_folder, \
            "Success notifications for folder deletion is mismatched or missing."

    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1},
        {"scan_template": Nessus.TemplateNames.HOST_DISCOVERY, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.HOST_DISCOVERY)),
         "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1}]}], indirect=True)
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Agent_Scan.db',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/',
                                                      'password': 'password', "encrypted": True}], indirect=True)
    def test_visibility_of_x_icon_for_each_listed_scans(self, create_scans, import_scan_via_api):
        """
        Test "X" icon is present for all scans listed in the page.
        1. Create and import some scans.
        2. Verify the visibility of "X" icon for all(created and imported) scans listed in the page."""
        scans_page = ScansPage()
        scans_page.refresh()
        wait(lambda: scans_page.is_element_present("scan_searchbox", timeout=TIME_THREE_SECONDS))

        create_scans.append(import_scan_via_api)

        assert all([scan.delete_button.find_element(By.TAG_NAME, value='i').get_attribute('title')
                    == Nessus.Scan.Folder.TRASH for scan in ScanList().rows if scan.scan_name in create_scans]), \
            "'X' icon is invisible."

        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize("create_scans", [
        {'scans_details': [{"scan_template": Nessus.TemplateNames.ADVANCED_DYNAMIC,
                            "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                            "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED_DYNAMIC)),
                            "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1},
                           {"scan_template": Nessus.TemplateNames.ADVANCED,
                            "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                            "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
                            "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1}]}], indirect=True)
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Agent_Scan.db',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/',
                                                      'password': 'password', "encrypted": True}], indirect=True)
    def test_visibility_of_launch_icon_depends_on_scan_status_for_each_listed_scans(self, create_scans,
                                                                                    import_scan_via_api):
        """
        Test visibility of "Launch" icon is dependent on scan status.
        1. Create and import some scans
        2. Verify the visibility of "launch" icon for all created scans listed in the page,
           for imported scans its should invisible.
        """
        scans_page = ScansPage()
        scans_page.refresh()
        wait(lambda: scans_page.is_element_present("scan_searchbox", timeout=TIME_THREE_SECONDS))

        for scan in ScanList().rows:
            if scan.get_attribute('data-status') == API.Scan.Status.IMPORTED:
                assert len(scan.launch_action_button.find_elements(By.TAG_NAME, value='i')) == 0, \
                    "'Launch' icon is visible for imported scan."
            elif scan.scan_name in create_scans:
                assert scan.launch_action_button.find_element(By.TAG_NAME, value='i').get_attribute('title') == \
                       "Launch", "'Launch' icon is invisible for created scan."

        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.xfail(reason="Open bug ticket: NES-18178")
    @pytest.mark.usefixtures('nessus_api_login', 'delete_all_scans_in_nessus')
    @pytest.mark.parametrize("create_scans", [
        {'scans_details': [{"scan_template": Nessus.TemplateNames.PROXYLOGON_MS_EXCHANGE,
                            "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                            "scan_name": random_name(prefix="{}-".format(Nessus.TemplateNames.PROXYLOGON_MS_EXCHANGE)),
                            "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1},
                           {"scan_template": Nessus.TemplateNames.ZEROLOGON_REMOTE_SCAN,
                            "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                            "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ZEROLOGON_REMOTE_SCAN)),
                            "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1},
                           {"scan_template": Nessus.TemplateNames.RIPPLE_20_REMOTE_SCAN,
                            "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                            "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.RIPPLE_20_REMOTE_SCAN)),
                            "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1}]}], indirect=True)
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Agent_-_Basic.nessus',
                                                      'file_path': 'nessus/tests/ui/agents/test_data/'}], indirect=True)
    @pytest.mark.parametrize("sort", SortOrder.VALID_ORDERS)
    @pytest.mark.parametrize("column_to_sort", ["Name", "Schedule", "Last Scanned"])
    def test_sort_scan_list_column_values(self, create_scans, import_scan_via_api, sort, column_to_sort):
        """
        Test to sort list column values
        1. Navigate to "Scans" page and create and import some scans
        2. Click on 'sort' icon on last modified column and verify list should be present in sorted order..
        3. Repeat above for "Name" and "Schedule" column.
        """
        scans_page = ScansPage()
        scans_page.refresh()
        wait(lambda: scans_page.is_element_present("scan_searchbox", timeout=TIME_THREE_SECONDS))

        column_mapping = {'Name': 'scan_name', 'Schedule': 'scan_schedule', 'Last Scanned': 'scan_last_scanned_epoch'}
        sort_key = (lambda k: k.lower()) if (column_to_sort != 'Last Scanned') else (lambda k: time.localtime(int(k)))
        map_attribute = column_mapping[column_to_sort]

        scans_list = ScanList()
        expected_scans_list = sorted([getattr(scan, map_attribute) for scan in scans_list.rows], key=sort_key,
                                     reverse=(sort == SortOrder.DESCENDING))
        time.sleep(3)
        rendered_scans_list = sort_on_column_values(page_class_instance=scans_list, sort=sort,
                                                    column_name=column_to_sort)
        sorted_scans_list = [getattr(scan, map_attribute) for scan in rendered_scans_list]

        assert expected_scans_list == sorted_scans_list, \
            "{} is not sorted in {} order".format(column_to_sort, sort)

        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1},
        {"scan_template": Nessus.TemplateNames.BASIC_NETWORK, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.BASIC_NETWORK)),
         "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1}]}], indirect=True)
    def test_scans_count_visible_next_to_searchbox_matched_with_scanlist_count(self, create_scans):
        """
        Test to match scans count visible next to searchbox in scans page with list count value.
        1. Navigate to "Scans" page and create some scans.
        2. Get the count of scans list and verify it is same with the count visible next to searchbox in the page.
        3. Put some search string in searchbox and repeat step 2.
        4. Check some of filtered scans from list and repeat step 2.
        """
        scans_page = ScansPage()
        scans_list = ScanList()
        assert scans_page.get_total_scans_count == len(scans_list.rows), "Total scans count is mismatched."

        LoadingCircle(WAIT_SHORT)
        selected_scans = 0
        for scan in scans_list.rows:
            if "ad" in scan.name.text.lower():
                scan.checkbox.check()
                selected_scans += 1
            LoadingCircle(WAIT_NORMAL)

        assert scans_page.get_selected_scans_count == selected_scans, "Selected scans count is mismatched."

        scans_page.apply_search_on_scans(search_string="Advanced")
        LoadingCircle(WAIT_SHORT)
        assert scans_page.get_filtered_scans_count == len(scans_list.rows), "Filtered scans count is mismatched."
        scans_page.clear_search_icon.click()

    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize("create_scans", [
        {'scans_details': [{"scan_template": Nessus.TemplateNames.FIND_AI,
                            "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                            "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.FIND_AI)),
                            "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1},
                           {"scan_template": Nessus.TemplateNames.MALWARE,
                            "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                            "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.MALWARE)),
                            "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1},
                           {"scan_template": Nessus.TemplateNames.ADVANCED,
                            "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                            "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.
                                                                           ADVANCED)),
                            "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1}]}], indirect=True)
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Agent_-_Basic.nessus',
                                                      'file_path': 'nessus/tests/ui/agents/test_data/'}], indirect=True)
    def test_search_scan(self, create_scans, import_scan_via_api):
        """
        Test to search a scan in scan list.
        1. Enter a substring that exist in name
        2. Verify that the list is updated with the search item as well as the count.
        3. Repeat above steps with invalid strings.
        """
        search_strings = ["Demand", "ripple", "ze", "disabled"]

        scans_page = ScansPage()
        scans_page.refresh()
        LoadingCircle(WAIT_NORMAL)

        for string_name in search_strings:
            scans_page.apply_search_on_scans(search_string=string_name)
            LoadingCircle(WAIT_SHORT)
            assert scans_page.verify_search_result(search_string=string_name), \
                "Search failed with provided search string."
            scans_page.clear_search_icon.click()

        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.scanning
    @pytest.mark.usefixtures('delete_all_scans_in_nessus', 'login', 'create_new_folder')
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} Scan - ".format(Nessus.TemplateNames.ADVANCED)),
         "target_ip": "{}, {}".format(Nessus.Scan.Target.AWS_LINUX_TARGET_1, Nessus.Scan.Target.AWS_LINUX_TARGET_2),
         "keep_original_scan_name": False}]}], indirect=True)
    def test_more_button_for_created_scan(self, create_scans, create_new_folder):
        """
        Test to verify "More" button dropdown in scans main page.
        1. select one/more scan(s) from list and verify "More" button appears next to import button in page header.
        2. Verify options Configure/Copy to/Launch/Move to.
        3. Verify "Copy to" and "Move to" have inner options.
        4. Launch the scan and verify sub-options under "More" has changed to
           Configure/Mark Read/Move to/Pause/Stop
        5. Pause the scan and verify sub-options under "More" has again changed to
           Configure/Mark Read/Move to/Resume/Stop
        6. Wait for scan to complete and verify sub-options under "More" has again changed to
           Configure/Copy to/Launch/Mark Read-Unread/Move to
        """
        created_folder_name = create_new_folder[1]

        scans_page = ScansPage()
        scans_page.move_scan_to_selected_folder(scan_list=create_scans, folder_name=created_folder_name)

        scans_page.refresh()
        wait(lambda: scans_page.is_element_present("scan_searchbox") or scans_page.is_element_present(
            "create_a_new_scan_link"), waiting_for="Scan page gets loaded properly")

        SideNav().get_sidenav_element(element_name=created_folder_name).click()
        wait(lambda: scans_page.is_element_present("scan_searchbox"), waiting_for="Scan page gets loaded properly")

        assert not scans_page.more_button.is_displayed(), "'More' button is visible."

        scans_list = ScanList()
        scans_list.loaded()
        scans_list.select_scans(scans_list=create_scans)
        scans_page.js_scroll_into_view(element=scans_page.more_button)

        assert scans_page.is_element_present("more_button"), "'More' button is invisible."

        assert not all([scans_page.configure_option.is_displayed(), scans_page.copy_option.is_displayed(),
                        scans_page.launch_option.is_displayed(), scans_page.move_option.is_displayed()]), \
            "This sub options 'Configure/Copy to/Launch/Move' are visible without expanding 'More' dropdown."

        scans_page.more_button.click()

        assert all([scans_page.configure_option.is_displayed(), scans_page.copy_option.is_displayed(),
                    scans_page.is_folder_list_visible_for_sub_options_under_more_dropdown(Nessus.Scan.COPY_SCAN),
                    scans_page.launch_option.is_displayed(), scans_page.move_option.is_displayed(),
                    scans_page.is_folder_list_visible_for_sub_options_under_more_dropdown(Nessus.Scan.MOVE_SCAN)]), \
            "Sub options 'Configure/Copy to/Launch/Move to' under 'More' dropdown is invisible."

        scans_page.launch_option.click()
        launch_scan_modal = ActionCloseModal()
        launch_scan_modal.accept_action()
        launch_scan_modal.wait_for_modal_closed()

        scans_list.refresh()
        wait(lambda: scans_page.is_element_present("scan_searchbox"), waiting_for="scan list gets loaded")

        created_scan_running_status_element = scans_page.get_scan_status(scan_name=create_scans[0],
                                                                         scan_status=API.Scan.Status.RUNNING)
        visibility_of_element_located((created_scan_running_status_element.we_by,
                                       created_scan_running_status_element.we_value))(get_driver_no_init())

        if created_scan_running_status_element.is_displayed():
            scans_list.select_all_checkbox.click()
            scans_page.js_scroll_into_view(scans_page.more_button)
            scans_page.more_button.click()

            assert all([scans_page.configure_option.is_displayed(), scans_page.read_option.is_displayed(),
                        scans_page.move_option.is_displayed(),
                        scans_page.is_folder_list_visible_for_sub_options_under_more_dropdown(Nessus.Scan.MOVE_SCAN),
                        scans_page.pause_option.is_displayed(), scans_page.stop_option.is_displayed()]), \
                "Sub options 'Configure/Mark Read/Move to/Pause/Stop' under 'More' dropdown is invisible."

        if scans_page.pause_option.is_displayed():
            scans_page.pause_option.click()
            sleep(WAIT_NORMAL, reason="scan to be processed.")
            scans_list.refresh()
            wait(lambda: scans_page.is_element_present("scan_searchbox"), waiting_for="scan list gets loaded")
            sleep(WAIT_LONG, reason="scan to be processed.")

            created_scan_paused_status_element = scans_page.get_scan_status(scan_name=create_scans[0],
                                                                            scan_status=API.Scan.Status.PAUSED)
            visibility_of_element_located((created_scan_paused_status_element.we_by,
                                           created_scan_paused_status_element.we_value))(get_driver_no_init())

            if created_scan_paused_status_element.is_displayed():
                scans_list.select_scans(scans_list=create_scans)
                scans_page.js_scroll_into_view(scans_page.more_button)
                scans_page.more_button.click()

                assert all([scans_page.configure_option.is_displayed(), scans_page.read_option.is_displayed(),
                            scans_page.move_option.is_displayed(), scans_page.resume_option.is_displayed(),
                            scans_page.stop_option.is_displayed(),
                            scans_page.is_folder_list_visible_for_sub_options_under_more_dropdown(
                                Nessus.Scan.MOVE_SCAN)]), \
                    "Sub options 'Configure/Mark Read/Move to/Resume/Stop' under 'More' dropdown is invisible."

        if scans_page.resume_option.is_displayed():
            scans_page.resume_option.click()
            scans_list.refresh()
            wait(lambda: scans_page.is_element_present("scan_searchbox"), waiting_for="scan list gets loaded")

        with polling_ui():
            if scans_list.launch_scan_and_wait_for_status(scan_name=create_scans[0], status=API.Scan.Status.COMPLETED,
                                                          launch_scan=False):
                scans_list.select_scans(scans_list=create_scans)
                scans_page.js_scroll_into_view(scans_page.more_button)
                scans_page.more_button.click()

                assert all([scans_page.configure_option.is_displayed(), scans_page.copy_option.is_displayed(),
                            scans_page.is_folder_list_visible_for_sub_options_under_more_dropdown(
                                Nessus.Scan.COPY_SCAN), scans_page.launch_option.is_displayed(),
                            scans_page.read_option.is_displayed(), scans_page.move_option.is_displayed(),
                            scans_page.is_folder_list_visible_for_sub_options_under_more_dropdown(
                                Nessus.Scan.MOVE_SCAN)]), \
                    "Sub options 'Configure/Copy to/Launch/Mark Unread/Move to' under 'More' dropdown is invisible."

    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Agent_-_Basic.nessus',
                                                      'file_path': 'nessus/tests/ui/agents/test_data/'}], indirect=True)
    def test_more_button_for_imported_scan(self, import_scan_via_api):
        """
        Test to verify "More" button in scans main page for imported scan(s).
        1. select one/more scan(s) from list and click "More" button appears next to import button in page header.
        2. Verify visibility of options "Configure/Mark Read/Move to".
        3. Verify "Move to" option have inner options within it.
        """
        scans_page = ScansPage()
        scans_page.refresh()
        wait(lambda: scans_page.is_element_present("scan_searchbox"), waiting_for="scan list gets loaded")

        assert not scans_page.more_button.is_displayed(), "'More' button is visible for imported scan."

        ScanList().select_scans(scans_list=[import_scan_via_api[0]])

        assert visibility_of_element_located((scans_page.more_button.we_by, scans_page.more_button.we_value))(
            get_driver_no_init()), "'More' button is invisible for imported scan."

        scans_page.js_scroll_into_view(scans_page.more_button)
        scans_page.more_button.click()

        assert all([scans_page.configure_option.is_displayed(), scans_page.read_option.is_displayed(),
                    scans_page.move_option.is_displayed(),
                    scans_page.is_folder_list_visible_for_sub_options_under_more_dropdown(Nessus.Scan.MOVE_SCAN)]), \
            "Sub options 'Configure/Mark Read/Move to' under 'More' dropdown is invisible for imported scan."

        scans_page.read_option.click()
        LoadingCircle(WAIT_NORMAL)
        ScanList().select_scans(scans_list=[import_scan_via_api[0]])
        LoadingCircle(TIME_THREE_SECONDS)
        scans_page.js_scroll_into_view(scans_page.more_button)
        scans_page.more_button.click()

        assert all([scans_page.configure_option.is_displayed(), scans_page.unread_option.is_displayed(),
                    scans_page.move_option.is_displayed(),
                    scans_page.is_folder_list_visible_for_sub_options_under_more_dropdown(Nessus.Scan.MOVE_SCAN)]), \
            "Sub options 'Configure/Mark Unread/Move to' under 'More' dropdown is invisible for imported scan."

    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ACTIVE_DIRECTORY_STARTER,
         "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB, "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ACTIVE_DIRECTORY_STARTER))},
        {"scan_template": Nessus.TemplateNames.HOST_DISCOVERY, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.HOST_DISCOVERY)),
         "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1}]}], indirect=True)
    def test_invisibility_of_configure_option_for_more_than_one_selected_scan(self, create_scans):
        """
        Test to verify "configure" option is unavailable for more than one selected scans in scans main page.
        1. Create some scans and select more than scan from list.
        2. Click "More" button appears next to import button in page header.
        3. Verify "Configure" option is unavailable.

        NES-9445: UI Automation: Scans | Verify that configure option should not be visible when multiple scans are
                  selected

        Scenario Tested:
        [x] Verify that 'configure' option should not be visible when multiple scans are selected, Only 'Copy to',
            'Launch', 'Move to' options should display.
        """
        scans_page = ScansPage()
        ScanList().select_scans(scans_list=create_scans)
        LoadingCircle(WAIT_SHORT)

        scans_page.js_scroll_into_view(element=scans_page.more_button)
        scans_page.more_button.click()

        # Verify 'Configure' options is not visible under 'More' dropdown when multiple scans are selected
        assert not scans_page.configure_option.is_displayed(), "Sub options 'Configure' under 'More' dropdown " \
                                                               "is visible for more than one selected scan."

        # Verify 'Copy to', 'Launch' and 'Move to' options are displayed when multiple scans are selected
        assert all([scans_page.copy_option.is_displayed(), scans_page.launch_option.is_displayed(),
                    scans_page.move_option.is_displayed()]), "This sub options 'Configure/Copy to/Launch/Move' are " \
                                                             "visible without expanding 'More' dropdown."

    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Agent_Scan.db',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/',
                                                      'password': 'password', "encrypted": True}], indirect=True)
    def test_invisibility_of_copy_option_for_imported_scan(self, import_scan_via_api):
        """
        Test to verify "Copy to" option unavailable for imported scan in scans main page.
        1. Import a scan and select it from list
        2. Click "More" button appears next to import button in page header.
        3. Verify "Copy to" options is unavailable.
        """
        scans_page = ScansPage()
        scans_page.refresh()
        LoadingCircle(WAIT_NORMAL)

        ScanList().select_scans(scans_list=[import_scan_via_api[0]])
        LoadingCircle(WAIT_NORMAL)
        scans_page.js_scroll_into_view(scans_page.more_button)
        scans_page.more_button.click()
        assert not scans_page.copy_option.is_displayed(), \
            "Sub options 'Copy to' under 'More' drop-down is visible for imported scan."

        scans_page.refresh()
        LoadingCircle(WAIT_NORMAL)

    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.FIND_AI, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.FIND_AI)),
         "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1}]}], indirect=True)
    def test_new_folder_link_for_move_option_under_more_button(self, create_scans):
        """
        Test to verify "New Folder" link for "move to" option under 'more' dropdown in scans main page.
        1. Select one scan from list and Click "More" button appears next to import button in page header.
        2. Hover on "Move to" option and Verify visibility of "New Folder" link.
        3. Click the link and verify popup occurs with name field.
        """
        scans_page = ScansPage()
        ScanList().select_scans(scans_list=create_scans)
        LoadingCircle(WAIT_SHORT)
        scans_page.js_scroll_into_view(element=scans_page.more_button)
        scans_page.more_button.click()
        if scans_page.is_folder_list_visible_for_sub_options_under_more_dropdown(sub_option=Nessus.Scan.MOVE_SCAN):
            assert visibility_of_element_located((
                scans_page.new_folder_link_in_move_option.we_by,
                scans_page.new_folder_link_in_move_option.we_value))(get_driver_no_init()), \
                "'New Folder' link is invisible under 'Move to' option."
            scans_page.new_folder_link_in_move_option.click()
            scan_window = ScanFolderNameModalWindow()
            assert all([(scan_window.unsaved_changes_title.text == Nessus.Scan.MODAL_TITLE_FOR_SCAN_MOVE),
                        scan_window.name_field.is_displayed()]), "Modal pop-up with name field not found."
            scan_window.cancel_button.click()
            LoadingCircle(WAIT_SHORT)
        else:
            pytest.fail(msg="List of folders under 'Move to' option not found.")

    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.FIND_AI, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.FIND_AI)),
         "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1}]}], indirect=True)
    def test_new_folder_link_for_copy_option_under_more_button(self, create_scans):
        """
        Test to verify "New Folder" link for "Copy to" option under 'More' dropdown in scans main page.
        1. Select one scan from list and Click "More" button appears next to import button in page header.
        2. Hover on "Copy to" option and Verify visibility of "New Folder" link.
        3. Click the link and verify popup occurs with name field.
        """
        scans_page = ScansPage()
        ScanList().select_scans(scans_list=create_scans)
        LoadingCircle(WAIT_SHORT)
        scans_page.js_scroll_into_view(element=scans_page.more_button)
        scans_page.more_button.click()
        if scans_page.is_folder_list_visible_for_sub_options_under_more_dropdown(sub_option=Nessus.Scan.COPY_SCAN):
            assert visibility_of_element_located((
                scans_page.new_folder_link_in_copy_option.we_by,
                scans_page.new_folder_link_in_copy_option.we_value))(get_driver_no_init()), \
                "'New Folder' link is invisible under 'Copy to' option."
            scans_page.new_folder_link_in_copy_option.click()
            scan_copy_window = ScanFolderNameModalWindow()
            assert all([(scan_copy_window.unsaved_changes_title.text == Nessus.Scan.MODAL_TITLE_FOR_SCAN_COPY),
                        scan_copy_window.name_field.is_displayed()]), "Modal pop-up with name field not found."
            scan_copy_window.close_button.click()
            LoadingCircle(WAIT_SHORT)

        else:
            pytest.fail(msg="List of folders under 'Copy to' option not found.")

    @pytest.mark.scanning
    @pytest.mark.usefixtures("nessus_api_login", "create_new_folder")
    @pytest.mark.parametrize("create_scans", [
        {'scans_details': [{"scan_template": Nessus.TemplateNames.ADVANCED,
                            "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                            "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
                            "target_ip": Nessus.Scan.Target.LOCALHOST},
                           {"scan_template": Nessus.TemplateNames.BASIC_NETWORK,
                            "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                            "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.BASIC_NETWORK)),
                            "target_ip": Nessus.Scan.Target.LOCALHOST}]}], indirect=True)
    @pytest.mark.parametrize("include_scan_history", [True, False])
    @pytest.mark.parametrize("scan_count", ["Single_scan", "Multiple_scan"])
    def test_copy_scan_to_existing_folder(self, create_new_folder, create_scans, include_scan_history, scan_count):
        """
        Test to copy scan(s) with/without scan history to existing folder.
        1. Create more than 1 scan, launch/stop them to create history for the scan.
        2. Select one/more scan(s) from list and click "More" button appears next to import button in page header.
        3. Hover on "Copy to" option and select an existing folder.
        4. Verify popup occurs and check the checkbox to copy the history.
        5. Go to the destination folder and verify a copy of scan is listed with/without rows of history
           under "History" tab.
        """
        created_scans_list = create_scans

        folder_name = create_new_folder[1]
        mapping_element = {"Single_scan": [created_scans_list[0]], "Multiple_scan": created_scans_list}
        mapped_element = mapping_element[scan_count]

        scan_page = ScansPage()
        scan_page.launch_scan(scan_list=created_scans_list)
        sleep(WAIT_NORMAL, reason="waiting for scan get started running")
        scan_list = ScanList()

        for scan in created_scans_list:
            scan_page.refresh()
            wait(lambda: visibility_of_element_located(scan_page.scan_searchbox), waiting_for='Scan page to load')

            scan_id = get_scan_id(api_object=self.cat.api, scan_name=scan)
            self.cat.api.scans.stop(scan_id=scan_id)

            scan_page.refresh()
            wait(lambda: visibility_of_element_located(scan_page.scan_searchbox), waiting_for='Scan page to load')

            wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.CANCELED,
                            timeout=TIME_SIXTY_SECONDS)

        scan_list.refresh()
        wait(lambda: visibility_of_element_located(scan_page.scan_searchbox), waiting_for='Scan page to load')

        if scan_count == "Single_scan":
            copied_scan = scan_page.copy_scan_to_selected_folder(
                scan_list=mapped_element, folder_name=folder_name, copied_scan_name="NQA-1063-copy-of-{}".format(
                    mapped_element[0]), include_history=include_scan_history)
            sleep(WAIT_SHORT, reason="waiting for scan to copy")
            assert Notifications().successes[-1] == Messages.NotificationMessages.Scans.scan_copied, \
                     "Success notifications for scan copied to selected folder is mismatched or missing."
        else:
            scan_page.copy_scan_to_selected_folder(scan_list=mapped_element, folder_name=folder_name,
                                                   include_history=include_scan_history)
            sleep(WAIT_SHORT, reason="waiting for scan to copy")
            assert Notifications().successes[-1] == Messages.NotificationMessages.Scans.scans_copied, \
                "Success notifications for scans copied to selected folder is mismatched or missing."

        side_nav = SideNav()
        sleep(WAIT_SHORT, reason="waiting for sidenav to populate")
        side_nav.get_sidenav_element(element_name=folder_name).click()
        wait(lambda: visibility_of_element_located(scan_page.scan_searchbox), waiting_for='Scan page to load')
        for scan in created_scans_list:
            if scan_count == "Single_scan":
                scan_list.click_on_scan(scan_name=copied_scan)
                break
            else:
                sleep(WAIT_SHORT, reason="waiting for scan to copy")
                scan_list.click_on_scan(scan_name="Copy of {}".format(scan))

            scan_details_page = ScanViewPage()
            wait(lambda: scan_details_page.is_element_present("history_tab"), waiting_for="scan result gets loaded")
            scan_details_page.history_tab.click()
            sleep(WAIT_SHORT, reason="waiting for scan to copy")
            scan_history_list = ScanList()

            if include_scan_history:
                assert not scan_history_list.is_empty(), "History exists without exclude scan history."
            else:
                assert scan_history_list.is_empty(), "History exists with exclude scan history."

            scan_details_page.back_link.click()

        side_nav.get_sidenav_element(element_name=folder_name).click()
        wait(lambda: visibility_of_element_located(scan_page.scan_searchbox), waiting_for='Scan page to load')

        all_copied_scan = scan_list.get_all_scans()
        side_nav.get_sidenav_element(element_name=folder_name).click()
        side_nav.delete_custom_folder(folder_name=folder_name)

        assert Notifications().successes[-1] == Messages.NotificationMessages.SideNavFolders.delete_folder, \
            "Success notifications for folder deletion is mismatched or missing."
        for scan in all_copied_scan:
            sleep(WAIT_NORMAL, reason="waiting for scan to populate in trash")
            ScansTrashPage().delete_scan_from_trash(scan_name=scan)

        side_nav.get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()
        scan_list.loaded()

    @pytest.mark.usefixtures('delete_all_scans_in_nessus', 'login', 'create_scans')
    @pytest.mark.parametrize("create_scans", [
        {'scans_details': [{"scan_template": Nessus.TemplateNames.ADVANCED,
                            "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                            "scan_name": random_name(prefix="{}-".format(Nessus.TemplateNames.ADVANCED)),
                            "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1},
                           {"scan_template": Nessus.TemplateNames.WEB_APP,
                            "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                            "scan_name": random_name(prefix="{}-".format(Nessus.TemplateNames.WEB_APP)),
                            "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1}]}], indirect=True)
    @pytest.mark.parametrize("scan_count", ["Single_scan", "Multiple_scan"])
    def test_copy_scan_to_new_folder(self, create_scans, scan_count):
        """
        Test to copy scan(s) to new folder.
        1. Create more than 1 scan, launch/stop them to create history for the scan.
        2. Select one/more scan(s) from list and click "More" button appears next to import button in page header.
        3. Hover on "Copy to" option and select "New Folder" option.
        4. Verify popup occurs and success notifications.
        5. Go to the destination folder folder and verify a copy of scan is listed in that folder.
        """
        created_scans_list = create_scans
        LoadingCircle(WAIT_SHORT)

        folder_name = random_name(prefix="New-NQA-1063-")[:20]
        mapping_element = {"Single_scan": [created_scans_list[0]], "Multiple_scan": created_scans_list}
        mapped_element = mapping_element[scan_count]

        scan_page = ScansPage()
        scan_page.refresh()
        wait(lambda: visibility_of_element_located(scan_page.scan_searchbox), waiting_for='Scan page to load')

        if scan_count == "Single_scan":
            scan_page.copy_scan_to_selected_folder(scan_list=mapped_element, folder_name=folder_name, new_folder=True,
                                                   copied_scan_name="NQA-1063-copy-of-{}".format(mapped_element[0]))
        else:
            scan_page.copy_scan_to_selected_folder(scan_list=mapped_element, folder_name=folder_name, new_folder=True)

        assert Notifications().successes[-1] == Messages.NotificationMessages.SideNavFolders.folder_added, \
            "Success notifications for scan copied to new folder is mismatched or missing."

        side_nav = SideNav()
        side_nav.get_sidenav_element(element_name=folder_name).click()

        all_copied_scan = ScanList().get_all_scans()
        side_nav.delete_custom_folder(folder_name=folder_name)
        ActionCloseModal().wait_for_modal_closed()

        for scan in all_copied_scan:
            ScansTrashPage().delete_scan_from_trash(scan_name=scan)
            sleep(WAIT_NORMAL, reason="Scan list takes little bit time to get loaded after deleting scan")

        side_nav.get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.usefixtures("create_new_folder", 'delete_all_scans_in_nessus')
    @pytest.mark.parametrize("create_scans", [
        {'scans_details': [{"scan_template": Nessus.TemplateNames.ADVANCED,
                            "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                            "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.MALWARE)),
                            "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1},
                           {"scan_template": Nessus.TemplateNames.BASIC_NETWORK,
                            "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                            "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.BASIC_NETWORK)),
                            "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1}],
         "keep_original_scan_name": False}], indirect=True)
    @pytest.mark.parametrize("folder_option", ["Existing Folder", "New Folder"])
    @pytest.mark.parametrize("scan_count", ["Single_scan", "Multiple_scan"])
    def test_move_scans_to_selected_folder(self, create_new_folder, create_scans, folder_option, scan_count):
        """
        Test to move scan(s) to selected folder.
        1. Select more than one scan from list and click "More" button appears next to import button in page header.
        2. Hover on "Move to" option and select your folder.
        3. Verify scan is not listed in current folder.
        4. Go to moved folder and verify the scan is listed on the folder.
        """
        created_scans = create_scans
        LoadingCircle(WAIT_SHORT)

        folder_name = random_name(prefix="New-NQA-1063-")[:20]
        mapping_element = {"Existing Folder": create_new_folder[1], "New Folder": folder_name}
        mapped_element = mapping_element[folder_option]
        mapping_count_element = {"Single_scan": [created_scans[0]], "Multiple_scan": created_scans}
        mapped_count_element = mapping_count_element[scan_count]

        scan_page = ScansPage()
        scan_page.refresh()
        wait(lambda: visibility_of_element_located(scan_page.scan_searchbox), waiting_for='Scan page to load')

        if folder_option == "New Folder":
            scan_page.move_scan_to_selected_folder(scan_list=mapped_count_element, new_folder=True,
                                                   folder_name=mapped_element)
        else:
            scan_page.move_scan_to_selected_folder(scan_list=mapped_count_element, folder_name=mapped_element)

        notification = Notifications()

        if folder_option == "New Folder":
            assert notification.successes[-1] == Messages.NotificationMessages.SideNavFolders.folder_added, \
                "Success notifications for scans moved to new folder is mismatched or missing."
        else:
            if scan_count == "Multiple_scan":
                assert notification.successes[-1] == Messages.NotificationMessages.Scans.scans_moved, \
                    "Success notifications for scans moved to selected folder is mismatched or missing."
            else:
                assert notification.successes[-1] == Messages.NotificationMessages.Scans.scan_moved, \
                    "Success notifications for scan moved to selected folder is mismatched or missing."

        scan_list = ScanList()

        for scan in created_scans:
            assert scan not in scan_list.get_all_scans(), "Move failed: Scans exists in current scan folder."

            if scan_count != "Multiple_scan":
                break

        side_nav = SideNav()
        side_nav.get_sidenav_element(element_name=mapped_element).click()
        scan_list.loaded()

        for scan in created_scans:
            assert scan in scan_list.get_all_scans(), "Move failed: Scans not found in destination folder."

            if scan_count != "Multiple_scan":
                scan_list.delete_scan(scan_name=scan)
                side_nav.get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()
                break

        if folder_option == "New Folder":
            side_nav.get_sidenav_element(element_name=folder_name).click()
            side_nav.delete_custom_folder(folder_name=folder_name)
            ActionCloseModal().wait_for_modal_closed()
            side_nav.get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.parametrize("create_scan", [{"template_name": Nessus.TemplateNames.WEB_APP,
                                              "scan_type": API.Permissions.Types.SCANNER}], indirect=True)
    def test_clicking_on_x_icon_move_scan_to_trash(self, create_scan):
        """
        Test to move scan(s) to 'Trash' folder through 'X' icon.
        1. Create a scan
        2. Click on 'X' icon and verify success notification.
        3. Verify scan is not listed in current folder.
        4. Go to 'Trash' folder and verify the scan is listed in the folder.
        """
        scan_page = ScansPage()
        scan_page.save_button.click()
        LoadingCircle(WAIT_SHORT)
        NotificationActions().remove_all()

        scan_name = create_scan
        scan_list = ScanList()
        scan_list.delete_scan(scan_name=scan_name)

        assert Notifications().successes[-1] == Messages.NotificationMessages.scan_move_to_trash, \
            "Success notifications for scan delete is mismatched or missing."

        assert scan_name not in scan_list.get_all_scans(), "Scan exists in current scan folder after clicking 'X' icon."

        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.TRASH).click()
        wait(lambda: scan_name in scan_list.get_all_scans(),
             waiting_for="trash page to load")
        assert scan_name in scan_list.get_all_scans(), "Scan does not exists in trash folder."

        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.scanning
    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         "target_ip": Nessus.Scan.Target.LOCALHOST},
        {"scan_template": Nessus.TemplateNames.HOST_DISCOVERY, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.HOST_DISCOVERY)),
         "target_ip": Nessus.Scan.Target.LOCALHOST}]}], indirect=True)
    def test_mark_scan(self, create_scans):
        """
        Test to mark scan(s).
        1. Create two scans, launch them.
        2. Select any one scan and click "More" button appears next to import button in page header.
        3. Verify 'Mark Read' option is visible and click the option.
        4. Verify 'Mark Read' option is now changed to 'Mark Unread'.
        5. Select both scans and verify both options visible now.
        6. Verify click any of the option will effect both the scans
        """
        # Create scans, launch them and wait for completion
        created_scan_list = create_scans
        scans_page = ScansPage()
        scans_page.launch_scan(scan_list=created_scan_list)
        for scan in created_scan_list:
            scan_id = get_scan_id(api_object=self.cat.api, scan_name=scan)
            wait(lambda: (self.cat.api.scans.get_status(scan_id=scan_id) == API.Scan.Status.COMPLETED),
                 waiting_for="Scans to be in completed state.", timeout_seconds=TIME_TEN_MINUTES * 2)

        scans_page.refresh()
        LoadingCircle(WAIT_LONG)
        assert not scans_page.is_element_present('more_button'), '"More" button is visible while no scan(s) selected.'

        # Select the scan(s) and check their read/unread status accordingly
        scan_list = ScanList()
        scan_list.select_scans(scans_list=[created_scan_list[0]])
        LoadingCircle(WAIT_SHORT)
        scans_page.js_scroll_into_view(scans_page.more_button)
        scans_page.more_button.click()
        assert all(
            [scans_page.is_element_present('read_option'), not scans_page.is_element_present('unread_option')]), \
            "'Mark Read' option is invisible and 'Mark Unread' option is visible."

        scans_page.read_option.click()
        LoadingCircle(WAIT_NORMAL)
        scan_list.select_scans(scans_list=[created_scan_list[0]])
        scans_page.more_button.click()
        LoadingCircle(WAIT_SHORT)
        assert all(
            [scans_page.is_element_present('unread_option'), not scans_page.is_element_present('read_option')]), \
            "'Mark Unread' option is invisible and 'Mark Read' option is visible."

        scans_page.refresh()
        LoadingCircle(WAIT_LONG)
        scan_list.select_scans(scans_list=created_scan_list)
        LoadingCircle(WAIT_SHORT)
        scans_page.more_button.click()
        LoadingCircle(WAIT_SHORT)
        assert all([scans_page.is_element_present('read_option'), scans_page.is_element_present('unread_option')]), \
            "Both 'Mark Read'/'Mark Unread' option is invisible."

        LoadingCircle(TIME_THREE_SECONDS)
        scans_page.read_option.click()
        LoadingCircle(WAIT_SHORT)
        scans_page.refresh()
        LoadingCircle(WAIT_LONG)
        scan_list.select_scans(scans_list=created_scan_list)
        LoadingCircle(TIME_THREE_SECONDS)
        scans_page.more_button.click()
        assert all(
            [scans_page.is_element_present('unread_option'), not scans_page.is_element_present('read_option')]), \
            "'Mark Unread' option is invisible and 'Mark UnrRead' option is visible."

        LoadingCircle(WAIT_SHORT)

    @pytest.mark.xfail(reason="Inconsistent on nightly runs")
    @pytest.mark.parametrize('operation', ['delete', 'modify'])
    def test_scan_templates_icon_after_deleting_and_modifying_policy_wizards_json(self, operation):
        """
        NES-9152: UI test for NES-8964 - template icons from feed

        Scenario Tested:
        [x] Verify that user should not be allowed to see scan templates while creating scan and policy after deleting
            and modifying policy_wizards.json file.
        """
        data = None
        try:
            if operation == 'delete':
                delete_template_file(file='policy_wizards.json')
                restart_server()
            else:
                with SSH() as ssh:
                    data = ssh.read_from_file(remote_file_path=os.path.join(NESSUS_DATA_DIR, 'templates',
                                                                            'policy_wizards.json'))

                tamper_with_data_and_restart_server(
                    file_path=os.path.join(NESSUS_DATA_DIR, 'templates', 'policy_wizards.json'), data='abc')

            NotificationActions().remove_all()

            scan_page = ScansPage()
            scan_page.new_scan_button.click()

            assert scan_page.server_error.text == '500 - Internal Server Error', \
                'Error message is missing or mismatch while click on new scan button.'

            policies_page = PoliciesPage()
            SideNav().get_sidenav_element(Nessus.SideNavResources.POLICIES).click()

            LoadingCircle(WAIT_NORMAL)
            policies_page.new_policy_button.click()

            assert scan_page.server_error.text == '500 - Internal Server Error', \
                'Error message is missing or mismatch while click on new policy button.'
        finally:
            if operation == 'delete':
                update_plugins_and_restart_server()
            else:
                tamper_with_data_and_restart_server(
                    file_path=os.path.join(NESSUS_DATA_DIR, 'templates', 'policy_wizards.json'), data=data)

    @pytest.mark.parametrize('folder_count', [5])
    def test_different_custom_folder_scans_in_all_scans(self, folder_count):
        """
        NES-9392: UI Automation: Scans | Verify that all different folder scan should be displayed in 'All Scans' folder

        Steps:
        1. Log in NM/NP with the valid credential.
        2. Create multiple folders using the "New folder" option
        3. Create sample scan under all newly created folder
        4. Go to "All Scans" folder

        Scenario Tested:
        [x] Verify that all different folder scan should be displayed in "All Scans" folder
        """
        scan_page = ScansPage()
        side_nav = SideNav()
        folder_scan_details = {}

        try:
            for i in range(folder_count):
                # Create custom folder using the "New folder" option
                folder_name = random_name(prefix='Custom-folder-')[:20]
                scan_page.js_scroll_into_view(element=scan_page.new_folder_button)
                scan_page.create_new_folder(folder_name=folder_name)
                notification = Notifications()

                # Verify success message after creating folder
                assert notification.successes[-1] == Messages.NotificationMessages.SideNavFolders.folder_added, \
                    'Getting incorrect notification, Expected is {}.'.format(
                        Messages.NotificationMessages.SideNavFolders.folder_added)

                # Verify created folder is displayed under "Folders" in side navigation panel
                assert folder_name in side_nav.get_all_sidenav_folders_name(), \
                    "'{}' folder is not created.".format(folder_name)

                # Create advanced scan
                scan_name = random_name(prefix='Advanced_Scan-')
                scan_page.create_new_scan(scan_name=scan_name, scan_template=Nessus.TemplateNames.ADVANCED,
                                          scan_type=Nessus.Scan.ScanTemplateTabs.SCANNER_TAB, folder=folder_name,
                                          target_ip=Nessus.Scan.Target.LOCALHOST)

                # Verify success message after creating scan
                assert notification.successes[-1] == Messages.NotificationMessages.save_scan, \
                    'Getting incorrect notification, Expected is {}.'.format(Messages.NotificationMessages.save_scan)

                folder_scan_details[folder_name] = scan_name
                NotificationActions().remove_all()

            # Go to 'All Scans' folder
            side_nav.get_sidenav_element(element_name=Nessus.Scan.Folder.ALL_SCANS).click()
            scan_list = ScanList()

            # Verify created scan with custom folder is displayed in 'All Scans' folder
            for folder, scan in folder_scan_details.items():
                assert '\n'.join([folder, scan]) in scan_list.get_all_scans(), \
                    'All created different folder scan is not displayed in \'All Scans\' folder.'
        finally:
            # Delete created custom folders and scans
            for folder, scan in folder_scan_details.items():
                side_nav.get_sidenav_element(element_name=folder).click()
                side_nav.delete_custom_folder(folder_name=folder)
                ActionCloseModal().wait_for_modal_closed()

            ScansTrashPage().delete_selected_scan(select_all=True, scan_list=[])

    @pytest.mark.xray(test_key='NES-14247')
    def test_verify_after_click_on_icon_user_redirects_to_proper_page_after_collapsing(self):
        """
        NES-12478 [UI] After collapsing sidebar on main scan page, verify that each icon redirects user to proper
                       webpage.
        NES-14247 : After collapsing sidebar on main scan page, verify that each icon redirects user to proper webpage.

        Scenario Tested:
        [x] Verify that each icon redirects user to proper webpage after collapsing sidebar on main scan page.
        """
        header_page = HeaderBasePage()
        side_nav = SideNav()
        default_header_menu = Nessus.DEFAULT_HEADER_MENU

        try:
            side_nav.collapse_menu_icon.click()
            Nessus.SideNavSettings.SETTINGS_SUB_MENU.update(
                {Nessus.SideNavAccounts.MY_ACCOUNT: "#/settings/my-account"})

            sub_menu_dict = {Nessus.SCANS: (header_page.scan_link, Nessus.SideNavResources.SCANS_SUB_MENU),
                             Nessus.SETTINGS: (header_page.settings_link, Nessus.SideNavSettings.SETTINGS_SUB_MENU)}

            if is_manager():
                manager_header_menu = {Nessus.SENSORS: (header_page.sensors_tab,
                                                        Nessus.SideNavResources.SENSORS_SUB_MENU)}

                sub_menu_dict.update(manager_header_menu)

                other_manager_settings_sub_menu = {Nessus.SideNavSettings.LDAP_SERVER: "#/settings/ldap-server",
                                                   Nessus.SideNavAccounts.USERS: "#/settings/users",
                                                   Nessus.SideNavAccounts.GROUPS: "#/settings/groups"}

                default_header_menu.append(Nessus.SENSORS)
                sub_menu_dict.get(Nessus.SETTINGS)[1].update(other_manager_settings_sub_menu)
            elif is_pro():
                other_pro_settings_sub_menu = {Nessus.SideNavSettings.REMOTE_LINK: "#/settings/remote-link",
                                               Nessus.SideNavSettings.DEBUG_LOGS: "#/settings/logs"}

                sub_menu_dict.get(Nessus.SETTINGS)[1].update(other_pro_settings_sub_menu)
            else:
                unwanted_sub_menu_dict = {Nessus.SCANS: Nessus.SideNavResources.CUSTOMIZED_REPORTS,
                                          Nessus.SETTINGS: Nessus.SideNavSettings.UPGRADE_ASSISTANT}

                for menu in default_header_menu:
                    del sub_menu_dict.get(menu)[1][unwanted_sub_menu_dict.get(menu)]

            for header_menu in default_header_menu:
                sub_menu_dict.get(header_menu)[0].click()
                sleep(WAIT_NORMAL, reason="Page takes little bit time to get loaded")

                for sub_menu in list(sub_menu_dict.get(header_menu)[1].keys()):
                    side_nav_folder_element = side_nav.get_sidenav_element(element_name=sub_menu)
                    icon_href_value = side_nav_folder_element.get_attribute("href")
                    side_nav_folder_element.click()

                    expected_page_endpoint = sub_menu_dict.get(header_menu)[1].get(sub_menu)

                    assert all([icon_href_value.endswith(expected_page_endpoint), header_page.current_url.endswith(
                        expected_page_endpoint)]), "User does not redirect to proper page after clicking on icon of " \
                                                   "'{}' menu.".format(sub_menu)

        finally:
            side_nav.collapse_menu_icon.click()

    @pytest.mark.xray(test_key='NES-14621')
    @pytest.mark.xray(test_key='NES-14451')
    def test_verify_bell_icon_on_main_scan_page(self):
        """
        NES-14451 : Verify bell icon on main scan page
        NES-14621 : Verify notification popup opened from bell icon

        Scenario Tested:
        [x] Verify that Notification icon is visible on main Scan page when user login
        [x] Verify clicking Notification icon opens Notification History box
        [x] Verify Clicking on Close button on Notification History box dismisses notification history box
        """
        header_page = HeaderBasePage()
        wait(lambda: header_page.is_element_present('notification_icon', timeout=TIME_THREE_SECONDS))
        assert header_page.is_element_present('notification_icon'), 'Notification icon is not available on'

        header_page.notification_icon.click()
        wait(lambda: header_page.is_element_present('notification_history_box', timeout=TIME_THREE_SECONDS))
        assert header_page.is_element_present('notification_history_box'), 'Notification History box is not visible'

        header_page.notification_box_close_button.click()
        assert invisibility_of_element_located('notification_history_box'), 'Notification History box is ' \
                                                                            'still visible '

    @pytest.mark.xray(test_key='NES-14385')
    def test_verify_notification_page_navigation(self):
        """
        NES-14385 : Verify notification bell icon
        """
        header_page = HeaderBasePage()
        wait(lambda: header_page.is_element_present('notification_icon', timeout=TIME_THREE_SECONDS))

        assert header_page.is_element_present('notification_icon'), 'Notification icon is not available on'

        header_page.notification_icon.click()
        wait(lambda: header_page.is_element_present('notification_history_box', timeout=TIME_THREE_SECONDS))

        assert header_page.is_element_present(
            'notification_history_link'), 'View Notification History link is not visible'

        header_page.notification_history_link.click()
        notification_page = NotificationsPage()
        notification_list = NotificationsList()

        assert notification_page.loaded(), "Not redirected to Notification history page"

        wait(lambda: notification_page.is_element_present("page_header"),
             waiting_for='Notification list to populate', timeout_seconds=WAIT_NORMAL)

        assert notification_page.page_header.text == "Notifications", "Notifications history list is not loaded"

    @pytest.mark.xray(test_key='NES-14444')
    def test_verify_feed_error_after_backup_restore(self):
        """
        NES-14444 Verify the feed error after backup restore
        """

        # Perform Backup and Restore via CLI
        user_menu = UserMenu()
        user_menu.logout()
        nessus_api = NessusAPI()
        with SSH() as ssh:
            ssh.execute("{} {} {}".format(get_nessus_cli(), NessusCli.BackupAndRestore.BACKUP_COMMAND,
                                          NessusCli.BackupAndRestore.BACKUP_FILE_NAME))

            sleep(sleep_time=TIME_FIVE_SECONDS, reason='waiting for backup to get created')

            all_files = ssh.execute("ls {}".format(get_nessus_var_dir()))

            backup_file = [file for file in all_files if "nessus_backup" in file][0]

            backup_tar_file = path_join(path_dir_list=[get_nessus_var_dir(),
                                                       backup_file])

            assert ssh.path_exist(backup_tar_file), "Backup tar file was not created successfully!"

            stop_nessus()
            restore_backup_output = ssh.execute("{} {} {}".format(
                get_nessus_cli(), NessusCli.BackupAndRestore.RESTORE_COMMAND, backup_tar_file))
            log.debug("'{}' command output is : {}".format(NessusCli.BackupAndRestore.RESTORE_COMMAND,
                                                           restore_backup_output))

            assert NessusCli.BackupAndRestore.DB_VERSION_CHECK_PASSED in restore_backup_output, \
                "'{}' message is not present in 'backup --restore' command execution's output".format(
                    NessusCli.BackupAndRestore.DB_VERSION_CHECK_PASSED)

            start_nessus()
            wait_for_scanner_to_be_ready(api=nessus_api)

        # Verify Nessus is loading properly without any feed error

        login_page = LoginPage()
        login_page.refresh()
        wait(lambda: login_page.is_element_present('username_field'), timeout_seconds=TIME_THIRTY_SECONDS)
        # Verify all elements/ nessus type/ copyright year on login_page screen.
        assert login_page.is_element_present('username_field'), "Username field is not present on login_page screen."
        assert login_page.is_element_present('password_field'), "Password field is not present on login_page screen."
        assert login_page.is_element_present('sign_in_button'), "Sign-in button is not present on login_page screen."
        assert login_page.is_element_present('nessus_logo'), "Nessus logo is not present on login_page screen."

        login_page.login_with_defaults()
        header_base_page = HeaderBasePage()
        assert invisibility_of_element_located(
            header_base_page.feed_status_banner), 'Feed error banner is visible. Backup and Restore failed'

    @pytest.mark.xray(test_key='NES-14046')
    @pytest.mark.usefixtures('delete_all_scans_in_nessus')
    def test_empty_scan_list_on_main_page(self):
        """
        NES-14046 : Verify empty scan lists on page
        """
        scans_view_page = ScanViewPage()
        scan_list = ScanList()

        # verify there is no scan created
        assert len(scan_list.get_all_scans()) == 0, "Scan list is not empty"

        # verify empty scan message visible with Create link
        assert scans_view_page.empty_result.text == Messages.NotificationMessages.Scans.empty_scan_page_message, "Enpty scans message with Create link is not visible"


@pytest.mark.scans_2
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login', 'delete_all_scans_in_nessus', 'login', 'create_scans')
class TestForceStopButtonOnScansMainPage:
    cat = None

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         "target_ip": "172.26.48.0/24"}]}], indirect=True)
    @pytest.mark.parametrize("force_stop_scan_status", [API.Scan.Status.RUNNING, API.Scan.Status.PAUSED])
    def test_force_stop_action_for_local_scan(self, create_scans, force_stop_scan_status):
        """
        NES-11151: UI tests for force stop scans

        Scenario Tested:
            [x] Verify "Force stop" button appears after stopping the local scan.

        Steps:
        1. Create scan using local scanner.
        2. Stop scan from running/paused state.
        3. Verify that "Force stop" icon appears for the scan.
        4. Click on "Force stop" button
        5. Verify that scan gets cancelled within 10 seconds.
        """
        scans_page = ScansPage()
        wait(lambda: scans_page.is_element_present("scan_searchbox", timeout=TIME_THREE_SECONDS))

        scan_id = get_scan_id(api_object=self.cat.api, scan_name=create_scans[0])
        self.cat.api.scans.launch(scan_id=scan_id)
        wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.RUNNING,
                        timeout=TIME_FIVE_MINUTES)
        sleep(TIME_THREE_SECONDS, reason="Nessus UI to be in sync with API calls.")

        if force_stop_scan_status == API.Scan.Status.PAUSED:
            self.cat.api.scans.pause(scan_id)
            wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.PAUSED,
                            timeout=TIME_FIVE_MINUTES)
            sleep(TIME_THREE_SECONDS, reason="Nessus UI to be in sync with API calls.")

        self.cat.api.scans.stop(scan_id)

        scan_force_stop_element = scans_page.get_scan_force_stop_element(scan_name=create_scans[0])

        # Verify that "Force Stop" button appears for stopped scan.
        try:
            wait(lambda: scan_force_stop_element.is_displayed(), sleep_seconds=WAIT_SHORT,
                 waiting_for="'Force stop' element to get appeared on UI.")
        except TimeoutExpired:
            raise AssertionError("'Force stop' element is not present on UI after stopping the scan.")

        scan_force_stop_element.click()

        # Verify that scan gets cancelled within 10 seconds after clicking on "Force Stop".
        try:
            wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.CANCELED,
                            timeout=TIME_TEN_SECONDS * 2)
        except TimeoutExpired:
            raise AssertionError("Scan does not gets cancelled within 10 seconds after force stop.")


@pytest.mark.scans_2
@pytest.mark.real_agent
@pytest.mark.usefixtures('nessus_api_login', 'delete_all_scans_in_nessus', 'login', 'create_scans')
class TestForceStopButtonOnScansWithAgent:
    cat = None

    @pytest.mark.parametrize('create_scans', [
        {'scans_details': [{
            'scan_template': Nessus.TemplateNames.ADVANCED_AGENT, 'scan_type': Nessus.Scan.ScanTemplateTabs.AGENT_TAB,
            'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.ADVANCED_AGENT)),
            'description': 'Created a {} for force stop.'.format(Nessus.TemplateNames.ADVANCED_AGENT.lower()),
            'add_configuration': True}]}], indirect=True)
    def test_invisibility_of_force_stop_action_for_agent_scan(self, create_agent_group_with_real_agent, create_scans):
        """
        NES-11151: UI tests for force stop scans

        Scenario Tested:
            [x] Verify "Force stop" button does not appear for agent scan.

        Steps:
        1. Create scan using local scanner and launch scan.
        2. Stop scan from running state.
        3. Verify that "Force stop" icon does not appear for the scan.
        """
        agent_group_name = create_agent_group_with_real_agent['agent_group_name']
        new_scan = NewScanForm()
        new_scan.fill_new_scan_detail(agent_group=agent_group_name)
        new_scan.save_button.click()

        scans_page = ScansPage()
        wait(lambda: scans_page.is_element_present("scan_searchbox", timeout=TIME_THREE_SECONDS))

        scans_page.launch_scan(scan_list=[create_scans[0]])
        scan_running_element = scans_page.get_scan_status(scan_name=create_scans[0],
                                                          scan_status=API.Scan.Status.RUNNING)
        wait(lambda: visibility_of_element_located((scan_running_element.by, scan_running_element.f_value))(
            get_driver_no_init()), timeout_seconds=TIME_FIVE_MINUTES,
             waiting_for="Waiting for scan to be in Running status")

        scans_page.stop_scan(scan_list=[create_scans[0]])
        scan_force_stop_element = scans_page.get_scan_force_stop_element(scan_name=create_scans[0])

        # Verify that "Force Stop" button does not appear for agent scan.
        assert invisibility_of_element_located((scan_force_stop_element.by, scan_force_stop_element.f_value))(
            get_driver_no_init()), "Force stop button appears for agent scan."
