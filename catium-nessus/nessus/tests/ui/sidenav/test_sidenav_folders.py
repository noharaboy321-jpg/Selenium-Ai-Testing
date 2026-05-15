"""
Nessus Folders related test cases

:copyright: Tenable Network Security, 2017
:date: February 27, 2018
:last_modified: July 28, 2020
:author: @rdutta, @ntarwani, @kpanchal, @sacharya.ctr
"""

import pytest
from selenium.webdriver.support.expected_conditions import invisibility_of_element_located, \
    visibility_of_element_located
from waiting import TimeoutExpired

from catium.helpers.sleep_lib import sleep
from catium.lib.util import random_name
from catium.lib.webium.wait import wait
from nessus.helpers.scan import scan_save_launch_and_status_verification
from nessus.helpers.system import is_home, get_nessus_type_using_api
from nessus.lib.const import Nessus, API
from nessus.lib.message.messages import Messages
from nessus.pageobjects.about.about_page import OverView, About
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.scans.scan_trash_page import ScansTrashPage
from nessus.pageobjects.scans.scan_view_page import ScanViewPage, ScanHistoryList
from nessus.pageobjects.scans.scans_page import ScansPage, ScanList, ScanFolderNameModalWindow
from nessus.pageobjects.sidenav.sidenav import SideNav


@pytest.mark.nessus_settings_2
@pytest.mark.nessus_legacy
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login', 'nessus_api_login')
class TestSideNavFolders:
    """
    Covers Side Navigation Folders related test cases.
    NQA-1068 : automation test for Scans - Folder
    """
    cat = None

    @staticmethod
    def go_to_scan_more_options(scan_name: str) -> None:
        """
        Select scan of specified name and click on 'More' button

        :param str scan_name: Scan name 
        :return: None
        """
        scan_page = ScansPage()
        scan_list = ScanList()

        scan_list.select_scans(scans_list=[scan_name])
        scan_page.js_scroll_into_view(scan_page.more_button)
        scan_page.more_button.click()

    @pytest.mark.ie
    def test_default_folder_available(self):
        """
        NQA-1068 : automation test for Scans - Folder
        1. Navigate to Scans Page
        2. Verify by default "My Scans", "All Scans", "Trash" folder is present
        """
        side_nav = SideNav()

        assert all([side_nav.get_sidenav_element(Nessus.Scan.Folder.MY_SCANS).is_displayed(),
                    side_nav.get_sidenav_element(Nessus.Scan.Folder.ALL_SCANS).is_displayed(),
                    side_nav.get_sidenav_element(Nessus.Scan.Folder.TRASH).is_displayed()]), \
            "Default folders are not present"

    @pytest.mark.parametrize('folder', [Nessus.Scan.Folder.MY_SCANS.split(' (')[0], Nessus.Scan.Folder.TRASH,
                                        Nessus.Scan.Folder.ALL_SCANS])
    def test_same_name_folder_error(self, folder):
        """
        NQA-1068 : automation test for Scans - Folder
        1. Navigate to Scans Page
        2. Create a new folder with name "My Scans"
        3. Verify that error notification should be displayed
        4. Repeat above steps with name "All Scans" and "Trash"
        """
        ScansPage().create_new_folder(folder)

        assert Notifications().errors[-1] == Messages.NotificationMessages.SideNavFolders.invalid_name_error, \
            "Error notification for duplicate name is missing"

        assert SideNav().get_all_sidenav_folders_name().count(folder) == 1, "Another folder with default name is " \
                                                                            "created"

        ScanFolderNameModalWindow().cancel_button.click()

    def test_blank_folder_name(self):
        """
        NQA-1068 : automation test for Scans - Folder
        1. Navigate to Scans Page
        2. Create a new folder with blank name
        3. Verify that error notification should be displayed
        """
        ScansPage().create_new_folder('')

        assert Notifications().errors[-1] == Messages.NotificationMessages.continue_button_code, \
            "Error notification for blank name is missing"

        ScanFolderNameModalWindow().cancel_button.click()

    @pytest.mark.ie
    def test_cancel_new_folder_creation(self):
        """
        NQA-1068 : automation test for Scans - Folder
        1. Navigate to Scans Page
        2. Click New Folder
        3. Enter name and click cancel button
        4. Verify the folder is not created
        """
        ScansPage().new_folder_button.click()
        new_folder_name = random_name(prefix='Ui-Auto-')
        new_folder_modal = ScanFolderNameModalWindow()
        new_folder_modal.name_field.value = new_folder_name
        new_folder_modal.cancel_button.click()

        assert new_folder_name not in SideNav().get_all_sidenav_folders_name(), \
            "Cancel button does not work as expected"

    @pytest.mark.ie
    def test_length_of_name_field(self):
        """
        NQA-1068 : automation test for Scans - Folder
        1. Navigate to Scans Page
        2. Click New Folder
        3. Verify the name field does not accept more than 20 characters
        """
        ScansPage().new_folder_button.click()
        folder_modal_window = ScanFolderNameModalWindow()
        folder_modal_window.name_field.value = 'thisismorethan20charstring'

        assert len(ScanFolderNameModalWindow().name_field.value) <= 20, \
            "Length of name field must be less than or equal to 20"

        folder_modal_window.cancel_button.click()

    def test_create_new_custom_folder(self):
        """
        NQA-1068 : automation test for Scans - Folder
        1. Navigate to Scans Page
        2. Create new folder
        3. Verify the folder is created
        """
        new_folder_name = random_name(prefix='Ui-Auto-')
        ScansPage().create_new_folder(new_folder_name)

        assert Notifications().successes[-1] == Messages.NotificationMessages.SideNavFolders.folder_added, \
            "Success notification is missing"

        assert new_folder_name in SideNav().get_all_sidenav_folders_name(), "Folder is not created"

        # delete the newly created folder
        SideNav().delete_custom_folder(new_folder_name)
        ActionCloseModal().wait_for_modal_closed()

    @pytest.mark.usefixtures('create_new_folder')
    def test_create_duplicate_custom_folder(self, create_new_folder):
        """
        NQA-1068 : automation test for Scans - Folder
        1. Navigate to Scans Page
        2. Create new folder
        3. Verify the folder is created
        4. Create another folder with same name
        5. Verify error notification occurs
        """
        ScansPage().create_new_folder(create_new_folder[1])

        assert Notifications().errors[-1] == Messages.NotificationMessages.SideNavFolders.duplicate_folder_error, \
            "Error notification for duplicate name is missing"

        ScanFolderNameModalWindow().cancel_button.click()

    @pytest.mark.parametrize('folder', [Nessus.Scan.Folder.MY_SCANS, Nessus.Scan.Folder.TRASH,
                                        Nessus.Scan.Folder.ALL_SCANS])
    @pytest.mark.usefixtures('create_new_folder')
    def test_rename_custom_folder_to_default_name(self, create_new_folder, folder):
        """
        NQA-1068 : automation test for Scans - Folder
        1. Navigate to Scans Page
        2. Create new folder
        3. Rename the new folder to My Scans
        4. Verify error notification appears
        5. Repeat steps with All Scans and Trash
        """
        SideNav().rename_custom_folder(current_folder_name=create_new_folder[1], new_folder_name=folder)

        assert Notifications().errors[-1] == Messages.NotificationMessages.SideNavFolders.invalid_name_error, \
            "Error notification for duplicate name is missing"

        ScanFolderNameModalWindow().cancel_button.click()

    @pytest.mark.usefixtures('create_new_folder')
    def test_rename_custom_folder(self, create_new_folder):
        """
        NQA-1068 : automation test for Scans - Folder
        1. Navigate to Scans Page
        2. Create new folder
        3. Rename the new folder to some other name
        4. Verify success notification
        5. verify the name is changed
        """
        new_folder_name = random_name(prefix='Ui-Auto-')
        side_nav = SideNav()
        side_nav.rename_custom_folder(current_folder_name=create_new_folder[1], new_folder_name=new_folder_name)

        assert Notifications().successes[-1] == Messages.NotificationMessages.SideNavFolders.folder_updated, \
            "Success notification is missing"

        assert new_folder_name in side_nav.get_all_sidenav_folders_name(), \
            "Folder with new name does not exist in list"

    @pytest.mark.usefixtures('create_new_folder')
    def test_create_scan_in_custom_folder(self, create_new_folder):
        """
        NQA-1068 : automation test for Scans - Folder
        1. Navigate to Scans Page
        2. Create new folder
        3. Create a new scan and select new folder under folder dropdown
        4. Verify newly created scan in the folder specified
        """
        scan_name = random_name(prefix="AdvancedScan" + "-")
        scan_folder = create_new_folder[1]

        ScansPage().create_new_scan(scan_name=scan_name, scan_template=Nessus.TemplateNames.ADVANCED,
                                    scan_type=Nessus.Scan.ScanTemplateTabs.SCANNER_TAB, folder=scan_folder,
                                    target_ip=(Nessus.Scan.Target.LOCALHOST + "," +
                                               Nessus.Scan.Target.AWS_LINUX_TARGET_1))

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            "Scan not created successfully"

        SideNav().get_sidenav_element(element_name=scan_folder).click()

        assert scan_name in ScanList().get_all_scans(), "Scan does not exist in new folder"

    @pytest.mark.usefixtures('create_new_folder')
    def test_delete_custom_folder(self, create_new_folder):
        """
        NQA-1068 : automation test for Scans - Folder
        1. Navigate to Scans Page
        2. Create new folder
        3. Create a new scan and select new folder under folder dropdown
        4. Delete the folder
        5. verify folder is deleted and scan in the folder is moved to trash
        """
        scan_name = random_name(prefix="AdvancedScan" + "-")
        scan_folder = create_new_folder[1]

        ScansPage().create_new_scan(scan_name=scan_name, scan_template=Nessus.TemplateNames.ADVANCED,
                                    scan_type=Nessus.Scan.ScanTemplateTabs.SCANNER_TAB, folder=scan_folder,
                                    target_ip=(Nessus.Scan.Target.LOCALHOST + "," +
                                               Nessus.Scan.Target.AWS_LINUX_TARGET_1))

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            "Scan not created successfully"

        side_nav = SideNav()
        side_nav.delete_custom_folder(folder_name=scan_folder)
        ActionCloseModal().wait_for_modal_closed()

        assert scan_folder not in side_nav.get_all_sidenav_folders_name(), "Scan not present in the desired folder"

        side_nav.get_sidenav_element(element_name=Nessus.Scan.Folder.TRASH).click()

        assert scan_name in ScanList().get_all_scans(), "Scan is not moved to trash"

    @pytest.mark.usefixtures('create_new_folder')
    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.WANNACRY, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.WANNACRY)),
         'target_ip': Nessus.Scan.Target.LOCALHOST, 'keep_original_scan_name': True}]}], indirect=True)
    def test_move_scan_to_another_folder(self, create_new_folder, create_scans):
        """
        NQA-1068 : automation test for Scans - Folder
        1. Create scan and folder
        2. Select your scan
        3. Move scan to the new folder you created
        4. Navigate to the new folder and verify your scan is present
        """
        scan_name = create_scans[0]
        scan_folder = create_new_folder[1]

        scan_page = ScansPage()
        scan_page.move_scan_to_selected_folder(scan_list=[scan_name], folder_name=scan_folder)

        assert Notifications().successes[-1] == Messages.NotificationMessages.Scans.scan_moved, \
            "Success notification for scan moved is missing"

        SideNav().get_sidenav_element(element_name=scan_folder).click()

        assert scan_name in ScanList().get_all_scans(), "Move failed: Scan did not move to the selected folder"

    @pytest.mark.usefixtures('create_new_folder')
    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.WANNACRY, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.WANNACRY)),
         'target_ip': Nessus.Scan.Target.LOCALHOST, 'keep_original_scan_name': True}]}], indirect=True)
    def test_copy_scan_to_another_folder(self, create_new_folder, create_scans):
        """
        NQA-1068 : automation test for Scans - Folder
        1. Create scan and folder
        2. Select your scan
        3. Copy scan to the new folder you created
        4. Navigate to the new folder and verify your scan is present
        """
        scan_name = create_scans[0]
        scan_folder = create_new_folder[1]

        scan_page = ScansPage()
        scan_page.copy_scan_to_selected_folder(scan_list=[scan_name], copied_scan_name=scan_name,
                                               folder_name=scan_folder)

        assert Notifications().successes[-1] == Messages.NotificationMessages.Scans.scan_copied, \
            "Success notification for Scan copied is missing"

        side_nav = SideNav()
        side_nav.get_sidenav_element(element_name=scan_folder).click()
        scan_list = ScanList()

        assert scan_name in scan_list.get_all_scans(), "Copy failed: Scan did not get copied to the selected folder"

        # Delete copied scan from the custom folder and trash
        scan_list.delete_scan(scan_name)
        ScansTrashPage().delete_scan_from_trash(scan_name)

        side_nav.get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Agent_Scan.db',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/',
                                                      'password': 'password', "encrypted": True}], indirect=True)
    def test_no_launch_option_for_imported_scan_under_more_menu(self, import_scan_via_api):
        """
        NQA-1068 : automation test for Scans - Folder
        1. Import a scan
        2. Select your scan
        3. Click on more button
        4. Verify launch option is not present for imported scan
        """
        scan_page = ScansPage()
        scan_page.refresh()

        scan_list = ScanList()
        scan_list.select_scans(import_scan_via_api)

        scan_page.js_scroll_into_view(scan_page.more_button)
        scan_page.more_button.click()

        assert not scan_page.is_element_present('launch_option'), "Launch option is present for imported scan"

    @pytest.mark.scanning
    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.WANNACRY, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.WANNACRY)), 'add_configuration': True,
         'target_ip': Nessus.Scan.Target.LOCALHOST, 'keep_original_scan_name': False}]}], indirect=True)
    def test_mark_unread_scan_as_read(self, create_scans):
        """
        NQA-1068 : automation test for Scans - Folder
        1. Create scan
        2. Launch and stop scan to create activity
        3. Select your scan
        4. From more option select Mark Read
        5. Verify Mark Unread is present for the Scan now

        Scenario Tested:
        [x] Verify that Unread scan can be marked as read.
        """
        scan_count_before_read = 0
        scan_name = create_scans[0]
        side_nav = SideNav()

        # Launch created scan and wait for scan to be completed
        assert scan_save_launch_and_status_verification(
            scan_name=scan_name, navigate_to_scan_folder=False, scan_status=API.Scan.Status.COMPLETED), \
            'Scan has not been completed successfully.'

        scan_page = ScansPage()
        scan_list = ScanList()

        # Verify launched scan is displayed as Unread scan after completing
        assert not scan_list.scan_read_status(scan_name=scan_name), 'Scan with completed status is not displayed in ' \
                                                                    '\'Unread\' status.'

        # Verify unread scan count is displayed next to 'My Scans' folder
        assert side_nav.is_element_present('scan_count'), 'Unread scan count is not displayed next to \'My Scans\' ' \
                                                          'folder.'

        # Get the unread scan count if displayed
        if side_nav.is_element_present('scan_count'):
            scan_count_before_read = side_nav.get_unread_scan_count()

        # Select launched scan and click on 'More' options
        self.go_to_scan_more_options(scan_name=scan_name)

        # Verify 'Mark Read' option is displayed and 'Mark Unread' option is not displayed in 'More' options
        assert all([scan_page.is_element_present('read_option'), not scan_page.is_element_present('unread_option')]), \
            '\'Mark Read\' option is not present in \'More\' options for unread scan'

        # Click on 'Mark Read' option from 'More' options
        scan_page.read_option.click()

        try:
            wait(lambda: not side_nav.is_element_present('scan_count') or side_nav.get_unread_scan_count() == (
                    scan_count_before_read - 1), waiting_for="Scan unread count to get decreased by one.")
        except TimeoutExpired:
            raise AssertionError('Unread scan count is not getting updated after read the scan.')

        # Verify scan is displayed as Read scan after clicking on 'Mark Read' option from 'More' options
        assert scan_list.scan_read_status(scan_name=scan_name), \
            'Scan is not displayed in \'Read\' status after clicking on \'Mark Read\' option from \'More\' button.'

    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.WANNACRY, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.WANNACRY)),
         'target_ip': Nessus.Scan.Target.LOCALHOST, 'keep_original_scan_name': True}]}], indirect=True)
    def test_read_and_unread_option_for_scan_not_launched(self, create_scans):
        """
        NQA-1068 : automation test for Scans - Folder
        1. Create scan
        2. Do not launch scan and select scan
        3. Click more button
        4. Verify Mark Read or Mark Unread option is not present
        """
        scan_name = create_scans[0]
        scan_page = ScansPage()
        launch_status = scan_page.get_scan_status(scan_name=scan_name, scan_status=API.Scan.Status.EMPTY)

        assert launch_status.is_displayed(), "Launch status must be empty"

        ScanList().select_scans(scans_list=[scan_name])
        scan_page.js_scroll_into_view(element=scan_page.more_button)
        scan_page.more_button.click()

        assert all([not scan_page.is_element_present('unread_option'),
                    not scan_page.is_element_present('read_option')]), \
            "Mark Read or Mark Unread option is visible for scan not launched yet"

    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.WANNACRY, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.WANNACRY)),
         "target_ip": Nessus.Scan.Target.LOCALHOST},
        {"scan_template": Nessus.TemplateNames.HOST_DISCOVERY, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.HOST_DISCOVERY)),
         "target_ip": Nessus.Scan.Target.LOCALHOST}]}], indirect=True)
    @pytest.mark.parametrize("count", ['single', 'multiple'])
    def test_configure_option_for_selected_scan(self, create_scans, count):
        """
        NQA-1068 : automation test for Scans - Folder
        1. Create scans
        2. Select one scan
        3. Verify configure option is available under More option
        4. Select more than one scan
        5. Verify configure option is not available under More option

        NES-9445: UI Automation: Scans | Verify that configure option should not be visible when multiple scans are
                  selected

        Scenario Tested:
        [x] Verify that 'configure' option should not be visible when multiple scans are selected, Only 'Copy to',
            'Launch', 'Move to' options should display.
        """
        created_scans = create_scans
        scan_to_verify = [created_scans[0]] if count is 'single' else created_scans

        scan_list = ScanList()
        scan_list.select_scans(scans_list=scan_to_verify)

        scan_page = ScansPage()
        scan_page.js_scroll_into_view(element=scan_page.more_button)
        scan_page.more_button.click()

        if count == 'single':
            # Verify 'Configure' option is displayed for single scan
            assert scan_page.is_element_present('configure_option'), \
                "Configure option is not present for single scan selection"
        else:
            # Verify 'Configure' option is not displayed for multiple scans
            assert not scan_page.is_element_present('configure_option'), \
                "Configure option is present for multiple scan selection"

        # Verify 'Copy to', 'Launch' and 'Move to' options are displayed when multiple scans are selected
        assert all([scan_page.copy_option.is_displayed(), scan_page.launch_option.is_displayed(),
                    scan_page.move_option.is_displayed()]), 'This sub options \'Configure/Copy to/Launch/Move\' are ' \
                                                            'visible without expanding \'More\' dropdown.'

    @pytest.mark.scanning
    @pytest.mark.usefixtures('create_new_folder')
    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.WANNACRY, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.WANNACRY)),
         "target_ip": Nessus.Scan.Target.LOCALHOST},
        {"scan_template": Nessus.TemplateNames.HOST_DISCOVERY, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.HOST_DISCOVERY)),
         "target_ip": Nessus.Scan.Target.LOCALHOST}]}], indirect=True)
    @pytest.mark.parametrize('count', ['multiple', 'single'])
    @pytest.mark.parametrize('include_history', [False, True])
    def test_include_exclude_scan_history_while_copy(self, create_new_folder, create_scans, count, include_history):
        """
        NQA-1068 : automation test for Scans - Folder
        1. Create scans and create new folder
        2. Launch and stop scan for creating activity
        3. Select scan/scans
        4. Copy scan(s) to new folder created
        5. Check/Un-check include history
        6. Verify history present or not depending on Include history checkbox value
        """
        created_scans = create_scans
        scan_to_verify = [created_scans[0]] if count == 'single' else created_scans
        scan_folder = create_new_folder[1]

        # Create scan, launch them and wait for their completion
        scan_page = ScansPage()
        scan_list = ScanList()

        for scan in created_scans:
            scan_list.launch_scan_and_wait_for_status(scan_name=scan)

        # Copy scan to selected folder with/without included scan-history
        scan_page.refresh()
        scan_list.loaded()
        scan_page.copy_scan_to_selected_folder(
            scan_list=scan_to_verify, folder_name=scan_folder, include_history=include_history)

        # Navigate to the scan folder and verify copied scan exists with/without scan history
        side_nav = SideNav()
        side_nav.get_sidenav_element(element_name=scan_folder).click()
        scan_list.loaded()

        for scan in scan_to_verify:
            assert "Copy of {}".format(scan) in scan_list.get_all_scans(), \
                'Copied scan does not exists in specified scan folder.'

            scan_list.click_on_scan(scan_name="Copy of {}".format(scan))
            scan_view_page = ScanViewPage()
            wait(lambda: visibility_of_element_located(scan_view_page.history_tab),
                 waiting_for='Scan results page to load')

            scan_view_page.history_tab.click()
            scan_history = ScanHistoryList()

            if include_history:
                assert not scan_history.is_empty(), 'Scan history is empty'
            else:
                assert scan_history.is_empty(), 'Scan history is not empty'

            scan_view_page.back_link.click()
            scan_list.loaded()

        side_nav.delete_custom_folder(folder_name=scan_folder)
        ActionCloseModal().wait_for_modal_closed()

        for scan in scan_list.get_all_scans():
            scan_trash_page = ScansTrashPage()
            scan_trash_page.open()

            scan_list.loaded()
            scan_trash_page.delete_scan_from_trash(scan)

        side_nav.get_sidenav_element(Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.parametrize('characters', ["valid", "invalid"])
    def test_creation_of_folder_with_special_characters(self, characters):
        """
        NQA-1068 : automation test for Scans - Folder
        1. Create new folder with special characters
        2. Verify '-_.' is valid and other characters are invalid
        """
        mapping_element = {"valid": "-_.", "invalid": "!#&"}
        new_folder_name = "special {}".format(mapping_element[characters])

        ScansPage().create_new_folder(new_folder_name)
        side_nav = SideNav()
        notifications = Notifications()

        try:
            if characters == 'valid':
                assert notifications.successes[-1] == Messages.NotificationMessages.SideNavFolders.folder_added, \
                    "Success notification is missing"

                assert new_folder_name in side_nav.get_all_sidenav_folders_name(), "Folder is not created"
            else:
                assert notifications.errors[-1] == Messages.NotificationMessages.SideNavFolders. \
                    invalid_name_error, "Folder created with invalid characters"

                ScanFolderNameModalWindow().cancel_button.click()
        finally:
            if characters == 'valid':
                side_nav.delete_custom_folder(new_folder_name)
                ActionCloseModal().wait_for_modal_closed()

    def test_scan_in_all_scans_and_trash(self):
        """
        NQA-1068 : automation test for Scans - Folder
        1. Create new scan
        2. Go to All Scans
        3. Verify scan is present in All Scans
        4. Move scan to Trash
        5. Verify scan is still present in All Scans
        6. Go to Trash and delete the scan
        7. Verify scan is not present in Trash and All Scans
        """
        scan_name = random_name(prefix="AdvancedScan" + "-")
        scan_page = ScansPage()
        scan_page.create_new_scan(scan_name=scan_name, scan_template=Nessus.TemplateNames.WANNACRY,
                                  scan_type=Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                                  target_ip=Nessus.Scan.Target.LOCALHOST)

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            "Scan not created successfully"

        side_nav = SideNav()
        side_nav.get_sidenav_element(element_name=Nessus.Scan.Folder.ALL_SCANS).click()

        scan_list = ScanList()
        scan_list.js_scroll_to_bottom()
        scan_list.delete_scan("{}\n{}".format(Nessus.Scan.Folder.MY_SCANS.split(' (')[0], scan_name))
        sleep(0.5, reason="let the delete finish before we refresh")
        scan_page.refresh()
        wait(lambda: visibility_of_element_located(scan_page.scan_searchbox), waiting_for='scan page to load')

        assert ("{}\n{}".format(Nessus.Scan.Folder.TRASH, scan_name)) in scan_list.get_all_scans(), \
            "Scan not present in All scans"

        side_nav.get_sidenav_element(element_name=Nessus.Scan.Folder.TRASH).click()
        wait(lambda: visibility_of_element_located(scan_page.scan_searchbox), waiting_for='trash page to load')

        assert scan_name in scan_list.get_all_scans(), "Scan not present in Trash"

        ScansTrashPage().delete_scan_from_trash(scan_name)

        assert scan_name not in scan_list.get_all_scans(), "Scan present in Trash"

        side_nav.get_sidenav_element(element_name=Nessus.Scan.Folder.ALL_SCANS).click()

        assert ("{}\n{}".format(Nessus.Scan.Folder.TRASH, scan_name)) not in scan_list.get_all_scans(), \
            "Scan present in All scans"

    @pytest.mark.parametrize('folder', Nessus.Scan.Folder.DEFAULT_FOLDERS)
    def test_hide_side_nav_folder(self, folder):
        """
        NQA-1068 : automation test for Scans - Folder
        1. Click on Hide link for Folders on side nav
        2. Verify all the folders are hidden
        """
        side_nav = SideNav()
        side_nav.get_hide_show_link(side_nav_option='Folders', side_nav_sub_option=Nessus.Scan.Folder.ALL_SCANS).click()

        assert invisibility_of_element_located(side_nav.get_sidenav_element(element_name=folder)), \
            "Folders are not hidden"

    @pytest.mark.parametrize('folder', Nessus.Scan.Folder.DEFAULT_FOLDERS)
    def test_no_expansion_arrow_for_default_folders(self, folder):
        """
        NQA-1068 : automation test for Scans - Folder
        1. Verify expansion arrow icon, delete folder and rename folder is not visible for Default Folders
        """
        assert invisibility_of_element_located(SideNav().get_custom_folder_expand_icon(folder_name=folder)), \
            "Expansion arrow is present for Default folders"

    @pytest.mark.parametrize('import_scan_via_api', [
        {'file_name': 'Basic_Network_Scan_Result.db', 'file_path': 'nessus/tests/ui/scans/test_data/',
         'password': 'nessus', 'create_folder': True, 'encrypted': True}], indirect=True)
    def test_mark_read_scan_as_unread(self, import_scan_via_api):
        """
        NES-9441: UI Automation: Side nav | Verify that read scan can be marked as unread

        Steps:
        1. Select already read scan
        2. Go to 'More'-> select 'Mark Unread'
        3. Verify the highlighted scan as well as unread scan count next to folder name

        Scenario Tested:
        [x] Verify that read scan can be marked as unread.
        """
        scan_count_before_unread = 0
        imported_scan_name, created_folder_name, created_folder_id = import_scan_via_api

        scan_page = ScansPage()
        scan_page.refresh()
        scan_list = ScanList()
        scan_list.loaded()

        side_nav = SideNav()
        side_nav.get_sidenav_element(element_name=created_folder_name).click()
        scan_list.loaded()

        # Verify imported scan is displayed as Unread scan
        assert not scan_list.scan_read_status(scan_name=imported_scan_name), \
            'Imported scan is not displayed in \'Unread\' status.'

        # Verify unread scan count is displayed next to 'My Scans' folder
        assert side_nav.is_element_present('scan_count', timeout=2), \
            'Unread scan count is not displayed next to \'My Scans\' folder.'

        # Click on imported scan and refresh the scan page
        scan_list.click_on_scan(scan_name=imported_scan_name)
        wait(lambda: ScanViewPage().is_element_present('vulnerability_tab'), waiting_for='scan results to load')

        scan_page.back_link.click()
        scan_page.refresh()
        wait(lambda: visibility_of_element_located(scan_page.scan_searchbox), waiting_for='scan page to load')

        # Get the unread scan count if displayed
        if side_nav.is_element_present('scan_count', timeout=2):
            scan_count_before_unread = side_nav.get_unread_scan_count()

        # Select imported scan and click on 'More' options
        self.go_to_scan_more_options(scan_name=imported_scan_name)

        # Verify 'Mark Unread' option is displayed and 'Mark Read' option is not displayed in 'More' options
        assert all([scan_page.is_element_present('unread_option'), not scan_page.is_element_present('read_option')]), \
            '\'Mark Unread\' option is not present in \'More\' options for read scan.'

        # Click on 'Mark Unread' option from 'More' options
        scan_page.unread_option.click()
        scan_list.loaded()

        # Verify scan is displayed as Unread scan after clicking on 'Mark Unread' option from 'More' options
        assert not scan_list.scan_read_status(scan_name=imported_scan_name), \
            'Scan is not displayed in \'Unread\' status after clicking on \'Mark Unread\' option from \'More\' ' \
            'button.'

        # Verify unread scan count is updated after making scan unread
        if side_nav.is_element_present('scan_count', timeout=2):
            scan_count_after_unread = side_nav.get_unread_scan_count()

            assert all([scan_count_before_unread != scan_count_after_unread,
                        scan_count_after_unread == (scan_count_before_unread + 1)]), \
                'Unread scan count is not getting updated after unread the scan.'

    @pytest.mark.nessus_home
    def test_verify_sidenav_items_collapse_feature_on_main_page(self):
        """
        NES-12474: [UI] Side navigation bar - collapse functionality should work properly

        Steps:
        1. Click on collapse icon at side navigation
        2. Go to each icon on side navigation and verify tooltip text.

        Scenario Tested:
        [x] Verify that all side navigation items can be collapsed and each icon shows proper tooltip to user
        """
        side_nav = SideNav()
        side_nav.collapse_menu_icon.click()
        folder_tooltips = []

        for folder_item in side_nav.folder_items:
            side_nav.move_to_element(element=folder_item)
            folder_tooltips.append(side_nav.tool_tip_element.text)

        # Verify that tooltip for "My Scans" / "All Scans" is available for folders section.
        assert {Nessus.Scan.Folder.ALL_SCANS, Nessus.Scan.Folder.MY_SCANS}.issubset(set(folder_tooltips)), \
            "Tooltips for My scans/All scans folder is not available."

        expected_tooltip = {'scan-policies-item': Nessus.SideNavResources.POLICIES,
                            'plugin-rules-item': Nessus.SideNavResources.PLUGIN_RULES,
                            'bin': Nessus.Scan.Folder.TRASH}

        # Verify that Tooltip is correct for each icon on side navigation.
        for item in expected_tooltip.keys():
            side_nav.move_to_element(element=side_nav.get_sidenav_item(element_name=item))
            assert side_nav.tool_tip_element.text == expected_tooltip.get(item), \
                "Tooltip is incorrect for {}".format(expected_tooltip.get(item))

        # Verify "Customized Report" tooltip for Nessus pro
        if not is_home():
            side_nav.move_to_element(element=side_nav.get_sidenav_item(element_name='custom-reports-item'))
            assert side_nav.tool_tip_element.text == Nessus.SideNavResources.CUSTOMIZED_REPORTS, \
                "Customized report tooltip is not available for user."

    @pytest.mark.xray(test_key='NES-19367')
    @pytest.mark.nessus_home
    def test_resize_sidenav(self):
        """
        NES-19367 : Verify that side navigation bar can be resized and collapsed to expected widths
        """
        side_nav = SideNav()
        side_nav.collapse_menu_icon.click()
        assert side_nav.get_sidenav_width() == Nessus.UI.COLLAPSED_SIDENAV_WIDTH, \
            "Side nav was not collapsed to expected width from default state"
        side_nav.collapse_menu_icon.click()
        assert side_nav.get_sidenav_width() == Nessus.UI.DEFAULT_SIDENAV_WIDTH, \
            "Side nav was not expanded to expected default width"
        side_nav.drag_sidenav(direction="out", amount=Nessus.UI.MAX_SIDENAV_WIDTH)
        resized_side_nav_width = side_nav.get_sidenav_width()
        assert resized_side_nav_width == Nessus.UI.MAX_SIDENAV_WIDTH, \
            "Side nav width is not the expected maximum width after dragging it out"
        side_nav.refresh()
        assert side_nav.get_sidenav_width() == resized_side_nav_width, \
            "Side nav width did not remain the same after refreshing the page"
        side_nav.collapse_menu_icon.click()
        assert side_nav.get_sidenav_width() == Nessus.UI.COLLAPSED_SIDENAV_WIDTH, \
            "Side nav was not collapsed to expected collapsed width"
        side_nav.collapse_menu_icon.click()
        assert side_nav.get_sidenav_width() == Nessus.UI.MAX_SIDENAV_WIDTH, \
            "Side nav was not expanded to expected maximum width from collapsed state"
        side_nav.drag_sidenav(direction="in", amount=Nessus.UI.MAX_SIDENAV_WIDTH - Nessus.UI.COLLAPSED_SIDENAV_WIDTH)
        assert side_nav.get_sidenav_width() == Nessus.UI.MIN_SIDENAV_WIDTH, \
            "Side nav width is not the expected minimum width after dragging it in"


@pytest.mark.nessus_settings_2
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestSideNavManager:
    @pytest.mark.xray(test_key='NES-14374')
    @pytest.mark.xray(test_key='NES-14235')
    def test_verify_sidenav_items_collapse_feature_on_settings_page(self):
        """
        NES-14235 : Verify tool tip for Collapse / Expand when sections under side menu are hidden
        NES-14374 : Verify navigation for all tabs when sidebar is collapsed

        Steps:
        1. Click on collapse icon at side navigation
        2. Go to each icon on side navigation and verify tooltip text.

        Scenario Tested:
        [x] Verify that all side navigation items can be collapsed and each icon shows proper tooltip to user
        """
        about_page = About()
        about_page.open()
        side_nav = SideNav()
        side_nav.collapse_menu_icon.click()
        settings_tooltips = []

        for settings_item in side_nav.sidenav_links:
            side_nav.move_to_element(element=settings_item)
            settings_tooltips.append(side_nav.tool_tip_element.text)

        assert {Nessus.SideNavSettings.ABOUT, Nessus.SideNavSettings.ADVANCED, Nessus.SideNavSettings.CUSTOM_CA,
                Nessus.SideNavSettings.LDAP_SERVER, Nessus.SideNavSettings.NOTIFICATIONS,
                Nessus.SideNavSettings.PASSWORD_MGMT, Nessus.SideNavSettings.PROXY_SERVER}.issubset(
            set(settings_tooltips)), \
            "Tooltips is not available."


@pytest.mark.nessus_settings_2
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
@pytest.mark.usefixtures('login')
class TestSideNavAccounts:
    @pytest.mark.xray(test_key='NES-14480')
    def test_users_and_groups_not_visible_for_pro_home(self):
        """
        NES-14480 : Verify that "Users" or "Groups" tab is not visible for Nessus Pro/Home
        """
        overview_page = OverView()
        overview_page.open()
        sidenav = SideNav()
        all_links = sidenav.get_all_sidenav_links()

        # verify Users and Groups are not in list
        assert not {"Users",
                    "Groups"}.issubset(
            set(all_links)), f"Users/Groups menu is availalbe for {get_nessus_type_using_api()}"
