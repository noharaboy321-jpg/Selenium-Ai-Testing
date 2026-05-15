"""
Nessus Scans Trash related test cases

:copyright: Tenable Network Security, 2017
:date: Feb 27, 2017
:last_modified: May 13, 2021
:author: @jamreliya, @rdutta, @kpanchal
"""

import pytest

from catium.lib.const import WAIT_SHORT, WAIT_NORMAL
from catium.lib.log.log import create_logger
from catium.lib.util import random_name
from catium.lib.webium.wait import wait
from nessus.helpers.scan import empty_trash_folder
from nessus.helpers.sort import sort_on_column_values
from nessus.lib.const import Nessus
from nessus.lib.const.constants import API, SortOrder
from nessus.lib.message.messages import Messages
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.scans.scan_trash_page import ScansTrashPage
from nessus.pageobjects.scans.scan_view_page import ScanViewPage
from nessus.pageobjects.scans.scans_page import ScansPage, ScanList
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav

log = create_logger()


@pytest.mark.nessus_home
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_legacy
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestTrash:
    """Scans Trash Related Test Cases"""

    @pytest.mark.parametrize("create_scan", [{'template_name': Nessus.TemplateNames.BASIC_NETWORK,
                                              'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                                              'host_ip': Nessus.Scan.Target.PUB_TARGET_3}], indirect=True)
    def test_move_scan_to_trash(self, create_scan):
        """
        Move scans to “Trash” folder.
            1.Create and select one/more scan(s).
            2.Click on “More” option in drop-down from header and hover on “Move to”.
            3.It’ll shows a list of available folder (from SideNav), click desired one.
            4.Scan should move to the destination folder with a success notification as “Scan moved successfully.”
            5.Verify scan is not present in the folder.
            6.Scan should listed in “Trash”.
        """
        scan_name = create_scan
        ScansPage().save_button.click()

        empty_trash_folder()

        HeaderBasePage().clear_notification_history()
        ScansPage().move_scan_to_selected_folder(scan_list=[scan_name], folder_name=Nessus.Scan.Folder.TRASH)

        assert Notifications().successes[-1] == Messages.NotificationMessages.scan_move_to_trash, \
            "Success notifications for scan moved to selected folder is mismatched or missing."

        scan_list = ScanList()
        scan_list.loaded()
        assert scan_name not in scan_list.get_all_scans(), 'Scan not moved to Trash.'

        # open scan and verify scan present in Trash
        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.TRASH).click()
        LoadingCircle(WAIT_SHORT)
        assert scan_name in scan_list.get_all_scans(), 'Scan not found in Trash.'
        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.parametrize('folder_name', ['existing_folder', 'new_folder'])
    @pytest.mark.parametrize("create_scan", [{'template_name': Nessus.TemplateNames.BASIC_NETWORK,
                                              'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                                              'host_ip': Nessus.Scan.Target.PUB_TARGET_3}], indirect=True)
    def test_move_scan_from_trash(self, create_scan, folder_name):
        """
        Move scans from “Trash” folder.
            1.Select one/more scan(s) from “Trash” folder.
            2.Click on “More” option in drop-down from header and hover on “Move to”.
            3.It’ll show a list of available folder (from SideNav), click desired one.
            4.Scan should move to the destination folder with a success notification as “Scan moved successfully.”
            5.Scan should not listed in “Trash” anymore.
            6.Repeat above steps for “new folder” also.

        :param create_scan: create_scan fixture that create scan and do cleanup at end of the test
        :param folder_name: create folder
        """
        scan_name = create_scan
        scan_page = ScansPage()
        scan_page.save_button.click()

        notification = Notifications()

        mapping_folder = {"existing_folder": Nessus.Scan.Folder.MY_SCANS,
                          "new_folder": (random_name(prefix='folder'))[:20]}
        mapped_folder = mapping_folder[folder_name]

        # move scan to Trash
        empty_trash_folder()
        scan_list = ScanList()
        scan_list.delete_scan(scan_name=scan_name)

        ScansTrashPage().open()
        scan_list.loaded()

        if folder_name == "new_folder":
            scan_page.move_scan_to_selected_folder(scan_list=[scan_name], new_folder=True,
                                                   folder_name=mapped_folder.split(' (')[0])
        else:
            scan_page.move_scan_to_selected_folder(scan_list=[scan_name], folder_name=mapped_folder.split(' (')[0])

        if folder_name == "existing_folder":
            assert notification.successes[-1] == Messages.NotificationMessages.Scans.scan_moved, \
                "Success notifications for scan moved to selected folder is mismatched or missing."
        else:
            assert notification.successes[-1] == Messages.NotificationMessages.SideNavFolders.folder_added, \
                "Success notifications for scan moved to new folder is mismatched or missing."

        side_nav = SideNav()
        side_nav.get_sidenav_element(element_name=mapped_folder).click()
        scan_list.loaded()

        assert scan_name in scan_list.get_all_scans(), 'Scan \'{}\' not found in \'{}\'.'.format(
            scan_name, mapped_folder)

        if folder_name == 'new_folder':
            side_nav.delete_custom_folder(folder_name=mapped_folder)
            ActionCloseModal().wait_for_modal_closed()

    @pytest.mark.scanning
    @pytest.mark.parametrize("create_scan", [{'template_name': Nessus.TemplateNames.BASIC_NETWORK,
                                              'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                                              'host_ip': Nessus.Scan.Target.PUB_TARGET_3}], indirect=True)
    def test_read_unread_scan_from_trash(self, create_scan):
        """
        Mark scan(s) as read/unread listed in trash.
            1.Select one/more scan(s) from “Trash”.
            2.Click on “More” option in drop-down from header.
            3.Click on “Mark Read”/”Mark Unread” option, this status is depending upon your current status.
            4.An unread scan will visible in bold.
        """
        scan_name = create_scan
        scan_page = ScansPage()
        scan_page.save_button.click()
        LoadingCircle(WAIT_SHORT)

        # create and launch scan and wait for completion
        scan_list = ScanList()
        assert scan_list.launch_scan_and_wait_for_status(scan_name=scan_name, status=API.Scan.Status.COMPLETED), \
            'Scan has not been completed successfully.'

        scan_list.delete_scan(scan_name=scan_name)
        LoadingCircle(WAIT_SHORT)

        scan_page = ScansPage()
        trash_page = ScansTrashPage()
        trash_page.open()

        for option in ['read', 'unread']:
            scan_list.select_scans(scans_list=[scan_name])
            scan_page.js_scroll_into_view(scan_page.more_button)
            scan_page.more_button.click()

            if option == 'read':
                assert scan_page.read_option.is_displayed(), '\'Mark Read\' option is not present in \'More\' option.'

                assert not scan_list.scan_read_status(scan_name=scan_name), 'Scan is in read state.'

                scan_page.read_option.click()
                LoadingCircle(WAIT_SHORT)

                assert scan_list.scan_read_status(scan_name=scan_name), 'Scan is in unread state.'
            else:
                assert scan_page.unread_option.is_displayed(), '\'Mark Unread\' option is not present in \'More\' ' \
                                                               'option.'

                assert scan_list.scan_read_status(scan_name=scan_name), 'Scan is in unread state.'

                scan_page.unread_option.click()
                LoadingCircle(WAIT_SHORT)

                assert not scan_list.scan_read_status(scan_name=scan_name), 'Scan is in read state.'

    @pytest.mark.parametrize("create_scan", [{'template_name': Nessus.TemplateNames.ADVANCED,
                                              'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                                              'host_ip': Nessus.Scan.Target.PUB_TARGET_1}], indirect=True)
    def test_visibility_of_more_button(self, create_scan):
        """
        Verify “More” button in invisible when list is empty or none of scan selected.
            1.Navigate to “Trash” folder.
            2.Verify list is empty and there shouldn’t any “More” button available.
            3.Move some scan in trash folder.
            4.Checked the checkbox of one/more scan, verify “More” button is visible and “Empty Trash” button should
            invisible.
            5.Unchecked them again verify “More” button is invisible and “Empty Trash” button should visible.
        """
        scan_name = create_scan
        ScansPage().save_button.click()
        LoadingCircle(WAIT_SHORT)

        trash_page = ScansTrashPage()
        trash_page.open()
        scan_list = ScanList()
        if len(scan_list.get_all_scans()):
            log.info('Trash list is not empty. Removing Scan from Trash')
            trash_page.empty_trash_button.click()
            actionclosemodal = ActionCloseModal()
            actionclosemodal.action_button.click()
            actionclosemodal.wait_for_modal_closed()

        assert not trash_page.is_element_present('more_button'), 'More button is visible though trash list is empty'

        # move scan to trash
        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()
        scan_list.delete_scan(scan_name=scan_name)

        # check more button is visible
        trash_page.open()
        LoadingCircle(WAIT_NORMAL)
        scan_list.select_scans(scans_list=[scan_name])
        LoadingCircle(WAIT_SHORT)
        trash_page.js_scroll_into_view(element=trash_page.more_button)
        assert all([trash_page.is_element_present('more_button'),
                    (not trash_page.is_element_present('empty_trash_button'))]), \
            "'More' button is not visible and 'Empty Trash' button is visible"

        # check Empty Trash button is visible
        scan_list.unselect_scans(scans_list=[scan_name])
        LoadingCircle(WAIT_SHORT)
        trash_page.js_scroll_into_view(element=trash_page.empty_trash_button)
        assert all([(not trash_page.is_element_present('more_button')),
                    trash_page.is_element_present('empty_trash_button')]), \
            "'More' button is visible and 'Empty Trash' button is not visible"

        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": API.Permissions.Types.SCANNER,
         "scan_name": random_name(prefix=Nessus.TemplateNames.ADVANCED),
         "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1}]}], indirect=True)
    @pytest.mark.usefixtures('delete_all_scans_in_nessus')
    def test_visibility_of_clear_selected_link(self, create_scans):
        """
        Verify “Clear Selected Items” link in trash.
            1.Move some scans to “Trash” folder.
            2.Navigate to “Trash” folder.
            3.“Clear Selected Items” should be invisible.
            4.Checked the checkbox of some scans among them.
            5.“Clear Selected Items” should be visible now, click on link.
            6.Verify checked scans become Unchecked.
        """
        created_scan = create_scans
        scan_list = ScanList()
        for scan in created_scan[::-1]:
            scan_list.delete_scan(scan_name=scan)

        trash_page = ScansTrashPage()
        trash_page.open()
        assert not trash_page.is_element_present('clear_selected_item_link'), \
            '"Clear Selected item" link is visible though scan is not selected'

        scan_list.select_scans(scans_list=created_scan)
        LoadingCircle(WAIT_SHORT)
        assert trash_page.is_element_present('clear_selected_item_link'), \
            "'Clear selected item' link is not visible though scan is selected"
        trash_page.clear_selected_item_link.click()
        LoadingCircle(WAIT_SHORT)
        assert not scan_list.is_scan_selected(scans_list=created_scan), 'one or more scans are still selected'

        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": API.Permissions.Types.SCANNER,
         "scan_name": random_name(prefix=Nessus.TemplateNames.ADVANCED),
         "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1},
        {"scan_template": Nessus.TemplateNames.BASIC_NETWORK, "scan_type": API.Permissions.Types.SCANNER,
         "scan_name": random_name(prefix=Nessus.TemplateNames.BASIC_NETWORK),
         "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1},
        {"scan_template": Nessus.TemplateNames.WANNACRY, "scan_type": API.Permissions.Types.SCANNER,
         "scan_name": random_name(prefix=Nessus.TemplateNames.WANNACRY),
         "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1}]}], indirect=True)
    def test_verify_search_scan(self, create_scans):
        """
        Search scan(s) under listed scans of “Trash” folder.
            1.Navigate to Trash folder.
            2.Verify “search_icon” is visible in search box.
            3.Enter some string or sub-string that relates to your search in the search box.
            4.Verify “remove icon” is visible and “search_icon” is invisible.
            5.The list should filter out with provided search string and verify filtered list contains your search
              string.
            6.Remove the search and verify “search_icon” is visible again under search box.
        """
        created_scan = create_scans
        scan_list = ScanList()
        for scan in created_scan[::-1]:
            scan_list.delete_scan(scan_name=scan)

        trash_page = ScansTrashPage()
        trash_page.open()
        assert trash_page.search_icon.is_displayed(), 'Search icon is not visible'

        trash_page.apply_search_on_scans(search_string=Nessus.TemplateNames.ADVANCED)
        LoadingCircle(WAIT_SHORT)
        assert not trash_page.search_icon.is_displayed(), 'Search icon is still visible'
        assert trash_page.clear_search_icon.is_displayed(), 'Clear search icon is not visible'

        assert trash_page.verify_search_result(search_string=Nessus.TemplateNames.ADVANCED), \
            "Search failed with provided search string."

        trash_page.clear_search_icon.click()
        LoadingCircle(WAIT_SHORT)
        assert trash_page.search_icon.is_displayed(), 'Search icon is not visible'
        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.parametrize("sort", SortOrder.VALID_ORDERS)
    @pytest.mark.parametrize("column_to_sort", ["Name", "Schedule", "Last Scanned"])
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1}]}], indirect=True)
    def test_sort_scan_list_column_values(self, create_scans, sort, column_to_sort):
        """
        Test to sort list column values
            1. Navigate to "Scans" page and create and import some scans
            2. Click on 'sort' icon on last modified column and verify list should be present in sorted order..
            3. Repeat above for "Name" and "Schedule" column.
        """
        empty_trash_folder()

        created_scan = create_scans
        scans_list = ScanList()
        scans_list.loaded()

        for scan in created_scan[::-1]:
            scans_list.delete_scan(scan_name=scan)

        trash_page = ScansTrashPage()
        trash_page.open()

        column_mapping = {"Name": "scan_name", "Schedule": "scan_schedule", "Last Scanned": "scan_last_scanned_epoch"}
        map_attribute = column_mapping[column_to_sort]

        expected_scans_list = sorted([getattr(scan, map_attribute) for scan in scans_list.rows],
                                     key=lambda k: k.lower(), reverse=(sort == SortOrder.DESCENDING))

        rendered_scans_list = sort_on_column_values(page_class_instance=scans_list, sort=sort,
                                                    column_name=column_to_sort)
        assert expected_scans_list == [getattr(scan, map_attribute) for scan in rendered_scans_list], \
            "{} is not sorted in {} order".format(column_to_sort, sort)

        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.parametrize("create_scan", [{'template_name': Nessus.TemplateNames.ADVANCED,
                                              'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB}], indirect=True)
    def test_delete_scan(self, create_scan):
        """
        Delete a scan from “Trash” folders using “X” icon.
        1.Click on the ‘x’ icon of any scan listed in “Trash” folder.
        2.Click on “Delete” button on confirmation pop-up.
        3.Scan should delete with a success notification “Scan deleted successfully.”
        4.Verify that scan is not listed in “Trash” anymore.

        NES-9449: UI Automation: Sidenav | Verify that scan can be permanently deleted by clicking 'x' (Delete) button
                  from Trash folder

        Scenario Tested:
        [x] Verify that scan can be permanently deleted by clicking 'x' (Delete) button from Trash folder.
        """
        scan_name = create_scan
        ScansPage().save_button.click()

        notifications = Notifications()
        wait(lambda: notifications.successes, waiting_for='Notification list to populate.')

        # move scan to trash
        scan_list = ScanList()
        scan_list.delete_scan(scan_name=scan_name)
        wait(lambda: notifications.successes, waiting_for='Notification list to populate.')

        assert scan_name not in scan_list.get_all_scans(), "Scan not moved to trash folder"

        ScansTrashPage().open()
        scan_list.loaded()

        assert scan_name in scan_list.get_all_scans(), "Moved scan is not present in trash"

        scan = [scan for scan in scan_list.rows if scan.name.text == scan_name]
        scan[0].delete_button.click()
        modal_window = ActionCloseModal()

        assert modal_window.modal_content.text == "Are you sure you want to delete this scan? Once deleted," \
                                                  " it cannot be recovered."

        modal_window.action_button.click()
        modal_window.wait_for_modal_closed()

        assert scan_name not in scan_list.get_all_scans(), "Created scan is not deleted."

        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.parametrize("create_scan", [{'template_name': Nessus.TemplateNames.ADVANCED,
                                              'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB}], indirect=True)
    def test_delete_scan_from_more(self, create_scan):
        """
        Delete a scan(s) from “Trash” folder.
            1.Select one/more scan(s) listed in “Trash” folder.
            2.Click on “More” drop-down from header and click on “Delete”.
            3.Click on “Delete” button on confirmation pop-up.
            4.Scan should delete with a success notification as “Scan deleted successfully.”
            5.Scan should not listed in “Trash” anymore
        """
        scan_name = create_scan
        ScansPage().save_button.click()
        LoadingCircle(WAIT_NORMAL)

        # move scan to trash
        scan_list = ScanList()
        scan_list.delete_scan(scan_name=scan_name)

        trash_page = ScansTrashPage()
        trash_page.open()
        LoadingCircle(WAIT_SHORT)

        scan_list.select_scans(scans_list=[scan_name])
        trash_page.js_scroll_into_view(trash_page.more_button)
        trash_page.more_button.click()
        trash_page.delete_button.click()

        actionclosemodal = ActionCloseModal()
        assert actionclosemodal.modal.is_displayed(), "Confirmation pop up is not displayed for delete"
        actionclosemodal.accept_action()
        LoadingCircle(WAIT_SHORT)
        assert scan_name not in scan_list.get_all_scans(), "Scan not deleted from trash"

        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1}]}], indirect=True)
    def test_empty_trash(self, create_scans):
        """
        Empty “Trash” folder.
            1.Navigate to “Trash” folder.
            2.Click on “Empty Trash” button.
            3.Click on “Delete” button on confirmation pop-up.
            4.Scan(s) should delete with a success notification as “Scans deleted successfully.”
            5.“Trash” list should empty.
        """
        created_scan = create_scans
        wait(lambda: ScansPage().is_element_present("scan_searchbox"))

        # move scans to trash
        scan_list = ScanList()

        for scan in created_scan[::-1]:
            scan_list.delete_scan(scan_name=scan)
            wait(lambda: scan not in scan_list.get_all_scans())

        # open trash page
        trash_page = ScansTrashPage()
        trash_page.open()
        wait(lambda: trash_page.is_element_present("scan_searchbox"))

        # remove notification
        header_page = HeaderBasePage()
        header_page.clear_notification_history()
        wait(lambda: not header_page.is_element_present("clear_notification"))

        is_multiple_scans = len(scan_list.get_all_scans()) > 1
        trash_page.js_scroll_into_view(element=trash_page.empty_trash_button)
        trash_page.empty_trash_button.click()

        action_close_modal = ActionCloseModal()
        action_close_modal.accept_action()
        action_close_modal.wait_for_modal_closed()

        expected_notification = Messages.NotificationMessages.Scans.scans_deleted if is_multiple_scans else \
            Messages.NotificationMessages.delete_scan

        assert Notifications().successes[-1] == expected_notification, \
            "Success notifications for deletion of scan is mismatched or missing."

        assert len(scan_list.get_all_scans()) == 0, "Trash is not empty"

        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": API.Permissions.Types.SCANNER,
         "scan_name": random_name(prefix=Nessus.TemplateNames.ADVANCED),
         "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1},
        {"scan_template": Nessus.TemplateNames.BASIC_NETWORK, "scan_type": API.Permissions.Types.SCANNER,
         "scan_name": random_name(prefix=Nessus.TemplateNames.BASIC_NETWORK),
         "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1}]}], indirect=True)
    def test_empty_trash_button_on_trash_page(self, create_scans, create_new_folder):
        """
        NES-11350 : UI automation for NES-10809 (Scans > Trash | After moving one or more scans from trash to
                    any folder, and clicking on Empty trash button from trash,
                    the scans which are moved to another folder also deleted)
        Scenario Tested:
            [x] Verify invisibility of "Empty Trash" button when there are no scans present in Trash folder.
            [x] After moving one or more scans from trash to any folder, and clicking on Empty trash button from trash,
                verify that the scans which are moved to another folder does not get deleted

        Steps:
            1. Create two scans and move them to trash folder
            2. Move all scans from Trash to custom folder and verify that "Empty Trash" button does not appear.
            3. Move scans from custom folder to Trash folder
            4. Move only one scan out of two scans from Trash folder to custom folder.
            5. Click on "Empty Trash" button and verify that scan which is moved to custom folder does not get deleted.
        """
        created_scan = create_scans
        scan_page = ScansPage()
        scan_list = ScanList()
        side_nav = SideNav()
        scan_page.refresh()
        scan_list.loaded()

        # Verify that scans created successfully
        assert set(created_scan).issubset(scan_list.get_all_scans()), "Created scans are not present in scans page."
        scan_page.move_scan_to_selected_folder(scan_list=created_scan, folder_name=Nessus.Scan.Folder.TRASH)

        trash_page = ScansTrashPage()
        trash_page.open()
        scan_list.loaded()
        # Verify that all created scan moved to Trash folder successfully.
        assert set(created_scan).issubset(scan_list.get_all_scans()), "All created scans did not move to Trash folder."
        # Verify 'Empty Trash' button is visible.
        assert trash_page.is_element_present("empty_trash_button"), \
            "'Empty Trash' button is not visible even though scans are present."

        scan_page.move_scan_to_selected_folder(scan_list=created_scan, select_all=True,
                                               folder_name=create_new_folder[1])
        wait(lambda: ScanViewPage().empty_result.text == "Your trash is empty.",
             waiting_for='All scans from Trash folder to get moved to custom folder.')

        # Verify that 'Empty Trash' button is not visible when scans are not present in Trash folder
        assert not trash_page.is_element_present("empty_trash_button"), \
            "'Empty Trash' button is visible even though scans are not present in Trash folder."

        side_nav.get_sidenav_element(element_name=create_new_folder[1]).click()
        scan_list.loaded()

        scan_page.move_scan_to_selected_folder(scan_list=created_scan, folder_name=Nessus.Scan.Folder.TRASH)

        scan_to_be_moved = created_scan[0]

        trash_page.open()
        scan_list.loaded()
        scan_page.move_scan_to_selected_folder(scan_list=[scan_to_be_moved], folder_name=create_new_folder[1])
        wait(lambda: trash_page.is_element_present("empty_trash_button"),
             waiting_for='Empty Trash button to get appeared')

        # Verify that 'Empty Trash' button is visible when scan is present in Trash folder.
        assert trash_page.is_element_present("empty_trash_button"), \
            "'Empty Trash' button is not visible even though scans are present."

        trash_page.empty_trash_button.click()
        action_modal = ActionCloseModal()
        assert action_modal.modal.is_displayed(), "Confirmation pop up is not displayed for delete"
        action_modal.accept_action()
        wait(lambda: ScanViewPage().empty_result.text == "Your trash is empty.",
             waiting_for='All scans from Trash folder to get deleted.')
        assert not trash_page.is_element_present("empty_trash_button"), \
            "'Empty Trash' button is visible even though scans are not present in Trash folder."

        side_nav.get_sidenav_element(element_name=create_new_folder[1]).click()
        scan_list.loaded()
        # Verify that scan residing in custom folders does not get deleted by 'Empty Trash' button.
        assert scan_to_be_moved in scan_list.get_all_scans(), \
            "Scan present in other folder gets deleted by 'Empty Trash' button."
