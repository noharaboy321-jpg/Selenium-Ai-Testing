"""
Nessus Schedule Scans related test cases

:copyright: Tenable Network Security, 2019
:date: May 02, 2019
:last_modified: May 02, 2019
:author: @yshah
"""

import pytest
from selenium.common.exceptions import NoSuchElementException
from waiting.exceptions import TimeoutExpired

from catium.lib.const.base_constants import TIME_THIRTY_SECONDS, TIME_TEN_SECONDS, WAIT_TINY
from catium.lib.log.log import create_logger
from catium.lib.util import random_name
from catium.lib.webium.wait import wait
from nessus.lib.const import Nessus
from nessus.lib.message.messages import Messages
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.scans.scan_basic_settings_page import BasicSetting
from nessus.pageobjects.scans.scan_trash_page import ScansTrashPage
from nessus.pageobjects.scans.scan_view_page import ScanViewPage
from nessus.pageobjects.scans.scans_page import ScansPage, ScanList
from nessus.pageobjects.sidenav.sidenav import SideNav

log = create_logger()


@pytest.fixture()
def delete_schedule_scans():
    """
    Fixture to delete the schedule scan
    """
    try:
        if len(ScanList().get_all_schedule_scans()) > 0:
            ScansPage().delete_all_scans()

        side_nav = SideNav()
        side_nav.get_sidenav_element(element_name="Trash").click()

        if len(ScanList().get_all_schedule_scans()) > 0:
            ScansPage().delete_all_scans_from_trash()
        try:
            HeaderBasePage().scan_link.click()
        except NoSuchElementException as e:
            log.warning("scan link not found, Error: {}".format(e))
    except (NoSuchElementException, TimeoutExpired) as e:
        log.warning("Unable to delete schedule scans, Error: {}".format(e))


@pytest.mark.usefixtures('nessus_api_login', 'login', 'delete_schedule_scans')
@pytest.mark.nessus_home
class TestScheduleScanLimitForHome:

    @pytest.mark.xray(test_key='NES-13787')
    @pytest.mark.parametrize('create_scans', [{'scans_details': [{
        'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
        'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.ADVANCED)),
        'description': 'Created a {} for NES-9234.'.format(Nessus.TemplateNames.ADVANCED.lower()),
        'target_ip': Nessus.Scan.Target.LOCALHOST, "add_configuration": True, "schedule_scan": True}]}], indirect=True)
    def test_schedule_scan_limit_for_home_user(self, create_scans):
        """
        NES-9234: Nessus Essentials: Limit number of scans that can be scheduled
        NES-13787 : Verify cancel and continue button in warning popup

        Scenarios Tested:
        [x]  User should not be able to create more than one scheduled scan.

        Steps:
        1. Create a schedule scan and save it.
        2. Create another schedule scan.
        3. Saving should show a warning pop-up.
        4. Verify the pop-up.
        """
        scan_page = ScansPage()
        scan_page.save_button.click()

        # Click on scan link
        header_page = HeaderBasePage()
        header_page.scan_link.click()
        wait(lambda: scan_page.is_element_present('scan_searchbox', timeout=TIME_THIRTY_SECONDS),
             waiting_for="Visibility of search box")
        scan_name = random_name(prefix='{} Scan - '.format(Nessus.TemplateNames.BASIC_NETWORK))

        # Create another schedule scan
        scan_page.create_schedule_scan(scan_template=Nessus.TemplateNames.BASIC_NETWORK,
                                       scan_type=Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                                       target_ip=Nessus.Scan.Target.LOCALHOST, scan_name=scan_name)

        action_modal = ActionCloseModal()
        wait(lambda: action_modal.is_element_present('modal', timeout=TIME_THIRTY_SECONDS),
             waiting_for='modal to appear.')

        # Verify the action modal content like header, action button and cancel button
        assert action_modal.modal_title.text == Messages.NotificationMessages.ScanResults. \
            max_schedule_scan_popup_title, "Title of the popup is different"
        assert action_modal.modal_content.text == Messages.NotificationMessages.ScanResults. \
            max_schedule_scan_popup_content, "Content of the popup is different"
        assert all([action_modal.is_element_present("action_button"), action_modal.is_element_present("cancel_button"),
                    action_modal.is_element_present("close_button")]), "Action/Cancel/Close button is missing"
        action_modal.action_button.click()
        header_page.scan_link.click()
        wait(lambda: scan_page.is_element_present('scan_searchbox', timeout=TIME_THIRTY_SECONDS),
             waiting_for="Visibility of search box")
        schedule_scan_list = ScanList().get_all_schedule_scans()

        # Verify there should be only one scheduled scan exists
        assert len(schedule_scan_list) == 1, "There are more than one schedule scan exist"
        assert scan_name in schedule_scan_list, "Parent scan is not a scheduled scan"

    @pytest.mark.parametrize('create_scans', [{'scans_details': [{
        'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
        'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.ADVANCED)),
        'description': 'Created a {} for NES-9234.'.format(Nessus.TemplateNames.ADVANCED.lower()),
        'target_ip': Nessus.Scan.Target.LOCALHOST, "add_configuration": True, "schedule_scan": True}]}], indirect=True)
    @pytest.mark.parametrize('delete_level', ['delete scan from trash', 'move to trash only'])
    def test_create_another_schedule_scan_once_delete_schedule_scan(self, create_scans, delete_level):
        """
        NES-9234: Nessus Essentials: Limit number of scans that can be scheduled

        Scenarios Tested:
        [x]  Delete the scheduled scan and check user is able to create another scheduled scan.

        Steps:
        1. Create a scheduled scan and save it.
        2. Delete the created scheduled scan in step #1.
            a. Delete from 'My scan' folder but the scan is still in trash folder.
            b. Delete the scan from both the location.
        3. Create another scheduled scan and save it.
        4. Verify it should allow to create another scheduled scan.
        """
        scan_page = ScansPage()
        scan_page.save_button.click()

        notification = Notifications()
        wait(lambda: scan_page.is_element_present('scan_searchbox', timeout=TIME_THIRTY_SECONDS),
             waiting_for="Visibility of search box")
        scan_name = create_scans[0]

        # Delete the scans from My scan folder and trash folder depends on value from parameter.
        scan_list = ScanList()
        scan_list.delete_scan(scan_name=scan_name)
        if delete_level == "delete scan from trash":
            ScansTrashPage().delete_scan_from_trash(scan_name=scan_name)

        # Click on scan link
        header_page = HeaderBasePage()
        header_page.scan_link.click()

        # Create another schedule scan
        scan_name = random_name(prefix='{} Scan - '.format(Nessus.TemplateNames.BASIC_NETWORK))
        scan_page.create_schedule_scan(scan_template=Nessus.TemplateNames.BASIC_NETWORK,
                                       scan_type=Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                                       target_ip=Nessus.Scan.Target.LOCALHOST, scan_name=scan_name)

        if delete_level == "delete scan from trash":

            assert notification.successes[-1] == Messages.NotificationMessages.save_scan, \
                "Success message for saving scan is mismatched or missing."
        else:
            action_modal = ActionCloseModal()
            wait(lambda: action_modal.is_element_present('modal', timeout=TIME_THIRTY_SECONDS),
                 waiting_for='modal to appear.')
            assert action_modal.modal_title.text == Messages.NotificationMessages.ScanResults. \
                max_schedule_scan_popup_title, "Title of the popup is different"
            action_modal.action_button.click()

            assert notification.successes[-1] == Messages.NotificationMessages.save_scan, \
                "Success message for saving scan is mismatched or missing."

        header_page.scan_link.click()
        wait(lambda: scan_page.is_element_present('scan_searchbox', timeout=TIME_THIRTY_SECONDS),
             waiting_for="Visibility of search box")
        schedule_scan_list = scan_list.get_all_schedule_scans()

        # Verify there should be only one scheduled scan exists
        assert len(schedule_scan_list) == 1, "There are more than one schedule scan exist"
        assert scan_name in schedule_scan_list, "Parent scan is not a scheduled scan"

    @pytest.mark.usefixtures('create_new_folder')
    @pytest.mark.parametrize('create_scans', [{'scans_details': [{
        'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
        'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.ADVANCED)),
        'description': 'Created a {} for NES-9234.'.format(Nessus.TemplateNames.ADVANCED.lower()),
        'target_ip': Nessus.Scan.Target.LOCALHOST, "add_configuration": True, "schedule_scan": True}]}], indirect=True)
    @pytest.mark.parametrize("folders", ['My Scans', 'existing folder', "new folder"])
    def test_copy_of_scheduled_scan_should_not_allow_another_schedule_scan(self, create_scans, folders,
                                                                           create_new_folder):
        """
        NES-9234: Nessus Essentials: Limit number of scans that can be scheduled

        Scenarios Tested:
        [x] Copy of Scheduled scan should not have scheduled enabled
        [x] Copy to "My scan"/"Existing folder"/"New folder" and verify the copied scan should not have scheduled
        enabled.

        Steps:
        1. Create a scheduled scan and save it.
        2. Copy the created schedule scan in step #1.
            a. Copy to "My scan" folder and verify the copied scan should not have scheduled enabled.
            b. Copy to "Existing" folder and verify the copied scan should not have scheduled enabled.
            c. Copy to "New folder" and verify the copied scan should not have scheduled enabled.
        3. Verify Copy of scheduled scan should not have schedule enabled
        """
        folder_name = create_new_folder[1]

        scan_page = ScansPage()
        scan_page.save_button.click()

        wait(lambda: scan_page.is_element_present('scan_searchbox', timeout=TIME_THIRTY_SECONDS),
             waiting_for="Visibility of search box")
        scan_name = create_scans[0]

        side_nav = SideNav()
        scan_list = ScanList()
        scan_list.select_scans(scans_list=scan_name)
        wait(lambda: scan_page.is_element_present('more_button', timeout=TIME_THIRTY_SECONDS))

        # Copy scan to selected folders and verify the maximum number of schedule scan should be 1.
        if folders == "My Scans":
            scan_page.copy_scan_to_selected_folder(scan_list=[scan_name], folder_name="My Scans")
            schedule_scan_list = scan_list.get_all_schedule_scans()
            assert len(schedule_scan_list) == 1, "There are more than one schedule scan exist"
            assert scan_name in schedule_scan_list, "Parent scan is not a scheduled scan"
        elif folders == "existing folder":
            scan_page.copy_scan_to_selected_folder(scan_list=[scan_name], folder_name=folder_name)
            side_nav.get_sidenav_element(element_name=folder_name).click()
            wait(lambda: scan_page.is_element_present('scan_searchbox', timeout=TIME_THIRTY_SECONDS),
                 waiting_for="Visibility of search box")
            assert len(scan_list.get_all_schedule_scans()) == 0, "There is one schedule scan present"
        else:
            folder_name = random_name(prefix='folder-')
            scan_page.copy_scan_to_selected_folder(scan_list=[scan_name], folder_name=folder_name, new_folder=True,
                                                   copied_scan_name="NQA-1063-copy-of-{}".format(scan_name))
            side_nav.get_sidenav_element(element_name=folder_name).click()
            wait(lambda: scan_page.is_element_present('scan_searchbox', timeout=TIME_THIRTY_SECONDS),
                 waiting_for="Visibility of search box")
            assert len(scan_list.get_all_schedule_scans()) == 0, "There is one schedule scan present"

    @pytest.mark.usefixtures('create_new_folder')
    @pytest.mark.parametrize('create_scans', [{'scans_details': [{
        'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
        'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.ADVANCED)),
        'description': 'Created a {} for NES-9234.'.format(Nessus.TemplateNames.ADVANCED.lower()),
        'target_ip': Nessus.Scan.Target.LOCALHOST, "add_configuration": True, "schedule_scan": True}]}], indirect=True)
    @pytest.mark.parametrize("folder_name", ['New Folder', 'existing folder', 'Trash'])
    def test_move_schedule_scan_should_not_allow_another_schedule_scan(self, create_new_folder, create_scans,
                                                                       folder_name):
        """
        NES-9234: Nessus Essentials: Limit number of scans that can be scheduled

        Scenarios Tested:
        [x] Move schedule scan to another folder should not allow user to create another schedule scan in my scans/any
        other folder
        [x] It should not allow to create schedule scan if there is already a schedule scan in trash folder.

        Steps:
        1. Create a scheduled scan and save it.
        2. Move the created scheduled scan in step #1.
            a. Move to "Trash" folder and verify the moved scan should not have schedule enabled.
            b. Move to "Existing" folder and verify the moved scan should not have schedule enabled.
            c. Move to "New folder" and verify the moved scan should not have schedule enabled.
        3. Verify move scheduled scan to another folder should show a warning pop-up to user while create another
        scheduled scan.
        """
        folder = create_new_folder[1] if folder_name == 'existing folder' else "Trash"

        scan_page = ScansPage()
        scan_page.save_button.click()
        wait(lambda: scan_page.is_element_present('scan_searchbox', timeout=TIME_THIRTY_SECONDS),
             waiting_for="Visibility of search box")
        scan_name = create_scans[0]

        scan_list = ScanList()
        scan_list.select_scans(scans_list=scan_name)
        wait(lambda: scan_page.is_element_present('more_button', timeout=TIME_THIRTY_SECONDS))
        side_nav = SideNav()

        if folder_name == "New Folder":
            folder = random_name(prefix='folder-')
        scan_page.move_scan_to_selected_folder(scan_list=[scan_name], folder_name=folder,
                                               new_folder=folder_name == "New Folder")
        side_nav.get_sidenav_element(element_name=folder).click()
        wait(lambda: scan_page.is_element_present('scan_searchbox', timeout=TIME_THIRTY_SECONDS),
             waiting_for="Visibility of search box")

        # Verify there should be only one scheduled scan exists
        schedule_scan_list = scan_list.get_all_schedule_scans()
        assert len(schedule_scan_list) == 1, "There are more than one schedule scan exist"
        assert scan_name in schedule_scan_list, "Moved scan is not a scheduled scan"
        header_page = HeaderBasePage()
        header_page.scan_link.click()

        scan_name = random_name(prefix='{} Scan - '.format(Nessus.TemplateNames.BASIC_NETWORK))
        scan_page.create_schedule_scan(scan_template=Nessus.TemplateNames.BASIC_NETWORK,
                                       scan_type=Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                                       target_ip=Nessus.Scan.Target.LOCALHOST, scan_name=scan_name)
        action_modal = ActionCloseModal()

        # Verify the warning modal is displaying
        assert action_modal.is_element_present('modal'), "Modal does not appear and scan saved successfully"
        action_modal.action_button.click()
        header_page.scan_link.click()
        wait(lambda: scan_page.is_element_present('scan_searchbox', timeout=TIME_THIRTY_SECONDS),
             waiting_for="Visibility of search box")

    def test_message_displayed_for_limit_schedule_scan(self):
        """
        NES-9234: Nessus Essentials: Limit number of scans that can be scheduled

        Scenarios Tested:
        [x] Verify the warning message displayed while creating the every schedule scan.

        Steps:
        1. Click on valid scan template.
        2. Go to schedule section.
        3. Verify the warning message displayed while creating the scheduled scan.
        """
        scan_page = ScansPage()
        wait(lambda: (scan_page.is_element_present('scan_searchbox', timeout=TIME_TEN_SECONDS) or
                      (ScanViewPage().is_element_present("empty_result", timeout=TIME_TEN_SECONDS))),
             waiting_for="Visibility of search box")
        scan_page.new_scan_button.click()
        scan_page.click_by_scan(scan_text=Nessus.TemplateNames.ADVANCED)

        scan_setting = BasicSetting()
        scan_setting.schedule.click()
        scan_setting.enable_schedule.toggle()

        # Verify the maximum schedule scan warning message is displaying while creating schedule scan
        assert scan_page.limit_schedule_scan_message.text == Messages.Home.max_schedule_scan_limit, \
            "The message displayed is different"

    @pytest.mark.xray(test_key='NES-13971')
    def test_upgrade_nessus_link_on_schedule_scan(self):
        """
        NES-13971 Verify 'Upgrade to Nessus Professional' hyperlink
        """
        scan_page = ScansPage()
        wait(lambda: (scan_page.is_element_present('scan_searchbox', timeout=TIME_TEN_SECONDS) or
                      (ScanViewPage().is_element_present("empty_result", timeout=TIME_TEN_SECONDS))),
             waiting_for="Visibility of search box")
        scan_page.new_scan_button.click()
        scan_page.click_by_scan(scan_text=Nessus.TemplateNames.ADVANCED)
        scan_setting = BasicSetting()
        scan_setting.schedule.click()
        scan_setting.enable_schedule.toggle()

        assert scan_page.upgrade_nessus_link.text == Nessus.Essentials.UPGRADE_TO_PROFESSIONAL, 'Upgrade link does not match'

        scan_page.upgrade_nessus_link.click()
        action_modal = ActionCloseModal()

        assert action_modal.is_element_present('modal'), 'Upgrade modal is not available'

        assert action_modal.modal_title.text == Nessus.Essentials.UPGRADE_TO_PROFESSIONAL, 'Modal title does not match'

        action_modal.close_button.click()
        action_modal.wait_for_modal_closed(timeout_seconds=WAIT_TINY)

        assert not action_modal.is_element_present('modal'), 'modal is still visible'

    @pytest.mark.parametrize('create_scans', [{'scans_details': [{
        'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
        'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.ADVANCED)),
        'description': 'Created a {} for NES-9234.'.format(Nessus.TemplateNames.ADVANCED.lower()),
        'target_ip': Nessus.Scan.Target.LOCALHOST, "add_configuration": True, "schedule_scan": True}]}], indirect=True)
    def test_edit_schedule_scan_and_create_another_schedule_scan(self, create_scans):
        """
        NES-9234: Nessus Essentials: Limit number of scans that can be scheduled

        Scenarios Tested:
        [x] Create a scheduled scan and modify it to non-schedule scan, check user should be able to create another
        schedule scan..

        Steps:
        1. Create a scheduled scan and save it.
        2. Click on the created scheduled scan in step #1.
        3. Click on configure and update it to non-scheduled scan.
        4. Create another scheduled scan and verify user should able to create it without warning pop-up.
        """
        scan_page = ScansPage()
        scan_page.save_button.click()

        notification = Notifications()
        wait(lambda: scan_page.is_element_present('scan_searchbox', timeout=TIME_THIRTY_SECONDS),
             waiting_for="Visibility of search box")
        scan_name = create_scans[0]

        # Edit the scan
        scan_list = ScanList()
        scan_list.click_on_scan(scan_name=scan_name)

        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present("configure_button", timeout=TIME_TEN_SECONDS))

        # Configure the schedule scan to non-schedule scan
        scan_view_page.configure_button.click()
        scan_setting = BasicSetting()
        scan_setting.schedule.click()
        scan_setting.enable_schedule.untoggle()
        scan_page.save_button.click()
        wait(lambda: notification.successes, waiting_for="Notification list to populate")

        header_page = HeaderBasePage()
        header_page.scan_link.click()
        wait(lambda: scan_page.is_element_present('scan_searchbox', timeout=TIME_THIRTY_SECONDS),
             waiting_for="Visibility of search box")

        # Create schedule scan
        scan_name = random_name(prefix='{} Scan - '.format(Nessus.TemplateNames.BASIC_NETWORK))
        scan_page.create_schedule_scan(scan_template=Nessus.TemplateNames.BASIC_NETWORK,
                                       scan_type=Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                                       target_ip=Nessus.Scan.Target.LOCALHOST, scan_name=scan_name)

        # Verify the success message
        assert notification.successes[-1] == Messages.NotificationMessages.save_scan, \
            "Scan Saved but, notification was missing"
        header_page.scan_link.click()
        wait(lambda: scan_page.is_element_present('scan_searchbox', timeout=TIME_THIRTY_SECONDS),
             waiting_for="Visibility of search box")
        schedule_scan_list = scan_list.get_all_schedule_scans()

        # Verify there should be only one scheduled scan exists
        assert len(schedule_scan_list) == 1, "There are more than one schedule scan exist"
        assert scan_name in schedule_scan_list, "New created scan is not a scheduled scan"

    @pytest.mark.xray(test_key='NES-13765')
    @pytest.mark.xray(test_key='NES-13750')
    @pytest.mark.parametrize('create_scans', [{'scans_details': [{
        'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
        'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.ADVANCED)),
        'description': 'Created a {}'.format(Nessus.TemplateNames.ADVANCED.lower()),
        'target_ip': Nessus.Scan.Target.LOCALHOST, "add_configuration": True, "schedule_scan": True}]}], indirect=True)
    def test_create_another_schedule_scan_after_one_is_completed(self, create_scans):
        """
        NES-13765 Verify creating new scheduled scan after older scheduled scan is completed
        NES-13750 Verify second scheduled scan

        Scenarios Tested:
        [x]  User should not be able to create more than one scheduled scan even after one schedule scan is completed

        Steps:
        1. Create a schedule scan and Launch it and wait till it gets completed.
        2. Create another schedule scan.
        3. Saving should show a warning pop-up.
        4. Verify the pop-up.
        """
        scan_page = ScansPage()
        scan_page.save_button.click()

        scan_list = ScanList()

        # Launching created scan and waiting to be completed
        scan_list.launch_scan_and_wait_for_status(create_scans[0])

        # Click on scan link
        header_page = HeaderBasePage()
        header_page.scan_link.click()
        wait(lambda: scan_page.is_element_present('scan_searchbox', timeout=TIME_THIRTY_SECONDS),
             waiting_for="Visibility of search box")
        scan_name = random_name(prefix='{} Scan - '.format(Nessus.TemplateNames.BASIC_NETWORK))

        # Create another schedule scan
        scan_page.create_schedule_scan(scan_template=Nessus.TemplateNames.BASIC_NETWORK,
                                       scan_type=Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                                       target_ip=Nessus.Scan.Target.LOCALHOST, scan_name=scan_name)

        action_modal = ActionCloseModal()
        wait(lambda: action_modal.is_element_present('modal', timeout=TIME_THIRTY_SECONDS),
             waiting_for='modal to appear.')

        assert action_modal.is_element_present('modal'), "Schedule scan warning popup doesn't appear"

        action_modal.action_button.click()
        header_page.scan_link.click()
        header_page.refresh()
        wait(lambda: scan_page.is_element_present('scan_searchbox', timeout=TIME_THIRTY_SECONDS),
             waiting_for="Visibility of search box")
        schedule_scan_list = ScanList().get_all_schedule_scans()

        # Verify there should be only one scheduled scan exists
        assert len(schedule_scan_list) == 1, "There are more than one schedule scan exist"
        assert scan_name in schedule_scan_list, "Parent scan is not a scheduled scan"
