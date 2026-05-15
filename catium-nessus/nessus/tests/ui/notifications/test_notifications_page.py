"""
Nessus notifications page related test cases

:copyright: Tenable Network Security, 2019
:creation date: June 27, 2019
:last_modified: July 30, 2020
:author: @yshah, @kpanchal
"""

import json
from datetime import datetime, date

import os
import pytest
from _pytest.fixtures import SubRequest
from selenium.webdriver.common.by import By
from selenium.webdriver.support.expected_conditions import visibility_of_element_located

from catium.helpers.sleep_lib import sleep
from catium.lib.config.environment_variables import CommonConfig
from catium.lib.const.base_constants import TIME_TEN_SECONDS, TIME_FIFTEEN_SECONDS, WAIT_NORMAL
from catium.lib.log import create_logger
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.cli_command import upload
from nessus.helpers.nessuscli.helper import get_nessus_var_dir
from nessus.lib.const.constants import Nessus
from nessus.pageobjects.advanced_settings.advanced_settings_page import AdvancedSettingsPage
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications, ModalNotifications, NotificationActions
from nessus.pageobjects.header.user_menu import UserMenu
from nessus.pageobjects.login.login_page import LoginPage
from nessus.pageobjects.notifications.notifications_page import NotificationsList, NotificationFilter, \
    NotificationsPage
from nessus.pageobjects.password_mgmt.password_management_page import PasswordManagement
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav
from nessus.tests.api.server.conftest import _create_notifications_file, _reload_nessus

log = create_logger()


@pytest.fixture(scope="class")
def load_notifications_for_notification_page(request: 'SubRequest'):
    """
    Copies test_data/sample_notifications.json to the nessus installation
    and triggers them to be loaded.

    On teardown it removes the notifications.
    """
    file_name = request.param['file_name'] if hasattr(request, 'param') and 'file_name' in request.param else \
        'notifications_for_notification_page.json'
    api = NessusAPI()
    tmp_file = _create_notifications_file(file_name)

    with open(tmp_file, 'r') as f:
        notes_json = json.load(f)

    log.info('Inserting sample notifications')
    upload(tmp_file, os.path.join(get_nessus_var_dir(), 'notifications.json'))
    os.unlink(tmp_file)
    _reload_nessus(api)
    log.info('Done inserting sample notifications')

    yield notes_json

    log.info('Removing sample notifications')
    notifications_file = 'nessus/tests/api/server/test_data/default_notifications.json'
    upload(notifications_file, os.path.join(get_nessus_var_dir(), 'notifications.json'))
    _reload_nessus(api)
    log.info('Done removing sample notifications')


def manage_pop_up_task() -> None:
    """
    Clear any pop-ups (modals) present when user logs in
    :return: None
    """
    # acknowledge at least one notification
    dismiss_list = ['Modal High.']
    ModalNotifications().list(dismiss_list=dismiss_list)


@pytest.mark.serial
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('login')
class TestNotificationsTab:
    """Tests cases related to notifications tab at left navigation """

    def test_verify_entry_of_failed_login_and_success_login_notifications(self):
        """
        NES-9665 - NES-9549 Create historical view of user notifications

        Scenarios:
            [x] Verify the success login and failed login notification should be displayed on the notifications page.
            [x] Verify there should not be any saved policy/scan related notifications should be displayed.

        Steps:
        1. Enable login notifications
        2. Logout from nessus and attempt to login with invalid credentials.
        3. Login with valid credentials.
        4. Go to Notifications page.
        5. Verify the success login and failed login notification should be displayed on the notifications page.
        6. Disable login notifications
        """
        NotificationActions().remove_all()

        password_mgmt = PasswordManagement()
        password_mgmt.open()
        if password_mgmt.is_element_present('login_notification_switch', timeout=5) and not \
                password_mgmt.is_element_present('login_notifications_enabled'):
            password_mgmt.login_notification_switch.click()
            password_mgmt.save_button.click()
            sleep(TIME_FIFTEEN_SECONDS, reason='setting to take effect.')

        # Wait till loading circle to disappear
        LoadingCircle(WAIT_NORMAL)

        user_menu = UserMenu()

        user_menu.logout()
        login_page = LoginPage()
        wait(lambda: login_page.is_element_present('username_field'), timeout_seconds=TIME_TEN_SECONDS)

        login_page.login_with_credentials(username="admin", password="abc")

        NotificationActions().remove_all()

        login_page.refresh()
        login_page.loaded()

        login_page.login_with_defaults()

        wait(lambda: user_menu.is_element_present('user_menu_dropdown'), timeout_seconds=TIME_TEN_SECONDS)
        notification = NotificationsPage()
        notification.open()
        notifications = NotificationsList().get_all_notifications()

        # Verify the first notification should be of success login notification.
        assert "Last login occurred" in notifications[0], "Recent success notification does not exist"

        # Verify the second notification should be of failed login notification.
        assert "Failed login attempt occurred" in notifications[1], "Failed attempt notification does not exist"

        for notification in notifications:
            assert "saved successfully." not in notification, "Saved scan/policies notifications present in the " \
                                                              "notifications history"
        password_mgmt.open()
        if password_mgmt.is_element_present('login_notification_switch', timeout=5) and \
                password_mgmt.is_element_present('login_notifications_enabled'):
            password_mgmt.login_notification_switch.click()
            password_mgmt.save_button.click()
            sleep(TIME_FIFTEEN_SECONDS, reason='setting to take effect.')

        # Wait till loading circle to disappear
        LoadingCircle(WAIT_NORMAL)


    @pytest.mark.nessus_expert
    def test_content_of_filter_pop_up(self):
        """
        NES-9665 - NES-9549 Create historical view of user notifications

        Scenarios:
            [x] Verify content of filter pop-up on the notifications page.

        Steps:
        1. Go to Notifications page.
        2. Click on filter button.
        3. Verify the content on pop-up and verify remove filter button should not be displayed
        4. Click on add filter button and verify remove filter button should be displayed
        """
        notification = NotificationsPage()
        notification.open()
        wait(lambda: notification.is_element_present('filter'), timeout_seconds=TIME_TEN_SECONDS)
        notification.filter.click()
        wait(lambda: ActionCloseModal().is_element_present("modal"), timeout_seconds=TIME_TEN_SECONDS)
        notification_filter = NotificationFilter()

        # Verify all the mentioned locator will be visible on UI
        assert all([notification_filter.is_element_present(i) for i in
                    ["match_all", "select_key", "add_filter", "clear_filter_link", "date_input", "apply_button",
                     "cancel_link"]]), \
            "All the mentioned element are not visible on the UI"

        # Verify remove filter option should not be displayed.
        assert not notification_filter.is_element_present("remove_filter"), "Remove filter icon is displaying on UI"
        notification_filter.add_filter.click()

        # Verify remove filter option should be displayed after adding the filter.
        assert notification_filter.is_element_present("remove_filter"), "Remove filter icon is not displaying on UI"

        ActionCloseModal().cancel_button.click()

    @pytest.mark.nessus_expert
    def test_visibility_of_notifications_tab_and_content_on_tab(self):
        """
        NES-9665 - NES-9549 Create historical view of user notifications

        Scenarios:
            [x] Notifications option should be visible at left navigation.
            [x] All the locator like Page header, filter, notification search box, total notification should be
            visible on Notifications page.

        Steps:
        1. Verify "Notifications" option should be displayed at left navigation.
        2. Click on Notification option and wait for the notifications to load.
        3. Verify All the locators(Mentioned in the scenarios) should be displayed on page.
        """
        notification = NotificationsPage()
        notification.open()

        # Verify notifications option should be visible at left navigation.
        assert SideNav().get_sidenav_element(element_name='Notification'), "Notification option is not displaying " \
                                                                           "at the left navigation"
        get_driver_no_init().refresh()
        wait(lambda: notification.is_element_present('notification_search_box'), timeout_seconds=TIME_TEN_SECONDS)

        # Verify all the locator like Page header, filter, notification search box, total notification should be
        # visible on Notifications page.
        assert all([notification.is_element_present(i) for i in
                    ["page_header", "filter", "notification_search_box", "total_notifications"]]), \
            "All the mentioned element are not visible on the UI"

    @pytest.mark.nessus_expert
    def test_working_of_filter_on_notification_page(self):
        """
        NES-9665 - NES-9549 Create historical view of user notifications

        Scenarios:
            [x] Verify working of filter on the notifications page.

        Steps:
        1. Go to Notifications page.
        2. Put the value in the filter input box as the first notification message.
        3. Verify the count and the message displayed next to notification search filter.
        """
        notification = NotificationsPage()
        notification.open()
        wait(lambda: notification.is_element_present('notification_search_box'), timeout_seconds=TIME_TEN_SECONDS)
        notification_list = NotificationsList()
        get_notification_list = notification_list.get_all_notifications()
        notification.notification_search_box.value = get_notification_list[0]
        LoadingCircle(WAIT_NORMAL)

        filtered_notification_list = notification_list.get_all_notifications()

        # Verify there should be only one notification exist.
        assert {get_notification_list[0]} == set(filtered_notification_list), \
            "There is more than one notification available"

        # Verify the count display next to notification search filter.
        assert int(notification.filtered_notifications.text.split()[0]) == len(filtered_notification_list), \
            "It is displaying more than one notification"

    @pytest.mark.nessus_expert
    def test_verification_of_clear_filter_link(self):
        """
         NES-9665 - NES-9549 Create historical view of user notifications

         Scenarios:
             [x] Verify click on clear filter link should remove the existing filter.

         Steps:
         1. Go to notifications page and click on filter button.
         2. Apply filter and click on apply.
         3. Verify the count of applied filter.
         4. Click on remove filter link and verify the count should be disappeared from UI.
         """
        notification = NotificationsPage()
        notification.open()
        wait(lambda: notification.is_element_present('filter'), timeout_seconds=TIME_TEN_SECONDS)

        notification.filter.click()
        wait(lambda: ActionCloseModal().is_element_present("modal"), timeout_seconds=TIME_TEN_SECONDS)

        notification_filter = NotificationFilter()
        notification_filter.date_input.value = datetime.today().strftime('%Y-%m-%d')
        ActionCloseModal().action_button.click()
        wait(lambda: notification_filter.is_element_present('filter_count'))

        # Verify the applied filtered count
        assert int(notification_filter.filter_count.text) == 1, "Applied filter count is wrong"
        notification.filter.click()

        # Click on clear filter link
        notification_filter.clear_filter_link.click()

        # Verify the applied filter count must be disappeared from the UI.
        assert not notification_filter.is_element_present('filter_count'), "Applied filter count is still visible"


@pytest.mark.serial
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('login', 'nessus_api_login', 'load_notifications_for_notification_page')
class TestAdvancedFilterWithNotificationFile:
    """This class covers the test cases related to advanced filter where we need notifications.json file"""

    def test_visibility_of_pagination_related_locators(self):
        """
          NES-9665 - NES-9549 Create historical view of user notifications

          Scenarios:
              [x] Verify the visibility of pagination and its related locators.

          Steps:
          1. Go to notifications page (need at least 50 notification).
          2. Go to bottom and verify the locators i.e. pagination_next, pagination_first, pagination_last,
          pagination_previous etc.
          """
        for _ in range(5):
            wait(lambda: ModalNotifications().is_element_present('modal'), timeout_seconds=TIME_TEN_SECONDS)
        manage_pop_up_task()
        notification = NotificationsPage()
        notification.open()
        wait(lambda: notification.is_element_present('filter'), timeout_seconds=TIME_TEN_SECONDS)
        notification.js_scroll_into_view(notification.data_info)

        # Verify all locator must be visible on UI when notification count is greater than 50.
        assert all([notification.is_element_present(i) for i in
                    ["pagination_next", "pagination_last", "result_per_page", "data_info",
                     "pagination_first", "pagination_previous"]]), \
            "All the mentioned element are not visible on the UI"

    def test_verify_visibility_of_icons_and_tooltip(self):
        """
          NES-9665 - NES-9549 Create historical view of user notifications

          Scenarios:
              [x] Verify the visibility of Alert icons.
              [x] Verify it is showing correct tooltip.

          Steps:
          1. Go to notifications page and verify it is displaying alert icons.
          2. Verify it is showing correct tooltip.
          """
        manage_pop_up_task()
        notification = NotificationsPage()
        notification.open()
        wait(lambda: notification.is_element_present('filter'), timeout_seconds=TIME_TEN_SECONDS)

        for row in NotificationsList().rows:
            if row.messages.text in ['Modal High.', "Modal Low.", "Modal Medium."]:
                tooltip = {'Modal High.': 'High', "Modal Low.": 'Low', "Modal Medium.": 'Medium'}.get(row.messages.text)
                icon = tooltip.lower()
                # Verify it is displaying correct alert icon
                assert icon in row.status_tooltip.get_attribute('class').split(), \
                    "{} alert icon is not visible".format(icon)
                notification.move_to_element(row.status_tooltip)

                # Verify correct tooltip is visible
                assert row.status_tooltip.get_attribute('original-title') == tooltip, \
                    "{} is different from expected, Found tooltip is {}".format(tooltip,
                                                                                row.status_tooltip.get_attribute(
                                                                                    'original-title'))
            elif row.messages.text in Nessus.NotificationPage.critical_notifications:
                # Verify it is displaying critical alert icon
                assert 'critical' in row.status_tooltip.get_attribute('class').split(), \
                    "Critical alert icon is not visible"
                notification.move_to_element(row.status_tooltip)

                # Verify "Critical" tooltip is visible
                assert row.status_tooltip.get_attribute('original-title') == "Critical", \
                    "Tooltip is different from expected, Found tooltip is {}".format(
                        row.status_tooltip.get_attribute('original-title'))
            else:
                # Verify it should not display any alert icon
                assert row.status.get_attribute('innerHTML').split() == [], "Alert icon is visible"

    @pytest.mark.parametrize("displayed_date_with_operator", ["earlier than", "later than", "on"])
    def test_verification_of_advanced_filter_with_displayed_date_key(self, displayed_date_with_operator):
        """
         NES-9665 - NES-9549 Create historical view of user notifications

         Scenarios:
             [x] Verify the working of advanced filter with displayed date key.

         Steps:
         1. Go to notifications page and click on filter button.
         2. Select the key as displayed date and Apply filter with operator "earlier than".
         3. Verify it should show relevant result after applying the filter.
         4. Repeat the steps for other operators as mentioned in parameters.
         """
        manage_pop_up_task()
        key = 'Displayed Date'
        value = datetime.today().strftime('%Y-%m-%d')
        operator = displayed_date_with_operator

        notification = NotificationsPage()
        notification.open()
        wait(lambda: notification.is_element_present('filter'), timeout_seconds=TIME_TEN_SECONDS)

        NotificationFilter().apply_filter(key=key, value=value, operator=operator)
        notification_list = NotificationsList()

        if operator == "on":
            # Verify the notification count is greater than zero
            assert notification_list.get_all_notifications(), "No notification found after applying the filter"
        else:
            is_empty_notification = notification.is_element_present("empty_notification_list")

            if not is_empty_notification and displayed_date_with_operator == "earlier than":
                displayed_date_list = notification_list.get_displayed_date_value()

                assert all([int(date_value.split()[1]) < int(value.split('-')[2]) for date_value in
                            displayed_date_list]), \
                    "Displayed date of available notification is not earlier than today's date."
            else:
                # Verify there should't be any notification displayed
                assert is_empty_notification, "{} Notifications are displaying".format(
                    len(notification_list.get_all_notifications()))

    @pytest.mark.parametrize("displayed_date_with_operator", ["earlier than", "later than", "on"])
    def test_verification_of_advanced_filter_with_acknowledged_date_key(self, displayed_date_with_operator):
        """
         NES-9665 - NES-9549 Create historical view of user notifications

         Scenarios:
             [x] Verify the working of advanced filter with acknowledged date key.

         Steps:
         1. Go to notifications page and click on filter button.
         2. Select the key as acknowledged date and Apply filter with operator "earlier than".
         3. Verify it should show relevant result after applying the filter.
         4. Repeat the steps for other operators as mentioned in parameters.
         """
        manage_pop_up_task()
        key = 'Acknowledged Date'
        value = datetime.today().strftime('%Y-%m-%d')
        operator = displayed_date_with_operator

        notification = NotificationsPage()
        notification.open()
        wait(lambda: notification.is_element_present('filter'), timeout_seconds=TIME_TEN_SECONDS)

        NotificationFilter().apply_filter(key=key, value=value, operator=operator)
        notification_list = NotificationsList()

        if operator in ["earlier than", "later than"]:
            # Verify there should't be any notification displayed
            assert notification.is_element_present("empty_notification_list"), \
                "{} Notifications are displaying".format(len(notification_list.get_all_notifications()))
        else:
            is_empty_notification = notification.is_element_present("empty_notification_list")

            if is_empty_notification and int(value.split('-')[2]) < date.today().day:
                assert is_empty_notification, "Found notifications even though the filter value date is less than " \
                                              "today's date."
            else:
                # Verify the notification count is greater than zero
                assert notification_list.get_all_notifications(), "No notification found after applying the filter"

    @pytest.mark.parametrize("acknowledged_with_operator", ["is equal to", "is not equal to"])
    def test_verification_of_advanced_filter_with_acknowledged_key(self, acknowledged_with_operator):
        """
         NES-9665 - NES-9549 Create historical view of user notifications

         Scenarios:
             [x] Verify the working of advanced filter with acknowledged status key.

         Steps:
         1. Go to notifications page and click on filter button.
         2. Select the key as acknowledged and Apply filter with operator "is equal to".
         3. Verify it should show relevant result after applying the filter.
         4. Repeat the steps for "is not equal to" operators as mentioned in parameters.
         """
        manage_pop_up_task()
        key = 'Acknowledged'
        operator = acknowledged_with_operator

        notification = NotificationsPage()
        notification_filter = NotificationFilter()
        notification.open()
        wait(lambda: notification.is_element_present('filter'), timeout_seconds=TIME_TEN_SECONDS)
        notification.filter.click()
        notification_filter.select_key_dropdown.select_by_visible_text(key)
        notification_filter.option_dropdown.select_by_visible_text(operator)
        notification_filter.acknowledge_value_dropdown.select_by_visible_text("Yes")
        ActionCloseModal().action_button.click()

        notification_list = NotificationsList()
        if acknowledged_with_operator == "is equal to":
            # filter: Acknowledged == "Yes"
            # Verify the notification count should be greater than zero
            assert notification_list.get_all_notifications(), "No notification found on notification page"

            # Verify the notification count of the list containing status with acknowledged only
            result_not_acked = list(filter(lambda status: status in ["N/A", "No"],
                                           notification_list.get_notification_status()))
            assert not result_not_acked, "Notifications with status 'N/A' or 'No' are visible"

            # filter: Acknowledged == "No"
            notification.filter.click()
            NotificationFilter().acknowledge_value_dropdown.select_by_visible_text("No")
            ActionCloseModal().action_button.click()

            # Verify the notification count should be greater than zero
            assert notification_list.get_all_notifications(), "No notification found on notification page"

            # Verify the notification count of the list containing status with "No" only
            result_not_no = list(filter(lambda status: status != "No",
                                        notification_list.get_notification_status()))
            assert not result_not_no, "Notifications with status 'N/A' or 'No' are visible"
            notification.filter.click()

            # filter: Acknowledged == "N/A"
            NotificationFilter().acknowledge_value_dropdown.select_by_visible_text("N/A")
            ActionCloseModal().action_button.click()

            # Verify the notification count should be greater than zero
            assert notification_list.get_all_notifications(), "No notification found on notification page"

            # Verify the notification count of the list containing status with "N/A" only
            result_not_na = list(filter(lambda status: status != "N/A",
                                        notification_list.get_notification_status()))
            assert not result_not_na, "Notifications with status other than 'N/A' are visible"
        else:
            # filter: Acknowledged != "Yes"
            # Verify the notification count should be greater than zero
            assert notification_list.get_all_notifications(), "No notification found on notification page"
            result_acked = list(filter(lambda status: status not in ["No", "N/A"],
                                       notification_list.get_notification_status()))

            # Verify the notification count of the list should not contain status with "Yes".
            assert not result_acked, "Notifications with status other than 'N/A' or 'No' are visible"

            # filter: Acknowledged != "No"
            notification.filter.click()
            NotificationFilter().acknowledge_value_dropdown.select_by_visible_text("No")
            ActionCloseModal().action_button.click()

            # Verify the notification count should be greater than zero
            assert notification_list.get_all_notifications(), "No notification found on notification page"
            result_no = list(filter(lambda status: status == "No",
                                    notification_list.get_notification_status()))

            # Verify the notification count of the list should not contain status with "No".
            assert not result_no, "Notifications with status 'No' are visible"

            # filter: Acknowledged != "N/A"
            notification.filter.click()
            NotificationFilter().acknowledge_value_dropdown.select_by_visible_text("N/A")
            ActionCloseModal().action_button.click()

            # Verify the notification count should be greater than zero
            assert notification_list.get_all_notifications(), "No notification found on notification page"

            # Verify the notification count of the list should not contain status with "N/A".
            result_na = list(filter(lambda status: status == "N/A",
                                    notification_list.get_notification_status()))
            assert not result_na, "Notifications with status 'N/A' are visible"

    @pytest.mark.parametrize("select_operator", ["contains", "does not contain", "is equal to", "is not equal to"])
    def test_verification_of_advanced_filter_with_message_key(self, select_operator):
        """
         NES-9665 - NES-9549 Create historical view of user notifications

         Scenarios:
             [x] Verify the working of advanced filter with message key.

         Steps:
         1. Go to notifications page and click on filter button.
         2. Select the key as message date and Apply filter with operator "contains".
         3. Verify it should show relevant result after applying the filter.
         4. Repeat the steps for all the operators as mentioned in parameters.
         """
        manage_pop_up_task()
        key = 'Message'
        operator = select_operator

        notification = NotificationsPage()
        notification_list = NotificationsList()
        notification_filter = NotificationFilter()
        notification.open()
        wait(lambda: notification.is_element_present('filter'), timeout_seconds=TIME_TEN_SECONDS)

        select_notification = notification_list.get_all_notifications()[1]

        notification_filter.apply_filter(key=key, value=select_notification.rsplit(' ', 4)[0], operator=operator)

        filtered_notifications = notification_list.get_all_notifications()
        if operator == "contains":
            # Verify the notification count should be greater than zero
            assert filtered_notifications, \
                "No Notification found that contains {}".format(select_notification.rsplit(' ', 4)[0])

            # Verify every message should contain the searched string
            assert all([select_notification.rsplit(' ', 4)[0] in notifications for notifications in
                        notification_list.get_all_notifications()])
            notification.filter.click()
            notification_filter.message_input_box.clear()
            notification_filter.message_input_box.value = select_notification
            ActionCloseModal().action_button.click()

            # Verify the string is available in all the messages on the notification page
            assert all([select_notification in notifications for notifications in
                        notification_list.get_all_notifications()])
        elif operator == "does not contain":
            # Verify the notification count should be greater than zero
            assert filtered_notifications, \
                "No Notification found that contains {}".format(select_notification.rsplit(' ', 4)[0])

            # Verify any message should not contain the searched string
            assert not all([select_notification.rsplit(' ', 4)[0] in notifications
                            for notifications in notification_list.get_all_notifications()])
            notification.filter.click()
            notification_filter.message_input_box.clear()
            notification_filter.message_input_box.value = select_notification
            ActionCloseModal().action_button.click()

            # Verify any message should not contain the searched message
            assert not all([select_notification in notifications for notifications in
                            notification_list.get_all_notifications()])

        elif operator == "is equal to":
            # Verify the notification count should be zero for the searched string
            assert not filtered_notifications, \
                "Notification found that contains {}".format(select_notification.rsplit(' ', 4)[0])
            notification.filter.click()
            notification_filter.message_input_box.clear()
            notification_filter.message_input_box.value = select_notification
            ActionCloseModal().action_button.click()

            # Verify all message should be equal to the searched message
            assert all([select_notification == notifications for notifications in
                        notification_list.get_all_notifications()])
        else:
            # Verify the notification count should be greater than zero for the searched string
            assert filtered_notifications, \
                "No Notification found that contains {}".format(select_notification.rsplit(' ', 4)[0])
            notification.filter.click()
            notification_filter.message_input_box.clear()
            notification_filter.message_input_box.value = select_notification
            ActionCloseModal().action_button.click()

            # Verify searched string should not be available in any notification.
            assert select_notification not in notification_list.get_all_notifications(), \
                "{} is visible on notifications page".format(select_notification)


@pytest.fixture()
def remove_advanced_setting(request: SubRequest):
    """This fixture will remove any specific advanced setting from Nessus"""
    api = NessusAPI()
    api.login()
    setting_name = request.param.get('setting_name')

    def find_and_delete_given_setting():
        """This method will find if given setting exist in advanced settings and if yes then it will delete the same."""
        all_settings = api.settings.get_list()['preferences']
        setting_to_be_deleted = [setting for setting in all_settings if setting['name'] == setting_name]
        if setting_to_be_deleted:
            delete_payload = {'setting.0.action': 'remove', 'setting.0.id': setting_to_be_deleted[0]['id'],
                              'setting.0.name': setting_to_be_deleted[0]['name']}
            api.settings.update(delete_payload)
            log.debug("Setting - '{}' deleted successfully!!".format(setting_name))
        else:
            log.debug("'{}' setting not found".format(setting_name))

    find_and_delete_given_setting()
    yield
    find_and_delete_given_setting()
    api.logout()


@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('remove_advanced_setting', 'login')
@pytest.mark.parametrize('remove_advanced_setting', [{"setting_name": "acas_classification"}], indirect=True)
@pytest.mark.parametrize('add_advanced_setting', [{"name": "acas_classification", "value": "SECRET"}],
                         indirect=True)
class TestACASLoginNotifications:
    """Test cases related to ACAS login notifications"""

    def test_acas_successful_login_notification(self, add_advanced_setting):
        """

        NES-9877 : UI automation for ACAS login notifications NES-9701

        Scenarios:
            [x] Verify that unsuccessful login notification appears on Notification bar and
            notification history page when acas_classification has been set to "SECRET"

        Steps:
            1. Login to Nessus.
            2. Add a custom advanced setting having name "acas_classification" and value "SECRET".
            3. Logout from Nessus.
            4. Perform unsuccessful login for the given number of times.
            5. Perform successful login to Nessus.
            6. Verify that success messages appears on notification bar for successful login.
            7. Verify that error message appears on notification bar for unsuccessful login with
               specified count of attempts.
            8. Go to Notification history page.
            9. Verify that success message appears as latest notification on history page for successful login.
            10. Verify that error message appears on notification history page for unsuccessful login with
                specified count of attempts..
            11. Remove the advanced setting and logout from Nessus.
        """
        wait(lambda: AdvancedSettingsPage().is_element_present('search_textbox'),
             waiting_for="Advanced setting page to load properly")
        NotificationActions().remove_all()

        header_text = get_driver_no_init().find_element(By.CSS_SELECTOR, ".acas").text
        footer_text = get_driver_no_init().find_element(By.CSS_SELECTOR, ".acas.footer").text

        # Verify the header and footer text with setting value given in fixture.
        for text in [header_text, footer_text]:
            assert text == add_advanced_setting[1], 'Footer and header having name "%s" and value "%s" does not ' \
                                                    'exist'.format(add_advanced_setting[0], add_advanced_setting[1])

        UserMenu().logout()
        LoginPage().login_with_defaults()
        wait(lambda: visibility_of_element_located(HeaderBasePage().scan_link), waiting_for='Scan page to load')

        notification_bar_message = Notifications().successes[-1]

        # Verifying successful login notification.
        assert "Last successful login" in notification_bar_message, \
            "Recent notification success messages is not for Last successful login"

        NotificationsPage().open()
        latest_notification_history_message = NotificationsList().get_all_notifications()[0]
        latest_notification_history_message_1 = NotificationsList().get_all_notifications()[1]

        # Verifying successful login notification.
        if 'Plugins are done compiling' in latest_notification_history_message:
            assert "Last successful login" in latest_notification_history_message_1, \
                "Recent notification history messages is not for Last successful login"
        else:
            assert "Last successful login" in latest_notification_history_message, \
                "Recent notification history messages is not for Last successful login"

    @pytest.mark.parametrize('unsuccessful_login_attempt', [1, 2])
    def test_acas_unsuccessful_login_notification(self, add_advanced_setting, unsuccessful_login_attempt):
        """
        NES-9877 : UI automation for ACAS login notifications NES-9701

        Scenarios:
            [x] Verify that unsuccessful login notification appears on Notification bar and
            notification history page when acas_classification has been set to "SECRET"

        Steps:
            1. Login to Nessus.
            2. Add a custom advanced setting having name "acas_classification" and value "SECRET".
            3. Logout from Nessus.
            4. Perform unsuccessful login for the given number of times.
            5. Perform successful login to Nessus.
            6. Verify that success messages appears on notification bar for successful login.
            7. Verify that error message appears on notification bar for unsuccessful login with
               specified count of attempts.
            8. Go to Notification history page.
            9. Verify that success message appears as latest notification on history page for successful login.
            10. Verify that error message appears on notification history page for unsuccessful login with
                specified count of attempts..
            11. Remove the advanced setting and logout from Nessus.
        """

        wait(lambda: AdvancedSettingsPage().is_element_present('search_textbox'),
             waiting_for="Advanced setting page to load properly")
        notification_actions = NotificationActions()
        notification_actions.remove_all()

        header_text = get_driver_no_init().find_element(By.CSS_SELECTOR, ".acas").text
        footer_text = get_driver_no_init().find_element(By.CSS_SELECTOR, ".acas.footer").text

        # Verify the header and footer text with setting value given in fixture.
        for text in [header_text, footer_text]:
            assert text == add_advanced_setting[1], 'Footer and header having name "%s" and value "%s" does not ' \
                                                    'exist'.format(add_advanced_setting[0], add_advanced_setting[1])

        user_menu = UserMenu()
        user_menu.logout()
        login_page = LoginPage()

        # Performing unsuccessful login for the given number of times.
        for _ in range(unsuccessful_login_attempt):
            login_page.login_with_credentials(username="admin", password="abc")
            notification_actions.remove_all()

        login_page.login_with_defaults()
        notifications = Notifications()

        # Verifying successful login notification.
        assert "Last successful login" in notifications.successes[-1], \
            "Recent notification success messages is not for Last successful login"

        # Verifying unsuccessful login notification.
        assert "Last unsuccessful login" in notifications.errors[-1], \
            "Recent notification error messages is not for Last unsuccessful login"

        NotificationsPage().open()
        notifications = NotificationsList().get_all_notifications()

        if "Plugins are done" in notifications[0]:
            unsuccessful_attempts_count = notifications[2].split('(')[1].split(')')[0]

            # Verifying successful login notification.
            assert "Last successful login" in notifications[1], \
                "Recent notification history messages is not for Last successful login"

            # Verifying unsuccessful login notification.
            assert "Last unsuccessful login" in notifications[2], \
                "Recent notification history messages is not for Last unsuccessful login"

            # Verifying number of unsuccessful login attempts
            assert int(unsuccessful_attempts_count) == int(unsuccessful_login_attempt), \
                "Incorrect login attempt count in notification history is not matching with actual count"
        else:
            unsuccessful_attempts_count = notifications[1].split('(')[1].split(')')[0]

            # Verifying successful login notification.
            assert "Last successful login" in notifications[0], \
                "Recent notification history messages is not for Last successful login"

            # Verifying unsuccessful login notification.
            assert "Last unsuccessful login" in notifications[1], \
                "Recent notification history messages is not for Last unsuccessful login"

            # Verifying number of unsuccessful login attempts
            assert int(unsuccessful_attempts_count) == int(unsuccessful_login_attempt), \
                "Incorrect login attempt count in notification history is not matching with actual count"
