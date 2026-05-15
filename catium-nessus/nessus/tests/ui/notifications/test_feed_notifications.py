"""
Nessus feed notifications related test cases
Notifications for this test suite are defined in nessus/tests/api/server/test_data/sample_notifications.json

:copyright: Tenable Network Security, 2019
:creation date: Feb 22, 2019
:last_modified: July 02, 2020
:author: @mdriscoll, @yshah, @kpanchal
"""
import json
import os
from datetime import timedelta

import pytest
from _pytest.fixtures import SubRequest
from cassandra.query import datetime
from selenium.webdriver.common.by import By
from selenium.webdriver.support.expected_conditions import invisibility_of_element_located

from catium.helpers.sleep_lib import sleep
from catium.lib.const.base_constants import TIME_SIXTY_SECONDS, WAIT_SHORT
from catium.lib.const.base_constants import TIME_TEN_SECONDS, TIME_THIRTY_SECONDS, WAIT_NORMAL
from catium.lib.log import create_logger
from catium.lib.util.util import random_name
from catium.lib.webium.driver import get_driver, get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.cli_command import upload
from nessus.helpers.license import close_welcome_nessus_10_modal_for_pro
from nessus.helpers.system import is_pro, is_expert
from nessus.lib.const.constants import API, Nessus
from nessus.lib.message.messages import Messages
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.header.notifications import Notifications, ModalNotifications, FeedBannerNotifications, \
    NotificationActions
from nessus.pageobjects.header.user_menu import UserMenu
from nessus.pageobjects.login.login_page import LoginPage
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.users.users_page import UsersPage, UserList
from nessus.tests.api.server.conftest import load_sample_notifications, _create_notifications_file, _reload_nessus

log = create_logger()


@pytest.fixture()
def keep_notifications_visible():
    orig = NessusBasePage.hide_notifications_flag
    NessusBasePage.hide_notifications_flag = False
    yield 1
    NessusBasePage.hide_notifications_flag = orig


@pytest.fixture()
def add_user_and_login(request: 'SubRequest'):
    """
    Clear any notifications from the screen, create a user, and login as it.

    On teardown it removes the new user and logs in as the original test user.
    """
    username = request.param['user_name']
    role = request.param['role']

    user_page = UsersPage()
    user_menu = UserMenu()
    login_page = LoginPage()

    try:
        _remove_feed_notifications()

        user_page.open()
        user_page.add_new_user(user_name=username, password='p@ssw0rd123', email='test@tenable.com', role=role)

        user_menu.logout()
        login_page.login_with_credentials(username=username, password='p@ssw0rd123')

        yield
    finally:
        Notifications().list()

        user_menu.logout()
        login_page.login_with_defaults()

        _remove_feed_notifications()

        user_page.open()
        UserList().delete_user(user_name=username)


@pytest.fixture()
def load_license_expire_notifications(request: 'SubRequest'):
    """
    Copies test_data/sample_notifications.json to the nessus installation
    and triggers them to be loaded.

    On teardown it removes the notifications.
    """
    file_name = request.param['file_name'] if hasattr(request, 'param') and 'file_name' in request.param else \
        'sample_notifications.json'
    api = NessusAPI()
    tmp_file = _create_notifications_file(file_name)

    with open(tmp_file, 'r') as f:
        notes_json = json.load(f)

    log.info('Inserting sample notifications')
    upload(tmp_file, '/opt/nessus/var/nessus/notifications.json')
    os.unlink(tmp_file)
    _reload_nessus(api)
    log.info('Done inserting sample notifications')

    yield notes_json

    log.info('Removing sample notifications')
    notifications_file = 'nessus/tests/api/server/test_data/default_notifications.json'
    upload(notifications_file, '/opt/nessus/var/nessus/notifications.json')
    _reload_nessus(api)
    log.info('Done removing sample notifications')


def _remove_feed_notifications():
    """
    Removes modal and login feed notifications.
    """
    ModalNotifications().list()
    Notifications().list()
    NotificationActions().remove_all()


@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('load_sample_notifications', 'keep_notifications_visible', 'login')
class TestFeedNotifications:
    """ Tests related to notifications that come from the plugin feed. """

    def get_index(self, notifications, text):
        for i, n in enumerate(notifications):
            if n['text'] == text:
                return i

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    def test_feed_notifications_order(self):
        """
        Test the ordering of the three types of feed notifications

        [x] Verify that 'modal' notifications are ordered correctly
        [x] Verify that 'login' notifications are ordered correctly
        [x] Verify that 'banner' notifications are ordered correctly
        """
        modals = ModalNotifications().list()
        logins = Notifications().list()
        banners = FeedBannerNotifications().list()

        assert self.get_index(modals, 'Modal High.') < self.get_index(modals, 'Modal Medium.'), \
            "Modal ordering incorrect"
        assert self.get_index(modals, 'Modal Medium.') < self.get_index(modals, 'Modal Low.'), \
            "Modal ordering incorrect"
        if is_expert():
            assert True
        else:
            assert self.get_index(logins, 'Login High.') < self.get_index(logins, 'Login Medium.'), \
                "Login ordering incorrect"
            assert self.get_index(logins, 'Login Medium.') < self.get_index(logins, 'Login Low.'), \
                "Login ordering incorrect"
        assert self.get_index(banners, 'Banner High.') < self.get_index(banners, 'Banner Medium.'), \
            "Banner ordering incorrect"
        assert self.get_index(banners, 'Banner Low.') < self.get_index(banners, 'Banner Medium.'), \
            "Banner ordering incorrect"

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    def test_feed_notifications_permanent(self):
        """
        Test UI features of permanent notifications

        [x] Verify that permanent modal notifications have no 'Acknowledge' button
        [x] Verify that permanent login notifications have no 'Trashcan' button
        [x] Verify that permanent banner notifications have no 'Dismiss' link
        """
        modals = ModalNotifications().list()
        logins = Notifications().list()
        banners = FeedBannerNotifications().list()

        for m in modals:
            if m['title'] == 'Permanent':
                assert m['permanent'], '"%s" modal notification has an Ack button' % m['title']
            if m['title'] == 'Modal Low':
                assert not m['permanent'], '"%s" notification has no Ack button' % m['title']
        for l in logins:
            if l['text'] == 'Login Low.':
                assert l['permanent'], '"%s" notification has a Bin button' % l['title']
            if l['text'] == 'Login High.':
                assert not l['permanent'], '"%s" notification has no Bin button' % l['title']
        for b in banners:
            if b['text'] == 'Banner Permanent.':
                assert b['permanent'], '"%s" notification has a Dismiss button' % b['title']
            if b['text'] == 'Banner High.':
                assert not b['permanent'], '"%s" notification has no Dismiss button' % b['title']

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    def test_notification_ack_for_feed_notifications(self):
        """
        Test UI features of permanent notifications

        [x] Verify that modal notifications can be acknowledged
        [x] Verify that login notifications can be acknowledged
        [x] Verify that banner notifications can be acknowledged
        """
        to_dismiss = ['Modal Low.', 'Login High.', 'Banner Low.']
        modals = ModalNotifications().list(dismiss_list=to_dismiss)
        logins = Notifications().list(dismiss_list=to_dismiss)
        banners = FeedBannerNotifications().list(dismiss_list=to_dismiss)

        assert 'Modal Low.' in [x['text'] for x in modals], "Notification wasn't present in test start"
        assert 'Login High.' in [x['text'] for x in logins], "Notification wasn't present in test start"
        assert 'Banner Low.' in [x['text'] for x in banners], "Notification wasn't present in test start"

        # removed the code due to NES-17626 as expected. (after refreshing the page popup will not appear)
    @pytest.mark.parametrize('add_user_and_login', [
        {'user_name': random_name(prefix=API.User.Users.STANDARD_USER + ' - '), 'role': API.User.Role.STANDARD},
        {'user_name': random_name(prefix=API.User.Users.BASIC_USER + ' - '), 'role': API.User.Role.BASIC},
        {'user_name': random_name(prefix=API.User.Users.ADMIN_USER + ' - '), 'role': API.User.Role.ADMIN},
        {'user_name': random_name(prefix=API.User.Users.SYS_ADMIN_USER + ' - '), 'role': API.User.Role.SYS_ADMIN}],
                             indirect=True)
    @pytest.mark.xfail(reason='Expected as per NES-17626. No model will appear after refresh or logout')
    def test_acknowledge_button_for_non_admin_user(self, add_user_and_login):
        """
        NES-9558: NES-9550 Per-user notification acknowledgements

        Scenario Tested:
        [x] Verify that "Acknowledge" option should be displayed to all the users despite acknowledged by any user.

        Steps:
        1. Login as admin user and acknowledge all the modals.
        2. Create Standard user.
        3. Login as standard user and verify all the modal with acknowledge button should be visible.
        4. Dismiss the modal.
        5. Repeat the steps for Basic, Sys-Admin user.
        """
        modal_notification = ModalNotifications()

        for _ in range(15):
            if not modal_notification.is_element_present('modal'):
                break
            # Verify modal text must be in acknowledgement modal text list.
            assert modal_notification.modal_text.text in Nessus.AcknowledgementModal.ACKNOWLEDGEMENT_MODAL_TEXT_LIST, \
                "Modal text is not in the acknowledgement modal text list"
            if modal_notification.is_element_present('modal_acknowledge', timeout=TIME_TEN_SECONDS):
                modal_notification.modal_acknowledge.click()
            else:
                modal_notification.modal_dismiss.click()

            # Wait till loading circle to disappear
            LoadingCircle(WAIT_NORMAL)

    def test_visibility_of_popup_for_new_user_created_once_acknowledged_popup(self):
        """
        NES-9558: NES-9550 Per-user notification acknowledgements

        Scenario Tested:
        [x] Verify that "Acknowledge" option should be displayed to the new users created after acknowledged by any
        user.

        Steps:
        1. Login as admin user and acknowledge all the modals.
        2. Create a new user and login with new user credentials.
        3. Verify all the modal with acknowledge button should be visible.
        """
        modal_notification = ModalNotifications()
        modal_notification.modal_dismiss.click()

        for _ in range(15):
            if not modal_notification.is_element_present('modal'):
                break
            modal_notification.modal_acknowledge.click()

        user_page = UsersPage()
        user_page.open()
        wait(lambda: user_page.is_element_present("new_user_button"), timeout_seconds=TIME_THIRTY_SECONDS)

        user_name = random_name(prefix=API.User.Users.BASIC_USER)
        password = 'p@ssw0rd123'
        notification_action = NotificationActions()

        for _ in range(5):
            if not notification_action.is_element_present('offer_notifications'):
                break
            notification_action.remove_all()

        user_page.add_new_user(user_name=user_name, password=password, email='test@tenable.com',
                               role=API.User.Role.BASIC)
        UserMenu().logout()
        LoginPage().login_with_credentials(username=user_name, password=password)

        wait(lambda: modal_notification.modal_title.text == "Permanent", timeout_seconds=TIME_TEN_SECONDS)
        modal_notification.modal_dismiss.click()

        for _ in range(10):
            if not modal_notification.is_element_present('modal'):
                break
                # Verify modal text must be in acknowledgement modal text list.
            assert modal_notification.modal_text.text in Nessus.AcknowledgementModal.ACKNOWLEDGEMENT_MODAL_TEXT_LIST, \
                "Modal text is not in the acknowledgement modal text list"
            if modal_notification.is_element_present('modal_acknowledge', timeout=TIME_TEN_SECONDS):
                modal_notification.modal_acknowledge.click()
            else:
                modal_notification.modal_dismiss.click()


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('keep_notifications_visible', 'login')
class TestFeedNotificationsHTMLLinks:
    """ Tests related to HTML links in feed notifications, modals and banners. """

    @pytest.mark.parametrize('load_sample_notifications', [{'file_name': "sample_link_notifications.json"}],
                             indirect=True)
    def test_html_link_in_feed_notification(self, load_sample_notifications):
        """
        NES-9059: UI test for HTML support in feed notifications

        Scenario Tested:
        [x] Verify that html link is displayed and clickable for feed notifications, modals and banners.
        """
        # Verify HTML link in notification modals.
        modal_notification = ModalNotifications()

        assert modal_notification.is_element_present('modal'), 'Notification modal is not displayed after login.'

        assert modal_notification.is_element_present('modal_link'), "HTML link is not visible in notification modal."

        modal_link_url = modal_notification.get_href_from_link(modal_notification.modal_link)
        modal_notification.modal_link.click()

        assert modal_link_url == modal_notification.switch_window_and_get_url(), \
            'HTML link is not clickable and opened in new tab.'
        # Close all modals
        modal_notification.list()

        # Verify HTML link in notifications.
        notification = Notifications()

        assert notification.is_element_present('notification_link'), 'HTML link is not visible in notifications.'

        notification_link_url = notification.get_href_from_link(notification.notification_link)
        notification.notification_link.click()

        assert notification_link_url == notification.switch_window_and_get_url(), \
            'HTML link is not clickable and opened in new tab.'

        feed_banner = FeedBannerNotifications()

        # Verify HTML in Feed notification banners.
        assert feed_banner.is_element_present('feed_banner'), 'Feed notification banner is not visible.'

        # Verify HTML link in Feed notification banners.
        assert feed_banner.is_element_present('feed_banner_link'), 'HTML link is not visible in feed notification ' \
                                                                   'banner.'

        feed_banner_link = feed_banner.get_href_from_link(feed_banner.feed_banner_link)
        # Click on HTML link in Feed notification banners.
        feed_banner.feed_banner_link.click()

        assert feed_banner_link == feed_banner.switch_window_and_get_url(), \
            'HTML link is not clickable and opened in new tab.'


@pytest.mark.license_change
@pytest.mark.usefixtures('login')
class TestLicenseExpiresNotifications:
    """ Tests related to modal notifications for License Expiration. """

    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("load_license_expire_notifications", [{"file_name": "license_expire_notifications.json"}],
                             indirect=True)
    @pytest.mark.parametrize('setup_nessus_with_expiration_days', [{"expiration_days": 60}], indirect=True)
    def test_nessus_pro_license_expiration_notifications(self, load_license_expire_notifications,
                                                         setup_nessus_with_expiration_days):
        """
        NES-9586: UI automation - License constraints in notifications

        Scenarios:
            [x] Verify the notification modal when 60 days left to license expire.
            [ ] Verify the notification modal on the day when license expires. - Not supported anymore
            [ ] Verify the notification modal when license is already expired 7 days ago. - Not supported anymore

        Steps:
        1. Update the activation code to get the license with expiration days as set in parametrization (In fixture).
        2. Login and verify the modal content.
        3. Verify click on link should redirect the user to "https://www.tenable.com/"
        4. Acknowledge the modal.
        5. Update the activation code with expiration days as 365 to reset the license.
        6. Repeat the steps #1-#5 for the days 0 days and -7 days.
        """
        expiration_day = setup_nessus_with_expiration_days
        warning_message = None
        wait(lambda: LoginPage().is_element_present("username_field"), timeout_seconds=TIME_SIXTY_SECONDS)
        LoginPage().login_with_defaults()
        wait(lambda: invisibility_of_element_located((By.CSS_SELECTOR, '.login-username'))(get_driver()),
             waiting_for='Modal is closed', timeout_seconds=TIME_SIXTY_SECONDS)

        if is_pro():
            close_welcome_nessus_10_modal_for_pro()

        modal_notification = ModalNotifications()

        # Verify the modal is visible on successful login.
        assert modal_notification.is_element_present('modal'), 'Notification modal is not displayed after login.'

        license_expiration_date = datetime.today().date() + timedelta(days=expiration_day)
        expiration_modal_title = modal_notification.modal_title.text
        expiration_modal_message = modal_notification.modal_text.text.split(".")[0]

        nessus_base_page = NessusBasePage()

        if expiration_day > 0:
            # Verify the modal title.
            assert expiration_modal_title == Nessus.About.LICENSE_EXPIRING_SOON, \
                'Getting incorrect modal title, expected is {}.'.format(Nessus.About.LICENSE_EXPIRING_SOON)

            warning_message = Messages.ExpiredLicense.warning_message_for_future.format((expiration_day - 1),
                                                                                        license_expiration_date)

            # Verify the link text on the modal.
            assert modal_notification.modal_link.text == Nessus.About.RENEW_NESSUS, \
                'Getting incorrect link text, expected is {}.'.format(Nessus.About.RENEW_NESSUS)

        elif expiration_day <= 0:
            # Verify the modal title.
            assert expiration_modal_title == Nessus.About.LICENSE_EXPIRED, \
                'Getting incorrect modal title, expected is {}.'.format(Nessus.About.LICENSE_EXPIRED)

            # Verify the link text on the modal.
            assert modal_notification.modal_link.text == Nessus.About.RENEW_NESSUS_LICENSE, \
                'Getting incorrect link text, expected is {}.'.format(Nessus.About.RENEW_NESSUS_LICENSE)

            if expiration_day < 0:
                warning_message = Messages.ExpiredLicense.warning_for_expired_license.format(license_expiration_date,
                                                                                             abs(expiration_day))
            else:
                warning_message = Messages.ExpiredLicense.warning_message_today.format(license_expiration_date)

        # Verify the modal text.
        assert warning_message == expiration_modal_message, 'Getting incorrect notification message, ' \
                                                            'expected is {}.'.format(warning_message)

        # Verify the modal acknowledge button is displayed
        assert modal_notification.is_element_present('modal_acknowledge'), "'Acknowledge' button is not displayed'"

        # Verify the modal link is displayed
        assert modal_notification.is_element_present('modal_link'), "'Renew Nessus' link is not displayed."

        modal_link_url = 'https://www.tenable.com/'
        modal_notification.modal_link.click()

        # Verify the link when user clicks on modal link.
        assert modal_link_url == nessus_base_page.switch_window_and_get_url(), \
            "'Renew Nessus' link is not clickable and opened in new tab."

        modal_notification.modal_acknowledge.click()

    @pytest.mark.nessus_manager
    @pytest.mark.parametrize("load_license_expire_notifications", [{"file_name": "license_expire_notifications.json"}],
                             indirect=True)
    @pytest.mark.parametrize('setup_nessus_with_expiration_days', [{"expiration_days": 60},
                                                                   {"expiration_days": 0},
                                                                   {"expiration_days": -7}], indirect=True)
    def test_nessus_manager_license_expiration_notifications(self, load_license_expire_notifications,
                                                             setup_nessus_with_expiration_days):
        """
        NES-9586: UI automation - License constraints in notifications

        Scenarios:
            [x] Verify the notification modal when 60 days left to license expire.
            [x] Verify the notification modal on the day when license expires.
            [x] Verify the notification modal when license is already expired 7 days ago.

        Steps:
        1. Update the activation code to get the license with expiration days as set in parametrization (In fixture).
        2. Login and verify the modal content.
        3. Verify click on link should redirect the user to "https://www.tenable.com/"
        4. Acknowledge the modal.
        5. Update the activation code with expiration days as 365 to reset the license.
        6. Repeat the steps #1-#5 for the days 0 days and -7 days.
        """
        expiration_day = setup_nessus_with_expiration_days
        warning_message = None
        wait(lambda: LoginPage().is_element_present("username_field"), timeout_seconds=TIME_SIXTY_SECONDS)
        LoginPage().login_with_defaults()
        wait(lambda: invisibility_of_element_located((By.CSS_SELECTOR, '.login-username'))(get_driver()),
             waiting_for='Modal is closed', timeout_seconds=TIME_SIXTY_SECONDS)

        if is_pro():
            close_welcome_nessus_10_modal_for_pro()

        modal_notification = ModalNotifications()

        # Verify the modal is visible on successful login.
        assert modal_notification.is_element_present('modal'), 'Notification modal is not displayed after login.'

        license_expiration_date = datetime.today().date() + timedelta(days=expiration_day)
        expiration_modal_title = modal_notification.modal_title.text
        expiration_modal_message = modal_notification.modal_text.text.split(".")[0]

        nessus_base_page = NessusBasePage()

        if expiration_day > 0:
            # Verify the modal title.
            assert expiration_modal_title == Nessus.About.LICENSE_EXPIRING_SOON, \
                'Getting incorrect modal title, expected is {}.'.format(Nessus.About.LICENSE_EXPIRING_SOON)

            warning_message = Messages.ExpiredLicense.warning_message_for_future.format((expiration_day - 1),
                                                                                        license_expiration_date)

            # Verify the link text on the modal.
            assert modal_notification.modal_link.text == Nessus.About.RENEW_NESSUS, \
                'Getting incorrect link text, expected is {}.'.format(Nessus.About.RENEW_NESSUS)

        elif expiration_day <= 0:
            # Verify the modal title.
            assert expiration_modal_title == Nessus.About.LICENSE_EXPIRED, \
                'Getting incorrect modal title, expected is {}.'.format(Nessus.About.LICENSE_EXPIRED)

            # Verify the link text on the modal.
            assert modal_notification.modal_link.text == Nessus.About.RENEW_NESSUS_LICENSE, \
                'Getting incorrect link text, expected is {}.'.format(Nessus.About.RENEW_NESSUS_LICENSE)

            if expiration_day < 0:
                warning_message = Messages.ExpiredLicense.warning_for_expired_license.format(license_expiration_date,
                                                                                             abs(expiration_day))
            else:
                warning_message = Messages.ExpiredLicense.warning_message_today.format(license_expiration_date)

        # Verify the modal text.
        assert warning_message == expiration_modal_message, 'Getting incorrect notification message, ' \
                                                            'expected is {}.'.format(warning_message)

        # Verify the modal acknowledge button is displayed
        assert modal_notification.is_element_present('modal_acknowledge'), "'Acknowledge' button is not displayed'"

        # Verify the modal link is displayed
        assert modal_notification.is_element_present('modal_link'), "'Renew Nessus' link is not displayed."

        modal_link_url = 'https://www.tenable.com/'
        modal_notification.modal_link.click()

        # Verify the link when user clicks on modal link.
        assert modal_link_url == nessus_base_page.switch_window_and_get_url(), \
            "'Renew Nessus' link is not clickable and opened in new tab."

        modal_notification.modal_acknowledge.click()


@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login', 'login')
class TestAcknowledgeModalWithTime:
    """ This class covers the test cases related to 'acknowledge_duration_secs' parameter in notifications.json file"""

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("load_sample_notifications", [{"file_name": "notifications_ack_set_time.json"}],
                             indirect=True)
    def test_modal_acknowledge_should_display_with_defined_time(self, load_sample_notifications):
        """
        NES-9631: NES-9548 Allow users to acknowledge notifications for a configurable length of time

        Scenario Tested:
            [x] All notifications should be shown immediately.
            [x] Notification should not re-appear on page refresh, if acknowledging a notification without
                "acknowledge_duration_secs"
            [x] Notification should appear on page refresh after the number of seconds has passed, if acknowledging a
                notification without "acknowledge_duration_secs"

        Steps:
        1. Login as admin user and acknowledge all the modals.
        2. Wait for 30 Sec (As set) and refresh the page.
        3. Verify the modal appear on page refresh after the number of seconds has passed if it has parameter
           "acknowledge_duration_secs" passed
        4. Verify the modal should not appear if it does not have parameter "acknowledge_duration_secs" passed.
        """
        sample_notification = load_sample_notifications['notifications'][0]['message']
        general_notification = load_sample_notifications['notifications'][1]['message']
        modal_notification = ModalNotifications()
        wait(lambda: modal_notification.is_element_present('modal'), waiting_for="Modal to appear")

        # Verify modal should appear with title "General_notification"
        assert modal_notification.modal_text.text == general_notification, \
            "Modal text is different than expected, modal text is '{}' but expected text is '{}'".format(
                modal_notification.modal_text.text, general_notification)
        modal_notification.modal_acknowledge.click()
        LoadingCircle(WAIT_SHORT)

        # Verify modal should appear with title "Sample_notification"
        wait(lambda: modal_notification.is_element_present('modal'), waiting_for="Modal to appear")
        assert modal_notification.modal_text.text == sample_notification, \
            "Modal text is different than expected, modal text is '{}' but expected text is '{}'".format(
                modal_notification.modal_text.text, sample_notification)
        sleep(sleep_time=TIME_THIRTY_SECONDS, reason="Need to wait for 30 sec to re-appear the modal")
        get_driver_no_init().refresh()

        # Verify there is no modal should re-appear.
        assert not modal_notification.is_element_present('modal'), \
            "Modal has modal text {} is visible".format(modal_notification.modal_text.text)
