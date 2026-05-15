"""
Nessus page object class for Password Management page under settings

:copyright: Tenable Network Security, 2017
:date: May 21, 2018
:last_modified: May 25, 2018
:author: @rdutta
"""

from selenium.webdriver.common.by import By

from catium.lib.cat_registry import cat_registry
from catium.lib.const.base_constants import TIME_THREE_SECONDS
from catium.lib.webium import Find
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.text_field import TextField
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.shared.loading import LoadingCircle


@cat_registry.route('settings/password-management')
class PasswordManagement(NessusBasePage):
    """Page objects for password management page."""
    page_title = Find(by=By.CSS_SELECTOR, value='#titlebar h1')
    password_complexity_switch = Find(Clickable, by=By.CSS_SELECTOR, value='div[data-key="passwd_complexity"]')
    session_timeout_minutes = Find(TextField, by=By.CSS_SELECTOR, value='input[data-key="session_timeout"]')
    max_login_attempts = Find(TextField, by=By.CSS_SELECTOR, value='input[data-key="passwd_max_attempts"]')
    min_password_length = Find(TextField, by=By.CSS_SELECTOR, value='input[data-key="passwd_min_length"]')
    login_notification_switch = Find(Clickable, by=By.CSS_SELECTOR, value='div[data-key="passwd_notifications"]')
    login_notifications_enabled = Find(Clickable, by=By.CSS_SELECTOR,
                                       value='div[data-key="passwd_notifications"][data-value="on"]')
    save_button = Find(Clickable, by=By.CSS_SELECTOR, value='.button.secondary.floatleft.settings-save')
    cancel_button = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-domselect="cancel"]')
    password_complexity_toggle = Find(by=By.CSS_SELECTOR, value='div[data-key="passwd_complexity"] div.toggle')
    login_notification_toggle = Find(by=By.CSS_SELECTOR, value='div[data-key="passwd_notifications"] div.toggle')

    @property
    def page_header(self):
        """Returns the page title from header."""
        return self.page_title.text

    def get_saved_data(self) -> dict:
        """
        Get all saved data against according field from password management page and save it in dictionary
        :return: dict of all data
        :rtype dict
        """
        saved_details = {'password_complexity': self.password_complexity_switch.get_attribute('aria-pressed') == 'true',
                         'session_timeout': self.session_timeout_minutes.value,
                         'max_login_attempts': self.max_login_attempts.value,
                         'min_passwd_length': self.min_password_length.value,
                         'login_notification': self.login_notification_switch.get_attribute('aria-pressed') == 'true'}
        return saved_details

    def modify_password_settings(self, password_complexity: bool = False, session_timeout: int = 30,
                                 max_login_attempts: int = 0, min_passwd_length: int = 0,
                                 login_notification: bool = False) -> None:
        """
        Edit and manage password settings as per value specified otherwise set the default values.
        :param bool password_complexity: toggle on password complexity switch if true
        :param int session_timeout: input data in minutes for session to gets timeout
        :param int max_login_attempts: max login attempts
        :param int min_passwd_length: minimum length of settings up a password
        :param bool login_notification: toggle on login notification switch if true
        :return: None
        """
        if password_complexity:
            if not self.get_saved_data().get('password_complexity'):
                self.password_complexity_switch.click()
        else:
            if self.get_saved_data().get('password_complexity'):
                self.password_complexity_switch.click()

        self.session_timeout_minutes.value = session_timeout
        self.max_login_attempts.value = max_login_attempts
        self.min_password_length.value = min_passwd_length

        if login_notification:
            if not self.get_saved_data().get('login_notification'):
                self.login_notification_switch.click()
        else:
            if self.get_saved_data().get('login_notification'):
                self.login_notification_switch.click()

        LoadingCircle(TIME_THREE_SECONDS)
        self.save_button.click()
