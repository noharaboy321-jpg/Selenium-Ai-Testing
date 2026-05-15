"""
Nessus page classes for login page

:copyright: Tenable Network Security, 2017
:date: August 25, 2017
:last_modified: January 16, 2018
:author: @rdutta, @mameta
"""

from selenium.webdriver.common.by import By
from waiting import wait

from catium.lib.cat_registry.metadata_registry import register_page_object
from catium.lib.const.base_constants import WAIT_LONG, TIME_THIRTY_SECONDS
from catium.lib.webium import Find
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.text_field import TextField
from nessus.lib.config import NessusConfig
from nessus.lib.const import Nessus
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.user_menu import UserMenu


@register_page_object()
class LoginPage(NessusBasePage):
    """Page Object for Login Page in Nessus."""

    username_field = Find(TextField, by=By.CSS_SELECTOR, value='.login-username')
    password_field = Find(TextField, by=By.CSS_SELECTOR, value='.login-password')
    sign_in_button = Find(by=By.CSS_SELECTOR, value='button[data-domselect="sign-in"]')
    remember_me_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='.login-remember')
    nessus_logo = Find(by=By.TAG_NAME, value='h1')
    copyright_year = Find(by=By.TAG_NAME, value='h3')

    def __init__(self):
        super().__init__()
        self.required_elements = ['username_field', 'password_field', 'sign_in_button']

    def login_with_defaults(self) -> None:
        """Automatically login using configuration or environment variables."""
        self._do_login(NessusConfig.CAT_NESSUS_USERNAME, NessusConfig.CAT_NESSUS_PASSWORD)

    def login_with_credentials(self, username: str, password: str, open_page: bool = True) -> None:
        """
        Login to Nessus using specified credentials.

        :param str username: The account username.
        :param str password: The account password.
        :param bool open_page: Flag for open method to use or not
        """
        self._do_login(username, password, open_page=open_page)

    def _do_login(self, username: str, password: str, open_page: bool = True) -> None:
        if open_page:
            self.open(timeout=TIME_THIRTY_SECONDS, load_after=False)
            if self._driver.capabilities['browserName'] == 'internet explorer':
                self._driver.get("javascript:document.getElementById('overridelink').click()");
        # To prevent login failure in local
        for creds in range(4):
            if self.username_field.value == "" or self.password_field.value == "":
                self.username_field.value = username
                self.password_field.value = password
        self.sign_in_button.click()

    @staticmethod
    def do_login() -> None:
        """Helper function to perform login to Nessus."""
        login_page = LoginPage()
        login_page.login_with_defaults()
        wait(predicate=lambda: (not login_page.find_elements('css selector', 'body.nosession-wrapper')),
             timeout_seconds=2 * WAIT_LONG, sleep_seconds=0.5, waiting_for='Dashboard/Scans page to appear')
        login_page.wait_for_xhr_requests()
        user_menu = UserMenu()
        user_menu.loaded()


@register_page_object()
class Wizard(NessusBasePage):
    """ helper method for wizard """

    @staticmethod
    def do_wizard() -> None:
        wizard = Wizard()
        wizard._do_wizard()

    def _do_wizard(self, open_page: bool = True):
        if open_page:
            self.open()

    def __init__(self):
        super().__init__()


class HostDiscoveryWizard(ActionCloseModal):
    """Page Object for Host Discovery Wizard in Nessus."""

    hd_wizard_targets = Find(by=By.CSS_SELECTOR, value='.host-discovery-wizard-targets__label')
    hd_wizard_header = Find(by=By.CSS_SELECTOR, value='.host-discovery-wizard-targets__header')
    hd_wizard_report_header = Find(by=By.CSS_SELECTOR, value='.host-discovery-wizard-report__header')
    hd_wizard_detail = Find(by=By.CSS_SELECTOR, value='.host-discovery-wizard-targets__detail')
    hd_wizard_targets_input = Find(TextField, by=By.CSS_SELECTOR, value='textarea[data-name="targets"]')
    hd_wizard_loading_circle = Find(by=By.CSS_SELECTOR, value='.loading-spinner')
    hd_wizard_discovery_checkmark = Find(by=By.CSS_SELECTOR, value='i.checkmark')
    hd_wizard_scan_host_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div.checkbox')
    hd_wizard_back_button = Find(by=By.XPATH, value='//a[contains(text(),"Back")]')
    hd_wizard_scanned_host = Find(by=By.CSS_SELECTOR, value='#DataTables_Table_0 > tbody > tr > td.w150')
    hd_table_length_dropdown = Find(by=By.CSS_SELECTOR, value='.dataTables_length')
    hd_table_pagination = Find(by=By.CSS_SELECTOR, value='.dataTables_paginate')
    hd_scan_complete = Find(by=By.CSS_SELECTOR, value='.discovery-complete')

    def create_host_discovery_scan_on_wizard(self) -> None:
        """
        Method to create Host Discovery Scan
        :return: None
        """
        self.hd_wizard_targets_input.value = Nessus.Scan.Target.LOCALHOST
        self.action_button.click()

    def create_host_discovery_scan_on_wizard_max_targets(self) -> None:
        """
        Method to create Host Discovery Scan with max hosts
        :return: None
        """
        self.hd_wizard_targets_input.value = Nessus.Scan.Target.MAX_DISCOVERY_TARGET
        self.action_button.click()

    def create_host_discovery_scan_on_wizard_max_local_targets(self) -> None:
        """
        Method to create Host Discovery Scan with max hosts
        :return: None
        """
        self.hd_wizard_targets_input.value = Nessus.Scan.Target.MAX_DISCOVERY_TARGET_LOCAL
        self.action_button.click()
