"""
Nessus setup page 

:copyright: Tenable Network Security, 2017
:date: August 25, 2017
:last_modified: April 18, 2023
:author: @mameta, @kpanchal, @krpatel
"""

from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement

from catium.lib import const
from catium.lib.activation_code_generator import ActivationCodeGenerator
from catium.lib.config.environment_variables import CommonConfig
from catium.lib.const import WAIT_SHORT, TIME_FIVE_MINUTES
from catium.lib.webium import Find
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.wait import wait
from nessus.lib.config import NessusConfig
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.login.login_page import LoginPage
# TODO: have a base Nessus exception class object.
from nessus.pageobjects.shared.loading import LoadingCircle


class SettingsButtonNotPresentError(Exception):
    """Raised when the button for changing the download site for the activation code registration."""


class SetupCommonPoints(NessusBasePage):
    """element locators of setup wizard welcome window"""
    welcome_dialog_box = Find(by=By.CSS_SELECTOR, value='.register-content h2')
    copy_right_info = Find(by=By.CSS_SELECTOR, value='.nosession-content.preauth-content h3')
    body_area_text = Find(by=By.TAG_NAME, value='body')
    nessus_icon = Find(by=By.CSS_SELECTOR, value='.nosession-content.preauth-content h1')
    download_failed = Find(by=By.CSS_SELECTOR, value='.nosession-content.preauth-content h2')
    download_failed_message = Find(by=By.CSS_SELECTOR, value=".nosession-content.preauth-content .desc.mb20")
    run_nessus_cli_message = Find(by=By.CSS_SELECTOR, value=".nosession-content.preauth-content ul li:nth-child(1)")
    contact_tenable_support = Find(by=By.CSS_SELECTOR, value=".nosession-content.preauth-content ul li:nth-child(2)")
    install_expired = Find(by=By.CSS_SELECTOR, value='.nosession-content.preauth-content h2')
    tenable_customer_support = Find(Clickable, by=By.CSS_SELECTOR, value='.nosession-content.preauth-content ul '
                                                                         'li:nth-child(1) a')
    tenable_renewals = Find(Clickable, by=By.CSS_SELECTOR, value='.nosession-content.preauth-content ul '
                                                                 'li:nth-child(2) a')

    @property
    def welcome_text(self):
        """returns visible text of welcome note"""
        return self.welcome_dialog_box.text

    @staticmethod
    def setup_element_present(element, visibility=True):
        """returns True if setup wizard's elements are present"""
        return True if element.is_displayed() == visibility else False

    @property
    def copyright_text(self):
        """returns visible text of copyright"""
        return self.copy_right_info.text


class SetupPage(NessusBasePage):
    """Page Object for the Welcome page."""

    continue_button = Find(by=By.CSS_SELECTOR, value='button[data-name="Continue"]')

    _registration_types = {
        'all': ['NESSUS', 'SCANNER', 'SECURITYCENTER', 'OFFLINE'],
        'activation_code': ['NESSUS', 'SCANNER']
    }

    def __init__(self):
        super().__init__()
        self.required_elements = ['continue_button']

    # TODO: Discuss best approach
    def setup_application(self, username, password, registration_type: str = 'NESSUS', timeout: int = 1200):
        """
        This method performs automatic setup of Nessus.

        :param str username: The desired account username.
        :param str password: The desired account password.
        :param str registration_type: Registration Type
                                      Supported Options: NESSUS, SCANNER, SECURITYCENTER and OFFLINE.
        :param int timeout: Amount of time to wait (in seconds) for setup to complete. Default: 1200.
        :raises: ValueError

        .. note:: This method assumes that the Nessus Application is in a fresh install state.
        .. note:: The registration type is set to Nessus (Home, Professional or Manager)
        .. note:: The activation code is retrieved automatically.
        .. note:: The Plugin Feed Custom Host is set to CAT_PLUGIN_FEED_HOST
        .. note:: We use sleep() to slow the driver down to prevent UI communication errors

        .. warning:: This operation is time consuming.

        Valid Registration Types::
            NESSUS: Nessus (Home, Professional or Manager)
            SCANNER: Nessus Scanner
            SECURITYCENTER: Managed by SecurityCenter
            OFFLINE: Offline
        """

        activation_code = ''
        custom_host = ''

        if registration_type not in self._registration_types['all']:
            raise ValueError('Invalid value for registration_type.')

        if registration_type in self._registration_types['activation_code']:
            # Plugin Feed Custom Host
            custom_host = NessusConfig.CAT_PLUGIN_FEED_HOST

            # Retrieve a Nessus Plugin activation code
            activation_code = ActivationCodeGenerator.generate_code(ActivationCodeGenerator.NESSUS_PROFESSIONAL)

        self.loaded()
        self.continue_button.click()
        LoadingCircle(WAIT_SHORT)

        # On Account Setup page
        page = AccountSetupPage()
        page.loaded()
        page.setup_account(username, password)
        LoadingCircle(WAIT_SHORT)

        # On Product Registration page
        page = ProductRegistrationPage()
        page.loaded()
        page.registration_select.select_option(registration_type)

        if registration_type in self._registration_types['activation_code']:
            # Interact with the Custom/Advanced Settings modal
            page.click_advanced_settings()

            advanced_settings_modal = AdvancedSettingsModal()
            advanced_settings_modal.custom_host_field.value = custom_host
            advanced_settings_modal.save_button.click()

            # Wait for the modal to close
            wait(lambda: advanced_settings_modal.is_element_present('modal') is False,
                 timeout_seconds=const.TIME_FIVE_SECONDS,
                 waiting_for='Settings modal to close.')

        page.activation_code_field.value = activation_code

        page.loaded()
        page.continue_button.click()

        page = LoginPage()
        wait(lambda: page.is_element_present('sign_in_button') is True, timeout_seconds=timeout,
             waiting_for='Nessus setup to complete.')


class LoginSetupPage(NessusBasePage):
    """Page Object for the Login page."""

    login_username = Find(TextField, by=By.CSS_SELECTOR, value='input[aria-label="Username"]')
    login_password = Find(TextField, by=By.CSS_SELECTOR, value='input[aria-label="Password"]')
    sign_in_button = Find(Clickable, by=By.CSS_SELECTOR, value='button[data-domselect="sign-in"]')
    sensor_tab = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-topnav-menu="sensors"]')
    linked_scanner = Find(Clickable, by=By.CSS_SELECTOR, value='a[href="#/sensors/scanners"]')

    def __init__(self):
        super().__init__()
        self.required_elements = ['login_username', 'login_password', 'sign_in_button']


class AccountSetupPage(NessusBasePage):
    """Page Object for the Account Setup page."""

    account_setup_dialog = Find(by=By.CSS_SELECTOR, value='.nosession-content.register h4')
    username_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="Username"]')
    login_username = Find(TextField, by=By.CSS_SELECTOR, value='input[aria-label="Username"]')
    login_password = Find(TextField, by=By.CSS_SELECTOR, value='input[aria-label="Password"]')
    password_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="Password"]')
    confirm_password_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="Confirm Password"]')
    show_password = Find(by=By.CSS_SELECTOR, value='i[data-domselect="Show Password"]')
    continue_button = Find(by=By.CSS_SELECTOR, value='button[data-name="Continue"]')
    back_button = Find(by=By.CSS_SELECTOR, value='a[data-name="Back"]')

    def __init__(self):
        super().__init__()
        self.required_elements = ['username_field', 'confirm_password_field', 'continue_button']

    def setup_account(self, username: str, password: str) -> None:
        """
        This method automatically fills out the Account Setup form and submits it.
        :param username:  username
        :param password:  password
        """
        self.username_field.value = username
        self.password_field.value = password
        self.continue_button.click()


class ProductRegistrationPage(NessusBasePage):
    """Page Object for the Product Registration page."""

    registration_select = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-name="Activation Method"]')
    activation_code_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="Activation Code"]')
    activation_key_textarea = Find(TextField, by=By.CSS_SELECTOR, value='textarea[data-name="Activation Key"]')
    manager_host_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="Manager Host"]')
    manager_port_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="Manager Port"]')
    manager_key_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="Manager Key"]')
    use_proxy_checkbox = Find(by=By.CSS_SELECTOR, value='div[data-name="Manager Proxy"][class~="checkbox"]')
    continue_button = Find(by=By.CSS_SELECTOR, value='button[data-name="Continue"]')
    back_button = Find(by=By.CSS_SELECTOR, value='a[data-name="Back"]')
    custom_settings_button = Find(by=By.CSS_SELECTOR, value='a[data-name="Custom Settings"]')
    advanced_settings_button = Find(by=By.CSS_SELECTOR, value='a[data-name="Advanced Settings"]')
    error = Find(by=By.CSS_SELECTOR, value='.notification.error>span')
    linking_key = Find(by=By.CSS_SELECTOR, value='input[data-name="Linking Key"]')
    help_tool_tip = Find(by=By.CSS_SELECTOR, value='i[class="glyphicons question add-tip"]')
    registering_scanner_link = Find(by=By.CSS_SELECTOR, value='a[href*="register"]')
    click_here_button = Find(by=By.CSS_SELECTOR, value='a[href*="offline.php"]')
    nessus_license_textbox = Find(by=By.CSS_SELECTOR, value='textarea[data-name="Nessus License"]')
    nessus_page_element = Find(by=By.CSS_SELECTOR, value='input[name="challenge"]')
    challenge_code = Find(by=By.CSS_SELECTOR, value='span[data-name="Challenge"]')
    challenge_code_textbox = Find(by=By.CSS_SELECTOR, value='input[name="challenge"]')
    activation_code_textbox = Find(by=By.CSS_SELECTOR, value='input[name="activation_code"]')
    submit = Find(by=By.CSS_SELECTOR, value='input[value="Submit"]')
    initializing_setup = Find(by=By.CSS_SELECTOR, value='div[class*="loading-progress-status"]')
    setting_button = Find(Clickable, by=By.CSS_SELECTOR, value=".button.link.settings")

    def __init__(self):
        super().__init__()
        self.required_elements = ['continue_button']

    def dynamic_element(self, element_name: str) -> WebElement:
        """
        returns dynamic element
        :param str element_name: element name
        :return: WebElement
        """
        return Find(by=By.XPATH, value='.//*[contains(text(), "{}")]'.format(element_name), context=self)

    def click_advanced_settings(self) -> None:
        """
        Clicks the 'Advanced Settings' button (really a link element).

        .. note:: Nessus 6.7.0+ changed the 'Custom Settings' element to 'Advanced Settings', with that said
            this method handles before elements. This method falls back to 'Custom Settings' element if
            'Advanced Settings' element isn't present.

        :raises: SettingsButtonNotPresentError
        :returns: None
        :rtype: None
        """
        if self.is_element_present('advanced_settings_button'):
            self.advanced_settings_button.click()
            return None

        if self.is_element_present('custom_settings_button'):
            self.custom_settings_button.click()
            return None

        raise SettingsButtonNotPresentError('Cannot locate "Advanced Settings" or "Custom Settings" button.')


class AdvancedSettingsModal(NessusBasePage):
    """Page Object for the Advanced Settings modal window."""

    modal = Find(value='modal')
    close_icon = Find(by=By.CSS_SELECTOR, value='div.modal-close > i.remove')
    proxy_tab = Find(by=By.CSS_SELECTOR, value='a[data-domselect="Proxy"]')
    host_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="Proxy"]')
    port_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="Proxy Port"]')
    username_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="Proxy Username"]')
    password_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="Proxy Password"]')
    custom_host_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="Custom Host"]')
    save_button = Find(by=By.CLASS_NAME, value='modal-action')
    cancel_button = Find(by=By.CLASS_NAME, value='modal-close')
    new_cancel_button = Find(Clickable, by=By.CSS_SELECTOR, value='a.modal-close')
    plugin_feed = Find(by=By.CSS_SELECTOR, value='a[data-domselect="Plugin Feed"]')
    master_feed = Find(by=By.CSS_SELECTOR, value='a[data-domselect="Master Password"]')
    auth_method_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-name="Proxy Auth Method"]')
    user_agent_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="Proxy User-Agent"]')
    master_field_password = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="New Password"]')

    def __init__(self):
        super().__init__()
        wait(lambda: self.is_element_present('modal', timeout=5), waiting_for='Settings modal to appear.')

    def set_up_plugin_feed_during_registration(self, custom_host: str = CommonConfig.CAT_PLUGIN_FEED_HOST) -> None:
        """
        Set up plugin feed while registration
        :return: None
        """
        self.plugin_feed.click()
        self.custom_host_field.value = custom_host
        self.save_button.click()
        ActionCloseModal().wait_for_modal_closed(timeout_seconds=TIME_FIVE_MINUTES)

    def fill_proxy_settings_form(self, host: str, port: str, **kwargs) -> None:
        """
        Method for filling proxy setting form while register nessus.

        :param str host: proxy host name
        :param str port: proxy port
        :return: None
        """
        username = kwargs.get('username', '')
        password = kwargs.get('password', '')
        auth_method = kwargs.get('auth', 'AUTO DETECT')
        user_agent = kwargs.get('agent', '')

        self.host_field.value = host
        self.port_field.value = port
        self.username_field.value = username
        self.password_field.value = password
        self.auth_method_dropdown.select_by_visible_text(auth_method)
        self.user_agent_field.value = user_agent
