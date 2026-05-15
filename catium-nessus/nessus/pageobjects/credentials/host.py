""""
Nessus page classes for 'Host' category under 'Credentials' tab in new scan form page

:copyright: Tenable Network Security, 2017
:date: January 30, 2018
:last_modified: Jul 16, 2018
:author: @rdutta, @smadan, @mameta, @ntarwani. @jchavda
"""

from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement
from selenium.webdriver.support.expected_conditions import visibility_of_element_located

from catium.helpers.sleep_lib import sleep
from catium.lib.const import WAIT_SHORT
from catium.lib.webium import Find
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.controls.upload_field import UploadField
from catium.lib.webium.wait import wait
from nessus.pageobjects.credentials.credentials_page import Credentials
from nessus.pageobjects.scans.scans_page import ScansPage
from nessus.pageobjects.shared.loading import LoadingCircle


class Host(Credentials):
    """Page class for `Host` category in Nessus scan credentials."""
    open_form = Find(by=By.CSS_SELECTOR, value='li[class*="opened"]')

    # locators for Global Credentials Settings checkboxes for SSH  credentials type
    known_hosts_file = Find(by=By.CSS_SELECTOR, value='input[data-input-id="ssh_known_hosts"]')
    ssh_port = Find(by=By.CSS_SELECTOR, value='input[data-input-id="ssh_port"]')
    client_version = Find(by=By.CSS_SELECTOR, value='input[data-input-id="ssh_client_banner"]')
    attempt_least_privileges = Find(CheckboxDiv, by=By.CSS_SELECTOR,
                                    value='div[data-input-id="attempt_least_privilege"]')

    # locators for Global Credentials windows Settings checkboxes
    never_send_win_creds_in_clear = Find(CheckboxDiv, by=By.CSS_SELECTOR,
                                         value='li[class*="opened"]'
                                               '[data-name="Windows"] div[data-input-id='
                                               '"never_send_win_creds_in_the_clear"]')
    dont_use_ntlmv1 = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="Windows"] '
                                                                  'div[data-input-id="dont_use_ntlmv1"]')
    start_remote_registry = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="Windows"] '
                                                                        'div[data-input-id="start_remote_registry"]')
    enable_admin_shares = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="Windows"] '
                                                                      'div[data-input-id="enable_admin_shares"]')

    def __init__(self, **kwargs):
        super().__init__()
        self.click_credentials_type(category_name='Host', credentials_type=kwargs.get('host_type'))

    def authentication_method_element(self, credentials_type: str) -> WebElement:
        """
        returns the authentication method dropdown element's locator for given credentials type
        :param str credentials_type: type of host
        :rtype:WebElement
        """
        return Find(Select2Dropdown, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] '
                                                               'select[data-name="Authentication method"]'
                    .format(credentials_type), context=self)

    @property
    def opened_form_value(self):
        """Returns the opened form type."""
        return self.open_form.get_attribute('data-name')

    @property
    def selected_authentication_value(self):
        """returns selected authentication method."""
        return self.authentication_method_element(credentials_type=self.opened_form_value).get_value_selected()

    @property
    def auth_type(self):
        """ Returns expected authentication type """
        auth_type = self.selected_authentication_value
        return auth_type.split(' (')[0] if ' (' in auth_type else auth_type

    @property
    def username_element(self):
        """returns username field locator for the opened authentication form"""
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] div[data-group="{}"]'
                                                         ' input[data-input-id="username"]'
                    .format(self.opened_form_value, self.auth_type), context=self)

    @property
    def password_element(self):
        """returns password field locator for the opened authentication form"""
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] div[data-group="{}"]'
                                                         ' input[data-input-id="password"]'
                    .format(self.opened_form_value, self.auth_type), context=self)

    @property
    def private_key_passphrase_element(self):
        """returns private key pass phrase locator field for the opened authentication form"""
        return Find(TextField, by=By.CSS_SELECTOR,
                    value='li[class*="opened"] div[data-group="{}"] input[data-input-id*="private_key_passphrase"]'
                    .format(self.auth_type), context=self)

    @property
    def private_key_element(self):
        """Returns private key locator field for the opened authentication form under host."""
        return Find(UploadField, by=By.CSS_SELECTOR, value='div[data-group="{}"] input[data-input-id="private_key"]'
                    .format(self.auth_type), context=self)

    @property
    def private_key_file_name_element(self):
        """returns private key file name locator for the opened authentication form"""
        return Find(by=By.CSS_SELECTOR, value='div[data-group="{}"] div>a[data-name="Private key"] + '
                                              'div>div[class*="tag file"]]'.format(self.auth_type), context=self)

    @property
    def domain_element(self):
        """returns domain element locator field for the opened authentication form under host."""
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] div[data-group="{}"] '
                                                         'input[data-input-id="domain"]'
                    .format(self.opened_form_value, self.auth_type), context=self)

    def fill_global_setting_form(self, **kwargs) -> None:
        """
        fill global setting form for SSH
        :return: None
        """
        known_hosts = kwargs.get('known_hosts', '')
        preferred_port = kwargs.get('preferred_port', '22')
        client_version = kwargs.get('client_version', 'OpenSSH_5.0')
        use_least_privilege = kwargs.get('use_least_privilege', False)

        self.js_scroll_into_view(ScansPage().save_button)

        if known_hosts:
            self.known_hosts_file.send_keys(known_hosts)

        self.ssh_port.clear()
        self.ssh_port.send_keys(preferred_port)
        self.client_version.clear()
        self.client_version.send_keys(client_version)
        self.attempt_least_privileges.set_checked(use_least_privilege)

    def get_global_setting_form(self) -> dict:
        """
        returns filled global setting form data for ssh
        :return: form data
        :rtype: dict
        """
        return {'preferred_port': self.ssh_port.get_attribute('value'),
                'client_version': self.client_version.get_attribute('value'),
                'use_least_privilege': self.attempt_least_privileges.is_selected()}

    def fill_global_settings_for_windows(self, **kwargs) -> None:
        """
        fill global settings form for Windows
        :return: None
        """
        self.never_send_win_creds_in_clear.set_checked(kwargs.get('never_send_credentials', True))
        self.dont_use_ntlmv1.set_checked(kwargs.get('do_not_use_ntlm', True))
        self.start_remote_registry.set_checked(kwargs.get('start_remote_registry', False))
        self.enable_admin_shares.set_checked(kwargs.get('enable_admin_shares', False))

    def get_global_settings_for_windows(self) -> dict:
        """
        Returns global settings for Windows
        :return dict: dictionary containing global values
        :rtype: dict
        """
        return {'never_send_credentials': self.never_send_win_creds_in_clear.is_selected(),
                'do_not_use_ntlm': self.dont_use_ntlmv1.is_selected(),
                'start_remote_registry': self.start_remote_registry.is_selected(),
                'enable_admin_shares': self.enable_admin_shares.is_selected()}


class ElevatePrivileges(Host):
    """Page Object for the form opened on selecting 'elevate privileges with' dropdown."""

    @property
    def privileges_with_element(self):
        """
        returns privileges element locator field under 'elevate privileges with' dropdown in the opened
        authentication form
        """
        return Find(Select2Dropdown, by=By.CSS_SELECTOR, value='li[class*="opened"] div[data-group="{}"] '
                                                               'select[data-input-id*="elevate_privileges_with"]'
                    .format(self.auth_type), context=self)

    @property
    def su_user_element(self) -> WebElement:
        """
        returns su user element locator field under 'elevate privileges with' dropdown.
        :return: su_user element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR,
                    value='li[class*="opened"] div[data-group="{}"] input[data-input-id="su_user"]'
                    .format(self.selected_authentication_value), context=self)

    def escalation_account_element(self, elevate_privilege_value: str) -> WebElement:
        """
        Returns escalation account element locator field under 'elevate privileges with' dropdown.
        :param str elevate_privilege_value: Elevate privilege value
        :return: element of particular option
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR,
                    value='li[class*="opened"] div[data-group="{}"] div[data-group="{}"] '
                          'input[data-input-id="escalation_account"]'
                    .format(self.selected_authentication_value, elevate_privilege_value), context=self)

    def escalation_password_element(self, elevate_privilege_value: str) -> WebElement:
        """
        Returns escalation password element locator field under 'elevate privileges with' dropdown.
        :param str elevate_privilege_value: Elevate privilege value
        :return: element of particular option
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR,
                    value='li[class*="opened"] div[data-group="{}"] div[data-group="{}"] '
                          'input[data-input-id="escalation_password"]'
                    .format(self.selected_authentication_value, elevate_privilege_value), context=self)

    def bin_directory_element(self, elevate_privilege_value: str) -> WebElement:
        """
        returns bin directory element locator field under 'elevate privileges with' dropdown.
        :param str elevate_privilege_value: Elevate privilege value
        :return: element of particular option
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR,
                    value='li[class*="opened"] div[data-group="{}"] div[data-group="{}"] '
                          'input[data-input-id="bin_directory"]'
                    .format(self.selected_authentication_value, elevate_privilege_value), context=self)

    def fill_elevate_cred_account_name(self, elevate_privilege_value: str, user: str) -> None:
        """
        Fill details for elevate credential account name
        :param str elevate_privilege_value: value from "elevate privileges with" dropdown
        :param str user: user
        :return: None
        """
        self.privileges_with_element.select_by_visible_text(elevate_privilege_value)
        self.escalation_account_element(elevate_privilege_value=elevate_privilege_value).send_keys(user)

    def get_elevate_cred_account_name(self, elevate_privilege_value: str) -> dict:
        """
        returns elevate privilege credentials
        :param str elevate_privilege_value: value from "elevate privileges with" dropdown
        :return: value of elevate privilege credentials
        :rtype: dict
        """
        return {'elevate_privilege': elevate_privilege_value,
                'account_name': self.escalation_account_element(elevate_privilege_value).text}

    def fill_elevate_cred_dzdo_su(self, elevate_privilege_value: str, user: str, password: str,
                                  location: str) -> None:
        """
        fill details for elevate credentials for dzdo/su user under 'elevate privileges with' dropdown in the opened
        authentication form under host
        :param str elevate_privilege_value: value from "elevate privileges with" dropdown
        :param str user : user
        :param str password: user password
        :param str location: location
        :return: None
        """
        self.privileges_with_element.select_by_visible_text(elevate_privilege_value)
        self.escalation_account_element(elevate_privilege_value=elevate_privilege_value).send_keys(user)
        self.escalation_password_element(elevate_privilege_value=elevate_privilege_value).send_keys(password)
        self.bin_directory_element(elevate_privilege_value=elevate_privilege_value).send_keys(location)

    def get_elevate_cred_dzdo_su_name(self, elevate_privilege_value: str) -> dict:
        """
        returns elevate privilege 'dzdo' credentials
        :param elevate_privilege_value: value from "elevate privileges with" dropdown
        :return: value of 'dzdo' credentials under elevate privilege
        :rtype: dict
        """
        return {'elevate_privilege': elevate_privilege_value,
                'account_name': self.escalation_account_element(elevate_privilege_value).get_attribute('value'),
                'location': self.bin_directory_element(elevate_privilege_value).get_attribute('value'),
                'password': self.escalation_password_element(elevate_privilege_value).get_attribute('value')}

    def fill_su_sudo_user_cred(self, **kwargs) -> None:
        """
        fill credentials for su/sudo user under 'elevate privileges with' dropdown in the opened
        authentication form under host
        :param kwargs: arguments for su/sudo user under elevate privileges
        :return: None
        """
        su_user = kwargs.get('su_user', '')
        sudo_user = kwargs.get('sudo_user', '')
        password = kwargs.get('password', '')
        location = kwargs.get('location', '')
        self.privileges_with_element.select_by_visible_text('su+sudo')
        self.su_user_element.send_keys(su_user)
        self.escalation_account_element(elevate_privilege_value='su+sudo').send_keys(sudo_user)
        self.escalation_password_element(elevate_privilege_value='su+sudo').send_keys(password)
        self.bin_directory_element(elevate_privilege_value='su+sudo').send_keys(location)

    def get_elevate_cred_sudo_su_name(self, elevate_privilege_value: str) -> dict:
        """
        returns elevate privilege "su/sudo" credentials
        :param str elevate_privilege_value: elevate privilege value
        :return: value of 'su/sudo' credentials under elevate privilege
        :rtype: dict
        """
        return {'elevate_privilege': self.privileges_with_element.text,
                'su_user': self.su_user_element.get_attribute('value'),
                'sudo_user': self.escalation_account_element(elevate_privilege_value).get_attribute('value'),
                'location': self.bin_directory_element(elevate_privilege_value).get_attribute('value'),
                'password': self.escalation_password_element(elevate_privilege_value).get_attribute('value')}

    def fill_elevate_su_user_credential(self, **kwargs) -> None:
        """
        fill credentials for su user under 'elevate privileges with' dropdown in the opened
        authentication form under host
        :param kwargs: arguments for su user under elevate privileges
        :return: None
        """
        su_login = kwargs.get('su_login', '')
        su_password = kwargs.get('su_password', '')
        location = kwargs.get('location', '')
        self.privileges_with_element.select_by_visible_text('su')
        self.escalation_account_element(elevate_privilege_value='su').send_keys(su_login)
        self.escalation_password_element(elevate_privilege_value='su').send_keys(su_password)
        self.bin_directory_element(elevate_privilege_value='su').send_keys(location)

    def get_elevate_su_credential_values(self, elevate_privilege_value: str) -> dict:
        """
        returns elevate privilege credentials
        :param str elevate_privilege_value: elevate privilege value
        :return: value of 'su' credentials under elevate privilege
        :rtype: dict
        """
        return {'elevate_privilege': self.privileges_with_element.text,
                'su_login': self.escalation_account_element(elevate_privilege_value).get_attribute('value'),
                'su_password': self.escalation_password_element(elevate_privilege_value).get_attribute('value'),
                'location': self.bin_directory_element(elevate_privilege_value).get_attribute('value')}

    def fill_elevate_pbrun(self, elevate_privilege_value: str, password: str, location: str) -> None:
        """
        fill form for elevate privilege 'pbrun'
        :param str elevate_privilege_value: elevate privilege value
        :param str password: password
        :param str location: location
        :return: None
        """
        self.privileges_with_element.select_by_visible_text(elevate_privilege_value)
        self.escalation_password_element(elevate_privilege_value=elevate_privilege_value).send_keys(password)
        self.bin_directory_element(elevate_privilege_value=elevate_privilege_value).send_keys(location)

    def get_elevate_cred_pbrun(self, elevate_privilege_value: str) -> dict:
        """
        returns elevate privilege 'pbrun' credentials
        :param str elevate_privilege_value: elevate privilege value
        :return: value of 'pbrun' credentials under elevate privilege
        :return: dict
        """
        return {'elevate_privilege': self.privileges_with_element.text,
                'password': self.escalation_password_element(elevate_privilege_value).get_attribute('value'),
                'location': self.bin_directory_element(elevate_privilege_value).get_attribute('value')}


class Password(ElevatePrivileges):
    """Page Object for the form opened on selecting 'Password' dropdown."""

    def fill_password_ssh_form(self, username: str, password: str, **kwargs) -> None:
        """
        fill password form for SSH host
        :param str username: username
        :param str password: password
        :return: None
        """
        sleep(WAIT_SHORT, reason="waiting for form gets loaded properly")
        self.authentication_method_element(credentials_type='SSH').select_by_visible_text(
            kwargs.get('auth', 'password'))
        self.username_element.send_keys(username)
        self.password_element.send_keys(password)

    def get_password_ssh_form_data(self) -> dict:
        """
        returns filled password form data for ssh
        :return: form data of 'ssh' credentials under 'Host'
        :rtype: dict
        """
        return {'auth': self.authentication_method_element(credentials_type='SSH').text,
                'username': self.username_element.get_attribute('value'),
                'password': self.password_element.get_attribute('value')}

    def fill_password_windows_form(self, auth: str, username: str, password: str, domain: str) -> None:
        """
        fill password form for Windows host
        :param str username: username
        :param str password: password
        :param str domain: domain
        :param str auth: authentication method
        :return: None
        """
        sleep(WAIT_SHORT, reason="waiting for form gets loaded properly")
        self.authentication_method_element(credentials_type='Windows').select_by_visible_text(auth)
        self.username_element.send_keys(username)
        self.password_element.send_keys(password)
        self.domain_element.send_keys(domain)

    def get_password_windows_form_data(self) -> dict:
        """
        returns filled password form data for windows
        :return: dictionary containing password form data for windows
        :rtype: dict
        """
        return {'auth': 'Password', 'username': self.username_element.get_attribute('value'),
                'password': self.password_element.get_attribute('value'),
                'domain': self.domain_element.get_attribute('value')}


class ThycoticSecretServer(Host):
    """Page Object for the form opened on selecting 'Thycotic Secret Server' dropdown."""

    def secret_name_element(self, host_type: str) -> WebElement:
        """
        returns secret name element for opened form of 'Thycotic Secret Server' depending upon host type.
        :param str host_type: host type selected e.g. SSH or Windows.
        :return: locator of particular element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] input[data-input-id="'
                                                         'thycotic_secret_name"]'.format(host_type), context=self)

    def server_url_element(self, host_type: str) -> WebElement:
        """
        returns server url element for opened form of 'Thycotic Secret Server' depending upon host type.
        :param str host_type: host type selected e.g. SSH or Windows.
        :return: locator of server url element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] input[data-input-id="'
                                                         'thycotic_url"]'.format(host_type), context=self)

    def login_name_element(self, host_type: str) -> WebElement:
        """
        returns login name element for opened form of 'Thycotic Secret Server' depending upon host type.
        :param str host_type: host type selected e.g. SSH or Windows.
        :return: locator of login name element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] input[data-input-id="'
                                                         'thycotic_username"]'.format(host_type), context=self)

    def thycotic_password_element(self, host_type: str) -> WebElement:
        """
        returns thycotic password element for opened form of 'Thycotic Secret Server' depending upon host type.
        :param str host_type: host type selected e.g. SSH or Windows.
        :return: locator of thycotic password element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] input[data-input-id="'
                                                         'thycotic_password"]'.format(host_type), context=self)

    def organization_element(self, host_type: str) -> WebElement:
        """
        returns organization name element for opened form of 'Thycotic Secret Server' depending upon host type.
        :param str host_type: host type selected e.g. SSH or Windows.
        :return: locator of organization name element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] input[data-input-id="'
                                                         'thycotic_organization" ]'.format(host_type), context=self)

    def thycotic_domain_element(self, host_type: str) -> WebElement:
        """
        returns thycotic domain element for opened form of 'Thycotic Secret Server' depending upon host type.
        :param str host_type: host type selected e.g. SSH or Windows.
        :return: locator of thycotic domain element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] input[data-input-id="'
                                                         'thycotic_domain" ]'.format(host_type), context=self)

    def use_private_key_element(self, host_type: str) -> CheckboxDiv:
        """
        returns private key element for opened form of 'Thycotic Secret Server' depending upon host type.
        :param str host_type: host type selected e.g. SSH or Windows.
        :return: locator of private key element
        :rtype: CheckboxDiv
        """
        return Find(CheckboxDiv, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] div[data-input-id="'
                                                           'thycotic_private_key"]'.format(host_type), context=self)

    def ssl_certificate_element(self, host_type: str) -> CheckboxDiv:
        """
        returns ssl certificate field element for opened form of 'Thycotic Secret Server' depending upon host type.
        :param str host_type: host type selected e.g. SSH or Windows.
        :return: locator of checkbox for ssl certificate field
        :rtype: CheckboxDiv
        """
        return Find(CheckboxDiv, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] div[data-input-id="'
                                                           'thycotic_ssl_verify"'.format(host_type), context=self)

    def fill_thycotic_form(self, **kwargs) -> None:
        """
        fill details for Thycotic ssh form
        :param kwargs: arguments for thycotic form for host_type SSH or Windows
        :return: None
        """
        # thycotic form data to be saved
        host_type = kwargs.get('host_type', 'SSH')
        username = kwargs.get('username', '')
        domain_name = kwargs.get('domain_name', '')
        secret_name = kwargs.get('secret_name', '')
        server_url = kwargs.get('server_url', '')
        login_name = kwargs.get('login_name', '')
        thycotic_password = kwargs.get('thycotic_password', '')
        organization = kwargs.get('organization', '')
        thycotic_domain = kwargs.get('thycotic_domain', '')
        ssl_certificate_element = kwargs.get('ssl_certificate_element', True)
        use_private_key_element = kwargs.get('use_private_key_element', False)

        self.authentication_method_element(credentials_type=host_type).select_by_visible_text('Thycotic Secret Server')
        self.username_element.send_keys(username)
        if host_type == 'Windows':
            self.domain_element.send_keys(domain_name)
        self.secret_name_element(host_type=host_type).send_keys(secret_name)
        self.server_url_element(host_type=host_type).send_keys(server_url)
        self.login_name_element(host_type=host_type).send_keys(login_name)
        self.thycotic_password_element(host_type=host_type).send_keys(thycotic_password)
        self.organization_element(host_type=host_type).send_keys(organization)
        self.thycotic_domain_element(host_type=host_type).send_keys(thycotic_domain)
        self.ssl_certificate_element(host_type=host_type).set_checked(ssl_certificate_element)
        if host_type == 'SSH':
            self.use_private_key_element(host_type=host_type).set_checked(use_private_key_element)

    def get_thycotic_ssh_form_data(self, host_type: str) -> dict:
        """
        returns Thycotic form data for host type
        :param str host_type: host type
        :return: dictionary of filled data in thycotic_ssh form
        :rtype: dict
        """
        return {'auth': self.authentication_method_element(credentials_type=host_type).text,
                'username': self.username_element.get_attribute('value'),
                'secret_name': self.secret_name_element(host_type=host_type).get_attribute('value'),
                'server_url': self.server_url_element(host_type=host_type).get_attribute('value'),
                'login_name': self.login_name_element(host_type=host_type).get_attribute('value'),
                'organization': self.organization_element(host_type=host_type).get_attribute('value'),
                'thycotic_domain': self.thycotic_domain_element(host_type=host_type).get_attribute('value'),
                'thycotic_password': self.thycotic_password_element(host_type=host_type).get_attribute('value'),
                'ssl_certificate_element': self.ssl_certificate_element(host_type).is_selected(),
                'use_private_key_element': self.use_private_key_element(host_type).is_selected()}

    def get_thycotic_windows_form_data(self, host_type: str) -> dict:
        """
        returns Thycotic form data for Windows
        :param str host_type: host type
        :return: dictionary of filled data in thycotic_windows form
        :rtype: dict
        """
        return {'auth': self.authentication_method_element(credentials_type=host_type).text,
                'username': self.username_element.get_attribute('value'),
                'domain_name': self.domain_element.get_attribute('value'),
                'secret_name': self.secret_name_element(host_type=host_type).get_attribute('value'),
                'server_url': self.server_url_element(host_type=host_type).get_attribute('value'),
                'login_name': self.login_name_element(host_type=host_type).get_attribute('value'),
                'thycotic_password': self.thycotic_password_element(host_type=host_type).get_attribute('value'),
                'organization': self.organization_element(host_type=host_type).get_attribute('value'),
                'thycotic_domain': self.thycotic_domain_element(host_type=host_type).get_attribute('value'),
                'ssl_certificate_element': self.ssl_certificate_element(host_type).is_selected()}


class BeyondTrust(Host):
    """Page Object for the form having Authentication method 'BeyondTrust'."""

    def beyond_trust_host_element(self, host_type: str) -> WebElement:
        """
        returns host element for opened form of 'BeyondTrust' depending upon host type.
        :param str host_type: host type
        :return: locator of host element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] input[data-input-id="'
                                                         'beyondtrust_host"]'.format(host_type), context=self)

    def beyond_trust_port_element(self, host_type: str) -> WebElement:
        """
        returns port element for opened form of 'BeyondTrust' depending upon host type.
        :param str host_type: host type
        :return: locator of port element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] input[data-input-id="'
                                                         'beyondtrust_port"]'.format(host_type), context=self)

    def beyond_trust_api_user_element(self, host_type: str) -> WebElement:
        """
        returns api_user element for opened from of BeyondTrust depending upon host tyoe
        :param str host_type: host_type
        :return: locator for api_user element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] input[data-input-id='
                                                         '"beyondtrust_api_user"]'.format(host_type), context=self)

    def beyond_trust_api_key_element(self, host_type: str) -> WebElement:
        """
        returns api_key element for opened form of 'BeyondTrust' depending upon host type.
        :param str host_type: host type
        :return: locator of api_key element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] input[data-input-id="'
                                                         'beyondtrust_api_key"]'.format(host_type), context=self)

    def beyond_trust_checkout_duration_element(self, host_type: str) -> WebElement:
        """
        returns checkout_duration element for opened form of 'BeyondTrust' depending upon host type.
        :param str host_type: host type
        :return: locator of checkout_duration element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] input[data-input-id="'
                                                         'beyondtrust_duration"]'.format(host_type), context=self)

    def beyond_trust_use_ssl_element(self, host_type: str) -> CheckboxDiv:
        """
        returns use_ssl element for opened form of 'BeyondTrust' depending upon host type.
        :param str host_type: host type
        :return: checkbox locator of use_ssl element
        :rtype: CheckboxDiv
        """
        return Find(CheckboxDiv, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] div[data-group="{}"] '
                                                           'div[data-input-id="beyondtrust_use_ssl"]'
                    .format(host_type, self.selected_authentication_value), context=self)

    def beyond_trust_verify_ssl_element(self, host_type: str) -> CheckboxDiv:
        """
        returns verify_ssl element for opened form of 'BeyondTrust' depending upon host type.
        :param str host_type: host type
        :return: checkbox locator of verify_ssl element
        :rtype: CheckboxDiv
        """
        return Find(CheckboxDiv, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] div[data-group="{}"] '
                                                           ' div[data-input-id="beyondtrust_verify_ssl"]'
                    .format(host_type, self.selected_authentication_value), context=self)

    def beyond_trust_use_private_key_element(self, host_type: str) -> CheckboxDiv:
        """
        returns use_private_key element for opened form of 'BeyondTrust' depending upon host type.
        :param str host_type: host type
        :return: checkbox locator of use_private_key element
        :rtype: CheckboxDiv
        """
        return Find(CheckboxDiv, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] div[data-group="{}"] '
                                                           ' div[data-input-id="beyondtrust_use_private_key"]'
                    .format(host_type, self.selected_authentication_value), context=self)

    def beyond_trust_privilege_escalation_element(self, host_type: str) -> CheckboxDiv:
        """
        returns privilege_escalation element for opened form of 'BeyondTrust' depending upon host type.
        :param str host_type: host type
        :return: checkbox locator of privilege_escalation element
        :rtype: CheckboxDiv
        """
        return Find(CheckboxDiv, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] div[data-group="{}"] '
                                                           ' div[data-input-id="beyondtrust_use_escalation"]'
                    .format(host_type, self.selected_authentication_value), context=self)

    def fill_beyond_trust_form(self, host_type: str, **kwargs) -> None:
        """
        fills ssh form for the BeyondTrust authentication method
        :param str host_type: host type selected
        :return: None
        """
        username = kwargs.get('username')
        host = kwargs.get('host')
        domain = kwargs.get('domain')
        port = kwargs.get('port')
        api_user = kwargs.get('api_user')
        api_key = kwargs.get('api_key')
        checkout_duration = kwargs.get('checkout_duration')
        beyond_trust_use_ssl_element = kwargs.get('use_ssl', True)
        beyond_trust_verify_ssl_element = kwargs.get('verify_ssl', True)
        beyond_trust_use_private_key_element = kwargs.get('private_key', False)
        beyond_trust_privilege_escalation_element = kwargs.get('privilege_escalation', False)

        self.authentication_method_element(credentials_type=host_type).select_by_visible_text('BeyondTrust')
        self.username_element.send_keys(username)
        if host_type == 'Windows':
            self.domain_element.send_keys(domain)

        self.beyond_trust_host_element(host_type=host_type).send_keys(host)
        self.beyond_trust_port_element(host_type=host_type).send_keys(port)
        self.beyond_trust_api_user_element(host_type=host_type).send_keys(api_user)
        self.beyond_trust_api_key_element(host_type=host_type).send_keys(api_key)
        self.beyond_trust_checkout_duration_element(host_type=host_type).send_keys(checkout_duration)

        self.beyond_trust_use_ssl_element(host_type).set_checked(beyond_trust_use_ssl_element)

        self.beyond_trust_verify_ssl_element(host_type).set_checked(beyond_trust_verify_ssl_element)

        if host_type == "SSH":
            self.beyond_trust_use_private_key_element(host_type).set_checked(beyond_trust_use_private_key_element)
            self.beyond_trust_privilege_escalation_element(host_type).set_checked(
                beyond_trust_privilege_escalation_element)

    def get_ssh_beyond_trust_form_data(self) -> dict:
        """
        returns BeyondTrust form data for SSH
        :return: dictionary of filled data values for 'BeyondTrust' form under 'SSH' category
        :rtype: dict
        """
        return {'auth': self.authentication_method_element(credentials_type='SSH').text,
                'username': self.username_element.get_attribute('value'),
                'host': self.beyond_trust_host_element(host_type='SSH').get_attribute('value'),
                'port': self.beyond_trust_port_element(host_type='SSH').get_attribute('value'),
                'api_user': self.beyond_trust_api_user_element(host_type='SSH').get_attribute('value'),
                'checkout_duration': self.beyond_trust_checkout_duration_element(
                    host_type='SSH').get_attribute('value'),
                'use_ssl': self.beyond_trust_use_ssl_element(host_type='SSH').is_selected(),
                'verify_ssl': self.beyond_trust_verify_ssl_element(host_type='SSH').is_selected(),
                'private_key': self.beyond_trust_use_private_key_element(host_type='SSH').is_selected(),
                'privilege_escalation': self.beyond_trust_privilege_escalation_element(host_type='SSH').is_selected()}

    def get_windows_beyond_trust_form_data(self) -> dict:
        """
        returns BeyondTrust form data for Windows
        :return: dictionary of filled data values for 'BeyondTrust' form under 'Windows' category
        :rtype: dict
        """
        return {'auth': self.authentication_method_element(credentials_type='Windows').text,
                'username': self.username_element.get_attribute('value'),
                'domain': self.domain_element.get_attribute('value'),
                'host': self.beyond_trust_host_element(host_type='Windows').get_attribute('value'),
                'port': self.beyond_trust_port_element(host_type='Windows').get_attribute('value'),
                'api_user': self.beyond_trust_api_user_element(host_type='Windows').get_attribute('value'),
                'checkout_duration': self.beyond_trust_checkout_duration_element(
                    host_type='Windows').get_attribute('value'),
                'use_ssl': self.beyond_trust_use_ssl_element(host_type='Windows').is_selected(),
                'verify_ssl': self.beyond_trust_verify_ssl_element(host_type='Windows').is_selected()}


class Certificate(ElevatePrivileges):
    """Page Object for the form having Authentication method 'certificate'."""

    user_certificate = Find(UploadField, by=By.CSS_SELECTOR, value='li[class*="opened"] '
                                                                   'input[data-input-id="user_cert"]')
    user_cert_file_name = Find(by=By.CSS_SELECTOR, value='li[class*="opened"] div[data-group="certificate"]'
                                                         ' div[class="tag file"]')

    def fill_ssh_certificate_form(self, username: str, cert_path: str, key_path: str, passphrase: str,
                                  elevate_privilege: str, escalation_account: str, **kwargs) -> None:
        """
        fills ssh form for the certificate authentication method
        :param str username: Username value
        :param str cert_path:  User Certificate file path
        :param str key_path:  Private key certificate file path
        :param str passphrase: private key passphrase value
        :param str elevate_privilege: elevate privilege value
        :param str escalation_account: escalation account
        :return: None
        """
        self.authentication_method_element(credentials_type='SSH').select_by_visible_text(
            kwargs.get('auth', 'certificate'))
        self.username_element.send_keys(username)
        self.user_certificate.send_keys(cert_path)
        self.private_key_element.send_keys(key_path)
        self.private_key_passphrase_element.send_keys(passphrase)
        self.privileges_with_element.select_by_visible_text(elevate_privilege)
        self.escalation_account_element(elevate_privilege).send_keys(escalation_account)

    def get_certificate_ssh_form_data(self, elevate_privilege: str) -> dict:
        """
        returns certificate form data for SSH
        :return: dictionary of filled data values for 'Certificate' form under 'SSH' category
        :rtype: dict
        """
        return {'auth': self.authentication_method_element(credentials_type='SSH').text,
                'username': self.username_element.get_attribute('value'),
                'elevate_privilege': self.privileges_with_element.text,
                'passphrase': self.private_key_passphrase_element.get_attribute('value'),
                'escalation_account': self.escalation_account_element(elevate_privilege).get_attribute('value')}


class CyberArk(ElevatePrivileges):
    """Page Object for the form opened on selecting 'CyberArk' dropdown."""

    cyberark_elevate_privilege = Find(Select2Dropdown, by=By.CSS_SELECTOR,
                                      value='div[data-group="CyberArk"] '
                                            'select[data-input-id="vault_elevate_privileges_with"]')

    def cyberark_address(self, host_type: str) -> WebElement:
        """
        returns vault_address field for cyberark type
        :param host_type: host type
        :return: locator of vault_address element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] input[data-input-id='
                                                         '"vault_address"]'.format(host_type), context=self)

    def cyberark_client_cert_add_file(self, host_type: str) -> WebElement:
        """
        returns element to add client certificate
        :param host_type: host type
        :return: locator of client_cert element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value=' li[class*="opened"][data-name="{}"] input[data-input-id="'
                                                         'vault_cyberark_client_cert"]'.format(host_type), context=self)

    def cyberark_client_cert_private_key_add_file(self, host_type: str) -> WebElement:
        """
        returns element to add private key for client certificate
        :param host_type:host type
        :return: locator of private_key element for client certificate
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value=' li[class*="opened"][data-name="{}"] input[data-input-id="'
                                                         'vault_cyberark_private_key"]'.format(host_type), context=self)

    def cyberark_aim_service_url(self, host_type: str) -> WebElement:
        """
        returns cyberark aim service url element
        :param str host_type: host type selected e.g. SSH or Windows.
        :return: locator of aim_service_url element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] input[data-input-id='
                                                         '"vault_cyberark_url"]'.format(host_type), context=self)

    def credential_host(self, host_type: str) -> WebElement:
        """
        returns credentials host element
        :param str host_type: host type selected e.g. SSH or Windows
        :return: locator of credential_host element
        :rtype:WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] input[data-input-id='
                                                         '"pam_host"]'.format(host_type), context=self)

    def credential_port(self, host_type: str) -> WebElement:
        """
        returns credentials port element
        :param str host_type: host type selected e.g. SSH or Windows.
        :return: locator of credential_port element
        :rtype:WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] input[data-input-id='
                                                         '"vault_port"]'.format(host_type), context=self)

    def credential_username(self, host_type: str) -> WebElement:
        """
        returns credentials username element
        :param str host_type: host type selected e.g. SSH or Windows.
        :return: locator of username element
        :rtype:WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] input[data-input-id='
                                                         '"vault_username"]'.format(host_type), context=self)

    def credential_password(self, host_type: str) -> WebElement:
        """
        returns credentials password element
        :param str host_type: host type selected e.g. SSH or Windows.
        :return: locator of password element
        :rtype:WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] input[data-input-id='
                                                         '"vault_password"]'.format(host_type), context=self)

    def safe_element(self, host_type: str) -> WebElement:
        """
        returns safe element field locator
        :param str host_type: host type selected e.g. SSH or Windows.
        :return: locator of safe_element
        :rtype:WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] input[data-input-id='
                                                         '"pam_safe"]'.format(host_type), context=self)

    def appid_element(self, host_type: str) -> WebElement:
        """
        returns app_id element field locator
        :param str host_type: host type selected e.g. SSH or Windows.
        :return: locator of app_id element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] input[data-input-id='
                                                         '"pam_app_id"]'.format(host_type), context=self)

    def folder_element(self, host_type: str) -> WebElement:
        """
        returns folder element field locator
        :param str host_type: host type selected e.g. SSH or Windows.
        :return: locator of folder element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] input[data-input-id='
                                                         '"vault_folder"]'.format(host_type), context=self)

    def cyberark_policy_id_element(self, host_type: str) -> WebElement:
        """
        returns policy id element field locator
        :param str host_type: host type selected e.g. SSH or Windows.
        :return: locator of policy id element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] input[data-input-id='
                                                         '"vault_policy_id"]'.format(host_type), context=self)

    def use_ssl_element(self, host_type: str) -> CheckboxDiv:
        """
        returns use ssl element field locator
        :param str host_type: host type selected e.g. SSH or Windows.
        :return: locator for use_ssl_element checkbox
        :rtype: CheckboxDiv
        """
        return Find(CheckboxDiv, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] div[data-input-id='
                                                           '"pam_use_ssl"]'.format(host_type), context=self)

    def verify_ssl_element(self, host_type: str) -> CheckboxDiv:
        """
        returns verify ssl element field locator
        :param str host_type: host type selected e.g. SSH or Windows.
        :return: locator for verify_ssl_element checkbox
        :rtype: CheckboxDiv
        """
        return Find(CheckboxDiv, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] div[data-input-id='
                                                           '"pam_verify_ssl"]'.format(host_type), context=self)

    def account_name(self, host_type: str) -> WebElement:
        """
        returns account name element field locator
        :param str host_type: host type selected e.g. SSH or Windows.
        :return: locator for account_name element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] input[data-input-id='
                                                         '"vault_account_name"]'.format(host_type), context=self)

    def cyberark_escalation_account_element(self, elevate_privilege_value: str) -> WebElement:
        """
        returns cyberark escalation account field element.
        :param str elevate_privilege_value: value selected in 'elevate privileges with' dropdown
        :return: locator for escalation_account element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='div[data-group="CyberArk"] div[data-group="{}"] '
                                                         'input[data-input-id="pam_escalation_credential_id"]'
                    .format(elevate_privilege_value), context=self)

    def cyberark_escalation_password_element(self, elevate_privilege_value: str) -> WebElement:
        """
        returns cyberark escalation password field element.
        :param str elevate_privilege_value: value selected in 'elevate privileges with' dropdown
        :return: locator for escalation_password element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='div[data-group="CyberArk"] div[data-group="{}"] '
                                                         'input[data-input-id="pam_escalation_password"]'
                    .format(elevate_privilege_value), context=self)

    def bin_directory_element(self, elevate_privilege_value: str) -> WebElement:
        """
        returns bin directory field element.
        :param str elevate_privilege_value: value selected in 'elevate privileges with' dropdown
        :return: locator for bin_directory element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='div[data-group="CyberArk"] div[data-group="{}"] '
                                                         'input[data-input-id="vault_bin_directory"]'
                    .format(elevate_privilege_value), context=self)

    def su_user_element(self) -> WebElement:
        """
        returns su user account field element.
        :return: locator for su_user element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='div[data-group="CyberArk"] '
                                                         'input[data-input-id="su_user"]', context=self)

    def fill_cyberark_legacy_host_ssh_form(self, **kwargs) -> None:
        """
        fill form for cyberark host ssh form
        :return: None
        """
        # cyberark form data to be saved
        auth_method = kwargs.get('auth', 'CyberArk')
        host_type = kwargs.get("host_type", '')
        username = kwargs.get('username', '')
        cyberark_url = kwargs.get('cyberark_url', '')
        cred_host = kwargs.get('cred_host', '')
        cred_port = kwargs.get('cred_port', '')
        cred_username = kwargs.get('cred_username', '')
        cred_password = kwargs.get('cred_password', '')
        safe = kwargs.get('safe', '')
        passphrase = kwargs.get('passphrase', '')
        client_cert_filepath = kwargs.get('client_cert_filepath', '')
        private_key_filepath = kwargs.get('private_key_filepath', '')
        appid = kwargs.get('appid', '')
        folder = kwargs.get('folder', '')
        policy_id = kwargs.get('policy_id', '')
        use_ssl_element = kwargs.get('use_ssl_element', True)
        verify_ssl_element = kwargs.get('verify_ssl_element', True)
        account_name = kwargs.get('account_name', '')
        cyberark_address = kwargs.get('cyberark_address', '')
        elevate_privilege = kwargs.get('elevate_privilege', '')
        cyberark_escalation_password = kwargs.get('cyberark_escalation_password', '')

        self.authentication_method_element(credentials_type=host_type).select_by_visible_text(auth_method)
        self.username_element.send_keys(username)
        self.cyberark_aim_service_url(host_type).send_keys(cyberark_url)

        self.credential_host(host_type).send_keys(cred_host)
        self.credential_port(host_type).send_keys(cred_port)

        self.credential_username(host_type).send_keys(cred_username)
        self.credential_password(host_type).send_keys(cred_password)
        self.safe_element(host_type).send_keys(safe)

        self.cyberark_client_cert_add_file(host_type).send_keys(client_cert_filepath)
        self.cyberark_client_cert_private_key_add_file(host_type).send_keys(private_key_filepath)

        self.private_key_passphrase_element.send_keys(passphrase)
        self.appid_element(host_type).send_keys(appid)
        self.folder_element(host_type).send_keys(folder)
        self.js_scroll_into_view(element=ScansPage().save_button)

        self.cyberark_policy_id_element(host_type).send_keys(policy_id)
        self.use_ssl_element(host_type).set_checked(use_ssl_element)
        self.verify_ssl_element(host_type).set_checked(verify_ssl_element)

        self.account_name(host_type).send_keys(account_name)
        self.cyberark_address(host_type=host_type).send_keys(cyberark_address)

        self.privileges_with_element.select_by_visible_text(elevate_privilege)
        self.cyberark_escalation_password_element("Cisco 'enable'").send_keys(cyberark_escalation_password)

    def fill_cyberark_host_ssh_form(self, **kwargs) -> None:
        """
        fill form for cyberark host ssh form
        :return: None
        """
        # cyberark form data to be saved
        auth_method = kwargs.get('auth', 'CyberArk')
        host_type = kwargs.get("host_type", '')
        username = kwargs.get('username', '')
        cred_host = kwargs.get('cred_host', '')
        safe = kwargs.get('safe', '')
        appid = kwargs.get('appid', '')
        use_ssl_element = kwargs.get('use_ssl_element', True)
        verify_ssl_element = kwargs.get('verify_ssl_element', True)
        elevate_privilege = kwargs.get('elevate_privilege', '')
        cyberark_escalation_account_name = kwargs.get('cyberark_escalation_account_name', '')

        self.authentication_method_element(credentials_type=host_type).select_by_visible_text(auth_method)
        self.username_element.send_keys(username)
        self.credential_host(host_type).send_keys(cred_host)
        self.safe_element(host_type).send_keys(safe)
        self.appid_element(host_type).send_keys(appid)
        self.js_scroll_into_view(element=ScansPage().save_button)

        self.use_ssl_element(host_type).set_checked(use_ssl_element)
        self.verify_ssl_element(host_type).set_checked(verify_ssl_element)
        self.privileges_with_element.select_by_visible_text(elevate_privilege)
        self.cyberark_escalation_account_element("Cisco 'enable'").send_keys(cyberark_escalation_account_name)

    def get_cyberark_legacy_ssh_form_data(self) -> dict:
        """
        returns filled cyberark form data for ssh
        :return: dictionary of filled data values for cyberark form under 'SSH'
        :rtype: dict
        """
        return {'host_type': self.opened_form_value,
                'auth': self.authentication_method_element(credentials_type='SSH').text,
                'username': self.username_element.get_attribute('value'),
                'cyberark_url': self.cyberark_aim_service_url('SSH').get_attribute('value'),
                'cred_host': self.credential_host('SSH').get_attribute('value'),
                'cred_port': self.credential_port('SSH').get_attribute('value'),
                'cred_username': self.credential_username('SSH').get_attribute('value'),
                'safe': self.safe_element('SSH').get_attribute('value'),
                'appid': self.appid_element('SSH').get_attribute('value'),
                'folder': self.folder_element('SSH').get_attribute('value'),
                'policy_id': self.cyberark_policy_id_element('SSH').get_attribute('value'),
                'cyberark_address': self.cyberark_address(host_type='SSH').get_attribute('value'),
                'elevate_privilege': self.privileges_with_element.text,
                'cyberark_escalation_password': self.cyberark_escalation_password_element(
                    "Cisco 'enable'").get_attribute('value'),
                'use_ssl_element': self.use_ssl_element(host_type='SSH').is_selected(),
                'verify_ssl_element': self.verify_ssl_element(host_type='SSH').is_selected(),
                'passphrase': self.private_key_passphrase_element.get_attribute('value'),
                'cred_password': self.credential_password(host_type='SSH').get_attribute('value')}

    def get_cyberark_ssh_form_data(self) -> dict:
        """
        returns filled cyberark form data for ssh
        :return: dictionary of filled data values for cyberark form under 'SSH'
        :rtype: dict
        """
        return {'host_type': self.opened_form_value,
                'auth': self.authentication_method_element(credentials_type='SSH').text,
                'username': self.username_element.get_attribute('value'),
                'cred_host': self.credential_host('SSH').get_attribute('value'),
                'safe': self.safe_element('SSH').get_attribute('value'),
                'appid': self.appid_element('SSH').get_attribute('value'),
                'elevate_privilege': self.privileges_with_element.text,
                'cyberark_escalation_account_name': self.cyberark_escalation_account_element(
                    "Cisco 'enable'").get_attribute('value'),
                'use_ssl_element': self.use_ssl_element(host_type='SSH').is_selected(),
                'verify_ssl_element': self.verify_ssl_element(host_type='SSH').is_selected()}

    def fill_cyberark_legacy_host_windows_form(self, **kwargs) -> None:
        """
        Fill CyberArk host windows form.
        :return: None
        """
        # cyberark form data to be saved
        auth = kwargs.get('auth', 'CyberArk')
        username = kwargs.get('username', 'administrator')
        cyberark_url = kwargs.get('cyberark_url', '')
        domain = kwargs.get('domain', 'tenable')
        cred_host = kwargs.get('cred_host', '')
        cred_port = kwargs.get('cred_port', '')
        cred_username = kwargs.get('cred_username', '')
        cred_password = kwargs.get('cred_password', '')
        safe = kwargs.get('safe', '')
        passphrase = kwargs.get('passphrase', '')
        client_cert_filepath = kwargs.get('client_cert_filepath', '')
        private_key_filepath = kwargs.get('private_key_filepath', '')
        appid = kwargs.get('appid', '')
        folder = kwargs.get('folder', '')
        policy_id = kwargs.get('policy_id', '')
        account_name = kwargs.get('account_name', '')
        use_ssl = kwargs.get('use_ssl', True)
        verify_ssl = kwargs.get('verify_ssl', True)

        self.authentication_method_element(credentials_type='Windows').select_by_visible_text(auth)
        self.username_element.send_keys(username)
        self.cyberark_aim_service_url('Windows').send_keys(cyberark_url)
        self.domain_element.send_keys(domain)

        self.credential_host('Windows').send_keys(cred_host)
        self.credential_port('Windows').send_keys(cred_port)
        self.credential_username('Windows').send_keys(cred_username)
        self.credential_password('Windows').send_keys(cred_password)

        self.safe_element('Windows').send_keys(safe)

        self.cyberark_client_cert_add_file(host_type='Windows').send_keys(client_cert_filepath)
        self.cyberark_client_cert_private_key_add_file(host_type='Windows').send_keys(private_key_filepath)
        self.js_scroll_into_view(element=ScansPage().save_button)
        self.private_key_passphrase_element.send_keys(passphrase)

        self.appid_element('Windows').send_keys(appid)
        self.folder_element('Windows').send_keys(folder)

        self.cyberark_policy_id_element('Windows').send_keys(policy_id)

        self.account_name('Windows').send_keys(account_name)
        self.use_ssl_element(host_type='Windows').set_checked(use_ssl)
        self.verify_ssl_element(host_type='Windows').set_checked(verify_ssl)

    def fill_cyberark_host_windows_form(self, **kwargs) -> None:
        """
        Fill CyberArk host windows form.
        :return: None
        """
        # cyberark form data to be saved
        auth = kwargs.get('auth', 'CyberArk')
        username = kwargs.get('username', 'administrator')
        domain = kwargs.get('domain', 'tenable')
        cred_host = kwargs.get('cred_host', '')
        safe = kwargs.get('safe', '')
        appid = kwargs.get('appid', '')
        use_ssl = kwargs.get('use_ssl', True)
        verify_ssl = kwargs.get('verify_ssl', True)

        self.authentication_method_element(credentials_type='Windows').select_by_visible_text(auth)
        self.username_element.send_keys(username)
        self.domain_element.send_keys(domain)
        self.credential_host('Windows').send_keys(cred_host)
        self.safe_element('Windows').send_keys(safe)
        self.js_scroll_into_view(element=ScansPage().save_button)
        self.appid_element('Windows').send_keys(appid)
        self.use_ssl_element(host_type='Windows').set_checked(use_ssl)
        self.verify_ssl_element(host_type='Windows').set_checked(verify_ssl)

    def get_cyberark_legacy_windows_form_data(self):
        """
        returns filled cyberark form data for windows
        :return: dictionary containing cyberark form data under 'Windows'
        :rtype: dict
        """
        return {'auth': self.authentication_method_element(credentials_type='Windows').text,
                'username': self.username_element.get_attribute('value'),
                'cyberark_url': self.cyberark_aim_service_url('Windows').get_attribute('value'),
                'domain': self.domain_element.get_attribute('value'),
                'cred_host': self.credential_host('Windows').get_attribute('value'),
                'cred_port': self.credential_port('Windows').get_attribute('value'),
                'cred_username': self.credential_username('Windows').get_attribute('value'),
                'cred_password': self.credential_password('Windows').get_attribute('value'),
                'safe': self.safe_element('Windows').get_attribute('value'),
                'passphrase': self.private_key_passphrase_element.get_attribute('value'),
                'appid': self.appid_element('Windows').get_attribute('value'),
                'folder': self.folder_element('Windows').get_attribute('value'),
                'policy_id': self.cyberark_policy_id_element('Windows').get_attribute('value'),
                'use_ssl': self.use_ssl_element(host_type='Windows').is_selected(),
                'verify_ssl': self.verify_ssl_element(host_type='Windows').is_selected(),
                'account_name': self.account_name(host_type='Windows').get_attribute('value')}

    def get_cyberark_windows_form_data(self):
        """
        returns filled cyberark form data for windows
        :return: dictionary containing cyberark form data under 'Windows'
        :rtype: dict
        """
        return {'auth': self.authentication_method_element(credentials_type='Windows').text,
                'username': self.username_element.get_attribute('value'),
                'domain': self.domain_element.get_attribute('value'),
                'cred_host': self.credential_host('Windows').get_attribute('value'),
                'safe': self.safe_element('Windows').get_attribute('value'),
                'appid': self.appid_element('Windows').get_attribute('value'),
                'use_ssl': self.use_ssl_element(host_type='Windows').is_selected(),
                'verify_ssl': self.verify_ssl_element(host_type='Windows').is_selected()}


class PublicKey(ElevatePrivileges):
    """Page Object for the form having Authentication method 'public key'."""

    def fill_public_key_ssh_form(self, **kwargs) -> None:
        """
        fill public key ssh credential form
        :rtype: None
        """
        username = kwargs.get('username', '')
        key_path = kwargs.get('key_path', '')
        passphrase = kwargs.get('passphrase', '')
        elevate_privilege = kwargs.get('elevate_privilege')
        auth = kwargs.get('auth', 'public key')
        self.authentication_method_element(credentials_type='SSH').select_by_visible_text(auth)
        self.username_element.send_keys(username)
        self.private_key_element.send_keys(key_path)
        self.private_key_passphrase_element.send_keys(passphrase)
        self.privileges_with_element.select_by_visible_text(elevate_privilege)

    def get_public_key_ssh_form_data(self) -> dict:
        """
        Returns public key form data for SSH
        :return: dictionary of filled data values for cyberark form under 'SSH'
        :rtype: dict
        """
        return {'auth': self.authentication_method_element(credentials_type='SSH').text,
                'username': self.username_element.get_attribute('value'),
                'elevate_privilege': self.privileges_with_element.text,
                'passphrase': self.private_key_passphrase_element.get_attribute('value')}


class KerBeros(ElevatePrivileges):
    """Page Object for the form having Authentication method 'kerberos'."""

    realm = Find(TextField, by=By.CSS_SELECTOR,
                 value='li[class*="opened"] div[data-group="Kerberos"] input[data-input-id="realm"]')

    def key_dis_center_element(self, host_type: str) -> WebElement:
        """
        returns Key Distribution Center locator for the type of host.
        :param str host_type:  host type selected e.g. SSH or Windows.
        :return: locator for distribution_center element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR,
                    value='li[class*="opened"][data-name="{}"] div[data-group="Kerberos"]'
                          ' input[data-input-id="kdc"]'.format(host_type), context=self)

    def kdc_port_element(self, host_type: str) -> WebElement:
        """
        returns Key port locator for the type of host.
        :param str host_type: host type selected e.g. SSH or Windows.
        :return: locator for kdc_port element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] div[data-group='
                                                         '"Kerberos"] input[data-input-id="kdc_port"]'.format(
            host_type), context=self)

    def kdc_transport_element(self, host_type: str) -> WebElement:
        """
        returns KDC Transport dropdown locator.
        :param str host_type: host type selected e.g. SSH or Windows.
        :return: locator for kdc_transport element
        :rtype: WebElement
        """
        return Find(Select2Dropdown, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] div[data-group'
                                                               '="Kerberos"] select[data-input-id="kdc_transport"]'
                    .format(host_type), context=self)

    def fill_kerberos_ssh_form(self, **kwargs) -> None:
        """
        fills the kerberos ssh form value
        :return: None
        """
        # kerbros ssh form data to be saved
        username = kwargs.get('username', '')
        password = kwargs.get('password', '')
        key_dis_center = kwargs.get('key_dis_center', '')
        realm = kwargs.get('realm', '')
        sleep(WAIT_SHORT, reason="waiting for field gets loaded properly")
        self.authentication_method_element(credentials_type='SSH').select_by_visible_text('Kerberos')
        self.username_element.send_keys(username)
        self.password_element.send_keys(password)
        sleep(WAIT_SHORT, reason="waiting for field gets loaded properly")
        self.key_dis_center_element(host_type='SSH').send_keys(key_dis_center)
        self.realm.send_keys(realm)

    def get_kerberos_ssh_form_data(self) -> dict:
        """
        returns kerberos form data for ssh
        :return: dictionary containing data of 'kerberos' form under 'SSH'
        :rtype: dict
        """
        return {'auth': 'Kerberos', 'username': self.username_element.get_attribute('value'),
                'kdc': self.key_dis_center_element(host_type='SSH').get_attribute('value'),
                'realm': self.realm.get_attribute('value'), 'password': self.password_element.get_attribute('value')}

    def fill_kerberos_windows_form(self, **kwargs) -> None:
        """
        fills the kerberos Windows form value
        :return: None
        """
        # kerbros ssh form data to be saved
        username = kwargs.get('username', '')
        password = kwargs.get('password', '')
        key_dis_center = kwargs.get('key_dis_center', '')
        kdc_port = kwargs.get('kdc_port', '')
        domain = kwargs.get('domain', '')

        self.authentication_method_element(credentials_type='Windows').select_by_visible_text('Kerberos')
        self.username_element.send_keys(username)
        self.password_element.send_keys(password)
        self.key_dis_center_element(host_type='Windows').send_keys(key_dis_center)
        self.kdc_port_element(host_type='Windows').clear()
        self.kdc_port_element(host_type='Windows').send_keys(kdc_port)
        self.domain_element.send_keys(domain)

    def get_kerberos_windows_form_data(self) -> dict:
        """
        returns kerberos form data for windows
        :return: dictionary containing data of 'kerberos' form under 'Windows'
        :rtype : dict
        """
        return {'auth': 'Kerberos', 'username': self.username_element.get_attribute('value'),
                'password': self.password_element.get_attribute('value'),
                'key_dis_center': self.key_dis_center_element(host_type='Windows').get_attribute('value'),
                'kdc_port': self.kdc_port_element(host_type='Windows').get_attribute('value'),
                'domain': self.domain_element.get_attribute('value')}


class Hash(Host):
    """Page Object for the form having Authentication method 'LM Hash or NTLM Hash'."""

    def fill_windows_hash_form(self, username: str, hash_field: str, domain: str, auth: str) -> None:
        """
        fills the LM Hash Windows form value
        :param str username: username
        :param str hash_field: hash field
        :param str domain: domain
        :param str auth: hash type
        :return : None
        """
        wait(lambda: visibility_of_element_located(
            self.authentication_method_element(credentials_type='Windows').select_by_visible_text(auth)))
        self.username_element.send_keys(username)
        self.password_element.send_keys(hash_field)
        self.domain_element.send_keys(domain)

    def get_hash_windows_form_data(self) -> dict:
        """
        returns LM Hash form data for windows
        :return: dictionary containing hash form data under 'Windows'
        :rtype: dict
        """
        return {'auth': self.authentication_method_element(credentials_type='Windows').text,
                'username': self.username_element.get_attribute('value'),
                'hash_field': self.password_element.get_attribute('value'),
                'domain': self.domain_element.get_attribute('value')}


class SNMPv3(Host):
    """Page Object for the SNMPv3 form under host category."""
    username = Find(TextField, by=By.CSS_SELECTOR, value='li[class*=opened] input[data-input-id="username"]')
    port = Find(TextField, by=By.CSS_SELECTOR, value='li[class*=opened] '
                                                     'input[data-input-id="port"]')
    security_level = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='li[class*=opened] '
                                                                     'select[data-input-id="security_level"]')
    privacy_algo = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='li[class*=opened] '
                                                                   'select[data-input-id="privacy_algorithm"]')
    privacy_password = Find(TextField, by=By.CSS_SELECTOR, value='li[class*=opened] '
                                                                 'input[data-input-id="privacy_password"]')

    def authentication_algo_element(self, data_group: str) -> WebElement:
        """
        returns authentication algorithm field element locator
        :param str data_group: data group
        :return: locator for authentication_algo element
        :rtype: WebElement
        """
        return Find(Select2Dropdown, by=By.CSS_SELECTOR, value='li[class*=opened] div[data-group="{}"] '
                                                               'select[data-input-id="auth_algorithm"]'
                    .format(data_group), context=self)

    def authentication_password_element(self, data_group: str) -> WebElement:
        """
        returns authentication password field element locator
        :param str data_group: data group
        :return: locator for authentication_password element
        :rtype: WebElement
        """
        return Find(Select2Dropdown, by=By.CSS_SELECTOR, value='li[class*=opened] div[data-group="{}"] '
                                                               'input[data-input-id="auth_password"]'
                    .format(data_group), context=self)

    def fill_snmpv3_form(self, **kwargs) -> None:
        """
        fill details for authentication and privacy form
        :return: None
        """
        # SNMPv3 form data to be saved
        username = kwargs.get('username', '')
        port = kwargs.get('port', '')
        security_level = kwargs.get('security_level', 'Authentication and privacy')
        authentication_algo = kwargs.get('authentication_algo', 'SHA1')
        auth_password = kwargs.get('auth_password', '')
        privacy_algo = kwargs.get('privacy_algo', 'AES')
        privacy_password = kwargs.get('privacy_password', '')

        self.username.send_keys(username)
        self.port.value = port
        self.security_level.select_by_visible_text(security_level)
        LoadingCircle(WAIT_SHORT)
        if security_level == 'Authentication and privacy' or security_level == 'Authentication without privacy':
            self.authentication_algo_element(data_group=security_level).select_by_visible_text(authentication_algo)
            self.authentication_password_element(data_group=security_level).send_keys(auth_password)
        if security_level == 'Authentication and privacy':
            self.privacy_algo.select_by_visible_text(privacy_algo)
            self.privacy_password.send_keys(privacy_password)

    def get_snmpv3_form_data(self) -> dict:
        """
        returns SNMPv3 form data for host
        :return: dictionary containing SNMPv3 form data under 'Host'
        :rtype: dict
        """
        security_level = self.security_level.get_value_selected()
        base_dict = {'username': self.username.get_attribute('value'),
                     'port': int(self.port.get_attribute('value')),
                     'security_level': self.security_level.get_value_selected()}
        if security_level == 'Authentication without privacy':
            base_dict.update({'authentication_algo': self.authentication_algo_element(
                data_group=security_level).get_value_selected()})
        elif security_level == 'Authentication and privacy':
            base_dict.update({'authentication_algo': self.authentication_algo_element(
                data_group=security_level).get_value_selected(),
                              'privacy_algo': self.privacy_algo.get_value_selected()})
        return base_dict
