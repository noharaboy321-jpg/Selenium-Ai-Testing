"""
Nessus page classes for Plaintext authentication under credentials tab in new scan page/ new policy page

:copyright: Tenable Network Security, 2018
:date: May 09, 2018
:last_modified: July 13, 2018
:author: @mameta, @ntarwani, @kpanchal
"""
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement

from catium.lib.const.base_constants import WAIT_SHORT
from catium.lib.webium import Find
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.text_field import TextField
from nessus.lib.const import API
from nessus.pageobjects.credentials.credentials_page import Credentials
from nessus.pageobjects.shared.loading import LoadingCircle


class PlainTextAuthentication(Credentials):
    """Page class for Plaintext authentication field under category dropdown in Nessus scan/policy credentials."""

    open_form = Find(by=By.CSS_SELECTOR, value='li[class*="opened"]')
    username = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"] input[data-input-id="username"]')
    password = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"] input[data-input-id="password"]')

    def __init__(self, **kwargs):
        super().__init__()
        self.click_credentials_type(category_name=API.Credentials.Types.CATEGORY_PLAINTEXT_AUTHENTICATION,
                                    credentials_type=kwargs.get('auth_type'))

    @property
    def opened_form_value(self):
        """returns the opened form type."""
        return self.open_form.get_attribute('data-name')

    def fill_form(self, *args, **kwargs) -> None:
        """
        Set the value of form with kwargs as a dictionary.
        :return: None
        """
        self.username.value = kwargs.get('username')
        self.password.value = kwargs.get('password')

    def get_form_data(self) -> dict:
        """
        Returns the value of filled form as a dictionary.
        :return: dictionary containing values of filled form
        :rtype: dict
        """
        return {'username': self.username.value,
                'password': self.password.value}

    @staticmethod
    def get_auth_type(pt_auth: str) -> object:
        """
        Returns object for plaintext authentication type
        :param str pt_auth: value of form type given in string
        :return: object for the particular class
        :rtype: object
        """
        for _cls in PlainTextAuthentication.__subclasses__():
            if _cls._auth_type == pt_auth:
                return _cls(auth_type=pt_auth)
        else:
            return PlainTextAuthentication(auth_type=pt_auth)


class HTTP(PlainTextAuthentication):
    """Page class for HTTP under Plaintext authentication field under category dropdown in Nessus
       scan/policy credentials."""

    # locator to select http authentication field
    http_authentication_method = Find(Select2Dropdown, by=By.CSS_SELECTOR,
                                      value='li[class*="opened"][data-name="HTTP"] '
                                            'select[data-name="Authentication method"]')

    # locator for http login form
    login_page = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"] div[data-group="HTTP login form"] '
                                                           'input[data-name="Login page"]')
    login_submission_page = Find(TextField, by=By.CSS_SELECTOR,
                                 value='li[class*="opened"][data-name="HTTP"] '
                                       'input[data-name="Login submission page"]')
    login_parameters = Find(TextField, by=By.CSS_SELECTOR,
                            value='li[class*="opened"][data-name="HTTP"] input[data-name="Login parameters"]')
    check_authentication = Find(TextField, by=By.CSS_SELECTOR,
                                value='li[class*="opened"][data-name="HTTP"] '
                                      'input[data-name="Check authentication on page"]')
    regex_to_verify = Find(TextField, by=By.CSS_SELECTOR,
                           value='li[class*="opened"][data-name="HTTP"] input[data-name*="Regex to verify"]')

    # locator for http cookies import
    add_cookies_file = Find(TextField, by=By.CSS_SELECTOR,
                            value='li[class*="opened"][data-name="HTTP"] input[data-input-id="cookies_file"]')
    remove_cookies_file = Find(by=By.CSS_SELECTOR, value='.remove-attached-file')

    # locators for global credentials in HTTP under plaintext authentication credentials
    http_global_credential_login_method = Find(Select2Dropdown, by=By.CSS_SELECTOR,
                                               value='li[class*="opened"][data-name="HTTP"] '
                                                     'select[data-name="Login method"]')
    re_authenticate_delay = Find(TextField, by=By.CSS_SELECTOR,
                                 value='li[class*="opened"][data-name="HTTP"] '
                                       'input[data-name="Re-authenticate delay (seconds)"]')
    follow_redirection = Find(TextField, by=By.CSS_SELECTOR,
                              value='li[class*="opened"][data-name="HTTP"] '
                                    'input[data-name="Follow 30x redirections (# of levels)"]')
    invert_authenticated_regex = Find(CheckboxDiv, by=By.CSS_SELECTOR,
                                      value='li[class*="opened"][data-name="HTTP"] '
                                            'div[data-name="Invert authenticated regex"]')
    use_authenticated_regex = Find(CheckboxDiv, by=By.CSS_SELECTOR,
                                   value='li[class*="opened"][data-name="HTTP"] '
                                         'div[data-name="Use authenticated regex on HTTP headers"]')
    case_insensitive_authenticated_regex = Find(CheckboxDiv, by=By.CSS_SELECTOR,
                                                value='li[class*="opened"][data-name="HTTP"] '
                                                      'div[data-name="Case insensitive authenticated regex"]')

    _auth_type = API.Credentials.PlaintextAuthentication.HTTP

    def username(self, http_auth_type: str) -> WebElement:
        """
        returns http username field
        :param str http_auth_type: http authentication type
        :return: element for http username field
        :rtype:WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] '
                                                         'div[data-group="{}"] input[data-input-id="username"]'.
                    format(self.opened_form_value, http_auth_type), context=self)

    def password(self, http_auth_type: str) -> WebElement:
        """
        returns http password field
        :param str http_auth_type: http authentication type
        :return: element for http password field
        :rtype:WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="{}"] '
                                                         'div[data-group="{}"] input[data-input-id="password"]'.
                    format(self.opened_form_value, http_auth_type), context=self)

    def fill_form(self, **kwargs) -> None:
        """
        fill Plaintext authentication credential form for FTP/IMAP/IPMI/NNTP/POP2/POP3 sub categories
        :return:None
        """
        http_auth_type = kwargs.get('http_auth_type')

        LoadingCircle(WAIT_SHORT)
        self.http_authentication_method.select_by_visible_text(http_auth_type)
        if http_auth_type == "HTTP cookies import":
            self.add_cookies_file.send_keys(kwargs.get('add_cookies_file'))
        else:
            self.username(http_auth_type).clear()
            self.username(http_auth_type).send_keys(kwargs.get("username"))
            self.password(http_auth_type).clear()
            self.password(http_auth_type).send_keys(kwargs.get("password"))
            if http_auth_type == "HTTP login form":
                self.login_page.value = kwargs.get('login_page')
                self.login_submission_page.value = kwargs.get('login_submission_page')
                self.login_parameters.value = kwargs.get('login_parameters')
                self.check_authentication.value = kwargs.get('check_authentication')
                self.regex_to_verify.value = kwargs.get('regex_to_verify')

        self.http_global_credential_login_method.select_by_visible_text(kwargs.get('login_method'))
        self.re_authenticate_delay.value = kwargs.get('re_authenticate_delay')
        self.js_scroll_into_view(self.follow_redirection)

        self.follow_redirection.value = kwargs.get('follow_redirection')
        self.invert_authenticated_regex.set_checked(kwargs.get('invert_authenticated_regex', False))
        self.use_authenticated_regex.set_checked(kwargs.get('use_authenticated_regex', False))
        self.case_insensitive_authenticated_regex.set_checked(
            kwargs.get('case_insensitive_authenticated_regex', False))

    def get_form_data(self) -> dict:
        """
        get values for http plaintext credentials
        :return: dictionary containing values of http form under Plaintext Authentication Credentials
        :rtype:dict
        """
        data = ({'login_method': self.http_global_credential_login_method.get_attribute('value'),
                 're_authenticate_delay': int(self.re_authenticate_delay.value),
                 'follow_redirection': int(self.follow_redirection.value),
                 'invert_authenticated_regex': self.invert_authenticated_regex.is_selected(),
                 'use_authenticated_regex': self.use_authenticated_regex.is_selected(),
                 'case_insensitive_authenticated_regex': self.case_insensitive_authenticated_regex.is_selected()})

        http_auth_type = self.http_authentication_method.text

        if http_auth_type == "HTTP cookies import":
            data.update({'http_auth_type': http_auth_type})

        elif http_auth_type == "HTTP login form":
            data.update({'http_auth_type': http_auth_type,
                         'username': self.username(http_auth_type).get_attribute('value'),
                         'password': self.password(http_auth_type).get_attribute('value'),
                         'login_page': self.login_page.value,
                         'login_submission_page': self.login_submission_page.value,
                         'login_parameters': self.login_parameters.value,
                         'check_authentication': self.check_authentication.value,
                         'regex_to_verify': self.regex_to_verify.value})
        else:
            data.update({'http_auth_type': http_auth_type,
                         'username': self.username(http_auth_type).get_attribute('value'),
                         'password': self.password(http_auth_type).get_attribute('value')})
        return data


class SNMPv(PlainTextAuthentication):
    """Page class for SNMPv1/v2c under Plaintext authentication field under category dropdown in
                Nessus scan/policy credentials."""

    community_string = Find(TextField, by=By.CSS_SELECTOR,
                            value='li[class*="opened"][data-name="SNMPv1/v2c"] input[data-name="Community string"]')

    # locators for SNMPv1/v2c global credentials
    udp_port = Find(TextField, by=By.CSS_SELECTOR,
                    value='li[class*="opened"][data-name="SNMPv1/v2c"] input[data-name="UDP port"]')
    additional_udp_port1 = Find(TextField, by=By.CSS_SELECTOR,
                                value='li[class*="opened"][data-name="SNMPv1/v2c"] '
                                      'input[data-input-id="additional_snmp_port1"]')
    additional_udp_port2 = Find(TextField, by=By.CSS_SELECTOR,
                                value='li[class*="opened"][data-name="SNMPv1/v2c"] '
                                      'input[data-input-id="additional_snmp_port2"]')
    additional_udp_port3 = Find(TextField, by=By.CSS_SELECTOR,
                                value='li[class*="opened"][data-name="SNMPv1/v2c"] '
                                      'input[data-input-id="additional_snmp_port3"]')
    _auth_type = API.Credentials.PlaintextAuthentication.SNMPV12

    def fill_form(self, *args, **kwargs) -> None:
        """
        fill SNMPv1/v2c form under plaintext authentication credentials
        :return:None
        """
        self.community_string.value = kwargs.get('community_string')
        self.udp_port.value = kwargs.get('udp_port')
        self.additional_udp_port1.value = kwargs.get('additional_udp_port1')
        self.additional_udp_port2.value = kwargs.get('additional_udp_port2')
        self.additional_udp_port3.value = kwargs.get('additional_udp_port3')

    def get_form_data(self) -> dict:
        """
        get filled SNMPv1/v2c form values under plaintext authentication credentials
        :return: dictionary containing values of SNMPv1/v2c form under Plaintext Authentication Credentials
        :rtype:dict
        """
        return {'community_string': self.community_string.value,
                'udp_port': int(self.udp_port.value),
                'additional_udp_port1': int(self.additional_udp_port1.value),
                'additional_udp_port2': int(self.additional_udp_port2.value),
                'additional_udp_port3': int(self.additional_udp_port3.value)}


class TelnetRshRexecCredentials(PlainTextAuthentication):
    """Page class for telnet/rsh/rexec under Plaintext authentication field under category dropdown in
            Nessus scan/policy credentials."""

    # locators for global credentials in telnet/rsh/rexec
    patch_audits_over_telnet = Find(CheckboxDiv, by=By.CSS_SELECTOR,
                                    value='li[class*="opened"][data-name="telnet/rsh/rexec"] '
                                          'div[data-name*="over telnet"]')
    patch_audits_over_rsh = Find(CheckboxDiv, by=By.CSS_SELECTOR,
                                 value='li[class*="opened"][data-name="telnet/rsh/rexec"] '
                                       'div[data-name*="over rsh"]')
    patch_audits_over_rexec = Find(CheckboxDiv, by=By.CSS_SELECTOR,
                                   value='li[class*="opened"][data-name="telnet/rsh/rexec"] '
                                         'div[data-name*="over rexec"]')
    _auth_type = API.Credentials.PlaintextAuthentication.TELNET_RSH_REXEC

    def fill_form(self, *args, **kwargs) -> None:
        """
        fill telnet/rsh/rexec form under plaintext authentication credentials
        :return:None
        """
        self.username.value = kwargs.get('username')
        self.password.value = kwargs.get('password')
        self.patch_audits_over_telnet.set_checked(kwargs.get('patch_audits_over_telnet', False))
        self.patch_audits_over_rsh.set_checked(kwargs.get('patch_audits_over_rsh', False))
        self.patch_audits_over_rexec.set_checked(kwargs.get('patch_audits_over_rexec', False))

    def get_form_data(self) -> dict:
        """
        get filled telnet/rsh/rexec form values under plaintext authentication credentials
        :return: dictionary containing values of telnet/rsh/rexec form under Plaintext Authentication Credentials
        :rtype:dict
        """
        return {'username': self.username.value,
                'password': self.password.value,
                'patch_audits_over_telnet': self.patch_audits_over_telnet.is_selected(),
                'patch_audits_over_rsh': self.patch_audits_over_rsh.is_selected(),
                'patch_audits_over_rexec': self.patch_audits_over_rexec.is_selected()}
