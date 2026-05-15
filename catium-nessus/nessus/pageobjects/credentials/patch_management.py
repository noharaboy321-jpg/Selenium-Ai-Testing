"""
Nessus page classes for Patch Management

:copyright: Tenable Network Security, 2017
:date: May 9, 2018
:last_modified: May 15, 2018
:author: @ntarwani
"""

from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement
from catium.lib.webium import Find
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.controls.toggleswitch import ToggleSwitch
from nessus.pageobjects.credentials.credentials_page import Credentials


class PatchManagement(Credentials):
    """Page class for Patch Management field under category dropdown in Nessus scan credentials."""

    patch_management_open_form = Find(by=By.CSS_SELECTOR, value='li[class*=opened]')

    def __init__(self, **kwargs):
        super().__init__()
        self.click_credentials_type(category_name='Patch Management',
                                    credentials_type=kwargs.get('patch_type'))

    @property
    def opened_form_value(self):
        """Returns the opened form type"""
        return self.patch_management_open_form.get_attribute('data-name')

    @property
    def server(self) -> WebElement:
        """
        Returns web element for server text box
        :return: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR,
                    value='li[class*="opened"][data-name="{}"] input[data-input-id="server"]'.format(
                        self.opened_form_value), context=self)

    @property
    def port_element(self) -> WebElement:
        """
        Returns web element for port text box
        :return: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR,
                    value='li[class*="opened"][data-name="{}"] input[data-input-id="port"]'.format(
                        self.opened_form_value), context=self)

    @property
    def username(self) -> WebElement:
        """
        Returns web element for username text box
        :return: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR,
                    value='li[class*="opened"][data-name="{}"] input[data-input-id="username"]'.format(
                        self.opened_form_value), context=self)

    @property
    def password_element(self) -> WebElement:
        """
        Returns web element for password text box
        :return: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR,
                    value='li[class*="opened"][data-name="{}"] input[data-input-id="password"]'.format(
                        self.opened_form_value), context=self)

    def https_toggle_element(self) -> ToggleSwitch:
        """
        Returns web element for https toggle
        :return: ToggleSwitch
        """
        return Find(ToggleSwitch, by=By.CSS_SELECTOR,
                    value='li[class*="opened"][data-name="{}"] div[data-input-id="https"]'.format(
                        self.opened_form_value), context=self)

    def ssl_checkbox_element(self) -> CheckboxDiv:
        """
        Returns web element for Verify SSL Certificate Checkbox
        :return: CheckboxDiv
        """
        return Find(CheckboxDiv, by=By.CSS_SELECTOR,
                    value='li[class*="opened"][data-name="{}"] div[data-input-id="verify_ssl"]'.format(
                        self.opened_form_value), context=self)

    def fill_patch_management_common_form(self, **kwargs) -> None:
        """
        This form is used to fill common fields under for forms in Patch Management
        :return: None
        """
        username = kwargs.get('username', '')
        password = kwargs.get('password', '')
        server = kwargs.get('server', '')

        self.server.send_keys(server)
        self.username.send_keys(username)
        self.password_element.send_keys(password)

    def fill_red_hat_microsoft_and_ibm_form(self, form_name: str, **kwargs) -> None:
        """
        Fill form for Red Hat Satellite 5, Red Hat Satellite 6 and IBM Tivoli Endpoint Manager
        :param str form_name: name of the form to be filled.
        :return: None
        """
        self.fill_patch_management_common_form(username=kwargs.get('username'), password=kwargs.get('password'),
                                               server=kwargs.get('server'))
        self.port_element.clear()
        self.port_element.send_keys(kwargs.get('port'))
        if form_name in ['Red Hat Satellite 6 Server', 'IBM Tivoli Endpoint Manager (BigFix)', 'Microsoft WSUS']:
            self.https_toggle_element().set_toggle(kwargs.get('https_toggle'))
        if self.ssl_checkbox_element().is_displayed():
            self.ssl_checkbox_element().set_checked(kwargs.get('verify_ssl'))

    def get_red_hat_microsoft_and_ibm_data(self, form_name: str) -> dict:
        """
        Returns form data for Red Hat Satellite 5, Red Hat Satellite 6, Microsoft WSUS and IBM Tivoli Endpoint Manager
        :param str form_name: name of the form 
        :return: dictionary containing form data
        :rtype: dict
        """
        data = {'form_name': self.opened_form_value,
                'server': self.server.get_attribute('value'),
                'username': self.username.get_attribute('value'),
                'password': self.password_element.value,
                'port': self.port_element.get_attribute('value')}
        if self.ssl_checkbox_element().is_displayed():
            data.update({'verify_ssl': self.ssl_checkbox_element().is_selected()})
        if form_name in ['Red Hat Satellite 6 Server', 'IBM Tivoli Endpoint Manager (BigFix)', 'Microsoft WSUS']:
            data.update({'https_toggle': self.https_toggle_element().is_selected()})
        return data


class MicrosoftSCCM(PatchManagement):
    """
    Page Class related to Dell Kace K1000 form under Advanced Scan > Credentials > Patch Management > Microsoft SCCM
    """
    domain = Find(TextField, by=By.CSS_SELECTOR, value='input[data-input-id ="domain"]')

    def fill_microsoft_sccm_form(self, **kwargs) -> None:
        """
        Fill form for Microsoft SCCM under Advanced Scan > Credentials > Patch Management
        :return: None
        """
        self.fill_patch_management_common_form(server=kwargs.get('server'),
                                               username=kwargs.get('username'),
                                               password=kwargs.get('password'))
        self.domain.send_keys(kwargs.get('domain'))

    def get_microsoft_sccm_data(self) -> dict:
        """
        Returns Microsoft SCCM form data
        :return: dictionary containing Microsoft SCCM form data
        :rtype: dict
        """
        return {'server': self.server.get_attribute('value'),
                'username': self.username.get_attribute('value'),
                'password': self.password_element.value,
                'domain': self.domain.get_attribute('value')}


class DellKaceK1000(PatchManagement):
    """
    Page Class related to Dell Kace K1000 form under Advanced Scan > Credentials > Patch Management > Dell Kace K1000
    """
    org_db_name = Find(TextField, by=By.CSS_SELECTOR, value='input[data-input-id ="org_db_name"]')

    def fill_dell_kace_form(self, **kwargs) -> None:
        """
        Fill form for Dell Kace K1000 under Advanced Scan > Credentials > Patch Management
        :return: None
        """
        self.username.clear()
        self.fill_patch_management_common_form(server=kwargs.get('server'),
                                               username=kwargs.get('username'),
                                               password=kwargs.get('password'))
        self.port_element.clear()
        self.port_element.send_keys(kwargs.get('port'))
        self.org_db_name.value = kwargs.get('org_db_name')

    def get_dell_kace_form(self) -> dict:
        """
        Returns Dell Kace K1000 form data
        :return: dictionary containing Dell Kace K1000 form data
        :rtype: dict
        """
        return {'server': self.server.get_attribute('value'),
                'username': self.username.get_attribute('value'),
                'password': self.password_element.value,
                'port': self.port_element.get_attribute('value'),
                'org_db_name': self.org_db_name.get_attribute('value')}


class SymantecAltiris(PatchManagement):
    """
    Page Class related to Dell Kace K1000 form under Advanced Scan > Credentials > Patch Management > Symantec Altiris
    """
    use_windows_auth = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div[data-input-id="use_windows_auth"]')
    db_name = Find(TextField, by=By.CSS_SELECTOR, value='input[data-input-id="db_name"]')

    def fill_symantec_altiris_form(self, **kwargs) -> None:
        """
        Fill form for Symantec Altiris under Advanced Scan > Credentials > Patch Management
        :return: None
        """
        use_win_auth = kwargs.get('use_win_auth')

        self.fill_patch_management_common_form(server=kwargs.get('server'),
                                               username=kwargs.get('username'),
                                               password=kwargs.get('password'))
        self.port_element.clear()
        self.port_element.send_keys(kwargs.get('port'))
        self.db_name.clear()
        self.db_name.send_keys(kwargs.get('db_name'))
        self.use_windows_auth.set_checked(kwargs.get('use_win_auth'))

    def get_symantec_form_data(self) -> dict:
        """
        Returns form data for Symantec Altiris under Advanced Scan > Credentials > Patch Management
        :return: dictionary containing form data for Symantec Altiris
        :rtype: dict
        """
        return {'server': self.server.get_attribute('value'),
                'username': self.username.get_attribute('value'),
                'password': self.password_element.value,
                'port': self.port_element.get_attribute('value'),
                'db_name': self.db_name.get_attribute('value'),
                'use_win_auth': self.use_windows_auth.is_selected()}
