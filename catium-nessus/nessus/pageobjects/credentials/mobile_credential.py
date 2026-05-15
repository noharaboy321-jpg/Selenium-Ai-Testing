"""
Nessus page classes for Mobile under credentials tab in new scan page

:Copyright: Tenable Network Security, 2018
:Date: May 03, 2018
:last_modified: July 11, 2018
:Author: @jchavda, @kpanchal
"""

from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement

from catium.lib.webium import Find
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.controls.toggleswitch import ToggleSwitch
from nessus.pageobjects.credentials.credentials_page import Credentials


class Mobile(Credentials):
    """Page class for mobile field under category dropdown in Nessus scan credentials."""
    open_form = Find(by=By.CSS_SELECTOR, value='li[class*="opened"]')

    def __init__(self, **kwargs):
        super().__init__()
        self.click_credentials_type(category_name='Mobile', credentials_type=kwargs.get('mobile_credential_type'))

    @property
    def opened_form_value(self) -> str:
        """
        Returns the opened form type.
        :rtype; string
        """
        return self.open_form.get_attribute('data-name')

    @property
    def username(self) -> WebElement:
        """
        Get username element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='[data-name="{}"]  input[data-input-id="username"]'
                    .format(self.opened_form_value), context=self)

    @property
    def password(self) -> WebElement:
        """
        Get password element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='[data-name="{}"]  input[data-input-id="password"]'
                    .format(self.opened_form_value), context=self)

    @property
    def port_element(self) -> WebElement:
        """
        Get port element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='[data-name="{}"]  input[data-input-id="port"]'
                    .format(self.opened_form_value), context=self)

    @property
    def server(self) -> WebElement:
        """
        Get server element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='[data-name="{}"]  input[data-input-id="server"]'
                    .format(self.opened_form_value), context=self)

    @property
    def https_toggle_element(self) -> ToggleSwitch:
        """
        Get https toggle element
        :rtype: ToggleSwitch
        """
        return Find(ToggleSwitch, by=By.CSS_SELECTOR,
                    value='[data-name="{}"]  div[data-input-id="https"]'
                    .format(self.opened_form_value), context=self)

    @property
    def verify_ssl_element(self) -> CheckboxDiv:
        """
        Get verify ssl element
        :rtype: CheckboxDiv
        """
        return Find(CheckboxDiv, by=By.CSS_SELECTOR,
                    value='[data-name="{}"]  div[data-input-id="verify_ssl"]'
                    .format(self.opened_form_value), context=self)


class AirWatch(Mobile):
    """Page class for AirWatch field under Mobile field in Nessus scan credentials."""
    api_url = Find(TextField, by=By.CSS_SELECTOR, value='[data-input-id="api_url"]')
    api_key = Find(TextField, by=By.CSS_SELECTOR, value='input[data-input-id="api_key"]')

    def fill_airwatch_form(self, **kwargs) -> None:
        """
        Fill form for Airwatch under Advanced Settings > Credentials > Mobile > Airwatch
        :return: None
        """
        http_switch = kwargs.get('http_switch')
        ssl = kwargs.get('ssl')

        self.api_url.value = (kwargs.get('api_url'))
        self.port_element.value = (kwargs.get('port'))
        self.username.send_keys(kwargs.get('username'))
        self.password.send_keys(kwargs.get('password'))
        self.api_key.value = (kwargs.get('api_key'))
        self.https_toggle_element.set_toggle(http_switch)
        if self.verify_ssl_element.is_displayed():
            self.verify_ssl_element.set_checked(ssl)

    def get_airwatch_form_data(self) -> dict:
        """
        Returns AirWatch form data for Mobile type
        :return:dictionary containing form data for Airwatch under Mobile credentials
        :rtype: dict
        """
        air_watch_dict = {"api_url": self.api_url.get_attribute('value'),
                          "port": int(self.port_element.get_attribute('value')),
                          "username": self.username.get_attribute('value'),
                          "api_key": self.api_key.get_attribute('value'),
                          "http_switch": self.https_toggle_element.is_selected()}

        if self.verify_ssl_element.is_displayed():
            air_watch_dict.update({"ssl": self.verify_ssl_element.is_selected()})
        return air_watch_dict


class AppleProfileManager(Mobile):
    """Page class for Apple Profile Manager field under Mobile in Nessus scan credentials."""
    force_device = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div[data-input-id="apm_force_updates"]')
    device_update_timeout = Find(TextField, by=By.CSS_SELECTOR, value='[data-input-id="apm_update_timeout"]')

    def fill_apple_profile_manager_form(self, **kwargs) -> None:
        """
        Fill form Apple profile manager under Advanced Settings > Credentials > Mobile > Apple profile manager
        :return: None
        """
        http_switch = kwargs.get('http_switch')
        ssl = kwargs.get('ssl')

        self.server.send_keys(kwargs.get('server'))
        self.port_element.value = kwargs.get('port')
        self.username.send_keys(kwargs.get('username'))
        self.password.send_keys(kwargs.get('password'))
        self.https_toggle_element.set_toggle(http_switch)
        if self.verify_ssl_element.is_displayed():
            self.verify_ssl_element.set_checked(ssl)
        self.force_device.check()
        self.device_update_timeout.value = kwargs.get('device_update_timeout')

    def get_apple_profile_manager_form_data(self) -> dict:
        """
        Returns Apple Profile Manager form data for Mobile type
        :rtype: dict
        """
        apm_dict = {"server": self.server.get_attribute('value'),
                    "port": int(self.port_element.get_attribute('value')),
                    "username": self.username.get_attribute('value'),
                    "http_switch": self.https_toggle_element.is_selected(),
                    'force_device': self.force_device.is_selected(),
                    'device_update_timeout': self.device_update_timeout.get_attribute('value')}

        if self.verify_ssl_element.is_displayed():
            apm_dict.update({"ssl": self.verify_ssl_element.is_selected()})
        return apm_dict


class GoodMDM(Mobile):
    """Page class for Good MDM field under Mobile in Nessus scan credentials."""
    domain = Find(TextField, by=By.CSS_SELECTOR, value='input[data-input-id="domain"]')

    def fill_good_mdm_form(self, **kwargs) -> None:
        """
        Fill form for GoodMDM under Advanced Settings > Credentials > Mobile > GoodMDM
        :return: None
        """
        http_switch = kwargs.get('http_switch')
        ssl = kwargs.get('ssl')

        self.server.send_keys(kwargs.get('server'))
        self.port_element.send_keys(kwargs.get('port'))
        self.domain.value = (kwargs.get('domain'))
        self.username.send_keys(kwargs.get('username'))
        self.password.send_keys(kwargs.get('password'))
        self.https_toggle_element.set_toggle(http_switch)
        if self.verify_ssl_element.is_displayed():
            self.verify_ssl_element.set_checked(ssl)

    def get_good_mdm_form_data(self):
        """
        Get good MDM form data
        :return:dictionary containing form data for Good MDM under Mobile credentials
        :rtype: dict
        """
        good_mdm_dict = {'server': self.server.get_attribute('value'),
                         'port': int(self.port_element.get_attribute('value')),
                         'domain': self.domain.get_attribute('value'),
                         'username': self.username.get_attribute('value'),
                         'http_switch': self.https_toggle_element.is_selected()}

        if self.verify_ssl_element.is_displayed():
            good_mdm_dict.update({"ssl": self.verify_ssl_element.is_selected()})
        return good_mdm_dict


class MaaS360(Mobile):
    """Page class for MaaS360 field under Mobile in Nessus scan credentials."""
    root_url = Find(TextField, by=By.CSS_SELECTOR, value='input[data-input-id="root_url"]')
    platform_id = Find(TextField, by=By.CSS_SELECTOR, value='input[data-input-id="platform_id"]')
    billing_id = Find(TextField, by=By.CSS_SELECTOR, value='input[data-input-id="billing_id"]')
    app_id = Find(TextField, by=By.CSS_SELECTOR, value='input[data-input-id="app_id"]')
    app_version = Find(TextField, by=By.CSS_SELECTOR, value='input[data-input-id="app_version"]')
    app_access_key = Find(TextField, by=By.CSS_SELECTOR, value='input[data-input-id="app_access_key"]')

    def fill_maas_mobile_form(self, **kwargs) -> None:
        """
        Fill form for MaaS360 under Advanced Settings > Credentials > Mobile > MaaS360
        :return: None
        """
        self.username.send_keys(kwargs.get('username'))
        self.password.send_keys(kwargs.get('password'))
        self.root_url.value = (kwargs.get('root_url'))
        self.platform_id.value = (kwargs.get('platform_id'))
        self.billing_id.value = (kwargs.get('billing_id'))
        self.app_id.value = (kwargs.get('app_id'))
        self.app_version.value = (kwargs.get('app_version'))
        self.app_access_key.value = (kwargs.get('app_access_key'))

    def get_maas_mobile_form_data(self):
        """
        Get MaaS360 form data
        :return:dictionary containing form data for MaaS360 under Mobile credentials
        :rtype: dict
        """
        return {'username': self.username.get_attribute('value'),
                'root_url': self.root_url.get_attribute('value'),
                'platform_id': self.platform_id.get_attribute('value'),
                'billing_id': self.billing_id.get_attribute('value'),
                'app_id': self.app_id.get_attribute('value'),
                'app_version': self.app_version.get_attribute('value'),
                'app_access_key': self.app_access_key.get_attribute('value')}


class MobileIron(Mobile):
    """Page class for MobileIron field under Mobile in Nessus scan credentials."""
    portal_url = Find(TextField, by=By.CSS_SELECTOR, value='input[data-input-id="portal_url"]')

    def fill_mobileiron_form(self, **kwargs) -> None:
        """
        Fill form for MobileIron under Advanced Settings > Credentials > Mobile > MobileIron
        :return: None
        """
        http_switch = kwargs.get('http_switch')
        ssl = kwargs.get('ssl')

        self.portal_url.value = (kwargs.get('portal_url'))
        self.port_element.value = kwargs.get('port')
        self.username.send_keys(kwargs.get('username'))
        self.password.send_keys(kwargs.get('password'))
        self.https_toggle_element.set_toggle(http_switch)
        if self.verify_ssl_element.is_displayed():
            self.verify_ssl_element.set_checked(ssl)

    def get_mobileiron_form_data(self):
        """
        Returns Mobile Iron form data for Mobile type
        :return:dictionary containing form data for MobileIron under Mobile credentials
        :rtype: dict
        """
        mobileiron_dict = {"portal_url": self.portal_url.get_attribute('value'),
                           "port": int(self.port_element.get_attribute('value')),
                           "username": self.username.get_attribute('value'),
                           "http_switch": self.https_toggle_element.is_selected()}

        if self.verify_ssl_element.is_displayed():
            mobileiron_dict.update({"ssl": self.verify_ssl_element.is_selected()})
        return mobileiron_dict
