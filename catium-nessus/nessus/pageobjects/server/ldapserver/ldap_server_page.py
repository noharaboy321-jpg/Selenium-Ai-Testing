"""
Nessus LDAP server communication page, contains info about LDAP server

:copyright: Tenable Network Security, 2017
:date: Jan 18, 2018
:author: @jamreliya
"""

from selenium.webdriver.common.by import By

from catium.lib.cat_registry import cat_registry
from catium.lib.log import create_logger
from catium.lib.webium import Find
from catium.lib.webium.controls.checkbox import Checkbox
from catium.lib.webium.controls.password_field import PasswordField
from catium.lib.webium.controls.text_field import TextField
from nessus.pageobjects.basepage import NessusBasePage

log = create_logger()


@cat_registry.route('settings/ldap-server')
class LdapServerPage(NessusBasePage):
    """LDAP Server Tab under Settings contains info related to LDAP"""

    ldap_server_description_icon = Find(by=By.CSS_SELECTOR, value='.description-icon i')
    ldap_server_description = Find(by=By.CLASS_NAME, value='description-copy')
    host_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-key="ldap_host"]')
    port_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-key="ldap_port"]')
    username_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-key="ldap_username"]')
    password_field = Find(PasswordField, by=By.CSS_SELECTOR, value='input[data-key="ldap_password"]')
    base_dn_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-key="ldap_base_dn"]')
    test_ldap_server_btn = Find(by=By.CSS_SELECTOR, value='.test-ldap-server')
    save_button = Find(by=By.CSS_SELECTOR, value='.settings-save')
    show_advanced_settings = Find(Checkbox, by=By.CSS_SELECTOR, value='.ldap-advanced-settings')
    username_attribute_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-key = "ldap_username_attribute"]')
    email_attribute_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-key = "ldap_email_attribute"]')
    name_attribute_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-key="ldap_name_attribute"]')
    ca_field = Find(TextField, by=By.CSS_SELECTOR, value='textarea[data-key="ldap_ca"]')
    cancel_button = Find(by=By.CSS_SELECTOR, value='.settings-cancel')

    def __init__(self):
        super().__init__()

    def add_ldap_settings(self, host: str, port: int, username: str, password: str, base_dn: str,
                          **attributes) -> None:
        """
        :param host: ldap host value
        :param port:  port of the ldap server
        :param username: username for ldap server
        :param password: password for ldap server
        :param base_dn: base dn of ldap server
        :param attributes: advanced setting attribute dictionary
        :return: None
        """
        self.host_field.value = host
        self.port_field.value = port
        self.username_field.value = username
        self.password_field.value = password
        self.base_dn_field.value = base_dn

        if bool(attributes):
            self.show_advanced_settings.check()
            for attr, value in attributes.items():
                if value and hasattr(self, attr):
                    setattr(self, attr, value)
