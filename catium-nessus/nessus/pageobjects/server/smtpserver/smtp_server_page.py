"""
Nessus SMTP server communication page, contains info about SMTP server

:copyright: Tenable Network Security, 2017
:date: Jan 23, 2018
:author: @jamreliya
"""

from selenium.webdriver.common.by import By

from catium.lib.cat_registry import cat_registry
from catium.lib.webium import Find
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.text_field import TextField
from nessus.lib.const import API
from nessus.pageobjects.basepage import NessusBasePage


@cat_registry.route('settings/smtp-server')
class SmtpServerPage(NessusBasePage):
    """SMTP Server Tab under Settings contains info related to SMTP"""

    host_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-key="smtp_host"]')
    port_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-key="smtp_port"]')
    sender_email = Find(TextField, by=By.CSS_SELECTOR, value='input[data-key="smtp_from"]')
    encryption = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-key="smtp_enc"]')
    host_name_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-key="smtp_www_host"]')
    auth_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-key="smtp_auth"]')
    save_settings = Find(by=By.CSS_SELECTOR, value='.settings-save')
    smtp_user = Find(TextField, by=By.CSS_SELECTOR, value='input[data-key="smtp_user"]')
    smtp_pass = Find(TextField, by=By.CSS_SELECTOR, value='input[data-key="smtp_pass"]')
    send_test_email = Find(Clickable, by=By.CSS_SELECTOR, value='a[class*="send-test-email"]')
    cancel_button = Find(by=By.CSS_SELECTOR, value='.settings-cancel')

    def __init__(self):
        super().__init__()

    def add_smtp_settings(self, **kwargs) -> None:
        """
        Add smtp server settings
        
        Kwargs:
            host (str):  host of smtp
            port (int):   port of smtp server
            sender_email (str): sender email from which mail will be send 
            host_name (str): host name 
            encryption (str): type of encryption
            auth (str): authentication type
        """
        # smtp server settings data and their default values
        host = kwargs.get('host', API.Settings.Smtp.SMTP_HOST)
        port = kwargs.get('port', API.Settings.Smtp.SMTP_PORT)
        sender_email = kwargs.get('sender_email', API.Settings.Smtp.SMTP_SENDER_EMAIL)
        encryption = kwargs.get('encryption', 'No Encryption')
        auth_dropdown_value = kwargs.get('auth_method', 'NONE')
        host_name = kwargs.get('host_name', API.Settings.Smtp.SMTP_HOST_NAME)
        smtp_user = kwargs.get('smtp_user' '')
        smtp_password = kwargs.get('smtp_password', '')

        self.host_field.value = host
        self.port_field.value = port
        self.sender_email.value = sender_email
        self.host_name_field.value = host_name
        self.encryption.select_by_visible_text(encryption)
        self.auth_dropdown.select_by_visible_text(auth_dropdown_value)
        if auth_dropdown_value != 'NONE':
            self.smtp_user.value = smtp_user
            self.smtp_pass.value = smtp_password

    def get_smtp_server_settings(self) -> dict:
        """Return saved smtp server settings"""
        auth = self.auth_dropdown.get_value_selected()

        smtp_settings = {'host': self.host_field.value, 'port': self.port_field.value, 'auth_method': auth,
                         'sender_email': self.sender_email.value, 'smtp_user': self.smtp_user.value,
                         'encryption': self.encryption.get_value_selected(), 'host_name': self.host_name_field.value}

        if auth == 'NONE':
            del smtp_settings['smtp_user']

        return smtp_settings

    @staticmethod
    def sanitize_smtp_server_settings(smtp_data: dict) -> dict:
        """
        Returns dictionary having smtp settings with default values if not exist.
        
        :param dict smtp_data: smtp settings in a dictionary
        :return: dict
        """

        if 'smtp_password' in smtp_data:
            del smtp_data['smtp_password']
        if 'encryption' not in smtp_data:
            smtp_data['encryption'] = 'No Encryption'
        if 'auth_method' not in smtp_data:
            smtp_data['auth_method'] = "NONE"
        return smtp_data
