"""
Nessus Proxy server communication page, contains info about Proxy server

:copyright: Tenable Network Security, 2017
:date: Feb 15, 2018
:last_modified: Nov 26, 2021
:author: @smadan, @kpanchal
"""
from selenium.webdriver.common.by import By

from catium.lib.cat_registry import cat_registry
from catium.lib.webium import Find
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.text_field import TextField
from nessus.pageobjects.basepage import NessusBasePage


@cat_registry.route('settings/proxy-server')
class ProxyServer(NessusBasePage):
    """ Page Object for Proxy Server Page under Settings in Nessus"""

    proxy_server_description_icon = Find(by=By.CSS_SELECTOR, value='.description-icon i')
    proxy_server_description = Find(by=By.CLASS_NAME, value='description-copy')
    host = Find(TextField, by=By.CSS_SELECTOR, value='input[data-key="proxy"]')
    port = Find(TextField, by=By.CSS_SELECTOR, value='input[data-key="proxy_port"]')
    username = Find(TextField, by=By.CSS_SELECTOR, value='input[data-key="proxy_username"]')
    password = Find(TextField, by=By.CSS_SELECTOR, value='input[data-key="proxy_password"]')
    auth_method = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-key="proxy_auth"]')
    user_agent = Find(TextField, by=By.CSS_SELECTOR, value='input[data-key="user_agent"]')
    test_proxy_server = Find(Clickable, by=By.CSS_SELECTOR, value='a[class*=test-proxy-authentication]')
    save_button = Find(Clickable, by=By.CSS_SELECTOR, value='button[type="submit"]')
    cancel_button = Find(Clickable, by=By.CSS_SELECTOR, value='a[class*="cancel"]')

    def __init__(self):
        super().__init__()
        self.required_elements = ['host']

    def fill_proxy_server_form(self, host: str, port: str, **kwargs) -> None:
        """
        Method for filling proxy server form.
        :param str host: proxy host
        :param str port: proxy port
        :return: None
        """
        username = kwargs.get('username', '')
        password = kwargs.get('password', '')
        auth_method = kwargs.get('auth', 'AUTO DETECT')
        user_agent = kwargs.get('agent', '')

        self.host.value = host
        self.port.value = port
        self.username.value = username
        self.password.value = password
        self.auth_method.select_by_visible_text(auth_method)
        self.user_agent.value = user_agent

    def get_proxy_server_settings(self) -> dict:
        """ Return Proxy Server settings"""
        proxy_server_settings = {'host': self.host.value,
                                 'port': self.port.value,
                                 'username': self.username.value,
                                 'password': self.password.value,
                                 'agent': self.user_agent.value,
                                 'auth': self.auth_method.get_text_selected()
                                 }

        return proxy_server_settings

    @staticmethod
    def sanitize_proxy_server_settings(proxy_data: dict) -> dict:
        """
        Returns dictionary having proxy server settings with default values if not exist.

        :param dict proxy_data: proxy server settings in a dictionary
        :return: dict
        """
        if 'username' not in proxy_data:
            proxy_data['username'] = ''
        if 'password' not in proxy_data:
            proxy_data['password'] = ''
        if 'agent' not in proxy_data:
            proxy_data['agent'] = ''
        if 'auth' not in proxy_data:
            proxy_data['auth'] = 'AUTO DETECT'

        return proxy_data
