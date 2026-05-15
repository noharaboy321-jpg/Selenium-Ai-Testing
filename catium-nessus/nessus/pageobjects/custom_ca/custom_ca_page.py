"""
custom_ca page, contains info about CA certificate
This page has method that add CA certificate and
remove CA certificate

:copyright: Tenable Network Security, 2017
:date: Feb 13, 2018
:author: @jamreliya
"""
from selenium.webdriver.common.by import By

from catium.lib.cat_registry import cat_registry
from catium.lib.const import WAIT_SHORT
from catium.lib.log import create_logger
from catium.lib.webium import Find
from catium.lib.webium.controls.text_field import TextField
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.shared.loading import LoadingCircle

log = create_logger()


@cat_registry.route('settings/custom-ca')
class CustomCAPage(NessusBasePage):
    """custom-ca under Settings contains info related to Certificate Authority"""

    certificate_field = Find(TextField, by=By.CSS_SELECTOR, value='textarea[data-domselect="Custom CA"]')
    save_button = Find(by=By.CSS_SELECTOR, value='button[data-domselect="save"]')
    cancel_button = Find(by=By.CSS_SELECTOR, value='a[data-domselect="cancel"]')

    def __init__(self):
        super().__init__()

    def add_custom_ca(self, ca_value: str) -> None:
        """
        add CA certificate
        :param str ca_value: CA certificate value
        :return: None
        """
        self.certificate_field.value = ca_value
        self.save_button.click()

    def remove_custom_ca(self) -> None:
        """
        remove CA certificate
        :return: None
        """
        self.certificate_field.clear()
        self.save_button.click()
        LoadingCircle(WAIT_SHORT)
        ActionCloseModal().accept_action()
        LoadingCircle(WAIT_SHORT)
