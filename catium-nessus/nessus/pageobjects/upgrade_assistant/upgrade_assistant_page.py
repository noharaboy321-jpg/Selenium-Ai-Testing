"""
Nessus page object classes for Upgrade Assistant page

:copyright: Tenable Network Security, 2019
:date: Aug 20, 2019
:last_modified: Oct 10, 2019
:author: @kpanchal
"""

from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement

from catium.lib.cat_registry import cat_registry
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.link import Link
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.find import Find, Finds
from nessus.pageobjects.basepage import NessusBasePage


@cat_registry.route(r'/settings/migrate')
class UpgradeAssistantPage(NessusBasePage):
    """ Defines properties and methods inherited by the Nessus Upgrade Assistant Page. """

    upgrade_now_button = Find(Clickable, by=By.CSS_SELECTOR, value='button[data-domselect="start-migrate"]')
    sign_up_first_button = Find(Clickable, by=By.CSS_SELECTOR, value='button[data-domselect="sign-up"]')
    access_key = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="Access Key"]')
    secret_key = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="Secret Key"]')
    tenable_io_domain = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="Tenable Vulnerability Management domain"]')
    nessus_identifier = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="Nessus instance"]')
    upgrade_button = Find(Clickable, by=By.CSS_SELECTOR, value='button[data-domselect="migrate"]')
    cancel_button = Find(Link, by=By.CSS_SELECTOR, value='a[data-domselect="cancel"]')
    upgrade_buttons_description = Finds(by=By.CSS_SELECTOR, value='.description-copy b')
    upgrade_assistant_description = Find(by=By.CSS_SELECTOR, value='.description-copy.mt5')

    def __init__(self):
        super().__init__()

    def get_tool_tip_element(self, element_name: str) -> WebElement:
        """
        Returns UI element for tooltip

        :param str element_name: UI element name
        :return: UI element
        :rtype: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value='input[data-name="{}"] + i'.format(element_name), context=self)

    def fill_upgrade_details(self, **kwargs) -> None:
        """
        Fill Nessus Upgrade details

        :param kwargs: 
                    access_key(str): Access Key
                    secret_key(str): Secret Key
                    tenable_io_domain(str): Tenable.io Domain
                    nessus_instance(str): Nessus Identifier
        :return: None
        """
        self.access_key.value = kwargs.get('access_key')
        self.secret_key.value = kwargs.get('secret_key')
        self.tenable_io_domain.value = kwargs.get('tenable_io_domain')
        self.nessus_identifier.value = kwargs.get('nessus_instance')
