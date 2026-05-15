"""
Nessus page object class for Remote Link page

:copyright: Tenable Network Security, 2019
:date: Oct 10, 2019
:last_modified: Oct 14, 2019
:author: @kpanchal
"""

from selenium.webdriver.common.by import By

from catium.lib.cat_registry import cat_registry
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.link import Link
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.controls.toggleswitch import ToggleSwitch
from catium.lib.webium.find import Find
from nessus.lib.const.constants import Nessus
from nessus.pageobjects.basepage import NessusBasePage


@cat_registry.route(r'settings/remote-link')
class RemoteLinkPage(NessusBasePage):
    """ Page objects of Remote Link Page """

    remote_link_description = Find(by=By.CSS_SELECTOR, value='.description-copy')
    toggle_switch = Find(ToggleSwitch, by=By.CLASS_NAME, value='toggle-switch')
    link_to_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-name="Link to"]')
    scanner_name = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="Scanner Name"]')
    manager_host = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="Manager Host"]')
    manager_port = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="Manager Port"]')
    linking_key = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="Linking Key"]')
    use_proxy_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div[data-name="Proxy"]')
    save_button = Find(Clickable, by=By.CSS_SELECTOR, value='button[data-domselect="remote-link-save"]')
    cancel_button = Find(Link, by=By.CSS_SELECTOR, value='a[data-domselect="remote-link-cancel"]')

    def add_linking_settings(self, **kwargs) -> None:
        """
        Add linking settings

        Kwargs:
            link_to (str): Tenable.io / Nessus Manager
            scanner_name (str): Scanner name
            manager_host (str): host of Nessus manager
            manager_port (str): port of Nessus manager 
            linking_key (str): Linking key
            use_proxy (bool): True or False
        """
        link_to = kwargs.get('link_to', Nessus.RemoteLink.TENABLE_IO)
        use_proxy = kwargs.get('use_proxy', False)

        self.link_to_dropdown.select_by_visible_text(link_to)
        self.scanner_name.value = kwargs.get('scanner_name')

        if link_to == Nessus.RemoteLink.NESSUS_MANAGER:
            self.manager_host.value = kwargs.get('manager_host')
            self.manager_port.value = kwargs.get('manager_port')

        self.linking_key.value = kwargs.get('linking_key')

        if use_proxy:
            self.use_proxy_checkbox.check()
