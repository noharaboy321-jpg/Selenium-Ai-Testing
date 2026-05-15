"""
User Menu PageObject

:copyright: Tenable Network Security, 2017
:date: Oct 23, 2017
:last_modified: July 15, 2021
:author: @smadan, @kpanchal
"""
from selenium.webdriver.common.by import By

from catium.helpers.sleep_lib import sleep
from catium.lib.const.base_constants import WAIT_NORMAL
from catium.lib.webium import Find
from catium.lib.webium.controls.link import Link
from catium.lib.webium.wait import wait
from nessus.pageobjects.basepage import NessusBasePage


class UserMenu(NessusBasePage):
    """Page Object for User Menu in Header of Nessus."""

    user_menu_dropdown = Find(by=By.CSS_SELECTOR, value='a[data-domselect="user-menu"]')
    user_profile_link = Find(Link, by=By.CSS_SELECTOR, value='a[href="#/settings/my-account"]')
    support_link = Find(by=By.CSS_SELECTOR, value='#menu-user-dropdown li:contains("Help & Support")')
    sign_out_link = Find(Link, by=By.CSS_SELECTOR, value='a[href="#/logout"]')
    username = Find(by=By.CSS_SELECTOR, value='.user-popup-body__text--highlight')

    def __init__(self):
        super().__init__()
        self.required_elements = ['user_menu_dropdown']

    def logout(self) -> None:
        """Helper function to perform logout in Nessus."""
        self.user_menu_dropdown.click()
        wait(lambda: self.is_element_present("sign_out_link"), waiting_for="Sign out link to be displayed")
        self.sign_out_link.click()
        sleep(WAIT_NORMAL, reason="Wait for user getting sign out.")
