from catium.lib.webium import Find
from selenium.webdriver.common.by import By
from nessus.pageobjects.basepage import NessusBasePage
from catium.lib.webium.controls.text_field import TextField


class BasicSearch(NessusBasePage):
    """Page Object which that is used to interact with the search if it is on the page"""
    search_box = Find(TextField, by=By.CSS_SELECTOR, value='#searchbox > input')

    def __init__(self):
        super().__init__()
        self.required_elements = ['search_box']

    def is_showing(self) -> bool:
        """
        Method to determine if the search input box is visible.

        :returns: True or False
        :rtype: bool
        """
        return self.is_element_present('search_box')
