"""
WebElement for RadioGroup custom control for Nessus Manager

:copyright: Tenable Network Security, 2017
:date: Sept 05, 2017
:author: smadan
"""
from selenium.webdriver.common.by import By

from catium.lib.webium import Finds
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.radio_group import RadioGroup


class RadioGroupNessus(RadioGroup):
    """
    Inherited radio_group functionality and override get_option_elements method.
    """

    def get_option_elements(self, additional_selector=None) -> list:
        """Get all radio buttons contained in this RadioGroup"""
        family_name = self.get_attribute('data-radio-family')
        radio_options = Finds(CheckboxDiv,
                              by=By.CSS_SELECTOR,
                              value='div[class*="radio"][data-radio-family="{}"]{}'
                              .format(family_name, additional_selector or ''),
                              context=self.parent)
        return list(radio_options)
