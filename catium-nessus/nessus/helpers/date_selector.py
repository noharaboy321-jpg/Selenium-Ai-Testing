"""
Nessus helper methods related to date picker

:copyright: Tenable Network Security, 2017
:date: November 25, 2017
:author: @rdutta
"""

from datetime import datetime, date

from selenium.webdriver.common.by import By
from selenium.webdriver.support.expected_conditions import invisibility_of_element_located

from catium.lib.log import create_logger
from catium.lib.webium.controls.date_picker import DatePicker
from catium.lib.webium.driver import get_driver_no_init
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.generic.generic_modals import UnsavedChangesModal

log = create_logger()


def select_date_in_datepicker(page_class_instance: NessusBasePage, input_date: datetime.date) -> None:
    """
    Select the date in date picker window
    :param page_class_instance: class object, where date picker's locator resides
    :param input_date: date to select (format: yyyy-mm-dd e.g. 2017-02-04)
    """
    if isinstance(input_date, str):
        log.warning("Input date should be datetime.date object, not string.")
        input_date = datetime.strptime(input_date, "%Y-%m-%d").date()

    date_picker = DatePicker(page_class_instance.select_date)
    current_day = int(page_class_instance.current_date.find_element(By.TAG_NAME, 'a').text)
    current_month = int(page_class_instance.current_date.get_attribute('data-month')) + 1
    current_year = int(page_class_instance.current_date.get_attribute('data-year'))

    year_diff = abs(input_date.year - current_year)
    if input_date >= date(current_year, current_month, current_day):
        # for dates in current or future
        navigation_count = (12 * year_diff) + input_date.month - current_month

        for count in range(navigation_count):
            date_picker.next_month()
    else:
        if invisibility_of_element_located((By.CSS_SELECTOR, 'a[data-handler="prev"]'))(get_driver_no_init()):
            log.warning("Your date can't be in the past!")
            UnsavedChangesModal().unsaved_changes_title.click()
            return

        else:
            # for dates in past
            month_diff = 12 - input_date.month
            navigation_count = (12 * (year_diff - 1)) + month_diff + current_month

            for count in range(navigation_count):
                date_picker.previous_month()

    date_picker.select_day(day=input_date.day)
