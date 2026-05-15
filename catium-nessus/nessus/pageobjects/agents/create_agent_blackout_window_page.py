"""
Nessus agent related window page

Creates class for Creating an Agent Blackout Window 

:copyright: Tenable Network Security, 2017
:date: July 25, 2017
:last_modified: Nov 23, 2020
:author: @smadan, @kpanchal
"""
from datetime import datetime, timedelta
from operator import eq

import pytz
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from waiting import wait

from catium.lib.cat_registry import cat_registry
from catium.lib.const import TIME_THREE_SECONDS, TIME_FIVE_MINUTES
from catium.lib.webium import Find
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.date_picker import DatePicker
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.text_field import TextField
from nessus.pageobjects.basepage import NessusBasePage


@cat_registry.route(r'sensors/agent-freeze-windows/new')
class CreateBlackoutWindowPage(NessusBasePage):
    """Page Object for Create Blackout Window Page in Nessus"""

    name_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-domselect="name"]')
    page_title = Find(by=By.CSS_SELECTOR, value='h1.has-back')

    save_button = Find(Clickable, by=By.CSS_SELECTOR, value='#blackout-window-save')
    cancel_button = Find(by=By.XPATH, value='.//a[@href="#/sensors/agent-freeze-windows" and contains('
                                            '@class, "button")]')
    enable_toggle_button = Find(by=By.CSS_SELECTOR, value='div.toggle-switch')
    toggle_switch = Find(by=By.CSS_SELECTOR, value='div.toggle')

    frequency = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-name="Frequency"]')
    repeat_every = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-name="Repeat Every"]')
    repeat_on = Find(Select2Dropdown, by=By.XPATH, value='.//div[@data-name="Repeat On"]/ul')
    repeat_by = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-name="Repeat By"]')

    end_time = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-name="Ends Times"]')

    # TODO: Remaining locators
    date_picker = Find(DatePicker, by=By.CSS_SELECTOR, value='div#ui-datepicker-div')
    start_date = Find(TextField, by=By.CSS_SELECTOR, value='input[name="startDate"]')
    start_time = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-name="Starts Times"]')
    search_input = Find(TextField, by=By.CSS_SELECTOR, value='.select2-search__field')
    time_zone = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-name="Timezone"]')
    end_date = Find(TextField, by=By.CSS_SELECTOR, value='input[name="endDate"]')
    summary = Find(by=By.CSS_SELECTOR, value="span.no-edit")
    weekly_repeat_on = Find(by=By.CSS_SELECTOR, value="ul[aria-label='Repeat On']")

    def __init__(self):
        super().__init__()
        self.form_fields = ['name_field']

    def new_blackout_window(self, name: str, frequency: str, is_time_set=False, bw_duration: int = 20,
                            save_window: bool = True) -> None:
        """
        Creates a new blackout window 
        
        :param str name: Blackout window name
        :param str frequency: Blackout window frequency
        :param bool is_time_set: True if specific time needs to be set else False
        :param int bw_duration: Blackout window duration in minutes
        :param bool save_window: If user want to save the freeze window or not
        """
        self._create_blackout_window(name, frequency, is_time_set, bw_duration, save_window)

    def _create_blackout_window(self, name: str, frequency: str, is_time_set: bool, bw_duration: int,
                                save_window: bool = True) -> None:
        """Helper function to create a blackout window """
        self.name_field.value = name

        # Adding below block to create blackout window which starts within 2 minutes of time.
        if is_time_set:
            # Creating two minutes ahead start_time_input using pytz and datetime libraries
            timezone = self.time_zone.value

            start_utc_time = pytz.utc.localize(datetime.utcnow()) + timedelta(minutes=2)
            start_time = start_utc_time.astimezone(pytz.timezone(timezone))
            start_time_hour = start_time.hour
            start_time_min = start_time.minute
            start_time_input = str(start_time_hour) + ":" + str(start_time_min)
            self.start_time.click()
            self.search_input.value = start_time_input
            self.search_input.send_keys(Keys.ENTER)
            self.start_date.value = start_time.strftime('%Y-%m-%d')

            end_utc_time = pytz.utc.localize(datetime.utcnow()) + timedelta(minutes=bw_duration)
            end_time = end_utc_time.astimezone(pytz.timezone(timezone))
            end_time_hour = end_time.hour
            end_time_min = end_time.minute
            end_time_input = str(end_time_hour) + ":" + str(end_time_min)
            self.end_time.click()
            self.search_input.value = end_time_input
            self.search_input.send_keys(Keys.ENTER)
            self.end_date.value = end_time.strftime('%Y-%m-%d')

        self.select_save_frequency(element=self.frequency, value=frequency, save_window=save_window)

        # Waiting till blackout window gets enabled
        if is_time_set:
            wait(lambda: pytz.utc.localize(datetime.utcnow()).
                 astimezone(pytz.timezone(timezone)).minute == start_time_min,
                 sleep_seconds=TIME_THREE_SECONDS, timeout_seconds=TIME_FIVE_MINUTES,
                 waiting_for="blackout window gets enabled")

    def select_save_frequency(self, element, value, save_window: bool = True):
        """Selects the value from the dropdown"""
        element.select_by_visible_text(value)
        if save_window:
            self.save_button.click()

    def select_week_day(self, selected_day: int) -> None:
        """
        Selects the required day from the week
        
        :param int selected_day: Day from the week list
        """

        days = self.repeat_on.find_elements(By.TAG_NAME, 'li')
        for day in days:
            checked_day = day.get_attribute('class')
            if not eq(checked_day, "checked"):
                if day.text == selected_day:
                    day.click()
                    self.save_button.click()
                    break
            else:
                if day.text == selected_day:
                    self.save_button.click()
                    break

    def configure_full_day_blackout_window(self, name, save_bw: bool = True) -> None:
        """
        This page object method will create blackout window for full day
        :param str name: Name of blackout window.
        :param bool save_bw: Save blackout window if True
        :return: None
        """
        self.name_field.value = name
        self.start_time.click()
        self.search_input.value = "00:00"
        self.search_input.send_keys(Keys.ENTER)
        self.end_time.click()
        self.search_input.value = "24:00"
        self.search_input.send_keys(Keys.ENTER)
        date_value = (datetime.now() + timedelta(days=2)).strftime("%Y-%m-%d")
        self.start_date.value = date_value
        self.end_date.value = date_value
        if save_bw:
            self.save_button.click()
