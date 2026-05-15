"""
Nessus agent related window page

Agent Settings classes

:copyright: Tenable Network Security, 2017
:date: Aug 22, 2019
:last_modified: July 31, 2020
:author: @smadan, @kpanchal
"""

from selenium.webdriver.common.by import By
from waiting import wait

from catium.lib.cat_registry import cat_registry
from catium.lib.const import WAIT_NORMAL
from catium.lib.log import create_logger
from catium.lib.webium import Find
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.text_field import TextField
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.header.notifications import Notifications

log = create_logger()


# Agent Settings route/view
@cat_registry.route(r'sensors/agents/settings')
class AgentSettingsPage(NessusBasePage):
    """Page Object for Agent Settings Page in Nessus"""

    unlink_checkbox = Find(Clickable, by=By.CSS_SELECTOR, value='div[data-name="Remove Inactive Agents"]')
    unlink_input = Find(TextField, by=By.CSS_SELECTOR, value='input[data-domselect="inactive-time"]')
    track_unlinked_agent_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR,
                                         value='div[data-name="Track Unlinked Agents"]')
    software_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR,
                             value='div[data-name="Exclude All Agents From Software Updates"]')
    save_button = Find(Clickable, by=By.CSS_SELECTOR, value='button[data-domselect="Save"]')

    def __init__(self):
        super().__init__()

    def set_inactive_agent_time(self, days: int) -> None:
        """
        Sets the number of days for inactive agent
        
        :param int days: Number of days
        """
        self.unlink_checkbox.click()
        self.unlink_input.value = days
        self.save_button.click()

    def track_unlinked_agent(self, enable_tracking=True) -> None:
        """
        Set track unlinked agent setting
        
        :param bool enable_tracking: enable tracking if is true
        """
        if enable_tracking:
            self.track_unlinked_agent_checkbox.check()
        else:
            self.track_unlinked_agent_checkbox.uncheck()

        self.save_button.click()
        wait(lambda: Notifications().successes, waiting_for='Notification List to populate',
             timeout_seconds=WAIT_NORMAL)
