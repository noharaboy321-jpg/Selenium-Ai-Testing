"""
Nessus page object classes for Agent Updates tab under Sensors.

:copyright: Tenable Network Security, 2022
:date: April 29, 2022
:author: @krpatel
"""
import datetime

from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement

from catium.lib.cat_registry import cat_registry
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.find import Find, Finds
from nessus.lib.const import Nessus
from nessus.pageobjects.basepage import NessusBasePage


@cat_registry.route(r'sensors/agent-updates')
class AgentUpdatesPage(NessusBasePage):
    """ Page object class to defines the key names for agent updates page. """

    agent_updates_logo = Find(by=By.CSS_SELECTOR, value='.description-icon i')
    agent_updates_description = Find(by=By.CSS_SELECTOR, value='.description-agents-updates')
    enable_agent_updates = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div[data-domselect="enable-agent-updates"]')
    enable_agent_updates_text = Find(by=By.XPATH, value='//span[text()="Enable Agent Updates"]')
    update_option_labels = Finds(by=By.CSS_SELECTOR, value='div[aria-label="Version Update"] > span.radio-label')
    selected_agent_update_option = Find(by=By.CSS_SELECTOR,
                                        value='div.radio.checked[data-radio-family="Agent Version Update"]')
    agent_update_save_button = Find(Clickable, by=By.CSS_SELECTOR, value='button[id="agent-updates-save"]')
    agent_update_cancel_button = Find(Clickable, by=By.CSS_SELECTOR, value='div ~ a[href="#/sensors/agent-updates"]')
    feed_box_rows = Finds(by=By.CSS_SELECTOR, value='div[class*="feed-box-rows"]')
    agent_update_header = Find(Clickable, by=By.CSS_SELECTOR, value='#titlebar h1')
    manual_agent_update_button = Find(Clickable, by=By.CSS_SELECTOR, value='#manual-agent-update')
    agent_update_title = Find(by=By.XPATH, value='//label[text()="Automatic Updates"]')
    default_update_plan_ga = Find(CheckboxDiv, by=By.CSS_SELECTOR,
                                  value='div[data-radio-family="Agent Version Update"] div[data-value="ga"]')
    last_checked = Find(by=By.CSS_SELECTOR, value='div:nth-child(6) > span.feed-updates')

    def __init__(self):
        super().__init__()

    def get_element_of_agent_update_radio_button(self, update_option: str) -> WebElement:
        """
        Returns web element to select given agent update plan under Agent updates tab

        :param str update_option: agent update option to be select
        :return: Web element to click agent update option
        :rtype: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value='div[data-radio-family="Agent Version Update"] div[data-value="{}"]'.
                    format(update_option), context=self)

    def get_agent_update_plan_options(self) -> list:
        """
        Return list of agent update plan options labels

        :return: List of agent update plan options
        :rtype: list
        """
        update_options = []

        for option in self.update_option_labels:
            update_options.append(option.text)

        return update_options

    def get_selected_agent_update_plan_option(self) -> str:
        """
        Return selected agent update plan option ("ea","ga","stable)

        :return: selected agent update plan option
        :rtype: str
        """
        return self.selected_agent_update_option.get_attribute('data-value')

    def get_element_of_feed_box_labels_or_values(self, is_label: bool = True) -> list:
        """
        Returns web element
        """
        dom_tag = "label" if is_label else "span"

        return Finds(by=By.CSS_SELECTOR, value='div[class*="feed-box-rows"] {}'.format(dom_tag), context=self)

    def get_list_of_feed_box_labels_or_values(self, is_label: bool = True) -> list:
        """
        Returns list of feed box labels or values under Agent updates tab

        :param bool is_label: True to return the labels else False to return values
        :return: list of feed box labels or values
        :rtype: list
        """
        return [element.text for element in self.get_element_of_feed_box_labels_or_values(is_label=is_label)]

    def get_value_of_specific_feed_box_label(self, label_name: str) -> str:
        """
        Return feed box label value of given feed box label name

        :param str label_name: feed box label name
        :return: feed box label value
        :rtype: str
        """
        for feed_box_detail in self.feed_box_rows:
            if feed_box_detail.find_element(By.TAG_NAME, "label").text == label_name:
                return feed_box_detail.find_element(By.TAG_NAME, "span").text

    def get_element_of_agent_update_option_tip_toggle(self, update_option: str) -> WebElement:
        """
        Returns web element of tip-toggle for agent update option under Agent updates tab

        :param str update_option: agent update option to be select
        :return: Web element of tip-toggle
        :rtype: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value='div[data-value="{}"] + span + i'.format(update_option), context=self)

    def get_text_of_tip_toggle_for_specific_channel(self, tip_toggle: str):
        """
        Returns the text for Web element selected.

        :param str tip_toggle: tip-toggle to be select
        :return: text for the selected tip-toggle element
        :rtype: str
        """
        if tip_toggle == Nessus.Agents.AgentsUpdates.TOOLTIP_FOR_EA:
            update_option = Nessus.About.SoftwareUpdateChannel.UPDATE_EA_OPTION
        elif tip_toggle == Nessus.Agents.AgentsUpdates.TOOLTIP_FOR_GA:
            update_option = Nessus.About.SoftwareUpdateChannel.UPDATE_GA_OPTION
        else:
            update_option = Nessus.About.SoftwareUpdateChannel.STABLE_VERSION_OPTION

        return self.get_element_of_agent_update_option_tip_toggle(update_option).get_attribute('title')

    def get_agent_version_from_feed_box_labels(self, channel: str):
        """
        Returns the text for Web element selected.

        :param str channel: agent update channel to be select
        :return: text for the selected channel element
        :rtype: str
        """
        if channel == 'ea':
            label_name = Nessus.Agents.AgentsUpdates.EA_FEED_BOX_LABEL
        elif channel == 'ga':
            label_name = Nessus.Agents.AgentsUpdates.GA_FEED_BOX_LABEL
        else:
            label_name = Nessus.Agents.AgentsUpdates.STABLE_FEED_BOX_LABEL
        return self.get_value_of_specific_feed_box_label(label_name)

    @staticmethod
    def epoch_time_to_time(epoch_time):
        """
        Returns epoch time to the Hour/minute time format.

        :param epoch_time: epoch time
        :return: time
        :rtype: str
        """
        return datetime.datetime.fromtimestamp(epoch_time).strftime("%I:%M %p")
