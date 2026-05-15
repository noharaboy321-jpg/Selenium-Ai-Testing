"""
Nessus page object class for New Policy Templates and forms

:copyright: Tenable Network Security, 2017
:date: July 21, 2017
:last_modified: March 27, 2018
:author: @rdutta, @jamreliya, @mameta, @smadan
"""

from waiting import wait

from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By

from catium.lib.cat_registry import cat_registry
from catium.lib.const import TIME_TEN_SECONDS
from catium.lib.webium import Find
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.text_field import TextField
from nessus.pageobjects.basepage import NessusBasePage


class PolicyTemplatePage(NessusBasePage):
    """Page Object for the Policy Template Page in Nessus."""
    policies = Find(by=By.CSS_SELECTOR, value='#content section :nth-child(1)')
    title_in_header = Find(by=By.CSS_SELECTOR, value='#titlebar h1')
    search_template_field = Find(by=By.CSS_SELECTOR, value='input[data-domselect="searchInput"]')

    def __init__(self):
        super().__init__()
        self.required_elements = ['policies']

    @property
    def get_page_heading(self):
        """Return page title from header of your current nessus page."""
        return self.title_in_header.text.split('\n')[0]

    def click_by_policy(self, policy_text: str) -> None:
        """
        Click a policy provided on the policy page.
        :param str policy_text: Text for the link to click.
        :return: None
        """
        wait(lambda: len(self.policies.find_elements(By.TAG_NAME, 'a')),
             waiting_for='templates to load', timeout_seconds=TIME_TEN_SECONDS)
        policies_title = self.policies.find_elements(By.TAG_NAME, 'a')
        for policy in policies_title:
            if policy.find_element(By.TAG_NAME, 'h5').text == policy_text:
                policy.click()
                break
        else:
            raise NoSuchElementException("Element with the link text " + policy_text + " not found.")


@cat_registry.route('policies/new')
class NewPolicyForm(NessusBasePage):
    """
    Page Object for New Policy Creation Page in Nessus.

    .. note:: This Page Object doesn't reroute to a URL since the actual URL
        contains an unique ID, which is unknown upfront. The best way
        to call this object is simply instantiating it after clicking
        the 'New Policy' button.
    """

    title_in_header = Find(by=By.CSS_SELECTOR, value='#titlebar h1')
    settings = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="settings"]')
    scap = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="scap"]')
    credentials = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="credentials"]')
    compliance = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="compliance"]')
    plugin = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="plugins"]')
    name_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-input-id="name"]')
    required_badge = Find(by=By.CSS_SELECTOR, value='div[class*="required"]')
    description_textarea = Find(TextField, by=By.CSS_SELECTOR, value='textarea[data-input-id="description"]')
    save_button = Find(by=By.CSS_SELECTOR, value='button[data-action="save"]')
    database_area0 = Find(by=By.XPATH,
                         value='//*[@id="active-credentials"] //div[@data-group="CyberArk"] //input[@aria-label="Database Name"] [@placeholder=''] [@aria-required="false"]')
    database_area = Find(by=By.XPATH, value='//*[@id="active-credentials"] //div[@data-group="CyberArk"] //input[@aria-label="Database Name"] [@aria-required="true"]')
    cancel_button = Find(by=By.CSS_SELECTOR, value='a.editor-cancel')
    back_to_policies = Find(by=By.CSS_SELECTOR, value='.title-box a')
    plugin_eye_icon = Find(by=By.CSS_SELECTOR, value='.glyphicons.enabled.read-only.add-tip')

    def __init__(self):
        super().__init__()
        self.required_elements = ['name_field', 'cancel_button']

    @property
    def get_page_heading(self):
        """Return page title from header of your current nessus page."""
        return self.title_in_header.text.split('\n')[0]

    def save_new_policy(self, policy_name: str) -> None:
        """
        this method specify the policy name and click on save button
        :param str policy_name: name of policy
        :return: None
        """
        self.name_field.clear()
        self.name_field.value = policy_name
        self.save_button.click()

    def add_policy(self, policy_name: str, policy_description: str) -> None:
        """
        Fill basic details in the policy form
        :param str policy_name: Name of the policy
        :param str policy_description: Description for the policy
        :return: None
        """
        self.name_field.value = policy_name
        self.description_textarea.value = policy_description

    def get_policy_form_data(self) -> dict:
        """
        Returns the saved policy data as a dictionary.
        :return: saved policy data.
        :rtype: dict
        """
        return {'policy_name': self.name_field.value, 'policy_description': self.description_textarea.value}


class PolicyType(PolicyTemplatePage):
    """Page Object for policy type"""
    scanner = Find(Clickable, by=By.CSS_SELECTOR, value='#tabs a[data-view="scanner"]')
    agent = Find(Clickable, by=By.CSS_SELECTOR, value='#tabs a[data-view="agent"]')
    agent_policies = Find(by=By.CSS_SELECTOR, value='#content section a[data-view="agent"]')

    def __init__(self):
        super().__init__()
        self.required_elements = ['scanner']
