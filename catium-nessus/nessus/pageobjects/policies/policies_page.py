"""
Nessus page object classes for Policies page

:copyright: Tenable Network Security, 2017
:date: Sept 04, 2017
:last_modified: Aug 18, 2022
:author: @smadan, @rdutta, @ntarwani, @kpanchal, @krpatel.ctr
"""

import os

from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
from waiting import wait

from catium.helpers.testdata import get_file_path
from catium.lib import const
from catium.lib.cat_registry import cat_registry
from catium.lib.const import WAIT_SHORT, WAIT_TINY
from catium.lib.const.base_constants import TIME_THREE_SECONDS
from catium.lib.log import create_logger
from catium.lib.util import random_name
from catium.lib.webium import Find, Finds
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.table import GenericBaseTable, GenericTableRow
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.controls.upload_field import UploadField
from nessus.lib.const import API
from nessus.lib.const.constants import Nessus
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.generic.object_list import ObjectList
from nessus.pageobjects.policies.new_policy_form import PolicyType, NewPolicyForm
from nessus.pageobjects.scans.new_scan_form import ScanTemplatePage
from nessus.pageobjects.shared.loading import LoadingCircle

log = create_logger()


@cat_registry.route(r'/scans/policies')
class PoliciesPage(NessusBasePage):
    """Defines properties and methods inherited by the Nessus Policies Page."""
    title_in_header = Find(by=By.CSS_SELECTOR, value='#titlebar h1')
    scan_templates_link = Find(Clickable, by=By.CSS_SELECTOR, value='.description-group a')
    create_a_new_policy_link = Find(by=By.CSS_SELECTOR, value='.empty-results a')
    import_button = Find(Clickable, by=By.CSS_SELECTOR, value='#import')
    new_policy_button = Find(by=By.XPATH, value='.//a[@href="#/scans/policies/new" and contains(@class, "button")]')
    import_policies = Find(by=By.CSS_SELECTOR, value='input[class="policy-upload-form-input"]')
    more_button = Find(by=By.CSS_SELECTOR, value='#policies-overview-menu')
    copy_option = Find(by=By.CSS_SELECTOR, value='#copy')
    export_option = Find(by=By.CSS_SELECTOR, value='#export')
    delete_option = Find(by=By.CSS_SELECTOR, value='#delete')
    select_all_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='.select-all')
    plugins_tab = Find(Clickable, by=By.CSS_SELECTOR, value='[data-name="plugins"]')

    # Search related elements
    policies_searchbox = Find(TextField, by=By.CSS_SELECTOR, value='#searchbox input')
    search_icon = Find(by=By.CSS_SELECTOR, value='.glyphicons.search')
    clear_search_icon = Find(by=By.CSS_SELECTOR, value='#searchbox .glyphicons.remove')
    total_policies_count = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Total Records"]')
    selected_policies_count = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Checked"]')
    filtered_policies_count = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Results"]')
    clear_selected_item_link = Find(by=By.CSS_SELECTOR, value='a[data-domselect="clear-all"]')

    def __init__(self):
        super().__init__()
        self.required_elements = ['new_policy_button']

    @property
    def get_page_heading(self):
        """Return page title from header of your current nessus page."""
        return self.title_in_header.text

    @property
    def get_total_policies_count(self):
        """Return count of policies shows in policies table header."""
        return int(self.total_policies_count.text.split(" ")[0])

    @property
    def get_filtered_policies_count(self):
        """Return count of policies filtered with given search string shows in policies table header."""
        return int(self.filtered_policies_count.text.split(" ")[0])

    @property
    def get_selected_policies_count(self):
        """Return counted string shows in policies table header of policies selected in the list."""
        return int(self.selected_policies_count.text.split(" ")[0][1])

    def apply_search_on_policies(self, search_key: str) -> None:
        """
        apply a search in policies list
        :param str search_key: substring for search to apply
        :return: None
        """
        self.policies_searchbox.clear()
        LoadingCircle(WAIT_TINY)
        self.policies_searchbox.value = search_key

    def verify_search_result(self, search_key: str) -> bool:
        """
        verify search string exists in any column data of rows in the list
        :param str search_key: substring of applied filter
        :return: True if search key matches with extracted row data
        :rtype: bool
        """
        return True if all(search_key.lower() in row.text.lower() for row in PolicyList().rows) else False

    def import_policy_file(self, **kwargs) -> str:
        """
        import a policies file
        :param kwargs:
            :str file_name: policies file to be imported
            :str file_path: path from import
            :str policies_file: absolute path along with file name
        :return: imported file name
        :rtype: str
        """
        file_name = kwargs.get('file_name')
        file_path = kwargs.get('file_path')
        if file_name and file_path:
            policies_file = get_file_path(file_path + file_name)
        else:
            policies_file = kwargs.get('policies_file')

        policy_file_extension = os.path.splitext(policies_file)[1][1:]
        UploadField(self.import_policies).file = policies_file

        if policy_file_extension == API.Scan.ExportFormats.FORMAT_NESSUS:
            return os.path.splitext(file_name)[0].replace("_", " ") if file_name else None
        else:
            return file_name if file_name else None

    def create_new_policy(self, **kwargs) -> str:
        """
        Create a new policy
        :param kwargs:
            :str template_name: Template to create policy
            :str type: type of template (scanner/agent)
            :str policy_name: policy name to be created
            :str description: description
        :return: Name of created policy
        :rtype: str
        """
        policy_template = kwargs.get("template_name")
        if not policy_template:
            return log.error("No template name found, Can't create policy without a template.")

        new_policy_name = kwargs.get('policy_name', random_name(prefix="{} - ".format(kwargs.get("template_name"))))
        policy_description = kwargs.get('description',
                                        "Creating a new policy for {}.".format(kwargs.get("template_name")))

        self.js_scroll_into_view(element=self.new_policy_button)
        self.new_policy_button.click()
        wait(lambda: ScanTemplatePage().is_element_present('vuln_template_section'),
             waiting_for='scan templates to load properly.')

        policy_type = PolicyType()
        if kwargs.get('type') == Nessus.Scan.ScanTemplateTabs.AGENT_TAB:
            policy_type.agent.click()
        policy_type.click_by_policy(policy_text=policy_template)

        new_policy_form = NewPolicyForm()
        new_policy_form.add_policy(policy_name=new_policy_name, policy_description=policy_description)
        if not kwargs.get('add_configuration'):
            new_policy_form.save_button.click()
            LoadingCircle(WAIT_SHORT)
        return new_policy_name

    def copy_policies(self, select_all: bool = False, policy_list: list = None) -> None:
        """
        Copy all policies if select_all flag is true, otherwise copy policy listed in policy_list.
        :param bool select_all: If true then select_all checkbox become checked
        :param list policy_list: list of policy(s) to be copied.
        :return: None
        """
        self.select_all_checkbox.check() if select_all else PolicyList().select_policies(policies_list=policy_list)
        self.more_button.click()
        self.copy_option.click()

    def export_policy(self, policy_name: str) -> None:
        """
        Export policy of the given name
        :param str policy_name: name of the policy to export
        :return: None
        """
        PolicyList().select_policies(policies_list=[policy_name])
        self.more_button.click()
        self.export_option.click()

    def delete_policies(self, select_all: bool = False, policy_list: list = None) -> None:
        """
        Delete all policies if select_all flag is true, otherwise delete policy listed in policy_list.

        :param bool select_all: If true then select_all checkbox become checked
        :param list policy_list: list of policy(s) to be deleted.
        :return: None
        """
        self.select_all_checkbox.check() if select_all else PolicyList().select_policies(policies_list=policy_list)
        self.more_button.click()
        self.delete_option.click()

        delete_policy_modal = ActionCloseModal()
        delete_policy_modal.accept_action()
        delete_policy_modal.wait_for_modal_closed()

    def export_and_delete_policy(self, policy_name: str, export_policy_popup=True) -> None:
        """
        Verify export and delete policy
        :param str policy_name: policy name
        :param bool export_policy_popup: True or False
        :return: None
        """
        policy_list = PolicyList()

        # export created policy
        policy_list.export_policy(policy_name=policy_name)
        LoadingCircle(WAIT_SHORT)
        action_close_modal = ActionCloseModal()
        if export_policy_popup:
            action_close_modal.accept_action()
        LoadingCircle(TIME_THREE_SECONDS)

        # delete created policy
        policy_list.delete_policy(policy_name=policy_name)


class PolicyRecord(GenericTableRow):
    """Defines the key names for Policy Records returned by PolicyList."""
    select = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div.checkbox')
    name = Find(by=By.CSS_SELECTOR, value='td.policy-name')
    type = Find(by=By.CSS_SELECTOR, value='td:nth-child(3)')
    last_modified = Find(by=By.CSS_SELECTOR, value='td:nth-child(4)')
    export = Find(by=By.CSS_SELECTOR, value='td[title="Export"]')
    remove = Find(by=By.CSS_SELECTOR, value='td[title="Delete"]')

    @property
    def policy_name(self):
        """Returns name of the policy."""
        return self.name.text

    @property
    def policy_template_name(self):
        """Returns template name of the policy."""
        return self.type.text

    @property
    def policy_last_modified(self):
        """Returns last modified timing of the policy."""
        return self.last_modified.text


class PolicyList(ObjectList):
    """Returns a list containing Policies displayed on the Policy Management Page."""
    results = Finds(PolicyRecord, by=By.CSS_SELECTOR, value='tr.policy')
    result = Find(by=By.CSS_SELECTOR, value='tr.policy')

    object_table = Find(GenericBaseTable, value="content")
    configure_button = None
    generics_map = {GenericTableRow: PolicyRecord}

    def __init__(self):
        super().__init__()
        self.loaded()

    def loaded(self, **kwargs):
        """waits for the list of scans to populate"""
        self.is_element_present('rows', timeout=const.TIME_THIRTY_SECONDS)

    def get_all_policies(self) -> list:
        """
        Returns the list of all policies.
        :return: list of all policies
        :rtype: list
        """
        try:
            return [policy.name.text for policy in self.rows]
        except NoSuchElementException:
            return []

    def click_on_policy(self, policy_name: str) -> None:
        """
        Click on policy
        :param str policy_name: name of the policy to click
        :return: None
        """
        for policy_item in self.rows:
            if policy_item.name.text == policy_name:
                policy_item.click()
                break
        else:
            log.warning('Policy: "%s" not found in the list', policy_name)

    def select_policies(self, policies_list: list) -> None:
        """
        Select policy(s) listed in policies_list in the policies page
        :param list policies_list: policy(s) to be selected.
        :return: None
        """
        for row in self.rows:
            if row.name.text in policies_list:
                row.select.check()

    def is_policy_selected(self, policies_list: list) -> bool:
        """
        Verify if checkbox is checked against policy(s) under policies_list in the policies page
        :param list policies_list: policy(s) to be selected.
        :return: True if provided policies row is already checked
        :rtype: bool
        """
        return all(row.select.is_selected() for row in self.rows if row.name.text in policies_list)

    def delete_policy(self, policy_name: str) -> None:
        """
        Deletes policy of the given name
        :param str policy_name: name of the policy to delete
        :return: None
        """
        self.loaded()

        for policy_item in self.rows:
            if policy_item.name.text == policy_name:
                policy_item.remove.click()
                delete_policy_modal = ActionCloseModal()
                delete_policy_modal.accept_action()
                delete_policy_modal.wait_for_modal_closed()
                break
        else:
            log.warning('Delete Failed: "%s" not found in the list', policy_name)

    def export_policy(self, policy_name: str) -> None:
        """
        Export policy of the given name
        :param str policy_name: name of the policy to export
        :return: None
        """
        for policy_item in self.rows:
            if policy_item.name.text == policy_name:
                policy_item.export.click()
                break
        else:
            log.warning('Export Failed: "%s" not found in the list', policy_name)
