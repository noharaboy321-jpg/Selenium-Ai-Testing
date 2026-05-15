""""
Nessus Page Object classes for SCAP tab.

:copyright: Tenable Network Security, 2017
:date: June 07, 2018
:last_modified: June 11, 2018
:author: @rdutta
"""

import os
from selenium.webdriver.common.by import By

from catium.helpers.sleep_lib import sleep
from catium.helpers.testdata import get_file_path
from catium.lib.const.base_constants import WAIT_NORMAL, TIME_THREE_SECONDS, WAIT_SHORT
from catium.lib.log import create_logger
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.find import Find, Finds
from nessus.lib.const.constants import API
from nessus.pageobjects.policies.new_policy_form import NewPolicyForm
from nessus.pageobjects.scans.new_scan_form import NewScanForm
from nessus.pageobjects.shared.loading import LoadingCircle

log = create_logger()


class SCAP(NewScanForm, NewPolicyForm):
    """Page Object class of SCAP page"""
    empty_list = Find(by=By.CSS_SELECTOR, value='#active-scap .empty')
    form_types = Finds(by=By.CSS_SELECTOR, value='.scap.component')
    linux_scap = Find(by=By.CSS_SELECTOR, value='.inactive-scap li[data-name="Linux"]')
    linux_oval = Find(by=By.CSS_SELECTOR, value='.inactive-scap li[data-name="Linux (OVAL)"]')
    windows_scap = Find(by=By.CSS_SELECTOR, value='.inactive-scap li[data-name="Windows"]')
    windows_oval = Find(by=By.CSS_SELECTOR, value='.inactive-scap li[data-name="Windows (OVAL)"]')
    credentials_tab = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="credentials"]')
    remove_credential_form = Find(by=By.CSS_SELECTOR, value='i.glyphicons.remove.add-tip')
    required_cred_link = Find(by=By.CSS_SELECTOR, value='li.scap.component.opened a.required-cred-link')
    required_cred_msg = Find(by=By.CSS_SELECTOR, value='li.scap.component.opened .message.required-creds')

    def __init__(self):
        super().__init__()
        self.scap.click()
        LoadingCircle(WAIT_NORMAL)

    def get_list_of_all_form_types(self) -> list:
        """
        Return list of all form types available in scap tab page.
        :return: list of forms
        :rtype: list
        """
        return [form.find_element(By.CSS_SELECTOR, '.instance-name').text for form in self.form_types]


class ScapAndOvalForm(SCAP):
    """Page Object class of SCAP and OVAL forms"""
    opened_form = Finds(by=By.CSS_SELECTOR, value='#active-scap .scap.component')
    form_header = Find(by=By.CSS_SELECTOR, value='.opened .component-header .instance-name')
    close_form = Find(Clickable, by=By.CSS_SELECTOR, value='.opened .component-header .remove')
    add_file = Find(Clickable, by=By.CSS_SELECTOR, value='.opened input[data-type="file"]')
    attached_file = Find(by=By.CSS_SELECTOR, value='.attached-file .file')
    remove_attached_file = Find(Clickable, by=By.CSS_SELECTOR, value='.editor.remove-attached-file')
    scap_version = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='.opened select[data-name="SCAP Version"]')
    scap_data_stream = Find(TextField, by=By.CSS_SELECTOR, value='.opened input[data-name="SCAP Data Stream ID"]')
    scap_benchmark = Find(TextField, by=By.CSS_SELECTOR, value='.opened input[data-name="SCAP Benchmark ID"]')
    scap_profile = Find(TextField, by=By.CSS_SELECTOR, value='.opened input[data-name="SCAP Profile ID"]')
    oval_result_type = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='.opened select[data-name="OVAL Result Type"]')

    def __init__(self):
        super().__init__()

    @property
    def header_of_expanded_form(self):
        """Return text written in header of a expanded form."""
        return self.form_header.text

    def get_all_opened_form(self) -> list:
        """
        Return a list containing form_type and its attached value as a dictionary of
        key-value pair of all listed opened form.
        :return: all listed opened forms
        :rtype: list
        """
        all_forms = []

        for form in self.opened_form:
            current_form = form.find_element(By.CSS_SELECTOR, '.instance-name').text
            all_forms.append({current_form.split(' File: ')[0]: current_form.split(' File: ')[1]})

        return all_forms

    def expand_form(self, form_type: str, attached_file_name: str) -> None:
        """
        Expand a form from the listed opened forms if form_type and its attached file name gets match up.
        :param str form_type: Type of form
        :param str attached_file_name: attached file name.
        :return: None
        """
        for form in self.opened_form:
            current_form = form.find_element(By.CSS_SELECTOR, '.instance-name').text
            if (current_form.split(' File: ')[0] == form_type) and \
                    (current_form.split(' File: ')[1] == attached_file_name):
                form.find_element(By.CSS_SELECTOR, '.instance-edit').click()
                break
        else:
            log.warning("No such %s form found in listed forms with %s file attached.", form_type, attached_file_name)

    def fill_form_details(self, **kwargs) -> str:
        """
        set values for all required and optional fields in opened form
        :param kwargs: data to be fill
        ..note: required and optional fields in kwargs are
            str form_type: type of form to be filled            
            ## required fields for all type of forms(scap and oval)
            str definition_file_name: definition file name to be added
            str definition_file_path: definition file path where file resides            
            ## required fields for scap forms
            str version: scap version
            str benchmark_id: scap benchmark id
            str stream_id: scap data stream id.(If version >=1.2)
            ## optional fields for scap forms
            str profile_id: scap profile id
            str result_type: oval result type
        :return: Name of the attached file
        :rtype: str
        """
        version = kwargs.get('version', '1.2')
        benchmark_id = kwargs.get('benchmark_id', None)
        profile_id = kwargs.get('profile_id', None)
        data_stream_id = kwargs.get('stream_id', None)
        result_type = kwargs.get('result_type', None)
        definition_file_name = kwargs.get('definition_file_name', None)
        definition_file_path = kwargs.get('definition_file_path', None)
        attached_definition_file_name = None

        if not (definition_file_name and definition_file_path):
            log.error("can't fill up the form. Required definition file information is missing.")
        else:
            # add definition file
            definition_file = os.path.abspath(get_file_path(definition_file_path + definition_file_name))
            self.add_file.send_keys(definition_file)
            attached_definition_file_name = self.attached_file.text

        # add data to scap forms
        if kwargs.get('form_type') in [API.Scap.Types.LINUX_SCAP, API.Scap.Types.WINDOWS_SCAP]:
            if (version < '1.2' and (not benchmark_id)) or\
                    (version >= '1.2' and (not (benchmark_id and data_stream_id))):
                log.error("can't fill up the form. Required field information's are missing.")
            else:
                self.scap_version.select_by_visible_text(version)
                self.scap_benchmark.value = benchmark_id
                if version <= '1.2' and self.is_element_present('scap_data_stream'):
                    self.scap_data_stream.value = data_stream_id
                if profile_id:
                    self.scap_profile.value = profile_id
                if result_type:
                    self.oval_result_type.select_by_visible_text(result_type)

        return attached_definition_file_name

    def get_saved_data_of_opened_form(self) -> dict:
        """
        Return a dictionary of visible saved values with their respective fields in the opened form.
        :return: all available field values
        :rtype: dict
        """
        form_values = {'definition_file_name': self.attached_file.text}
        if self.header_of_expanded_form.split(' File: ')[0] in [API.Scap.Types.LINUX_SCAP, API.Scap.Types.WINDOWS_SCAP]:
            form_values.update({'version': self.scap_version.value, 'benchmark_id': self.scap_benchmark.value,
                                'profile_id': self.scap_profile.value, 'result_type': self.oval_result_type.value})
            if self.is_element_present('scap_data_stream'):
                form_values.update({'stream_id': self.scap_data_stream.value})
            else:
                log.info("Scap Data Stream ID is not visible for scap version: %s", self.scap_version.value)

        return form_values

    def open_form_and_fill_details(self, form_information: list) -> list:
        """
        Click and open up 'count_of_forms' number of scap and oval forms specified by types.
        :param list form_information: a list containing all information of forms to be created.
            Below sample will open and fill 8 forms at a time.
            e.g.: form_information = [
            {'count_of_forms': 2, 'form_type': API.Scap.Types.WINDOWS_SCAP, 'form_details': [
                {'version': '1.2', 'benchmark_id': 'Windows_7_STIG', 'profile_id': 'MAC - 1_Classified',
                 'stream_id': '1234567', 'result_type': 'Full results w/o system characteristics',
                 'definition_file_name': 'U_Windows_7_V1R27_STIG_SCAP_1-1_Benchmark.zip',
                 'definition_file_path': 'nessus/tests/api/scan/test_data/'},
                {'version': '1.2', 'benchmark_id': 'Windows_7_STIG', 'profile_id': 'MAC - 1_Classified',
                 'stream_id': '1234567', 'result_type': 'Full results w/o system characteristics',
                 'definition_file_name': 'U_Windows_7_V1R27_STIG_SCAP_1-1_Benchmark.zip',
                 'definition_file_path': 'nessus/tests/api/scan/test_data/'}]},
            {'count_of_forms': 2, 'form_type': API.Scap.Types.WINDOWS_OVAL, 'form_details': [
                {'definition_file_name': 'U_Windows_7_V1R27_STIG_SCAP_1-1_Benchmark.zip',
                 'definition_file_path': 'nessus/tests/api/scan/test_data/'},
                {'definition_file_name': 'U_Windows_7_V1R27_STIG_SCAP_1-1_Benchmark.zip',
                 'definition_file_path': 'nessus/tests/api/scan/test_data/'}]},
            {'count_of_forms': 2, 'form_type': API.Scap.Types.LINUX_SCAP, 'form_details': [
                {'version': '1.2', 'benchmark_id': 'Windows_7_STIG', 'profile_id': 'MAC - 1_Classified',
                 'stream_id': '1234567', 'result_type': 'Full results w/o system characteristics',
                 'definition_file_name': 'U_Windows_7_V1R27_STIG_SCAP_1-1_Benchmark.zip',
                 'definition_file_path': 'nessus/tests/api/scan/test_data/'},
                {'version': '1.2', 'benchmark_id': 'Windows_7_STIG', 'profile_id': 'MAC - 1_Classified',
                 'stream_id': '1234567', 'result_type': 'Full results w/o system characteristics',
                 'definition_file_name': 'U_Windows_7_V1R27_STIG_SCAP_1-1_Benchmark.zip',
                 'definition_file_path': 'nessus/tests/api/scan/test_data/'}]},
            {'count_of_forms': 2, 'form_type': API.Scap.Types.LINUX_OVAL, 'form_details': [
                {'definition_file_name': 'scap-benchmarks.zip',
                 'definition_file_path': 'nessus/tests/ui/scan/test_data/'},
                {'definition_file_name': 'scap-benchmarks.zip',
                 'definition_file_path': 'nessus/tests/ui/scan/test_data/'}]}]
         :return: list of forms name with their attached file
         :rtype: list
        """
        added_forms = []
        mapping_forms = {API.Scap.Types.LINUX_SCAP: self.linux_scap,
                         API.Scap.Types.LINUX_OVAL: self.linux_oval,
                         API.Scap.Types.WINDOWS_SCAP: self.windows_scap,
                         API.Scap.Types.WINDOWS_OVAL: self.windows_oval}

        if not form_information:
            log.error("No information found to open and fill up any form.")
            return

        for form in form_information:
            if form['count_of_forms'] != len(form['form_details']):
                log.error("Insufficient data provided. Count_of_forms and its related information is mismatched.")
                return
            elif (form['form_type'] in [API.Scap.Types.LINUX_SCAP, API.Scap.Types.WINDOWS_SCAP]) and (
                        form['count_of_forms'] > 5):
                log.warning("Maximum 5 %s forms can be created.", form['form_type'])
            else:
                for count in range(form['count_of_forms']):
                    mapping_forms.get(form['form_type']).click()
                    form.get('form_details')[count].update({'form_type': form.get('form_type')})
                    attached_file = self.fill_form_details(**form.get('form_details')[count])
                    added_forms.append({form.get('form_type'): attached_file})
        return added_forms
