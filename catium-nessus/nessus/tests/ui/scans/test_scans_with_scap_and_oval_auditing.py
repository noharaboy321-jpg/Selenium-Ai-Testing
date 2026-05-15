""""
Nessus test cases related to Scans with SCAP and OVAl Auditing.

:copyright: Tenable Network Security, 2017
:date: June 06, 2018
:last_modified: Jul 15, 2025
:author: @rdutta, @jchavda, @krpatel.ctr
"""
import pytest

from catium.helpers.testdata import load_testdata
from catium.lib.const import WAIT_NORMAL, WAIT_SHORT, WAIT_LONG
from catium.lib.const.base_constants import TIME_THREE_SECONDS
from catium.lib.log.log import create_logger
from catium.lib.util import random_name
from catium.lib.webium.driver import get_driver
from catium.lib.webium.wait import wait
from nessus.lib.const import API, Nessus
from nessus.lib.const.constants import Prefixes
from nessus.lib.message.messages import Messages
from nessus.pageobjects.credentials.host import Password
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications, NotificationActions
from nessus.pageobjects.scans.new_scan_form import NewScanForm
from nessus.pageobjects.scans.scan_view_page import ScanViewPage
from nessus.pageobjects.scans.scans_page import ScanList, ScansPage
from nessus.pageobjects.scap.scap_page import SCAP, ScapAndOvalForm
from nessus.pageobjects.shared.loading import LoadingCircle

log = create_logger()

scap_and_oval_information = API.Scap.SCAP_AND_OVAL_INFORMATION


def go_back_to_scans_list():
    """
    Click on 'Back to Scan templates' and 'Back to Scan' link
    :return: None
    """
    HeaderBasePage().scan_link.click()
    scan_page = ScansPage()
    scan_page.refresh()
    wait(lambda: scan_page.is_element_present('create_a_new_scan_link') or scan_page.is_element_present(
        'scan_searchbox'), waiting_for='Scan page to load properly')


@pytest.mark.scans_2
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
@pytest.mark.parametrize('create_scans', [{'scans_details': [
    {'scan_template': Nessus.TemplateNames.SCAP_OVAL, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
     'scan_name': random_name(prefix="Scanner scan with {} - ".format(Nessus.TemplateNames.SCAP_OVAL)),
     'target_ip': Nessus.Scan.Target.AWS_LINUX_TARGET_1, 'add_configuration': True}]}], indirect=True)
class TestScansWithSCAPAndOVALForScanner:
    """Covers test cases related to Scans with SCAP and OVAl Auditing for Scanner."""
    form_information = load_testdata('nessus/tests/ui/scans/test_data/scap_oval_auditing_data.json')

    @pytest.mark.nessus_legacy
    def test_availability_of_all_types_of_scap_and_oval_form(self, create_scans):
        """
        #NQA-1271: Automation tests related to scap page(#Test-1: For Scanner Scan)
        Test to verify visibility of all types of scap and oval forms.
        1. Click 'New scan' button and select 'Scap and Oval auditing' template under 'Scanner' tab.
        2. Verify visibility of 'SCAP' tab.
        3. Verify all types of scap and oval forms (Linux(SCAP), Linux(Oval), Windows(SCAP), Windows(Oval)) are present.
        4. Verify ‘Add SCAP checks from the adjacent list’ message is displayed if no forms opened.
        """
        assert NewScanForm().is_element_present('scap'), "SCAP tab is invisible."

        scap_page = SCAP()

        assert sorted(scap_page.get_list_of_all_form_types()) == sorted(API.Scap.Types.VALID_TYPES), \
            "Any of the scap and oval auditing form is missing or mismatched."

        assert scap_page.empty_list.text == 'Add SCAP checks from the adjacent list', \
            'Expected message for empty list is missing or mismatched.'

        go_back_to_scans_list()

    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize('test_data', scap_and_oval_information)
    def test_save_values_retained_for_scanner_scan_with_scap_and_oval_auditing(self, create_scans, test_data):
        """
        #NQA-1271: Automation tests related to scap page(#Test-2: For Scanner Scan)
        Test to verify saved values are retained after saving a scanner scan.        
        1. Create a scanner scan with 'Scap and Oval auditing' template.
        2. Go to SCAP tab, open and fill all types of forms with required and optional fields
        3. Hit Save and verify success notification.
        4. Click on scanner scan and navigated to 'SCAP' tab.
        5. Verify the above configuration still exists for all saved forms.
        """
        scan_name = create_scans[0]

        if test_data.get('form_type') in [API.Scap.Types.LINUX_SCAP, API.Scap.Types.LINUX_OVAL]:
            Password(host_type=API.Credentials.Host.Types.SSH).fill_password_ssh_form(
                username=Nessus.USERNAME, password=Nessus.PASSWORD, auth=API.Credentials.Host.SSHAuthTypes.PASSWORD)
        elif test_data.get('form_type') in [API.Scap.Types.WINDOWS_SCAP, API.Scap.Types.WINDOWS_OVAL]:
            Password(host_type=API.Credentials.Host.Types.WINDOWS).fill_password_windows_form(
                username=Nessus.USERNAME, password=Nessus.PASSWORD, domain=Nessus.Scan.Target.AWS_LINUX_TARGET_2,
                auth=API.Credentials.Host.WindowsAuthTypes.PASSWORD)
        else:
            log.info("%s form doesn't need any credentials to be added.", test_data.get('form_type'))

        scap_page = ScapAndOvalForm()
        attached_file_name = scap_page.open_form_and_fill_details(form_information=[test_data]
                                                                  )[0].get(test_data.get('form_type'))
        NotificationActions().remove_all()
        LoadingCircle(WAIT_SHORT)
        scap_page.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            "Success notifications for saving scan is mismatched or missing."

        LoadingCircle(TIME_THREE_SECONDS)
        scans_list = ScanList()

        assert scan_name in scans_list.get_all_scans(), "Saved scan is not listed in scan list."

        scan_form_data_to_compare = dict(filter(lambda i: i[0] not in ('form_type', 'definition_file_path'),
                                                test_data.get('form_details')[0].items()))
        scan_form_data_to_compare['definition_file_name'] = attached_file_name

        scans_list.click_on_scan(scan_name=scan_name)
        LoadingCircle(WAIT_NORMAL)
        scan_details_page = ScanViewPage()
        scan_details_page.configure_button.click()
        LoadingCircle(WAIT_NORMAL)
        scap_page.scap.click()
        scap_page.expand_form(form_type=test_data.get('form_type'),
                              attached_file_name=scan_form_data_to_compare.get('definition_file_name'))
        LoadingCircle(TIME_THREE_SECONDS)

        assert scap_page.get_saved_data_of_opened_form() == scan_form_data_to_compare, \
            "Saved values weren't retained in the scan form after saving the scan successfully."

        go_back_to_scans_list()

    @pytest.mark.nessus_legacy
    def test_save_scan_page_without_scap_content(self, create_scans):
        """
        NQA-1272: Automation tests related to scap page.
        Test-1: Verify error message throws if no scap content added.
        1. Create a Scanner scan with ‘SCAP & OVAL Auditing’ template.
        2. Provide only name field, keep blank all other fields
        3. Hit on save button, verify that the error will be thrown “Error: SCAP content must be added to this policy.”
        """
        ScansPage().save_button.click()

        assert Notifications().errors[-1] == Messages.NotificationMessages.Scap.scap_content_error, \
            'Notification is missing when saving the scan without Scap Content'

        go_back_to_scans_list()

    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize('test_data', [
        {'count_of_forms': 1, 'form_type': API.Scap.Types.LINUX_SCAP, 'form_details': [
            {'definition_file_name': 'U_Windows_7_V1R27_STIG_SCAP_1-1_Benchmark.zip',
             'definition_file_path': 'nessus/tests/ui/scan/test_data/'}]},
        {'count_of_forms': 1, 'form_type': API.Scap.Types.WINDOWS_SCAP, 'form_details': [
            {'version': '1.2', 'profile_id': 'Windows - 1_Classified',
             'result_type': 'Full results w/o system characteristics',
             'definition_file_name': 'U_Windows_7_V1R27_STIG_SCAP_1-1_Benchmark.zip',
             'definition_file_path': 'nessus/tests/ui/scan/test_data/'}]}])
    def test_save_scan_with_blank_benchmark_data_stream_field(self, create_scans, test_data):
        """
        NQA-1272: Automation tests related to scap page.
        Test-2: Verify blank values in required field throws error while saving the scan.
        1. Create a Scanner scan with ‘SCAP & OVAL Auditing’ template.
        2. Add scap file and other required fields except ‘Benchmark ID’ and ‘Scap Data stream ID’
           (keep them blank) fields under SCAP form.
        3. Hit ‘Save’ and verify error notification.
        """
        scan_form = ScapAndOvalForm()
        scan_form.open_form_and_fill_details(form_information=[test_data])

        notification = NotificationActions()
        notification.remove_all()
        scan_form.save_button.click()

        assert Notifications().errors[-1] == Messages.NotificationMessages.Scap.data_stream_error, \
            'Notification is missing for saving the scan without SCAP data stream'

        notification.remove_all()
        scan_form.scap_data_stream.value = '1234567'
        LoadingCircle(WAIT_NORMAL)
        scan_form.save_button.click()

        assert Notifications().errors[-1] == Messages.NotificationMessages.Scap.benchmark_id_error, \
            'Notification is missing for saving the scan without Benchmark Id'

        go_back_to_scans_list()

    @pytest.mark.nessus_legacy
    def test_visibility_of_data_stream_field_on_scap_page(self, create_scans):
        """
        NQA-1272: Automation tests related to scap page.
        Test-3: Verify scap data stream ID get vanished if you select scap version less than ‘1.2’.
        1. Create a Scanner scan with ‘SCAP & OVAL Auditing’ template.
        2. Fill all required inputs.
        3. Verify scap data stream ID field is visible.
        4. Select scap version less 1.2 from the dropdown.
        5. Verify ‘scap data stream ID’ get invisible now.
        """
        scan_form = ScapAndOvalForm()
        scan_form.linux_scap.click()

        assert scan_form.scap_data_stream.is_displayed(), 'Scap data stream field is invisible'

        scan_form.scap_version.select_by_visible_text('1.0')

        assert not scan_form.scap_data_stream.is_displayed(), 'Scap data stream field is visible'

        go_back_to_scans_list()

    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize('test_data', [
        {'count_of_forms': 1, 'form_type': API.Scap.Types.WINDOWS_SCAP, 'form_details': [
            {'version': '1.2', 'benchmark_id': 'Windows_7_STIG', 'profile_id': 'Windows - 1_Classified',
             'stream_id': '1234567', 'result_type': 'Full results w/o system characteristics'}]},
        {'count_of_forms': 1, 'form_type': API.Scap.Types.WINDOWS_OVAL, 'form_details': [
            {'definition_file_name': None, 'definition_file_path': None}]},
        {'count_of_forms': 1, 'form_type': API.Scap.Types.LINUX_SCAP, 'form_details': [
            {'version': '1.1', 'benchmark_id': 'RHEL_6_STIG', 'profile_id': 'MAC - 1_Classified',
             'result_type': 'Full results w/ system characteristics'}]},
        {'count_of_forms': 1, 'form_type': API.Scap.Types.LINUX_OVAL, 'form_details': [
            {'definition_file_name': None, 'definition_file_path': None}]}])
    def test_save_scan_without_attach_definition_file(self, create_scans, test_data):
        """
        NQA-1272: Automation tests related to scap page.
        Test-4: Verify saving scan without adding the file, will throw an error
        1. Create a Scanner scan with ‘SCAP & OVAL Auditing’ template.
        2. Fill all required inputs.
        3. Don’t add any scap Or oval definition file
        4. Hit ‘Save’ and verify error notification as “Error: SCAP File(Zip) is required”.
        """
        scap_page = ScapAndOvalForm()
        scap_page.open_form_and_fill_details(form_information=[test_data])

        NotificationActions().remove_all()
        scap_page.save_button.click()

        error_message = Notifications().errors[-1]

        assert error_message in [Messages.NotificationMessages.Scap.scap_file_error,
                                 Messages.NotificationMessages.Scap.oval_file_error], \
            'Notification is missing when saving the scan without Scap and Oval file(Zip)'

        go_back_to_scans_list()

    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize('test_data', scap_and_oval_information)
    def test_notice_msg_and_credential_link_on_scap_page(self, create_scans, test_data):
        """
        NQA-1272: Automation tests related to scap page.
        Test-5: Verify the notice message to add credentials on ‘SCAP’ tab.
        1. Create a Scanner scan with ‘SCAP & OVAL Auditing’ template
        2. Navigate to ‘SCAP’ tab and add a Linux (scap/oval) form
        3. Verify notice message “NOTICE: SSH credentials are required for this audit.”
        4. Also verify clicking on the typed credential link will take you to that opened
           credential typed category directly
        """
        scap_page = ScapAndOvalForm()
        mapping_forms = {API.Scap.Types.LINUX_SCAP: scap_page.linux_scap,
                         API.Scap.Types.LINUX_OVAL: scap_page.linux_oval,
                         API.Scap.Types.WINDOWS_SCAP: scap_page.windows_scap,
                         API.Scap.Types.WINDOWS_OVAL: scap_page.windows_oval}

        mapping_forms.get(test_data['form_type']).click()
        LoadingCircle(WAIT_NORMAL)

        assert scap_page.required_cred_msg.is_displayed(), 'NOTICE Message for Credential is missing'

        scap_page.required_cred_link.click()

        assert '/credentials' in scap_page.current_url, "Credential page is not opened"

        go_back_to_scans_list()

    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize('test_data', scap_and_oval_information)
    def test_save_values_retained_with_remove_definition_file(self, create_scans, test_data):
        """
        NQA-1272: Automation tests related to scap page.
        Test-6: Verify removing of added scap file or required field data will throw errors and doesn't let you to edit
        configuration of scan.
        1. Create and save a Scanner scan with ‘SCAP & OVAL Auditing’ template and verify scan has saved
           properly.
        2. Click the saved scan, hit configure.
        3. Navigate to scap page and remove added scap/oval definition file.
        4. Hit ‘Save’ and verify error notifications as Error: SCAP File (Zip) is required.”
        5. Again try to remove the data of “SCAP Data Stream ID” field from the form and click on “Save” button.
        6. Verify scan should not save and must throw you an error notification as “Error: SCAP Data Stream ID
           is required.”
        7. Repeat above steps “SCAP Benchmark ID” field.
        """
        scan_name = create_scans[0]

        if test_data.get('form_type') in [API.Scap.Types.LINUX_SCAP, API.Scap.Types.LINUX_OVAL]:
            Password(host_type=API.Credentials.Host.Types.SSH).fill_password_ssh_form(
                username=Nessus.USERNAME, password=Nessus.PASSWORD, auth=API.Credentials.Host.SSHAuthTypes.PASSWORD)
        elif test_data.get('form_type') in [API.Scap.Types.WINDOWS_SCAP, API.Scap.Types.WINDOWS_OVAL]:
            Password(host_type=API.Credentials.Host.Types.WINDOWS).fill_password_windows_form(
                username=Nessus.USERNAME, password=Nessus.PASSWORD, domain=Nessus.Scan.Target.AWS_LINUX_TARGET_2,
                auth=API.Credentials.Host.WindowsAuthTypes.PASSWORD)
        else:
            log.info("%s form doesn't need any credentials to be added.", test_data.get('form_type'))

        scap_page = ScapAndOvalForm()
        attached_file_name = scap_page.open_form_and_fill_details(form_information=[test_data]
                                                                  )[0].get(test_data.get('form_type'))

        notification = NotificationActions()
        notification.remove_all()
        scap_page.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            'Notification is missing when saving the scan'

        scans_list = ScanList()

        assert scan_name in scans_list.get_all_scans(), "Saved scan is not listed in scan list."

        scan_form_data_to_compare = dict(filter(lambda i: i[0] not in ('form_type', 'definition_file_path'),
                                                test_data.get('form_details')[0].items()))
        scan_form_data_to_compare['definition_file_name'] = attached_file_name

        scans_list.click_on_scan(scan_name=scan_name)
        LoadingCircle(WAIT_SHORT)
        scan_details_page = ScanViewPage()
        scan_details_page.configure_button.click()
        LoadingCircle(WAIT_SHORT)
        scap_page.scap.click()
        scap_page.expand_form(form_type=test_data.get('form_type'),
                              attached_file_name=scan_form_data_to_compare.get('definition_file_name'))

        LoadingCircle(WAIT_SHORT)
        # Remove added scap/oval definition file.
        scap_page.remove_attached_file.click()
        notification.remove_all()
        scap_page.save_button.click()
        error_message = Notifications().errors[-1]

        assert error_message in [Messages.NotificationMessages.Scap.scap_file_error,
                                 Messages.NotificationMessages.Scap.oval_file_error], \
            'Notification is missing when saving the scan without Scap and Oval file(Zip)'

        if test_data.get('form_type') in [API.Scap.Types.LINUX_SCAP, API.Scap.Types.WINDOWS_SCAP]:
            # Remove the data of “SCAP Data Stream ID” field from the form and click on “Save” button.
            scap_page.back_link.click()
            scan_details_page.configure_button.click()
            LoadingCircle(WAIT_SHORT)
            scap_page.scap.click()
            scap_page.expand_form(form_type=test_data.get('form_type'),
                                  attached_file_name=scan_form_data_to_compare.get('definition_file_name'))
            LoadingCircle(WAIT_SHORT)
            scap_page.scap_data_stream.clear()
            notification.remove_all()
            scap_page.save_button.click()

            assert Notifications().errors[-1] == Messages.NotificationMessages.Scap.data_stream_error, \
                'Notification is missing when saving the scan without Scap Data Stream'

            # Remove the data of “SCAP Benchmark ID” field from the form and click on “Save” button.
            scap_page.back_link.click()
            scan_details_page.configure_button.click()
            LoadingCircle(WAIT_SHORT)
            scap_page.scap.click()
            scap_page.expand_form(form_type=test_data.get('form_type'),
                                  attached_file_name=scan_form_data_to_compare.get('definition_file_name'))
            LoadingCircle(WAIT_SHORT)
            scap_page.scap_benchmark.clear()
            notification.remove_all()
            scap_page.save_button.click()

            assert Notifications().errors[-1] == Messages.NotificationMessages.Scap.benchmark_id_error, \
                'Notification is missing when saving the scan without Scap Benchmark Id'

        go_back_to_scans_list()

    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize('test_data', scap_and_oval_information)
    def test_save_values_retained_with_remove_scap_content(self, create_scans, test_data):
        """
        NQA-1272: Automation tests related to scap page.
        Test-7: Verify changes made to scan are not saved for ‘SCAP & OVAL Auditing’ if you remove all of the
        scap already added to it.
        1. Create and save a Scanner scan with ‘SCAP & OVAL Auditing’ template and verify scan has
        saved properly.
        2. Click the saved scan and modify the scan name.
        3. Navigate to “SCAP” tab and remove all scap/oval forms you have already added and Click on “Save” button.
        4. Scan should not save and it must throw you an error notification as “Error: Scap content must be
        added to this scan”.
        """
        scan_name = create_scans[0]

        if test_data.get('form_type') in [API.Scap.Types.LINUX_SCAP, API.Scap.Types.LINUX_OVAL]:
            Password(host_type=API.Credentials.Host.Types.SSH).fill_password_ssh_form(
                username=Nessus.USERNAME, password=Nessus.PASSWORD, auth=API.Credentials.Host.SSHAuthTypes.PASSWORD)
        elif test_data.get('form_type') in [API.Scap.Types.WINDOWS_SCAP, API.Scap.Types.WINDOWS_OVAL]:
            Password(host_type=API.Credentials.Host.Types.WINDOWS).fill_password_windows_form(
                username=Nessus.USERNAME, password=Nessus.PASSWORD, domain=Nessus.Scan.Target.AWS_LINUX_TARGET_2,
                auth=API.Credentials.Host.WindowsAuthTypes.PASSWORD)
        else:
            log.info("%s form doesn't need any credentials to be added.", test_data.get('form_type'))

        scap_page = ScapAndOvalForm()
        attached_file_name = scap_page.open_form_and_fill_details(form_information=[test_data]
                                                                  )[0].get(test_data.get('form_type'))

        notification = NotificationActions()
        notification.remove_all()
        scap_page.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            'Notification is missing when saving the scan'

        scans_list = ScanList()

        assert scan_name in scans_list.get_all_scans(), "Saved scan is not listed in scan list."

        scan_form_data_to_compare = dict(filter(lambda i: i[0] not in ('form_type', 'definition_file_path'),
                                                test_data.get('form_details')[0].items()))
        scan_form_data_to_compare['definition_file_name'] = attached_file_name

        scans_list.click_on_scan(scan_name=scan_name)
        ScanViewPage().configure_button.click()
        ScansPage().name_field.value = random_name(prefix="Editing {} - ".format(scan_name))
        LoadingCircle(WAIT_SHORT)
        scap_page.scap.click()
        scap_page.expand_form(form_type=test_data.get('form_type'),
                              attached_file_name=scan_form_data_to_compare.get('definition_file_name'))

        LoadingCircle(WAIT_NORMAL)
        # Remove all Scap or Oval form content
        scap_page.close_form.click()
        notification.remove_all()
        scap_page.save_button.click()

        assert Notifications().errors[-1] == Messages.NotificationMessages.Scap.scap_content_error, \
            'Notification is missing when saving the scan without Scap and Oval Content'

        go_back_to_scans_list()

    @pytest.mark.parametrize('test_data', scap_and_oval_information)
    def test_save_values_retained_with_remove_credential(self, create_scans, test_data):
        """
        NQA-1272: Automation tests related to scap page.
        Test-8: Verify changes made to scan are not saved for ‘SCAP & OVAL Auditing’ if you remove all of the
        credentials form (mandatory field) already added to it.
        1. Create and save a Scanner scan with ‘SCAP & OVAL Auditing’ template and verify scan has saved
        properly.
        2. Click on the existing created scan having template ‘SCAP & OVAL Auditing’.
        3. Navigate to “Credentials” tab and remove all credential(s) you have already added.
        4. Click on “Save” button, verify it should take you to the “SCAP” tab.
        5. Verify scan should not save and must throw you an error notification as “Error: Linux SCAP requires SSH
        credentials.”/ “Error: Windows SCAP requires Windows credentials.”/ “Error: Linux (OVAL) SCAP requires SSH
        credentials.”/ “Error: Windows (OVAL) SCAP requires Windows credentials.” depending on which scap file you
        have already added to scan.
        """
        scan_name = create_scans[0]

        if test_data.get('form_type') in [API.Scap.Types.LINUX_SCAP, API.Scap.Types.LINUX_OVAL]:
            Password(host_type=API.Credentials.Host.Types.SSH).fill_password_ssh_form(
                username=Nessus.USERNAME, password=Nessus.PASSWORD, auth=API.Credentials.Host.SSHAuthTypes.PASSWORD)
        elif test_data.get('form_type') in [API.Scap.Types.WINDOWS_SCAP, API.Scap.Types.WINDOWS_OVAL]:
            Password(host_type=API.Credentials.Host.Types.WINDOWS).fill_password_windows_form(
                username=Nessus.USERNAME, password=Nessus.PASSWORD, domain=Nessus.Scan.Target.AWS_LINUX_TARGET_2,
                auth=API.Credentials.Host.WindowsAuthTypes.PASSWORD)
        else:
            log.info("%s form doesn't need any credentials to be added.", test_data.get('form_type'))

        expected_error = {
            API.Scap.Types.LINUX_SCAP: Messages.NotificationMessages.Scap.scap_ssh_credential_error,
            API.Scap.Types.LINUX_OVAL: Messages.NotificationMessages.Scap.scap_oval_ssh_credential_error,
            API.Scap.Types.WINDOWS_SCAP: Messages.NotificationMessages.Scap.scap_window_credential_error,
            API.Scap.Types.WINDOWS_OVAL: Messages.NotificationMessages.Scap.scap_oval_window_credential_error}

        scap_page = ScapAndOvalForm()
        scap_page.open_form_and_fill_details(form_information=[test_data])
        notification = NotificationActions()
        notification.remove_all()
        scap_page.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            'Notification is missing when saving the scan'

        scans_list = ScanList()

        assert scan_name in scans_list.get_all_scans(), "Saved scan is not listed in scan list."

        scans_list.click_on_scan(scan_name=scan_name)
        LoadingCircle(WAIT_SHORT)
        ScanViewPage().configure_button.click()
        scap_page.credentials_tab.click()

        LoadingCircle(WAIT_SHORT)
        # Remove all credential(s) you have already added.
        scap_page.remove_credential_form.click()
        notification.remove_all()
        scap_page.save_button.click()

        assert Notifications().errors[-1] == expected_error.get(test_data['form_type']), \
            'Notification is missing when saving the scan without Credentials'

        go_back_to_scans_list()

    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize('form_types', [API.Scap.Types.WINDOWS_SCAP, API.Scap.Types.LINUX_SCAP,
                                            API.Scap.Types.WINDOWS_OVAL, API.Scap.Types.LINUX_OVAL])
    def test_invisible_component_link_on_scap_page(self, create_scans, form_types):
        """
        NQA-1272: Automation tests related to scap page.
        Test-9: Verify the component form link is invisible when its maximum count gets exits.
        1. Navigate to “SCAP” tab for creating/editing a scan having template ‘SCAP & OVAL Auditing’.
        2. Try to add the component form until its maximum count is not get exits.
        3. Verify that component link is invisible when its max count exits.
        4. For infinite count we can try to add more than 10 forms.
        """
        scap_page = ScapAndOvalForm()
        mapping_forms = {API.Scap.Types.LINUX_SCAP: scap_page.linux_scap,
                         API.Scap.Types.LINUX_OVAL: scap_page.linux_oval,
                         API.Scap.Types.WINDOWS_SCAP: scap_page.windows_scap,
                         API.Scap.Types.WINDOWS_OVAL: scap_page.windows_oval}

        if form_types in [API.Scap.Types.LINUX_OVAL, API.Scap.Types.WINDOWS_OVAL]:
            for i in range(11):
                mapping_forms.get(form_types).click()
            assert mapping_forms.get(form_types).is_displayed(), 'Can not add more than 10 forms with infinity' \
                                                                 ' component link '
        else:
            self.form_information["form_test_data"][0]["form_type"] = form_types
            scap_page.open_form_and_fill_details(form_information=self.form_information["form_test_data"])

            assert not mapping_forms.get(self.form_information["form_test_data"][0]["form_type"]).is_displayed(), \
                'Component link is not invisible when its max count exits'

        go_back_to_scans_list()


@pytest.mark.scans_2
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
@pytest.mark.parametrize("create_agent_groups", [{'agent_group_details': [
    {'agent_group_name': Prefixes.AGENT_GROUP}]}], indirect=True)
@pytest.mark.parametrize('create_scans', [{'scans_details': [
    {'scan_template': Nessus.TemplateNames.SCAP_OVAL_AGENT, 'scan_type': Nessus.Scan.ScanTemplateTabs.AGENT_TAB,
     'scan_name': random_name(prefix="Agent scan with {} - ".format(Nessus.TemplateNames.SCAP_OVAL_AGENT)),
     'description': 'Created agent scan for Scap and Oval Auditing.', 'add_configuration': True}]}], indirect=True)
class TestScansWithSCAPAndOVALForAgent:
    """Covers test cases related to Scans with SCAP and OVAl Auditing for Agent."""

    form_information = load_testdata('nessus/tests/ui/scans/test_data/scap_oval_auditing_data.json')

    def test_availability_of_all_types_of_scap_and_oval_form(self, create_agent_groups, create_scans):
        """
        #NQA-1271: Automation tests related to scap page(#Test-1: For Agent Scan)
        
        Test to verify visibility of all types of scap and oval forms.
        1. Click 'New scan' button and select 'Scap and Oval auditing' template under 'Agent' tab.
        2. Verify visibility of 'SCAP' tab.
        3. Verify all types of scap and oval forms (Linux(SCAP), Linux(Oval), Windows(SCAP), Windows(Oval)) are present.
        4. Verify ‘Add SCAP checks from the adjacent list’ message is displayed if no forms opened.
        """
        assert NewScanForm().is_element_present('scap'), "SCAP tab is invisible."

        scap_page = SCAP()

        assert sorted(scap_page.get_list_of_all_form_types()) == sorted(API.Scap.Types.VALID_TYPES), \
            "Any of the scap and oval auditing form is missing or mismatched."

        assert scap_page.empty_list.text == 'Add SCAP checks from the adjacent list', \
            'Expected message for empty list is missing or mismatched.'

        go_back_to_scans_list()

    @pytest.mark.parametrize('test_data', scap_and_oval_information)
    def test_save_values_retained_for_agent_scan_with_scap_and_oval_auditing(self, create_agent_groups, create_scans,
                                                                             test_data):
        """
        #NQA-1271: Automation tests related to scap page(#Test-2: For Agent Scan)
        Test to verify saved values are retained after saving a scan.        
        1. Create a agent scan with 'Scap and Oval auditing' template.
        2. Go to SCAP tab, open and fill all types of forms with required and optional fields
        3. Hit Save and verify success notification.
        4. Click on agent scan and navigated to 'SCAP' tab.
        5. Verify the above configuration still exists for all saved forms.
        """
        agent_group = create_agent_groups[0]
        scan_name = create_scans[0]
        NewScanForm().fill_new_scan_detail(agent_group=agent_group)

        scap_page = ScapAndOvalForm()
        attached_file_name = scap_page.open_form_and_fill_details(form_information=[test_data]
                                                                  )[0].get(test_data.get('form_type'))
        NotificationActions().remove_all()
        scap_page.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            "Success notifications for saving scan is mismatched or missing."

        LoadingCircle(TIME_THREE_SECONDS)
        scans_list = ScanList()

        assert scan_name in scans_list.get_all_scans(), "Saved scan is not listed in scan list."

        scan_form_data_to_compare = dict(filter(lambda i: i[0] not in ('form_type', 'definition_file_path'),
                                                test_data.get('form_details')[0].items()))
        scan_form_data_to_compare['definition_file_name'] = attached_file_name

        scans_list.click_on_scan(scan_name=scan_name)
        LoadingCircle(WAIT_NORMAL)
        scan_details_page = ScanViewPage()
        scan_details_page.configure_button.click()
        scap_page.scap.click()
        scap_page.expand_form(form_type=test_data.get('form_type'),
                              attached_file_name=scan_form_data_to_compare.get('definition_file_name'))
        LoadingCircle(TIME_THREE_SECONDS)

        assert scap_page.get_saved_data_of_opened_form() == scan_form_data_to_compare, \
            "Saved values weren't retained in the scan form after saving the scan successfully."

        go_back_to_scans_list()

    def test_save_scan_page_without_scap_content(self, create_agent_groups, create_scans):
        """
        NQA-1272: Automation tests related to scap page.
        Test-1: Verify error message throws if no scap content added For Agent Scan.
        1. Create a Agent scan with ‘SCAP & OVAL Auditing’ template.
        2. Provide only name field, keep blank all other fields
        3. Hit on save button, verify that the error will be thrown “Error: SCAP content must be added to this policy.”
        """
        agent_group = create_agent_groups[0]
        scan_form = NewScanForm()
        scan_form.fill_new_scan_detail(agent_group=agent_group)
        NotificationActions().remove_all()
        scan_form.save_button.click()

        assert Notifications().errors[-1] == Messages.NotificationMessages.Scap.scap_content_error, \
            'Notification is missing when saving the scan without Scap Content'

        go_back_to_scans_list()

    @pytest.mark.parametrize('test_data', [
        {'count_of_forms': 1, 'form_type': API.Scap.Types.LINUX_SCAP, 'form_details': [
            {'definition_file_name': 'U_Windows_7_V1R27_STIG_SCAP_1-1_Benchmark.zip',
             'definition_file_path': 'nessus/tests/ui/scan/test_data/'}]},
        {'count_of_forms': 1, 'form_type': API.Scap.Types.WINDOWS_SCAP, 'form_details': [
            {'version': '1.2', 'profile_id': 'Windows - 1_Classified',
             'result_type': 'Full results w/o system characteristics',
             'definition_file_name': 'U_Windows_7_V1R27_STIG_SCAP_1-1_Benchmark.zip',
             'definition_file_path': 'nessus/tests/ui/scan/test_data/'}]}])
    def test_save_scan_with_blank_benchmark_data_stream_field(self, create_agent_groups, create_scans, test_data):
        """
        NQA-1272: Automation tests related to scap page.
        Test-2: Verify blank values in required field throws error while saving the scan For Agent Tab.
        1. Create a Agent scan with ‘SCAP & OVAL Auditing’ template.
        2. Add scap file and other required fields except ‘Benchmark ID’ and ‘Scap Data stream ID’
           (keep them blank) fields under SCAP form.
        3. Hit ‘Save’ and verify error notification.
        """
        agent_group = create_agent_groups[0]
        scan_form = NewScanForm()
        scan_form.fill_new_scan_detail(agent_group=agent_group)
        scap_page = ScapAndOvalForm()
        scap_page.open_form_and_fill_details(form_information=[test_data])
        notification = NotificationActions()
        notification.remove_all()
        scan_form.save_button.click()

        assert Notifications().errors[-1] == Messages.NotificationMessages.Scap.data_stream_error, \
            'Notification is missing for saving the scan without SCAP data stream'

        notification.remove_all()
        scap_page.scap_data_stream.value = '1234567'
        LoadingCircle(WAIT_NORMAL)
        scap_page.save_button.click()

        assert Notifications().errors[-1] == Messages.NotificationMessages.Scap.benchmark_id_error, \
            'Notification is missing for saving the scan without Benchmark Id'

        go_back_to_scans_list()

    def test_visibility_of_data_stream_field_on_scap_page(self, create_agent_groups, create_scans):
        """
        NQA-1272: Automation tests related to scap page.
        Test-3: Verify scap data stream ID get vanished if you select scap version less than ‘1.2’.
        1. Create a Agent scan with ‘SCAP & OVAL Auditing’ template.
        2. Fill all required inputs.
        3. Verify scap data stream ID field is visible.
        4. Select scap version less 1.2 from the dropdown.
        5. Verify ‘scap data stream ID’ get invisible now.
        """
        agent_group = create_agent_groups[0]
        NewScanForm().fill_new_scan_detail(agent_group=agent_group)

        scan_form = ScapAndOvalForm()
        scan_form.linux_scap.click()

        assert scan_form.scap_data_stream.is_displayed(), 'Scap Stream is invisible'

        scan_form.scap_version.select_by_visible_text('1.0')

        assert not scan_form.scap_data_stream.is_displayed(), 'Scap Stream is visible'

        go_back_to_scans_list()

    @pytest.mark.parametrize('test_data', [
        {'count_of_forms': 1, 'form_type': API.Scap.Types.WINDOWS_SCAP, 'form_details': [
            {'version': '1.2', 'benchmark_id': 'Windows_7_STIG', 'profile_id': 'Windows - 1_Classified',
             'stream_id': '1234567', 'result_type': 'Full results w/o system characteristics'}]},
        {'count_of_forms': 1, 'form_type': API.Scap.Types.WINDOWS_OVAL, 'form_details': [
            {'definition_file_name': None, 'definition_file_path': None}]},
        {'count_of_forms': 1, 'form_type': API.Scap.Types.LINUX_SCAP, 'form_details': [
            {'version': '1.1', 'benchmark_id': 'RHEL_6_STIG', 'profile_id': 'MAC - 1_Classified',
             'result_type': 'Full results w/ system characteristics'}]},
        {'count_of_forms': 1, 'form_type': API.Scap.Types.LINUX_OVAL, 'form_details': [
            {'definition_file_name': None, 'definition_file_path': None}]}])
    def test_save_scan_without_attach_definition_file(self, create_agent_groups, create_scans, test_data):
        """
        NQA-1272: Automation tests related to scap page.
        Test-4: Verify saving Agent Scan without adding the file, will throw an error
        1. Create a Agent scan with ‘SCAP & OVAL Auditing’ template.
        2. Fill all required inputs.
        3. Don’t add any scap Or oval definition file
        4. Hit ‘Save’ and verify error notification as “Error: SCAP File(Zip) is required”.
        """
        agent_group = create_agent_groups[0]
        NewScanForm().fill_new_scan_detail(agent_group=agent_group)
        scap_page = ScapAndOvalForm()

        scap_page.open_form_and_fill_details(form_information=[test_data])
        NotificationActions().remove_all()
        scap_page.save_button.click()
        error_message = Notifications().errors[-1]

        assert error_message in [Messages.NotificationMessages.Scap.scap_file_error,
                                 Messages.NotificationMessages.Scap.oval_file_error], \
            'Notification is missing when saving the scan without Scap and Oval file(Zip)'

        go_back_to_scans_list()

    @pytest.mark.parametrize('test_data', scap_and_oval_information)
    def test_save_values_retained_with_remove_definition_file(self, create_agent_groups, create_scans, test_data):
        """
        NQA-1272: Automation tests related to scap page.
        Test-6: Verify removing of added scap file or required field data will throw errors and doesn't let you to edit
        configuration of scan.
        1. Create and save a Agent scan with ‘SCAP & OVAL Auditing’ template and verify scan has saved
           properly.
        2. Click the saved scan, hit configure.
        3. Navigate to scap page and remove added scap Or oval definition file.
        4. Hit ‘Save’ and verify error notifications as Error: SCAP File (Zip) is required.”
        5. Again try to remove the data of “SCAP Data Stream ID” field from the form and click on “Save” button.
        6. Verify Scan should not save and must throw you an error notification as “Error: SCAP Data Stream ID
           is required.”
        7. Repeat above steps “SCAP Benchmark ID” field.
        """
        agent_group = create_agent_groups[0]
        scan_name = create_scans[0]
        NewScanForm().fill_new_scan_detail(agent_group=agent_group)
        scap_page = ScapAndOvalForm()
        attached_file_name = scap_page.open_form_and_fill_details(form_information=[test_data]
                                                                  )[0].get(test_data.get('form_type'))

        notification = NotificationActions()
        notification.remove_all()
        scap_page.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            'Notification is missing when saving the scan'

        LoadingCircle(WAIT_LONG)
        get_driver().refresh()

        scans_list = ScanList()

        assert scan_name in scans_list.get_all_scans(), "Saved scan is not listed in scan list."

        scan_form_data_to_compare = dict(filter(lambda i: i[0] not in ('form_type', 'definition_file_path'),
                                                test_data.get('form_details')[0].items()))
        scan_form_data_to_compare['definition_file_name'] = attached_file_name

        scans_list.click_on_scan(scan_name=scan_name)
        LoadingCircle(WAIT_SHORT)
        scan_details_page = ScanViewPage()
        scan_details_page.configure_button.click()
        LoadingCircle(WAIT_SHORT)
        scap_page.scap.click()
        # scap_page.expand_form(form_type=test_data.get('form_type'),
        #                       attached_file_name=scan_form_data_to_compare.get('definition_file_name'))

        LoadingCircle(WAIT_SHORT)
        # Remove added scap/oval definition file.
        scap_page.remove_attached_file.click()
        notification.remove_all()
        scap_page.save_button.click()
        error_message = Notifications().errors[-1]

        assert error_message in [Messages.NotificationMessages.Scap.scap_file_error,
                                 Messages.NotificationMessages.Scap.oval_file_error], \
            'Notification is missing when saving the scan without Scap and Oval file(Zip)'

        if test_data.get('form_type') in [API.Scap.Types.LINUX_SCAP, API.Scap.Types.WINDOWS_SCAP]:
            # Remove the data of “SCAP Data Stream ID” field from the form and click on “Save” button.
            scap_page.back_link.click()
            scan_details_page.configure_button.click()
            LoadingCircle(WAIT_SHORT)
            scap_page.scap.click()
            scap_page.expand_form(form_type=test_data.get('form_type'),
                                  attached_file_name=scan_form_data_to_compare.get('definition_file_name'))
            LoadingCircle(WAIT_SHORT)
            scap_page.scap_data_stream.clear()
            notification.remove_all()
            scap_page.save_button.click()

            assert Notifications().errors[-1] == Messages.NotificationMessages.Scap.data_stream_error, \
                'Notification is missing when saving the scan without Scap Data Stream'

            # Remove the data of “SCAP Benchmark ID” field from the form and click on “Save” button.
            scap_page.back_link.click()
            scan_details_page.configure_button.click()
            LoadingCircle(WAIT_SHORT)
            scap_page.scap.click()
            scap_page.expand_form(form_type=test_data.get('form_type'),
                                  attached_file_name=scan_form_data_to_compare.get('definition_file_name'))
            LoadingCircle(WAIT_SHORT)
            scap_page.scap_benchmark.clear()
            notification.remove_all()
            scap_page.save_button.click()

            assert Notifications().errors[-1] == Messages.NotificationMessages.Scap.benchmark_id_error, \
                'Notification is missing when saving the scan without Scap Benchmark Id'

        go_back_to_scans_list()

    @pytest.mark.parametrize('test_data', scap_and_oval_information)
    def test_save_values_retained_with_remove_scap_content(self, create_agent_groups, create_scans, test_data):
        """
        NQA-1272: Automation tests related to scap page.
        Test-7: Verify changes made to scan are not saved for ‘SCAP & OVAL Auditing’ if you remove all of the
        scap already added to it.
        1. Create and save a Agent scan with ‘SCAP & OVAL Auditing’ template and verify scan has
        saved properly.
        2. Click the saved scan and modify the scan name.
        3. Navigate to “SCAP” tab and remove all scap/oval forms you have already added and Click on “Save” button.
        4. Scan should not save and it must throw you an error notification as “Error: Scap content must be
        added to this scan”.
        """
        agent_group = create_agent_groups[0]
        scan_name = create_scans[0]
        NewScanForm().fill_new_scan_detail(agent_group=agent_group)

        scap_page = ScapAndOvalForm()
        notification = NotificationActions()
        attached_file_name = scap_page.open_form_and_fill_details(
            form_information=[test_data])[0].get(test_data.get('form_type'))

        notification.remove_all()
        scap_page.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            'Notification is missing when saving the Scan'

        scans_list = ScanList()

        assert scan_name in scans_list.get_all_scans(), "Saved scan is not listed in scan list."

        scan_form_data_to_compare = dict(filter(lambda i: i[0] not in ('form_type', 'definition_file_path'),
                                                test_data.get('form_details')[0].items()))
        scan_form_data_to_compare['definition_file_name'] = attached_file_name

        scans_list.click_on_scan(scan_name=scan_name)
        scan_details_page = ScanViewPage()
        scan_details_page.configure_button.click()
        ScansPage().name_field.value = random_name(prefix="Editing {} - ".format(scan_name))
        LoadingCircle(WAIT_SHORT)
        scap_page.scap.click()
        scap_page.expand_form(form_type=test_data.get('form_type'),
                              attached_file_name=scan_form_data_to_compare.get('definition_file_name'))

        LoadingCircle(WAIT_NORMAL)
        # Remove all Scap/Oval forms
        scap_page.close_form.click()
        notification.remove_all()
        scap_page.save_button.click()

        assert Notifications().errors[-1] == Messages.NotificationMessages.Scap.scap_content_error, \
            'Notification is missing when saving the scan without Scap and Oval Content'

        go_back_to_scans_list()

    @pytest.mark.parametrize('form_types', [API.Scap.Types.WINDOWS_SCAP, API.Scap.Types.LINUX_SCAP,
                                            API.Scap.Types.WINDOWS_OVAL, API.Scap.Types.LINUX_OVAL])
    def test_invisible_component_link_on_scap_page(self, create_agent_groups, create_scans, form_types):
        """
        NQA-1272: Automation tests related to scap page.
        Test-9: Verify the component form link is invisible when its maximum count gets exits.
        1. Navigate to “SCAP” tab for creating Or editing a scan having template ‘SCAP & OVAL Auditing’.
        2. Try to add the component form until its maximum count is not get exits.
        3. Verify that component link is invisible when its max count exits.
        4. For infinite count we can try to add more than 10 forms.
        """
        agent_group = create_agent_groups[0]
        NewScanForm().fill_new_scan_detail(agent_group=agent_group)

        scap_page = ScapAndOvalForm()
        mapping_forms = {API.Scap.Types.LINUX_SCAP: scap_page.linux_scap,
                         API.Scap.Types.LINUX_OVAL: scap_page.linux_oval,
                         API.Scap.Types.WINDOWS_SCAP: scap_page.windows_scap,
                         API.Scap.Types.WINDOWS_OVAL: scap_page.windows_oval}

        if form_types in [API.Scap.Types.LINUX_OVAL, API.Scap.Types.WINDOWS_OVAL]:
            for i in range(11):
                mapping_forms.get(form_types).click()
            assert mapping_forms.get(form_types).is_displayed(), 'Can not add more than 10 forms with infinity' \
                                                                 ' component link '
        else:
            self.form_information["form_test_data"][0]["form_type"] = form_types
            scap_page.open_form_and_fill_details(form_information=self.form_information["form_test_data"])

            assert not mapping_forms.get(self.form_information["form_test_data"][0]["form_type"]).is_displayed(), \
                'Component link is not invisible when its max count exits'

        go_back_to_scans_list()
