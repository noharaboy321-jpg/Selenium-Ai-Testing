"""
Nessus Scans on Scanner - Editing related tests

:copyright: Tenable Network Security, 2017
:date: July 06, 2018
:last_modified: Jan 03, 2021
:author: @ntarwani, @kpanchal
"""
import os
from datetime import datetime, timedelta

import pytest
from selenium.webdriver.common.by import By

from catium.helpers.sleep_lib import sleep
from catium.helpers.testdata import get_file_path
from catium.lib.const import WAIT_NORMAL, WAIT_SHORT
from catium.lib.const.base_constants import TIME_THIRTY_SECONDS, TIME_SIXTY_SECONDS
from catium.lib.util import random_name
from catium.lib.webium.wait import wait
from nessus.helpers.date_selector import select_date_in_datepicker
from nessus.lib.const import Nessus, API
from nessus.lib.const.compliance_constants import ComplianceConst
from nessus.lib.message.messages import Messages
from nessus.pageobjects.compliances.compliance_page import Compliance
from nessus.pageobjects.compliances.compliance_sub_categories import AppleProfileManagerTNS, \
    CISJuniperJunosBenchmarkL1, TNSBlueCoatProxySGBenchmark, CISMicrosoftAzureFoundations
from nessus.pageobjects.credentials.cloud_services import MicrosoftAzure
from nessus.pageobjects.credentials.credentials_page import Credentials
from nessus.pageobjects.credentials.host import Password
from nessus.pageobjects.credentials.mobile_credential import AirWatch
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.header.user_menu import UserMenu
from nessus.pageobjects.login.login_page import LoginPage
from nessus.pageobjects.scans.new_scan_form import NewScanForm
from nessus.pageobjects.scans.scan_basic_settings_page import BasicSetting, DiscoverySetting, AssessmentSetting
from nessus.pageobjects.scans.scan_basic_settings_page import ScanSettings
from nessus.pageobjects.scans.scan_view_page import ScanViewPage
from nessus.pageobjects.scans.scans_page import ScanList
from nessus.pageobjects.scans.scans_page import ScansPage
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav


def reconfigure_scan_and_get_notification(setting_type: str, scan_name: str, form_name: str) -> str:
    """
    Common method for configuration steps used frequently in the test cases
    :param str setting_type: Setting type: Credentials, Compliance or Plugin
    :param str form_name: Name of the credential/compliance form saved
    :param str scan_name: Scan name to be clicked and configured
    :return: String containing notification text
    :rtype: str
    """
    ScanList().click_on_scan(scan_name)
    LoadingCircle(WAIT_NORMAL)

    scan_view_page = ScanViewPage()
    scan_view_page.js_scroll_into_view(scan_view_page.configure_button)
    scan_view_page.configure_button.click()

    scan_form_page = NewScanForm()
    if setting_type == Nessus.Scan.ScanFeatureTabs.CREDENTIALS:
        scan_form_page.credentials.click()
        credentials = Credentials()
        credentials.open_saved_credentials_component(form_name)
        credentials.remove_form.click()

    elif setting_type == Nessus.Scan.ScanFeatureTabs.COMPLIANCE:
        scan_form_page.compliance.click()
        compliance = Compliance()
        if compliance.active_expansion_icon.is_displayed():
            compliance.open_saved_compliance_component(form_name)
        compliance.remove_form.click()

    LoadingCircle(WAIT_NORMAL)
    scan_form_page.save_button.click()

    return Notifications().errors[-1]


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestScansScannerEditing:
    """
    This file contains test cases related to:
    1. NQA-1086-Automation tests for Scans - Scanner Editing for created scans.
    2. NQA-1287-Verify mandatory field validation while edit for Advanced scan with Settings tab
    """

    @staticmethod
    def accept_schedule_warning_pop_up() -> None:
        """
        Accepts schedule warning pop-up

        :return: None
        """
        action_modal = ActionCloseModal()

        if action_modal.is_element_present('modal'):
            action_modal.accept_action()

    @pytest.mark.nessus_home
    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         "target_ip": Nessus.Scan.Target.LINUX_TARGET, 'add_configuration': True}]}], indirect=True)
    def test_page_title_and_back_link(self, create_scans):
        """
        NQA-1086-Automation tests for Scans - Scanner Editing for created scans.(Step 1/2)
        1. Navigate to “My Scans/custom folder” page under Scans and click on the existing created scan.
        2. Verify it will open scan details page having title as “Scan Name”.
        3. Click on “Configure” button for editing.
        4. Verify page title as “Scan Name / Configuration”.
        5. Verify ‘Name’ field filled with the ‘Scan Name’.
        6. Verify “Back to Scan Report” link is present in page header.
        7. Click on the link.
        8. Verify it takes you to the scan details page.
        """
        new_scan = NewScanForm()
        new_scan.save_button.click()

        created_scan = create_scans[0]
        ScanList().click_on_scan(created_scan)

        scan_view_page = ScanViewPage()
        assert new_scan.page_heading == created_scan, 'Page header should contain the scan name'
        scan_view_page.configure_button.click()
        assert new_scan.page_heading == "{} / Configuration".format(created_scan), \
            'Configuration page for scan is not opened'
        assert new_scan.name_field.value == created_scan, 'Scan name is incorrect under name field'

        assert new_scan.back_link.is_displayed(), 'Back link is not present'
        new_scan.back_link.click()
        assert scan_view_page.page_header == created_scan, 'Back link is not working or broken'

    @pytest.mark.nessus_home
    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         "target_ip": Nessus.Scan.Target.LINUX_TARGET, 'add_configuration': True}]}], indirect=True)
    def test_blank_name_field_validation_on_edit(self, create_scans):
        """
        NQA-1287: Verify mandatory field validation while edit for Advanced scan with Setting Tab (Step 1)
        Remove name field value and verify validation message
        1. Clicked on existing scan
        2. Remove data of name field
        3. Hit 'Save'
        4. Validation message should appear
        """
        scan_name = create_scans[0]

        scan_form_page = NewScanForm()
        scan_form_page.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            'Notification for scan saved is incorrect or missing'

        ScanList().click_on_scan(scan_name=scan_name)
        ScanViewPage().configure_button.click()

        scan_form_page.name_field.clear()
        scan_form_page.save_button.click()
        notification = Notifications()

        assert notification.errors[-1] == Messages.NotificationMessages.Scans.required_scan_name, \
            'Validation message for name field is missing'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.nessus_home
    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         "target_ip": Nessus.Scan.Target.LINUX_TARGET, 'add_configuration': True}]}], indirect=True)
    def test_blank_target_field_validation_on_edit(self, create_scans):
        """
        NQA-1287: Verify mandatory field validation while edit for Advanced scan with Setting Tab (Step 2)
        Remove target field value and verify validation message
        1. Clicked on existing scan
        2. Remove data of Target field
        3. Hit 'Save'
        4. Validation message should appear
        """
        scan_name = create_scans[0]

        scan_form_page = NewScanForm()
        scan_form_page.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            'Notification for scan saved is incorrect or missing'

        ScanList().click_on_scan(scan_name=scan_name)
        ScanViewPage().configure_button.click()

        scan_form_page.targets_textarea.clear()
        scan_form_page.save_button.click()
        notification = Notifications()

        assert notification.errors[-1] == Messages.NotificationMessages.target_required_error, \
            'Validation message for target field is missing'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.nessus_home
    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         "target_ip": Nessus.Scan.Target.LINUX_TARGET, 'add_configuration': True}]}], indirect=True)
    def test_scan_saved_successfully_on_edit(self, create_scans):
        """
        NQA-1086-Automation tests for Scans - Scanner Editing for created scans. (Step 3)
        1. Navigate to “My Scans/custom folder” page under Scans and click on the existing created scan.
        2. Click on “Configure” button for editing.
        3. Edit the name
        4. Save the scan
        5. Verify the edited name in scan list
        """
        new_scan = NewScanForm()
        new_scan.save_button.click()

        created_scan = create_scans[0]
        scan_list = ScanList()
        scan_list.click_on_scan(created_scan)
        ScanViewPage().configure_button.click()

        edited_scan = "Edited " + created_scan
        new_scan.name_field.value = edited_scan
        new_scan.save_button.click()

        notification = Notifications()
        assert notification.successes[-1] == Messages.NotificationMessages.save_scan, \
            'Notification for scan saved is incorrect or missing'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        assert edited_scan in scan_list.get_all_scans(), 'Edited scan is not present in the scan list'

        scan_list.delete_scan(edited_scan)

    @pytest.mark.nessus_home
    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         "target_ip": Nessus.Scan.Target.LINUX_TARGET, 'add_configuration': True}]}], indirect=True)
    def test_editing_scan_not_saved_on_cancel(self, create_scans):
        """
        NQA-1086-Automation tests for Scans - Scanner Editing for created scans. (Step 4)
        1. Navigate to “My Scans/custom folder” page under Scans and click on the existing created scan.
        2. Click on “Configure” button for editing.
        3. Edit the name
        4. Click on the cancel button.
        5. Verify the edited name not in the scan list
        """
        new_scan = NewScanForm()
        new_scan.save_button.click()

        created_scan = create_scans[0]
        scan_list = ScanList()
        scan_list.click_on_scan(created_scan)
        ScanViewPage().configure_button.click()

        edited_scan = "Edited " + created_scan
        new_scan.name_field.value = edited_scan
        new_scan.cancel_button.click()

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        assert edited_scan not in scan_list.get_all_scans(), 'Edited scan is getting saved with Cancel button'

    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.AUDIT_CLOUD, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.AUDIT_CLOUD)),
         'add_configuration': True}]}], indirect=True)
    @pytest.mark.parametrize('microsoft_azure_form_data', [{'auth_method': 'Password', 'username': 'admin',
                                                            'password': 'P@ssw0rd', 'application_id': '1234',
                                                            'subscription_id': '1234'},
                                                           {'auth_method': 'Key', 'application_id': '1234',
                                                            'subscription_id': '1234', 'client_secret': 'P@ssw0rd',
                                                            'tenant_id': "1234"}])
    def test_remove_compliance_from_audit_cloud_template(self, create_scans, microsoft_azure_form_data):
        """
        NQA-1086-Automation tests for Scans - Scanner Editing for created scans.(Step 7)
        1. Click on the existing created Scan having template ‘Audit Cloud Infrastructure’.
        2. Click on “Configure” button for editing and navigate to “Compliance” tab and remove compliance(s) added.
        3. Click on “Save” button.
        4. Scan should not save and it must throw you an error notification as
        “Error: At least one audit must be added to this policy in the 'Compliance' section.”
        """
        scan_form_page = NewScanForm()
        # add required credentials and compliance
        MicrosoftAzure(cloud_type=API.Credentials.CloudServices.Types.MICROSOFT_AZURE).fill_microsoft_azure_form(
            **microsoft_azure_form_data)

        compliance_page = CISMicrosoftAzureFoundations()
        LoadingCircle(WAIT_SHORT)
        compliance_page.fill_compliance_form(sharepoint_domain="www.tenable.com")

        scan_form_page.save_button.click()
        assert create_scans[0] in ScanList().get_all_scans(), 'Created scan is not in the list of scans'

        notification_text = reconfigure_scan_and_get_notification(setting_type=Nessus.Scan.ScanFeatureTabs.COMPLIANCE,
                                                                  form_name="Microsoft 365 Foundations",
                                                                  scan_name=create_scans[0])

        assert notification_text == Messages.NotificationMessages.Policies.audit_policy_validation, \
            'Scan should not saved successfully without required compliance.'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)

    @pytest.mark.usefixtures('load_test_data')
    @pytest.mark.parametrize('test_data_file', [
        os.path.abspath(get_file_path('nessus/tests/ui/scans/test_data/compliance_data.json'))], indirect=True)
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.OFFLINE_AUDIT, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.OFFLINE_AUDIT)),
         'add_configuration': True}]}], indirect=True)
    def test_remove_compliance_from_offline_audit(self, create_scans, load_test_data):
        """
        NQA-1086-Automation tests for Scans - Scanner Editing for created scans.(Step 7)
        1. Click on the existing created Scan having template ‘Offline Config Audit’.
        2. Click on “Configure” button for editing and navigate to “Compliance” tab and remove compliance(s) added.
        3. Click on “Save” button.
        4. Scan should not save and it must throw you an error notification as
        “Error: At least one audit must be added to this policy in the 'Compliance' section.”
        """
        # add required credentials and compliance
        compliance = CISJuniperJunosBenchmarkL1()
        juniper_data = load_test_data.get('juniper_data')
        juniper_data['config_file'] = os.path.abspath(get_file_path(
            'nessus/tests/api/plugins/test_data/api_pub_key_target_priv_key'))

        compliance.fill_compliance_form(**load_test_data.get('juniper_data'))
        LoadingCircle(WAIT_NORMAL)
        compliance.inactive_expansion_icon.click()
        NewScanForm().save_button.click()
        LoadingCircle(WAIT_NORMAL)

        assert create_scans[0] in ScanList().get_all_scans(), 'Created scan is not in the list of scans'

        notification_text = reconfigure_scan_and_get_notification(setting_type=Nessus.Scan.ScanFeatureTabs.COMPLIANCE,
                                                                  form_name=ComplianceConst.JUNIPER_OS,
                                                                  scan_name=create_scans[0])
        assert notification_text == Messages.NotificationMessages.Policies.audit_policy_validation, \
            'Scan should not saved successfully without required compliance.'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)

    @pytest.mark.xfail(reason="'TNS BlueCoat ProxySG Benchmark' compliance type is not present under 'BlueCoat ProxySG'"
                              "compliance category.")
    @pytest.mark.usefixtures('load_test_data')
    @pytest.mark.parametrize('test_data_file',
                             [os.path.abspath(
                                 get_file_path('nessus/tests/ui/scans/test_data/compliance_data.json'))],
                             indirect=True)
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.COMPLIANCE_AUDIT, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.COMPLIANCE_AUDIT)),
         "target_ip": Nessus.Scan.Target.LINUX_TARGET, 'add_configuration': True}]}], indirect=True)
    def test_remove_compliance_from_policy_compliance_audit(self, create_scans, load_test_data):
        """
        NQA-1086-Automation tests for Scans - Scanner Editing for created scans.(Step 7)
        1. Click on the existing created Scan having template ‘Policy Compliance Auditing’.
        2. Click on “Configure” button for editing and navigate to “Compliance” tab and remove compliance(s) added.
        3. Click on “Save” button.
        4. Scan should not save and it must throw you an error notification as
        “Error: At least one audit must be added to this policy in the 'Compliance' section.”
        """
        # add required credentials and compliance
        credentials = Password(host_type=API.Credentials.Host.Types.SSH)
        credentials.fill_password_ssh_form(username='admin', password='admin')

        compliance = TNSBlueCoatProxySGBenchmark()
        LoadingCircle(WAIT_NORMAL)

        bluecoat_proxysg_data = load_test_data.get('bluecoat_proxysg_data')
        del bluecoat_proxysg_data['config_file']
        compliance.fill_compliance_form(**load_test_data.get('bluecoat_proxysg_data'))

        NewScanForm().save_button.click()
        assert create_scans[0] in ScanList().get_all_scans(), 'Created scan is not in the list of scans'

        notification_text = reconfigure_scan_and_get_notification(
            setting_type=Nessus.Scan.ScanFeatureTabs.COMPLIANCE, form_name=ComplianceConst.BLUECOAT_PROXYSG,
            scan_name=create_scans[0])
        assert notification_text == Messages.NotificationMessages.Policies.audit_policy_validation, \
            'Scan should not saved successfully without required compliance.'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)

    @pytest.mark.parametrize("create_scans", [
        ({'scans_details': [
            {"scan_template": Nessus.TemplateNames.AUDIT_PATCH, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
             "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.AUDIT_PATCH)),
             "target_ip": Nessus.Scan.Target.LINUX_TARGET, 'add_configuration': True}]}),
        ({'scans_details': [
            {"scan_template": Nessus.TemplateNames.MALWARE, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
             "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.MALWARE)),
             "target_ip": Nessus.Scan.Target.LINUX_TARGET, 'add_configuration': True}]})], indirect=True)
    def test_remove_credentials_from_audit_patch_and_malware(self, create_scans):
        """
        NQA-1086-Automation tests for Scans - Scanner Editing for created scans.(Step 8)
        1. Click on the existing created Scan having template ‘Credentialed Patch Audit’/'Malware'.
        2. Click on “Configure” button for editing, navigate to “Credentials” tab and remove credential(s) added.
        3. Click on “Save” button.
        4. Scan should not save and it must throw you an error notification.
        """
        # add required credentials
        credentials = Password(host_type=API.Credentials.Host.Types.SSH)
        credentials.fill_password_ssh_form(username='admin', password='admin')

        NewScanForm().save_button.click()
        assert create_scans[0] in ScanList().get_all_scans(), 'Created scan is not in the list of scans'

        notification_text = reconfigure_scan_and_get_notification(
            setting_type=Nessus.Scan.ScanFeatureTabs.CREDENTIALS, form_name=API.Credentials.Host.SSHAuthTypes.PASSWORD,
            scan_name=create_scans[0])

        if create_scans[0] == Nessus.TemplateNames.AUDIT_PATCH:
            assert notification_text == Messages.NotificationMessages.Policies.cred_patch_audit_validation, \
                'Scan should not saved successfully without required credentials.'
        elif create_scans[0] == Nessus.TemplateNames.MALWARE:
            assert notification_text == Messages.NotificationMessages.Policies.malware_credential_validation, \
                'Scan should not saved successfully without required credentials.'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)

    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         "target_ip": Nessus.Scan.Target.LINUX_TARGET, 'add_configuration': True}]}], indirect=True)
    def test_host_discovery_scan_validation(self, create_scans):
        """
        NQA-1086-Automation tests for Scans - Scanner Editing for created scans.(Step 15)
        1. Navigate to “My Scans/custom folder” page under Scans and click on the existing created Scan.
        2. Click on “Configure” button for editing and go to "Host Discovery" in “Discovery” sub-link under “Settings”
           tab.
        3. Verify presence of “Ping the remote host”, it is enabled by default.
        4. Toggle it off and verify 'Ping the remote host' should no longer be enabled
        5. Hit “Save” button and verify success notifications.
        6. Delete the value from “Destination Ports” and hit “Save”
        7. Verify the default value will retains after success notification.
        """
        scan_page_form = NewScanForm()
        scan_page_form.save_button.click()

        ScanList().click_on_scan(create_scans[0])
        ScanViewPage().configure_button.click()
        wait(lambda: scan_page_form.is_element_present('name_field'), timeout_seconds=TIME_THIRTY_SECONDS,
             sleep_seconds=WAIT_SHORT, waiting_for="Scan configure page to get loaded properly.")

        scan_setting = DiscoverySetting()
        scan_setting.click_by_link_text(setting_value=Nessus.Scan.SettingsTypes.DISCOVERY)
        assert scan_setting.ping_remote_switch.is_displayed(), '"Ping the remote host" toggle is not displayed'
        assert scan_setting.ping_remote_switch.is_selected(), '"Ping the remote host" toggle is not enabled'

        scan_setting.ping_remote_switch.untoggle()

        scan_setting.ping_remote_switch.set_toggle(True)
        destination_value = scan_setting.destination_ports.value

        scan_setting.destination_ports.clear()
        scan_page_form.js_scroll_into_view(scan_page_form.save_button)
        scan_page_form.save_button.click()
        notification = Notifications()
        assert notification.successes[-1] == Messages.NotificationMessages.save_scan, \
            'Notification for scan saved is incorrect or missing'
        LoadingCircle(WAIT_NORMAL)
        assert scan_setting.destination_ports.value == destination_value, \
            'Default destination value should not be changed'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)

    @pytest.mark.nessus_home
    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         "target_ip": Nessus.Scan.Target.LINUX_TARGET, 'add_configuration': True}]}], indirect=True)
    def test_scan_schedule_validations(self, create_scans):
        """
        NQA-1086-Automation tests for Scans - Scanner Editing for created scans.(Step 18/23)
        1. Navigate to “My Scans/custom folder” page under Scans and click on the existing created Scan.
        2. Click on “Configure” button for editing and go to "Schedule" in “Basic” sub-link under “Settings” tab.
        3. Verify a schedule enable slider toggle is displayed and it is disabled by default.
        4. Toggle it on and verify now its enabled
        5. Verify presence of the frequency/date-picker/start time drop-down/ time-zone drop-down/summary fields
        6. Select time in past from start time drop-down
        7. Verify red border around drop-down
        6. Schedule a scan in future date/time, hit “Save” and verify success notification.
        """
        scan_page_form = NewScanForm()
        scan_page_form.save_button.click()

        ScanList().click_on_scan(create_scans[0])
        ScanViewPage().configure_button.click()
        wait(lambda: scan_page_form.is_element_present('name_field'), timeout_seconds=TIME_THIRTY_SECONDS,
             sleep_seconds=WAIT_SHORT, waiting_for="Scan configure page to get loaded properly.")

        scan_settings = BasicSetting()
        scan_settings.click_link_inside_link(setting_value=Nessus.Scan.SettingsTypes.BASIC, link_text='Schedule')
        assert scan_settings.enable_schedule.is_displayed(), '"Schedule enable slider" toggle is not displayed'

        scan_settings.enable_schedule.set_toggle(True)
        assert scan_settings.enable_schedule.get_attribute('data-value') == 'on', \
            'Schedule enable slider toggle is not working'
        assert all([scan_settings.frequency.is_displayed(),
                    scan_settings.start_time_dropdown_field.is_displayed(),
                    scan_settings.starts_datepicker_field.is_displayed(),
                    scan_settings.time_dropdown.is_displayed(),
                    scan_settings.summary.is_displayed()]), \
            'One of the fields from "frequency/date-picker/start time drop-down/ time-zone dropdown/summary fields" ' \
            'is not displayed'

        scan_settings.starts_datepicker_field.click()
        scan_settings.select_date.select_day(day=int(scan_settings.current_date.find_element(By.TAG_NAME, 'a').text))

        dropdown_options = [element['label'] for element in scan_settings.start_time_dropdown_field.option_values]
        scan_settings.start_time_dropdown_field.select_by_visible_text(dropdown_options[0])
        scan_page_form.save_button.click()

        self.accept_schedule_warning_pop_up()
        notification = Notifications()

        assert notification.errors[-1] == Messages.NotificationMessages.Scans.invalid_scheduled_time, \
            'The scan scheduled time cannot be in past'

        scan_settings.starts_datepicker_field.click()
        select_date_in_datepicker(page_class_instance=scan_settings,
                                  input_date=(datetime.today().date() + timedelta(days=7)))

        scan_page_form.save_button.click()
        self.accept_schedule_warning_pop_up()

        assert notification.successes[-1] == Messages.NotificationMessages.save_scan, \
            'Notification for scan saved is incorrect or missing'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)

    @pytest.mark.nessus_home
    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         "target_ip": Nessus.Scan.Target.LINUX_TARGET, 'add_configuration': True}]}], indirect=True)
    @pytest.mark.parametrize("uid_type", ['Start UID', 'End UID'])
    def test_validations_for_windows_assessment_tab(self, create_scans, uid_type):
        """
        NQA-1086-Automation tests for Scans - Scanner Editing for created scans.(Step 25)
        1. Navigate to “My Scans/custom folder” page under Scans and click on the existing created Scan.
        2. Click on “Configure” button for editing and go to "Windows" in “Assessment” sub-link under “Settings” tab.
        3. Delete the default value from “Start UID” under “Enumerate Domain Users/ Enumerate Local Users” and hit
           “Save” button.
        4. Verify the default value will retains after success notification.
        5. Put an invalid character (e.g.: Start UID = AA) and verify the box should turn red.
        6. Hit “Save” button and verify error notifications as “Error: Start UID is invalid”
        7. Delete the invalid characters and put a valid response (e.g.: 1000) and verify the input box turns back to
           its original colour (white/grey outline).
        8. Hit “Save” button and verify success notifications.
        9. Repeat above steps for “End UID”.
        """
        scan_page_form = NewScanForm()
        scan_page_form.save_button.click()

        ScanList().click_on_scan(create_scans[0])
        ScanViewPage().configure_button.click()
        wait(lambda: scan_page_form.is_element_present('name_field'), timeout_seconds=TIME_THIRTY_SECONDS,
             sleep_seconds=WAIT_SHORT, waiting_for="Scan configure page to get loaded properly.")

        scan_settings = AssessmentSetting()
        scan_settings.click_link_inside_link(setting_value=Nessus.Scan.SettingsTypes.ASSESSMENT, link_text='Windows')
        scan_settings.rid_brute_forcing_toggle.click()
        uid_value = scan_settings.get_uid_element_under_assessment(uid_type).get_attribute('value')
        scan_settings.get_uid_element_under_assessment(uid_type).clear()
        scan_page_form.save_button.click()

        notification = Notifications()

        assert notification.successes[-1] == Messages.NotificationMessages.save_scan, \
            'Notification for scan saved is incorrect or missing'

        sleep(WAIT_NORMAL, reason="waiting for scan values to be saved")

        assert scan_settings.get_uid_element_under_assessment(uid_type).get_attribute('value') == uid_value, \
            'UID value should be set to default if we clear and save'

        scan_settings.get_uid_element_under_assessment(uid_type).send_keys('AA')

        assert 'error' in scan_settings.get_uid_element_under_assessment(uid_type).get_css_classes(), \
            'The textbox border should turn red when there is a validation error'

        scan_page_form.save_button.click()

        assert notification.errors[-1] == "Error: %s is invalid." % uid_type, 'UID value should be numeric only'

        scan_settings.get_uid_element_under_assessment(uid_type).clear()

        assert 'error' not in scan_settings.get_uid_element_under_assessment(uid_type).get_css_classes(), \
            'The textbox border should turn black if the validation check is correct'

        scan_settings.get_uid_element_under_assessment(uid_type).send_keys('1000')
        scan_page_form.save_button.click()

        assert notification.successes[-1] == Messages.NotificationMessages.save_scan, \
            'Notification for scan saved is incorrect or missing'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)

    @pytest.mark.nessus_home
    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         "target_ip": Nessus.Scan.Target.LINUX_TARGET, 'add_configuration': True}]}], indirect=True)
    def test_assessment_general_tab_checkbox(self, create_scans):
        """
        NQA-1086-Automation tests for Scans - Scanner Editing for created scans.(Step 26)
        1. Navigate to “My Scans/custom folder” page under Scans and click on the existing created Scan.
        2. Click on “Configure” button for editing and go to "General" in “Assessment” sub-link under “Settings” tab.
        3. Verify presence of “Override normal accuracy” checkbox under “Accuracy”.
        4. Verify the above is unchecked by default and the under listed radio options are also inaccessible.
        5. Checked the checkbox and verify you are able to access the radio button options now.
        """
        scan_page_form = NewScanForm()
        scan_page_form.save_button.click()

        ScanList().click_on_scan(create_scans[0])
        ScanViewPage().configure_button.click()
        wait(lambda: scan_page_form.is_element_present('name_field'), timeout_seconds=TIME_THIRTY_SECONDS,
             sleep_seconds=WAIT_SHORT, waiting_for="Scan configure page to get loaded properly.")

        scan_settings = AssessmentSetting()
        scan_settings.click_by_link_text(setting_value=Nessus.Scan.SettingsTypes.ASSESSMENT)
        assert scan_settings.override_normal_accuracy_checkbox.is_displayed() and not \
            scan_settings.override_normal_accuracy_checkbox.is_selected(), \
            'Either Override normal accuracy checkbox is not displayed or it is checked'

        assert 'checked' not in scan_settings.radio_family_for_override_accuracy.get_css_classes(), \
            'Radio family related to Override normal accuracy should not be accessible'

        scan_settings.override_normal_accuracy_checkbox.check()
        assert 'checked' in scan_settings.radio_family_for_override_accuracy.get_css_classes(), \
            'Radio family related to Override normal accuracy should be accessible'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)


@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestScansScannerEditingForManager:
    """Covers scan editing related test cases for Nessus Manager."""

    @pytest.mark.parametrize("create_user", [{'username': random_name(prefix=API.User.Users.STANDARD_USER + ' - '),
                                              'password': 'password', 'role': API.User.Role.STANDARD,
                                              'do_login': False}], indirect=True)
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         "target_ip": Nessus.Scan.Target.LINUX_TARGET, 'add_configuration': True}]}], indirect=True)
    def test_shared_permission_with_other_user(self, create_user, create_scans):
        """
        NQA-1086-Automation tests for Scans - Scanner Editing for created scans. (Step 12)
        1. Create a standard user
        2. Navigate to existing scan and give any permission to the user created above
        3. Save the scan and verify Shared tag is present as prefix to scan name
        4. Login as a new user
        5. Verify the functionality according to given role
        """
        scan_form_page = NewScanForm()
        scan_form_page.save_button.click()

        scan_list = ScanList()
        scan_list.click_on_scan(create_scans[0])
        scan_view_page = ScanViewPage()
        scan_view_page.configure_button.click()
        wait(lambda: scan_form_page.is_element_present('name_field'), timeout_seconds=TIME_THIRTY_SECONDS,
             sleep_seconds=WAIT_SHORT, waiting_for="Scan configure page to get loaded properly.")

        scan_settings = BasicSetting()
        scan_settings.click_link_inside_link(setting_value=Nessus.Scan.SettingsTypes.BASIC,
                                             link_text=Nessus.Scan.SettingsBasicSubMenu.PERMISSIONS)
        scan_settings.set_user_permissions_for_scans(permission=Nessus.Scan.UserPermissions.CAN_CONFIGURE,
                                                     user_name=create_user[0])
        scan_form_page.save_button.click()

        notification = Notifications()
        assert notification.successes[-1] == Messages.NotificationMessages.save_scan, \
            'Notification is not displayed for saving scan'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        assert ("{}\n{}".format("Shared", create_scans[0])) in scan_list.get_all_scans(), \
            'Scan was not created successfully with a "Shared" tag'

        LoadingCircle(WAIT_NORMAL)
        user_menu = UserMenu()
        user_menu.logout()

        # Login and check the functionality according to role given. Here we have given 'Can Edit' role so user
        # should be able to edit the scan
        login_page = LoginPage()
        login_page.login_with_credentials(username=create_user[0], password=create_user[1])
        LoadingCircle(WAIT_NORMAL)

        scan_list.click_on_scan("{}\n{}".format("Shared", create_scans[0]))

        edited_scan_name = "Edited" + create_scans[0]
        scan_view_page.configure_button.click()
        scan_form_page.name_field.value = edited_scan_name
        scan_form_page.save_button.click()
        assert notification.successes[-1] == Messages.NotificationMessages.save_scan, \
            'There is no notification for editing shared scan'

        user_menu.logout()
        login_page.do_login()

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        scan_list.delete_scan("{}\n{}".format("Shared", edited_scan_name))

    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.MOBILE_DEVICE, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.MOBILE_DEVICE)),
         'add_configuration': True}]}], indirect=True)
    def test_credentials_from_mobile_device(self, create_scans):
        """
        NQA-1086-Automation tests for Scans - Scanner Editing for created scans.(Step 9)
        1. Click on the existing created Scan having template ‘Mobile Device Scan’.
        2. Click on “Configure” button for editing, navigate to “Credentials” tab and remove credential(s) added.
        3. Click on “Save” button.
        4. Scan should not save and it must throw you an error notification as
        "Error: One of the following credentials must be added to this policy:
        MobileIron, MaaS360, AirWatch, Good MDM, Apple Profile Manager, ADSI"
        """
        scan_form_page = NewScanForm()

        # add required credentials
        credentials = AirWatch(mobile_credential_type=API.Credentials.Mobile.AIRWATCH)
        credentials.fill_airwatch_form(api_key='1UQH4IQQAAG6A45QAUAA', api_url='as705.awmdm.com/airwatchservices/0/',
                                       port=API.Credentials.Mobile.Ports.PORT, username='admin', http_switch=True,
                                       password='admin')

        scan_form_page.save_button.click()
        assert create_scans[0] in ScanList().get_all_scans(), 'Created scan is not in the list of scans'

        notification_text = reconfigure_scan_and_get_notification(
            setting_type=Nessus.Scan.ScanFeatureTabs.CREDENTIALS, form_name=API.Credentials.Mobile.AIRWATCH,
            scan_name=create_scans[0])

        assert notification_text == Messages.NotificationMessages.Policies.mobile_device_validation, \
            'Scan should not saved successfully without required credentials.'

        HeaderBasePage().scan_link.click()

    @pytest.mark.usefixtures('load_test_data')
    @pytest.mark.parametrize('test_data_file',
                             [os.path.abspath(get_file_path('nessus/tests/ui/scans/test_data/compliance_data.json'))],
                             indirect=True)
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.MDM_AUDIT, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.MDM_AUDIT)),
         'add_configuration': True}]}], indirect=True)
    def test_remove_compliance_from_mdm_audit(self, create_scans, load_test_data):
        """
        NQA-1086-Automation tests for Scans - Scanner Editing for created scans.(Step 7)
        1. Click on the existing created Scan having template ‘MDM Config Audit’.
        2. Click on “Configure” button for editing and navigate to “Compliance” tab and remove compliance(s) added.
        3. Click on “Save” button.
        4. Scan should not save and it must throw you an error notification as
        “Error: At least one audit must be added to this policy in the 'Compliance' section.”
        """
        scan_form_page = NewScanForm()

        # add required credentials and compliance
        credentials = AirWatch(mobile_credential_type=API.Credentials.Mobile.AIRWATCH)
        credentials.fill_airwatch_form(api_key='1UQH4IQQAAG6A45QAUAA', api_url='as705.awmdm.com/airwatchservices/0/',
                                       port=API.Credentials.Mobile.Ports.PORT, username='admin', http_switch=True,
                                       password='admin')

        compliance = AppleProfileManagerTNS()
        LoadingCircle(WAIT_NORMAL)
        compliance.fill_compliance_form(**load_test_data.get('apple_profile_manager_data'))

        scan_form_page.save_button.click()
        assert create_scans[0] in ScanList().get_all_scans(), 'Created scan is not in the list of scans'

        notification_text = reconfigure_scan_and_get_notification(
            setting_type=Nessus.Scan.ScanFeatureTabs.COMPLIANCE, form_name=ComplianceConst.MOBILEIRON,
            scan_name=create_scans[0])

        assert notification_text == Messages.NotificationMessages.Policies.audit_policy_validation, \
            'Scan should not saved successfully without required compliance.'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)


@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures("nessus_api_login")
@pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_Scan_Result.db',
                                                  'file_path': 'nessus/tests/ui/scans/test_data/',
                                                  'password': 'nessus', "encrypted": True}], indirect=True)
@pytest.mark.usefixtures('login')
class TestImportedScanEditing:
    """NQA-1276: Automation tests for Scans - Scanner Editing for imported scans."""

    cat = None

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_legacy
    def test_verify_tabs_settings_link_for_imported_scans(self, import_scan_via_api):
        """
        NQA-1276: Automation tests for Scans - Scanner Editing for imported scans. (Step 1)
        1. Navigate to "My Scans" page under Scans and click on the existing imported scan.
        2. Click on "Configure" button for editing.
        3. Verify presence of only "Settings" tab with "Basic" sub-link.
        4. Verify absence of other tabs (e.g. "Plugins")
        5. Verify absence of other sub-link (e.g.: "Assessment", "Discovery" etc.)
        """
        scan_name = import_scan_via_api[0]
        ScansPage().refresh()

        ScanList().click_on_scan(scan_name=scan_name)
        ScanViewPage().configure_button.click()
        LoadingCircle(WAIT_SHORT)

        scan_form_page = NewScanForm()
        assert all([scan_form_page.is_element_present('settings_tab'),
                    not scan_form_page.is_element_present('credentials'),
                    not scan_form_page.is_element_present('compliance'),
                    not scan_form_page.is_element_present('plugin'), not scan_form_page.is_element_present('scap')]), \
            'Only Settings Tab should be visible for Imported scans. Other tabs should not be present'

        scan_settings = ScanSettings()
        assert all([scan_settings.is_element_present('basic'),
                    not scan_settings.is_element_present('assessment'),
                    not scan_settings.is_element_present('report'),
                    not scan_settings.is_element_present('discovery'),
                    not scan_settings.is_element_present('advanced')]), \
            'Only Basic settings link should be present. Other settings should not be present'

    def test_verify_settings_sub_link_for_imported_scans(self, import_scan_via_api):
        """
        NQA-1276: Automation tests for Scans - Scanner Editing for imported scans. (Step 2)
        1. Navigate to "My Scans" page under Scans and click on the existing imported scan.
        2. Click on "Configure" button for editing.
        3. Verify presence of only "General/Permission" sub-links under "Settings" tab.
        4. Verify absence of other sub-link (e.g.: "Notifications", "Schedule" etc.)
        """
        scan_name = import_scan_via_api[0]
        ScansPage().refresh()

        ScanList().click_on_scan(scan_name=scan_name)
        ScanViewPage().configure_button.click()
        LoadingCircle(WAIT_SHORT)

        basic_setting = BasicSetting()
        assert all([basic_setting.is_element_present('general'), not basic_setting.is_element_present('notifications'),
                    basic_setting.is_element_present('permissions'),
                    not basic_setting.is_element_present('schedule')]), \
            'Only General and Permissions settings sub link should be present. Other settings should not be present'

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_legacy
    def test_verify_fields_presence_validation(self, import_scan_via_api):
        """
        NQA-1276: Automation tests for Scans - Scanner Editing for imported scans. (Step 3)
        1. Navigate to "My Scans" page under Scans and click on the existing imported scan.
        2. Click on "Configure" button for editing.
        3. Verify the presence of these field "Name/descriptions/Folder/Dashboard" and absence of
           "Targets/Upload targets" field.
        """
        scan_name = import_scan_via_api[0]
        ScansPage().refresh()

        ScanList().click_on_scan(scan_name=scan_name)
        ScanViewPage().configure_button.click()
        LoadingCircle(WAIT_SHORT)

        scan_form_page = NewScanForm()

        properties = self.cat.api.server.properties()
        if properties['nessus_type'] != "Nessus Manager":
            assert all([scan_form_page.is_element_present('name_field'),
                        scan_form_page.is_element_present('description_textarea'),
                        scan_form_page.is_element_present('select_folder')])

        else:
            assert all([scan_form_page.is_element_present('name_field'),
                        scan_form_page.is_element_present('description_textarea'),
                        scan_form_page.is_element_present('select_folder'),
                        scan_form_page.is_element_present('select_dashboard'),
                        not scan_form_page.is_element_present('targets_textarea'),
                        not scan_form_page.is_element_present('upload_targets')]), \
                '"Name/descriptions/Folder/Dashboard" should be present and "Targets/Upload targets" ' \
                'should not be present'

    def test_enable_disable_dashboard_for_imported_scan(self, import_scan_via_api):
        """
        NQA-1276: Automation tests for Scans - Scanner Editing for imported scans. (Step 4)
        1. Import a scan file and navigate to "My Scans" page under Scans and click on the imported scan.
        2. Verify absence of "Dashboard" tab in scan details page and presence of "Click here" link to enable the
           dashboard for that scan in top right corner of the page.
        3. Click on "Configure" button for editing and edit dashboard option to "Enable".
        4. Click save button and verify success notification.
        5. Go back to scan details page and verify "Dashboard" tab is showing the scan results and absence of
          "Click here" link to enable the dashboard.
        6. Repeat Step-3 and 5 for "Disabled" and Verify Dashboard is not present and Click here link is present
        """
        scan_name = import_scan_via_api[0]
        ScansPage().refresh()

        ScanList().click_on_scan(scan_name=scan_name)
        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present('search_box'), waiting_for='Scan details to load')

        scan_view_page.host_tab.click()
        wait(lambda: scan_view_page.is_element_present('search_box'), waiting_for='Scan details to load')

        assert all([not scan_view_page.is_element_present('dashboard_tab'),
                    scan_view_page.is_element_present('link_to_enable_dashboard')]), \
            'Dashboard tab is present for imported scan by default or Link to enable dashboard is not present'

        scan_view_page.configure_button.click()
        scan_form_page = NewScanForm()
        scan_form_page.select_dashboard.set_checked(True)
        scan_form_page.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            'Scan saved successfully message did not occur'

        scan_form_page.back_link.click()
        wait(lambda: scan_view_page.is_element_present('dashboard_tab'), waiting_for='Scan details to load')

        assert scan_view_page.dashboard_tab.is_displayed(), \
            'Dashboard tab is not present even after enabling dashboard'

        assert not scan_view_page.is_element_present('link_to_enable_dashboard'), \
            'Link to enable dashboard is still present'

        scan_view_page.configure_button.click()
        scan_form_page.select_dashboard.set_checked(False)
        scan_form_page.save_button.click()

        scan_form_page.back_link.click()
        wait(lambda: scan_view_page.is_element_present('search_box'), waiting_for='Scan details to load',
             timeout_seconds=TIME_SIXTY_SECONDS)

        assert not scan_view_page.is_element_present('dashboard_tab'), \
            'Dashboard tab is present for imported scan or Link to enable dashboard is not present'

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_legacy
    @pytest.mark.usefixtures('delete_all_scans_in_nessus', 'delete_all_custom_folders', 'login', 'create_new_folder')
    def test_move_imported_scan_to_other_folder(self, import_scan_via_api, create_new_folder):
        """
        NQA-1276: Automation tests for Scans - Scanner Editing for imported scans. (Step 5)
        1. Create a new custom folder
        2. Import scan in default folder
        3. Click on the imported scan and hit "Configure" button for editing.
        4. Verify the folder option shows your current folder.
        5. Change the folder to new folder created and save it.
        6. Verify success notification.
        7. Go back to the main page and verify the scan is not listed in that folder.
        8. Go to created folder page and verify the scan is listed here.
        """
        scan_name = import_scan_via_api[0]
        folder_name = create_new_folder[1]

        scan_page = ScansPage()
        scan_page.refresh()
        wait(lambda: scan_page.is_element_present("scan_searchbox"), waiting_for="scans list gets loaded")

        scan_list = ScanList()
        scan_list.click_on_scan(scan_name)
        ScanViewPage().configure_button.click()

        scan_form_page = NewScanForm()
        wait(lambda: scan_form_page.is_element_present("name_field"), waiting_for="scan form to be loaded",
             timeout_seconds=TIME_SIXTY_SECONDS)

        assert scan_form_page.select_folder.get_text_selected() == Nessus.Scan.Folder.MY_SCANS.split(' (')[0], \
            'Default folder is not same as current folder of scan'

        scan_form_page.select_folder.select_by_visible_text(folder_name)
        scan_form_page.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            'Scan saved successfully message did not occur'

        side_nav = SideNav()
        side_nav.click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        wait(lambda: scan_page.is_element_present("scan_searchbox") or scan_page.is_element_present(
            "create_a_new_scan_link"), waiting_for="Scan page gets loaded properly")

        assert scan_name not in scan_list.get_all_scans(), 'Imported scan is still in the My Scans list'

        side_nav.click_by_link_text("{} ".format(folder_name))
        wait(lambda: scan_page.is_element_present("scan_searchbox"), waiting_for="scans list gets loaded")

        assert scan_name in scan_list.get_all_scans(), 'Unable to move scan into created folder'
