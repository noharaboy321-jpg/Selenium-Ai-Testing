"""
Nessus Policy > Scanner Editing related tests

:copyright: Tenable Network Security, 2017
:date: June 22, 2018
:last_modified: Jan 22, 2020
:author: @ntarwani, @kpanchal
"""
import os
import pytest

from catium.helpers.sleep_lib import sleep
from catium.helpers.testdata import get_file_path
from catium.lib.const import WAIT_NORMAL, WAIT_SHORT
from catium.lib.util import random_name
from catium.lib.webium.wait import wait
from nessus.lib.const import Nessus, API
from nessus.lib.const.compliance_constants import ComplianceConst
from nessus.lib.message.messages import Messages
from nessus.pageobjects.compliances.compliance_page import Compliance
from nessus.pageobjects.compliances.compliance_sub_categories import AppleProfileManagerTNS, \
    TNSBlueCoatProxySGBenchmark, CISJuniperJunosBenchmarkL1, CISAmazonWebServicesFoundationsL1
from nessus.pageobjects.credentials.cloud_services import AmazonAWS
from nessus.pageobjects.credentials.credentials_page import Credentials
from nessus.pageobjects.credentials.host import Password
from nessus.pageobjects.credentials.mobile_credential import AirWatch
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.header.user_menu import UserMenu
from nessus.pageobjects.login.login_page import LoginPage
from nessus.pageobjects.policies.new_policy_form import NewPolicyForm
from nessus.pageobjects.policies.policies_page import PoliciesPage, PolicyList
from nessus.pageobjects.scans.scan_basic_settings_page import BasicSetting
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav


def configuration_steps(setting_type: str, policy_name: str, form_name: str) -> None:
    """
    Common method for configuration steps used frequently in the test cases
    :param str setting_type: Setting type: Credentials, Compliance or Plugin
    :param str form_name: Name of the credential/compliance form saved
    :param str policy_name: Policy name to be clicked and configured
    :return: None
    :rtype: None
    """
    new_policy = NewPolicyForm()
    PolicyList().click_on_policy(policy_name)

    if setting_type == "Credentials":
        new_policy.credentials.click()
        credentials = Credentials()
        credentials.open_saved_credentials_component(form_name)
        credentials.remove_form.click()

    if setting_type == "Compliance":
        new_policy.compliance.click()
        compliance = Compliance()
        compliance.open_saved_compliance_component(form_name)
        compliance.remove_form.click()

    new_policy.save_button.click()


@pytest.mark.policies_pipeline_1
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestPoliciesScannerEditing:
    """NQA-1070- Automation tests for Policies - Scanner, Editing."""

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix="Policy of {} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    def test_page_title_and_back_link(self, create_policies):
        """
        NQA-1070- Automation tests for Policies - Scanner, Editing.
        1. Navigate to “Policies” page and click on the existing created policy.
        2. Verify it will open Configuration page having title “Policy Name / Configuration” and ‘Name’ field filled
           with the ‘Policy Name’.
        3. Verify “Back to Policies” link is present in page header.
        4. Click on the link.
        5. Verify redirection to the policies main page.
        """
        new_policy = NewPolicyForm()
        new_policy.save_button.click()

        created_policy = create_policies[0]
        policy_list = PolicyList()

        policy_list.click_on_policy(created_policy)
        assert new_policy.get_page_heading == "{} / Configuration".format(created_policy), \
            'Configuration page for policy is not opened'
        assert new_policy.name_field.value == created_policy, "Policy name is incorrect under name field"
        assert new_policy.back_to_policies.is_displayed(), 'Back to Policies link is not displayed'

        new_policy.back_to_policies.click()
        assert PoliciesPage().title_in_header.text == Nessus.SideNavResources.POLICIES.split(' ')[0], \
            'Expected current page to be Policies Main page'

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix="Policy of {} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    def test_saved_success_message_on_editing(self, create_policies):
        """
        NQA-1070- Automation tests for Policies - Scanner, Editing.:
        1. Navigate to “Policies” page and click on the existing created policy.
        2. Edit the ‘Name’ field.
        3. Click on “Save” button.
        4. Policy should save with a success notification as “Policy saved successfully.”
        5. Click “Back to Policies” link and verify that the policy is listed with edited name.
        """
        new_policy = NewPolicyForm()
        new_policy.save_button.click()

        created_policy = create_policies[0]
        policy_list = PolicyList()
        edited_policy = "Edited " + created_policy

        policy_list.click_on_policy(created_policy)
        new_policy.name_field.value = edited_policy
        new_policy.save_button.click()

        notification = Notifications()
        assert notification.successes[-1] == Messages.NotificationMessages.Policies.policy_saved, \
            "Notification for policy saved is incorrect"

        new_policy.back_to_policies.click()
        sleep(sleep_time=WAIT_NORMAL, reason="Wait for policy list to load")
        assert edited_policy in policy_list.get_all_policies(), "Edited policy is not present in the policy list"

        policy_list.delete_policy(edited_policy)

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix="Policy of {} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    def test_editing_not_saved_on_cancel_button(self, create_policies):
        """
        NQA-1070- Automation tests for Policies - Scanner, Editing.:
        1. Navigate to “Policies” page and click on the existing created policy.
        2. Edit the ‘Name’ field.
        3. Click on “Cancel” button.
        4. It should redirect you to the Policies main page and verify that the policy is listed with existing name
        """
        new_policy = NewPolicyForm()
        new_policy.save_button.click()

        created_policy = create_policies[0]
        policy_list = PolicyList()
        edited_policy = "Edited " + created_policy

        policy_list.click_on_policy(created_policy)
        new_policy.name_field.value = edited_policy
        new_policy.cancel_button.click()

        assert PoliciesPage().title_in_header.text == Nessus.SideNavResources.POLICIES.split(' ')[0], \
            'Expected current page to be Policies Main page'
        assert edited_policy not in policy_list.get_all_policies(), "Edited policy is getting saved with Cancel button"

    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {'template_name': Nessus.TemplateNames.MOBILE_DEVICE, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix="Policy of {} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    def test_remove_mobile_device_credentials(self, create_policies):
        """
        NQA-1070- Automation tests for Policies - Scanner, Editing.
        1. Navigate to the existing Mobile Device policy
        2. Go to credentials tab
        3. Remove active credentials
        4. Click on save button
        5. Verify you get error message for credential required validation
        """
        new_policy = NewPolicyForm()
        credentials = AirWatch(mobile_credential_type=API.Credentials.Mobile.AIRWATCH)
        credentials.fill_airwatch_form(api_key='1UQH4IQQAAG6A45QAUAA', api_url='as705.awmdm.com/airwatchservices/0/',
                                       port=API.Credentials.Mobile.Ports.PORT, username='admin', http_switch=True,
                                       password='admin')

        new_policy.save_button.click()
        configuration_steps(setting_type="Credentials", policy_name=create_policies[0],
                            form_name=API.Credentials.Mobile.AIRWATCH)

        assert Notifications().errors[-1] == Messages.NotificationMessages.Policies.mobile_device_validation, \
            'Error notification for credential validation is not correct or did not appear'

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED, API.Permissions.Types.SCANNER)],
                             indirect=True)
    def test_number_of_forms_link(self, create_policy):
        """
        NQA-1070- Automation tests for Policies - Scanner, Editing.
        1. Navigate to existing policy
        2. Go to credentials tab
        3. Select Miscellaneous from category dropdown
        4. Observe that number of forms for ADSI is 5
        5. Click the form 5 times.
        6. Verify the form is not present under sub-category list after the maximum limit is reached
        7. Now select Host from Category dropdown
        8. Click the form with ∞ sign more than 10 times and verify the correct number of forms opened
        """
        new_policy = NewPolicyForm()
        new_policy.save_button.click()
        LoadingCircle(WAIT_SHORT)

        policy_list = PolicyList()
        policy_list.click_on_policy(create_policy)
        new_policy.credentials.click()

        credentials = Credentials()
        credentials.credentials_type.select_by_visible_text("Miscellaneous")

        while credentials.get_number_of_forms_element("ADSI").text >= '1':
            credentials.get_number_of_forms_element("ADSI").click()
            LoadingCircle(WAIT_SHORT)
        assert not credentials.get_inclusive_credentials_type(data_credentials="Miscellaneous",
                                                              sub_category="ADSI").is_displayed(), \
            'The sub category is still displayed after the maximum count of forms is reached'

        for _ in credentials.active_credentials:
            credentials.open_saved_credentials_component(form_name="ADSI")
            credentials.remove_form.click()

        credentials.credentials_type.select_by_visible_text("Host")
        if "infinity" in credentials.get_number_of_forms_element("SSH").get_css_classes():
            for _ in range(11):
                credentials.get_inclusive_credentials_type(data_credentials="Host", sub_category="SSH").click()
                credentials.js_scroll_into_view(credentials.credentials_tab)
            assert len(credentials.active_credentials) == 11, 'The number of forms active is incorrect'

        SideNav().click_by_link_text(Nessus.SideNavResources.POLICIES)

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.usefixtures('load_test_data')
    @pytest.mark.parametrize('test_data_file',
                             [os.path.abspath(get_file_path('nessus/tests/ui/scans/test_data/compliance_data.json'))],
                             indirect=True)
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.AUDIT_CLOUD, API.Permissions.Types.SCANNER)],
                             indirect=True)
    def test_remove_aci_compliance(self, create_policy, load_test_data):
        """
        NQA-1070- Automation tests for Policies - Scanner, Editing.
        1. Navigate to the existing Audit Compliance policy
        2. Go to compliance tab
        3. Remove active compliance
        4. Click on save button
        5. Verify you get error message for compliance/audit required validation
        """
        new_policy = NewPolicyForm()

        credentials = AmazonAWS(cloud_type=API.Credentials.CloudServices.Types.AMAZON_AWS)
        credentials.fill_amazon_aws_form(access_key='admin', secret_key='admin', regions_to_access='China')

        compliance = CISAmazonWebServicesFoundationsL1()
        compliance.fill_compliance_form(**load_test_data.get('amazon_data'))
        compliance.js_scroll_into_view(new_policy.save_button)
        new_policy.save_button.click()
        sleep(sleep_time=WAIT_NORMAL, reason="Wait for policy to get saved")
        policy_list = PolicyList()
        assert create_policy in policy_list.get_all_policies(), 'Policy was not created successfully'

        configuration_steps(setting_type="Compliance", policy_name=create_policy, form_name=ComplianceConst.AMAZON)

        assert Notifications().errors[-1] == Messages.NotificationMessages.Policies.audit_policy_validation, \
            'Error notification for compliance validation did not appear'

        SideNav().click_by_link_text(Nessus.SideNavResources.POLICIES)

    @pytest.mark.usefixtures('load_test_data')
    @pytest.mark.parametrize('test_data_file',
                             [os.path.abspath(get_file_path('nessus/tests/ui/scans/test_data/compliance_data.json'))],
                             indirect=True)
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.MDM_AUDIT, API.Permissions.Types.SCANNER)],
                             indirect=True)
    def test_remove_mdm_compliance(self, create_policy, load_test_data):
        """
        NQA-1070- Automation tests for Policies - Scanner, Editing.
        1. Navigate to the existing MDM Audit policy
        2. Go to compliance tab
        3. Remove active compliance
        4. Click on save button
        5. Verify you get error message for compliance/audit required validation
        """
        new_policy = NewPolicyForm()

        credentials = AirWatch(mobile_credential_type=API.Credentials.Mobile.AIRWATCH)
        credentials.fill_airwatch_form(api_key='1UQH4IQQAAG6A45QAUAA', api_url='as705.awmdm.com/airwatchservices/0/',
                                       port=API.Credentials.Mobile.Ports.PORT, username='admin', http_switch=True,
                                       password='admin')

        compliance = AppleProfileManagerTNS()
        compliance.fill_compliance_form(**load_test_data.get('apple_profile_manager_data'))
        new_policy.save_button.click()
        sleep(sleep_time=WAIT_NORMAL, reason="Wait for policy to get saved")
        policy_list = PolicyList()
        assert create_policy in policy_list.get_all_policies(), 'Policy was not created successfully'

        configuration_steps(setting_type="Compliance", policy_name=create_policy, form_name=ComplianceConst.MOBILEIRON)

        assert Notifications().errors[-1] == Messages.NotificationMessages.Policies.audit_policy_validation, \
            'Error notification for compliance validation did not appear'

        SideNav().click_by_link_text(Nessus.SideNavResources.POLICIES)

    @pytest.mark.xfail(reason="'TNS BlueCoat ProxySG Benchmark' compliance type is not present under 'BlueCoat ProxySG'"
                              "compliance category.")
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.usefixtures('load_test_data')
    @pytest.mark.parametrize('test_data_file',
                             [os.path.abspath(get_file_path('nessus/tests/ui/scans/test_data/compliance_data.json'))],
                             indirect=True)
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.COMPLIANCE_AUDIT, API.Permissions.Types.SCANNER)],
                             indirect=True)
    def test_remove_policy_compliance_auditing_compliance(self, create_policy, load_test_data):
        """
        NQA-1070- Automation tests for Policies - Scanner, Editing.
        1. Navigate to the existing Policy Compliance auditing policy
        2. Go to compliance tab
        3. Remove active compliance
        4. Click on save button
        5. Verify you get error message for compliance/audit required validation
        """
        new_policy = NewPolicyForm()
        policy_list = PolicyList()

        credentials = Password(host_type=API.Credentials.Host.Types.SSH)
        credentials.fill_password_ssh_form(username='admin', password='admin')

        compliance = TNSBlueCoatProxySGBenchmark()
        LoadingCircle(WAIT_NORMAL)

        bluecoat_proxysg_data = load_test_data.get('bluecoat_proxysg_data')
        del bluecoat_proxysg_data['config_file']
        compliance.fill_compliance_form(**load_test_data.get('bluecoat_proxysg_data'))
        compliance.js_scroll_into_view(new_policy.save_button)
        new_policy.save_button.click()
        sleep(sleep_time=WAIT_NORMAL, reason="Wait for policy to get saved")
        assert create_policy in policy_list.get_all_policies(), 'Policy was not created successfully'

        configuration_steps(setting_type="Compliance", policy_name=create_policy,
                            form_name=ComplianceConst.BLUECOAT_PROXYSG)

        assert Notifications().errors[-1] == Messages.NotificationMessages.Policies.audit_policy_validation, \
            'Error notification is not correct'

        SideNav().click_by_link_text(Nessus.SideNavResources.POLICIES)

    @pytest.mark.nessus_expert
    # @pytest.mark.nessus_pro Juniper OS compliance is not available for nessus pro
    @pytest.mark.usefixtures('load_test_data')
    @pytest.mark.parametrize('test_data_file',
                             [os.path.abspath(get_file_path('nessus/tests/ui/scans/test_data/compliance_data.json'))],
                             indirect=True)
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.OFFLINE_AUDIT, API.Permissions.Types.SCANNER)],
                             indirect=True)
    def test_remove_offline_audit_compliance(self, create_policy, load_test_data):
        """
        NQA-1070- Automation tests for Policies - Scanner, Editing.
        1. Navigate to the existing Offline Config Audit policy
        2. Go to compliance tab
        3. Remove active compliance
        4. Click on save button
        5. Verify you get error message for compliance/audit required validation
        """
        new_policy = NewPolicyForm()

        compliance = CISJuniperJunosBenchmarkL1()
        juniper_data = load_test_data.get('juniper_data')
        juniper_data['config_file'] = os.path.abspath(get_file_path(
            'nessus/tests/api/plugins/test_data/api_pub_key_target_priv_key'))

        compliance.fill_compliance_form(**load_test_data.get('juniper_data'))
        compliance.js_scroll_into_view(new_policy.save_button)
        new_policy.save_button.click()

        policy_list = PolicyList()
        assert create_policy in policy_list.get_all_policies(), 'Policy creation is not successful'

        configuration_steps(setting_type="Compliance", policy_name=create_policy,
                            form_name=ComplianceConst.JUNIPER_OS)

        assert Notifications().errors[-1] == Messages.NotificationMessages.Policies.audit_policy_validation, \
            'Error message for offline config file did not appear'

        SideNav().click_by_link_text(Nessus.SideNavResources.POLICIES)

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.AUDIT_PATCH, API.Permissions.Types.SCANNER)],
                             indirect=True)
    def test_remove_credential_patch_audit_credentials(self, create_policy):
        """
        NQA-1070- Automation tests for Policies - Scanner, Editing.
        1. Navigate to the existing Credential patch audit policy
        2. Go to credentials tab
        3. Remove active credentials
        4. Click on save button
        5. Verify you get error message for credentials required validation
        """
        new_policy = NewPolicyForm()
        policy_list = PolicyList()
        credentials = Password(host_type=API.Credentials.Host.Types.SSH)
        credentials.fill_password_ssh_form(username='admin', password='admin')

        new_policy.js_scroll_into_view(new_policy.save_button)
        new_policy.save_button.click()
        sleep(sleep_time=WAIT_NORMAL, reason="Wait for policy to get saved")
        assert create_policy in policy_list.get_all_policies(), 'Policy was not created successfully'

        configuration_steps(setting_type="Credentials", policy_name=create_policy,
                            form_name=API.Credentials.Host.SSHAuthTypes.PASSWORD)

        assert Notifications().errors[-1] == Messages.NotificationMessages.Policies.cred_patch_audit_validation, \
            'Error notification for credential validation did not appear'

        SideNav().click_by_link_text(Nessus.SideNavResources.POLICIES)

    @pytest.mark.parametrize("create_user", [{'username': random_name(prefix=API.User.Users.STANDARD_USER + ' - '),
                                              'password': 'password', 'role': API.User.Role.STANDARD,
                                              'do_login': False}], indirect=True)
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED, API.Permissions.Types.SCANNER)],
                             indirect=True)
    def test_shared_permission_with_other_user(self, create_user, create_policy):
        """
        NQA-1070- Automation tests for Policies - Scanner, Editing.
        1. Create another user
        2. Navigate to existing policy and give any permission to the user created above
        3. Save the policy and verify Shared tag is present as prefix to policy name
        4. Login as a new user
        5. Verify the functionality according to given role
        """
        new_policy = NewPolicyForm()
        new_policy.save_button.click()

        policy_list = PolicyList()
        policy_list.click_on_policy(create_policy)
        LoadingCircle(WAIT_NORMAL)

        policy_settings = BasicSetting()
        policy_settings.click_link_inside_link(setting_value=Nessus.Scan.SettingsTypes.BASIC,
                                               link_text=Nessus.Scan.SettingsBasicSubMenu.PERMISSIONS)
        policy_settings.set_user_permissions_for_scans(permission=Nessus.Scan.UserPermissions.CAN_EDIT,
                                                       user_name=create_user[0])
        new_policy.save_button.click()

        notification = Notifications()
        assert notification.successes[-1] == Messages.NotificationMessages.Policies.policy_saved, \
            'No notification occurred for saved policy'

        new_policy.back_to_policies.click()
        sleep(sleep_time=WAIT_NORMAL, reason="Wait for policy list to load")
        assert ("{}\n{}".format("Shared", create_policy)) in policy_list.get_all_policies(), \
            'Policy was not created successfully with a "Shared" tag'

        LoadingCircle(WAIT_NORMAL)
        user_menu = UserMenu()
        user_menu.logout()

        # Login and check the functionality according to role given. Here we have given 'Can Edit' role so user
        # should be able to edit the policy
        login_page = LoginPage()
        login_page.login_with_credentials(username=create_user[0], password=create_user[1])
        LoadingCircle(WAIT_NORMAL)

        SideNav().click_by_link_text(Nessus.SideNavResources.POLICIES)
        sleep(sleep_time=WAIT_NORMAL, reason="Wait for policy list to load")
        policy_list.click_on_policy("{}\n{}".format("Shared", create_policy))

        edited_policy_name = "Edited" + create_policy
        new_policy.name_field.value = edited_policy_name
        new_policy.save_button.click()
        assert notification.successes[-1] == Messages.NotificationMessages.Policies.policy_saved, \
            'There is no notification for Policy saving'

        user_menu.logout()
        login_page.do_login()

        SideNav().click_by_link_text(Nessus.SideNavResources.POLICIES)
        sleep(sleep_time=WAIT_NORMAL, reason="Wait for policy list to load")
        policy_list.delete_policy("{}\n{}".format("Shared", edited_policy_name))
