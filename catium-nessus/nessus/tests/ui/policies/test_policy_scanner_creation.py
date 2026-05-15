"""
Nessus Policy > Scanner Creation related tests

:copyright: Tenable Network Security, 2017
:date: June 06, 2018
:last_modified: June 16, 2022
:author: @ntarwani, @kpanchal, @krpatel
"""
from datetime import datetime
from random import randint

import pytest
from packaging.version import parse

from catium.lib.const import WAIT_NORMAL
from catium.lib.log.log import create_logger
from catium.lib.webium.driver import get_driver_no_init
from nessus.helpers.system import get_nessus_version, is_expert, is_pro, is_home
from nessus.lib.const import Nessus, API
from nessus.lib.const.compliance_constants import ComplianceConst
from nessus.lib.message.messages import Messages
from nessus.pageobjects.compliances.compliance_page import Compliance
from nessus.pageobjects.compliances.compliance_sub_categories import AppleProfileManagerTNS, \
    TNSBlueCoatProxySGBenchmark, CISAmazonWebServicesFoundationsL1
from nessus.pageobjects.credentials.cloud_services import AmazonAWS
from nessus.pageobjects.credentials.credentials_page import Credentials
from nessus.pageobjects.credentials.host import Password
from nessus.pageobjects.credentials.mobile_credential import AirWatch
from nessus.pageobjects.dynamic_plugins.dynamic_plugins_page import DynamicPlugin
from nessus.pageobjects.header.notifications import Notifications, NotificationActions
from nessus.pageobjects.plugins.plugins_page import Plugin
from nessus.pageobjects.policies.new_policy_form import PolicyTemplatePage, NewPolicyForm
from nessus.pageobjects.policies.policies_page import PoliciesPage, PolicyList
from nessus.pageobjects.scans.new_scan_form import ScanTemplatePage
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav

log = create_logger()


@pytest.mark.policies_pipeline_3
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestPolicyScannerCreation:
    """NQA-1066-Automation tests for Policies-Scanner Creation"""
    cat = None

    @pytest.mark.nessus_home
    @pytest.mark.nessus_legacy
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.usefixtures('nessus_api_login')
    def test_new_policy_page_url(self):
        """
        NQA-1066-Automation tests for Policies-Scanner Creation
        1. Navigate to Policies from Side Nav > Resources
        2. Click on new policy button
        3. Verify the url contains '/#/scans/policies/new'
        """
        policy_page = PoliciesPage()
        policy_page.open()

        policy_page.new_policy_button.click()
        LoadingCircle(WAIT_NORMAL)
        policy_page.js_scroll_to_bottom()

        assert '/#/scans/policies/new' in get_driver_no_init().current_url, 'Policy template page is not opened'

        if parse(get_nessus_version()) < parse('8.1.0'):
            Nessus.TemplateNames.SCAN_TEMPLATE_LIST.remove(Nessus.TemplateNames.ADVANCED_DYNAMIC)

        scan_template_page = ScanTemplatePage()
        scanner_templates = scan_template_page.get_all_scan_templates(scan_type=API.Permissions.Types.SCANNER)

        if is_expert():
            assert set(scanner_templates) == set(Nessus.TemplateNames.SCAN_TEMPLATE_LIST_EXPERT), \
                'All templates are not present under Scanner Tab'
        elif is_home():
            assert set(scanner_templates) == set(Nessus.TemplateNames.SCAN_TEMPLATE_LIST_HOME), \
                'All templates are not present under Scanner Tab'
        else:
            assert set(scanner_templates) == set(Nessus.TemplateNames.SCAN_TEMPLATE_LIST), \
                'All templates are not present under Scanner Tab'

        if is_expert():
            assert scanner_templates[:3] == Nessus.TemplateNames.SCAN_TEMPLATE_ORDER_EXPERT, \
                'First three scan types were not in the expected order for Expert'
        else:
            assert scanner_templates[:3] == Nessus.TemplateNames.SCAN_TEMPLATE_ORDER, \
                'First three scan types were not in the expected order'

    @pytest.mark.skip(reason="Jira ID NES-10750")
    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize("templates", [pytest.param(Nessus.TemplateNames.ADVANCED_DYNAMIC)] +
                             Nessus.TemplateNames.SCAN_TEMPLATE_LIST[1::])
    def test_verify_element_visibility_in_all_policy_scanner_templates(self, templates):
        """
        NQA-1066-Automation tests for Policies-Scanner Creation
        1. Navigate to Policies from Side Nav > Resources
        2. Click on new policy button
        3. Select Advanced Scan
        4. Verify Name field has required badge
        5. Verify for all templates

        NQA-1070: Automation tests for Policies - Scanner, Editing.
        4. Verify the “Eye icon” in “Plugins” tab for all policy templates except “Advanced Scan”.
            - Navigate to “Policies” page and click on the existing created policy.
            - Verify there is an “Eye” icon visible on the right side in “Plugins” tab.

        NQA-1070: Automation tests for Policies - Scanner, Editing.
        5. Verify you can’t edit any plugins from “Plugins” tab for all policy templates except “Advanced Scan”.
            - Navigate to “Policies” page under Scans and click on the existing created policy.
            - Click on “Plugins” tab.
            - Verify “Show Enabled”/ “Show All”/ “Disable All”/ “Enable All” options are not visible in the page.
            - Verify plugin details windows shows “No plugin family selected”.
        """
        properties = self.cat.api.server.properties()
        nessus_version = properties.get('nessus_ui_version')

        if templates == Nessus.TemplateNames.ADVANCED_DYNAMIC:
            if nessus_version < '8.1.0':
                pytest.xfail('{} template is not available in Nessus below 8.1.0 version.'.format(templates))

        if templates in [Nessus.TemplateNames.MDM_AUDIT, Nessus.TemplateNames.MOBILE_DEVICE] \
                and properties['nessus_type'] != "Nessus Manager":
            pytest.xfail('{} template does not work under Nessus Pro and Nessus Legacy.'.format(templates))

        scan_template = templates

        policy_page = PoliciesPage()
        policy_page.open()
        policy_page.new_policy_button.click()

        LoadingCircle(WAIT_NORMAL)
        PolicyTemplatePage().click_by_policy(policy_text=scan_template)
        new_policy_form = NewPolicyForm()

        assert new_policy_form.required_badge.is_displayed(), 'Required badge is not displayed'

        new_policy_form.save_button.click()

        if scan_template == Nessus.TemplateNames.ADVANCED_DYNAMIC:
            assert Notifications().errors[-1] == Messages.NotificationMessages.continue_button_code, \
                'Error notification did not appear or is incorrect'

            assert '/dynamic-plugins' in get_driver_no_init().current_url, 'Dynamic plugins tab is not opened.'

            DynamicPlugin().filter_control_input.send_keys('CVE-{}-{}'.format(datetime.now().year,
                                                                              randint(1000, 99999)))
            new_policy_form.settings.click()
            NotificationActions().remove_all()
            new_policy_form.save_button.click()

        assert Notifications().errors[-1] == Messages.NotificationMessages.Scans.required_scan_name, \
            'Error notification did not appear or is incorrect'

        if scan_template not in [Nessus.TemplateNames.ADVANCED, Nessus.TemplateNames.ADVANCED_DYNAMIC]:
            assert new_policy_form.plugin_eye_icon.is_displayed(), \
                "'Eye' icon' is not visible on the right side in Plugins tab in {} template.".format(scan_template)

            plugin_page = Plugin()

            assert not all([plugin_page.is_element_present('disable_all'),
                            plugin_page.is_element_present('enable_all'),
                            plugin_page.is_element_present('show_enabled'),
                            plugin_page.is_element_present('show_all')]), \
                "'Show Enabled', 'Show All', 'Disable All', 'Enable All' options are visible in Plugins tab."

            assert plugin_page.plugin_window_message.text == 'No plugin family selected.', \
                "Plugin details window is not showing 'No plugin family selected.'."

    @pytest.mark.nessus_legacy
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.usefixtures('get_nessus_server_properties')
    def test_aci_validations_and_compliance(self, get_nessus_server_properties):
        """
        NQA-1066-Automation tests for Policies-Scanner Creation
        1. Navigate to Policies from Side Nav > Resources
        2. Click on new policy button
        3. Select Audit Cloud Infrastructure
        4. Enter name and save policy
        5. Verify "Error: At least one audit must be added to this policy in the 'Compliance' section." appears
        6. Verify Compliance tab exists
        7. Verify list of compliance for this policy
        8. Verify search box is present below compliance categories
        9. Verify searching with keyword updates the list of sub categories and search text is present in all results
        """
        policy_page = PoliciesPage()
        policy_page.open()

        policy_page.create_new_policy(template_name=Nessus.TemplateNames.AUDIT_CLOUD, add_configuration=True)
        NewPolicyForm().save_button.click()

        assert Notifications().errors[-1] == Messages.NotificationMessages.Policies.audit_policy_validation, \
            'Error notification for compliance validation did not appear'

        compliance = Compliance()
        assert compliance.compliance.is_displayed(), 'Compliance tab is not displayed'
        list = compliance.get_category_type_list()
        log.debug("ACI compliance list ::{}".format(list))

        if self.cat.server_properties['license']['type'] == 'professional':
            log.debug("ACI compliance list ::{}".format(compliance.get_category_type_list()))
            assert compliance.get_category_type_list() == ComplianceConst.ACI_COMPLIANCE_LIST_PRO, \
                'Expected category list does not match with the present list'
        else:
            assert compliance.get_category_type_list() == ComplianceConst.ACI_COMPLIANCE_LIST, \
                'Expected category list does not match with the present list'

        assert compliance.compliance_type.text == "All", 'Default compliance type should be "All"'
        assert compliance.search_textbox.is_displayed(), 'Search box is not displayed'

        compliance.search_textbox.value = "Amazon"

        for compliance_cate in compliance.get_sub_category_list("All"):
            assert "Amazon" in compliance_cate.get_attribute('value'), 'Search is not working properly'

    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.AUDIT_CLOUD, API.Permissions.Types.SCANNER)],
                             indirect=True)
    @pytest.mark.parametrize('compliance_data', [({'compliance_name': 'Amazon AWS', 'cred_type': 'Amazon AWS',
                                                   'compliance_type': "CIS Amazon Web Services Foundations v5.0.0 L1"}),
                                                 ({'compliance_name': 'Microsoft Azure', 'cred_type': 'Microsoft Azure',
                                                   'compliance_type': "CIS Microsoft 365 Foundations v5.0.0 L2 E5"})])
    def test_aci_compliance_forms_and_credentials_link_pro(self, create_policy, compliance_data):
        """
        NQA-1066-Automation tests for Policies-Scanner Creation
        1. Navigate to Policies from Side Nav > Resources
        2. Click on new policy button
        3. Select Audit Cloud Infrastructure
        4. Navigate to compliance tab
        5. Select compliance type as Amazon AWS
        6. Verify the list is updated
        7. Open any form from the list
        8. Verify Credentials link is present for particular category
        9. Click on the link and verify Credentials tab is active with correct form open
        """
        new_policy = NewPolicyForm()
        compliance = Compliance()

        compliance.compliance_type.select_by_visible_text(compliance_data['compliance_name'])
        for compliance_type in compliance.get_sub_category_list(data_compliance=compliance_data['compliance_name']):
            assert compliance_type.get_attribute("data-parent") == compliance_data['compliance_name'], \
                'Compliance list is not according to the type selected'
        compliance_form = Compliance()
        compliance_form.get_compliance_type(compliance_data['compliance_type'])
        assert compliance_data['compliance_name'] == compliance_form.required_cred_link.get_attribute('text'), \
            'Required link for credential is improper'

        LoadingCircle(WAIT_NORMAL)
        compliance_form.required_cred_link.click()
        assert 'on' in new_policy.credentials.get_css_classes(), 'Credential tab is not active'
        assert Credentials().opened_form_value == compliance_data['cred_type'], 'Incorrect credential form is opened'

        SideNav().click_by_link_text(Nessus.SideNavResources.POLICIES)

    @pytest.mark.nessus_expert
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.AUDIT_CLOUD, API.Permissions.Types.SCANNER)],
                             indirect=True)
    @pytest.mark.parametrize('compliance_data', [({'compliance_name': 'Amazon AWS', 'cred_type': 'Amazon AWS',
                                                   'compliance_type': "CIS Amazon Web Services Foundations v5.0.0 L1"}),
                                                 ({'compliance_name': 'Microsoft Azure', 'cred_type': 'Microsoft Azure',
                                                   'compliance_type': "CIS Microsoft 365 Foundations v5.0.0 L2 E5"}),
                                                 ({'compliance_name': 'Rackspace', 'cred_type': 'Rackspace',
                                                   'compliance_type': "Tenable Best Practices RackSpace v2.0.0"}),
                                                 ({'compliance_name': 'Salesforce.com', 'cred_type': 'Salesforce.com',
                                                   'compliance_type': "TNS Salesforce Best Practices Audit v1.2.0"})])
    def test_aci_compliance_forms_and_credentials_link(self, create_policy, compliance_data):
        """
        NQA-1066-Automation tests for Policies-Scanner Creation
        1. Navigate to Policies from Side Nav > Resources
        2. Click on new policy button
        3. Select Audit Cloud Infrastructure
        4. Navigate to compliance tab
        5. Select compliance type as Amazon AWS
        6. Verify the list is updated
        7. Open any form from the list
        8. Verify Credentials link is present for particular category
        9. Click on the link and verify Credentials tab is active with correct form open
        """
        new_policy = NewPolicyForm()
        compliance = Compliance()

        compliance.compliance_type.select_by_visible_text(compliance_data['compliance_name'])
        for compliance_type in compliance.get_sub_category_list(data_compliance=compliance_data['compliance_name']):
            assert compliance_type.get_attribute("data-parent") == compliance_data['compliance_name'], \
                'Compliance list is not according to the type selected'
        compliance_form = Compliance()
        compliance_form.get_compliance_type(compliance_data['compliance_type'])
        assert compliance_data['compliance_name'] == compliance_form.required_cred_link.get_attribute('text'), \
            'Required link for credential is improper'

        LoadingCircle(WAIT_NORMAL)
        compliance_form.required_cred_link.click()
        assert 'on' in new_policy.credentials.get_css_classes(), 'Credential tab is not active'
        assert Credentials().opened_form_value == compliance_data['cred_type'], 'Incorrect credential form is opened'

        SideNav().click_by_link_text(Nessus.SideNavResources.POLICIES)

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.AUDIT_CLOUD, API.Permissions.Types.SCANNER)],
                             indirect=True)
    def test_policy_aci_scan_creation(self, create_policy):
        """
        NQA-1066-Automation tests for Policies-Scanner Creation
        1. Navigate to Policies from Side Nav > Resources
        2. Click on new policy button
        3. Select Audit Cloud Infrastructure
        4. Enter valid values under General, Credentials and Compliance tab
        5. Save the policy
        6. Verify the created policy is listed under Policies list
        """
        new_policy = NewPolicyForm()

        credentials = AmazonAWS(cloud_type=API.Credentials.CloudServices.Types.AMAZON_AWS)
        credentials.fill_amazon_aws_form(access_key='admin', secret_key='admin', regions_to_access='China')

        compliance = CISAmazonWebServicesFoundationsL1()
        compliance.fill_compliance_form(days_without_account_activity='80')

        new_policy.js_scroll_into_view(new_policy.save_button)
        new_policy.save_button.click()
        assert create_policy in PolicyList().get_all_policies(), 'Policy was not created successfully'

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.AUDIT_PATCH, API.Permissions.Types.SCANNER)],
                             indirect=True)
    def test_cred_patch_audit_validations_and_credentials(self, create_policy):
        """
        NQA-1066-Automation tests for Policies-Scanner Creation
        1. Navigate to Policies from Side Nav > Resources
        2. Click on new policy button
        3. Select Credentialed Patch Audit
        4. Enter name and save policy
        5. Verify error message for adding credentials appears
        6. Verify Credentials tab exists and Credentials type dropdown exists
        7. Verify list of Credentials type
        8. Verify default Credential type is Host
        """
        NewPolicyForm().save_button.click()
        notification = Notifications()

        assert notification.errors[-1] == Messages.NotificationMessages.Policies.cred_patch_audit_validation, \
            'Error notification for compliance validation did not appear'

        credentials = Credentials()
        assert credentials.credentials_tab.is_displayed(), 'Credentials tab is not displayed'

        credentials.credentials_tab.click()
        properties = self.cat.api.server.properties()
        if properties['nessus_type'] == "Nessus Manager":
            assert credentials.get_category_type_list() == ['All', 'API Gateway', 'Database', 'Host', 'Miscellaneous',
                                                            'Patch Management', 'Plaintext Authentication'], \
                'Expected category list does not match with the present list'
        else:
            assert credentials.get_category_type_list() == ['All', 'API Gateway', 'Database', 'Host', 'Miscellaneous',
                                                            'Plaintext Authentication'], \
                'Expected category list does not match with the present list'

        assert credentials.credentials_type.text == "Host", 'Default credential type should be "Host"'

        SideNav().click_by_link_text(Nessus.SideNavResources.POLICIES)

    @pytest.mark.nessus_home
    @pytest.mark.nessus_legacy
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    def test_credential_category_search(self):
        """
        NQA-1066-Automation tests for Policies-Scanner Creation
        1. Navigate to Policies from Side Nav > Resources
        2. Click on new policy button
        3. Select Credentialed Patch Audit
        4. Navigate to Credentials tab
        5. Verify filter box is present with place holder as “Filter Credentials” and “search_icon”
           is visible inside the box.
        6. Enter some search string and verify filtered list contains your search string.
        7. Also verify “remove_icon” is visible and “search_icon” is invisible inside the box.
        8. Click on “remove_icon” to clear the search string.
        9. Again verify “search_icon” is visible and “remove_icon” is invisible inside the box..
        """
        policy_page = PoliciesPage()
        policy_page.open()

        policy_page.create_new_policy(template_name=Nessus.TemplateNames.AUDIT_PATCH, add_configuration=True)
        credentials = Credentials()
        credentials.credentials_tab.click()
        assert all([credentials.search_category.is_displayed(), credentials.search_icon.is_displayed(),
                    credentials.search_category.get_attribute('placeholder') == "Filter Credentials"]), \
            'Search box or search icon is not displayed'

        credentials.credentials_type.select_by_visible_text("All")
        credentials.search_category.value = "Red Hat"
        for cred_type in credentials.get_sub_category_list(data_credentials="All"):
            assert "Red Hat" in cred_type.get_attribute('value'), 'Search is not working'
        assert credentials.remove_icon_searchbox.is_displayed() and not credentials.search_icon.is_displayed(), \
            'Either remove icon is not displayed or search icon is displayed'

        credentials.remove_icon_searchbox.click()
        assert not credentials.remove_icon_searchbox.is_displayed() and credentials.search_icon.is_displayed(), \
            'Either remove icon is displayed or search icon is not displayed'

        SideNav().click_by_link_text(Nessus.SideNavResources.POLICIES)

    @pytest.mark.nessus_home
    @pytest.mark.nessus_legacy
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.AUDIT_PATCH, API.Permissions.Types.SCANNER)],
                             indirect=True)
    def test_add_cred_patch_audit_policy(self, create_policy):
        """
        NQA-1066-Automation tests for Policies-Scanner Creation
        1. Navigate to Policies from Side Nav > Resources
        2. Click on new policy button
        3. Select Credentialed Patch Audit
        4. Enter valid values under General and Credentials tab
        5. Save the policy
        6. Verify the created policy is listed under Policies list
        """
        new_policy = NewPolicyForm()

        credentials = Password(host_type=API.Credentials.Host.Types.SSH)
        credentials.fill_password_ssh_form(username='admin', password='admin')

        new_policy.js_scroll_into_view(new_policy.save_button)
        new_policy.save_button.click()
        LoadingCircle(WAIT_NORMAL)
        assert create_policy in PolicyList().get_all_policies(), 'Policy was not created successfully'

    @pytest.mark.nessus_home
    @pytest.mark.nessus_legacy
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.MALWARE, API.Permissions.Types.SCANNER)],
                             indirect=True)
    def test_malware_scan_validations_and_creation(self, create_policy):
        """
        NQA-1066-Automation tests for Policies-Scanner Creation
        1. Navigate to Policies from Side Nav > Resources
        2. Click on new policy button
        3. Select Malware Scan
        4. Enter name and save policy
        5. Verify "Error: One of the following credentials must be added to this policy: Windows, SSH" appears
        6. Verify Credentials tab exists
        7. Verify list of Credentials type
        8. Enter valid values under General and Credentials tab
        9. Save the policy
        10. Verify policy is listed under Policies list
        """
        new_policy = NewPolicyForm()
        new_policy.save_button.click()
        notifications = Notifications()
        assert notifications.errors[-1] == Messages.NotificationMessages.Policies.malware_credential_validation, \
            'Error message is not proper'

        credentials = Credentials()
        assert credentials.credentials_tab.is_displayed(), 'Credentials tab is not displayed'

        credentials.credentials_tab.click()
        assert credentials.get_category_type_list() == ['All', 'API Gateway', 'Host'], \
            'Expected credentials category list does not match the list present.'

        credentials = Password(host_type=API.Credentials.Host.Types.SSH)
        credentials.fill_password_ssh_form(username='admin', password='admin')

        new_policy.js_scroll_into_view(new_policy.save_button)
        new_policy.save_button.click()

        assert create_policy in PolicyList().get_all_policies(), 'Policy was not created successfully'

    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.MDM_AUDIT, API.Permissions.Types.SCANNER)],
                             indirect=True)
    def test_mdm_validations_and_creation(self, create_policy):
        """
        NQA-1066-Automation tests for Policies-Scanner Creation
        1. Navigate to Policies from Side Nav > Resources
        2. Click on new policy button
        3. Select "MDM Config Audit"
        4. Enter name and save policy
        5. Verify "Error: At least one audit must be added to this policy in the 'Compliance' section." appears
        6. Verify Compliance tab exists
        7. Verify list of compliance for this policy
        8. Enter valid values under General, Credentials and Compliance tab
        9. Save the policy
        10. Verify policy is listed under Policies list
        """
        new_policy = NewPolicyForm()
        new_policy.save_button.click()

        notification = Notifications()
        assert notification.errors[-1] == "Error: At least one audit must be added to this policy in the " \
                                          "'Compliance' section."

        compliance = Compliance()
        assert compliance.compliance.is_displayed(), 'Compliance tab is not displayed'
        assert compliance.get_category_type_list() == ['All', "Mobile Device Manager"], \
            'Expected list does not match the present list'

        credentials = AirWatch(mobile_credential_type=API.Credentials.Mobile.AIRWATCH)
        credentials.fill_airwatch_form(api_key='1UQH4IQQAAG6A45QAUAA', api_url='as705.awmdm.com/airwatchservices/0/',
                                       port=API.Credentials.Mobile.Ports.PORT, username='admin', http_switch=True,
                                       password='admin')
        apple_profile = AppleProfileManagerTNS()
        apple_profile_manager_data = {'device_application_whitelist': '.**', 'device_application_blacklist': '$#@!'}
        apple_profile.js_scroll_into_view(new_policy.save_button)
        apple_profile.fill_compliance_form(**apple_profile_manager_data)
        new_policy.save_button.click()
        assert create_policy in PolicyList().get_all_policies(), 'Policy was not created successfully'

    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.MOBILE_DEVICE, API.Permissions.Types.SCANNER)],
                             indirect=True)
    def test_mobile_device_validations_and_creation(self, create_policy):
        """
        NQA-1066-Automation tests for Policies-Scanner Creation
        1. Navigate to Policies from Side Nav > Resources
        2. Click on new policy button
        3. Select Mobile Device Scan
        4. Enter name and save policy
        5. "Error: One of the following credentials must be added to this policy: Windows, SSH"
        6. Verify Credentials tab exists
        7. Verify list of Credentials type
        8. Enter valid values under General and Credentials tab
        9. Save the policy
        10. Verify policy is listed under Policies list
        """
        new_policy = NewPolicyForm()
        new_policy.save_button.click()
        notifications = Notifications()
        assert notifications.errors[-1] == Messages.NotificationMessages.Policies.mobile_device_validation, \
            'Error notification is not correct'

        credentials = Credentials()
        assert credentials.credentials_tab.is_displayed(), 'Credentials tab is not displayed'

        credentials.credentials_tab.click()
        assert credentials.get_category_type_list() == ['All', 'Miscellaneous', 'Mobile'], \
            'Expected list does not match the present list'

        credentials = AirWatch(mobile_credential_type=API.Credentials.Mobile.AIRWATCH)
        credentials.fill_airwatch_form(api_key='1UQH4IQQAAG6A45QAUAA', api_url='as705.awmdm.com/airwatchservices/0/',
                                       port=API.Credentials.Mobile.Ports.PORT, username='admin', http_switch=True,
                                       password='admin')

        new_policy.js_scroll_into_view(new_policy.save_button)
        new_policy.save_button.click()

        assert create_policy in PolicyList().get_all_policies(), 'Policy was not created successfully'

    @pytest.mark.nessus_legacy
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.usefixtures('get_nessus_server_properties')
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.COMPLIANCE_AUDIT, API.Permissions.Types.SCANNER)],
                             indirect=True)
    def test_policy_compliance_auditing_validations(self, get_nessus_server_properties, create_policy):
        """
        NQA-1066-Automation tests for Policies-Scanner Creation
        1. Navigate to Policies from Side Nav > Resources
        2. Click on new policy button
        3. Select Policy Compliance Auditing
        4. Enter name and save policy
        5. Verify "Error: At least one audit must be added to this policy in the 'Compliance' section." appears
        6. Verify Compliance tab exists
        7. Verify list of compliance for this policy
        """
        NewPolicyForm().save_button.click()

        assert Notifications().errors[-1] == Messages.NotificationMessages.Policies.audit_policy_validation, \
            'Error notification is not correct'

        compliance = Compliance()

        assert compliance.compliance.is_displayed(), 'Compliance tab is not displayed'

        nessus_version = get_nessus_server_properties["nessus_ui_version"]

        if parse(nessus_version) < parse('8.1.0'):
            ComplianceConst.POLICY_COMPLIANCE_LIST.remove('NetApp API')

        if self.cat.server_properties['license']['type'] == 'manager' and 'Mobile Device Manager' \
                not in ComplianceConst.POLICY_COMPLIANCE_LIST:
            ComplianceConst.POLICY_COMPLIANCE_LIST.insert(22, 'Mobile Device Manager')
        if self.cat.server_properties['license']['type'] == 'manager' and 'ArubaOS' \
                not in ComplianceConst.POLICY_COMPLIANCE_LIST:
            ComplianceConst.POLICY_COMPLIANCE_LIST.insert(23, 'ArubaOS')

        log.debug("Compliance category list from {} :: :: {}".format(self.cat.server_properties['license']['type'],
                                                                     compliance.get_category_type_list()))

        ComplianceConst.POLICY_COMPLIANCE_LIST.sort()
        log.debug("Compliance Constant :: :: {}".format(ComplianceConst.POLICY_COMPLIANCE_LIST))
        list = set(compliance.get_category_type_list())
        log.debug("Compliance Constant :: {}".format(list))

        log.debug("license :: {}".format(self.cat.server_properties['license']['type']))
        if self.cat.server_properties['license']['type'] == 'professional':
            log.debug("Compliance Constant {}".format(set(compliance.get_category_type_list())))
            log.debug("Compliance Constant List {}".format(set(ComplianceConst.POLICY_COMPLIANCE_LIST_PRO)))
            assert set(compliance.get_category_type_list()) == set(ComplianceConst.POLICY_COMPLIANCE_LIST_PRO), \
                'Expected list does not match the present list'
        else:
            assert set(compliance.get_category_type_list()) == set(ComplianceConst.POLICY_COMPLIANCE_LIST), \
            'Expected list does not match the present list'

        SideNav().click_by_link_text(Nessus.SideNavResources.POLICIES)

    @pytest.mark.xfail(reason="'TNS BlueCoat ProxySG Benchmark' compliance type is not present under 'BlueCoat ProxySG'"
                              "compliance category.")
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.COMPLIANCE_AUDIT, API.Permissions.Types.SCANNER)],
                             indirect=True)
    def test_policy_compliance_auditing_creation(self, create_policy):
        """
        NQA-1066-Automation tests for Policies-Scanner Creation
        1. Navigate to Policies from Side Nav > Resources
        2. Click on new policy button
        3. Select Policy Compliance Auditing
        4. Enter valid values under General and Credentials tab
        5. Save the policy
        6. Verify policy is listed under Policies list
        """
        new_policy = NewPolicyForm()
        new_policy.save_button.click()

        credentials = Password(host_type=API.Credentials.Host.Types.SSH)
        credentials.fill_password_ssh_form(username='admin', password='admin')

        compliance = TNSBlueCoatProxySGBenchmark()
        bluecoat_proxysg_data = {'primary_gateway': '172.26.17.225', 'primary_dns_server': '172.26.17.225',
                                 'alternate_dns_server': '172.26.17.225', 'adn_primary_manager': 'admin',
                                 'syslog_server': '172.26.17.225', 'internal_networks': '172.26.17.225',
                                 'snmp_community': 'snmp write only'}
        LoadingCircle(WAIT_NORMAL)
        compliance.js_scroll_into_view(new_policy.save_button)
        compliance.fill_compliance_form(**bluecoat_proxysg_data)

        new_policy.js_scroll_into_view(new_policy.save_button)
        new_policy.save_button.click()
        assert create_policy in PolicyList().get_all_policies(), 'Policy was not created successfully'
