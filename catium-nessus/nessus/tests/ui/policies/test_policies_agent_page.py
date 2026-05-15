"""
Nessus test cases related to Agent main page under New Policy.

:copyright: Tenable Network Security, 2018
:creation date: June 07, 2018
:last_modified: Dec 19, 2024
:author: @kpanchal, @mdabra
"""
from random import randint

import pytest

from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.lib.const import API, Nessus
from nessus.lib.message.messages import Messages
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.policies.new_policy_form import NewPolicyForm
from nessus.pageobjects.policies.policies_page import PoliciesPage, PolicyType, PolicyList
from nessus.pageobjects.policies.policy_basic_settings_page import PolicySettings, DiscoverySetting, \
    AssessmentSetting, ReportSetting
from nessus.pageobjects.scans.new_scan_form import ScanType
from nessus.pageobjects.scans.scan_basic_settings_page import ScanSettings
from nessus.pageobjects.scap.scap_page import ScapAndOvalForm

scap_and_oval_information = [{'count_of_forms': 1, 'form_type': API.Scap.Types.LINUX_OVAL,
                              'form_details': [{'definition_file_name': 'U_RedHat_6_V1R9_STIG_OVAL.zip',
                                                'definition_file_path': 'nessus/tests/ui/scan/test_data/'}]}]


@pytest.mark.policies_pipeline_2
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestAgentPolicyMainPage:
    """
    This class covers agent policy main page creation and editing related test cases.

    NQA-1266: Automation tests for creation and editing of Policies – Agent templates.
    """

    def test_visibility_of_elements_in_agent_template_page(self):
        """
        1. Verify that “/scans/policies/new” URL will be navigated to policy template page and will consist of agent tab
        2. Verify that on clicking the agent tab, five templates list will be present (Advanced agent San, Basic agent
        Scan, Malware Scan, Policy Compliance Auditing, SCAP and OVAL agent Auditing).
        """
        policy_page = PoliciesPage()
        policy_page.open()
        policy_page.new_policy_button.click()

        assert "/scans/policies/new" in get_driver_no_init().current_url, \
            "The page is not navigated to policy template page after clicking on 'New Policy' button."

        policy_type = PolicyType()

        assert policy_type.agent.is_displayed(), "'Agent' tab is not displayed in policy template page."

        policy_type.agent.click()
        scan_type = ScanType()
        agent_template_types = scan_type.get_all_scan_templates(scan_type=API.Permissions.Types.AGENT)

        listed_agent_templates = [Nessus.TemplateNames.ADVANCED_AGENT, Nessus.TemplateNames.BASIC_AGENT,
                                  Nessus.TemplateNames.MALWARE, Nessus.TemplateNames.COMPLIANCE_AUDIT,
                                  Nessus.TemplateNames.SCAP_OVAL_AGENT]

        for agent_template_type in listed_agent_templates:
            assert agent_template_type in agent_template_types, \
                "'%s' is not visible on agent template page.'" % agent_template_type

    @pytest.mark.parametrize("create_policies", [
        {'template_name': Nessus.TemplateNames.ADVANCED_AGENT, 'type': API.Permissions.Types.AGENT},
        {'template_name': Nessus.TemplateNames.BASIC_AGENT, 'type': API.Permissions.Types.AGENT},
        {'template_name': Nessus.TemplateNames.MALWARE, 'type': API.Permissions.Types.AGENT},
        {'template_name': Nessus.TemplateNames.COMPLIANCE_AUDIT, 'type': API.Permissions.Types.AGENT},
        {'template_name': Nessus.TemplateNames.SCAP_OVAL_AGENT, 'type': API.Permissions.Types.AGENT}])
    def test_agent_form_with_blank_policy_name(self, create_policies):
        """
        3. Verify that on clicking every template, form page will be displayed and each template has a required name
        field.
        4. Verify that on saving the policy without entering name field, error will be thrown “Error: Name is required.”
        """
        policy_page = PoliciesPage()
        policy_page.open()
        policy_page.new_policy_button.click()

        policy_type = PolicyType()
        policy_type.agent.click()
        policy_type.click_by_policy(policy_text=create_policies['template_name'])

        policy_form = NewPolicyForm()

        assert policy_form.name_field.is_displayed() and policy_form.name_field.get_attribute('aria-required'), \
            'Required name field is not displayed.'

        policy_form.add_policy(policy_name='', policy_description="Creating a new policy for {}.".
                               format(create_policies['template_name']))
        policy_form.save_button.click()

        assert Notifications().errors[-1] == Messages.NotificationMessages.Agent.required_name, \
            'Error notification for Blank name is missing.'

        policy_form.back_to_policies.click()

    @pytest.mark.parametrize("create_policy", [
        (Nessus.TemplateNames.ADVANCED_AGENT, Nessus.Scan.ScanTemplateTabs.AGENT_TAB),
        (Nessus.TemplateNames.BASIC_AGENT, Nessus.Scan.ScanTemplateTabs.AGENT_TAB),
        (Nessus.TemplateNames.MALWARE, Nessus.Scan.ScanTemplateTabs.AGENT_TAB),
        (Nessus.TemplateNames.COMPLIANCE_AUDIT, Nessus.Scan.ScanTemplateTabs.AGENT_TAB),
        (Nessus.TemplateNames.SCAP_OVAL_AGENT, Nessus.Scan.ScanTemplateTabs.AGENT_TAB)], indirect=True)
    @pytest.mark.parametrize('test_data', scap_and_oval_information)
    def test_notification_after_edit_the_policy(self, create_policy, test_data):
        """
        5. Click on created agent policy, change the name and save the policy, policy must be edited successfully.
        """
        policy_name = create_policy
        policy_form = NewPolicyForm()

        if policy_name.split('-')[0] == Nessus.TemplateNames.SCAP_OVAL_AGENT:
            scap_page = ScapAndOvalForm()
            scap_page.open_form_and_fill_details(form_information=[test_data])[0].get(test_data.get('form_type'))

        policy_form.save_button.click()
        notification = Notifications()

        assert notification.successes[-1] == Messages.NotificationMessages.Policies.policy_saved, \
            'Success notification is missing after saving the policy.'

        policy_list = PolicyList()
        policy_list.click_on_policy(policy_name=policy_name)
        policy_form.add_policy(policy_name='Edited {}'.format(policy_name),
                               policy_description='Edited new policy for {}.'.format(policy_name.split('-')[0]))
        policy_form.save_button.click()

        assert notification.successes[-1] == Messages.NotificationMessages.Policies.policy_saved, \
            'Success notification is missing after editing the policy.'

        policy_form.back_to_policies.click()
        wait(lambda: PoliciesPage().is_element_present("policies_searchbox"))
        policy_list.delete_policy(policy_name='Edited {}'.format(policy_name))

    @pytest.mark.parametrize("create_policy", [
        (Nessus.TemplateNames.SCAP_OVAL_AGENT, Nessus.Scan.ScanTemplateTabs.AGENT_TAB)], indirect=True)
    def test_scap_and_oval_agent_form(self, create_policy):
        """
        6. Click on SCAP and Oval Agent Auditing template and provide the name, click on save button, verify that the
        error will be thrown “Error: SCAP content must be added to this policy.”
        """
        policy_form = NewPolicyForm()
        policy_form.save_button.click()

        assert Notifications().errors[-1] == Messages.NotificationMessages.Agent.invalid_content, \
            'Error notification for SCAP content is missing.'

        assert policy_form.scap.is_displayed(), "'SCAP' tab is not visible on 'SCAP and Oval Agent Auditing' template."

        policy_form.back_to_policies.click()

    @pytest.mark.parametrize("create_policy", [
        (Nessus.TemplateNames.ADVANCED_AGENT, Nessus.Scan.ScanTemplateTabs.AGENT_TAB),
        (Nessus.TemplateNames.BASIC_AGENT, Nessus.Scan.ScanTemplateTabs.AGENT_TAB),
        (Nessus.TemplateNames.MALWARE, Nessus.Scan.ScanTemplateTabs.AGENT_TAB),
        (Nessus.TemplateNames.COMPLIANCE_AUDIT, Nessus.Scan.ScanTemplateTabs.AGENT_TAB),
        (Nessus.TemplateNames.SCAP_OVAL_AGENT, Nessus.Scan.ScanTemplateTabs.AGENT_TAB)], indirect=True)
    def test_save_cancel_button_on_all_agent_templates(self, create_policy):
        """
        7. Verify that on clicking any template, policy form page will open and it will have ’Save’ and ‘Cancel’ button
        8. Verify that Clicking on ‘Cancel’ button present on form page will re-direct to url /scans/policies’
        without saving any data.
        """
        policy_name = create_policy
        policy_form = NewPolicyForm()

        assert all([policy_form.save_button.is_displayed(), policy_form.cancel_button.is_displayed()]), \
            "'Save' and 'Cancel' buttons are not visible on '%s' template." % policy_name.split('-')[0]

        policy_form.cancel_button.click()

        assert "/scans/policies" in get_driver_no_init().current_url, \
            "New Policy form page is not re-direct to 'Policies' page after clicking on 'Cancel' button."

        policy_list = PolicyList()

        assert policy_name not in policy_list.get_all_policies(), "Policy form is saved after clicking on " \
                                                                  "'Cancel' button."

    @pytest.mark.parametrize("create_policy", [
        (Nessus.TemplateNames.ADVANCED_AGENT, Nessus.Scan.ScanTemplateTabs.AGENT_TAB),
        (Nessus.TemplateNames.BASIC_AGENT, Nessus.Scan.ScanTemplateTabs.AGENT_TAB),
        (Nessus.TemplateNames.MALWARE, Nessus.Scan.ScanTemplateTabs.AGENT_TAB),
        (Nessus.TemplateNames.COMPLIANCE_AUDIT, Nessus.Scan.ScanTemplateTabs.AGENT_TAB),
        (Nessus.TemplateNames.SCAP_OVAL_AGENT, Nessus.Scan.ScanTemplateTabs.AGENT_TAB)], indirect=True)
    @pytest.mark.parametrize('test_data', scap_and_oval_information)
    def test_created_policy_with_basic_settings(self, create_policy, test_data):
        """
        pre-requisite: Create a new policy

        1. Edit created policy with 'Basic' settings
            1. Edit the policy name
            2. Hit save and verify success notification
            3. Get back to above edited changes and verify changes retained its values.
        """
        policy_name = create_policy
        policy_form = NewPolicyForm()

        if policy_name.split('-')[0] == Nessus.TemplateNames.SCAP_OVAL_AGENT:
            scap_page = ScapAndOvalForm()
            scap_page.open_form_and_fill_details(form_information=[test_data])[0].get(test_data.get('form_type'))

        policy_form.save_button.click()
        notification = Notifications()

        assert notification.successes[-1] == Messages.NotificationMessages.Policies.policy_saved, \
            'Success notification is missing after saving the policy.'

        policy_form_data = {'policy_name': 'Edited {}'.format(policy_name),
                            'policy_description': 'Edited new policy for {}.'.format(policy_name.split('-')[0])}

        policy_list = PolicyList()
        policy_list.click_on_policy(policy_name=policy_name)
        policy_form.add_policy(**policy_form_data)
        policy_form.save_button.click()

        assert notification.successes[-1] == Messages.NotificationMessages.Policies.policy_saved, \
            'Success notification is missing after saving the policy.'

        policy_form.back_to_policies.click()
        policy_page = PoliciesPage()
        wait(lambda: policy_page.is_element_present("policies_searchbox"))
        policy_list.click_on_policy(policy_name=policy_form_data['policy_name'])

        assert policy_form.get_policy_form_data() == policy_form_data, 'Edited data and saved data are different.'

        policy_form.back_to_policies.click()
        wait(lambda: policy_page.is_element_present("policies_searchbox"))
        policy_list.delete_policy(policy_name='Edited {}'.format(policy_name))

    @pytest.mark.parametrize("create_policy", [
        (Nessus.TemplateNames.ADVANCED_AGENT, Nessus.Scan.ScanTemplateTabs.AGENT_TAB),
        (Nessus.TemplateNames.BASIC_AGENT, Nessus.Scan.ScanTemplateTabs.AGENT_TAB),
        (Nessus.TemplateNames.MALWARE, Nessus.Scan.ScanTemplateTabs.AGENT_TAB),
        (Nessus.TemplateNames.COMPLIANCE_AUDIT, Nessus.Scan.ScanTemplateTabs.AGENT_TAB),
        (Nessus.TemplateNames.SCAP_OVAL_AGENT, Nessus.Scan.ScanTemplateTabs.AGENT_TAB)], indirect=True)
    @pytest.mark.parametrize("wmi, ssh", [(True, True), (True, False), (False, True), (False, False)])
    @pytest.mark.parametrize('test_data', scap_and_oval_information)
    def test_created_policy_with_discovery_settings(self, create_policy, wmi, ssh, test_data):
        """
        2. Edit created policy with 'Discovery' settings
            1. Edit the policy with below configurations
            2. Uncheck 'WMI (netstat)' under 'Local Port Enumerators'
            3. Hit save and verify success notification
            4. Get back to above edited changes and verify changes retained its values.
        """
        policy_name = create_policy
        policy_form = NewPolicyForm()

        if policy_name.split('-')[0] == Nessus.TemplateNames.SCAP_OVAL_AGENT:
            scap_page = ScapAndOvalForm()
            scap_page.open_form_and_fill_details(form_information=[test_data])[0].get(test_data.get('form_type'))

        policy_form.save_button.click()
        notification = Notifications()

        assert notification.successes[-1] == Messages.NotificationMessages.Policies.policy_saved, \
            'Success notification is missing after saving the policy.'

        policy_form_data = {'policy_name': 'Edited {}'.format(policy_name),
                            'policy_description': 'Edited new policy for {}.'.format(policy_name.split('-')[0])}

        policy_list = PolicyList()
        policy_list.click_on_policy(policy_name=policy_name)
        policy_form.add_policy(**policy_form_data)

        policy_settings = PolicySettings()
        policy_settings.click_by_link_text(setting_value=API.PoliciesSettings.SettingsTypes.DISCOVERY)

        discovery_setting = DiscoverySetting()
        discovery_setting.wmi_netstat.set_checked(wmi)
        discovery_setting.ssh_netstat.set_checked(ssh)
        policy_form.save_button.click()

        assert notification.successes[-1] == Messages.NotificationMessages.Policies.policy_saved, \
            'Success notification is missing after saving the policy.'

        policy_form.back_to_policies.click()
        policy_page = PoliciesPage()
        wait(lambda: policy_page.is_element_present("policies_searchbox"))
        policy_list.click_on_policy(policy_name=policy_form_data['policy_name'])

        assert policy_form.get_policy_form_data() == policy_form_data, 'Edited data and saved data are different.'

        policy_settings.click_by_link_text(setting_value=API.PoliciesSettings.SettingsTypes.DISCOVERY)

        assert discovery_setting.wmi_netstat.is_selected() == wmi, \
            "Unable to uncheck 'WMI (netstat)' under Local Port Enumerators."

        assert discovery_setting.ssh_netstat.is_selected() == ssh, \
            "Unable to uncheck 'SSH (netstat)' under Local Port Enumerators."

        policy_form.back_to_policies.click()
        wait(lambda: policy_page.is_element_present("policies_searchbox"))
        policy_list.delete_policy(policy_name='Edited {}'.format(policy_name))

    @pytest.mark.parametrize("create_policy", [
        (Nessus.TemplateNames.ADVANCED_AGENT, Nessus.Scan.ScanTemplateTabs.AGENT_TAB),
        (Nessus.TemplateNames.BASIC_AGENT, Nessus.Scan.ScanTemplateTabs.AGENT_TAB)], indirect=True)
    @pytest.mark.parametrize("normal_accuracy, perform_tests", [
        (True, True), (True, False), (False, True), (False, False)])
    @pytest.mark.parametrize("smb_domain", [False, True])
    @pytest.mark.parametrize("scan_for_malware", [True, False])
    def test_advanced_scan_policy_with_assessment_settings(self, create_policy, normal_accuracy, perform_tests,
                                                           smb_domain, scan_for_malware):
        """
        3. Edit created policy with 'Assessment' settings
            1. Edit the policy with below configurations
            2. Select a value greater than 0 for 'Antivirus definition grace period (in days)' drop-down under 'General'
            3. Uncheck 'Request information about the SMB Domain' under 'General Settings' in 'windows'
            4. Toggle 'Scan for malware' and uncheck 'Disable DNS resolution' under general settings under 'Malware'
            5. Hit save and verify success notification
            6. Get back to edited changes and verify changes retained its values.
        """
        grace_period_day = randint(1, 7)

        policy_name = create_policy
        policy_form = NewPolicyForm()
        policy_form.save_button.click()
        notification = Notifications()

        assert notification.successes[-1] == Messages.NotificationMessages.Policies.policy_saved, \
            'Success notification is missing after saving the policy.'

        policy_form_data = {'policy_name': 'Edited {}'.format(policy_name),
                            'policy_description': 'Edited new policy for {}.'.format(policy_name.split('-')[0])}

        policy_list = PolicyList()
        policy_list.click_on_policy(policy_name=policy_name)
        policy_form.add_policy(**policy_form_data)

        policy_settings = PolicySettings()
        policy_settings.click_by_link_text(setting_value=API.PoliciesSettings.SettingsTypes.ASSESSMENT)
        assessment_setting = AssessmentSetting()

        scan_settings = ScanSettings()

        if policy_name.split('-')[0] == Nessus.TemplateNames.BASIC_AGENT:
            assessment_setting.scan_type.select_by_visible_text('Custom')
            scan_settings.click_link_inside_link(setting_value=API.PoliciesSettings.SettingsTypes.ASSESSMENT,
                                                 link_text=API.PoliciesSettings.SettingsTypes.Assessment.GENERAL)

        assessment_setting.report_paranoia.set_checked(normal_accuracy)
        assessment_setting.perform_test.set_checked(perform_tests)
        assessment_setting.antivirus.select_by_visible_text('%s' % grace_period_day)

        scan_settings.click_link_inside_link(setting_value=API.PoliciesSettings.SettingsTypes.ASSESSMENT,
                                             link_text=API.PoliciesSettings.SettingsTypes.Assessment.WINDOWS)
        assessment_setting.request_windows_smb_domain.set_checked(smb_domain)

        if policy_name.split('-')[0] != Nessus.TemplateNames.BASIC_AGENT:
            scan_settings.click_link_inside_link(setting_value=API.PoliciesSettings.SettingsTypes.ASSESSMENT,
                                                 link_text=API.PoliciesSettings.SettingsTypes.Assessment.MALWARE)
            assessment_setting.scan_for_malware.set_toggle(scan_for_malware)

        scan_settings.click_link_inside_link(setting_value=API.PoliciesSettings.SettingsTypes.ASSESSMENT,
                                             link_text=API.PoliciesSettings.SettingsTypes.Assessment.GENERAL)
        policy_form.save_button.click()

        assert notification.successes[-1] == Messages.NotificationMessages.Policies.policy_saved, \
            'Success notification is missing after saving the policy.'

        policy_form.back_to_policies.click()
        policy_page = PoliciesPage()
        wait(lambda: policy_page.is_element_present("policies_searchbox"))
        policy_list.click_on_policy(policy_name=policy_form_data['policy_name'])

        assert policy_form.get_policy_form_data() == policy_form_data, 'Edited data and saved data are different.'

        policy_settings.click_by_link_text(setting_value=API.PoliciesSettings.SettingsTypes.ASSESSMENT)

        if policy_name.split('-')[0] == Nessus.TemplateNames.BASIC_AGENT:
            assessment_setting.scan_type.select_by_visible_text('Custom')
            scan_settings.click_link_inside_link(setting_value=API.PoliciesSettings.SettingsTypes.ASSESSMENT,
                                                 link_text=API.PoliciesSettings.SettingsTypes.Assessment.GENERAL)

        assert assessment_setting.report_paranoia.is_selected() == normal_accuracy, \
            "Unable to check 'Override normal accuracy' under Accuracy."

        assert assessment_setting.perform_test.is_selected() == perform_tests, \
            "Unable to check 'Perform thorough tests' under Accuracy."

        assert int(assessment_setting.antivirus.get_value_selected()) == grace_period_day, \
            'Selected grace period days and saved grace period days are different.'

        scan_settings.click_link_inside_link(setting_value=API.PoliciesSettings.SettingsTypes.ASSESSMENT,
                                             link_text=API.PoliciesSettings.SettingsTypes.Assessment.WINDOWS)
        assert assessment_setting.request_windows_smb_domain.is_selected() == smb_domain, \
            "Unable to check 'Request information about the SMB Domain' under General Settings in Windows."

        if policy_name.split('-')[0] != Nessus.TemplateNames.BASIC_AGENT:
            scan_settings.click_link_inside_link(setting_value=API.PoliciesSettings.SettingsTypes.ASSESSMENT,
                                                 link_text=API.PoliciesSettings.SettingsTypes.Assessment.MALWARE)
            assert assessment_setting.scan_for_malware.is_selected() == scan_for_malware, \
                "Unable to toggle on 'Scan for malware' under Malware Settings in Malware."

        policy_form.back_to_policies.click()
        wait(lambda: policy_page.is_element_present("policies_searchbox"))
        policy_list.delete_policy(policy_name='Edited {}'.format(policy_name))

    @pytest.mark.parametrize("create_policy", [
        (Nessus.TemplateNames.MALWARE, Nessus.Scan.ScanTemplateTabs.AGENT_TAB)], indirect=True)
    @pytest.mark.parametrize("normal_accuracy, perform_tests", [
        (True, True), (True, False), (False, True), (False, False)])
    @pytest.mark.parametrize("scan_for_malware", [True, False])
    def test_malware_scan_policy_with_assessment_settings(self, create_policy, normal_accuracy, perform_tests,
                                                          scan_for_malware):
        """
        3. Edit created policy with 'Assessment' settings
            1. Edit the policy with below configurations
            2. Select a value greater than 0 for 'Antivirus definition grace period (in days)' drop-down under 'General'
            3. Uncheck 'Request information about the SMB Domain' under 'General Settings' in 'windows'
            4. Toggle 'Scan for malware' and uncheck 'Disable DNS resolution' under general settings under 'Malware'
            5. Hit save and verify success notification
            6. Get back to edited changes and verify changes retained its values.
        """
        policy_name = create_policy
        policy_form = NewPolicyForm()
        policy_form.save_button.click()
        notification = Notifications()

        assert notification.successes[-1] == Messages.NotificationMessages.Policies.policy_saved, \
            'Success notification is missing after saving the policy.'

        policy_form_data = {'policy_name': 'Edited {}'.format(policy_name),
                            'policy_description': 'Edited new policy for {}.'.format(policy_name.split('-')[0])}

        policy_list = PolicyList()
        policy_list.click_on_policy(policy_name=policy_name)
        policy_form.add_policy(**policy_form_data)

        policy_settings = PolicySettings()
        policy_settings.click_by_link_text(setting_value=API.PoliciesSettings.SettingsTypes.ASSESSMENT)

        assessment_setting = AssessmentSetting()
        assessment_setting.report_paranoia.set_checked(normal_accuracy)
        assessment_setting.perform_test.set_checked(perform_tests)

        scan_settings = ScanSettings()
        scan_settings.click_link_inside_link(setting_value=API.PoliciesSettings.SettingsTypes.ASSESSMENT,
                                             link_text=API.PoliciesSettings.SettingsTypes.Assessment.MALWARE)
        assessment_setting.scan_for_malware.set_toggle(scan_for_malware)

        scan_settings.click_link_inside_link(setting_value=API.PoliciesSettings.SettingsTypes.ASSESSMENT,
                                             link_text=API.PoliciesSettings.SettingsTypes.Assessment.GENERAL)
        policy_form.save_button.click()

        assert notification.successes[-1] == Messages.NotificationMessages.Policies.policy_saved, \
            'Success notification is missing after saving the policy.'

        policy_form.back_to_policies.click()
        policy_page = PoliciesPage()
        wait(lambda: policy_page.is_element_present("policies_searchbox"))
        policy_list.click_on_policy(policy_name=policy_form_data['policy_name'])

        assert policy_form.get_policy_form_data() == policy_form_data, 'Edited data and saved data are different.'

        policy_settings.click_by_link_text(setting_value=API.PoliciesSettings.SettingsTypes.ASSESSMENT)

        assert assessment_setting.report_paranoia.is_selected() == normal_accuracy, \
            "Unable to check 'Override normal accuracy' under Accuracy."

        assert assessment_setting.perform_test.is_selected() == perform_tests, \
            "Unable to check 'Perform thorough tests' under Accuracy."

        scan_settings.click_link_inside_link(setting_value=API.PoliciesSettings.SettingsTypes.ASSESSMENT,
                                             link_text=API.PoliciesSettings.SettingsTypes.Assessment.MALWARE)
        assert assessment_setting.scan_for_malware.is_selected() == scan_for_malware, \
            "Unable to toggle on 'Scan for malware' under Malware Settings in Malware."

        policy_form.back_to_policies.click()
        wait(lambda: policy_page.is_element_present("policies_searchbox"))
        policy_list.delete_policy(policy_name='Edited {}'.format(policy_name))

    @pytest.mark.parametrize("create_policy", [
        (Nessus.TemplateNames.ADVANCED_AGENT, Nessus.Scan.ScanTemplateTabs.AGENT_TAB),
        (Nessus.TemplateNames.BASIC_AGENT, Nessus.Scan.ScanTemplateTabs.AGENT_TAB),
        (Nessus.TemplateNames.MALWARE, Nessus.Scan.ScanTemplateTabs.AGENT_TAB),
        (Nessus.TemplateNames.COMPLIANCE_AUDIT, Nessus.Scan.ScanTemplateTabs.AGENT_TAB),
        (Nessus.TemplateNames.SCAP_OVAL_AGENT, Nessus.Scan.ScanTemplateTabs.AGENT_TAB)], indirect=True)
    @pytest.mark.parametrize("allow_edit_scan_results", [False, True])
    @pytest.mark.parametrize('test_data', scap_and_oval_information)
    def test_created_policy_with_report_settings(self, create_policy, allow_edit_scan_results, test_data):
        """
        4. Edit created policy with 'Reports' settings
            1. Edit the policy with below configurations
            2. Uncheck 'Allow users to edit scan results' and check 'Display unreachable hosts' under 'Output' in
            'Reports'
            3. Hit save and verify success notification
            4. Get back to edited changes and verify changes retained its values.
        """
        policy_name = create_policy
        policy_form = NewPolicyForm()

        if policy_name.split('-')[0] == Nessus.TemplateNames.SCAP_OVAL_AGENT:
            scap_page = ScapAndOvalForm()
            scap_page.open_form_and_fill_details(form_information=[test_data])[0].get(test_data.get('form_type'))

        policy_form.save_button.click()
        notification = Notifications()

        assert notification.successes[-1] == Messages.NotificationMessages.Policies.policy_saved, \
            'Success notification is missing after saving the policy.'

        policy_form_data = {'policy_name': 'Edited {}'.format(policy_name),
                            'policy_description': 'Edited new policy for {}.'.format(policy_name.split('-')[0])}

        policy_list = PolicyList()
        policy_list.click_on_policy(policy_name=policy_name)
        policy_form.add_policy(**policy_form_data)

        policy_settings = PolicySettings()
        policy_settings.click_by_link_text(setting_value=API.PoliciesSettings.SettingsTypes.REPORT)

        report_setting = ReportSetting()
        report_setting.allow_users_edit_scan.set_checked(allow_edit_scan_results)
        policy_form.save_button.click()

        assert notification.successes[-1] == Messages.NotificationMessages.Policies.policy_saved, \
            'Success notification is missing after saving the policy.'

        policy_form.back_to_policies.click()
        policy_page = PoliciesPage()
        wait(lambda: policy_page.is_element_present("policies_searchbox"))
        policy_list.click_on_policy(policy_name=policy_form_data['policy_name'])

        assert policy_form.get_policy_form_data() == policy_form_data, 'Edited data and saved data are different.'

        policy_settings.click_by_link_text(setting_value=API.PoliciesSettings.SettingsTypes.REPORT)

        assert report_setting.allow_users_edit_scan.is_selected() == allow_edit_scan_results, \
            "Unable to check 'Allow users to edit scan results' under Output."

        policy_form.back_to_policies.click()
        wait(lambda: policy_page.is_element_present("policies_searchbox"))
        policy_list.delete_policy(policy_name='Edited {}'.format(policy_name))

    @pytest.mark.parametrize("create_policy", [
        (Nessus.TemplateNames.ADVANCED_AGENT, Nessus.Scan.ScanTemplateTabs.AGENT_TAB),
        (Nessus.TemplateNames.BASIC_AGENT, Nessus.Scan.ScanTemplateTabs.AGENT_TAB),
        (Nessus.TemplateNames.MALWARE, Nessus.Scan.ScanTemplateTabs.AGENT_TAB),
        (Nessus.TemplateNames.COMPLIANCE_AUDIT, Nessus.Scan.ScanTemplateTabs.AGENT_TAB),
        (Nessus.TemplateNames.SCAP_OVAL_AGENT, Nessus.Scan.ScanTemplateTabs.AGENT_TAB)], indirect=True)
    @pytest.mark.parametrize("log_scan_details, enable_plugin_debugging", [
        (True, True), (True, False), (False, True), (False, False)])
    @pytest.mark.parametrize('test_data', scap_and_oval_information)
    def test_created_policy_with_advanced_settings(self, create_policy, log_scan_details, enable_plugin_debugging,
                                                   test_data):
        """
        5. Edit created policy with 'Advanced' settings
            1. Edit the policy with below configurations
            2. check 'Log scan details' under 'Debug settings' in 'Advanced'
            3. Hit save and verify success notification
            4. Get back to edited changes and verify changes retained its values.
        """
        policy_name = create_policy
        policy_form = NewPolicyForm()

        if policy_name.split('-')[0] == Nessus.TemplateNames.SCAP_OVAL_AGENT:
            scap_page = ScapAndOvalForm()
            scap_page.open_form_and_fill_details(form_information=[test_data])[0].get(test_data.get('form_type'))

        policy_form.save_button.click()
        notification = Notifications()

        assert notification.successes[-1] == Messages.NotificationMessages.Policies.policy_saved, \
            'Success notification is missing after saving the policy.'

        policy_form_data = {'policy_name': 'Edited {}'.format(policy_name),
                            'policy_description': 'Edited new policy for {}.'.format(policy_name.split('-')[0])}

        policy_list = PolicyList()
        policy_list.click_on_policy(policy_name=policy_name)
        policy_form.add_policy(**policy_form_data)

        policy_settings = PolicySettings()
        policy_settings.click_by_link_text(setting_value=API.PoliciesSettings.SettingsTypes.ADVANCED)

        policy_settings.log_scan_details.set_checked(log_scan_details)
        policy_settings.enable_plugin_debugging.set_checked(enable_plugin_debugging)
        policy_form.save_button.click()

        assert notification.successes[-1] == Messages.NotificationMessages.Policies.policy_saved, \
            'Success notification is missing after saving the policy.'

        policy_form.back_to_policies.click()
        policy_page = PoliciesPage()
        wait(lambda: policy_page.is_element_present("policies_searchbox"))
        policy_list.click_on_policy(policy_name=policy_form_data['policy_name'])

        assert policy_form.get_policy_form_data() == policy_form_data, 'Edited data and saved data are different.'

        policy_settings.click_by_link_text(setting_value=API.PoliciesSettings.SettingsTypes.ADVANCED)

        assert policy_settings.log_scan_details.is_selected() == log_scan_details, \
            "Unable to check 'Log scan details' under Debug Settings."

        assert policy_settings.enable_plugin_debugging.is_selected() == enable_plugin_debugging, \
            "Unable to check 'Enable plugin debugging' under Debug Settings."

        policy_form.back_to_policies.click()
        wait(lambda: policy_page.is_element_present("policies_searchbox"))
        policy_list.delete_policy(policy_name='Edited {}'.format(policy_name))

    def test_agent_tab_scan_template_categories_for_new_policy(self):
        """
        NES-9857 - UI automation for Scan Library Org NES-9820

        Scenarios:
            [x] Verify that scan templates under agent tab on create policy page are organized in
            two categories "Discovery" and "Vulnerabilities".

        Steps:
        1. Login to Nessus.
        2. Click on "Create New Policy" and go to "Agent" tab.
        3. Verify Scan templates are organized in two categories.
        4. Verify Scan template categories are "Discovery" and "Vulnerabilities".
        5. Verify scan templates list for both scan category.
        6. Verify "Vulnerabilities" category has "Basic Agent Scan" and "Advanced Agent Scan" at first two places.
        7. Logout from Nessus.
        """
        policy_page = PoliciesPage()
        scan_type = ScanType()
        policy_page.open()
        wait(lambda: policy_page.is_element_present('policies_searchbox') or policy_page.is_element_present(
            'create_a_new_policy_link'), waiting_for='Policy page to loaded properly')

        policy_page.new_policy_button.click()
        wait(lambda: scan_type.is_element_present('scanner'), waiting_for='Scan templates to load properly')

        scan_type.select_scan_type(type_of_scan=Nessus.Scan.ScanTemplateTabs.AGENT_TAB)
        category_names_agents = scan_type.get_all_scan_categories_names()

        # Verifying scan templates categories
        assert set(category_names_agents) == set(Nessus.TemplateCategories.AGENT_TEMPLATE_CATEGORIES_LIST), \
            "Scan templates categories are not matching in agent tab"

        agent_vulnerabilities_scan_list = scan_type.get_scan_templates_list_for_given_category(
            category_name=Nessus.TemplateCategories.VULNERABILITIES,
            scan_type=Nessus.Scan.ScanTemplateTabs.AGENT_TAB.lower())

        # Verifying scan templates list for "Vulnerabilities"
        assert set(agent_vulnerabilities_scan_list) == set(Nessus.TemplateNames.AGENT_VULNERABILITIES_TEMPLATE_LIST), \
            "Scan template list for 'Vulnerabilities' is not matching"

        # Verifying scan templates list for "Compliance"
        assert set(scan_type.get_scan_templates_list_for_given_category(
            category_name=Nessus.TemplateCategories.COMPLIANCE,
            scan_type=Nessus.Scan.ScanTemplateTabs.AGENT_TAB.lower())) == set(
            Nessus.TemplateNames.AGENT_COMPLIANCE_TEMPLATE_LIST), "Scan template list for 'Compliance' is not matching"

        # Verify that "Vulnerabilities" category has 'Basic Agent Scan' and 'Advanced Agent Scan' at first two places.
        assert agent_vulnerabilities_scan_list[0] == Nessus.TemplateNames. \
            BASIC_AGENT and agent_vulnerabilities_scan_list[1] == Nessus.TemplateNames.ADVANCED_AGENT, \
            "First two scan templates for vulnerabilities are not 'Basic Agent Scan' and 'Advanced Agent Scan'"
