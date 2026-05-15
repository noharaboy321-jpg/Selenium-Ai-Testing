"""
Nessus policies related test cases

Test cases to verify if it is possible to create, delete
and export different types of policies available in 'Agent' tab

:copyright: Tenable Network Security, 2017
:creation date: Aug 23, 2017
:last_modified: June 24, 2020
:author: @rdutta, @smadan, @mameta, @kpanchal
"""
import pytest
from selenium.common.exceptions import NoSuchElementException

from catium.helpers.testdata import get_file_path
from catium.helpers.testdata import load_testdata
from catium.lib.const import WAIT_SHORT, WAIT_NORMAL, os
from nessus.lib.const.compliance_constants import ComplianceConst
from nessus.lib.const.constants import API, Nessus
from nessus.pageobjects.compliances.compliance_page import Compliance
from nessus.pageobjects.credentials.mobile_credential import AirWatch, AppleProfileManager, MobileIron, GoodMDM, MaaS360
from nessus.pageobjects.plugins.plugins_page import Plugin, PluginFamilyList, PluginsList
from nessus.pageobjects.policies.new_policy_form import NewPolicyForm, PolicyType
from nessus.pageobjects.policies.policies_page import PolicyList, PoliciesPage
from nessus.pageobjects.policies.policy_basic_settings_page import PolicySettings, AssessmentSetting, ReportSetting
from nessus.pageobjects.scans.new_scan_form import ScanType, NewScanForm
from nessus.pageobjects.scans.scans_page import ScansPage
from nessus.pageobjects.scap.scap_page import ScapAndOvalForm
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav


@pytest.mark.policies_pipeline_3
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestAgentPolicies:
    """Policies related test cases for Nessus Manager only"""
    credential_type = load_testdata(os.path.abspath(
        get_file_path("nessus/tests/ui/scans/test_data/credential_data.json")))

    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.COMPLIANCE_AUDIT,
                                                Nessus.Scan.ScanTemplateTabs.AGENT_TAB)], indirect=True)
    def test_agent_pci_with_compliance(self, create_policy):
        """
        Policy - Create, export and delete : NQA- 971
        1. Create a policy with random name and description
        2. Click the Compliance Tab and choose some Unix and Windows Audits
        3. Save
        4. Verify created policy exist
        5. Export the policy
        6. Delete the created policy
        """
        LoadingCircle(WAIT_SHORT)
        policy_name = create_policy

        compliance_page = Compliance()
        compliance_page.click_compliance_type(category_name=ComplianceConst.UNIX,
                                              compliance_type="CIS Amazon Linux v2.1.0 L2")
        LoadingCircle(WAIT_SHORT)
        compliance_page.click_compliance_type(category_name=ComplianceConst.WINDOWS, compliance_type="CIS IE 10 v1.1.0")

        NewPolicyForm().save_button.click()

        policy_list = PolicyList()
        assert policy_name in policy_list.get_all_policies(), 'Policy "%s" is not created successfully' % policy_name

        PoliciesPage().export_and_delete_policy(policy_name=policy_name, export_policy_popup=False)

        # Wait is required to get updated list
        LoadingCircle(WAIT_NORMAL)
        # verify above deleted policy doesn't exists anymore in policies management page
        assert policy_name not in policy_list.get_all_policies(), \
            'Policy "%s" is not deleted successfully' % policy_name

    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED_AGENT,
                                                Nessus.Scan.ScanTemplateTabs.AGENT_TAB)], indirect=True)
    def test_advanced_agent_scan_policy_with_pci_audits(self, create_policy):
        """
        Policy - Create, export and delete : NQA- 975
        1. Create a policy with random name and description
        2. On the Compliance tab, add some UNIX audits
        3. Save
        4. Export the policy
        5. Verify created policy exist
        6. Delete the created policy
        """
        LoadingCircle(WAIT_SHORT)
        policy_name = create_policy

        compliance_page = Compliance()
        compliance_page.click_compliance_type(category_name=ComplianceConst.UNIX,
                                              compliance_type='CIS CentOS 6 Server L1 v3.0.0')
        LoadingCircle(WAIT_SHORT)
        compliance_page.click_compliance_type(category_name=ComplianceConst.UNIX,
                                              compliance_type='CIS Debian Linux 7 L1 v1.0.0')
        LoadingCircle(WAIT_SHORT)
        compliance_page.click_compliance_type(category_name=ComplianceConst.UNIX,
                                              compliance_type='CIS Ubuntu Linux 16.04 LTS Workstation L2 v2.0.0')

        LoadingCircle(WAIT_SHORT)
        NewPolicyForm().save_button.click()

        policy_list = PolicyList()
        assert policy_name in policy_list.get_all_policies(), 'Policy "%s" is not created successfully' % policy_name

        PoliciesPage().export_and_delete_policy(policy_name=policy_name, export_policy_popup=False)

        # Wait is required to get updated list
        LoadingCircle(WAIT_NORMAL)
        # verify above deleted policy doesn't exists anymore in policies management page
        assert policy_name not in policy_list.get_all_policies(), \
            'Policy "%s" is not deleted successfully' % policy_name

    @pytest.mark.parametrize("create_policy", [
        (Nessus.TemplateNames.BASIC_AGENT, Nessus.Scan.ScanTemplateTabs.AGENT_TAB),  # NQA-969
        (Nessus.TemplateNames.ADVANCED_AGENT, Nessus.Scan.ScanTemplateTabs.AGENT_TAB),  # NQA-968
        (Nessus.TemplateNames.MALWARE, Nessus.Scan.ScanTemplateTabs.AGENT_TAB)], indirect=True)  # NQA-970
    def test_export_agent_policy_without_cred(self, create_policy):
        """
        Policy - Create, export and delete
        1. Create a policy with random name
        2. Verify created policy exist
        3. Export the policy
        4. Delete the created policy
        """
        policy_name = create_policy
        NewPolicyForm().save_button.click()

        policy_list = PolicyList()
        assert policy_name in policy_list.get_all_policies(), 'Policy "%s" is not created successfully' % policy_name

        PoliciesPage().export_and_delete_policy(policy_name=policy_name, export_policy_popup=False)

        # Wait is required to get updated list
        LoadingCircle(WAIT_NORMAL)
        # verify above deleted policy doesn't exists anymore in policies management page
        assert policy_name not in policy_list.get_all_policies(), \
            'Policy "%s" is not deleted successfully' % policy_name

    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED_AGENT,
                                                Nessus.Scan.ScanTemplateTabs.AGENT_TAB)], indirect=True)
    def test_advance_agent_without_default(self, create_policy):
        """
        Policy - Create, export and delete an Advanced Agent Scan policy with non default options enabled NQA-973
        1. Create a policy with random name
        2. Click on ASSESSMENT tab and Choose accuracy options
        3. Click on REPORTS tab and choose reports options
        4. Save the policy
        5. Verify created policy exist
        6. Export the policy
        7. Delete policy
        """
        accuracy_option = 'Paranoid (more false alarms)'
        reports_option = 'Verbose'

        new_policy_name = create_policy
        policy_test = PolicySettings()
        policy_test.click_by_link_text(setting_value=API.PoliciesSettings.SettingsTypes.ASSESSMENT)
        AssessmentSetting().choose_accuracy_option(option_value=accuracy_option)
        policy_test.click_by_link_text(setting_value=API.PoliciesSettings.SettingsTypes.REPORT)
        ReportSetting().choose_reports_option(option_value=reports_option)
        policy_test.save_button.click()

        policy_list = PolicyList()
        assert new_policy_name in policy_list.get_all_policies(), \
            'Policy "%s" is not created successfully' % new_policy_name

        PoliciesPage().export_and_delete_policy(policy_name=new_policy_name, export_policy_popup=False)

        # Wait is required to get updated list
        LoadingCircle(WAIT_NORMAL)
        # verify above deleted policy doesn't exists anymore in policies management page
        assert new_policy_name not in policy_list.get_all_policies(), \
            'Policy "%s" is not deleted successfully' % new_policy_name

    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.SCAP_OVAL_AGENT,
                                                Nessus.Scan.ScanTemplateTabs.AGENT_TAB)], indirect=True)
    def test_scap_and_oval_agent_auditing_policy(self, create_policy):
        """
        # NQA-972 : UI - Policies - SCAP and OVAL Agent Auditing - Create, export and delete
        test to create, configure, export and delete SCAP and OVAL Agent Auditing policy
        1. Click Policy in UI
        2. Fill out Name and Description
        3. Click on SCAP tab and add the SCAP configuration files
        4. Save
        6. Delete
        """
        scap_policy_name = create_policy
        # navigate to SCAP tab and add the SCAP configuration files
        scap_page = ScapAndOvalForm()
        scap_page.open_form_and_fill_details(form_information=[
            {'count_of_forms': 1, 'form_type': API.Scap.Types.WINDOWS_SCAP, 'form_details': [
                {'version': "1.1", 'benchmark_id': "Windows_7_STIG", 'profile_id': "MAC - 1_Classified",
                 'stream_id': '1234567', 'result_type': 'Full results w/o system characteristics',
                 'definition_file_name': 'U_Windows_7_V1R27_STIG_SCAP_1-1_Benchmark.zip',
                 'definition_file_path': 'nessus/tests/api/scan/test_data/'}]}])

        scap_page.open_form_and_fill_details(form_information=[
            {'count_of_forms': 1, 'form_type': API.Scap.Types.LINUX_SCAP, 'form_details': [
                {'version': "1.1", 'benchmark_id': "RHEL_6_STIG", 'profile_id': "MAC-1_Classified",
                 'stream_id': '1234567', 'result_type': 'Full results w/o system characteristics',
                 'definition_file_name': 'U_Windows_7_V1R27_STIG_SCAP_1-1_Benchmark.zip',
                 'definition_file_path': 'nessus/tests/api/scan/test_data/'}]}])

        NewPolicyForm().save_button.click()
        # verify above created policy is exists in policies management page
        policy_list = PolicyList()
        assert scap_policy_name in policy_list.get_all_policies(), \
            'Policy "%s" is not created successfully' % scap_policy_name
        # delete above created policy
        policy_list.delete_policy(policy_name=scap_policy_name)

        # Wait is required to get updated list
        LoadingCircle(WAIT_NORMAL)
        # verify above deleted policy doesn't exists anymore in policies management page
        assert scap_policy_name not in policy_list.get_all_policies(), \
            "Policy '%s' is not deleted successfully" % scap_policy_name

    @pytest.mark.parametrize("create_user", [{'username': API.User.Users.STANDARD_USER,
                                              'password': API.Credentials.Host.SSHAuthTypes.PASSWORD,
                                              'role': API.User.Role.STANDARD, 'do_login': True}], indirect=True)
    def test_standard_user_agent_scan_policies_access(self, create_user):
        """
        # NQA-163 :	UI - Policy - Agent - templates tab
        1. Create a standard user and Log In from that user
        2. Check agent tab on policy template page
        3. Click on every template and verify policy form page opens
        4. Check agent tab on scan template page
        5. Click on every template and verify scan form page opens
        6. Delete the user created
        """
        LoadingCircle(WAIT_SHORT)
        policy_page = PoliciesPage()
        policy_page.open()
        LoadingCircle(WAIT_SHORT)

        policy_page.new_policy_button.click()
        LoadingCircle(WAIT_SHORT)
        policy_type = PolicyType()
        assert policy_type.agent.is_displayed(), "Agent Tab is not present on policy template page"

        policy_type.agent.click()
        LoadingCircle(WAIT_SHORT)
        assert policy_type.agent_policies.is_displayed(), "Unable to see policy templates for Agents"

        scan_page = ScansPage()
        policy_templates = scan_page.get_all_scan_templates(scan_type=API.Permissions.Types.AGENT)
        for template in policy_templates:
            try:
                policy_type.click_by_policy(template)
            except NoSuchElementException:
                raise AssertionError('User can not see Policy Template')
            else:
                new_policy_form = NewPolicyForm()
                LoadingCircle(WAIT_NORMAL)
                assert new_policy_form.name_field.is_displayed(), "Unable to see Policy '%s' Template Form" % template
                new_policy_form.back_to_policies.click()
                policy_type.agent.click()
                LoadingCircle(WAIT_SHORT)

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        scan_page.new_scan_button.click()

        LoadingCircle(WAIT_SHORT)
        scan_type = ScanType()
        assert scan_type.agent.is_displayed(), "Agent Tab is not present under Scan templates page"
        scan_type.agent.click()

        scan_templates = scan_page.get_all_scan_templates(scan_type=API.Permissions.Types.AGENT)
        for template in scan_templates:
            try:
                scan_type.click_by_scan(template)
            except NoSuchElementException:
                raise AssertionError('User can not see Scan Template')
            else:
                new_scan_form = NewScanForm()
                assert new_scan_form.name_field.is_displayed(), "Unable to see scan '%s' Template Form" % template
                new_scan_form.back()
                scan_type.agent.click()
                LoadingCircle(WAIT_SHORT)

    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED_AGENT,
                                                Nessus.Scan.ScanTemplateTabs.AGENT_TAB)], indirect=True)  # NQA-974
    def test_agent_advance_scan_policy_with_plugin(self, create_policy):
        """
        # NQA-974: Policy - Create, export and delete an Advanced Agent Scan
        choosing only a select number of plugins
        1. Create a policy with random name
        2. Click on Plugins tab and disable all plugins
        3. Enable one of the given plugin family
        4. Enable the given plugin of a particular plugin family
        5. Save the policy
        6. Verify if the policy is exist
        7. Export the policy
        8. Delete the policy
        """
        advance_policy_name = create_policy
        plugin_family_general = "CentOS Local Security Checks"
        plugin_family_settings = "Windows"
        plugin_name = "7-Zip Installed"

        Plugin().disable_all.click()

        plugin_family_list = PluginFamilyList()
        plugin_family_list.toggle_plugin_family(plugin_family_list=plugin_family_general)

        assert API.Status.ENABLED in plugin_family_list.get_plugin_families_status(
            plugin_family_list=plugin_family_general).values(), "plugin family status is not enabled"

        plugin_list = PluginsList()
        plugin_list.toggle_plugins(plugin_family=plugin_family_settings,
                                   plugin_name_list=[plugin_name])

        assert API.Status.ENABLED.upper() in plugin_list.get_plugins_status(
            plugin_family=plugin_family_settings, plugin_name_list=[plugin_name]).values(), \
            "plugin status is not enabled"

        NewPolicyForm().save_button.click()
        LoadingCircle(WAIT_NORMAL)

        policy_list = PolicyList()
        assert advance_policy_name in policy_list.get_all_policies(), \
            'Policy "%s" is not created successfully' % advance_policy_name
        # verify above created policy is exists in policies management page
        PoliciesPage().export_and_delete_policy(policy_name=advance_policy_name, export_policy_popup=False)

        # Wait is required to get updated list
        LoadingCircle(WAIT_NORMAL)
        # verify above deleted policy doesn't exists anymore in policies management page
        assert advance_policy_name not in policy_list.get_all_policies(), \
            'Policy "%s" is not deleted successfully' % advance_policy_name

    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.MDM_AUDIT,
                                                Nessus.Scan.ScanTemplateTabs.SCANNER_TAB)], indirect=True)
    def test_mdm_config_policy_with_compliance_and_credentials(self, create_policy):
        """
        # NQA-959 : UI - Policies - MDM Config Audit - Create, export and delete
        1. Create a policy with random name and description
        2. Add mobile(airwatch/apm/goodmdm) credentials
        3. Add Compliance audits
        4. Save
        5. Verify created policy exist
        6. Export the policy
        7. Delete the created policy
        """
        LoadingCircle(WAIT_SHORT)
        AirWatch(mobile_credential_type=API.Credentials.Mobile.AIRWATCH).fill_airwatch_form(
            **self.credential_type["air_watch_form_data"])
        AppleProfileManager(mobile_credential_type=API.Credentials.Mobile.APM).fill_apple_profile_manager_form(
            **self.credential_type["apm_form_data"])
        MobileIron(mobile_credential_type=API.Credentials.Mobile.MOBILEIRON).fill_mobileiron_form(
            **self.credential_type["mobile_iron_form_data"])

        policy_name = create_policy
        # navigate to compliance tab and select compliance value accordingly
        compliance_page = Compliance()
        compliance_page.click_compliance_type(category_name=ComplianceConst.MOBILE_DEVICE_MANAGER,
                                              compliance_type="MobileIron - DISA Samsung Android 7 with Knox 2.x v1r1")
        LoadingCircle(WAIT_SHORT)

        # save the policy
        NewPolicyForm().save_button.click()

        policy_list = PolicyList()
        assert policy_name in policy_list.get_all_policies(), 'Policy "%s" is not created successfully' % policy_name
        # verify above created policy is exists in policies management page
        PoliciesPage().export_and_delete_policy(policy_name=policy_name)

        # Wait is required to get updated list
        LoadingCircle(WAIT_NORMAL)
        # verify above deleted policy doesn't exists anymore in policies management page
        assert policy_name not in policy_list.get_all_policies(), \
            'Policy "%s" is not deleted successfully' % policy_name

    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.MOBILE_DEVICE,
                                                Nessus.Scan.ScanTemplateTabs.SCANNER_TAB)], indirect=True)
    def test_mobile_device_scan_policy(self, create_policy):
        """
        # NQA-960 : UI - Policies - Mobile Device Scan - Create, export and delete
          test to export and delete mobile device scan policy
        1. Create a policy with random name and description
        2. Add mobile credentials
        3. Save
        4. Verify created policy exist in list
        5. Export the created policy
        6. Delete the created policy
        """
        LoadingCircle(WAIT_SHORT)
        AirWatch(mobile_credential_type=API.Credentials.Mobile.AIRWATCH).fill_airwatch_form(
            **self.credential_type["air_watch_form_data"])
        AppleProfileManager(mobile_credential_type=API.Credentials.Mobile.APM).fill_apple_profile_manager_form(
            **self.credential_type["apm_form_data"])
        GoodMDM(mobile_credential_type=API.Credentials.Mobile.GOODMDM).fill_good_mdm_form(
            **self.credential_type["good_mdm_form_data"])
        MaaS360(mobile_credential_type=API.Credentials.Mobile.MAAS360).fill_maas_mobile_form(
            **self.credential_type["maas360_form_data"])
        MobileIron(mobile_credential_type=API.Credentials.Mobile.MOBILEIRON).fill_mobileiron_form(
            **self.credential_type["mobile_iron_form_data"])

        policy_name = create_policy
        NewPolicyForm().save_button.click()

        policy_list = PolicyList()
        assert policy_name in policy_list.get_all_policies(), 'Policy "%s" is not created successfully' % policy_name

        PoliciesPage().export_and_delete_policy(policy_name=policy_name)

        # Wait is required to get updated list
        LoadingCircle(WAIT_NORMAL)
        # verify above deleted policy doesn't exists anymore in policies management page
        assert policy_name not in policy_list.get_all_policies(), \
            'Policy "%s" is not deleted successfully' % policy_name
