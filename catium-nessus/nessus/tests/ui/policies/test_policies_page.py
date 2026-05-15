"""
Nessus policies related test cases

Test cases to verify if it is possible to create delete
and export different types of policies

:copyright: Tenable Network Security, 2017
:creation date: Aug 23, 2017
:last_modified: Aug 22, 2022
:author: @rdutta, @smadan, @mameta, @kpanchal, @krpatel.ctr
"""
import os
import time

import pytest
from selenium.webdriver import ChromeOptions

from catium.helpers.testdata import get_file_path, load_testdata
from catium.lib.config import Config
from catium.lib.const import WAIT_SHORT, WAIT_NORMAL, GRID_BROWSER_DOWNLOAD_PATH, TIME_THREE_SECONDS, \
    TIME_TEN_SECONDS
from catium.lib.log import create_logger
from catium.lib.util import random_name
from catium.lib.webium.controls.upload_field import UploadField
from catium.lib.webium.wait import wait
from nessus.helpers.system import is_manager
from nessus.helpers.utility import get_downloaded_files_chrome
from nessus.lib.const.compliance_constants import ComplianceConst
from nessus.lib.const.constants import API, Nessus
from nessus.lib.message.messages import Messages
from nessus.pageobjects.compliances.compliance_page import Compliance
from nessus.pageobjects.compliances.compliance_sub_categories import CISCiscoCisIosL1
from nessus.pageobjects.credentials.cloud_services import AmazonAWS, MicrosoftAzure, RackSpace, SalesForce
from nessus.pageobjects.credentials.host import Password
from nessus.pageobjects.dynamic_plugins.dynamic_plugins_page import DynamicPlugin
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.plugins.plugins_page import Plugin, PluginFamilyList, PluginsList
from nessus.pageobjects.policies.new_policy_form import NewPolicyForm, PolicyType
from nessus.pageobjects.policies.policies_page import PolicyList, PoliciesPage
from nessus.pageobjects.policies.policy_basic_settings_page import PolicySettings, AssessmentSetting, ReportSetting, \
    DiscoverySetting
from nessus.pageobjects.scans.new_scan_form import ScanTemplatePage
from nessus.pageobjects.scans.scan_basic_settings_page import BasicSetting
from nessus.pageobjects.scap.scap_page import ScapAndOvalForm
from nessus.pageobjects.shared.loading import LoadingCircle

log = create_logger()
timestamped_path = 'Download_logs_file_' + str(int(time.time()))  # use timestamp to differentiate test


@pytest.fixture()
def chrome_options():
    """Set download path for Chrome."""
    log.debug('fixture init: Override Chrome Options to support downloads')

    options = ChromeOptions()
    if Config.CAT_USE_GRID:
        log.info("Using grid")
        directory = os.path.join(GRID_BROWSER_DOWNLOAD_PATH, timestamped_path)
    else:
        directory = os.path.join(Config.CAT_LOCAL_BROWSER_DOWNLOAD_PATH, timestamped_path)
    prefs = {'download.default_directory': directory}
    options.add_experimental_option('prefs', prefs)
    return options


@pytest.mark.policies_pipeline_2
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('wait_for_plugin_families_to_be_available', 'nessus_api_login', 'login')
class TestPolicies:
    """ Policies related test cases. """
    credential_type = load_testdata(os.path.abspath(
        get_file_path("nessus/tests/ui/scans/test_data/credential_data.json")))

    @pytest.mark.parametrize("create_policy", [
        (Nessus.TemplateNames.ADVANCED, API.Credentials.Host.Types.WINDOWS),  # NQA-944
        (Nessus.TemplateNames.BASIC_NETWORK, API.Credentials.Host.Types.WINDOWS),  # NQA-952
        (Nessus.TemplateNames.AUDIT_PATCH, API.Credentials.Host.Types.SSH),  # NQA-953
        (Nessus.TemplateNames.FIND_AI, API.Credentials.Host.Types.WINDOWS),  # NQA-956
        (Nessus.TemplateNames.MALWARE, API.Credentials.Host.Types.WINDOWS),  # NQA-958
        (Nessus.TemplateNames.WEB_APP, API.Credentials.PlaintextAuthentication.HTTP)], indirect=True)
    def test_scanner_policy_with_credentials(self, create_policy):
        """
        Policy - Create, export and delete
        1. Create a policy with random name and description.
        2. Add credentials.
        3. Save.
        4. Verify created policy exist.
        5. Export the created policy.
        6. Delete the created policy.
        """
        policy_name, cred_type = create_policy
        # Fill data for selected type of credentials
        if cred_type == API.Credentials.Host.Types.WINDOWS:
            Password(host_type=API.Credentials.Host.Types.WINDOWS).fill_password_windows_form(
                **self.credential_type["windows_form_data"])
        elif cred_type == API.Credentials.Host.Types.SSH:
            Password(host_type=API.Credentials.Host.Types.SSH).fill_password_ssh_form(
                **self.credential_type["ssh_form_data"])

        NewPolicyForm().save_button.click()

        policy_list = PolicyList()
        assert policy_name in policy_list.get_all_policies(), 'Policy "%s" is not created successfully' % policy_name

        # export above created policy
        policy_list.export_policy(policy_name=policy_name)
        action_close_modal = ActionCloseModal()
        if cred_type != API.Credentials.PlaintextAuthentication.HTTP:
            action_close_modal.accept_action()

        policy_list.delete_policy(policy_name=policy_name)

        # verify above deleted policy doesn't exists anymore in policies management page
        LoadingCircle(WAIT_NORMAL)
        assert policy_name not in policy_list.get_all_policies(), \
            'Policy "%s" is not deleted successfully' % policy_name

    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.AUDIT_CLOUD,
                                                Nessus.Scan.ScanTemplateTabs.SCANNER_TAB)], indirect=True)
    @pytest.mark.parametrize('microsoft_azure_form_data', [{'auth_method': 'Password', 'username': 'admin',
                                                            'password': 'P@ssw0rd', 'application_id': '1234',
                                                            'subscription_id': '1234'},
                                                           {'auth_method': 'Key', 'application_id': '1234',
                                                            'subscription_id': '1234', 'client_secret': 'P@ssw0rd',
                                                            'tenant_id': "1234"}])
    def test_aci_with_compliance_and_credentials(self, create_policy, microsoft_azure_form_data):
        """
        Policy - Create, export and delete : NQA- 949
        1. Create a policy with random name and description.
        2. Add Credentials for Amazon AWS, Microsoft Azure, Rackspace, Salesforce.com
        3. Choose some related compliance audits on the Compliance Tab.
        4. Save.
        5. Verify created policy exist.
        6. Export the policy.
        7. Delete the created policy.
        """
        policy_name = create_policy
        AmazonAWS(cloud_type=API.Credentials.CloudServices.Types.AMAZON_AWS).fill_amazon_aws_form(
            **self.credential_type["amazon_form_data"])
        MicrosoftAzure(cloud_type=API.Credentials.CloudServices.Types.MICROSOFT_AZURE).fill_microsoft_azure_form(
            **microsoft_azure_form_data)
        RackSpace(cloud_type=API.Credentials.CloudServices.Types.RACKSPACE).fill_rackspace_form(
            **self.credential_type["rackspace_form_data"])
        SalesForce(cloud_type=API.Credentials.CloudServices.Types.SALESFORCE).fill_sales_force_form(
            **self.credential_type["sales_force_form"])

        compliance_page = Compliance()
        compliance_page.click_compliance_type(category_name=ComplianceConst.AMAZON_AWS,
                                              compliance_type="CIS Amazon Web Services Foundations v5.0.0 L1")

        LoadingCircle(WAIT_SHORT)
        compliance_page.click_compliance_type(category_name=ComplianceConst.RACKSPACE,
                                              compliance_type="Tenable Best Practices RackSpace v2.0.0")

        LoadingCircle(WAIT_NORMAL)
        policy_form = NewPolicyForm()
        policy_form.js_scroll_into_view(policy_form.save_button)
        policy_form.save_button.click()

        policy_list = PolicyList()
        assert policy_name in policy_list.get_all_policies(), 'Policy "%s" is not created successfully' % policy_name

        PoliciesPage().export_and_delete_policy(policy_name=policy_name)

        # Wait is required to get updated list
        LoadingCircle(WAIT_NORMAL)
        # verify above deleted policy doesn't exists anymore in policies management page
        assert policy_name not in policy_list.get_all_policies(), \
            'Policy "%s" is not deleted successfully' % policy_name

    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.COMPLIANCE_AUDIT,
                                                Nessus.Scan.ScanTemplateTabs.SCANNER_TAB)], indirect=True)
    def test_pci_with_compliance_and_credentials(self, create_policy):
        """
        Policy - Create, export and delete : NQA-963
        1. Create a policy with random name and description.
        2. Add Compliance audits.
        3. Add credentials.
        4. Save.
        5. Verify created policy exist.
        6. Export the policy.
        7. Delete the created policy.
        """
        policy_name = create_policy

        compliance_page = Compliance()
        compliance_page.click_compliance_type(category_name=ComplianceConst.UNIX,
                                              compliance_type="CIS Amazon Linux v2.1.0 L1")
        LoadingCircle(WAIT_SHORT)
        compliance_page.click_compliance_type(category_name=ComplianceConst.WINDOWS,
                                              compliance_type="CIS IE 10 v1.1.0")

        Password(host_type=API.Credentials.Host.Types.WINDOWS).fill_password_windows_form(
            **self.credential_type["windows_form_data"])
        LoadingCircle(WAIT_SHORT)
        Password(host_type=API.Credentials.Host.Types.SSH).fill_password_ssh_form(
            **self.credential_type["ssh_form_data"])

        LoadingCircle(WAIT_SHORT)
        NewPolicyForm().save_button.click()

        policy_list = PolicyList()
        assert policy_name in policy_list.get_all_policies(), 'Policy "%s" is not created successfully' % policy_name

        PoliciesPage().export_and_delete_policy(policy_name=policy_name)

        # Wait is required to get updated list
        LoadingCircle(WAIT_NORMAL)
        # verify above deleted policy doesn't exists anymore in policies management page
        assert policy_name not in policy_list.get_all_policies(), \
            'Policy "%s" is not deleted successfully' % policy_name

    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.OFFLINE_AUDIT,
                                                Nessus.Scan.ScanTemplateTabs.SCANNER_TAB)], indirect=True)
    def test_offline_config_with_compliance(self, create_policy):
        """
        Policy - Create, export and delete : NQA- 961
        1. Create a policy with random name and description.
        2. On the Compliance Tab choose an audit for Cisco IOS and attach IOS config files
        3. Save.
        4. Verify created policy exist.
        5. Export the policy.
        6. Delete the created policy.
        """
        policy_name = create_policy
        key_path = os.path.abspath(get_file_path("nessus/tests/api/plugins/test_data/api_pub_key_target_priv_key"))

        cis_cisco = CISCiscoCisIosL1()
        LoadingCircle(WAIT_NORMAL)

        cis_cisco.config_file.send_keys(key_path)
        LoadingCircle(WAIT_NORMAL)

        NewPolicyForm().save_button.click()

        policy_list = PolicyList()
        assert policy_name in policy_list.get_all_policies(), 'Policy "%s" is not created successfully' % policy_name

        PoliciesPage().export_and_delete_policy(policy_name=policy_name, export_policy_popup=False)

        # Wait is required to get updated list
        LoadingCircle(WAIT_NORMAL)
        # verify above deleted policy doesn't exists anymore in policies management page
        assert policy_name not in policy_list.get_all_policies(), \
            'Policy "%s" is not deleted successfully' % policy_name

    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED,
                                                Nessus.Scan.ScanTemplateTabs.SCANNER_TAB)], indirect=True)
    def test_advanced_scan_policy_with_pci_audits(self, create_policy):
        """
        Policy - Create, export and delete : NQA- 948
        1. Create a policy with random name and description.
        2. Add Windows and SSH creds and add some UNIX audits.
        3. Save.
        4. Export the policy.
        5. Verify created policy exist.
        6. Delete the created policy.
        """
        policy_name = create_policy

        Password(host_type=API.Credentials.Host.Types.WINDOWS).fill_password_windows_form(
            **self.credential_type["windows_form_data"])
        Password(host_type=API.Credentials.Host.Types.SSH).fill_password_ssh_form(
            **self.credential_type["ssh_form_data"])

        LoadingCircle(WAIT_SHORT)
        compliance_page = Compliance()
        compliance_page.click_compliance_type(category_name=ComplianceConst.UNIX,
                                              compliance_type="CIS CentOS 6 Server L1 v3.0.0")
        LoadingCircle(WAIT_SHORT)
        compliance_page.click_compliance_type(category_name=ComplianceConst.UNIX,
                                              compliance_type="CIS Debian Linux 7 L1 v1.0.0")
        LoadingCircle(WAIT_SHORT)
        compliance_page.click_compliance_type(category_name=ComplianceConst.UNIX,
                                              compliance_type="CIS Ubuntu Linux 16.04 LTS Workstation L2 v2.0.0")
        LoadingCircle(WAIT_SHORT)
        NewPolicyForm().save_button.click()

        policy_list = PolicyList()
        assert policy_name in policy_list.get_all_policies(), 'Policy "%s" is not created successfully' % policy_name

        PoliciesPage().export_and_delete_policy(policy_name=policy_name)

        # Wait is required to get updated list
        LoadingCircle(WAIT_NORMAL)
        # verify above deleted policy doesn't exists anymore in policies management page
        assert policy_name not in policy_list.get_all_policies(), \
            'Policy "%s" is not deleted successfully' % policy_name

    @pytest.mark.parametrize("create_policy", [
        (Nessus.TemplateNames.HOST_DISCOVERY, Nessus.Scan.ScanTemplateTabs.SCANNER_TAB),  # NQA-955
        (Nessus.TemplateNames.PCI_EXTERNAL, Nessus.Scan.ScanTemplateTabs.SCANNER_TAB)], indirect=True)  # NQA-962
    def test_export_policy_without_cred(self, create_policy):
        """
        Policy - Create, export and delete
        1. Create a policy with random name.
        2. Verify created policy exist.
        3. Export the policy.
        4. Delete the created policy.
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

    @pytest.mark.nessus_home
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED,
                                                API.Permissions.Types.SCANNER)], indirect=True)  # NQA-947
    def test_advance_scan_policy_with_plugin(self, create_policy):
        """
        Policy - Create, export and delete an Advanced Scan policy
        choosing only a select number of plugins
        1. Create a policy with random name.
        2. Click on Plugins tab and disable all plugins .
        3. Enable one of the given plugin plugin family.
        4. Enable the given plugin of a particular plugin family.
        5. Save the policy.
        6. Verify if the policy is exist.
        7. Export the policy.
        8. Delete the policy.
        """
        advance_policy_name = create_policy
        plugin_family_dns = "DNS"
        plugin_family_ftp = "FTP"
        ftp_family_plugin_name = "Anonymous FTP Enabled"

        Plugin().disable_all.click()

        plugin_family_list = PluginFamilyList()
        plugin_family_list.toggle_plugin_family(plugin_family_list=plugin_family_dns)

        assert API.Status.ENABLED in plugin_family_list.get_plugin_families_status(
            plugin_family_list=plugin_family_dns).values(), "plugin family status is not enabled"

        plugin_list = PluginsList()
        plugin_list.toggle_plugins(plugin_family=plugin_family_ftp,
                                   plugin_name_list=[ftp_family_plugin_name])

        assert API.Status.ENABLED.upper() in plugin_list.get_plugins_status(
            plugin_family=plugin_family_ftp, plugin_name_list=[ftp_family_plugin_name]).values(), \
            "plugin status is not enabled"
        assert API.Status.MIXED in PluginFamilyList().get_plugin_families_status(
            plugin_family_list=plugin_family_ftp).values(), "plugin family status is not mixed"

        NewPolicyForm().save_button.click()
        LoadingCircle(WAIT_NORMAL)
        policy_list = PolicyList()
        assert advance_policy_name in policy_list.get_all_policies(), \
            'Policy "%s" is not created successfully' % advance_policy_name

        PoliciesPage().export_and_delete_policy(policy_name=advance_policy_name, export_policy_popup=False)

        # Wait is required to get updated list
        LoadingCircle(WAIT_NORMAL)
        # verify above deleted policy doesn't exists anymore in policies management page
        assert advance_policy_name not in policy_list.get_all_policies(), \
            'Policy "%s" is not deleted successfully' % advance_policy_name

    @pytest.mark.xfail(reason="template depreciated")
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.SCAP_OVAL,
                                                API.Permissions.Types.SCANNER)], indirect=True)
    def test_scap_and_oval_auditing_policy(self, create_policy):
        """
        # NQA-964 :	UI - Policies - SCAP and OVAL Auditing - Create, export and delete
        test to create, configure, export and delete SCAP and OVAL Auditing policy.
        1. Click Policy in UI
        2. Fill out Name and Description.
        3. Add Credentials for SSH and Windows.
        4. On the SCAP tab, add the files and info related to SCAP.
        5. Save
        6. Delete
        """
        LoadingCircle(WAIT_SHORT)
        Password(host_type=API.Credentials.Host.Types.SSH).fill_password_ssh_form(
            **self.credential_type["ssh_form_data"])
        Password(host_type=API.Credentials.Host.Types.WINDOWS).fill_password_windows_form(
            **self.credential_type["windows_form_data"])

        # fill up name and description for policy
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

        policy_list = PolicyList()
        assert scap_policy_name in policy_list.get_all_policies(), 'Policy "%s" is not created successfully' \
                                                                   % scap_policy_name

        # delete above created policy
        policy_list.delete_policy(policy_name=scap_policy_name)

        LoadingCircle(WAIT_NORMAL)
        assert scap_policy_name not in policy_list.get_all_policies(), "Policy %s is not deleted successfully" \
                                                                       % scap_policy_name

    @pytest.mark.nessus_home
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED,
                                                API.Permissions.Types.SCANNER)], indirect=True)
    def test_advanced_scan_with_non_default_options_enabled(self, create_policy):
        """
        # NQA-946 :	UI-Policies - Advanced-Create, export and delete an Advanced policy with non default options enabled
        test to create, export and delete Advanced Scan policy.
        1. Click Policy in UI
        2. Fill out Name and Description.
        3. Click on ASSESSMENT tab and Choose accuracy options in Assessment settings
        4. Click on REPORTS tab and choose reports options.
        5. Add SSH and Windows Credentials
        6. Save
        7. Export
        8. Delete
        """
        # test data
        accuracy_option = 'Paranoid (more false alarms)'
        reports_option = 'Verbose'

        scanner_policy_name = create_policy

        policy_setting = PolicySettings()
        policy_setting.click_by_link_text(setting_value=API.PoliciesSettings.SettingsTypes.ASSESSMENT)
        AssessmentSetting().choose_accuracy_option(accuracy_option)

        # report settings
        policy_setting.click_by_link_text(setting_value=API.PoliciesSettings.SettingsTypes.REPORT)
        ReportSetting().choose_reports_option(reports_option)
        LoadingCircle(WAIT_NORMAL)

        # add Credentials for SSH and Windows
        Password(host_type=API.Credentials.Host.Types.SSH).fill_password_ssh_form(
            **self.credential_type["ssh_form_data"])
        Password(host_type=API.Credentials.Host.Types.WINDOWS).fill_password_windows_form(
            **self.credential_type["windows_form_data"])

        # save the policy
        NewPolicyForm().save_button.click()

        policy_list = PolicyList()
        assert scanner_policy_name in policy_list.get_all_policies(), \
            'Policy "%s" is not created successfully' % scanner_policy_name

        PoliciesPage().export_and_delete_policy(policy_name=scanner_policy_name)

        # Wait is required to get updated list
        LoadingCircle(WAIT_NORMAL)
        # verify above deleted policy doesn't exists anymore in policies management page
        assert scanner_policy_name not in policy_list.get_all_policies(), \
            'Policy "%s" is not deleted successfully' % scanner_policy_name

    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.COMPLIANCE_AUDIT,
                                                API.Permissions.Types.SCANNER)], indirect=True)
    def test_edit_compliance_audit(self, create_policy):
        """ error because of audit file related bug
        # NQA-109 :	Policies - Policy Compliance Auditing - Replace Existing Windows Audit File.
        1. Click Policy Compliance Auditing in UI
        2. Fill out Name and Description.
        3. Add Windows Credentials and Click on compliance tab.
        4. Add Windows Compliance File.
        5. Save the policy
        6. Add SSH Credentials.
        7. Click on the created policy and verify file added.
        8. Remove the file and add Unix File.
        9. Save the policy
        10. Verify File has been Replaced.
        11. Delete.
        """
        policy_name = create_policy
        Password(host_type=API.Credentials.Host.Types.WINDOWS).fill_password_windows_form(
            **self.credential_type["windows_form_data"])

        compliance_page = Compliance()
        compliance_page.click_compliance_type(category_name=ComplianceConst.WINDOWS,
                                              compliance_type="Upload a custom Windows audit file")
        LoadingCircle(WAIT_SHORT)
        compliance_page.add_audit_and_config_file(
            audit_file_path='nessus/tests/api/plugins/test_data/', audit_file_name='api_pub_key_target_priv_key',
            config_file_path=None, config_file_name=None)
        LoadingCircle(WAIT_SHORT)

        policy_form = NewPolicyForm()
        policy_form.save_button.click()

        policy_list = PolicyList()
        policy_list.click_on_policy(policy_name)
        Password(host_type=API.Credentials.Host.Types.SSH).fill_password_ssh_form(
            **self.credential_type["ssh_form_data"])

        edit_compliance_page = Compliance()
        assert compliance_page.uploaded_file_title.get_attribute('title') == "Custom Windows", "File is not saved"
        edit_compliance_page.get_remove_element(compliance_type=ComplianceConst.WINDOWS).click()
        LoadingCircle(WAIT_SHORT)

        edit_compliance_page.click_compliance_type(category_name=ComplianceConst.UNIX,
                                                   compliance_type="Upload a custom Unix audit file")
        LoadingCircle(WAIT_SHORT)

        compliance_page.add_audit_and_config_file(
            audit_file_path='nessus/tests/api/plugins/test_data/', audit_file_name='api_pub_key_target_priv_key',
            config_file_path=None, config_file_name=None)
        LoadingCircle(WAIT_SHORT)

        policy_form.save_button.click()
        assert edit_compliance_page.uploaded_file_title.get_attribute('title') == "Custom Unix", "File is not replaced"

        policy_form.back_to_policies.click()
        LoadingCircle(WAIT_SHORT)

        policy_list.delete_policy(policy_name=policy_name)

        # verify above deleted policy doesn't exists anymore in policies management page
        LoadingCircle(WAIT_NORMAL)
        assert policy_name not in policy_list.get_all_policies(), \
            "Policy %s not deleted successfully" % policy_name

    @pytest.mark.nessus_home
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED,
                                                Nessus.Scan.ScanTemplateTabs.SCANNER_TAB)], indirect=True)
    def test_uncheck_icmp_edit_tcp(self, create_policy):
        """
        # NQA-103 :	Policies - Advanced - Edit TCP destination port after unchecking ICMP.
        1. Click Advanced Scan Policy in UI
        2. Fill out Name and Description.
        3. Click on DISCOVERY tab and uncheck ICMP ping method.
        4. Edit TCP ping method, add random tcp destination port.
        5. Save the policy
        6. Click on the created policy and click on DISCOVERY TAB.
        7. Verify changes exist.
        8. Delete
        """
        advanced_policy_name = create_policy
        ping_method = "ICMP"

        # assessment settings
        policy_setting = PolicySettings()
        policy_setting.click_by_link_text(setting_value=API.PoliciesSettings.SettingsTypes.DISCOVERY)

        discovery_setting = DiscoverySetting()
        discovery_setting.get_checkbox_element_for_value(check_box_value=ping_method).click()

        tcp_port = random_name(prefix="built-in" + "-")
        discovery_setting.tcp_destination_ports.clear()
        discovery_setting.tcp_destination_ports.send_keys(tcp_port)
        LoadingCircle(WAIT_NORMAL)

        policy_form = NewPolicyForm()
        policy_form.save_button.click()

        policy_list = PolicyList()
        policy_list.click_on_policy(policy_name=advanced_policy_name)
        LoadingCircle(WAIT_NORMAL)
        policy_setting.click_by_link_text(setting_value=API.PoliciesSettings.SettingsTypes.DISCOVERY)

        assert not discovery_setting.get_checkbox_element_for_value(check_box_value=ping_method).is_selected(), \
            'Unable to uncheck "%s" method' % ping_method

        assert discovery_setting.tcp_destination_ports.get_attribute('value') == tcp_port, \
            'Unable to edit TCP destination port field after unchecking "%s" ping method' % ping_method

        policy_form.back_to_policies.click()
        LoadingCircle(WAIT_SHORT)

        policy_list.delete_policy(policy_name=advanced_policy_name)

        # verify above deleted policy doesn't exists anymore in policies management page
        LoadingCircle(WAIT_NORMAL)
        assert advanced_policy_name not in policy_list.get_all_policies(), \
            "Policy '%s' is not deleted successfully" % advanced_policy_name

    @pytest.mark.browser_file_download
    @pytest.mark.nessus_home
    @pytest.mark.parametrize('create_policies', [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED_DYNAMIC, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix='Advanced_Dynamic_Scan_Policy_'), 'add_configuration': True,
         'description': 'Created advanced dynamic scan policy for NQA-1301.'}]}], indirect=True)
    def test_dynamic_plugins_retained_in_imported_policy(self, create_policies):
        """
        # NQA-1301 : Automation tests for Dynamic Scan. (step: 12-13)
        Test to verify dynamic plugins were retained in imported policy

        1. Create a policy using 'Advanced Dynamic Scan' template with added dynamic plugins and save it.
        2. Export the policy.
        3. Import the above exported policy and navigate to 'Dynamic Plugins' tab.
        4. Verify above added plugins were retained here.
        """
        policy_name = create_policies[0]
        plugin_filter_to_apply = [
            {Nessus.Filter.INDEX: 1, Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_NAME,
             Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.CONTAINS, Nessus.Filter.VALUE: 'nessus'},
            {Nessus.Filter.INDEX: 2, Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_TYPE,
             Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.EQUAL_TO, Nessus.Filter.VALUE: 'remote'},
            {Nessus.Filter.INDEX: 3, Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_NAME,
             Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.NOT_CONTAINS, Nessus.Filter.VALUE: 'detection'}]

        # Add dynamic plugins filter
        dynamic_plugins = DynamicPlugin()
        applied_plugins = dynamic_plugins.manage_dynamic_plugins(add_plugins=True, preview_plugins=True,
                                                                 plugins_filter_list=plugin_filter_to_apply)

        # Save policy, verify success notifications
        dynamic_plugins.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.Policies.policy_saved, \
            "Success notification for saving policy is missing or mismatched."

        # Export the policy and delete it, otherwise it will duplicate the policy when we import the same
        policies_page = PoliciesPage()
        policies_page.export_and_delete_policy(policy_name=policy_name, export_policy_popup=False)
        LoadingCircle(TIME_THREE_SECONDS)

        # Import the above exported policy
        exported_policy = get_downloaded_files_chrome(filename=policy_name)
        log.info("Path of the exported policy file: %s", exported_policy)

        formatted_file_path = exported_policy[0].split('//')[1]
        if Config.CAT_USE_GRID:
            policies_page.import_policies.send_keys(formatted_file_path)
        else:
            UploadField(policies_page.import_policies).file = formatted_file_path
        LoadingCircle(TIME_TEN_SECONDS)

        # Navigate to 'Dynamic Plugins' tab
        PolicyList().click_on_policy(policy_name=policy_name)
        LoadingCircle(WAIT_NORMAL)
        dynamic_plugins.dynamic_plugins.click()

        # Verify added plugins filters (while creating the policy to export) were retained in imported policy
        plugin_filter_in_imported_policy = dynamic_plugins.get_added_plugins_filter()
        assert plugin_filter_to_apply == plugin_filter_in_imported_policy, \
            'Mismatched: added plugin filters weren\'t  retained in imported policy.'

        # Verify plugin_list by plugin_family should remained same in imported policy
        current_plugins = dynamic_plugins.preview_plugins_by_family()
        assert applied_plugins == current_plugins, 'Mismatched: applied plugins weren\'t retained in imported policy.'

        NewPolicyForm().back_to_policies.click()
        LoadingCircle(TIME_THREE_SECONDS)

    @pytest.mark.nessus_home
    def test_visibility_of_permissions_link_under_policies_basic_settings(self):
        """
        NES-13103 [Automation]: Verify that "Permissions" tab is not visible for Scans/Policies in Nessus
                                professional/Home

        Scenario Tested:
        [x] Verify that "Permissions" tab should not be visible for Policies in Nessus professional/Home.
        """
        policy_page = PoliciesPage()
        policy_page.open()
        wait(lambda: policy_page.is_element_present('policies_searchbox') or policy_page.is_element_present(
            'create_a_new_policy_link'), waiting_for='Policy page to loaded properly')

        policy_page.new_policy_button.click()
        wait(lambda: ScanTemplatePage().is_element_present('vuln_template_section'),
             waiting_for='scan templates to load properly.')

        PolicyType().click_by_policy(policy_text=Nessus.TemplateNames.ADVANCED)
        wait(lambda: NewPolicyForm().is_element_present('name_field'), waiting_for='new policy form to load properly.')

        is_permission_tab_visible = BasicSetting().is_element_present("permissions")

        if is_manager():
            assert is_permission_tab_visible, "'Permissions' tab is missing in Nessus Manager."
        else:
            assert not is_permission_tab_visible, "'Permissions' tab is visible in Nessus Professional/Home."

    @pytest.mark.xray(test_key='NES-14128')
    def test_plugin_filters_for_advanced_policy_template(self):
        """
        NES-14128 : Verify filter with any substring is successfully filtered in Advanced Policy template.

        Scenarios Covered:
        [X] Filter check with substring of plugin can have relevant results
        [X] Filter check with exact string can have exact results.
        """
        policy_page = PoliciesPage()
        policy_page.open()
        wait(lambda: policy_page.is_element_present('policies_searchbox') or policy_page.is_element_present(
            'create_a_new_policy_link'), waiting_for='Policy page to loaded properly')

        policy_page.new_policy_button.click()
        wait(lambda: ScanTemplatePage().is_element_present('vuln_template_section'),
             waiting_for='scan templates to load properly.')

        PolicyType().click_by_policy(policy_text=Nessus.TemplateNames.ADVANCED)
        wait(lambda: NewPolicyForm().is_element_present('name_field'), waiting_for='new policy form to load properly.')

        policy_page.plugins_tab.click()

        wait(lambda: policy_page.is_element_present('policies_searchbox'), waiting_for='filter box to load properly.')
        assert all([policy_page.policies_searchbox.is_displayed(), policy_page.search_icon.is_displayed()]), \
            "Filter search box is not present with 'Search icon'."

        plugin_families = ['Security', 'Backdoors', 'FTP', 'Netware', 'SNMP', 'Checks', 'SCADA', 'CISCO']
        plugin_family_list = PluginFamilyList()
        expected_family_list = plugin_family_list.get_all_plugin_families()

        for plugin_family in plugin_families:
            policy_page.apply_search_on_policies(search_key=plugin_family)
            LoadingCircle(WAIT_SHORT)
            filtered_family_list = plugin_family_list.get_all_plugin_families()

            if len(filtered_family_list) > 1:
                for filtered_result in filtered_family_list:
                    assert plugin_family in filtered_result, "Searched substring is not available in filtered result"
            elif len(filtered_family_list) == 1:
                assert (plugin_family == filtered_family_list[0]), \
                    "Searched plugin family is not available in filtered plugin family list."

        assert all([(not policy_page.search_icon.is_displayed()), policy_page.clear_search_icon.is_displayed()]), \
            "'Search icon' is visible and 'Remove icon' is not visible."

        policy_page.clear_search_icon.click()
        LoadingCircle(WAIT_SHORT)

        assert all([policy_page.search_icon.is_displayed(), (not policy_page.clear_search_icon.is_displayed())]), \
            "'Search icon' is not visible and 'Remove icon' is visible."

        assert expected_family_list == plugin_family_list.get_all_plugin_families(), \
            'All plugin families are present after removing the search.'
