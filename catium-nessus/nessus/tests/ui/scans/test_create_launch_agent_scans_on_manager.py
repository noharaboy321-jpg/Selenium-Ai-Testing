"""
Nessus test cases related to Scans on Controller with all available agents templates

:copyright: Tenable Network Security, 2017
:date: December 12, 2017
:last_modified: July 16, 2018
:author: @rdutta, @mameta
"""
# pylint: disable=undefined-variable

import pytest
from selenium.webdriver.support.expected_conditions import visibility_of_element_located

from catium.lib.const import WAIT_SHORT
from catium.lib.const.base_constants import WAIT_NORMAL, TIME_THREE_SECONDS
from catium.lib.util import random_name
from catium.lib.webium.wait import wait
from nessus.helpers.agents import get_online_linked_agent
from nessus.helpers.scan import scan_save_launch_and_status_verification, delete_created_scan
from nessus.lib.const.compliance_constants import ComplianceConst
from nessus.lib.const.constants import API, Nessus, Prefixes
from nessus.pageobjects.agents.agent_group_page import CreateGroupWindowPage
from nessus.pageobjects.compliances.compliance_page import Compliance
from nessus.pageobjects.plugins.plugins_page import PluginFamilyList, Plugin, PluginsList
from nessus.pageobjects.scans.new_scan_form import NewScanForm
from nessus.pageobjects.scans.scan_basic_settings_page import AssessmentSetting
from nessus.pageobjects.scans.scan_view_page import ScanViewPage
from nessus.pageobjects.scans.scans_page import ScansPage, ScanList
from nessus.pageobjects.scap.scap_page import ScapAndOvalForm
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav


@pytest.mark.scanning
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login', 'create_new_folder', 'login')
@pytest.mark.parametrize('create_agent_groups', [{'agent_group_details': [{
    'agent_group_name': Prefixes.AGENT_GROUP, 'add_agents': True}]}], indirect=True)
class TestAgentScansOnManager:
    """Covers test cases related to Scans on Manager with all available agent templates."""

    cat = None

    @staticmethod
    def add_agent_to_created_group() -> None:
        """
        Add agent to agent_group for scanning if any remote agent(with online status) found to be linked with product.
        :return: None
        """
        linked_agent = get_online_linked_agent(api=__class__.cat.api)

        if linked_agent:
            CreateGroupWindowPage().add_agent_member_to_agent_group(member_agent_list=[linked_agent[0]])
            LoadingCircle(WAIT_NORMAL)
        else:
            pytest.xfail(reason="Can't proceed further as no remote agent linked to the product.")

    @pytest.mark.parametrize('data_to_be_scanned', [
        {'all_plugin_families': {'scan_name': 'NQA-386 - Advanced All Plugins'}},
        {'custom_one_plugin_family': {'scan_name': 'NQA-386 - Advanced Custom One Pluginset',
                                      'plugin_family': 'Settings'}},
        {'custom_couple_plugin_family': {'scan_name': 'NQA-386 - Advanced Custom Couple Pluginset',
                                         'plugin_set': [{'plugin_family': 'General', 'plugin_id_list': ['34098']},
                                                        {'plugin_family': 'Settings', 'plugin_id_list': ['19506']}]}},
        {'all_plugin_families_with_compliance': {
            'scan_name': 'NQA-386 - Advanced All Plugins w/ compliance',
            'compliance_to_scan': [
                {'category_type': ComplianceConst.UNIX, 'file': 'CIS_Red_Hat_EL6_Server_L1_v2.0.2.audit',
                 'file_path': 'nessus/tests/ui/scan/test_data/'},
                {'category_type': ComplianceConst.WINDOWS, 'file': 'CIS_MS_Windows_7_L1_v3.0.1.audit',
                 'file_path': 'nessus/tests/ui/scan/test_data/'}]}}])
    def test_advanced_agent_scan(self, create_new_folder, create_agent_groups, data_to_be_scanned):
        """
        #NQA-386 : Short Cycle - Agent - Stage 2 - Scans.
        1. Create Advanced Agent scan with different plugins and compliance enabled
        2. Verify scan is completed successfully and there are no errors on controller or the agent
        """
        folder_name = create_new_folder[1]
        type_of_data_to_be_scanned = list(data_to_be_scanned.keys())[0]
        scan_name = data_to_be_scanned.get(type_of_data_to_be_scanned).get('scan_name')

        # Add remote agent to the created agent group
        __class__.add_agent_to_created_group()

        # Create scan with data to be scanned
        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()
        scan_page = ScansPage()
        wait(lambda: visibility_of_element_located(scan_page.new_scan_button),
             waiting_for='Waiting for New scan button')
        scan_page.create_new_scan(
            scan_template=Nessus.TemplateNames.ADVANCED_AGENT, scan_type=Nessus.Scan.ScanTemplateTabs.AGENT_TAB,
            description='Created an Advanced Scan with {}.'.format(type_of_data_to_be_scanned),
            scan_name=scan_name, folder=folder_name, agent_group=create_agent_groups[0], add_configuration=True)

        # Add required data to be scanned
        LoadingCircle(TIME_THREE_SECONDS)
        if type_of_data_to_be_scanned in ['custom_one_plugin_family', 'custom_couple_plugin_family']:
            plugin_page = Plugin()
            plugin_page.disable_all.click()
            if type_of_data_to_be_scanned == 'custom_one_plugin_family':
                PluginFamilyList().toggle_plugin_family(
                    plugin_family_list=data_to_be_scanned.get(type_of_data_to_be_scanned).get('plugin_family'))
            else:
                plugins_list = PluginsList()
                for plugin in data_to_be_scanned.get(type_of_data_to_be_scanned).get('plugin_set'):
                    plugins_list.toggle_plugins(plugin_family=plugin.get('plugin_family'),
                                                plugin_id_list=plugin.get('plugin_id_list'))

        elif type_of_data_to_be_scanned == 'all_plugin_families_with_compliance':
            compliance_page = Compliance()
            for compliance in data_to_be_scanned.get(type_of_data_to_be_scanned).get('compliance_to_scan'):
                LoadingCircle(TIME_THREE_SECONDS)
                compliance_page.click_compliance_type(category_name=compliance.get('category_type'),
                                                      compliance_type="Upload a custom {} audit file".
                                                      format(compliance.get('category_type')))
                compliance_page.open_saved_compliance_component(
                    form_name="Upload a custom {} audit file".format(compliance.get('category_type')))
                LoadingCircle(WAIT_SHORT)
                compliance_page.add_audit_and_config_file(audit_file_name=compliance.get('file'),
                                                          audit_file_path=compliance.get('file_path'))

        # Save scan, launch it and verify it's successful completion
        assert scan_save_launch_and_status_verification(scan_name=scan_name, scan_folder_name=folder_name),\
            'Scan has not been completed successfully.'

        # Delete the created scan
        delete_created_scan(scan_name=scan_name)

    @pytest.mark.parametrize('templates_to_scan', [
        {'scan_template': Nessus.TemplateNames.BASIC_AGENT, 'scan_name': 'NQA-386 - Basic Agent Scan'},
        {'scan_template': Nessus.TemplateNames.MALWARE, 'scan_name': 'NQA-386 - Malware Scan'},
        {'scan_template': Nessus.TemplateNames.SCAP_OVAL_AGENT, 'scan_name': 'NQA-386 - SCAP and OVAL'},
        {'scan_template': Nessus.TemplateNames.COMPLIANCE_AUDIT, 'scan_name': 'NQA-386 - PCI Scan',
         'compliance_to_scan': [{'category_type': ComplianceConst.UNIX, 'file_path': 'nessus/tests/ui/scan/test_data/',
                                 'file': 'CIS_Red_Hat_EL6_Server_L1_v2.0.2.audit'},
                                {'category_type': ComplianceConst.WINDOWS_FILE_CONTENTS,
                                 'file_path': 'nessus/tests/ui/scan/test_data/',
                                 'file': 'CIS_MS_Windows_7_L1_v3.0.1.audit'}]}])
    def test_agent_scans_with_different_templates(self, create_new_folder, create_agent_groups, templates_to_scan):
        """
        #NQA-386 : Short Cycle - Agent - Stage 2 - Scans.
        1. Create Agent scan with different templates with required data
        2. Verify scan is completed successfully and there are no errors on controller or the agent
        """
        folder_name = create_new_folder[1]
        scan_name = templates_to_scan.get('scan_name')

        # Add remote agent to the created agent group
        __class__.add_agent_to_created_group()

        # Create scan with data to be scanned
        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()
        LoadingCircle(WAIT_NORMAL)
        ScansPage().create_new_scan(
            scan_template=templates_to_scan.get('scan_template'), scan_type=Nessus.Scan.ScanTemplateTabs.AGENT_TAB,
            description='Created a {} for NQA-386.'.format(templates_to_scan.get('scan_template').lower()),
            scan_name=scan_name, folder=folder_name, agent_group=create_agent_groups[0], add_configuration=True)

        if templates_to_scan.get('scan_template') == Nessus.TemplateNames.SCAP_OVAL_AGENT:
            scap_page = ScapAndOvalForm()
            scap_page.open_form_and_fill_details(
                form_information=API.Scap.SCAP_AND_OVAL_INFORMATION)
        elif templates_to_scan.get('scan_template') == Nessus.TemplateNames.COMPLIANCE_AUDIT:
            compliance_page = Compliance()
            for compliance in templates_to_scan.get('compliance_to_scan'):
                LoadingCircle(TIME_THREE_SECONDS)
                compliance_page.click_compliance_type(category_name=compliance.get('category_type'),
                                                      compliance_type="Upload a custom {} audit file".
                                                      format(compliance.get('category_type')))
                compliance_page.open_saved_compliance_component(
                    form_name="Upload a custom {} audit file".format(compliance.get('category_type')))
                LoadingCircle(WAIT_SHORT)
                compliance_page.add_audit_and_config_file(audit_file_name=compliance.get('file'),
                                                          audit_file_path=compliance.get('file_path'))

        # Save scan, launch it and verify it's successful completion
        LoadingCircle(TIME_THREE_SECONDS)
        assert scan_save_launch_and_status_verification(scan_name=scan_name, scan_folder_name=folder_name),\
            'Scan has not been completed successfully.'

        # Delete the created scan
        delete_created_scan(scan_name=scan_name)

    @pytest.mark.parametrize('create_scans', [
        {'scans_details': [{
            'scan_template': Nessus.TemplateNames.ADVANCED_AGENT, 'scan_type': Nessus.Scan.ScanTemplateTabs.AGENT_TAB,
            'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.ADVANCED_AGENT)),
            'description': 'Created a {} for NQA-335.'.format(Nessus.TemplateNames.ADVANCED_AGENT.lower()),
            'add_configuration': True}]},
        {'scans_details': [{
            'scan_template': Nessus.TemplateNames.MALWARE, 'scan_type': Nessus.Scan.ScanTemplateTabs.AGENT_TAB,
            'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.MALWARE)),
            'description': 'Created a {} for NQA-335.'.format(Nessus.TemplateNames.MALWARE.lower()),
            'add_configuration': True}]}], indirect=True)
    def test_toggle_malware_setting_in_agent_scan(self, create_new_folder, create_agent_groups, create_scans):
        """
        #NQA-335: UI - Policy - Toggle Enable/Disable Malware Scan.
        1. Create a new scan
        2. Navigate through Advanced scan -> assessment -> Malware.
        3. Click on the toggle to make sure that it works and brings up the malware settings.
        4. Click the toggle for File system scanning and hit 'Save'
        5. Go back and make sure that the toggle is still set to enabled.
        6. Repeat above Steps for Malware Template.
        """
        agent_group = create_agent_groups[0]
        scan_folder = create_new_folder[1]
        scan_name = create_scans[0]

        # Add malware settings
        NewScanForm().fill_new_scan_detail(folder=scan_folder, agent_group=agent_group)
        assessment_setting = AssessmentSetting()
        assessment_setting.click_link_inside_link(setting_value=API.PoliciesSettings.SettingsTypes.ASSESSMENT,
                                                  link_text="Malware")

        if 'Malware' not in scan_name:
            assert assessment_setting.malware_switch.get_attribute('data-value') == 'no', \
                "Scan for malware switch is not disabled"
            assessment_setting.malware_switch.click()

        assert assessment_setting.malware_switch.get_attribute('data-value') == 'yes', \
            "Scan for malware switch is not enabled"

        assessment_setting.scan_file_system.click()
        assert assessment_setting.scan_file_system.get_attribute('data-value') == 'yes', \
            "Scan file system is not enabled"

        assessment_setting.save_button.click()
        LoadingCircle(WAIT_SHORT)

        # Navigate to scan folder and configure the scan
        side_nav = SideNav()
        side_nav.get_sidenav_element(element_name=scan_folder).click()
        LoadingCircle(WAIT_NORMAL)

        ScanList().click_on_scan(scan_name=scan_name)
        LoadingCircle(WAIT_NORMAL)
        ScanViewPage().configure_button.click()
        LoadingCircle(WAIT_SHORT)
        assessment_setting.click_link_inside_link(setting_value=API.PoliciesSettings.SettingsTypes.ASSESSMENT,
                                                  link_text="Malware")

        # Verify settings retained
        assert all([(assessment_setting.malware_switch.get_attribute('data-value') == 'yes'),
                    (assessment_setting.scan_file_system.get_attribute('data-value') == 'yes')]), \
            "'Scan for malware switch' and 'Scan file system' is not enabled."

        side_nav.get_sidenav_element(element_name=scan_folder).click()
        LoadingCircle(WAIT_NORMAL)
