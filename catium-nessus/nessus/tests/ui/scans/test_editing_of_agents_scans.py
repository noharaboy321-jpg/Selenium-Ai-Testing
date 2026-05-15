"""
Nessus test class for Editing of created agent scan

:Copyright: Tenable Network Security, 2018
:Date: Jun 18, 2018
:last_modified: Jun 18, 2018
:Author: @jchavda
"""

from random import randint

import pytest

from catium.lib.const import WAIT_SHORT
from catium.lib.const.base_constants import TIME_THIRTY_SECONDS
from catium.lib.webium.wait import wait
from nessus.lib.const import API, Nessus, random_name, Prefixes
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.scans.new_scan_form import NewScanForm
from nessus.pageobjects.scans.scan_basic_settings_page import BasicSetting, DiscoverySetting, AssessmentSetting, \
    ScanSettings, AdvancedSetting
from nessus.pageobjects.scans.scan_trash_page import ScansTrashPage
from nessus.pageobjects.scans.scan_view_page import ScanViewPage
from nessus.pageobjects.scans.scans_page import ScansPage, ScanList
from nessus.pageobjects.scap.scap_page import ScapAndOvalForm
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav

scap_and_oval_information = [
    {'count_of_forms': 1, 'form_type': API.Scap.Types.WINDOWS_SCAP, 'form_details': [
        {'version': '1.2', 'benchmark_id': 'Windows_7_STIG', 'profile_id': 'Windows - 1_Classified',
         'stream_id': '1234567', 'result_type': 'Full results w/o system characteristics',
         'definition_file_name': 'U_Windows_7_V1R27_STIG_SCAP_1-1_Benchmark.zip',
         'definition_file_path': 'nessus/tests/ui/scan/test_data/'}]}]


@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
@pytest.mark.parametrize("create_agent_groups", [{'agent_group_details': [
    {'agent_group_name': Prefixes.AGENT_GROUP}]}], indirect=True)
@pytest.mark.parametrize('create_scans', [{'scans_details': [{'scan_template': Nessus.TemplateNames.ADVANCED_AGENT,
                                                              'scan_type': Nessus.Scan.ScanTemplateTabs.AGENT_TAB,
                                                              'scan_name': random_name(prefix="{} - ".format(
                                                                  Nessus.TemplateNames.ADVANCED_AGENT)),
                                                              'add_configuration': True}]},
                                          {'scans_details': [{'scan_template': Nessus.TemplateNames.BASIC_AGENT,
                                                              'scan_type': Nessus.Scan.ScanTemplateTabs.AGENT_TAB,
                                                              'scan_name': random_name(prefix="{} - ".format(
                                                                  Nessus.TemplateNames.BASIC_AGENT)),
                                                              'add_configuration': True}]},
                                          {'scans_details': [{'scan_template': Nessus.TemplateNames.MALWARE,
                                                              'scan_type': Nessus.Scan.ScanTemplateTabs.AGENT_TAB,
                                                              'scan_name': random_name(prefix="{} - ".format(
                                                                  Nessus.TemplateNames.MALWARE)),
                                                              'add_configuration': True}]},
                                          {'scans_details': [{'scan_template': Nessus.TemplateNames.COMPLIANCE_AUDIT,
                                                              'scan_type': Nessus.Scan.ScanTemplateTabs.AGENT_TAB,
                                                              'scan_name': random_name(prefix="{} - ".format(
                                                                  Nessus.TemplateNames.COMPLIANCE_AUDIT)),
                                                              'add_configuration': True}]},
                                          {'scans_details': [{'scan_template': Nessus.TemplateNames.SCAP_OVAL_AGENT,
                                                              'scan_type': Nessus.Scan.ScanTemplateTabs.AGENT_TAB,
                                                              'scan_name': random_name(prefix="{} - ".format(
                                                                  Nessus.TemplateNames.SCAP_OVAL_AGENT)),
                                                              'add_configuration': True}]}], indirect=True)
@pytest.mark.parametrize('test_data', scap_and_oval_information)
class TestAgentScanEdit:
    """
    NQA-1267: Editing of Scans -> Agent Page, pre-requisite: Create a new agent scan relates Test Cases
    """
    @staticmethod
    def delete_agent_scan(scan_name: str):
        """
        Delete a scan specified by scan_name
        :param str scan_name: name of the scan to delete
        :return: None
        """
        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)
        scan_list = ScanList()
        scan_list.delete_scan(scan_name=scan_name)
        LoadingCircle(WAIT_SHORT)
        ScansTrashPage().delete_scan_from_trash(scan_name=scan_name)

    @pytest.mark.parametrize("toggle_value", [True])
    @pytest.mark.parametrize("recipient_email", ['admin@tenable.com'])
    def test_create_scan_and_edit_basic_setting(self, create_agent_groups, create_scans, toggle_value, recipient_email,
                                                test_data):
        """
        NQA-1267: Edit created scan with 'Basic' settings
        1. Navigate to created scan and click 'Configure' button
        2. Edit the scan name and scan window value to 15 minute
        3. Toggle 'Enabled'  and set frequency as 'daily' under 'Schedule'
        4. Add value for 'Email Recipient(s)' under 'Notifications'
        5. Hit save and verify success notification
        6. Get back to above edited changes and verify changes retained its values.
        """
        # Create new scan under Agent Tab
        agent_group = create_agent_groups[0]
        scan_name = create_scans[0]
        scan_form = NewScanForm()
        scan_form.fill_new_scan_detail(agent_group=agent_group)

        if Nessus.TemplateNames.SCAP_OVAL_AGENT in scan_name:
            ScapAndOvalForm().open_form_and_fill_details(form_information=[test_data])[0].get(
                test_data.get('form_type'))

        scan_form.save_button.click()
        # test_data dict for edit value
        test_data = {'scan_name': 'Edited {}'.format(scan_name), 'scan_window': '15 minutes'}

        ScanList().click_on_scan(scan_name=scan_name)
        LoadingCircle(WAIT_SHORT)
        scan_view_page = ScanViewPage()
        scan_view_page.configure_button.click()
        wait(lambda: scan_form.is_element_present('name_field'), timeout_seconds=TIME_THIRTY_SECONDS,
             sleep_seconds=WAIT_SHORT, waiting_for="Scan configure page to get loaded properly.")

        # Edit scan name and scan window After saved
        scan_page = ScansPage()
        scan_page.name_field.value = test_data['scan_name']
        scan_page.select_scan_window.select_by_visible_text(test_data['scan_window'])
        LoadingCircle(WAIT_SHORT)

        # Edit Toggle enable and Email recipient under BASIC settings
        setting_page = BasicSetting()
        setting_page.click_link_inside_link(setting_value="BASIC", link_text="Schedule")
        setting_page.enable_schedule.set_toggle(toggle_value)
        setting_page.frequency.select_by_visible_text('Daily')
        setting_page.set_email_recipient_for_notification(recipient_email=recipient_email)

        # Hit save and verify success notification
        scan_page.save_button.click()
        scan_name = test_data['scan_name']


        assert Notifications().successes[-1] == "Scan saved successfully.", \
            'Notification is missing after saving the scan'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        ScanList().click_on_scan(scan_name=scan_name)
        scan_view_page.configure_button.click()
        wait(lambda: scan_form.is_element_present('name_field'), timeout_seconds=TIME_THIRTY_SECONDS,
             sleep_seconds=WAIT_SHORT, waiting_for="Scan configure page to get loaded properly.")

        # Get back to above edited changes and verify changes retained its values.
        assert scan_page.name_field.value == test_data['scan_name'], 'Name is not changed'
        assert scan_page.select_scan_window.get_text_selected() == '15 minutes', 'Edited Scan window value is different'
        assert setting_page.enable_schedule.is_selected() == toggle_value, 'Schedule value is not enabled'
        assert setting_page.frequency.get_attribute('value') == 'DAILY', 'Frequency selected value is different'
        assert setting_page.get_email_recipient_for_notification() == recipient_email, \
            'Edited email recipient is different'

        # Delete Scan
        TestAgentScanEdit.delete_agent_scan(scan_name)

    @pytest.mark.parametrize("wmi_check", [False])
    def test_create_scan_and_edit_discovery_setting(self, create_agent_groups, create_scans, wmi_check, test_data):
        """
        NQA-1267: Edit created scan with 'Discovery' settings
        1. Navigate to created scan and click 'Configure' button
        2. Edit the scan with below configurations
        3. Uncheck  'WMI (netstat)' under 'Local Port Enumerators'
        4. Hit save and verify success notification
        5. Get back to above edited changes and verify changes retained its values.
        """
        agent_group = create_agent_groups[0]
        scan_name = create_scans[0]
        scan_form = NewScanForm()
        scan_form.fill_new_scan_detail(agent_group=agent_group)

        if Nessus.TemplateNames.SCAP_OVAL_AGENT in scan_name:
            ScapAndOvalForm().open_form_and_fill_details(form_information=[test_data])[0].get(
                test_data.get('form_type'))

        scan_form.save_button.click()
        ScanList().click_on_scan(scan_name=scan_name)
        LoadingCircle(WAIT_SHORT)
        scan_view_page = ScanViewPage()
        scan_view_page.configure_button.click()
        wait(lambda: scan_form.is_element_present('name_field'), timeout_seconds=TIME_THIRTY_SECONDS,
             sleep_seconds=WAIT_SHORT, waiting_for="Scan configure page to get loaded properly.")

        local_port_enumerator = 'WMI (netstat)'
        DiscoverySetting().click_by_link_text(setting_value=Nessus.Scan.SettingsTypes.DISCOVERY)
        DiscoverySetting().get_checkbox_element_for_value(check_box_value=local_port_enumerator).set_checked(wmi_check)
        ScansPage().save_button.click()


        assert Notifications().successes[-1] == "Scan saved successfully.", \
            "Notification is missing after saving the scan"

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        ScanList().click_on_scan(scan_name=scan_name)
        scan_view_page.configure_button.click()
        wait(lambda: scan_form.is_element_present('name_field'), timeout_seconds=TIME_THIRTY_SECONDS,
             sleep_seconds=WAIT_SHORT, waiting_for="Scan configure page to get loaded properly.")
        DiscoverySetting().click_by_link_text(setting_value=Nessus.Scan.SettingsTypes.DISCOVERY)

        assert DiscoverySetting().get_checkbox_element_for_value(
            check_box_value=local_port_enumerator).is_selected() == wmi_check,\
            "Unable to uncheck {0} under Local Port Enumerators.".format(local_port_enumerator)

        # Delete Scan
        TestAgentScanEdit.delete_agent_scan(scan_name)

    @pytest.mark.parametrize("smb_domain", [False])
    @pytest.mark.parametrize("malware_switch", [True])
    def test_create_scan_and_edit_assessment_setting(self, create_agent_groups, create_scans,
                                                     smb_domain, malware_switch, test_data):
        """
        NQA-1267: Edit created scan with 'Assessment' settings
        1. Edit the scan with below configurations
        2. Select a value greater than 0 for 'Antivirus definition grace period (in days)' drop-down under 'General'
        3. Uncheck 'Request information about the SMB Domain' under 'General Settings' in 'windows'
        4. Toggle 'Scan for malware' and uncheck 'Disable DNS resolution' under general settings in 'Malware'
        5. Hit save and verify success notification
        6. Get back to edited changes and verify changes retained its values.
        """
        grace_period_day = randint(1, 7)
        agent_group = create_agent_groups[0]
        scan_name = create_scans[0]

        if Nessus.TemplateNames.COMPLIANCE_AUDIT in scan_name or Nessus.TemplateNames.SCAP_OVAL_AGENT in scan_name:
            pass
        else:
            scan_form = NewScanForm()
            scan_form.fill_new_scan_detail(agent_group=agent_group)
            scan_form.save_button.click()

            ScanList().click_on_scan(scan_name=scan_name)
            LoadingCircle(WAIT_SHORT)
            scan_view_page = ScanViewPage()
            scan_view_page.configure_button.click()
            wait(lambda: scan_form.is_element_present('name_field'), timeout_seconds=TIME_THIRTY_SECONDS,
                 sleep_seconds=WAIT_SHORT, waiting_for="Scan configure page to get loaded properly.")

            smb_domain_request = 'Request information about the SMB Domain'
            assessment_setting = AssessmentSetting()
            if Nessus.TemplateNames.ADVANCED_AGENT in scan_name:
                assessment_setting.click_by_link_text(setting_value=Nessus.Scan.SettingsTypes.ASSESSMENT)
                assessment_setting.anti_grace_period.select_by_visible_text('%s' % grace_period_day)

                assessment_setting.click_link_inside_link(setting_value=Nessus.Scan.SettingsTypes.ASSESSMENT,
                                                          link_text='Windows')
                assessment_setting.get_checkbox_element_for_value(check_box_value=smb_domain_request).set_checked(
                    smb_domain)

                assessment_setting.click_link_inside_link(setting_value=Nessus.Scan.SettingsTypes.ASSESSMENT,
                                                          link_text='Malware')
                assessment_setting.malware_switch.set_toggle(malware_switch)
                assessment_setting.click_link_inside_link(setting_value=Nessus.Scan.SettingsTypes.ASSESSMENT,
                                                          link_text='General')
            elif Nessus.TemplateNames.BASIC_AGENT in scan_name:

                assessment_setting.click_by_link_text(setting_value=Nessus.Scan.SettingsTypes.ASSESSMENT)
                assessment_setting.scan_type.select_by_visible_text('Custom')

                assessment_setting.click_link_inside_link(setting_value=Nessus.Scan.SettingsTypes.ASSESSMENT,
                                                          link_text='General')
                assessment_setting.anti_grace_period.select_by_visible_text('%s' % grace_period_day)

                assessment_setting.click_link_inside_link(setting_value=Nessus.Scan.SettingsTypes.ASSESSMENT,
                                                          link_text='Windows')
                assessment_setting.get_checkbox_element_for_value(check_box_value=smb_domain_request).set_checked(
                    smb_domain)
            elif Nessus.TemplateNames.MALWARE in scan_name:
                assessment_setting.click_by_link_text(setting_value=Nessus.Scan.SettingsTypes.ASSESSMENT)
                assessment_setting.click_link_inside_link(setting_value=Nessus.Scan.SettingsTypes.ASSESSMENT,
                                                          link_text='Malware')
                assessment_setting.malware_switch.set_toggle(malware_switch)

            ScansPage().save_button.click()

            assert Notifications().successes[-1] == "Scan saved successfully.", \
                "Notification is missing after saving the scan"

            SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
            ScanList().click_on_scan(scan_name=scan_name)
            scan_view_page.configure_button.click()
            wait(lambda: scan_form.is_element_present('name_field'), timeout_seconds=TIME_THIRTY_SECONDS,
                 sleep_seconds=WAIT_SHORT, waiting_for="Scan configure page to get loaded properly.")

            if Nessus.TemplateNames.ADVANCED_AGENT in scan_name:

                assessment_setting.click_link_inside_link(setting_value=Nessus.Scan.SettingsTypes.ASSESSMENT,
                                                          link_text='General')
                assert int(assessment_setting.anti_grace_period.value) > 0, 'Period is not greater than zero'

                assessment_setting.click_link_inside_link(setting_value=Nessus.Scan.SettingsTypes.ASSESSMENT,
                                                          link_text='Windows')
                assert assessment_setting.get_checkbox_element_for_value(
                    check_box_value=smb_domain_request).is_selected() == smb_domain,\
                    "Unable to uncheck {0} under Windows.".format(smb_domain_request)

                assessment_setting.click_link_inside_link(setting_value=Nessus.Scan.SettingsTypes.ASSESSMENT,
                                                          link_text='Malware')
                assert assessment_setting.malware_switch.is_selected() == malware_switch, \
                    'Malware toggle value is not saved'

            elif Nessus.TemplateNames.BASIC_AGENT in scan_name:

                assessment_setting.click_by_link_text(setting_value=Nessus.Scan.SettingsTypes.ASSESSMENT)
                assessment_setting.scan_type.select_by_visible_text('Custom')

                assessment_setting.click_link_inside_link(setting_value=Nessus.Scan.SettingsTypes.ASSESSMENT,
                                                          link_text='General')
                assert int(assessment_setting.anti_grace_period.value) > 0, 'Period is not greater than zero'
                assessment_setting.click_link_inside_link(setting_value=Nessus.Scan.SettingsTypes.ASSESSMENT,
                                                          link_text='Windows')
                assert assessment_setting.get_checkbox_element_for_value(
                    check_box_value=smb_domain_request).is_selected() == smb_domain, \
                    "Unable to uncheck {0} under Windows.".format(smb_domain_request)
            else:
                assessment_setting.click_link_inside_link(setting_value=Nessus.Scan.SettingsTypes.ASSESSMENT,
                                                          link_text='Malware')
                assert assessment_setting.malware_switch.is_selected() == malware_switch, \
                    'Malware toggle value is not saved'

            # Delete Scan
            TestAgentScanEdit.delete_agent_scan(scan_name)

    @pytest.mark.parametrize("scan_result", [False])
    def test_create_scan_and_edit_report_setting(self, create_agent_groups, create_scans, scan_result, test_data):
        """
        NQA-1267: Edit created scan with 'Reports' settings
        1. Edit the scan with below configurations
        2. Uncheck 'Allow users to edit scan results'
        3. Hit save and verify success notification
        4. Get back to edited changes and verify changes retained its values.
        """
        agent_group = create_agent_groups[0]
        scan_name = create_scans[0]
        scan_form = NewScanForm()
        scan_form.fill_new_scan_detail(agent_group=agent_group)

        if Nessus.TemplateNames.SCAP_OVAL_AGENT in scan_name:
            ScapAndOvalForm().open_form_and_fill_details(form_information=[test_data])[0].get(
                test_data.get('form_type'))

        scan_form.save_button.click()
        ScanList().click_on_scan(scan_name=scan_name)
        LoadingCircle(WAIT_SHORT)

        scan_view_page = ScanViewPage()
        scan_view_page.configure_button.click()
        wait(lambda: scan_form.is_element_present('name_field'), timeout_seconds=TIME_THIRTY_SECONDS,
             sleep_seconds=WAIT_SHORT, waiting_for="Scan configure page to get loaded properly.")

        output = 'Allow users to edit scan results'
        scan_setting = ScanSettings()
        scan_setting.click_by_link_text(setting_value=Nessus.Scan.SettingsTypes.REPORT)
        scan_setting.get_checkbox_element_for_value(check_box_value=output).set_checked(scan_result)
        ScansPage().save_button.click()


        assert Notifications().successes[-1] == "Scan saved successfully.", \
            "Notification is missing after saving the scan"

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        ScanList().click_on_scan(scan_name=scan_name)
        scan_view_page.configure_button.click()
        wait(lambda: scan_form.is_element_present('name_field'), timeout_seconds=TIME_THIRTY_SECONDS,
             sleep_seconds=WAIT_SHORT, waiting_for="Scan configure page to get loaded properly.")
        discovery_setting = DiscoverySetting()
        discovery_setting.click_by_link_text(setting_value=Nessus.Scan.SettingsTypes.REPORT)

        assert discovery_setting.get_checkbox_element_for_value(
            check_box_value=output).is_selected() == scan_result, "Unable to uncheck {0} under Output.".format(output)

        # Delete Scan
        TestAgentScanEdit.delete_agent_scan(scan_name)

    @pytest.mark.parametrize("log_scan", [True])
    def test_create_scan_and_edit_advance_setting(self, create_agent_groups, create_scans, log_scan, test_data):
        """
        NQA-1267: Edit created scan with 'Advanced' settings
        1. Edit the scan with below configurations
        2. Check 'Log scan details' under 'Debug settings' in 'Advanced'
        3. Hit save and verify success notification
        4. Get back to edited changes and verify changes retained its values.
        """
        agent_group = create_agent_groups[0]
        scan_name = create_scans[0]
        scan_form = NewScanForm()
        scan_form.fill_new_scan_detail(agent_group=agent_group)

        if Nessus.TemplateNames.SCAP_OVAL_AGENT in scan_name:
            ScapAndOvalForm().open_form_and_fill_details(form_information=[test_data])[0].get(
                test_data.get('form_type'))

        scan_form.save_button.click()
        ScanList().click_on_scan(scan_name=scan_name)
        LoadingCircle(WAIT_SHORT)

        scan_view_page = ScanViewPage()
        scan_view_page.configure_button.click()
        wait(lambda: scan_form.is_element_present('name_field'), timeout_seconds=TIME_THIRTY_SECONDS,
             sleep_seconds=WAIT_SHORT, waiting_for="Scan configure page to get loaded properly.")

        debug_setting = 'Log scan details'
        scan_setting = AdvancedSetting()
        scan_setting.click_by_link_text(setting_value=Nessus.Scan.SettingsTypes.ADVANCED)
        scan_setting.get_checkbox_element_for_value(check_box_value=debug_setting).set_checked(log_scan)
        ScansPage().save_button.click()


        assert Notifications().successes[-1] == "Scan saved successfully.", \
            "Notification is missing after saving the scan"

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        ScanList().click_on_scan(scan_name=scan_name)
        scan_view_page.configure_button.click()
        wait(lambda: scan_form.is_element_present('name_field'), timeout_seconds=TIME_THIRTY_SECONDS,
             sleep_seconds=WAIT_SHORT, waiting_for="Scan configure page to get loaded properly.")
        discovery_setting = DiscoverySetting()
        discovery_setting.click_by_link_text(setting_value=Nessus.Scan.SettingsTypes.ADVANCED)

        assert discovery_setting.get_checkbox_element_for_value(
            check_box_value=debug_setting).is_selected() == log_scan, \
            "Unable to check {0} under Debug Setting.".format(debug_setting)

        # Delete Scan
        TestAgentScanEdit.delete_agent_scan(scan_name)
