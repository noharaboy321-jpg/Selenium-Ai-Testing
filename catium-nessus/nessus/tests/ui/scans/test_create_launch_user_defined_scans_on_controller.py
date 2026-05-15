"""
Nessus test cases related to User-defined Scans on Controller

:copyright: Tenable Network Security, 2018
:date: October 09, 2018
:last_modified: June 19, 2020
:author: @rdutta, @kpanchal
"""
import time
from datetime import datetime, timedelta

import pytest

from catium.helpers.sleep_lib import sleep
from catium.lib.const.base_constants import WAIT_NORMAL, TIME_THREE_SECONDS
from catium.lib.log import create_logger
from catium.lib.util.util import random_name
from catium.lib.webium.wait import wait
from nessus.helpers.polling_ui import polling_ui
from nessus.helpers.scan import delete_created_scan
from nessus.lib.const.constants import Nessus, API
from nessus.lib.message.messages import Messages
from nessus.pageobjects.credentials.host import Password
from nessus.pageobjects.dynamic_plugins.dynamic_plugins_page import DynamicPlugin
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.policies.policies_page import PoliciesPage, PolicyList
from nessus.pageobjects.scans.new_scan_form import NewScanForm
from nessus.pageobjects.scans.scan_basic_settings_page import BasicSetting
from nessus.pageobjects.scans.scan_view_page import ScanViewPage, VulnerabilityList
from nessus.pageobjects.scans.scans_page import ScanList, ScansPage
from nessus.pageobjects.sidenav.sidenav import SideNav

log = create_logger()


@pytest.mark.scanning
@pytest.mark.nessus_home
@pytest.mark.nessus_pro
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login', 'create_new_folder')
class TestCreateAndLaunchUserDefinedScansOnController:
    """Covers test cases related to User defined Scans on Controller."""
    cat = None

    @pytest.mark.parametrize('create_policies', [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED_DYNAMIC, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix='{} Policy - '.format(Nessus.TemplateNames.ADVANCED_DYNAMIC)),
         'description': 'Created scanner policy for Advanced Dynamic Scan.',
         'add_configuration': True}]}], indirect=True)
    def test_user_defined_scan_with_advanced_dynamic_policy(self, create_policies):
        """
        #NQA-1301 : Automation tests for Dynamic Scan.(step-1)
        Test to create and launch a scan with advanced dynamic policy

        1. Create a policy using 'Advanced Dynamic Scan' template
        2. Add all mandatory details in 'Setting' tab
        3. Navigate to 'Dynamic Plugins' tab
        4. Add atleast one plugin filter (eg. PluginName contains 'Nessus')
        5. Save policy, verify success notifications
        6. Now create a scan with above defined policy and launch it.
        7. verify scan is completed successfully and there are no errors on controller
        8. It should shows up vulnerabilities in scan results related to choosed dynamic plugins only in scan result
        9. Verify scan must be launch on scheduled time and completed successfully.
        """
        policy_name = create_policies[0]

        # Add settings
        Password(host_type=API.Credentials.Host.Types.SSH).fill_password_ssh_form(
            username=Nessus.USERNAME, password=Nessus.PASSWORD, auth=API.Credentials.Host.SSHAuthTypes.PASSWORD)

        # Add dynamic plugins filter
        dynamic_plugins = DynamicPlugin()
        dynamic_plugins.manage_dynamic_plugins(add_plugins=True, preview_plugins=False, plugins_filter_list=[
            {Nessus.Filter.INDEX: 1, Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_NAME,
             Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.CONTAINS, Nessus.Filter.VALUE: 'nessus'}])

        # Save policy, verify success notifications
        dynamic_plugins.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.Policies.policy_saved, \
            "Success notification for saving policy is missing or mismatched."

        SideNav().get_sidenav_element(Nessus.Scan.Folder.MY_SCANS).click()
        sleep(sleep_time=TIME_THREE_SECONDS, reason='Waiting to scan page gets loaded properly')

        # Create a scan with above defined policy
        scan_name = 'Scan with {}'.format(policy_name)
        ScansPage().create_new_scan(scan_type=Nessus.Scan.ScanTemplateTabs.USER_DEFINED_TAB,
                                    scan_template=policy_name, scan_name=scan_name, add_configuration=True,
                                    target_ip=Nessus.Scan.Target.LOCALHOST,
                                    description='Created a user defined scan with {} policy for NQA-1301.'.format(
                                        Nessus.TemplateNames.ADVANCED_DYNAMIC.lower()))

        NewScanForm().save_button.click()
        scan_list = ScanList()
        scan_list.launch_scan_and_wait_for_status(scan_name=scan_name)
        # Navigate to scan results page and verify added plugins in results
        scan_list.click_on_scan(scan_name=scan_name)
        sleep(sleep_time=WAIT_NORMAL, reason='waiting for scan result page to be loaded')

        scan_details_page = ScanViewPage()
        scan_details_page.vulnerability_tab.click()

        assert ['nessus' in plugin_name for plugin_name in VulnerabilityList().get_plugin_names()], \
            'Applied filter value does not matched with scan result value.'

        # clean up code for created scan
        scan_details_page.back_link.click()
        sleep(sleep_time=WAIT_NORMAL, reason='waiting for scan page to be loaded')

        delete_created_scan(scan_name=scan_name)

    @pytest.mark.parametrize('create_policies', [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED_DYNAMIC, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix='{} Policy - '.format(Nessus.TemplateNames.ADVANCED_DYNAMIC)),
         'description': 'Created scanner policy for Advanced Dynamic Scan.',
         'add_configuration': True}]}], indirect=True)
    def test_user_defined_scheduled_scan_with_advanced_dynamic_policy(self, create_policies):
        """
        #NQA-1301 : Automation tests for Dynamic Scan.(step-1)
        Test to create and launch a scan with advanced dynamic policy

        1. Create a policy using 'Advanced Dynamic Scan' template
        2. Add all mandatory details in 'Setting' tab
        3. Enable Schedule toggle and set schedule information only if it is a schedule scan.
        4. Navigate to 'Dynamic Plugins' tab
        5. Add atleast one plugin filter (eg. PluginName contains 'Nessus')
        6. Save policy, verify success notifications
        7. Now create a scan with above defined policy and launch it.
        8. verify scan is completed successfully and there are no errors on controller
        9. It should shows up vulnerabilities in scan results related to choosed dynamic plugins only in scan result
        10. For Scheduled Scan, scan must be launch on scheduled time and completed successfully.
        """
        # Get system's timezone and mark the test accordingly as scheduling of scan depends on it.
        log.debug(msg='You are currently in {} timezone.'.format(time.tzname))
        if 'UTC' not in time.tzname:
            SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()
            pytest.xfail(reason='Can\'t proceed further as we are supporting only UTC timezone for scheduled scan')

        policy_name = create_policies[0]

        # Add settings
        Password(host_type=API.Credentials.Host.Types.SSH).fill_password_ssh_form(
            username=Nessus.USERNAME, password=Nessus.PASSWORD, auth=API.Credentials.Host.SSHAuthTypes.PASSWORD)

        # Add dynamic plugins filter
        dynamic_plugins = DynamicPlugin()
        dynamic_plugins.manage_dynamic_plugins(add_plugins=True, preview_plugins=False, plugins_filter_list=[
            {Nessus.Filter.INDEX: 1, Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_NAME,
             Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.CONTAINS, Nessus.Filter.VALUE: 'nessus'}])

        # Save policy, verify success notifications
        dynamic_plugins.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.Policies.policy_saved, \
            "Success notification for saving policy is missing or mismatched."

        SideNav().get_sidenav_element(Nessus.Scan.Folder.MY_SCANS).click()
        scan_list = ScanList()
        scan_list.loaded()

        # Create a scan with above defined policy
        scan_name = 'Scan with {}'.format(policy_name)
        ScansPage().create_new_scan(scan_type=Nessus.Scan.ScanTemplateTabs.USER_DEFINED_TAB,
                                    scan_template=policy_name, scan_name=scan_name, add_configuration=True,
                                    target_ip=Nessus.Scan.Target.LOCALHOST,
                                    description='Created a user defined scan with {} policy for NQA-1301.'.format(
                                        Nessus.TemplateNames.ADVANCED_DYNAMIC.lower()))

        # scan scheduling information
        schedule_info = {'schedule_date': datetime.today().date(), 'schedule_timezone': time.tzname[0],
                         'schedule_time': (datetime.today() + timedelta(minutes=4)).time(),
                         'schedule_frequency': API.Schedule.Frequencies.FREQ_ONCE.title()}

        # Enable Schedule toggle and set schedule information only if it is a schedule scan
        BasicSetting().schedule_scan(**schedule_info)

        new_scan_form = NewScanForm()
        new_scan_form.save_button.click()

        # If there's a schedule warning prompt (on Essentials), confirm it
        if new_scan_form.is_element_present('schedule_confirmation_button'):
            new_scan_form.schedule_confirmation_button.click()

        scan_list.loaded()
        with polling_ui():
            scan_list.launch_scan_and_wait_for_status(is_scheduled_scan=True, scan_name=scan_name, launch_scan=False)
        # Navigate to scan results page and verify added plugins in results
        scan_list.click_on_scan(scan_name=scan_name)

        scan_details_page = ScanViewPage()
        wait(lambda: scan_details_page.is_element_present('vulnerability_tab'), waiting_for='scan view page to load')
        scan_details_page.vulnerability_tab.click()

        assert ['nessus' in plugin_name for plugin_name in VulnerabilityList().get_plugin_names()], \
            'Applied filter value does not matched with scan result value.'

        # clean up code for created scan
        scan_details_page.back_link.click()
        scan_list.loaded()

        delete_created_scan(scan_name=scan_name)


@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('login')
@pytest.mark.parametrize("create_policies", [{'policies_details': [
    {"template_name": Nessus.TemplateNames.BASIC_NETWORK, "type": API.Permissions.Types.SCANNER},
    {"template_name": Nessus.TemplateNames.ADVANCED, "type": API.Permissions.Types.SCANNER},
    {"template_name": Nessus.TemplateNames.BASIC_NETWORK, "type": API.Permissions.Types.SCANNER},
    {"template_name": Nessus.TemplateNames.ADVANCED, "type": API.Permissions.Types.SCANNER}]}], indirect=True)
class TestUserDefinedScanTemplatesOrder:

    def test_user_defined_scan_templates_ordering(self, create_policies):
        """
        NES-9857 - UI automation for Scan Library Org NES-9820

        Scenarios:
            [x] Verify that scan templates are organized in alphabetical order on user defined tab..

        Steps:
        1. Login to Nessus.
        2. Create Policies
        3. Go to User defined tab and verify that Scan templates are organized in alphabetical order.
        4. Delete policies and logout from Nessus.
        """
        wait(lambda: PoliciesPage().is_element_present('policies_searchbox'), waiting_for='Policies page to load')

        all_policies_names = PolicyList().get_all_policies()

        assert set(create_policies).issubset(all_policies_names), \
            "All created policies does not appear on Policies page."

        scan_page = ScansPage()
        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()

        wait(lambda: scan_page.is_element_present('create_a_new_scan_link') or scan_page.is_element_present(
            'scan_searchbox'), waiting_for='Scan page to load properly')

        scan_page.new_scan_button.click()
        wait(lambda: scan_page.is_element_present('scanner'), waiting_for='New scan page to load properly')

        scan_page.select_scan_type(type_of_scan=Nessus.Scan.ScanTemplateTabs.USER_DEFINED_TAB)

        scan_templates_list_on_user_defined_tab = scan_page.get_all_scan_templates(
            scan_type=API.Permissions.Types.USER_DEFINED)
        all_policies_names.sort()

        # Verify that scan templates are organized in alphabetical order on user defined tab.
        assert all_policies_names == scan_templates_list_on_user_defined_tab, \
            "User defined scan templates are not organized in alphabetical order"
