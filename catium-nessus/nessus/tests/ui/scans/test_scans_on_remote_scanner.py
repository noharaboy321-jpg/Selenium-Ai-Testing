"""
Nessus test cases related to scans on remote scanner with different scan templates

:copyright: Tenable Network Security, 2017
:date: Nov 14, 2017
:last_modified: Nov 07, 2018
:author: @mameta, @rdutta
"""

import time
from datetime import datetime, timedelta

import pytest
from selenium.webdriver.support.expected_conditions import visibility_of_element_located

from catium.helpers.sleep_lib import sleep
from catium.lib.const import WAIT_NORMAL, TIME_SIXTY_SECONDS
from catium.lib.const import WAIT_SHORT
from catium.lib.const.base_constants import TIME_THREE_SECONDS, WAIT_LONG
from catium.lib.log.log import create_logger
from catium.lib.util import random_name
from catium.lib.webium.wait import wait
from nessus.helpers.polling_ui import polling_ui
from nessus.helpers.scan import get_scan_id, scan_save_launch_and_status_verification, delete_created_scan, \
    save_and_configure_scan
from nessus.helpers.scanner import get_remote_scanner
from nessus.lib.const.compliance_constants import ComplianceConst
from nessus.lib.const.constants import Nessus, API
from nessus.pageobjects.compliances.compliance_page import Compliance
from nessus.pageobjects.credentials.host import Password
from nessus.pageobjects.dynamic_plugins.dynamic_plugins_page import DynamicPlugin
from nessus.pageobjects.plugins.plugins_page import Plugin, PluginFamilyList, PluginsList
from nessus.pageobjects.scans.scan_basic_settings_page import BasicSetting
from nessus.pageobjects.scans.scan_view_page import ScanViewPage, VulnerabilityList, ScansHostList
from nessus.pageobjects.scans.scans_page import ScansPage, ScanList
from nessus.pageobjects.scap.scap_page import ScapAndOvalForm
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav

log = create_logger()


@pytest.mark.scanning
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login', 'login', 'create_new_folder')
class TestScansOnRemoteScanner:
    """Covers test cases related to scans on remote scanner with different scan templates."""
    cat = None

    @pytest.mark.parametrize('data_to_be_scanned', [
        {'all_plugin_families': {'scan_name': 'NQA-399 - Advanced All Plugins'}},
        {'custom_one_plugin_family': {'scan_name': 'NQA-399 - Advanced Custom One Pluginset',
                                      'plugin_family': 'Settings'}},
        {'custom_couple_plugin_family': {'scan_name': 'NQA-399 - Advanced Custom Couple Pluginset',
                                         'plugin_set': [{'plugin_family': 'General', 'plugin_id_list': ['42084']},
                                                        {'plugin_family': 'Settings', 'plugin_id_list': ['60024']}]}},
        {'all_plugin_families_with_compliance': {
            'scan_name': 'NQA-399 - Advanced All Plugins w/ compliance',
            'compliance_to_scan': [
                {'category_type': ComplianceConst.UNIX, 'file': 'CIS_Red_Hat_EL6_Server_L1_v2.0.2.audit',
                 'file_path': 'nessus/tests/ui/scan/test_data/'},
                {'category_type': ComplianceConst.WINDOWS, 'file': 'CIS_MS_Windows_7_L1_v3.0.1.audit',
                 'file_path': 'nessus/tests/ui/scan/test_data/'}]}}])
    def test_advanced_scan_with_different_plugins_compliance(self, create_new_folder, data_to_be_scanned):
        """
        #NQA-399 : Short Cycle - Scanner - Stage 3 - Scans.
        1. Create an Advanced Scan against remote scanner with different plugins and compliance enabled
        2. Verify scan is completed successfully and there are no errors on controller
        """
        # get remote scanner to add in scan configuration
        remote_scanners = get_remote_scanner(api=self.cat.api)
        LoadingCircle(TIME_THREE_SECONDS)
        remote_scanner = remote_scanners[0] if remote_scanners \
            else pytest.xfail("Can't proceed further as no remote scanner linked to the product.")

        folder_name = create_new_folder[1]
        type_of_data_to_be_scanned = list(data_to_be_scanned.keys())[0]
        scan_name = data_to_be_scanned.get(type_of_data_to_be_scanned).get('scan_name')
        LoadingCircle(WAIT_NORMAL)

        # Create scan with data to be scanned
        ScansPage().create_new_scan(
            scan_template=Nessus.TemplateNames.ADVANCED, scan_type=Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
            scan_name=scan_name, scanner=remote_scanner, folder=folder_name, target_ip=Nessus.Scan.Target.LOCALHOST,
            description='Created an Advanced Scan with {}.'.format(type_of_data_to_be_scanned), add_configuration=True)

        # Configure with required data (credentials/compliance/plugins) to be scanned
        LoadingCircle(TIME_THREE_SECONDS)
        Password(host_type=API.Credentials.Host.Types.SSH).fill_password_ssh_form(
            username=Nessus.USERNAME, password=Nessus.PASSWORD, auth=API.Credentials.Host.SSHAuthTypes.PASSWORD)
        Password(host_type=API.Credentials.Host.Types.WINDOWS).fill_password_windows_form(
            username=Nessus.USERNAME, password=Nessus.PASSWORD, domain=Nessus.Scan.Target.AWS_LINUX_TARGET_2,
            auth=API.Credentials.Host.WindowsAuthTypes.PASSWORD)

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

                LoadingCircle(WAIT_SHORT)
                compliance_page.add_audit_and_config_file(audit_file_name=compliance.get('file'),
                                                          audit_file_path=compliance.get('file_path'))

        # Save scan, launch it and verify it's successful completion
        LoadingCircle(TIME_THREE_SECONDS)
        assert scan_save_launch_and_status_verification(scan_name=scan_name, scan_folder_name=folder_name), \
            'Scan has not been completed successfully.'

        # Delete the created scan
        delete_created_scan(scan_name=scan_name)

    @pytest.mark.parametrize('templates_to_scan', [
        {'scan_template': Nessus.TemplateNames.BASIC_NETWORK, 'scan_name': 'NQA-399 - Basic Network Scan'},
        {'scan_template': Nessus.TemplateNames.MALWARE, 'scan_name': 'NQA-399 - Malware Scan'},
        {'scan_template': Nessus.TemplateNames.HOST_DISCOVERY, 'scan_name': 'NQA-399 - Host Discovery Scan'},
        {'scan_template': Nessus.TemplateNames.SCAP_OVAL, 'scan_name': 'NQA-399 - SCAP and OVAL'},
        {'scan_template': Nessus.TemplateNames.COMPLIANCE_AUDIT, 'scan_name': 'NQA-399 - PCI Scan',
         'compliance_to_scan': [
             {'category_type': ComplianceConst.UNIX, 'file_path': 'nessus/tests/ui/scan/test_data/',
              'file': 'CIS_Red_Hat_EL6_Server_L1_v2.0.2.audit'},
             {'category_type': ComplianceConst.WINDOWS_FILE_CONTENTS, 'file_path': 'nessus/tests/ui/scan/test_data/',
              'file': 'CIS_MS_Windows_7_L1_v3.0.1.audit'}]}])
    def test_scanner_scans_with_different_templates(self, create_new_folder, templates_to_scan):
        """
        #NQA-399 : Short Cycle - Scanner - Stage 3 - Scans.
        1. Create scanner scan against remote scanner with different templates with required data
        2. Verify scan is completed successfully and there are no errors on controller
        3. For Host Discovery scan, verify "Ping on the remote host" vulnerability is returned after
            successful completion of the scan
        """
        # get remote scanner to add in scan configuration
        remote_scanners = get_remote_scanner(api=self.cat.api)
        LoadingCircle(TIME_THREE_SECONDS)
        remote_scanner = remote_scanners[0] if remote_scanners \
            else pytest.xfail("Can't proceed further as no remote scanner linked to the product.")

        folder_name = create_new_folder[1]
        scan_name = templates_to_scan.get('scan_name')
        LoadingCircle(WAIT_NORMAL)

        # Create scan with data to be scanned
        ScansPage().create_new_scan(
            scan_template=templates_to_scan.get('scan_template'), scan_type=Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
            scan_name=scan_name, scanner=remote_scanner, folder=folder_name, target_ip=Nessus.Scan.Target.LOCALHOST,
            description='Created a {} Scan for NQA-399.'.format(templates_to_scan.get('scan_template').lower()),
            add_configuration=True)

        # Configure with required data (credentials/compliance/scap) to be scanned
        LoadingCircle(TIME_THREE_SECONDS)
        if templates_to_scan.get('scan_template') != Nessus.TemplateNames.HOST_DISCOVERY:
            Password(host_type=API.Credentials.Host.Types.SSH).fill_password_ssh_form(
                username=Nessus.USERNAME, password=Nessus.PASSWORD, auth=API.Credentials.Host.SSHAuthTypes.PASSWORD)
            Password(host_type=API.Credentials.Host.Types.WINDOWS).fill_password_windows_form(
                username=Nessus.USERNAME, password=Nessus.PASSWORD, domain=Nessus.Scan.Target.AWS_LINUX_TARGET_2,
                auth=API.Credentials.Host.WindowsAuthTypes.PASSWORD)

        if templates_to_scan.get('scan_template') == Nessus.TemplateNames.SCAP_OVAL:
            LoadingCircle(TIME_THREE_SECONDS)
            scap_page = ScapAndOvalForm()
            scap_page.open_form_and_fill_details(
                form_information=API.Scap.SCAP_AND_OVAL_INFORMATION)

        if templates_to_scan.get('scan_template') == Nessus.TemplateNames.COMPLIANCE_AUDIT:
            LoadingCircle(TIME_THREE_SECONDS)
            compliance_page = Compliance()
            for compliance in templates_to_scan.get('compliance_to_scan'):
                LoadingCircle(TIME_THREE_SECONDS)
                compliance_page.click_compliance_type(category_name=compliance.get('category_type'),
                                                      compliance_type="Upload a custom {} audit file".
                                                      format(compliance.get('category_type')))
                LoadingCircle(WAIT_SHORT)
                compliance_page.add_audit_and_config_file(audit_file_name=compliance.get('file'),
                                                          audit_file_path=compliance.get('file_path'))

        # Save scan, launch it and verify it's successful completion
        LoadingCircle(TIME_THREE_SECONDS)
        assert scan_save_launch_and_status_verification(scan_name=scan_name, scan_folder_name=folder_name), \
            'Scan has not been completed successfully.'

        LoadingCircle(WAIT_NORMAL)
        ScanList().click_on_scan(scan_name=scan_name)
        LoadingCircle(WAIT_NORMAL)
        scan_details_page = ScanViewPage()
        scan_details_page.vulnerability_tab.click()

        vulns_list = VulnerabilityList()
        if templates_to_scan.get('scan_template') == Nessus.TemplateNames.HOST_DISCOVERY:
            assert Nessus.Scan.Vulnerability.PING_THE_REMOTE_HOST in vulns_list.get_plugin_names(), \
                "Expected vulnerability hadn't been returned for {} scan.".format(Nessus.TemplateNames.HOST_DISCOVERY)
        else:
            assert vulns_list.get_total_rows(), \
                'No vulnerabilities found against {} scan.'.format(templates_to_scan.get('scan_template'))

        # Delete the created scan
        delete_created_scan(scan_name=scan_name)

    @pytest.mark.nessus_home
    def test_real_time_scan_result_update(self, create_new_folder):
        """
        #NQA-366 : Scanner - Managed - Ensure scan results can be viewed in real time while scan is occurring.
        1. Create a scan and launched it on the managed scanner.
        2. Make sure to use a couple of hosts or even a subnet so the scan lasts long enough to test properly.
        3. Click on the running scan to drill into it
        4. Navigate to Hosts tab, this will force the scanner to attempt to get live results from the managed scanner.
        5. Ensure that in a few seconds the managed scanner uploads scan results and
            the progress of the scan is available.
        6. Watching over time should see info/vulnerability increases and the % complete should also increase.
        """
        # get remote scanner to add in scan configuration
        remote_scanners = get_remote_scanner(api=self.cat.api)
        LoadingCircle(TIME_THREE_SECONDS)
        remote_scanner = remote_scanners[0] if remote_scanners \
            else pytest.xfail("Can't proceed further as no remote scanner linked to the product.")

        folder_name = create_new_folder[1]
        scan_name = "NQA-366 - Advanced Scan"

        # Create scan with required data
        ScansPage().create_new_scan(
            scan_template=Nessus.TemplateNames.ADVANCED, scan_type=Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
            scan_name=scan_name, description='Created an Advanced Scan for NQA-399.', folder=folder_name,
            target_ip='{}, {}, {}'.format(Nessus.Scan.Target.LOCALHOST, Nessus.Scan.Target.AWS_LINUX_TARGET_1,
                                          Nessus.Scan.Target.AWS_LINUX_TARGET_2), scanner=remote_scanner)

        LoadingCircle(TIME_THREE_SECONDS)
        scan_list = ScanList()
        scan_list.refresh()
        LoadingCircle(TIME_THREE_SECONDS)
        SideNav().get_sidenav_element(element_name=folder_name).click()
        LoadingCircle(WAIT_NORMAL)
        scan_id = get_scan_id(scan_name=scan_name, api_object=__class__.cat.api)  # pylint: disable=undefined-variable

        if scan_list.launch_scan_and_wait_for_status(scan_name=scan_name, status=API.Scan.Status.RUNNING):
            scan_list.click_on_scan(scan_name)
            LoadingCircle(WAIT_SHORT)
            ScanViewPage().host_tab.click()
            LoadingCircle(WAIT_SHORT)

            with polling_ui():
                scan_host_list = ScansHostList()
                wait(lambda: not scan_host_list.object_table.is_empty(), timeout_seconds=TIME_SIXTY_SECONDS,
                     waiting_for='Scan host list gets updated')
                initial_progress = scan_host_list.get_hosts_percentage()

                checks_count, verified_hosts = 0, []
                while self.cat.api.scans.get_status(scan_id=scan_id) == API.Scan.Status.RUNNING and checks_count < 2:
                    latest_progress = scan_host_list.get_hosts_percentage()
                    for host, progress in latest_progress.items():
                        try:
                            if host not in verified_hosts:
                                previous_sample = initial_progress[host]
                                if progress > previous_sample:
                                    verified_hosts.append(host)
                                    checks_count += 1
                        except KeyError:
                            initial_progress[host] = progress

                assert checks_count > 1, 'scan results progress cannot be viewed in real time while scan is running.'

        SideNav().get_sidenav_element(element_name=folder_name).click()
        LoadingCircle(WAIT_NORMAL)
        if self.cat.api.scans.get_status(scan_id=scan_id) == API.Scan.Status.RUNNING:
            scan_list.stop_scan(scan_name)
            LoadingCircle(WAIT_LONG)

        # Delete the created scan
        delete_created_scan(scan_name=scan_name)

    @pytest.mark.nessus_home
    @pytest.mark.parametrize('scan_type', ['Default_Scan', 'Schedule_Scan'])
    def test_advanced_dynamic_scan_on_remote_scanner(self, create_new_folder, scan_type):
        """
        # NQA-1301 : Automation tests for Dynamic Scan. (step: 17)
        Test to create and launch an advanced dynamic scan in remote scanner

        1. Create a Scan using 'Advanced Dynamic Scan' template
        2. Add all mandatory details in 'Setting' tab, and select remote scanner.
        3. Enable Schedule toggle and set schedule information only if it is a schedule scan.
        4. Navigate to 'Dynamic Plugins' tab
        5. Add atleast one plugin filter (eg. PluginName contains 'Nessus')
        6. Save scan, verify success notifications and Launch it
        7. Verify scan is completed successfully and there are no errors on controller
        8. It should shows up vulnerabilities in scan results related to choosed dynamic plugins only in scan result
        9. For Scheduled Scan, scan must be launch on scheduled time and completed successfully.
        """
        # get remote scanner to add in scan configuration
        remote_scanners = get_remote_scanner(api=self.cat.api)
        LoadingCircle(TIME_THREE_SECONDS)
        remote_scanner = remote_scanners[0] if remote_scanners \
            else pytest.xfail("Can't proceed further as no remote scanner linked to the product.")

        # Get system's timezone and mark the test accordingly as scheduling of scan depends on timezone.
        log.debug(msg='You are currently in {} timezone.'.format(time.tzname))
        if (scan_type == 'Schedule_Scan') and ('UTC' not in time.tzname):
            pytest.xfail('Can\'t proceed further as we are supporting only UTC timezone for scheduled scan')

        # scan scheduling information
        schedule_info = {'schedule_date': datetime.today().date(), 'schedule_timezone': time.tzname[0],
                         'schedule_time': (datetime.today() + timedelta(minutes=2)).time(),
                         'schedule_frequency': API.Schedule.Frequencies.FREQ_ONCE.title()}
        custom_scan_folder = create_new_folder[1]
        scan_name = random_name(prefix='{} Scan - '.format(Nessus.TemplateNames.ADVANCED_DYNAMIC))

        # Create scan with settings data
        ScansPage().create_new_scan(scan_template=Nessus.TemplateNames.ADVANCED_DYNAMIC, scan_name=scan_name,
                                    scan_type=Nessus.Scan.ScanTemplateTabs.SCANNER_TAB, scanner=remote_scanner,
                                    description='Created an {} on remote scanner for NQA-1301.'.format(
                                        Nessus.TemplateNames.ADVANCED_DYNAMIC.lower()), folder=custom_scan_folder,
                                    target_ip=Nessus.Scan.Target.LOCALHOST, add_configuration=True)

        # Add credentials and set schedule information if it is a scheduled scan
        if scan_type == 'Schedule_Scan':
            schedule_summary = BasicSetting().schedule_scan(**schedule_info)
        Password(host_type=API.Credentials.Host.Types.SSH).fill_password_ssh_form(
            username=Nessus.USERNAME, password=Nessus.PASSWORD, auth=API.Credentials.Host.SSHAuthTypes.PASSWORD)

        # Add dynamic plugins filter
        DynamicPlugin().manage_dynamic_plugins(add_plugins=True, preview_plugins=False, plugins_filter_list=[
            {Nessus.Filter.INDEX: 1, Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_NAME,
             Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.CONTAINS, Nessus.Filter.VALUE: 'nessus'}])

        # Verify scan save and completed successfully
        assert scan_save_launch_and_status_verification(scan_name=scan_name, scan_folder_name=custom_scan_folder,
                                                        is_scan_scheduled=(scan_type == 'Schedule_Scan')), \
            'Scan has not been completed successfully.'

        # Navigate to scan results page and verify added plugins in results
        ScanList().click_on_scan(scan_name=scan_name)
        sleep(sleep_time=WAIT_NORMAL, reason='waiting for scan results page to be loaded')
        scan_details_page = ScanViewPage()
        scan_details_page.vulnerability_tab.click()

        # Verify scan must be launched on scheduled time
        if scan_type == 'Schedule_Scan':
            scan_start_time = scan_details_page.get_levels_value_of_details_section(
                Nessus.Scan.Results.ScanDetailsLevels.SCAN_START_TIME).text
            if scan_start_time.split(' at')[0] == 'Today':
                scan_start_time = datetime.strftime(datetime.today().date(), '%A, %B %dth, %Y') + \
                                  ' at{}'.format(scan_start_time.split(' at')[1])
                scheduled_time = schedule_summary.split('on ')[1]
            else:
                sc_summary = schedule_summary.split(', ')[1:]
                scheduled_time = sc_summary[0][:-2] + sc_summary[1][4:]

            assert scan_start_time == scheduled_time, 'Scan has not been started at it\'s scheduled time.'

        assert ['nessus' in plugin_name for plugin_name in VulnerabilityList().get_plugin_names()], \
            'Applied filter value doesnot matched with scan result value.'

        scan_details_page.back_link.click()
        sleep(sleep_time=WAIT_NORMAL, reason='waiting for scan page to be loaded')

        # Delete the created scan
        delete_created_scan(scan_name=scan_name)

    @pytest.mark.xray(test_key='NES-17833')
    @pytest.mark.parametrize('data_to_be_scanned', [
        {'all_plugin_families_with_compliance': {
            'scan_name': 'Advanced compliance for AL2_L1',
            'compliance_to_scan': [
                {'category_type': ComplianceConst.UNIX}]}}])
    def test_amazon_compliance_scan_output(self, create_new_folder, data_to_be_scanned):
        """
        NES-17833: Verify the compliance output is available by running the compliance scan.

        1. Login to the Nessus
        2. Go to new scan creation page
        3. create a scan with policy compliance audit template
        4. give the required details and switch to the credential tab
        5. give the required details and switch to compliance tab
        6. select the unix > Amazon linux 2 v1 l1 compliance
        7. save and launch the scan
        8. Once scan is completed open the scan result page
        9. Verify the compliance tab is available
        10 Click on tab and open any compliance
        11. click on compliance and make sure output is available for it
        """

        folder_name = create_new_folder[1]
        scan_name = data_to_be_scanned['all_plugin_families_with_compliance']['scan_name']
        LoadingCircle(WAIT_NORMAL)

        # Create scan with data to be scanned
        ScansPage().create_new_scan(
            scan_template=Nessus.TemplateNames.COMPLIANCE_AUDIT, scan_type=Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
            scan_name=scan_name, folder=folder_name, target_ip=Nessus.Scan.Target.LINUX_TARGET_2,
            description='Created an Advanced Scan with Compliance.', add_configuration=True)

        # Configure with required data (credentials/compliance/plugins) to be scanned
        LoadingCircle(TIME_THREE_SECONDS)
        Password(host_type=API.Credentials.Host.Types.SSH).fill_password_ssh_form(
            username=Nessus.ROOT, password=Nessus.LABPASS, auth=API.Credentials.Host.SSHAuthTypes.PASSWORD)

        compliance_page = Compliance()
        for compliance in data_to_be_scanned['all_plugin_families_with_compliance']['compliance_to_scan']:
            LoadingCircle(TIME_THREE_SECONDS)
            compliance_page.click_compliance(category_name=compliance.get('category_type'),
                                             compliance_type="CIS Amazon Linux 2 v3.0.0 L1 ")

        # Save scan, launch it and verify it's successful completion
        LoadingCircle(TIME_THREE_SECONDS)
        assert scan_save_launch_and_status_verification(scan_name=scan_name, scan_folder_name=folder_name), \
            'Scan has not been completed successfully.'

        ScanList().click_on_scan(scan_name=scan_name)

        # verify the compliance tab
        scan_view_page = ScanViewPage()
        wait(lambda: visibility_of_element_located(scan_view_page.compliance_tab),
             waiting_for='compliance tab to load')
        assert visibility_of_element_located(scan_view_page.compliance_tab), "Compliance tab is not generated or visible"

        # open the tab
        scan_view_page.compliance_tab.click()
        wait(lambda: visibility_of_element_located(scan_view_page.search_icon),
             waiting_for="Host Details Page to load", timeout_seconds=WAIT_NORMAL)

        # Click on any compliance available
        vulnerabilities_list = VulnerabilityList()
        vulnerabilities_list.rows[0].click()

        # wait for output to be visible
        wait(lambda: visibility_of_element_located(scan_view_page.output_area),
             waiting_for="output to be loaded on page", timeout_seconds=WAIT_NORMAL)
        assert visibility_of_element_located(scan_view_page.output_area), "Compliance output area is not available"

