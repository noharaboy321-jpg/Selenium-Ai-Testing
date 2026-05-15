""""
Nessus test cases related to Scans with plugins.

:copyright: Tenable Network Security, 2017
:date: May 11, 2018
:last_modified: Aug 19, 2020
:author: @rdutta, @pdave
"""
import pytest
from selenium.webdriver.support.expected_conditions import visibility_of_element_located

from catium.helpers.testdata import get_file_path
from catium.lib.const import WAIT_NORMAL, TIME_THREE_SECONDS, TIME_TEN_MINUTES, TIME_TEN_SECONDS
from catium.lib.const.base_constants import TIME_FIFTEEN_MINUTES, TIME_TWO_MINUTES
from catium.lib.log.log import create_logger
from catium.lib.ssh import SSH
from catium.lib.util import random_name
from catium.lib.webium.wait import wait
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.nessuscli.helper import stop_nessus, start_nessus, get_nessus_var_dir, get_os_name
from nessus.helpers.scan import send_plugin_file_and_update, launch_scan_and_get_particular_vulnerability
from nessus.helpers.waiters import wait_for_scanner_status
from nessus.lib.const import API, Nessus, OperatingSystems, SSHCommands
from nessus.lib.message.messages import Messages
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.login.login_page import LoginPage
from nessus.pageobjects.plugins.plugins_page import Plugin, PluginFamilyList
from nessus.pageobjects.scans.new_scan_form import NewScanForm
from nessus.pageobjects.scans.scan_view_page import ScanViewPage
from nessus.pageobjects.scans.scans_page import ScansPage, ScanList
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav

log = create_logger()


@pytest.mark.nessus_pro
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestScansWithPlugins:
    """Covers Scans with plugins related test cases."""

    @staticmethod
    def login_after_plugin_update() -> None:
        """
        Login and wait till the required login elements are not found

        :return: None
        """
        login_page = LoginPage()
        wait(lambda: login_page.is_element_present("username_field") and login_page.is_element_present(
            "password_field") or login_page.refresh(), sleep_seconds=TIME_TEN_SECONDS, timeout_seconds=TIME_TEN_MINUTES,
             waiting_for="Login page to appear")
        login_page.login_with_defaults()

    @pytest.mark.nessus_home
    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         'target_ip': Nessus.Scan.Target.PUB_TARGET_3, 'add_configuration': True}]}], indirect=True)
    def test_save_scan_with_all_plugins_disabled(self, create_scans):
        """
        # NQA-1173 : Create and save a scan with all plugins disabled.
        Sub-task of #NQA-1171
        1. Create a advance scan
        2. Go to plugin tab, disable all plugins
        3. Hit Save and verify success notification.
        4. Click on scan and navigated to 'Plugin' tab.
        5. Verify the above configuration still exists and all plugins are in disabled state
        """
        scan_name = create_scans[0]
        LoadingCircle(TIME_THREE_SECONDS)

        plugins_page = Plugin()
        plugins_page.disable_all.click()
        scans_page = ScansPage()
        scans_page.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            "Success notifications for scan save is mismatched or missing."

        scans_list = ScanList()
        assert scan_name in scans_list.get_all_scans(), "Failed to save scan, scan not found in scan_list."

        scans_list.click_on_scan(scan_name=scan_name)
        LoadingCircle(WAIT_NORMAL)
        ScanViewPage().configure_button.click()
        plugins_page.plugin.click()
        assert all([value == API.Status.DISABLED.lower()
                    for value in PluginFamilyList().get_plugin_families_status().values()]), \
            "All plugin families are not in disabled state."

        NewScanForm().back_link.click()
        scans_page.back_to_folder.click()
        LoadingCircle(TIME_THREE_SECONDS)

    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         'target_ip': Nessus.Scan.Target.LOCALHOST, 'add_configuration': True}]}], indirect=True)
    @pytest.mark.parametrize('plugin_name, plugin_file, plugin_id', [
        ("SCE-1863", [get_file_path('nessus/tests/ui/plugins/sce-1863-update-1.tar.gz'),
                      get_file_path('nessus/tests/ui/plugins/sce-1863-update-2.tar.gz')], "900594")])
    def test_update_plugins_and_verify(self, create_scans, plugin_file, plugin_name, plugin_id):
        """
        # SCE-1938 : Update plugins and verify they are affected or not.
        # SCE-2209 : affecting above ticket, improved Nessus error redirection

        Steps:
            1. Update through 'update-1' plugin file and verify a new plugin is present
            2. Update through 'update-2' plugin file and verify earlier added plugin is now unavailable
            3. Stop Nessus service and modify 'plugins-desc.db' file and then start Nessus service
            4. Verify the De-fragmentation process takes place with no errors
        """
        display_content_command = None
        scan_name = create_scans[0]

        log.info('Disable all plugins.')
        plugins_page = Plugin()
        plugins_page.disable_all.click()

        log.info('Save scan after disabling all plugins')
        scans_page = ScansPage()
        scans_page.save_button.click()

        notification = Notifications()


        # Verify success notification message after adding SMTP server settings
        assert notification.successes[-1] == Messages.NotificationMessages.save_scan, \
            'Success Notification is missing or mismatched after saving scan.'

        plugin_update_1_file = plugin_file[0].split('/')[5]

        log.info('Send plugin file "sce-1863-update-1.tar.gz" and updated the nessus')
        assert send_plugin_file_and_update(absolute_path=plugin_file[0], remote_file_path=plugin_update_1_file), \
            "Plugin update with {} wasn't successful".format(plugin_update_1_file)

        self.login_after_plugin_update()
        scan_list = ScanList()
        scan_list.loaded()
        scan_list.click_on_scan(scan_name=scan_name)

        scan_view_page = ScanViewPage()
        wait(lambda: visibility_of_element_located(scan_view_page.configure),
             waiting_for='configure button to be visible.')
        scan_view_page.configure.click()

        wait(lambda: visibility_of_element_located(scans_page.plugins_tab), waiting_for='plugins tab to be visible.')
        scans_page.plugins_tab.click()

        plugin_family_list = PluginFamilyList()
        plugin_family_list.loaded()
        new_added_plugin_family = [plugin_family for plugin_family in plugin_family_list.get_all_plugin_families()
                                   if plugin_name in plugin_family]

        log.info('verifies new added plugin family')
        assert new_added_plugin_family, "failed to get new plugin after plugin-update."

        log.info('Click on new added plugin')
        plugin_family_list.click_on_plugins_family(new_added_plugin_family[0])
        new_added_plugin_info = plugin_family_list.get_plugin_info(new_added_plugin_family[0]).text

        assert plugin_name in new_added_plugin_info and plugin_id in new_added_plugin_info, \
            "details of plugin added doesn't match after plugin processed."

        log.info('Save scan after verifying new added plugin family info')
        scans_page.save_button.click()

        assert notification.successes[-1] == Messages.NotificationMessages.save_scan, \
            "Success notifications for saving scan is mismatched or missing."

        log.info('Click on "My scan" from side navigation')
        side_nav = SideNav()
        side_nav.get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()

        log.info('Launch created scan to get particular vulnerability for plugin file "sce-1863-update-1.tar.gz"')
        assert launch_scan_and_get_particular_vulnerability(scan_name=scan_name, vulnerability_name=plugin_name), \
            "newly added plugin isn't present in vulnerability list, after updating sce-1863-update-1.tar.gz file."

        plugin_update_2_file = plugin_file[1].split('/')[5]

        log.info('Send plugin file "sce-1863-update-2.tar.gz" and updated the nessus')
        assert send_plugin_file_and_update(absolute_path=plugin_file[1], remote_file_path=plugin_update_2_file), \
            "Plugin update with {} wasn't successful".format(plugin_update_1_file)

        self.login_after_plugin_update()
        scan_list.loaded()

        log.info('Clicked on "My scan" from side navigation after updating plugin "sce-1863-update-2.tar.gz"')
        side_nav.get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()

        log.info('Launch created scan to get particular vulnerability for plugin file "sce-1863-update-2.tar.gz"')
        assert not launch_scan_and_get_particular_vulnerability(scan_name=scan_name, vulnerability_name=plugin_name), \
            "newly added plugin isn't deleted after updating sce-1863-update-2.tar.gz file."

        nessus_api = NessusAPI()

        try:
            log.info('Stop nessus')
            stop_nessus()
            os_name = get_os_name()

            with SSH() as ssh:
                plugin_file_path = '{}/plugins-desc.db'.format(get_nessus_var_dir())
                copy_plugin_file_path = '{}/plugins-desc2.db'.format(get_nessus_var_dir())

                if os_name == OperatingSystems.WINDOWS:
                    ssh.execute(
                        'powershell -c "$data = [System.IO.File]::ReadAllBytes("^""{0}"^""); '
                        '$data[12] = 0; $data[13] = 0; $data[14] = 0; $data[15] = 0; $data[16] = 2; $data[17] = 0; '
                        '$data[18] = 0; $data[19] = 0; '
                        '[System.IO.File]::WriteAllBytes("^""{0}"^"", $data)"'.format(plugin_file_path))

                    display_content_command = SSHCommands.Windows.COMMAND["display_content"]
                    log.info('Executed ssh command to modify content of {} for Windows'.format(plugin_file_path))

                elif os_name == OperatingSystems.LINUX:
                    ssh.execute(
                        "(head -c 12 {0}; echo -ne '\\x00\\x00\\x00\\x00\\x02\\x00\\x00\\x00'; tail -c +21 {0}) > {1}; "
                        "mv {1} {0}".format(plugin_file_path, copy_plugin_file_path))

                    display_content_command = SSHCommands.Linux.COMMAND["display_content"]
                    log.info('Executed ssh command to modify content of {} for Linux'.format(plugin_file_path))

                else:
                    raise Exception("The support for {} is not present".format(os_name))

            log.info('Starting nessus after executing ssh commands')
            start_nessus()

            wait_for_scanner_status(api=nessus_api, status=API.Status.READY, timeout=TIME_FIFTEEN_MINUTES,
                                    msg='Waiting for server to be in ready state.')

            self.login_after_plugin_update()
            output = ssh.execute('{} {}/logs/{}'.format(display_content_command, get_nessus_var_dir(),
                                                        Nessus.AdvancedSettings.NESSUS_FILES[0]))

            assert all([Messages.NessusCli.DB_TREE_READ_DATA_ERROR not in op for op in output]), \
                "de-fragmentation didn't completed successfully."

        finally:
            log.info('In finally block.')

            if nessus_api.server.status().get('status') != API.Status.READY:
                start_nessus()
                log.info('Wait for nessus to be ready after started')
                wait_for_scanner_status(api=nessus_api, status=API.Status.READY, timeout=TIME_FIFTEEN_MINUTES,
                                        msg='Waiting for server to be in ready state.')
                log.info('Login with default credentials after nessus ready')
                self.login_after_plugin_update()
            else:
                log.info("Nessus is already in Ready state...")
