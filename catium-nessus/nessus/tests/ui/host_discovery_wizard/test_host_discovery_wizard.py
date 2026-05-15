""""
Nessus Essentials test cases related to host discovery wizard

:copyright: Tenable Network Security, 2019
:date: July 29,2019
:author: @vsoni
"""
import re

import pytest
from selenium.webdriver.support.expected_conditions import visibility_of_element_located

from catium.lib import const
from catium.lib.const.base_constants import TIME_SIXTY_SECONDS, TIME_FIFTEEN_MINUTES, TIME_TEN_SECONDS
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.lib.const import API, Nessus, random_name
from nessus.lib.message.messages import Messages
from nessus.pageobjects.about.about_page import OverView, LicenseUtilization
from nessus.pageobjects.header.notifications import Notifications, NotificationActions
from nessus.pageobjects.header.user_menu import UserMenu
from nessus.pageobjects.login.login_page import HostDiscoveryWizard, LoginPage
from nessus.pageobjects.scans.scan_trash_page import ScansTrashPage
from nessus.pageobjects.scans.scan_view_page import ScanViewPage, ScanHistoryList
from nessus.pageobjects.scans.scans_page import ScanList, ScansPage
from nessus.pageobjects.sidenav.sidenav import SideNav


@pytest.mark.nessus_settings_1
@pytest.mark.nessus_home
@pytest.mark.parametrize('login', [{'keep_wizard_enabled': True}], indirect=True)
class TestHostDiscoveryWizardForEssentials:
    """Test cases to verify Host discovery wizard on Nessus Essentials"""
    cat = None

    @pytest.mark.xray(test_key='NES-14011')
    @pytest.mark.usefixtures('delete_all_scans_in_nessus', 'enable_scan_wizard', 'login')
    def test_verify_host_discovery_wizard_on_fresh_login(self):
        """
        NES-9834: NES-9818 - Host Discovery Wizard for Essentials/Trialware
        NES-14011: Verify scan description in HD wizard

        Scenario Tested:
            [x] Verify Host Discovery Wizard appears with Proper details when login to Nessus Essentials.

        Steps:
        1. Login to Nessus.
        2. Verify that Host Discovery wizard appears.
        3. Verify that wizard has title as "Welcome to Nessus Essentials".
        3 (b). Verify scan description in HD wizard for NES-14011
        4. Verify that wizard has text box to enter hostname or IP details.
        5. Verify that wizard has option for "close" and "submit" buttons.
        6. Close the wizard
        7. Logout from Nessus
        """
        host_discovery_wizard = HostDiscoveryWizard()
        get_driver_no_init().refresh()
        wait(lambda: host_discovery_wizard.is_element_present('modal'), waiting_for='hd wizard to get appeared',
             timeout_seconds=TIME_TEN_SECONDS)

        # Verify that Host discovery wizard appears
        assert host_discovery_wizard.is_element_present('modal'), \
            "Host Discovery Wizard is not appearing for fresh login"

        # Verify Host Discovery Wizard header text
        assert host_discovery_wizard.hd_wizard_header.text == "Welcome to Nessus Essentials", \
            "Host Discovery Wizard header is not 'Welcome to Nessus Essentials'"

        # Verify Host Discovery Wizard detail text
        assert host_discovery_wizard.hd_wizard_detail.text == Nessus.Scan.ScanDescriptions.HD_WIZARD_DESC

        # Verify Host Discovery Wizard "Targets" label
        assert host_discovery_wizard.is_element_present('hd_wizard_targets'), \
            "Host Discovery Wizard does not have lable 'Targets' for entering IP address to run the scan"

        host_discovery_wizard.close_button.click()
        host_discovery_wizard.wait_for_modal_closed()

    @pytest.mark.usefixtures('delete_all_scans_in_nessus', 'enable_scan_wizard', 'login')
    def test_verify_host_discovery_wizard_on_refresh_or_relogin(self):
        """
        NES-9834: NES-9818 - Host Discovery Wizard for Essentials/Trialware

        Scenario Tested:
            [x] Test Host discovery wizard appears on refresh or re-login to Nessus Essentials

        Steps:
        1. Login to Nessus.
        2. Verify that Host Discovery wizard appears.
        3. Refresh Nessus Essentials and wait till page loads properly. 
        4. Verify that Host Discovery wizard appears.
        5. Close the wizard.
        6. Logout from Nessus.
        7. Login again to Nessus and check if Host discovery wizard appears
        8. Close the wizard 
        9. Logout from Nessus
        """
        host_discovery_wizard = HostDiscoveryWizard()
        get_driver_no_init().refresh()
        wait(lambda: host_discovery_wizard.is_element_present('modal'), waiting_for='hd wizard to get appeared',
             timeout_seconds=TIME_TEN_SECONDS)

        # Verify that Host discovery wizard appears
        assert host_discovery_wizard.is_element_present('modal'), \
            "Host Discovery Wizard is not appearing for fresh login"

        # Refresh to Nessus and verify that scan wizard appears.
        host_discovery_wizard.refresh()
        wait(lambda: host_discovery_wizard.is_element_present('modal'),
             waiting_for='Host Discovery Wizard to appear on Nessus')

        assert host_discovery_wizard.is_element_present('modal'), \
            "Host Discovery Wizard is not appearing after page refresh."

        # Re-login to Nessus and verify that scan wizard appear.
        host_discovery_wizard.close_button.click()
        host_discovery_wizard.wait_for_modal_closed()

        NotificationActions().remove_all()
        UserMenu().logout()
        LoginPage().do_login()

        assert host_discovery_wizard.is_element_present('modal'), \
            "Host Discovery Wizard is not appearing on Nessus Essentials on re-login."

    @pytest.mark.usefixtures('delete_all_scans_in_nessus', 'enable_scan_wizard', 'login')
    def test_verify_scan_run_using_scan_wizard_on_nessus_essentials(self):
        """
        NES-9834: NES-9818 - Host Discovery Wizard for Essentials/Trialware

        Scenario Tested:
            [x] Create H-D scan and run basic network scan using scan wizard for Nessus Essentials

        Steps:
        1. Login to Nessus.
        2. Verify that Host Discovery wizard appears.
        3. Enter the IP address in Targets field and click on submit.
        4. Verify that Host discovery scan started and running.
        5. Before the scan gets completed, click on "Run Scan" button.
        6. Verify that error message displays on notifications.
        7. After host discovery get completed, click on "Run Scan" button.
        8. Check if scan launched and has the status as "Running".
        9. Wait till scan to get completed.
        10. Refresh the Nessus and verify that scan wizard does not appear.
        11. Re-login to Nessus and verify that scan wizard does not appear.
        12. Delete scan and log out from Nessus.
        """
        host_discovery_wizard = HostDiscoveryWizard()
        get_driver_no_init().refresh()
        wait(lambda: host_discovery_wizard.is_element_present('modal'), waiting_for='hd wizard to get appeared',
             timeout_seconds=TIME_TEN_SECONDS)

        # Verify that Host discovery wizard appears
        assert host_discovery_wizard.is_element_present('modal'), \
            "Host Discovery Wizard is not appearing on Nessus Essentials when login"

        # Creating scan via scan wizard
        host_discovery_wizard.create_host_discovery_scan_on_wizard()
        wait(lambda: host_discovery_wizard.hd_wizard_report_header.text == "My Host Discovery Scan Results",
             waiting_for='Host Discovery Scan on wizard to appear')

        # Verify that scan has completed
        assert host_discovery_wizard.is_element_present('hd_wizard_loading_circle'), \
            "Loading circle is not appearing on wizard when HD-Scan is running"

        host_discovery_wizard.action_button.click()

        # Verify Error notification when scan launched without selecting IP
        assert Notifications().errors[-1] == Messages.NotificationMessages.select_host_on_scan_wizard_error, \
            "Error message should be displayed when clicking on run Scan without selecting any IP addresses"

        wait(lambda: host_discovery_wizard.is_element_present('hd_wizard_discovery_checkmark'),
             timeout_seconds=TIME_SIXTY_SECONDS, waiting_for='Host Discovery scan to get completed')

        host_discovery_wizard.hd_wizard_scan_host_checkbox.check()
        host_discovery_wizard.action_button.click()
        host_discovery_wizard.wait_for_modal_closed()

        try:
            scan_result_page = ScanViewPage()
            wait(lambda: scan_result_page.is_element_present('history_tab'),
                 waiting_for='Redirecting to Scan results page.')

            scan_result_page.history_tab.click()
            history_list = ScanHistoryList()

            # Verify that scan has 'Running' status
            assert history_list.rows[0].scan_status == API.Scan.Status.RUNNING.title(), \
                "Scan status should be 'Running' after launching scan via scan wizard"

            scan_result_page.back_link.click()
            scan_list = ScanList()
            scan_list.loaded()

            assert scan_list.launch_scan_and_wait_for_status(
                scan_name=Nessus.Scan.DEFAULT_SCAN_NAMES_CREATED_VIA_WIZARD[0], launch_scan=False,
                status=API.Scan.Status.COMPLETED), "Scan has not been completed."

            # Refreshing Nessus and verify that scan wizard does not appear
            user_menu = UserMenu()
            user_menu.refresh()
            user_menu.loaded()

            # Verify that Host discovery wizard does not appear
            assert not host_discovery_wizard.is_element_present('modal'), \
                "Host Discovery Wizard is appearing when scan has already been created"

            # Re-login to Nessus and verify that scan wizard does not appear.
            NotificationActions().remove_all()
            user_menu.logout()
            LoginPage().do_login()

            # Verify that Host discovery wizard does not appear
            assert not host_discovery_wizard.is_element_present('modal'), \
                "Host Discovery Wizard is appearing when scan has already been created"
        finally:
            # Deleting scans created via wizard
            scan_list = ScanList()

            for scan_name in Nessus.Scan.DEFAULT_SCAN_NAMES_CREATED_VIA_WIZARD:
                SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()
                wait(lambda: visibility_of_element_located(ScansPage().scan_searchbox), waiting_for='scan list to load')
                scan_list.delete_scan(scan_name=scan_name)
                ScansTrashPage().delete_scan_from_trash(scan_name=scan_name)

    @pytest.mark.usefixtures('login', 'create_scans', 'enable_scan_wizard')
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.BASIC_NETWORK, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.BASIC_NETWORK)),
         "target_ip": Nessus.Scan.Target.LOCALHOST}]}], indirect=True)
    def test_verify_no_scan_wizard_appears_when_scan_already_created(self):
        """
        NES-9834: NES-9818 - Host Discovery Wizard for Essentials/Trialware

        Scenario Tested:
            [x] Test Host Discovery wizard does not appear when scan has already been created (Nessus Essentials)

        Steps:
        1. Login to Nessus
        2. Create the scan using fixture.
        3. Set the fix parameter show_wizard to "yes".
        4. Refresh Nessus and verify that scan wizard does not appear.
        5. Re-login to Nessus and verify that Host discovery wizard does not appear.
        6. Delete scan and logout from Nessus.
        """
        host_discovery_wizard = HostDiscoveryWizard()
        get_driver_no_init().refresh()

        # Verify that Host discovery wizard does not appear
        assert not host_discovery_wizard.is_element_present('modal'), \
            "Host Discovery Wizard should not appear when scan has already been created"

        # Refreshing Nessus and verify that scan wizard does not appear
        user_menu = UserMenu()
        user_menu.refresh()
        user_menu.loaded()

        # Verify that Host discovery wizard does not appear
        assert not host_discovery_wizard.is_element_present('modal'), \
            "Host Discovery Wizard is appearing when scan has already been created"

        # Re-login to Nessus and verify that scan wizard does not appear.
        NotificationActions().remove_all()
        user_menu.logout()
        login_page = LoginPage()
        login_page.do_login()

        # Verify that Host discovery wizard does not appear
        assert not host_discovery_wizard.is_element_present('modal'), \
            "Host Discovery Wizard is appearing when scan has already been created"

    @pytest.mark.xray(test_key='NES-13799')
    @pytest.mark.usefixtures('delete_all_scans_in_nessus', 'enable_scan_wizard', 'login')
    def test_ip_selection_checkbox_present_on_hd_scan_wizard(self):
        """
        NES-13799 : Verify checkbox for IP selection in wizard

        """
        host_discovery_wizard = HostDiscoveryWizard()
        get_driver_no_init().refresh()
        wait(lambda: host_discovery_wizard.is_element_present('modal'), waiting_for='hd wizard to get appeared',
             timeout_seconds=TIME_TEN_SECONDS)

        # Verify that Host discovery wizard appears
        assert host_discovery_wizard.is_element_present('modal'), \
            "Host Discovery Wizard is not visible when no scan is created"

        # Creating scan via scan wizard
        host_discovery_wizard.create_host_discovery_scan_on_wizard()
        wait(lambda: host_discovery_wizard.hd_wizard_report_header.text == "My Host Discovery Scan Results",
             waiting_for='Host Discovery Scan on wizard to appear')

        # Verify that scan has completed
        assert host_discovery_wizard.is_element_present('hd_wizard_loading_circle'), \
            "Loading circle is not appearing on wizard when HD-Scan is running"

        # Verify that checkboxes are present
        assert visibility_of_element_located(
            host_discovery_wizard.hd_wizard_scan_host_checkbox), 'IP selection checkboxes are not present on HD scan wizard'

        host_discovery_wizard.hd_wizard_scan_host_checkbox.check()

        # Verify that checkbox are selected
        assert host_discovery_wizard.hd_wizard_scan_host_checkbox.is_selected(), 'Checkbox not selected'


    @pytest.mark.xray(test_key='NES-13752')
    @pytest.mark.usefixtures('delete_all_scans_in_nessus', 'enable_scan_wizard', 'login')
    def test_dismiss_hd_scan_wizard(self):
        """
        NES-13752 : Verify HD wizard dismiss
        """
        host_discovery_wizard = HostDiscoveryWizard()
        get_driver_no_init().refresh()
        wait(lambda: host_discovery_wizard.is_element_present('modal'), waiting_for='hd wizard to get appeared',
             timeout_seconds=TIME_TEN_SECONDS)

        # Verify that Host discovery wizard appears
        assert host_discovery_wizard.is_element_present('modal'), \
            "Host Discovery Wizard is not visible when no scan is created"

        host_discovery_wizard.cancel_button.click()

        # Verify that Host discovery wizard is dismissed
        assert not host_discovery_wizard.is_element_present('modal'), \
            "Host Discovery Wizard is still visible "

    @pytest.mark.xray(test_key='NES-13837')
    @pytest.mark.usefixtures('delete_all_scans_in_nessus', 'enable_scan_wizard', 'login')
    def test_back_button_on_hd_scan_wizard(self):
        """
        NES-13837 : Verify Back button of wizard
        """
        host_discovery_wizard = HostDiscoveryWizard()
        get_driver_no_init().refresh()
        wait(lambda: host_discovery_wizard.is_element_present('modal'), waiting_for='hd wizard to get appeared',
             timeout_seconds=TIME_TEN_SECONDS)

        # Verify that Host discovery wizard appears
        assert host_discovery_wizard.is_element_present('modal'), \
            "Host Discovery Wizard is not visible when no scan is created"

        # Creating scan via scan wizard
        host_discovery_wizard.create_host_discovery_scan_on_wizard()

        assert host_discovery_wizard.is_element_present('hd_wizard_loading_circle'), \
            "Loading circle is not appearing on wizard when HD-Scan is running"

        # Clicking Back button on wizard
        host_discovery_wizard.hd_wizard_back_button.click()

        # Verify Host Discovery Wizard header text after going back
        assert host_discovery_wizard.hd_wizard_header.text == "Welcome to Nessus Essentials", \
            "Host Discovery Wizard header is not 'Welcome to Nessus Essentials'"

    @pytest.mark.xray(test_key='NES-13789')
    @pytest.mark.usefixtures('delete_all_scans_in_nessus', 'enable_scan_wizard', 'login')
    def test_hd_wizard_result(self):
        """
        NES-13789 : Verify 'My Host Discovery Scan Results'

        Scenario tested :
        [x] Verified that Input target adn scanned host both are same on the wizard
        """
        host_discovery_wizard = HostDiscoveryWizard()
        get_driver_no_init().refresh()
        wait(lambda: host_discovery_wizard.is_element_present('modal'), waiting_for='hd wizard to get appeared',
             timeout_seconds=TIME_TEN_SECONDS)

        # Verify that Host discovery wizard appears
        assert host_discovery_wizard.is_element_present('modal'), \
            "Host Discovery Wizard is not visible when no scan is created"

        # Run scan on wizard
        host_discovery_wizard.create_host_discovery_scan_on_wizard()
        wait(lambda: host_discovery_wizard.hd_wizard_report_header.text == "My Host Discovery Scan Results",
             waiting_for='Host Discovery Scan on wizard to appear')

        # Verify that scan has completed
        assert host_discovery_wizard.is_element_present('hd_wizard_loading_circle'), \
            "Loading circle is not appearing on wizard when HD-Scan is running"

        assert Nessus.Scan.Target.LOCALHOST == host_discovery_wizard.hd_wizard_scanned_host.text, "Input targets and " \
                                                                                                  "scanned targets " \
                                                                                                  "are not matching "


    @pytest.mark.xray(test_key='NES-13925')
    @pytest.mark.xray(test_key='NES-13731')
    @pytest.mark.usefixtures('delete_all_scans_in_nessus', 'enable_scan_wizard', 'login')
    def test_verify_scans_on_scan_page_after_hd_wizard_is_closed(self):
        """
        NES-13925 : Verify HD completed scan
        NES-13731 : Verify created BNS
        """
        host_discovery_wizard = HostDiscoveryWizard()
        get_driver_no_init().refresh()
        wait(lambda: host_discovery_wizard.is_element_present('modal'), waiting_for='hd wizard to get appeared',
             timeout_seconds=TIME_TEN_SECONDS)

        # Verify that Host discovery wizard appears
        assert host_discovery_wizard.is_element_present('modal'), \
            "Host Discovery Wizard is not visible when no scan is created"

        # Run scan on wizard
        host_discovery_wizard.create_host_discovery_scan_on_wizard()
        wait(lambda: host_discovery_wizard.hd_wizard_report_header.text == "My Host Discovery Scan Results",
             waiting_for='Host Discovery Scan on wizard to appear')

        # Verify that scan has completed
        assert host_discovery_wizard.is_element_present('hd_wizard_loading_circle'), \
            "Loading circle is not appearing on wizard when HD-Scan is running"

        host_discovery_wizard.hd_wizard_scan_host_checkbox.check()

        wait(lambda: host_discovery_wizard.hd_wizard_scan_host_checkbox.is_selected(),
             waiting_for='waiting for checkbox to get selected')

        host_discovery_wizard.action_button.click()

        wait(lambda: visibility_of_element_located('back_to_folder'),
             waiting_for='waiting for scan details page to get loaded')

        scan_page = ScansPage()
        scan_page.back_to_folder.click()

        scan_list = ScanList()
        scan_list.loaded()
        all_scans = scan_list.get_all_scans()

        # Verify that both scans are created
        assert Nessus.Scan.DEFAULT_SCAN_NAMES_CREATED_VIA_WIZARD[
                   0] in all_scans, f'{Nessus.Scan.DEFAULT_SCAN_NAMES_CREATED_VIA_WIZARD[0]} not found in scan list'
        assert Nessus.Scan.DEFAULT_SCAN_NAMES_CREATED_VIA_WIZARD[
                   1] in all_scans, f'{Nessus.Scan.DEFAULT_SCAN_NAMES_CREATED_VIA_WIZARD[1]} not found in scan list'

    @pytest.mark.xray(test_key='NES-13957')
    @pytest.mark.xray(test_key='NES-13885')
    @pytest.mark.usefixtures('delete_all_scans_in_nessus', 'login', 'enable_scan_wizard', "nessus_api_login")
    def test_license_utilization_after_creating_hd_scan(self):
        """
        NES-13885 : Verify license utilization for HD scan
        NES-13957 : Verify license utilization tab when 0 license used
        """

        host_discovery_wizard = HostDiscoveryWizard()
        get_driver_no_init().refresh()
        wait(lambda: host_discovery_wizard.is_element_present('modal'), waiting_for='hd wizard to get appeared',
             timeout_seconds=TIME_TEN_SECONDS)

        # Verify that Host discovery wizard appears
        assert host_discovery_wizard.is_element_present('modal'), \
            "Host Discovery Wizard is not visible when no scan is created"

        # Run scan on wizard
        host_discovery_wizard.create_host_discovery_scan_on_wizard()
        wait(lambda: host_discovery_wizard.hd_wizard_report_header.text == "My Host Discovery Scan Results",
             waiting_for='Host Discovery Scan on wizard to appear')

        # Verify that scan has completed
        assert host_discovery_wizard.is_element_present('hd_wizard_loading_circle'), \
            "Loading circle is not appearing on wizard when HD-Scan is running"

        host_discovery_wizard.close_button.click()

        scan_list = ScanList()
        scan_list.loaded()
        all_scans = scan_list.get_all_scans()

        # Verify that host discovery scan are created
        assert Nessus.Scan.DEFAULT_SCAN_NAMES_CREATED_VIA_WIZARD[
                   1] in all_scans, f'{Nessus.Scan.DEFAULT_SCAN_NAMES_CREATED_VIA_WIZARD[1]} not found in scan list'

        about_page = OverView()
        about_page.open()
        wait(lambda: about_page.is_element_present('used_hosts'), timeout_seconds=const.TIME_THIRTY_SECONDS,
             waiting_for='OverView tab to be displayed.')

        host_usage_info = about_page.used_hosts.text

        # Verify that "used hosts" information is available with proper format.
        assert re.match(r'(\d{1,2}(?!\d)) of (\d{1,2}(?!\d)) used', host_usage_info), \
            "Used hosts information is not in proper format"

        no_of_used_hosts = self.cat.api.server.properties()['used_ip_count']

        scanned_host_no = int(host_usage_info.split(' of')[0])
        max_host_scanned = int(host_usage_info.split(' of ')[1].split(' used')[0])

        # Verify that host is still 0 after creating HD scan
        assert scanned_host_no == no_of_used_hosts, "used hosts is not 0 and is used toward licence limit"

        # Verify Max host count is 16
        assert max_host_scanned == 16, "Max host count is not 16"

        license_page = LicenseUtilization()
        license_page.open()
        if no_of_used_hosts == 0:
            assert license_page.no_results.text == Nessus.Essentials.NO_HOST_USED

    @pytest.mark.xray(test_key='NES-13934')
    @pytest.mark.usefixtures('delete_all_scans_in_nessus', 'enable_scan_wizard', 'login')
    def test_hd_scan_with_multiple_hosts(self):
        """
        NES-13934 : Verify HD scan with multiple hosts
        """
        host_discovery_wizard = HostDiscoveryWizard()
        get_driver_no_init().refresh()
        wait(lambda: host_discovery_wizard.is_element_present('modal'), waiting_for='hd wizard to get appeared',
             timeout_seconds=TIME_TEN_SECONDS)

        # Verify that Host discovery wizard appears
        assert host_discovery_wizard.is_element_present('modal'), \
            "Host Discovery Wizard is not visible when no scan is created"

        # Run scan on wizard
        host_discovery_wizard.create_host_discovery_scan_on_wizard_max_targets()
        wait(lambda: host_discovery_wizard.hd_wizard_report_header.text == "My Host Discovery Scan Results",
             waiting_for='Host Discovery Scan on wizard to appear')

        wait(lambda: host_discovery_wizard.is_element_present('hd_scan_complete'),
             timeout_seconds=TIME_FIFTEEN_MINUTES, waiting_for='Host Discovery scan to get completed')

        # Verify that scan has completed
        assert host_discovery_wizard.is_element_present('hd_scan_complete'), \
            "HD table length dropdown is not visible"

        # Verify that scan has completed
        assert host_discovery_wizard.is_element_present('hd_table_pagination'), \
            "HD table Pagination controls are not visible"


@pytest.mark.nessus_settings_1
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('login')
class TestNoHostDiscoveryWizardForManagerAndPro:
    """Test cases to verify Host discovery wizard on Nessus Manager/ Nessus Professional"""

    def test_verify_no_scan_wizard_for_professional_or_manager(self):
        """
        NES-9834: NES-9818 - Host Discovery Wizard for Essentials/Trialware

        Scenario Tested:
            [x] Test Host Discovery Wizard does not appear (Nessus Manager/Nessus Pro)

        Steps:
        1. Login to Nessus.
        2. Verify that Host Discovery wizard does not appear.
        3. Logout from Nessus.
        """
        # Verify that Host discovery wizard does not appear
        assert not HostDiscoveryWizard().is_element_present('modal'), \
            "Host Discovery Wizard is appearing for Nessus Manager/Nessus Professional"

        # Refreshing Nessus and verify that scan wizard does not appear
        user_menu = UserMenu()
        user_menu.refresh()
        user_menu.loaded()

        # Verify that Host discovery wizard does not appear
        assert not HostDiscoveryWizard().is_element_present('modal'), \
            "Host Discovery Wizard is appearing for Nessus Manager/Nessus Professional on refresh"
