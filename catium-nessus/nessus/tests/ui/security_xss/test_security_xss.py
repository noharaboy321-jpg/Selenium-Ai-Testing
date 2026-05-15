"""
Nessus Security xss attack verification

:copyright: Tenable Network Security, 2019
:date: Aug 11, 2017
:last_modified: Sept 14, 2020
:author: @rdutta, @jamreliya, @smadan, @yshah, @kpanchal
"""

from http import HTTPStatus

import pytest
from catium.helpers.sleep_lib import sleep
from selenium.webdriver.common.by import By
from selenium.webdriver.support.expected_conditions import visibility_of_element_located

from catium.helpers.testdata import get_file_path
from catium.lib.const.base_constants import WAIT_NORMAL, TIME_SIXTY_SECONDS, TIME_TEN_SECONDS, TIME_THIRTY_SECONDS
from catium.lib.util import random_name
from catium.lib.webium.driver import get_driver, get_driver_no_init
from catium.lib.webium.wait import wait
from catium.lib.webium.windows_handler import WindowsHandler
from nessus.helpers.scanner import create_scanner
from nessus.lib.const import API, Nessus
from nessus.lib.message.messages import Messages
from nessus.pageobjects.about.about_page import OverView
from nessus.pageobjects.agents.agents_page import AgentsList, AgentsPage
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.policies.new_policy_form import PolicyTemplatePage, NewPolicyForm
from nessus.pageobjects.policies.policies_page import PoliciesPage, PolicyList
from nessus.pageobjects.scanners.linked_scanners import ScannerList, ScannerPage
from nessus.pageobjects.scans.scan_trash_page import ScansTrashPage
from nessus.pageobjects.scans.scan_view_page import ScanViewPage
from nessus.pageobjects.scans.scans_page import ScansPage, ScanList
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav


@pytest.mark.nessus_settings_2
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_legacy
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login', 'login')
class TestSecurityXSS:
    """ Test Cases for security xss """

    cat = None

    @pytest.mark.ie
    def test_security_xss_check(self):
        """
        # NQA-377 : Security - UI - XSS - Stored XSS
        test to verify xss attack on new created policy
        """
        policy = "<body/onload=<!-- >&#10alert(1)> <script itworksinallbrowsers>" \
                 "alert('hello world')</script>"
        scan_name = random_name('scan-')

        policy_page = PoliciesPage()
        policy_page.open()
        wait(lambda: policy_page.is_element_present("new_policy_button", timeout=TIME_TEN_SECONDS))
        policy_page.new_policy_button.click()
        wait(lambda: policy_page.is_element_present("policies_searchbox", timeout=TIME_TEN_SECONDS))
        PolicyTemplatePage().click_by_policy(policy_text=Nessus.TemplateNames.BASIC_NETWORK)

        # create policy template and give its name as below to check xss security
        NewPolicyForm().save_new_policy(policy_name=policy)
        wait(lambda: policy_page.is_element_present("policies_searchbox", timeout=TIME_TEN_SECONDS))
        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()
        scan_page = ScansPage()
        wait(lambda: scan_page.is_element_present("new_scan_button", timeout=TIME_TEN_SECONDS))
        scan_page.create_new_scan(scan_type=Nessus.Scan.ScanTemplateTabs.USER_DEFINED_TAB,
                                  scan_template=policy, scan_name=scan_name, target_ip=Nessus.Scan.Target.LOCALHOST)

        # verify any alert didn't come
        window = WindowsHandler()
        assert not window.is_alert_present(), 'Alert window is present '

        # delete created scan and policy
        scan_list = ScanList()
        scan_list.delete_scan(scan_name=scan_name)
        ScansTrashPage().delete_scan_from_trash(scan_name=scan_name)

        policy_page.open()
        PolicyList().delete_policy(policy_name=policy)

    @pytest.mark.ie
    def test_security_xss_scan_dropdown(self):
        """
        # NQA-116 : Security - UI - XSS in scan policy dropdown
        Verify that scripts do not alert you when choosing a user-defined policy.
        """
        # click on policies from the side navigation bar
        policy_name = "<script>alert('hello XSS');</script>"
        scan_name = random_name('scan-')

        # Open policy page and create new policy.
        policy_page = PoliciesPage()
        policy_page.open()
        wait(lambda: policy_page.is_element_present("new_policy_button", timeout=TIME_TEN_SECONDS))
        policy_page.new_policy_button.click()
        wait(lambda: policy_page.is_element_present("policies_searchbox", timeout=TIME_TEN_SECONDS))
        PolicyTemplatePage().click_by_policy(policy_text=Nessus.TemplateNames.BASIC_NETWORK)

        # create policy template and give its name as below to check xss security
        NewPolicyForm().save_new_policy(policy_name=policy_name)
        wait(lambda: policy_page.is_element_present("policies_searchbox", timeout=TIME_TEN_SECONDS))
        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()
        scan_page = ScansPage()
        wait(lambda: scan_page.is_element_present("new_scan_button", timeout=TIME_TEN_SECONDS))
        scan_page.create_new_scan(scan_type=Nessus.Scan.ScanTemplateTabs.USER_DEFINED_TAB, scan_name=scan_name,
                                  scan_template=policy_name, target_ip=Nessus.Scan.Target.LOCALHOST)

        click_scan = ScanList()
        click_scan.click_on_scan(scan_name=scan_name)
        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present('configure_button', timeout=TIME_TEN_SECONDS))
        scan_view_page.js_scroll_into_view(scan_view_page.configure_button)
        scan_view_page.configure_button.click()

        policy_list = scan_view_page.policy_option.option_values
        assert policy_name in [item['label'] for item in policy_list], 'policy is not present'

        HeaderBasePage().scan_link.click()
        wait(lambda: scan_view_page.is_element_present("search_box", timeout=TIME_TEN_SECONDS))
        click_scan.delete_scan(scan_name=scan_name)
        ScansTrashPage().delete_scan_from_trash(scan_name=scan_name)

        policy_page.open()
        PolicyList().delete_policy(policy_name=policy_name)

    @pytest.mark.usefixtures('nessus_api_login')
    def test_security_xss_on_import_policy(self):
        """
        # NQA-384 : Security - UI - XSS in editor toggle

        test case to verify xss attack uploaded policy edit
        """
        file = get_file_path('nessus/tests/ui/security-xss/test_data/nessus_policy_plop.nessus')
        fileuploaded = self.cat.api.file.upload(file=file)

        self.cat.api.policies.import_policy(file=fileuploaded)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        policy_page = PoliciesPage()
        policy_page.open()
        wait(lambda: policy_page.is_element_present("new_policy_button", timeout=TIME_TEN_SECONDS))

        policy_list = PolicyList()
        policy_list.click_on_policy(policy_name='plop')

        window = WindowsHandler()
        assert not window.is_alert_present(), 'Alert window is present '

        # refresh to get error notification
        get_driver().refresh()
        new_policy = NewPolicyForm()
        wait(lambda: new_policy.is_element_present("name_field", timeout=TIME_TEN_SECONDS))
        new_policy.save_new_policy(policy_name='plop_edited')

        assert Notifications().errors[-1] == Messages.NotificationMessages.invalid_udp_port, \
            "Error notification is missing"

        # delete imported policy
        policy_page.open()
        policy_list.delete_policy(policy_name='plop')

    @pytest.mark.scanning
    @pytest.mark.parametrize("create_scan", [
        {'template_name': Nessus.TemplateNames.BASIC_NETWORK, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': '<script>alert("lol")</script>', 'host_ip': Nessus.Scan.Target.LOCALHOST}], indirect=True)
    def test_security_xss_scanner_overview(self, create_scan):
        """
        # NQA-406 : Security - UI - XSS in Scanners/Local/Overview
        test to verify xss in local scanner
        """
        scan_name = create_scan
        scan_page = ScansPage()
        scan_page.save_button.click()
        wait(lambda: scan_page.is_element_present("scan_searchbox"), waiting_for="scans list get loaded")

        scan_list = ScanList()
        scan_list.launch_scan(scan_name=scan_name)
        sleep(WAIT_NORMAL, reason="Scan takes little time to get in running state")

        header_page = HeaderBasePage()
        header_page.settings_link.click()
        wait(lambda: OverView().is_element_present("nessus_version"), timeout_seconds=TIME_THIRTY_SECONDS * 2,
             waiting_for='about overview page gets load properly.')

        # add assert here
        assert not WindowsHandler().is_alert_present(), 'Alert window is present.'

        header_page.scan_link.click()
        wait(lambda: scan_page.is_element_present("scan_searchbox"), waiting_for="scans list get loaded")
        scan_list.loaded()

        # Wait for stop button to appear
        scan_list.stop_scan(scan_name=scan_name)

        scan_page.refresh()
        wait(lambda: scan_page.is_element_present("scan_searchbox"), waiting_for="scans list get loaded")

        scan_stopped = scan_page.get_scan_status(scan_name=scan_name, scan_status=API.Scan.Status.CANCELED)
        wait(lambda: visibility_of_element_located((scan_stopped.we_by, scan_stopped.we_value))(
            get_driver()), timeout_seconds=TIME_SIXTY_SECONDS)  # this wait is for to stop the scan

    @pytest.mark.parametrize("create_scan", [{'template_name': Nessus.TemplateNames.BASIC_NETWORK,
                                              'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                                              'scan_name': random_name(prefix=Nessus.TemplateNames.BASIC_NETWORK),
                                              'host_ip': Nessus.Scan.Target.LOCALHOST}], indirect=True)
    @pytest.mark.parametrize("scan_description", ['"></textarea><img src={} onerror=alert(1)>',
                                                  "Created a {}".format(Nessus.TemplateNames.BASIC_NETWORK)])
    @pytest.mark.parametrize("image_src", ["scan_desc_image"])
    def test_security_xss_scan_description(self, create_scan, image_src, scan_description):
        """
        VRB-128943: UI automation for VRB-126694 (Stored XSS in Nessus 8.10.0)

        Scenario Tested:
            [x] Test to verify xss on scan description.

        Steps:
        1. Create a scan with scan description as some scripting code line.
        2. Got to scan configure page for the created scan
        3. Verify no alerts present on scan configure page.
        4. Verify the scan description is same as text entered during scan creation.
        5. Verify the given scripting code in scan description is not executed.
        6. Verify the scan can be saved successfully.
        """
        scan_name = create_scan
        scan_page = ScansPage()
        scan_description = scan_description.format(image_src)
        scan_page.description_textarea.value = scan_description
        scan_page.save_button.click()

        scan_list = ScanList()
        scan_list.loaded()
        scan_list.click_on_scan(scan_name=scan_name)

        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present('configure_button'))
        scan_view_page.configure_button.click()

        # Verify that no alert present on scan configuration screen.
        assert not WindowsHandler().is_alert_present(), 'Alert window is present '

        wait(lambda: scan_page.is_element_present('description_textarea'))

        # Verify the scan description text is same as value given while creating scan
        assert scan_page.description_textarea.value == scan_description, \
            'Scan description text is not same as text entered during scan creation.'

        # Verify that the script on scan description does not get executed.
        assert not [element for element in get_driver_no_init().find_elements(by=By.TAG_NAME, value="img")
                    if image_src in element.get_attribute("src")], \
            "Web-element with tag 'img' is present on scan configuration page."
        scan_page.save_button.click()

        # Verify that scan successfully saved on scan configuration page.
        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            "Scan does not saved successfully"


@pytest.mark.nessus_settings_2
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login', 'login')
class TestSecurityXSSForNessusManager:
    """ Test Cases for security xss with Nessus Manager only """

    cat = None

    @pytest.mark.ie
    def test_security_xss_linked_agent(self):
        """
        # NQA - 121 : Security - UI - XSS in linked scanner name
        test case verify xss attack while linking agent
        """
        # create fake agent though api
        agent_name = '<script>alert(xss)</script>'
        self.cat.api.agents.add_fake_agent(agent_name=agent_name)

        # navigate to agent page
        agent_page = AgentsPage()
        agent_page.open()

        # fetch agent list and verify the created one have the same name and non of the char escaped
        agent_list = AgentsList()
        assert agent_name in agent_list.get_all_agents_by_name(), 'Failed to create agent'

        agent_list.click_on_agent(agent_name=agent_name)

        # clicking on created agent should not throw any popup
        window = WindowsHandler()
        assert not window.is_alert_present(), 'Alert window is present '

        # remove created agent
        agent_page.open()
        agent_list.delete_agent(agent_name)
        action_modal = ActionCloseModal()
        action_modal.accept_action()
        action_modal.wait_for_modal_closed()

        wait(lambda: visibility_of_element_located(agent_page.export_button),
             waiting_for='notification to be disappear')

    @pytest.mark.ie
    def test_security_xss_linked_scanner(self):
        """
        # NQA - 121 : Security - UI - XSS in linked scanner name
        test case verify xss attack while linking scanner
        """
        # link fake scanner
        scanner_name = '<script>alert(xss)</script>'
        create_scanner(api=self.cat.api, scanner_name=scanner_name)

        scanner_page = ScannerPage()
        scanner_page.open()

        # scanner name if followed by 'shared' as table cell have 'shared' word along with scanner name
        scanner_list = ScannerList()
        assert 'Shared\n' + scanner_name in [agent.name.text for agent in scanner_list.results], \
            'Failed to create scanner'

        scanner_list.click_on_scanner(scanner_name=scanner_name)

        # clicking on created scanner should not throw any popup
        window = WindowsHandler()
        assert not window.is_alert_present(), 'Alert window is present '

        # remove created scanner
        scanner_page.open()
        scanner_list.delete_scanner(scanner_name=scanner_name)
        ActionCloseModal().accept_action()
