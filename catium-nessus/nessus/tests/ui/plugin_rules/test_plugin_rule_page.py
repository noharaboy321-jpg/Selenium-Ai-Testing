"""
Nessus Plugin Rules related test cases

:copyright: Tenable Network Security, 2017
:created: November 07, 2017
:last_modified: Mar 23, 2022
:author: @rdutta, @kpanchal
"""
import random
from datetime import datetime, timedelta

import pytest
from selenium.webdriver.support.expected_conditions import visibility_of_element_located

from catium.helpers.sleep_lib import sleep
from catium.lib.const import WAIT_SHORT
from catium.lib.const.base_constants import WAIT_NORMAL, TIME_THREE_SECONDS
from catium.lib.log.log import create_logger
from catium.lib.util.util import random_name
from catium.lib.webium.wait import wait
from nessus.helpers.date_selector import select_date_in_datepicker
from nessus.helpers.polling_ui import polling_ui
from nessus.helpers.sort import sort_on_column_values
from nessus.helpers.system import is_expert
from nessus.lib.const import Nessus
from nessus.lib.const.constants import API, SortOrder
from nessus.lib.message.messages import Messages
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.plugin_rules.plugin_rules_page import PluginRulesPage, PluginRulesList, NewRuleWindow
from nessus.pageobjects.scans.new_scan_form import NewScanForm
from nessus.pageobjects.scans.scan_view_page import ScanViewPage, ScanVulnerabilities, ScansHostList, VulnerabilityList
from nessus.pageobjects.scans.scans_page import ScanList
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav

log = create_logger()


@pytest.mark.nessus_home
@pytest.mark.nessus_pro
@pytest.mark.nessus_legacy
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestPluginRules:
    """Test class covers Plugin Rules page related Test Cases"""

    cat = None

    @pytest.mark.xray(test_key='NES-14024')
    @pytest.mark.nessus_expert
    def test_plugin_rule_searchbox(self):
        """
        NQA-1001 : Scans - Plugin Rules - Plugin rules search box
        NES-14024: Verify the description and icon plugin rule, search plugin rules place holder

        1. creates some plugin rules
        2. search some string
        3. search results should work for each column of the row in list.

        Scenario Tested:
        [x] Verify that search field is displayed after creating plugin rules.
        [x] Verify that placeholder text is displayed under search field.
        """
        plugin_rules = [{"host": 'hello', "plugin_id": '123', "severity": Nessus.Scan.Severity.CRITICAL},
                        {"host": '172.26.16.0', "plugin_id": '101126',
                         "expiry_date": str(datetime.today().date() + timedelta(days=1)),
                         "severity": Nessus.Scan.Severity.LOW},
                        {"host": '172.26.48.75', "plugin_id": '129051', "severity": Nessus.Scan.Severity.LOW,
                         "expiry_date": str(datetime.today().date() + timedelta(days=35))}]
        search_keys = {"key1": 'he', "key2": '12', "key3": 'N/A', "key4": 'low'}

        # Navigate to plugin rules page
        plugin_rule_page = PluginRulesPage()
        plugin_rule_page.open()

        # create plugin rules
        plugin_rule_list = PluginRulesList()

        for rule in plugin_rules:
            plugin_rule_page.add_new_plugin_rule(**rule)
            plugin_rule_list.loaded()

            assert rule["host"] in plugin_rule_list.get_host_name(), "Plugin rule not added successfully."

        assert plugin_rule_page.is_element_present("search_rule"), \
            "Search field is missing or not displayed even after creating plugin rules."

        assert plugin_rule_page.search_rule.get_attribute("placeholder") == "Search Rules", \
            "Place holder text is either missing or mismatch in plugin rules search field."

        # search rules using sub strings
        for value in search_keys.values():
            plugin_rule_list.apply_filter(value)
            plugin_rule_list.loaded()

            assert plugin_rule_list.verify_filter_result(value), "Search failed: Wrong list populated."

        # Remove all other notifications
        header_page = HeaderBasePage()
        header_page.clear_notification_history()

        # delete created plugin rules
        plugin_rule_page.remove_search_icon.click()
        plugin_rule_list.loaded()

        for rule in plugin_rules:
            plugin_rule_list.delete_plugin_rule(plugin_id=rule['plugin_id'])
            success_notifications_list = header_page.get_all_notifications_from_notification_box().get('Success')

            assert success_notifications_list[-1] == Messages.NotificationMessages.PlugInRules.delete_rule, \
                "Plugin rule not deleted successfully."

            header_page.notification_box_close_button.click()

    @pytest.mark.xray(test_key='NES-14547')
    @pytest.mark.ie
    @pytest.mark.nessus_expert
    def test_new_rule_button_and_window(self):
        """
        NQA-1067 : Automation test for Plugin rules
        NES-14547: Verify placeholders for create new plugin rule pop up.

        1. Navigate to plugin rule page
        2. Verify is new rule button exists
        3. Click on new rule button
        4. Verify plugin rule modal window is displayed
        5. Verify title of the modal window is 'New rule'
        6. Click on cancel and verify the plugin rule is not created.

        Scenario Tested:
        [x] Verify 'New rule' popup fields and it's placeholder texts.
            field : placeholder text
            -------------------------
            - Host : Leave empty for all hosts.
            - Plugin ID : Number
            - Expiration Date : Optional
            - Severity : Hide this result
        """
        plugin_rule_page = PluginRulesPage()
        plugin_rule_page.open()

        assert plugin_rule_page.new_rule_button.is_displayed(), 'New Rule button is not displayed on the page'

        plugin_rule_page.new_rule_button.click()
        plugin_rule_window = ActionCloseModal()

        assert plugin_rule_window.is_element_present('modal'), 'Plugin Rule window is not displayed.'

        assert all([plugin_rule_page.is_element_present("modal_title"),
                    plugin_rule_window.modal_title.text == "New Rule",
                    plugin_rule_window.is_element_present("action_button"),
                    plugin_rule_window.is_element_present("cancel_button"),
                    plugin_rule_window.is_element_present("close_button")]), \
            "'New Rule' pop-up modal is not getting displayed properly after clicking on 'New Rule' button."

        expected_placeholder_values = {
            plugin_rule_page.host: "Leave empty for all hosts.", plugin_rule_page.plugin_id: "Number",
            plugin_rule_page.expiration_date: "Optional"}

        for field_element, placeholder in expected_placeholder_values.items():
            assert visibility_of_element_located(field_element), \
                "'Host', 'Plugin ID' and 'Expiration Date' fields are not displayed in 'New Rule' pop-up."

            assert field_element.get_attribute("placeholder") == placeholder, \
                "Getting invalid placeholder value. Expected is :: {}".format(placeholder)

        assert all([plugin_rule_page.is_element_present("severity"),
                    plugin_rule_page.severity.get_text_selected() == "Hide this result"]), \
            "'Severity' field is missing or it's placeholder value is mismatched in 'New Rule' pop-up."

        plugin_rule_window.cancel_button.click()
        plugin_rule_window.wait_for_modal_closed()

    @pytest.mark.nessus_expert
    def test_plugin_rule_blank_values(self):
        """
        # NQA-1067 : Automation test for Plugin rules
        1. Navigate to plugin rule page
        2. Click on new rule button
        3. Click save button without any input
        4. Verify error notification for blank fields appears
        """
        plugin_rule_page = PluginRulesPage()
        plugin_rule_page.open()
        plugin_rule_page.new_rule_button.click()

        action_modal = ActionCloseModal()
        action_modal.action_button.click()

        assert Notifications().errors[-1] == Messages.NotificationMessages.continue_button_code, \
            'Error Notification for blank field is missing.'

        action_modal.cancel_button.click()

    @pytest.mark.parametrize('plugin_id', ['xyz', '12345', '123.45', '1x2y3z'])
    @pytest.mark.nessus_expert
    def test_valid_invalid_input_on_plugin_id(self, plugin_id):
        """
        # NQA-1067 : Automation test for Plugin rules
        1. Navigate to plugin rule page
        2. Click on new rule button
        3. Enter non numeric value in plugin id field
        4. Click save
        5. Verify error notification for invalid input appears

        NES-9395: UI Automation: Plugin Rules | Verify 'New Rule' popup field validation

        Scenario Tested:
        [x] Verify that only digits are acceptable in plugin ID field
        """
        # Go to plugin rules page and click on 'New Rule' button
        plugin_rule_page = PluginRulesPage()
        plugin_rule_page.open()
        plugin_rule_page.new_rule_button.click()

        # Enter plugin id and click on 'Add' button
        plugin_rule_page.plugin_id.value = plugin_id
        action_modal = ActionCloseModal()
        action_modal.accept_action()
        notification = Notifications()

        if plugin_id.isdigit():
            # Verify success message after adding plugin rule
            assert notification.successes[-1] == Messages.NotificationMessages.PlugInRules.add_rule, \
                'Getting invalid notification, Expected is \'{}\'.'.format(Messages.NotificationMessages.PlugInRules.
                                                                           add_rule)

            # Verify created plugin rule is getting added in plugin rules list
            assert plugin_id in PluginRulesList().get_plugin_id(), 'Created plugin rule is not available in ' \
                                                                   'plugin rules list.'
        else:
            # Verify error message after entering invalid values
            assert notification.errors[-1] == Messages.NotificationMessages.continue_button_code, \
                'Getting invalid notification, Expected is \'{}\'.'.format(Messages.NotificationMessages.
                                                                           continue_button_code)

            # Verify input box is getting 'Red' while entering invalid values
            assert 'error' in plugin_rule_page.plugin_id.get_css_classes(), 'Input box has not turned red'

            action_modal.cancel_button.click()

    @pytest.mark.ie
    @pytest.mark.nessus_smoke
    @pytest.mark.parametrize("create_plugin_rule", [{'plugin_id': '22964',
                                                     'severity': Nessus.Scan.Severity.CRITICAL}], indirect=True)
    @pytest.mark.nessus_expert
    def test_add_plugin_rule(self, create_plugin_rule):
        """
        # NQA-1067 : Automation test for Plugin rules
        1. Navigate to plugin rule page
        2. Click on new rule button
        3. Enter valid details for all fields
        4. Click save
        5. Verify notification for successful save appears
        """
        plugin_list = PluginRulesList()
        assert create_plugin_rule['plugin_id'] in plugin_list.get_plugin_id(), "Plugin not added"

        plugin_rule_list = PluginRulesList()
        plugin_rule_list.apply_filter(create_plugin_rule['plugin_id'])
        LoadingCircle(WAIT_SHORT)

        assert plugin_rule_list.verify_filter_result(create_plugin_rule['plugin_id']), \
            'Search failed: Plugin rule not added with plugin id "%s"' % create_plugin_rule['plugin_id']

    @pytest.mark.scanning
    @pytest.mark.parametrize("create_plugin_rule", [{'plugin_id': '22964',
                                                     'severity': Nessus.Scan.Severity.CRITICAL}], indirect=True)
    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'description': 'Created a {} scan for NQA-1067.'.format(Nessus.TemplateNames.ADVANCED.lower()),
         'target_ip': '{}, {}'.format(Nessus.Scan.Target.LOCALHOST, Nessus.Scan.Target.AWS_LINUX_TARGET_1),
         'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    def test_verify_plugin_rule_under_scan_vulnerability(self, create_plugin_rule, create_scans):
        """
        # NQA-1067 : Automation test for Plugin rules
        1. Navigate to plugin rule page
        2. Create plugin rule
        3. Create scan with two host
        4. Launch scan with two host
        5. Verify vulnerability for plugin id is critical for both the hosts
        """
        NewScanForm().save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            "Success notifications for saving scan is mismatched or missing."
        scan_name = create_scans[0]
        scan_list = ScanList()
        scan_list.loaded()

        assert scan_list.launch_scan_and_wait_for_status(scan_name=scan_name, status=API.Scan.Status.COMPLETED), \
            'Scan has not been completed successfully.'

        scan_list.click_on_scan(scan_name=scan_name)
        scan_view_page = ScanViewPage()
        scan_view_page.host_tab.click()
        ScanVulnerabilities().apply_filter(key='Plugin ID', operator='is equal to',
                                           value=create_plugin_rule['plugin_id'])
        ActionCloseModal().wait_for_modal_closed()

        scan_host = ScansHostList()

        for host in scan_host.results:
            host.click()

            assert VulnerabilityList().check_severity_name(severity=Nessus.Scan.Severity.CRITICAL.upper()), \
                'Severity of hosts is not changed'

            scan_view_page.back_link.click()

        SideNav().get_sidenav_element(Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.scanning
    @pytest.mark.parametrize("create_plugin_rule", [{'plugin_id': '22964',
                                                     'severity': Nessus.Scan.Severity.CRITICAL}], indirect=True)
    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'description': 'Created a {} scan for NQA-1067.'.format(Nessus.TemplateNames.ADVANCED.lower()),
         'target_ip': '{}, {}'.format(Nessus.Scan.Target.LOCALHOST, Nessus.Scan.Target.AWS_LINUX_TARGET_1),
         'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    def test_verify_edit_plugin_rule_host(self, create_plugin_rule, create_scans):
        """
        # NQA-1067 : Automation test for Plugin rules
        1. Navigate to plugin rule page
        2. Create plugin rule
        3. Create scan with two host
        4. Update host field with '10.10.13.11' and save
        5. Launch scan
        6. Verify vulnerability for plugin id is critical for host mentioned and Info for the other
        """
        NewScanForm().save_button.click()

        notification = Notifications()
        assert notification.successes[-1] == Messages.NotificationMessages.save_scan, \
            "Success notifications for saving scan is mismatched or missing."
        scan_name = create_scans[0]
        plugin_id = create_plugin_rule['plugin_id']

        plugin_rule_page = PluginRulesPage()
        plugin_rule_page.open()
        plugin_rule_page.edit_plugin_rule(host=Nessus.Scan.Target.LOCALHOST, plugin_id=plugin_id,
                                          severity=Nessus.Scan.Severity.CRITICAL)

        assert notification.successes[-1] == Messages.NotificationMessages.PlugInRules.update_rule, \
            'Plugin rule \'{}\' is not updated successfully.'.format(plugin_id)

        side_nav = SideNav()
        side_nav.get_sidenav_element(Nessus.Scan.Folder.MY_SCANS).click()
        scan_list = ScanList()

        with polling_ui():
            assert scan_list.launch_scan_and_wait_for_status(scan_name=scan_name, status=API.Scan.Status.COMPLETED), \
                'Scan has not been completed successfully.'

        scan_list.click_on_scan(scan_name=scan_name)
        scan_view_page = ScanViewPage()
        scan_view_page.host_tab.click()

        ScanVulnerabilities().apply_filter(key='Plugin ID', operator='is equal to', value=plugin_id)
        ActionCloseModal().wait_for_modal_closed()
        scan_host = ScansHostList()

        for host in scan_host.results:
            if host.host.text == Nessus.Scan.Target.LOCALHOST:
                host.click()
                assert VulnerabilityList().check_severity_name(severity=Nessus.Scan.Severity.CRITICAL.upper()), \
                    'Severity of selected host is not changed'
            else:
                host.click()
                assert VulnerabilityList().check_severity_name(severity=Nessus.Scan.Severity.INFO.upper()), \
                    'Severity of other host is changed'
            scan_view_page.back_link.click()

        side_nav.get_sidenav_element(Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.scanning
    @pytest.mark.parametrize("create_plugin_rule", [{'plugin_id': '22964',
                                                     'severity': Nessus.Scan.Severity.CRITICAL}], indirect=True)
    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'description': 'Created a {} scan for NQA-1067.'.format(Nessus.TemplateNames.ADVANCED.lower()),
         'target_ip': '{}, {}'.format(Nessus.Scan.Target.PUB_TARGET_3, Nessus.Scan.Target.LOCALHOST),
         'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    def test_edit_plugin_rule_severity(self, create_plugin_rule, create_scans):
        """
        # NQA-1067 : Automation test for Plugin rules
        1. Navigate to plugin rule page
        2. Create plugin rule
        3. Create scan with two host
        4. Change severity to Hide this result and host to Nessus.Scan.Target.LOCALHOST
        5. Launch scan
        6. Verify only host that is not in the rule has vulnerability
        """
        NewScanForm().save_button.click()

        notification = Notifications()
        assert notification.successes[-1] == Messages.NotificationMessages.save_scan, \
            "Success notifications for saving scan is mismatched or missing."

        plugin_id = create_plugin_rule['plugin_id']
        scan_name = create_scans[0]
        plugin_rule_page = PluginRulesPage()
        plugin_rule_page.open()
        plugin_rule_page.edit_plugin_rule(severity=Nessus.Scan.Severity.HIDE, plugin_id=plugin_id,
                                          host=Nessus.Scan.Target.PUB_TARGET_3)

        assert notification.successes[-1] == Messages.NotificationMessages.PlugInRules.update_rule, \
            'Plugin rule \'{}\' is not updated successfully.'.format(plugin_id)

        side_nav = SideNav()
        side_nav.get_sidenav_element(Nessus.Scan.Folder.MY_SCANS).click()
        scan_list = ScanList()

        with polling_ui():
            assert scan_list.launch_scan_and_wait_for_status(scan_name=scan_name, status=API.Scan.Status.COMPLETED), \
                'Scan has not been completed successfully.'

        scan_list.click_on_scan(scan_name=scan_name)
        ScanViewPage().host_tab.click()
        if is_expert():
            assert True, "Scanning limit was reached."
        else:
            ScanVulnerabilities().apply_filter(key='Plugin ID', operator='is equal to', value=plugin_id)
            ActionCloseModal().wait_for_modal_closed()

            log.info(ScansHostList().get_severity_host_list())
            assert Nessus.Scan.Target.LOCALHOST in ScansHostList().get_severity_host_list(), \
                'Severity of selected host is not hidden'

            side_nav.get_sidenav_element(Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.scanning
    @pytest.mark.parametrize("create_plugin_rule", [{'plugin_id': '22964',
                                                     'severity': Nessus.Scan.Severity.CRITICAL}], indirect=True)
    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'description': 'Created a {} scan for NQA-1067.'.format(Nessus.TemplateNames.ADVANCED.lower()),
         'target_ip': '{}, {}'.format(Nessus.Scan.Target.PUB_TARGET_3, Nessus.Scan.Target.AWS_LINUX_TARGET_1),
         'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    def test_set_expiry_date_to_past_date(self, create_plugin_rule, create_scans):
        """
        # NQA-1067 : Automation test for Plugin rules
        1. Navigate to plugin rule page
        2. Create plugin rule
        3. Create scan with two host
        4. Change expiry date to past date
        5. Launch scan
        6. Verify vulnerability is INFO for both host
        """
        NewScanForm().save_button.click()

        notification = Notifications()
        assert notification.successes[-1] == Messages.NotificationMessages.save_scan, \
            "Success notifications for saving scan is mismatched or missing."

        plugin_id = create_plugin_rule['plugin_id']
        scan_name = create_scans[0]
        plugin_rule_page = PluginRulesPage()
        plugin_rule_page.open()
        plugin_rule_page.edit_plugin_rule(expiry_date='02/02/2018', plugin_id=plugin_id)

        assert notification.successes[-1] == Messages.NotificationMessages.PlugInRules.update_rule, \
            'Plugin rule \'{}\' is not updated successfully.'.format(plugin_id)

        side_nav = SideNav()
        side_nav.get_sidenav_element(Nessus.Scan.Folder.MY_SCANS).click()
        scan_list = ScanList()

        with polling_ui():
            assert scan_list.launch_scan_and_wait_for_status(scan_name=scan_name, status=API.Scan.Status.COMPLETED), \
                'Scan has not been completed successfully.'

        scan_list.click_on_scan(scan_name=scan_name)

        scan_view_page = ScanViewPage()
        scan_view_page.host_tab.click()
        ScanVulnerabilities().apply_filter(key='Plugin ID', operator='is equal to', value=plugin_id)
        ActionCloseModal().wait_for_modal_closed()

        scan_host = ScansHostList()
        wait(lambda: visibility_of_element_located(scan_host.results), timeout_seconds=WAIT_SHORT)

        for host in scan_host.results:
            host.click()

            assert VulnerabilityList().check_severity_name(severity=Nessus.Scan.Severity.INFO.upper()), \
                'Expected severity is INFO'

            scan_view_page.back_link.click()

        side_nav.get_sidenav_element(Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.parametrize('create_plugin_rules', [
        {'plugin_list': [{"host": "", "plugin_id": 22964, "type": "recast_critical"},
                         {"host": "", "plugin_id": 11219, "type": "recast_critical"}]}], indirect=True)
    @pytest.mark.nessus_expert
    def test_plugin_rule_filter(self, create_plugin_rules):
        """
        # NQA-1067 : Automation test for Plugin rules
        1. Navigate to plugin rule page
        2. Create two plugin rules
        3. Verify two rules are saved
        4. Type '22964' in filter
        5. Verify one rule shows up
        """
        plugin_rule_page = PluginRulesPage()
        plugin_rule_page.open()

        plugin_list = PluginRulesList()
        created_plugin_ids = [plugin_rule['plugin_id'] for plugin_rule in create_plugin_rules]

        plugin_rules = self.cat.api.plugins.list_plugin_rules()['plugin_rules']
        plugin_rules_ids = [plugin_rule['plugin_id'] for plugin_rule in plugin_rules]

        assert all([plugin_id in plugin_rules_ids for plugin_id in created_plugin_ids]), \
            'Plugin Rule is not added successfully'

        plugin_list.apply_filter('22964')
        LoadingCircle(WAIT_SHORT)

        assert plugin_list.verify_filter_result('22964'), 'Search failed: Plugin rule not in the list'

        assert not plugin_list.verify_filter_result('11219'), 'Filter is not working correctly.'

        plugin_list.remove_search_icon.click()

    @pytest.mark.scanning
    @pytest.mark.parametrize("create_plugin_rule", [{'plugin_id': '22964',
                                                     'severity': Nessus.Scan.Severity.CRITICAL}], indirect=True)
    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'description': 'Created a {} scan for NQA-1067.'.format(Nessus.TemplateNames.ADVANCED.lower()),
         'target_ip': '{}, {}'.format(Nessus.Scan.Target.PUB_TARGET_3, Nessus.Scan.Target.AWS_LINUX_TARGET_1),
         'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    def test_delete_plugin_rules(self, create_plugin_rule, create_scans):
        """
        # NQA-1067 : Automation test for Plugin rules
        1. Navigate to plugin rule page
        2. Create two plugin rules
        3. Create scan with two host
        4. Delete both rules
        5. Verify rules have been deleted
        6. Launch scan
        7. Verify vulnerability is INFO for both rules
        """
        NewScanForm().save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            "Success notifications for saving scan is mismatched or missing."
        scan_name = create_scans[0]
        plugin_rule_page = PluginRulesPage()
        plugin_rule_page.open()

        plugin_id = '11219'
        plugin_rule_page.js_scroll_into_view(plugin_rule_page.new_rule_button)
        plugin_rule_page.add_new_plugin_rule(plugin_id=plugin_id, severity=Nessus.Scan.Severity.CRITICAL)
        plugin_list = PluginRulesList()

        assert plugin_id in plugin_list.get_plugin_id(), "Plugin not added"

        plugin_id = {"plugin_1": "22964", "plugin_2": "11219"}

        for plugin in plugin_id.values():
            for row in plugin_list.rows:
                if plugin == row.plugin_id.text:
                    row.remove.click()
                    delete_plugin_rule_modal = ActionCloseModal()

                    # Verify 'Delete' and 'Cancel' buttons are displayed in 'Delete Rule' modal
                    assert all([delete_plugin_rule_modal.is_element_present('modal'),
                                delete_plugin_rule_modal.is_element_present('action_button'),
                                delete_plugin_rule_modal.is_element_present('cancel_button')]), \
                        '\'Delete Rules\' modal is not displayed properly.'

                    # Verify 'Delete Rule' modal title
                    assert delete_plugin_rule_modal.modal_title.text == Nessus.PluginRules.SINGLE_DELETE_MODAL_HEADER, \
                        'Getting incorrect modal title. Expected title is \'{}\''.format(Nessus.PluginRules.
                                                                                         SINGLE_DELETE_MODAL_HEADER)

                    # Verify 'Delete Rule' modal content
                    assert delete_plugin_rule_modal.modal_content.text == Nessus.PluginRules. \
                        SINGLE_DELETE_MODAL_CONTENT, 'Getting incorrect modal content. Expected content is \'{}\''. \
                        format(Nessus.PluginRules.SINGLE_DELETE_MODAL_CONTENT)

                    delete_plugin_rule_modal.accept_action()
                    delete_plugin_rule_modal.wait_for_modal_closed()

        side_nav = SideNav()
        side_nav.get_sidenav_element(Nessus.Scan.Folder.MY_SCANS).click()
        LoadingCircle(WAIT_SHORT)
        scan_list = ScanList()

        with polling_ui():
            assert scan_list.launch_scan_and_wait_for_status(scan_name=scan_name, status=API.Scan.Status.COMPLETED), \
                'Scan has not been completed successfully.'

        scan_list.click_on_scan(scan_name=scan_name)
        scan_view_page = ScanViewPage()
        scan_view_page.host_tab.click()

        for plugin in plugin_id.values():
            ScanVulnerabilities().apply_filter(key='Plugin ID', operator='is equal to', value=plugin)
            ActionCloseModal().wait_for_modal_closed()
            scan_host = ScansHostList()

            for host in scan_host.results:
                host.click()

                assert VulnerabilityList().check_severity_name(severity=Nessus.Scan.Severity.INFO.upper()), \
                    'Expected severity is INFO'

                scan_view_page.back_link.click()
                LoadingCircle(WAIT_NORMAL)

        side_nav.get_sidenav_element(Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.parametrize('create_plugin_rules', [
        {'plugin_list': [{"host": "172.26.12.10", "plugin_id": 12345, "type": "recast_critical"},
                         {"host": "172.26.16.20", "plugin_id": 67890, "type": "recast_low"},
                         {"host": '172.26.48.75', "plugin_id": 13579, "type": "recast_medium"},
                         {"host": '172.26.75.48', "plugin_id": 24680, "type": "recast_high"},
                         {"host": '172.26.20.16', "plugin_id": 97531, "type": "recast_info"}]}], indirect=True)
    @pytest.mark.nessus_expert
    def test_check_visibility_of_delete_button(self, create_plugin_rules):
        """
        NQA-1290: Automation tests for Plugin Rules page validations
        Check visibility of Delete button when more than one plugin rules are selected
            - Navigate to Plugin Rules page
            - Create more than one plugin rules
            - Select all the rules created
            - Verify the delete button is visible
            - Verify able to delete multiple plugin rules at a time
        """
        plugin_rule_page = PluginRulesPage()
        plugin_rule_page.open()
        plugin_rule_list = PluginRulesList()

        created_plugin_ids = [plugin_rule['plugin_id'] for plugin_rule in create_plugin_rules]

        plugin_rules = self.cat.api.plugins.list_plugin_rules()['plugin_rules']
        plugin_rules_ids = [plugin_rule['plugin_id'] for plugin_rule in plugin_rules]

        assert all([plugin_id in plugin_rules_ids for plugin_id in created_plugin_ids]), \
            'Plugin Rule is not added in Plugin List successfully'

        plugin_rule_list.select_all.click()

        assert plugin_rule_list.delete_button.is_displayed(), \
            'Delete button is not visible after selecting all plugin rule.'

        plugin_rule_list.delete_button.click()
        ActionCloseModal().accept_action()
        LoadingCircle(WAIT_SHORT)

        plugin_rules = self.cat.api.plugins.list_plugin_rules()['plugin_rules']

        if plugin_rules:
            plugin_rules_ids = [plugin_rule['plugin_id'] for plugin_rule in plugin_rules]
            assert all(plugin_id not in plugin_rules_ids for plugin_id in created_plugin_ids), \
                'Plugin Rule is not deleted successfully'

    @pytest.mark.parametrize("create_plugin_rule", [{'host': '127.0.0.1', 'plugin_id': '22964',
                                                     'severity': Nessus.Scan.Severity.CRITICAL}], indirect=True)
    @pytest.mark.nessus_expert
    def test_verify_validation_for_plugin_id_while_edit(self, create_plugin_rule):
        """
        NQA-1290: Automation tests for Plugin Rules page validations
        Verify validations for plugin id field while edit
            - Navigate to Plugin Rules page
            - Create a plugin rule
            - Click on the rule created
            - Remove plugin id field and click save
            - Verify validation message appears
        """
        plugin_rule_list = PluginRulesList()
        plugin_rule_id = create_plugin_rule["plugin_id"]

        assert plugin_rule_id in plugin_rule_list.get_plugin_id(), \
            "'{}' Plugin rule is not added successfully.".format(plugin_rule_id)

        plugin_rule_list.click_on_plugin_rule(plugin_id=plugin_rule_id)
        plugin_rule_list.plugin_id.clear()
        plugin_rule_list.accept_action()

        assert Notifications().errors[-1] == Messages.NotificationMessages.continue_button_code, \
            "Error notification for blank 'Plugin ID' is missing."

        plugin_rule_list.cancel_button.click()

    @pytest.mark.parametrize('create_plugin_rules', [
        {'plugin_list': [{"host": "127.0.0.1", "plugin_id": random.randint(1000, 2000), "type": "recast_critical"},
                         {"host": "172.26.16.0", "plugin_id": random.randint(1000, 2000), "type": "recast_low"},
                         {"host": '172.26.48.75', "plugin_id": random.randint(1000, 2000), "type": "recast_medium"},
                         {"host": '172.26.75.48', "plugin_id": random.randint(1000, 2000), "type": "recast_high"},
                         {"host": '172.26.0.16', "plugin_id": random.randint(1000, 2000), "type": "recast_low"}]}],
                             indirect=True)
    @pytest.mark.nessus_expert
    def test_verify_count_of_plugin_rules_near_search_box(self, create_plugin_rules):
        """
        NQA-1290: Automation tests for Plugin Rules page validations
        Verify the count of plugin rules is same as the count shown near search box
            - Navigate to Plugin Rules page
            - Create 4-5 rules
            - Enter some string in search box
            - Verify the count of rules listed matches the count shown besides the search box
        """
        plugin_rule_page = PluginRulesPage()
        plugin_rule_page.open()
        plugin_rule_list = PluginRulesList()

        created_plugin_ids = [plugin_rule['plugin_id'] for plugin_rule in create_plugin_rules]

        plugin_rules = self.cat.api.plugins.list_plugin_rules()['plugin_rules']
        plugin_rules_ids = [plugin_rule['plugin_id'] for plugin_rule in plugin_rules]

        assert all([plugin_id in plugin_rules_ids for plugin_id in created_plugin_ids]), \
            'Plugin Rule is not added in Plugin List successfully'

        plugin_rule_list.apply_filter(filter_key=Nessus.Scan.Severity.LOW)
        LoadingCircle(WAIT_SHORT)

        assert plugin_rule_list.filtered_plugin_rule_count == len(plugin_rule_list.rows), \
            'Filtered plugin rules count is mismatched.'

    @pytest.mark.xray(test_key='NES-14481')
    @pytest.mark.xray(test_key='NES-14024')
    @pytest.mark.nessus_expert
    def test_visibility_of_new_plugin_rules_link(self):
        """
        NES-9395: UI Automation: Plugin Rules | Verify 'New Rule' popup field validation
        NES-14024: Verify the description and icon plugin rule, search plugin rules place holder
        NES-14481: Verify create a new plugin rule hyperlink navigate to create dialogue box

        Steps:
        1. Navigate to Plugin Rules page
        2. Verify that 'Create a new plugin rule' link is displayed when no rule exist. Verify link

        Scenario Tested:
        [x] Verify that 'Create a new plugin rule' link is displayed when no rule exist.
        [x] Verify that Plugin rule icon is displayed.
        [x] Verify that Plugin rule description is displayed.
        [x] Verify that 'Create a new plugin rule' hyperlink navigates user to create 'New rule' dialogue box.
        """
        # Go to Plugin Rules page
        plugin_rule_page = PluginRulesPage()
        plugin_rule_page.open()
        wait(lambda: visibility_of_element_located(plugin_rule_page.plugin_rule_description),
             waiting_for='plugin rules page to load')

        if plugin_rule_page.is_element_present('select_all'):
            plugin_rule_page.delete_all_plugin_rules()

        assert all([plugin_rule_page.is_element_present("plugin_rule_icon"),
                    plugin_rule_page.is_element_present("plugin_rule_description")]), \
            "Plugin rules icon or description is missing under plugin rules page."

        # Verify 'Create a new plugin rule' link is displayed when no rule exist
        assert plugin_rule_page.is_element_present('new_plugin_rule_link'), \
            "'Create a new plugin rule' link is not displayed."

        plugin_rule_page.new_plugin_rule_link.click()
        new_plugin_rule_modal = ActionCloseModal()
        sleep(TIME_THREE_SECONDS, reason="Popup takes sometimes little bit time to come out.")

        assert new_plugin_rule_modal.is_element_present("modal"), \
            "New rule pop up is not getting opened after clicking on 'Create a new plugin rule' link."

    @pytest.mark.nessus_expert
    def test_default_value_of_severity_drop_down(self):
        """
        NES-9395: UI Automation: Plugin Rules | Verify 'New Rule' popup field validation

        Scenario Tested:
        [x] Verify that default value of Severity dropdown is ‘Hide this result’.
        """
        # Go to Plugin Rules page
        plugin_rule_page = PluginRulesPage()
        plugin_rule_page.open()

        # Click on 'New Rule' button
        plugin_rule_page.new_rule_button.click()
        action_modal = ActionCloseModal()
        wait(lambda: visibility_of_element_located(action_modal.modal), waiting_for='New rule popup to open')

        # Verify the default value of Severity dropdown is ‘Hide this result’
        assert plugin_rule_page.severity.get_text_selected() == Nessus.Scan.Severity.HIDE, \
            'Getting incorrect default value, Expected is \'{}\''.format(Nessus.Scan.Severity.HIDE)

        action_modal.cancel_button.click()

    @pytest.mark.nessus_expert
    def test_created_plugin_rule_on_add_operation(self):
        """
        NES-9395: UI Automation: Plugin Rules | Verify 'New Rule' popup field validation

        Scenario Tested:
        [x] Verify that plugin rule is created when click Add button with mandatory details.
        """
        plugin_id = random.randint(1000, 2000)

        # Go to Plugin Rules page
        plugin_rule_page = PluginRulesPage()
        plugin_rule_page.open()

        # Click on 'New Rule' button
        plugin_rule_page.new_rule_button.click()
        action_modal = ActionCloseModal()
        wait(lambda: visibility_of_element_located(action_modal.modal), waiting_for='New rule popup to open')

        # Fills mandatory details in 'New Rule' popup
        plugin_rule_page.fill_rule_details(host='127.0.0.1', plugin_id=plugin_id)
        action_modal.accept_action()
        action_modal.wait_for_modal_closed()

        # Verify success message after adding plugin rule
        assert Notifications().successes[-1] == Messages.NotificationMessages.PlugInRules.add_rule, \
            'Getting invalid notification, Expected is \'{}\'.'.format(Messages.NotificationMessages.PlugInRules.
                                                                       add_rule)

        # Verify created plugin rule is getting added in plugin rules list
        assert str(plugin_id) in PluginRulesList().get_plugin_id(), 'Created plugin rule \'{}\' is not available ' \
                                                                    'in plugin rules list.'.format(plugin_id)

    @pytest.mark.xray(test_key='NES-14132')
    @pytest.mark.parametrize("operation_type", ["add", "edit"])
    @pytest.mark.nessus_expert
    def test_discard_plugin_rule_on_cancel_operation(self, operation_type):
        """
        NES-9395: UI Automation: Plugin Rules | Verify 'New Rule' popup field validation
        NES-14132: Verify that cancel button works properly for edit/add plugin rule pop up.

        Scenario Tested:
        [x] Verify that New Rule popup is discarded after clicking on cancel button while adding or editing plugin rule.
        """
        plugin_id = str(random.randint(1000, 2000))
        edited_plugin_id = str(random.randint(1000, 2000))

        # Go to Plugin Rules page
        plugin_rule_page = PluginRulesPage()
        plugin_rule_page.open()

        # Click on 'New Rule' button
        plugin_rule_page.new_rule_button.click()
        action_modal = ActionCloseModal()
        wait(lambda: visibility_of_element_located(action_modal.modal), waiting_for='New rule popup to open')

        # Fills mandatory details in 'New Rule' popup
        plugin_rule_page.fill_rule_details(host=Nessus.Scan.Target.LOCALHOST, plugin_id=plugin_id,
                                           severity=Nessus.Scan.Severity.CRITICAL)

        plugin_rule_list = PluginRulesList()

        if operation_type == "add":
            action_modal.cancel_button.click()
        else:
            action_modal.action_button.click()
            action_modal.wait_for_modal_closed()
            wait(lambda: plugin_rule_page.is_element_present("search_rule"), waiting_for="search plugin rule field")
            plugin_rule_list.loaded()

            assert plugin_id in plugin_rule_list.get_plugin_id(), "Failed to add new plugin rule."

            plugin_rule_list.click_on_plugin_rule(plugin_id=plugin_id)
            plugin_rule_page.fill_rule_details(host=Nessus.Scan.Target.PUB_TARGET_3, plugin_id=edited_plugin_id,
                                               severity=Nessus.Scan.Severity.MEDIUM)

            action_modal.cancel_button.click()

        # Verify 'New Rule' popup is getting closed after clicking on 'Cancel' button
        assert not action_modal.is_element_present('modal'), 'New rule popup is not getting closed after ' \
                                                             'clicking on \'Cancel\' button.'

        all_plugin_rules = plugin_rule_list.get_plugin_id()

        # Verify plugin id is not getting added in plugin rules list after clicking on Cancel button
        if operation_type == "add":
            assert plugin_id not in all_plugin_rules, "Plugin rule '{}' is getting added in plugin rules list even " \
                                                      "after clicking on 'Cancel' button.".format(plugin_id)
        else:
            assert all([plugin_id in all_plugin_rules, edited_plugin_id not in all_plugin_rules]), \
                "Plugin rule '{}' is getting edited in plugin rules list even after clicking on 'Cancel' " \
                "button.".format(edited_plugin_id)

    @pytest.mark.parametrize('plugin_rule_field', ['host', 'plugin_id', 'expiry_date'])
    @pytest.mark.nessus_expert
    def test_plugin_rule_fields_with_blank_values(self, plugin_rule_field):
        """
        NES-9395: UI Automation: Plugin Rules | Verify 'New Rule' popup field validation

        Scenario Tested:
        [x] For Host – Verify that ‘Host’ text box can be left blank.
        [x] For Plugin ID – Verify that 'Plugin ID' cannot be left blank.
        [x] For Expiration Date – Verify that 'Expiration Date' can be left blank.
        """
        plugin_id = random.randint(1000, 2000)
        plugin_rule_details = {'host': '127.0.0.1', 'plugin_id': plugin_id,
                               'expiry_date': str(datetime.today().date() + timedelta(days=1))}

        plugin_rule_details.update({plugin_rule_field: ''})

        # Click on 'New Rule' button and fills plugin rules details
        plugin_rule_page = PluginRulesPage()
        plugin_rule_page.open()
        plugin_rule_page.new_rule_button.click()
        plugin_rule_page.fill_rule_details(**plugin_rule_details)

        # Click on 'Add' button in 'New Rule' modal
        action_modal = ActionCloseModal()
        action_modal.action_button.click()
        notification = Notifications()

        if plugin_rule_field == 'plugin_id':
            # Verify error message after entering blank values
            assert notification.errors[-1] == Messages.NotificationMessages.continue_button_code, \
                'Getting invalid notification, Expected is \'{}\'.'.format(Messages.NotificationMessages.
                                                                           continue_button_code)

            action_modal.cancel_button.click()
        else:
            action_modal.wait_for_modal_closed()

            # Verify success message after adding plugin rule
            assert notification.successes[-1] == Messages.NotificationMessages.PlugInRules.add_rule, \
                'Getting invalid notification, Expected is \'{}\'.'.format(Messages.NotificationMessages.PlugInRules.
                                                                           add_rule)

            # Verify created plugin rule is getting added in plugin rules list
            assert str(plugin_id) in PluginRulesList().get_plugin_id(), 'Created plugin rule \'{}\' is not available ' \
                                                                        'in plugin rules list.'.format(plugin_id)

    @pytest.mark.nessus_expert
    def test_date_picker_field_of_plugin_rule_pop_up(self):
        """
        NES-9395: UI Automation: Plugin Rules | Verify 'New Rule' popup field validation

        Scenario Tested:
        [x] Verify that date picker calendar opens when click on expiration date field.
        [x] Verify that past date cannot be selected from calendar.
        [x] Verify that text input cannot be entered in expiration date field.
        """
        # Go to 'Plugin Rules' page and click on 'New Rule' button
        plugin_rule_page = PluginRulesPage()
        plugin_rule_page.open()
        plugin_rule_page.new_rule_button.click()

        # Verify 'Expiration Date' input field is displayed in 'New Rule' popup
        assert plugin_rule_page.is_element_present('expiration_date'), '\'Expiration Date\' input field is not ' \
                                                                       'displayed in \'New Rule\' pop-up.'

        # Click on 'Expiration Date' input field
        plugin_rule_page.expiration_date.click()

        # Verify Date picker calender is displayed after clicking on 'Expiration Date' input field
        assert plugin_rule_page.is_element_present('expiration_date_block'), \
            'Date picker calender is not opened after clicking on \'Expiration Date\' input field.'

        action_modal = ActionCloseModal()
        action_modal.close_button.click()
        action_modal.wait_for_modal_closed()

        plugin_rule_page.new_rule_button.click()
        plugin_rule_page.expiration_date.click()

        # Verify CSS class for previous disabled date
        assert all([css_class in plugin_rule_page.previous_date.get_css_classes() for css_class in
                    ['ui-datepicker-unselectable', 'ui-state-disabled']]), \
            'Previous date is not clickable from date picker calender because it\'s getting disabled.'

        # Select past date from Date picker calendar
        select_date_in_datepicker(page_class_instance=NewRuleWindow(),
                                  input_date=datetime.today().date() - timedelta(days=1))

        # Verify 'Expiration Date' value is getting blank when we select past date from date picker calender
        assert plugin_rule_page.expiration_date.text == '', 'User can select previous date from date picker calender.'

        action_modal.cancel_button.click()

    @pytest.mark.parametrize('create_plugin_rules', [{'plugin_list': [
        {"host": "172.26.12.10", "plugin_id": random.randint(1000, 2000), "type": "recast_critical",
         "date": int(datetime.timestamp(datetime.now() + timedelta(days=1)))},
        {"host": "172.26.16.20", "plugin_id": random.randint(1000, 2000), "type": "recast_low",
         "date": int(datetime.timestamp(datetime.now() + timedelta(days=2)))},
        {"host": '172.26.48.75', "plugin_id": random.randint(1000, 2000), "type": "recast_medium",
         "date": int(datetime.timestamp(datetime.now() + timedelta(days=3)))},
        {"host": '172.26.75.48', "plugin_id": random.randint(1000, 2000), "type": "recast_high",
         "date": int(datetime.timestamp(datetime.now() + timedelta(days=4)))},
        {"host": '172.26.20.16', "plugin_id": random.randint(1000, 2000), "type": "recast_info",
         "date": int(datetime.timestamp(datetime.now() + timedelta(days=5)))}]}], indirect=True)
    @pytest.mark.parametrize("sort", SortOrder.VALID_ORDERS)
    @pytest.mark.nessus_expert
    def test_ascending_descending_sort_on_plugin_rules_tabs(self, create_plugin_rules, sort):
        """
        NES-9432: UI Automation: Plugin Rules | Manage Plugin Rules

        Scenario Tested:
        [x] Verify that sorting functionality works for each columns e.g. Host, Plugin ID, Expiration, Severity
        [x] Verify that user should be able to sort plugin rules in ascending and descending order
        """
        plugin_rule_page = PluginRulesPage()
        plugin_rule_page.open()
        plugin_rule_list = PluginRulesList()

        column_mapping = {'Host': 'host_name', 'Plugin ID': 'plugin_rule_id', 'Expiration': 'expiration_date',
                          'Severity': 'severity_level'}

        for column in column_mapping.keys():
            map_attribute = column_mapping[column]

            expected_settings_list = sorted([getattr(
                plugin_rule, map_attribute) for plugin_rule in plugin_rule_list.rows], key=lambda k: k.lower(),
                reverse=(sort == SortOrder.DESCENDING))

            rendered_settings_list = sort_on_column_values(page_class_instance=plugin_rule_list, sort=sort,
                                                           column_name=column)

            assert expected_settings_list == [getattr(plugin_rule, map_attribute) for plugin_rule in
                                              rendered_settings_list], \
                '\'{}\' plugin rule tab is not sorted in \'{}\' order'.format(column, sort)

    @pytest.mark.parametrize('create_plugin_rules', [{'plugin_list': [
        {"host": "172.26.12.10", "plugin_id": random.randint(1000, 2000), "type": "recast_critical"},
        {"host": "172.26.16.20", "plugin_id": random.randint(1000, 2000), "type": "recast_low"},
        {"host": '172.26.48.75', "plugin_id": random.randint(1000, 2000), "type": "recast_medium"},
        {"host": '172.26.75.48', "plugin_id": random.randint(1000, 2000), "type": "recast_high"},
        {"host": '172.26.20.16', "plugin_id": random.randint(1000, 2000), "type": "recast_info"}]}], indirect=True)
    @pytest.mark.nessus_expert
    def test_delete_bulk_plugin_rules(self, create_plugin_rules):
        """
        NES-9432: UI Automation: Plugin Rules | Manage Plugin Rules

        Scenario Tested:
        [x] Verify that user should be able to delete single/bulk plugin rules
        """
        created_plugin_rule_id = [plugin_rule['plugin_id'] for plugin_rule in create_plugin_rules]

        plugin_rule_page = PluginRulesPage()
        plugin_rule_page.open()

        plugin_rule_list = PluginRulesList()
        plugin_rule_list.select_all_checkbox.click()

        # Verify 'Delete' button is displayed after selecting all plugin rules
        assert plugin_rule_page.is_element_present('delete_button'), '\'Delete\' button is not displayed after ' \
                                                                     'selecting all plugins rules.'

        plugin_rule_page.delete_button.click()
        delete_plugin_rule_modal = ActionCloseModal()

        # Verify 'Delete' and 'Cancel' buttons are displayed in 'Delete Rules' modal
        assert all([delete_plugin_rule_modal.is_element_present('modal'),
                    delete_plugin_rule_modal.is_element_present('action_button'),
                    delete_plugin_rule_modal.is_element_present('cancel_button')]), \
            '\'Delete Rules\' modal is not displayed properly.'

        # Verify 'Delete Rules' modal title
        assert delete_plugin_rule_modal.modal_title.text == Nessus.PluginRules.BULK_DELETE_MODAL_HEADER, \
            'Getting incorrect modal title. Expected title is \'{}\''.format(Nessus.PluginRules.
                                                                             BULK_DELETE_MODAL_HEADER)

        # Verify 'Delete Rules' modal content
        assert delete_plugin_rule_modal.modal_content.text == Nessus.PluginRules.BULK_DELETE_MODAL_CONTENT, \
            'Getting incorrect modal content. Expected content is \'{}\''.format(Nessus.PluginRules.
                                                                                 BULK_DELETE_MODAL_CONTENT)

        delete_plugin_rule_modal.accept_action()
        delete_plugin_rule_modal.wait_for_modal_closed()

        # Verify success notification after deleting plugin rules in bulk
        assert Notifications().successes[-1] == Messages.NotificationMessages.PlugInRules.bulk_delete_rules, \
            "Plugin rules are not deleted successfully."

        # Verify plugin rules are not exist after deleting plugin rules in bulk
        assert all([plugin_id not in plugin_rule_list.get_plugin_id() for plugin_id in created_plugin_rule_id]), \
            'Created plugin rules are not deleted successfully in bulk.'

    @pytest.mark.parametrize('create_plugin_rules', [{'plugin_list': [
        {"host": "172.26.12.10", "plugin_id": random.randint(1000, 2000), "type": "recast_critical"},
        {"host": "172.26.16.20", "plugin_id": random.randint(1000, 2000), "type": "recast_low"},
        {"host": '172.26.48.75', "plugin_id": random.randint(1000, 2000), "type": "recast_medium"},
        {"host": '172.26.75.48', "plugin_id": random.randint(1000, 2000), "type": "recast_high"},
        {"host": '172.26.20.16', "plugin_id": random.randint(1000, 2000), "type": "recast_info"}]}], indirect=True)
    @pytest.mark.nessus_expert
    def test_selected_plugin_rules_count(self, create_plugin_rules):
        """
        NES-9432: UI Automation: Plugin Rules | Manage Plugin Rules

        Scenario Tested:
        [x] Verify that number of selected rule count is displayed next search box with 'Clear Selected Items' link
        """
        count = 0
        created_plugin_rule_id = [plugin_rule['plugin_id'] for plugin_rule in create_plugin_rules]

        plugin_rule_page = PluginRulesPage()
        plugin_rule_page.open()

        plugin_rule_list = PluginRulesList()

        # Verify total rule count is displayed next to plugin rule search box
        assert plugin_rule_list.is_element_present('total_plugin_rule'), \
            'Total plugin rule count is not displayed next to plugin rule search box.'

        # Verify total plugin rule count
        assert int(plugin_rule_list.total_plugin_rule_count.text) == len(plugin_rule_list.rows), \
            'Getting incorrect total plugin rule count. Expected count is \'{}\''.format(len(created_plugin_rule_id))

        for plugin_id in created_plugin_rule_id[::2]:
            plugin_rule_list.select_plugin_rule(plugin_id=str(plugin_id))
            count += 1

        # Verify selected rule count is displayed next to total rule count
        assert plugin_rule_list.is_element_present('selected_plugin_rule'), \
            'Selected plugin rule count is not displayed next to total plugin rule count.'

        # Verify selected rule count
        assert int(plugin_rule_list.selected_plugin_rule_count.text) == count, \
            'Getting incorrect selected plugin rule count. Expected count is \'{}\''.format(count)

        # Verify 'Clear Selected Items' link is displayed next to selected rule count
        assert plugin_rule_list.is_element_present('clear_selected_items_link'), \
            '\'Clear Selected Items\' link is not displayed after selecting plugin rule.'

        plugin_rule_list.clear_selected_items_link.click()

        # Verify selected rule count and 'Clear Selected Items' link both are not displayed after clicking on
        # 'Clear Selected Items' link
        assert all([plugin_rule_list.is_element_present('total_plugin_rule'),
                    not plugin_rule_list.is_element_present('selected_plugin_rule'),
                    not plugin_rule_list.is_element_present('clear_selected_items_link')]), \
            '\'Clear Selected Items\' link and selected plugin rule count is still displayed after clicking on ' \
            '\'Clear Selected Items\' link.'
