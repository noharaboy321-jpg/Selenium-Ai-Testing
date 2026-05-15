""""
Nessus test cases related to Scans with Dynamic Plugins.

:copyright: Tenable Network Security, 2018
:date: Oct 15, 2018
:last_modified: Aug 01, 2019
:author: @rdutta, @kpanchal
"""
from datetime import datetime

import pytest

from catium.helpers.sleep_lib import sleep
from catium.lib.const import WAIT_NORMAL, WAIT_LONG
from catium.lib.const.base_constants import TIME_THREE_SECONDS
from catium.lib.util import random_name
from catium.lib.webium.driver import get_driver_no_init
from nessus.lib.const import Nessus
from nessus.lib.message.messages import Messages
from nessus.pageobjects.dynamic_plugins.dynamic_plugins_page import DynamicPlugin, PluginsListByFamily
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.scans.new_scan_form import NewScanForm
from nessus.pageobjects.scans.scan_view_page import ScanViewPage
from nessus.pageobjects.scans.scans_page import ScanList
from nessus.pageobjects.sidenav.sidenav import SideNav


@pytest.mark.nessus_home
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('wait_for_plugin_families_to_be_available', 'nessus_api_login', 'login')
class TestScansWithDynamicPlugins:
    """Covers Scans with dynamic plugins related test cases."""

    plugins_filter_data_to_add = [
        {Nessus.Filter.INDEX: 1, Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_NAME,
         Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.CONTAINS, Nessus.Filter.VALUE: 'nessus'},
        {Nessus.Filter.INDEX: 2, Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_MODIFICATION_DATE,
         Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.EARLIER_THAN,
         Nessus.Filter.VALUE: datetime.today().date()},
        {Nessus.Filter.INDEX: 3, Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_ID,
         Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.CONTAINS, Nessus.Filter.VALUE: '489'},
        {Nessus.Filter.INDEX: 4, Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_TYPE,
         Nessus.Filter.VALUE: 'local', Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.EQUAL_TO}]

    plugins_filter_data_to_modify = [
        {Nessus.Filter.INDEX: 1, Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_NAME,
         Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.NOT_CONTAINS, Nessus.Filter.VALUE: 'ness'},
        {Nessus.Filter.INDEX: 3, Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_ID,
         Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.EQUAL_TO, Nessus.Filter.VALUE: '102274'}]

    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED_DYNAMIC, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED_DYNAMIC)),
         'target_ip': Nessus.Scan.Target.AWS_LINUX_TARGET_1, 'add_configuration': True}]}], indirect=True)
    def test_save_scan_without_dynamic_plugins(self, create_scans):
        """
        # NQA-1301 : Automation tests for Dynamic Scan. (step: 2)
        Test validation while saving an advance dynamic scan without any dynamic plugins.

        1. Create a scan using 'Advanced Dynamic Scan' template
        2. Add the mandatory details in Settings tab
        3. Do not navigate to Dynamic Plugins tab or navigate to 'Dynamic Plugin' tab and come back to 'settings' tab
           w/o applying any filter
        4. Hit Save button and verify validation message "Error: Please correct all form errors to continue.".
        5. Verify user should redirected to 'Dynamic Plugins' tab.

        NES-9388: UI Automation: Scans | Verify that user should not be able to save dynamic scan without adding any
                  plugin

        Scenario Tested:
        [x] Verify that user should not be able to save dynamic scan without adding any plugin.
        [x] Verify User should be redirected to "Dynamic Plugins" tab and first default plugin blank field should be
            displayed with red color highlighted, and validation message should be displayed like
            "Error: Please correct all form errors to continue".
        """
        NewScanForm().save_button.click()
        scan_name = create_scans[0]

        # Verify error notification after saving advanced dynamic scan without plugins
        assert Notifications().errors[-1] == Messages.NotificationMessages.continue_button_code, \
            "Error notification for correcting all form errors is missing or mismatched."

        # Verify page navigation URL after getting error while saving advanced dynamic scan without plugins
        assert get_driver_no_init().current_url.endswith('dynamic-plugins'), 'User had not been redirected to ' \
                                                                             '\'Dynamic Plugins\' tab'

        # Verify plugin search input box is displayed in red color border
        assert 'error' in DynamicPlugin().get_filter_value_text_element(index_value=1).get_css_classes(), \
            'Plugin search input box has not turned to red color border.'

        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()

        # Verify scan is available in scan list
        assert scan_name not in ScanList().get_all_scans(), 'Scan should not be listed in current scan_list.'

    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED_DYNAMIC, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED_DYNAMIC)),
         'target_ip': Nessus.Scan.Target.AWS_LINUX_TARGET_1, 'add_configuration': True}]}], indirect=True)
    @pytest.mark.parametrize('action_to_perform_on_filters', ['add_multiple_filter',
                                                              'modify_multiple_filter', 'delete_multiple_filter'])
    def test_multiple_filter_in_dynamic_plugins(self, create_scans, action_to_perform_on_filters):
        """
        # NQA-1301 : Automation tests for Dynamic Scan. (step: 3)
        Test to add/modify/delete multiple filter in dynamic plugins

        1. Create a scan using 'Advanced Dynamic Scan' template
        2. Add the mandatory details in Settings tab
        3. Navigate to 'Dynamic Plugins' tab and add 1 filter
        4. Select Match 'All'/'Any', Click on '+' sign against the first filter and add  more than 3 plugin filters
        5. Hit Save button and verify success notification.
        6. For 'add', verify scan is listed in current scan_list.
        7. For 'modify', open the created scan again and configure it by modifying the value of one/more
            existing plugin filter
        8. Hit Save button and verify success notification and modified value.
        9. For 'delete', verify filter is no more listed in current added filter list.
        """
        scan_name = create_scans[0]

        # Add multiple dynamic plugins filter
        dynamic_plugins = DynamicPlugin()
        dynamic_plugins.manage_dynamic_plugins(add_plugins=True, preview_plugins=False,
                                               plugins_filter_list=self.plugins_filter_data_to_add)
        dynamic_plugins.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            "Success notification for saving scan is missing or mismatched."

        # Verify scan is listed in current scan_list.
        assert scan_name in ScanList().get_all_scans(), 'Scan should listed in current scan_list.'

        # Open the created scan again and navigated to added plugins filter
        ScanList().click_on_scan(scan_name=scan_name)
        ScanViewPage().configure_button.click()
        dynamic_plugins.dynamic_plugins.click()
        sleep(sleep_time=WAIT_NORMAL, reason='waiting for page gets loaded properly')

        applied_plugins = dynamic_plugins.get_added_plugins_filter()
        applied_plugins[1]['value'] = datetime.strptime(applied_plugins[1].get('value'), '%Y-%m-%d').date()
        assert applied_plugins == self.plugins_filter_data_to_add, \
            'Applied plugin filter list is different from added plugins list'
        sleep(sleep_time=WAIT_NORMAL, reason='giving time to element load')

        if action_to_perform_on_filters != 'add_multiple_filter':
            if action_to_perform_on_filters == 'modify_multiple_filter':
                # modify existing filter value
                dynamic_plugins.manage_dynamic_plugins(preview_plugins=False,
                                                       plugins_filter_list=self.plugins_filter_data_to_modify)
            else:
                # delete existing filter
                for filter_to_delete in self.plugins_filter_data_to_modify:
                    dynamic_plugins.delete_dynamic_plugin_filter(filter_index=filter_to_delete.get(Nessus.Filter.INDEX))

            # Hit Save button and verify success notification
            dynamic_plugins.save_button.click()

            assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
                "Success notification for saving scan is missing or mismatched."

            if action_to_perform_on_filters == 'modify_multiple_filter':
                # Verify modified value
                modified_pl = dynamic_plugins.get_added_plugins_filter()
                assert all([(modified_pl[0] == self.plugins_filter_data_to_modify[0]),
                            (modified_pl[2] == self.plugins_filter_data_to_modify[1])]), \
                    'Modified filter values has not been reflected in current plugins filter list.'
            else:
                # Verify filter is no more listed in current added filter list.
                plugin_filters_after_delete = dynamic_plugins.get_added_plugins_filter()
                assert len(plugin_filters_after_delete) != len(self.plugins_filter_data_to_add), \
                    'Existing filter has not been deleted successfully.'

        sleep(sleep_time=WAIT_NORMAL, reason='Giving time to load UI elements.')
        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED_DYNAMIC, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED_DYNAMIC)),
         'target_ip': Nessus.Scan.Target.AWS_LINUX_TARGET_1, 'add_configuration': True}]}], indirect=True)
    @pytest.mark.parametrize('filter_match_type', [Nessus.Filter.FilterMatch.ALL, Nessus.Filter.FilterMatch.ANY])
    def test_filter_match_type_for_dynamic_plugins(self, create_scans, filter_match_type):
        """
        # NQA-1301 : Automation tests for Dynamic Scan. (step: 4)
        Test match_type functionality for applying filter in dynamic plugins.
        sub-part : check plugins list are different according to filter match type.

        1. Create a scan using Advanced Dynamic scan template
        2. From 'Dynamic Plugins' tab Use Match 'All' option
        3. Now add more than 1 plugin filters (eg. Plugin ID =12218 and Plugin ID=22964)
        4. Click on 'Preview Plugins' and verify error notification 'Error: No plugins were found'.
        5. Repeat above steps with 'Any' option and verify there should be atleast one plugin family listed
            in the drop-down
        """
        # Add multiple dynamic plugins filter with match type
        dynamic_plugins = DynamicPlugin()
        dynamic_plugins.manage_dynamic_plugins(add_plugins=True, preview_plugins=False, plugins_filter_list=[
            {Nessus.Filter.INDEX: 1, Nessus.Filter.MATCH_TYPE: filter_match_type,
             Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_ID,
             Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.EQUAL_TO, Nessus.Filter.VALUE: '12218'},
            {Nessus.Filter.INDEX: 2, Nessus.Filter.MATCH_TYPE: filter_match_type,
             Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_ID,
             Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.EQUAL_TO, Nessus.Filter.VALUE: '22964'}])

        # verify error notifications or plugins list as per selected filter match_type
        if filter_match_type == Nessus.Filter.FilterMatch.ALL:
            dynamic_plugins.preview_plugins.click()

            assert Notifications().errors[-1] == Messages.NotificationMessages.no_plugins_found_error, \
                "Error notification for no plugins found with a particular plugin filter is missing or mismatched."

            assert not dynamic_plugins.is_element_present('select_family_dropdown'), \
                'Plugin family drop-down is visible without any plugins'

        else:
            plugins_list_by_family = dynamic_plugins.preview_plugins_by_family()
            assert len(plugins_list_by_family.keys()) >= 1, \
                'Plugins list should contains atleast 1 plugin for one/more selected family with ‘Any’ option.'

        SideNav().get_sidenav_element(Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED_DYNAMIC, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED_DYNAMIC)),
         'target_ip': Nessus.Scan.Target.AWS_LINUX_TARGET_1, 'add_configuration': True}]}], indirect=True)
    @pytest.mark.parametrize('filter_match_type', [Nessus.Filter.FilterMatch.ALL, Nessus.Filter.FilterMatch.ANY])
    def test_invalid_dynamic_plugins(self, create_scans, filter_match_type):
        """
        # NQA-1301 : Automation tests for Dynamic Scan. (step: 4)
        Test match_type functionality for applying filter in dynamic plugins.
        sub-part : check error notification if applied filters are invalid

        1. Create a scan using Advanced Dynamic scan template
        2. From 'Dynamic Plugins' tab Use Match 'All' option
        3. Now add more than 1 plugin filters (eg. Plugin ID =200007 and Plugin ID=200007)
        4. Click on 'Preview Plugins' and verify error notification 'Error: No plugins were found'.
        5. Repeat above steps with 'Any' option.
        """
        # Add multiple dynamic plugins filter with match type
        dynamic_plugins = DynamicPlugin()
        dynamic_plugins.manage_dynamic_plugins(add_plugins=True, preview_plugins=False, plugins_filter_list=[
            {Nessus.Filter.INDEX: 1, Nessus.Filter.MATCH_TYPE: filter_match_type,
             Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_ID,
             Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.EQUAL_TO, Nessus.Filter.VALUE: '920007'},
            {Nessus.Filter.INDEX: 2, Nessus.Filter.MATCH_TYPE: filter_match_type,
             Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_ID,
             Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.EQUAL_TO, Nessus.Filter.VALUE: '920007'}])

        dynamic_plugins.preview_plugins.click()

        assert Notifications().errors[-1] == Messages.NotificationMessages.no_plugins_found_error, \
            "Error notification for no plugins found with a particular plugin filter is missing or mismatched."

        assert not dynamic_plugins.is_element_present('select_family_dropdown'), \
            'Plugin family drop-down is visible without any plugins'

        SideNav().get_sidenav_element(Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED_DYNAMIC, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED_DYNAMIC)),
         'target_ip': Nessus.Scan.Target.AWS_LINUX_TARGET_1, 'add_configuration': True}]}], indirect=True)
    def test_pagination_for_previewed_plugins_list(self, create_scans):
        """
        # NQA-1301 : Automation tests for Dynamic Scan. (step: 7)
        Test pagination for plugin preview list

        1. Create a scan using Advanced Dynamic scan template
        2. Apply filter : CANVAS Exploit Framework = true
        3. Click on 'Preview Plugin' button and select plugin family(choose family having >50 plugins)
            from 'select a family' dropdown
        4. Verify visibility of 'Result per page' dropdown and 'next/last/previous/first' icons
        5. Also verify user is able to navigate by choosing next/previous/last/first options icon
        6. Verify on navigating to new page, user will redirected to top of the page
        """
        # Add multiple dynamic plugins filter
        dynamic_plugins = DynamicPlugin()
        dynamic_plugins.manage_dynamic_plugins(
            add_plugins=True, plugins_filter_list=[
                {Nessus.Filter.INDEX: 1, Nessus.Filter.KEY: Nessus.Filter.FilterKeys.CANVAS_EXPLOIT_FRAMEWORK,
                 Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.EQUAL_TO, Nessus.Filter.VALUE: 'true'}],
            plugin_family_to_preview=['Ubuntu Local Security Checks'])
        sleep(sleep_time=TIME_THREE_SECONDS, reason='waiting for plugins list gets populated')

        # Scroll down and verify visibility of 'Result per page' dropdown
        plugins_list = PluginsListByFamily()
        dynamic_plugins.js_scroll_into_view(element=dynamic_plugins.results_per_page_dropdown)
        assert dynamic_plugins.is_element_present('results_per_page_dropdown'), \
            'Dropdown to manage count of visible plugins per page is not found'

        # Verify 'previous/first' icons is disabled for first page of pagination
        assert all([not plugins_list.object_table.table_wrapper.is_button_enabled('first_page_button'),
                    not plugins_list.object_table.table_wrapper.is_button_enabled('previous_page_button'),
                    plugins_list.object_table.table_wrapper.is_button_enabled('next_page_button'),
                    plugins_list.object_table.table_wrapper.is_button_enabled('last_page_button')]), \
            '"previous/first" icons is enabled for first page of pagination'

        plugins_list.object_table.table_wrapper.next_page_button.click()
        sleep(sleep_time=TIME_THREE_SECONDS, reason='waiting for page loaded properly after navigation')

        # Verify on navigating to new page, user will redirected to top of the page
        assert dynamic_plugins.is_element_present(element_name='select_family_dropdown'), \
            'User has not been redirected to top of the page after navigating to new page'

        # Verify visibility of 'next/last/previous/first' icons
        dynamic_plugins.js_scroll_into_view(element=dynamic_plugins.results_per_page_dropdown)
        assert all([plugins_list.object_table.table_wrapper.is_button_enabled('first_page_button'),
                    plugins_list.object_table.table_wrapper.is_button_enabled('previous_page_button'),
                    plugins_list.object_table.table_wrapper.is_button_enabled('next_page_button'),
                    plugins_list.object_table.table_wrapper.is_button_enabled('last_page_button')]), \
            '"next/last/previous/first"" icons are invisible in pagination.'

        # Navigate to the last page and verify 'next/last' icon should be disabled
        plugins_list.object_table.table_wrapper.last_page_button.click()
        sleep(sleep_time=TIME_THREE_SECONDS, reason='waiting for page loaded properly after navigation')

        assert dynamic_plugins.is_element_present(element_name='select_family_dropdown'), \
            'User has not been redirected to top of the page after navigating to new page'

        assert all([plugins_list.object_table.table_wrapper.is_button_enabled('first_page_button'),
                    plugins_list.object_table.table_wrapper.is_button_enabled('previous_page_button'),
                    not plugins_list.object_table.table_wrapper.is_button_enabled('next_page_button'),
                    not plugins_list.object_table.table_wrapper.is_button_enabled('last_page_button')]), \
            '"next/last" icons is enabled for last page of pagination'

        SideNav().get_sidenav_element(Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED_DYNAMIC, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED_DYNAMIC)),
         'target_ip': Nessus.Scan.Target.AWS_LINUX_TARGET_1, 'add_configuration': True}]}], indirect=True)
    def test_plugins_count_in_previewed_list_against_plugin_family(self, create_scans):
        """
        # NQA-1301 : Automation tests for Dynamic Scan. (step: 8)
        Test plugin counts in previewed list is exactly same as count visible next to selected plugin family.

        1. Create an Advanced Dynamic Scan, with dynamic plugins
        2. Click on ‘Preview Plugin’ button
        3. Note down the count mentioned against Plugin family listed into ‘Select a family’ dropdown
            (eg. service detection(1))
        4. Now select a plugin family from dropdown and verify no. of listed plugins for that family is exactly same as
            you noted down above. (i.e.  for service detection(1): it should list out 1 plugin in preview list)
        """
        # Add multiple dynamic plugins filter
        dynamic_plugins = DynamicPlugin()
        previewed_plugins_list = dynamic_plugins.manage_dynamic_plugins(
            add_plugins=True, preview_plugins=True, plugins_filter_list=[
                {Nessus.Filter.INDEX: 1, Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.CONTAINS,
                 Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_NAME, Nessus.Filter.VALUE: 'patch detection'}])
        sleep(sleep_time=TIME_THREE_SECONDS, reason='waiting for plugins list gets populated')

        # Verify counts are exactly same
        for key, value in previewed_plugins_list.items():
            assert int(key.split(' (')[1].split(')')[0]) == len(value), \
                'Plugins count in previewed list is mismatched with count visible next to selected plugin family.'

        SideNav().get_sidenav_element(Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED_DYNAMIC, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED_DYNAMIC)),
         'target_ip': Nessus.Scan.Target.AWS_LINUX_TARGET_1, 'add_configuration': True}]}], indirect=True)
    def test_preview_plugins_list(self, create_scans):
        """
        # NQA-1301 : Automation tests for Dynamic Scan. (step: 11)
        Test visibility of plugins list is depending upon Preview Plugin’ button.

        1. Create an Advanced Dynamic Scan, with dynamic plugins
        2. Verify invisibility of ‘Select a family’ dropdown.
        3. Click on ‘Preview Plugin’ button and verify ‘Select a family’ dropdown get visible now.
        4. Select a plugin family from dropdown and verify plugins with plugin id is visible in list now.
        """
        # Add multiple dynamic plugins filter
        dynamic_plugins = DynamicPlugin()
        dynamic_plugins.manage_dynamic_plugins(add_plugins=True, preview_plugins=False, plugins_filter_list=[
            {Nessus.Filter.INDEX: 1, Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.CONTAINS,
             Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_NAME, Nessus.Filter.VALUE: 'patch detection'}])
        sleep(sleep_time=TIME_THREE_SECONDS, reason='waiting for plugins list gets populated')

        # Verify invisibility of ‘Select a family’ dropdown.
        assert not dynamic_plugins.is_element_present(element_name='select_family_dropdown'), \
            '‘Select a family’ dropdown is visible without clicking ‘Preview Plugin’ button.'

        # Click on ‘Preview Plugin’ button and verify ‘Select a family’ dropdown get visible now
        dynamic_plugins.preview_plugins.click()
        sleep(sleep_time=WAIT_LONG, reason='waiting for plugin family dropdown to be visible')
        assert dynamic_plugins.is_element_present(element_name='select_family_dropdown'), \
            '‘Select a family’ dropdown is invisible after clicking ‘Preview Plugin’ button.'

        plugins_list = PluginsListByFamily()
        assert not plugins_list.exists(), 'Plugin list is visible without selecting any plugin family.'

        # Select a plugin family from dropdown and verify plugins with plugin id is visible in list now
        dynamic_plugins.select_family_dropdown.select_by_visible_text(text='General', exact=False)
        sleep(sleep_time=WAIT_NORMAL, reason='waiting for plugin family dropdown to be visible')
        assert plugins_list.exists(), 'Plugin list is invisible after selecting plugin family.'

        SideNav().get_sidenav_element(Nessus.Scan.Folder.MY_SCANS).click()
