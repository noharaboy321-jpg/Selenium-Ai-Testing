""""
Nessus test cases related to Policies with plugins.

:copyright: Tenable Network Security, 2017
:date: May 11, 2018
:last_modified: July 30, 2020
:author: @rdutta, @kpanchal
"""
import pytest

from catium.lib.const import WAIT_NORMAL, WAIT_SHORT
from catium.lib.const.base_constants import TIME_THREE_SECONDS, TIME_FIVE_SECONDS
from catium.lib.util import random_name
from catium.lib.webium.wait import wait
from nessus.helpers.sort import sort_on_column_values
from nessus.lib.const import API, Nessus, SortOrder
from nessus.lib.message.messages import Messages
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.plugins.plugins_page import PluginFamilyList, Plugin, PluginsList
from nessus.pageobjects.policies.new_policy_form import NewPolicyForm
from nessus.pageobjects.policies.policies_page import PolicyList, PoliciesPage
from nessus.pageobjects.scans.scan_view_page import ScanViewPage
from nessus.pageobjects.shared.loading import LoadingCircle


@pytest.mark.policies_pipeline_2
@pytest.mark.nessus_home
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('wait_for_plugin_families_to_be_available', 'nessus_api_login', 'login')
class TestPoliciesWithPlugins:
    """Covers Policies with plugins related test cases."""

    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix="Policy of {} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    def test_save_policy_with_all_plugins_disabled(self, create_policies):
        """
        # NQA-1173 : Create and save a policy with all plugins disabled.
        Sub-task of #NQA-1171
        1. Create a advance policy
        2. Go to plugin tab, disable all plugins
        3. Hit Save and verify success notification.
        4. Click on scan and navigated to 'Plugin' tab.
        5. Verify the above configuration still exists and all plugins are in disabled state
        """
        policy_name = create_policies[0]

        plugins_page = Plugin()
        plugins_page.disable_all.click()

        new_policy_form = NewPolicyForm()
        new_policy_form.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.Policies.policy_saved, \
            'Success notifications for policy save is mismatched or missing.'

        policies_list = PolicyList()
        assert policy_name in policies_list.get_all_policies(), \
            'Failed to save policy, policy not found in policies list.'

        policies_list.click_on_policy(policy_name=policy_name)
        LoadingCircle(WAIT_NORMAL)
        plugins_page.plugin.click()
        plugin_family_list = PluginFamilyList()

        assert all([value == API.Status.DISABLED.lower()
                    for value in plugin_family_list.get_plugin_families_status().values()]), \
            "All plugin families are not in 'DISABLED' status."

        new_policy_form.back_to_policies.click()
        LoadingCircle(TIME_THREE_SECONDS)

    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix="Policy of {} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    def test_visibility_of_default_elements(self, create_policies):
        """
        NQA-1274: Automation tests related to plugins tab.
        1. Verify visibility of ‘Plugins’ tab and default elements
            - Create a new scan/policy having template ‘Advanced Scan’
            - Verify that ‘Plugins’ tab exists. Click on ‘Plugins’ tab
            - Verify “Show Enabled”/ “Show All”/ “Disable All”/ “Enable All” options are visible.
            - Verify that the ‘Status’ of Plugin Families present is by default Enabled.
            - Verify plugin details windows shows “No plugin family selected”.
            - Also verify ‘Save’ and “Cancel’ button.
        """
        assert NewPolicyForm().plugin.is_displayed(), "'plugins' tab is not visible."

        plugins_page = Plugin()

        assert all([plugins_page.show_enabled.is_displayed(), plugins_page.show_all.is_displayed(),
                    plugins_page.disable_all.is_displayed(), plugins_page.enable_all.is_displayed()]), \
            "'Show Enabled', 'Show All', 'Disable All' and 'Enable All' options are not visible."

        plugin_family_list = PluginFamilyList()

        assert all([value == API.Status.ENABLED
                    for value in plugin_family_list.get_plugin_families_status().values()]), \
            "All plugin families are not in by default 'ENABLED' status."

        assert plugins_page.plugin_window_message.text == 'No plugin family selected.', \
            "Plugin details window is not showing 'No plugin family selected.'."

        assert all([plugins_page.save_button.is_displayed(), plugins_page.cancel_button.is_displayed()]), \
            "'Save' and 'Cancel' buttons are not visible."

    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix="Policy of {} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    def test_verify_filter_with_plugin_family(self, create_policies):
        """
        NQA-1274: Automation tests related to plugins tab.
        2. Verify filter with any substring is successfully filtered the plugin families from the available list.
            - Create a new scan/policy having template ‘Advanced Scan’
            - Go to “Plugins” tab and verify filter search box is present with “search icon”.
            - Put some string to search any plugin family and verify the plugin family name contains your search string
            in filtered list.
            - Verify absence of “search icon” and presence of “remove_icon”.
            - Click on “remove_icon” to clear the search box.
            - Verify presence of “search icon” and absence of “remove_icon”.
        """
        plugins_page = Plugin()
        plugins_page.plugin.click()

        policy_page = PoliciesPage()

        assert all([policy_page.policies_searchbox.is_displayed(), policy_page.search_icon.is_displayed()]), \
            "Filter search box is not present with 'Search icon'."

        plugin_families = ['Backdoors', 'FTP', 'Netware', 'SNMP']
        plugin_family_list = PluginFamilyList()
        expected_family_list = plugin_family_list.get_all_plugin_families()

        for plugin_family in plugin_families:
            policy_page.apply_search_on_policies(search_key=plugin_family)
            LoadingCircle(WAIT_SHORT)
            filtered_family_list = plugin_family_list.get_all_plugin_families()

            assert (plugin_family in filtered_family_list) and (len(filtered_family_list) == 1), \
                "Searched plugin family is not available in filtered plugin family list."

        assert all([(not policy_page.search_icon.is_displayed()), policy_page.clear_search_icon.is_displayed()]), \
            "'Search icon' is visible and 'Remove icon' is not visible."

        policy_page.clear_search_icon.click()
        LoadingCircle(WAIT_SHORT)

        assert all([policy_page.search_icon.is_displayed(), (not policy_page.clear_search_icon.is_displayed())]), \
            "'Search icon' is not visible and 'Remove icon' is visible."

        assert expected_family_list == plugin_family_list.get_all_plugin_families(), \
            'All plugin families are present after removing the search.'

    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix="Policy of {} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    def test_verify_all_plugin_status_within_disabled_plugin_family(self, create_policies):
        """
        NQA-1274: Automation tests related to plugins tab.
        3.Verify disabling one plugin family will “DISABLED” all plugins within that family
            - Create a new scan/policy having template ‘Advanced Scan’
            - Go to “Plugins” tab and Click any plugin family from the list.
            - Verify it shows you all plugin names with plugin ID under that family with “ENABLED” status.
            - Now “DISABLED” the plugin family and verify all plugin names under that family becomes in “DISABLED”
            status.
        """
        netware = 'Netware'
        plugins_page = Plugin()
        plugins_page.plugin.click()

        plugin_list = PluginsList()

        assert all([value == API.Status.ENABLED.upper() for value in plugin_list.get_plugins_status(
            plugin_family=netware).values()]), "All plugins are not in by default 'ENABLED' status within '%s' " \
                                               "plugin family." % netware

        plugin_family_list = PluginFamilyList()
        plugin_family_list.toggle_plugin_family(plugin_family_list=[netware])

        assert all([value == API.Status.DISABLED.upper() for value in plugin_list.get_plugins_status(
            plugin_family=netware).values()]), "All plugins are not in 'DISABLED' status after disabling '%s' " \
                                               "plugin family." % netware

        plugins_page.back_to_policies.click()

    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix="Policy of {} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    def test_verify_scan_with_mixed_plugin_status(self, create_policies):
        """
        NQA-1274: Automation tests related to plugins tab.
        4. Verify scan can be created with mixed plugins.
            - Create a new scan/policy having template ‘Advanced Scan’
            - Go to “Plugins” tab and disable all.
            - Enable some of them and click that family to view its corresponding list.
            - Disable some of plugins under that family and verify status of that plugin family become ‘MIXED’
            - Hit save and verify success notification.
        """
        aix_local_security = 'AIX Local Security Checks'
        plugins_page = Plugin()
        plugins_page.plugin.click()

        plugins_page.disable_all.click()

        family_list = ['Amazon Linux Local Security Checks', 'Backdoors', 'CGI abuses', 'Databases', 'DNS', 'Firewalls']
        plugin_family_list = PluginFamilyList()
        plugin_family_list.toggle_plugin_family(plugin_family_list=family_list)

        plugins = ['AIX 5.1 : IY19744', 'AIX 5.1 : IY21309', 'AIX 5.1 : IY22268', 'AIX 5.1 : IY23846',
                   'AIX 5.1 : IY24231']
        plugin_list = PluginsList()
        plugin_list.toggle_plugins(plugin_family=aix_local_security, plugin_name_list=plugins)

        assert (value == API.Status.MIXED for value in plugin_family_list.get_plugin_families_status(
            plugin_family_list=[aix_local_security]).values()), "'%s' plugin family is not become in 'MIXED' " \
                                                                "status." % aix_local_security

        plugins_page.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.Policies.policy_saved, \
            'Success notification is missing after saving the policy.'

    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix="Policy of {} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    def test_verify_status_against_plugin_families_and_its_plugins(self, create_policies):
        """
        NQA-1274: Automation tests related to plugins tab.
        5. Verify status against plugin families and its plugins.
            - Create a new scan/policy having template ‘Advanced Scan’
            - Go to “Plugins” tab and verify there is a status tag visible to “ENABLED/DISABLED” against all plugin
            family.
            - Disable some of them and verify the status tag against that plugin family shows “DISABLED”.
            - Choose a Enabled plugin family and disable some of plugin under that plugin family and verify the status
            tag against that plugin name shows “DISABLED” and the status of that plugin family changed to “MIXED” from
            “ENABLED”.
        """
        aix_local_security = 'AIX Local Security Checks'
        plugins_page = Plugin()

        plugin_family_list = PluginFamilyList()

        assert all([value == API.Status.ENABLED
                    for value in plugin_family_list.get_plugin_families_status().values()]), \
            "All plugin families are not in by default 'ENABLED' status."

        family_list = ['Amazon Linux Local Security Checks', 'Backdoors', 'CGI abuses', 'Databases', 'DNS', 'Firewalls']
        plugin_family_list.toggle_plugin_family(plugin_family_list=family_list)

        for plugin_family in family_list:
            assert (value == API.Status.DISABLED.lower() for value in plugin_family_list.get_plugin_families_status(
                plugin_family_list=[plugin_family]).values()), "'%s' plugin family is not in 'DISABLED' status." \
                                                               % plugin_family

        plugins = ['AIX 5.1 : IY19744', 'AIX 5.1 : IY21309', 'AIX 5.1 : IY22268', 'AIX 5.1 : IY23846',
                   'AIX 5.1 : IY24231']
        plugin_list = PluginsList()
        plugin_list.toggle_plugins(plugin_family=aix_local_security, plugin_name_list=plugins)

        for plugin in plugins:
            assert (value == API.Status.DISABLED.upper() for value in plugin_list.get_plugins_status(
                plugin_family=aix_local_security, plugin_name_list=[plugin]).values()), \
                "'%s' plugin within '%s' plugin family is not in 'DISABLED' status after disabling the plugin family " \
                "status." % (plugin, aix_local_security)

        assert (value == API.Status.MIXED for value in plugin_family_list.get_plugin_families_status(
            plugin_family_list=[aix_local_security]).values()), "'%s' plugin family is not become in 'MIXED' status." \
                                                                % aix_local_security

        plugins_page.back_to_policies.click()

    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix="Policy of {} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    def test_verify_show_enabled_link(self, create_policies):
        """
        NQA-1274: Automation tests related to plugins tab.
        6. Verify ‘Show Enabled’ link
            - Create a new scan/policy having template ‘Advanced Scan’
            - Go to “Plugins” tab and disable some of plugins families
            - Click on “Show Enabled” option in top right corner of tab header and verify it will shows you only
            “ENABLED” plugin families.
        """
        aix_local_security = 'AIX Local Security Checks'
        plugins_page = Plugin()

        plugins = ['AIX 5.1 : IY19744', 'AIX 5.1 : IY21309', 'AIX 5.1 : IY22268', 'AIX 5.1 : IY23846',
                   'AIX 5.1 : IY24231']
        plugin_list = PluginsList()
        plugin_list.toggle_plugins(plugin_family=aix_local_security, plugin_name_list=plugins)

        family_list = ['Amazon Linux Local Security Checks', 'Backdoors', 'CGI abuses', 'Databases', 'DNS', 'Firewalls']
        plugin_family_list = PluginFamilyList()
        plugin_family_list.toggle_plugin_family(plugin_family_list=family_list)

        plugins_page.show_enabled.click()

        assert all([value == API.Status.ENABLED.upper() for value in plugin_list.get_plugins_status(
            plugin_family=aix_local_security, plugin_name_list=plugins).values() if value != '']), \
            "All plugins are not in 'ENABLED' status after clicking on 'Show Enabled' button."

        assert all([value in [API.Status.ENABLED, API.Status.MIXED]
                    for value in plugin_family_list.get_plugin_families_status().values()
                    if value != API.Status.DISABLED.lower()]), "All plugin families are not in 'ENABLED' status after" \
                                                               "clicking on 'Show Enabled' button."

        plugins_page.back_to_policies.click()

    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix="Policy of {} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    def test_verify_show_all_link(self, create_policies):
        """
        NQA-1274: Automation tests related to plugins tab.
        7. Verify ‘Show All’ link
            - Create a new scan/policy having template ‘Advanced Scan’
            - Go to “Plugins” tab and disable some of plugins families
            - Again make some families for MIXED status.
            - Click on “Show All” option in top right corner of tab header and verify it will shows you all plugin
            families including “ENABLED/ DISABLED/MIXED”.
        """
        aix_local_security = 'AIX Local Security Checks'
        plugins_page = Plugin()

        plugins = ['AIX 5.1 : IY19744', 'AIX 5.1 : IY21309', 'AIX 5.1 : IY22268', 'AIX 5.1 : IY23846',
                   'AIX 5.1 : IY24231']
        plugin_list = PluginsList()
        plugin_list.toggle_plugins(plugin_family=aix_local_security, plugin_name_list=plugins)

        family_list = ['Amazon Linux Local Security Checks', 'Backdoors', 'CGI abuses', 'Databases', 'DNS', 'Firewalls']
        plugin_family_list = PluginFamilyList()
        plugin_family_list.toggle_plugin_family(plugin_family_list=family_list)

        plugins_page.show_enabled.click()
        plugins_page.show_all.click()

        assert all([value in [API.Status.ENABLED, API.Status.DISABLED.lower(), API.Status.MIXED]
                    for value in plugin_family_list.get_plugin_families_status().values()]), \
            "All plugin families are not present with 'ENABLED', 'DISABLED' and 'MIXED' status."

        plugins_page.back_to_policies.click()

    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix="Policy of {} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    def test_verify_enable_all_button(self, create_policies):
        """
        NQA-1274: Automation tests related to plugins tab.
        8. Verify ‘Enable All’ button will enable all plugin families.
            - Create a new scan/policy having template ‘Advanced Scan’
            - Go to “Plugins” tab and disable some of plugins families
            - Again make some families for MIXED status.
            - Click on “Enable All” option in top right corner of page header and verify it will “ENABLED” all plugin
            families
        """
        aix_local_security = 'AIX Local Security Checks'
        plugins_page = Plugin()

        plugins = ['AIX 5.1 : IY19744', 'AIX 5.1 : IY21309', 'AIX 5.1 : IY22268', 'AIX 5.1 : IY23846',
                   'AIX 5.1 : IY24231']
        plugin_list = PluginsList()
        plugin_list.toggle_plugins(plugin_family=aix_local_security, plugin_name_list=plugins)

        family_list = ['Amazon Linux Local Security Checks', 'Backdoors', 'CGI abuses', 'Databases', 'DNS', 'Firewalls']
        plugin_family_list = PluginFamilyList()
        plugin_family_list.toggle_plugin_family(plugin_family_list=family_list)

        plugins_page.enable_all.click()

        assert all([value == API.Status.ENABLED.upper() for value in plugin_list.get_plugins_status(
            plugin_family=aix_local_security, plugin_name_list=plugins).values()]), \
            "All plugins within '%s' plugin family are not in 'ENABLED' status after clicking on 'Enable All' button." \
            % aix_local_security

        assert all([value == API.Status.ENABLED
                    for value in plugin_family_list.get_plugin_families_status().values()]), \
            "All plugin families are not in 'ENABLED' status after clicking on 'Enable All' button."

        plugins_page.back_to_policies.click()

    @pytest.mark.nessus_legacy
    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix="Policy of {} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    @pytest.mark.parametrize("sort", SortOrder.VALID_ORDERS)
    @pytest.mark.parametrize("column_to_sort", ["PLUGIN FAMILY", "TOTAL"])
    def test_verify_sorted_plugin_family_list(self, create_policies, sort, column_to_sort):
        """
        NQA-1274: Automation tests related to plugins tab.
        9. Sort the plugin families list by ‘Plugin Family Name’ and ‘Total’
            - Create a new scan/policy having template ‘Advanced Scan’
            - Go to “Plugins” tab and click on the sort icon visible next to the list column
            - Verify Sort order are successfully sort the list.
        """
        plugins_page = Plugin()

        column_mapping = {"PLUGIN FAMILY": "name", "TOTAL": "total_plugin_count"}
        map_attribute = column_mapping[column_to_sort]

        plugin_family_list = PluginFamilyList()

        if map_attribute == 'total_plugin_count':
            expected_scans_list = sorted([getattr(plugin_family, map_attribute)
                                          for plugin_family in plugin_family_list.rows], key=int,
                                         reverse=(sort == SortOrder.DESCENDING))
        else:
            expected_scans_list = sorted([getattr(plugin_family, map_attribute)
                                          for plugin_family in plugin_family_list.rows], key=lambda k: k.lower(),
                                         reverse=(sort == SortOrder.DESCENDING))

        rendered_scans_list = sort_on_column_values(page_class_instance=plugin_family_list, sort=sort,
                                                    column_name=column_to_sort)

        assert expected_scans_list == [getattr(scan, map_attribute) for scan in rendered_scans_list], \
            "{} is not sorted in {} order".format(column_to_sort, sort)

        plugins_page.back_to_policies.click()

    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix="Policy of {} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    def test_verify_plugin_filter(self, create_policies):
        """
        NES-9458: Manage plugin filter

        Steps:
        1.Login and navigate to Policies page
        2.Click New Policy > Select any policy template
        3.Navigate to Plugins tab
        4.Click on ‘Filter’ link beside search bar on top right corner
        5.Verify ‘Filter’ popup opens with below fields -
            - Match dropdown with All/Any options
            - Field filter dropdown shouldn't be empty
            - Relation dropdown shouldn't be empty
            - Value text-box
            - +(add), cancel, clear filter buttons
        """
        NewPolicyForm().plugin.click()
        scan_view_page = ScanViewPage()
        scan_view_page.filter_link.click()
        action_close_modal = ActionCloseModal()

        assert action_close_modal.is_element_present("modal"), "Filter modal not found"

        assert scan_view_page.is_element_present("filter_holder"), "Filter holder not found"

        assert scan_view_page.is_element_present("match_dropdown"), "Match dropdown not found"

        assert [option["label"] for option in scan_view_page.match_dropdown.option_values] == Nessus.Filter. \
            FilterMatch.FILTER_MATCH_OPTIONS, "Match dropdown isn't available with All/Any option"

        assert scan_view_page.get_filter_dropdown_element(index_value=1, element_type=Nessus.Filter.KEY). \
            is_displayed(), "Field filter dropdown not found"

        assert [option["label"] for option in scan_view_page.get_filter_dropdown_element(
            index_value=1, element_type=Nessus.Filter.KEY).option_values], "Field filter dropdown is empty."

        assert scan_view_page.get_filter_dropdown_element(
            index_value=1, element_type=Nessus.Filter.OPERATOR).is_displayed(), "Relation dropdown not found."

        assert [option["label"] for option in scan_view_page.get_filter_dropdown_element(
            index_value=1, element_type=Nessus.Filter.OPERATOR).option_values], "Relation dropdown is empty"

        assert scan_view_page.get_filter_dropdown_element(
            index_value=1, element_type=Nessus.Filter.VALUE) or scan_view_page.get_filter_value_datepicker(
            index_value=1) or scan_view_page.get_filter_value_text_element(index_value=1), "Value textbox is not found"

        assert scan_view_page.is_element_present("clear_filter_link") and action_close_modal. \
            is_element_present("action_button") and action_close_modal.is_element_present("cancel_button"), \
            "Clear filters, Apply and Cancel buttons are not found"

        action_close_modal.cancel_button.click()
        action_close_modal.wait_for_modal_closed()

    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix="Policy of {} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    def test_add_and_remove_plugin_filter(self, create_policies):
        """
        NES-9458: Manage plugin filter

        Steps:
        1.Login and navigate to Policies page
        2.Click New Policy > Select any policy template
        3.Navigate to Plugins tab
        4.Click on ‘Filter’ link beside search bar on top right corner
        5.Click on '+' button and verify that a new filter-holder is added
        6.Click on 'x' button and verify that a new filter-holder is removed

        Scenario Tested:
        [X] User is be able to add new filter from ‘+’ button
        [X] User is be able to remove added filter from ‘x’ button
        """
        NewPolicyForm().plugin.click()
        scan_view_page = ScanViewPage()
        scan_view_page.filter_link.click()
        before_add_filter_count = len(scan_view_page.count_of_filter_container)

        assert scan_view_page.is_element_present("add_filter"), "Add filter button not found"

        scan_view_page.add_filter.click()
        after_remove_filter_count = len(scan_view_page.count_of_filter_container)

        assert len(scan_view_page.count_of_filter_container) == after_remove_filter_count and len(
            scan_view_page.count_of_filter_container) > before_add_filter_count, "Add filter button didn't add new " \
                                                                                 "filter"

        scan_view_page.remove_filter.click()

        assert len(scan_view_page.count_of_filter_container) == before_add_filter_count and len(
            scan_view_page.count_of_filter_container) < after_remove_filter_count, "Remove filter button didn't " \
                                                                                   "remove the added filter"

        action_close_modal = ActionCloseModal()
        action_close_modal.cancel_button.click()
        action_close_modal.wait_for_modal_closed()

    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix="Policy of {} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    @pytest.mark.parametrize("button", [["clear", True], ["cancel", False]])
    def test_cancel_and_clear_plugin_filter(self, button, create_policies):
        """
        NES-9458: Manage plugin filter

        Test steps:
        1.Login and navigate to Policies page
        2.Click New Policy > Select any policy template
        3.Navigate to Plugins tab
        4.Click on ‘Filter’ link beside search bar on top right corner
        5.Click on 'cancel' button and verify that the no filter is added
        6.Click on 'clear-filter' button and verify that all filters added are removed

        Scenario Tested:
        [X] Filter shouldn't get added when clicked on ‘Cancel’ link
        [X] Filter should get clear and closed when clicked on ‘Clear Filter’ link
        """
        NewPolicyForm().plugin.click()
        scan_view_page = ScanViewPage()

        if button[0] == "cancel":
            scan_view_page.filter_link.click()

        scan_view_page.apply_filter(key=Nessus.Filter.FilterKeys.PLUGIN_ID,
                                    operator=Nessus.Filter.FilterOperators.CONTAINS,
                                    value='22372', apply=button[1])
        action_close_modal = ActionCloseModal()

        if button[0] == "clear":
            action_close_modal.wait_for_modal_closed()

            assert scan_view_page.count_of_filter.text == "1", "Filter is either not applied or another filter is " \
                                                               "applied previously"

            scan_view_page.clear_filter()
        elif button[0] == "cancel":
            action_close_modal.cancel_button.click()

        assert scan_view_page.count_of_filter.text == "", "Filter applied is not cleared"

    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix="Policy of {} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    @pytest.mark.parametrize("match_value", [Nessus.Filter.FilterMatch.ALL, Nessus.Filter.FilterMatch.ANY])
    @pytest.mark.parametrize("filter_values_to_apply", [
        {"filter_key": Nessus.Filter.FilterKeys.PLUGIN_NAME, "filter_operator": Nessus.Filter.FilterOperators.EQUAL_TO,
         "filter_value": 'ASG-Sentry SNMP Agent Detection'},
        {"filter_key": Nessus.Filter.FilterKeys.PLUGIN_ID, "filter_operator": Nessus.Filter.FilterOperators.EQUAL_TO,
         "filter_value": '26916'}])
    def test_manage_plugin_filter(self, match_value, filter_values_to_apply, create_policies):
        """
        NES-9458: Manage plugin filter

        Test steps:
        1.Login and navigate to Policies page
        2.Click New Policy > Select any policy template
        3.Navigate to Plugins tab
        4.Click on ‘Filter’ link beside search bar on top right corner
        5.Apply filter and verify with the filtered results
        6.Apply with both  match case ‘All’ and ‘Any’

        Scenario Tested:
        [X] Plugins gets filtered based on applied filter value
        [X] Plugins gets filtered with both match case ‘All’ and ‘Any’
        """
        NewPolicyForm().plugin.click()
        plugin_family_list = PluginFamilyList()
        plugin_list = PluginsList()

        ScanViewPage().apply_filter(key=filter_values_to_apply.get("filter_key"),
                                    operator=filter_values_to_apply.get("filter_operator"),
                                    value=filter_values_to_apply.get("filter_value"), match_type=match_value)
        ActionCloseModal().wait_for_modal_closed()

        plugin_family = plugin_family_list.get_all_plugin_families()

        if filter_values_to_apply.get("filter_key") in [Nessus.Filter.FilterKeys.PLUGIN_NAME,
                                                        Nessus.Filter.FilterKeys.PLUGIN_ID]:
            plugin_family_list.click_on_plugins_family(plugin_family[0])
            wait(lambda: plugin_list.is_element_present('plugin_list'), timeout_seconds=TIME_FIVE_SECONDS,
                 waiting_for="Waiting for plugin to be visible")

            assert filter_values_to_apply.get("filter_value") in [plugin_list.plugin_list[0].plugin_name.text,
                                                                  plugin_list.plugin_id_list[0].text], \
                "Filter is either not applied or cleared"
        else:
            assert filter_values_to_apply.get("filter_value") in plugin_family[0], \
                "Filter is either not applied or cleared for plugin family"


@pytest.mark.policies_pipeline_2
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('wait_for_plugin_families_to_be_available', 'nessus_api_login', 'login')
class TestPoliciesWithPluginsN:
    """Covers Policies with plugins related test cases.
    Refer NES-17141 that essential doesn't support it!
    """

    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix="Policy of {} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    @pytest.mark.parametrize("match_value", [Nessus.Filter.FilterMatch.ALL, Nessus.Filter.FilterMatch.ANY])
    @pytest.mark.parametrize("filter_values_to_apply", [
        {"filter_key": Nessus.Filter.FilterKeys.PLUGIN_FAMILY, "filter_value": 'Windows',
         "filter_operator": Nessus.Filter.FilterOperators.EQUAL_TO}])
    def test_manage_plugin_filters(self, match_value, filter_values_to_apply, create_policies):
        """
        NES-9458: Manage plugin filter
        Test steps:
        1.Login and navigate to Policies page
        2.Click New Policy > Select any policy template
        3.Navigate to Plugins tab
        4.Click on ‘Filter’ link beside search bar on top right corner
        5.Apply filter and verify with the filtered results
        6.Apply with both  match case ‘All’ and ‘Any’
        Scenario Tested:
        [X] Plugins gets filtered based on applied filter value
        [X] Plugins gets filtered with both match case ‘All’ and ‘Any’
        """
        NewPolicyForm().plugin.click()
        plugin_family_list = PluginFamilyList()
        plugin_list = PluginsList()

        ScanViewPage().apply_filter(key=filter_values_to_apply.get("filter_key"),
                                    operator=filter_values_to_apply.get("filter_operator"),
                                    value=filter_values_to_apply.get("filter_value"), match_type=match_value)
        ActionCloseModal().wait_for_modal_closed()

        plugin_family = plugin_family_list.get_all_plugin_families()

        if filter_values_to_apply.get("filter_key") in [Nessus.Filter.FilterKeys.PLUGIN_NAME,
                                                        Nessus.Filter.FilterKeys.PLUGIN_ID]:
            plugin_family_list.click_on_plugins_family(plugin_family[0])
            wait(lambda: plugin_list.is_element_present('plugin_list'), timeout_seconds=TIME_FIVE_SECONDS,
                 waiting_for="Waiting for plugin to be visible")

            assert filter_values_to_apply.get("filter_value") in [plugin_list.plugin_list[0].plugin_name.text,
                                                                  plugin_list.plugin_id_list[0].text], \
                "Filter is either not applied or cleared"
        else:
            assert filter_values_to_apply.get("filter_value") in plugin_family[0], \
                "Filter is either not applied or cleared for plugin family"
