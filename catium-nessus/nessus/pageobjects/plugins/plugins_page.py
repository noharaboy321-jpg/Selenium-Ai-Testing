""""
Nessus Page Object classes for Plugin tab.

:copyright: Tenable Network Security, 2017
:date: May 11, 2018
:last_modified: July 25, 2024
:author: @rdutta, @kpanchal, @krpatel
"""

from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement

from catium.lib.const.base_constants import TIME_FIVE_SECONDS, WAIT_SHORT, WAIT_NORMAL
from catium.lib.log import create_logger
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.table import GenericTableRow
from catium.lib.webium.controls.webium_element import WebiumWebElement
from catium.lib.webium.find import Find, Finds
from catium.pageobjects.cat_basepage import CATBasePage
from nessus.pageobjects.generic.generic_modals import UnsavedChangesModal
from nessus.pageobjects.generic.object_list import ObjectList
from nessus.pageobjects.policies.new_policy_form import NewPolicyForm
from nessus.pageobjects.scans.new_scan_form import NewScanForm
from nessus.pageobjects.shared.loading import LoadingCircle

log = create_logger()


class Plugin(NewScanForm, NewPolicyForm):
    """Page Object of plugin page"""
    disable_all = Find(Clickable, by=By.CSS_SELECTOR, value='li[data-status = "disabled"]')
    enable_all = Find(Clickable, by=By.CSS_SELECTOR, value='li[data-status = "enabled"]')
    show_enabled = Find(by=By.CSS_SELECTOR, value='.toggle span[data-function="show-enabled"]')
    show_all = Find(by=By.CSS_SELECTOR, value='.toggle span[data-function="show-all"]')
    plugin_window_message = Find(by=By.CSS_SELECTOR, value='#plugin-family-plugins tr')
    filter = Find(Clickable, by=By.CSS_SELECTOR, value='.advanced-search')
    select_key_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='.select-key select')
    plugin_id = Find(by=By.CSS_SELECTOR, value='.plugin-family-plugin-id')
    plugin_ids = Finds(by=By.CSS_SELECTOR, value='.plugin-family-plugin-id')
    plugin_dailog_box_close = Find(by=By.CSS_SELECTOR, value='.modal-close .remove')

    def __init__(self):
        super().__init__()
        self.required_elements = ['disable_all', 'enable_all']
        self.plugin.click()
        LoadingCircle(WAIT_NORMAL)


class PluginFamilyRecords(GenericTableRow):
    """Defines the key names for Plugin Family Records returned by PluginFamilyList."""
    status_family = Find(by=By.CSS_SELECTOR, value='.plugin-family-status')
    plugin_family_name = Find(by=By.CSS_SELECTOR, value='.plugin-family-name')
    total = Find(by=By.CSS_SELECTOR, value='.plugin-family-count')

    @property
    def status(self):
        """Returns current status that plugin-family."""
        return self.status_family.get_attribute('data-status')

    @property
    def name(self):
        """Returns name of the plugin-family."""
        return self.plugin_family_name.text

    @property
    def total_plugin_count(self):
        """Returns total plugins count under that plugin-family."""
        return self.total.text


class PluginFamilyList(ObjectList):
    """Returns a list containing Plugin families displayed on the Plugin Tab of New Scan form page."""
    configure_button = None
    generics_map = {GenericTableRow: PluginFamilyRecords}

    def __init__(self):
        super().__init__()

    def get_plugin_info(self, plugin_family: str) -> WebElement:
        """
        Return the plugin info element
        :param plugin_family: Name of the plugin family
        :return: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value='[data-family="{}"] .plugin-family-plugin'.format(plugin_family),
                    context=self)

    def get_all_plugin_families(self) -> list:
        """
        Returns the list of all plugin families
        :return: list of all plugin families
        :rtype: list
        """
        return [row.name for row in self.rows]

    def get_all_plugin_families_count(self) -> list:
        """
        Returns the list of all plugin families count
        :return: list of all plugin families count
        :rtype: list
        """
        return [row.total_plugin_count for row in self.rows]

    def get_plugin_families_status(self, plugin_family_list: list = None) -> dict:
        """
        Returns list of all plugin families with their status if no plugin_family name specified
        else return status of specific plugin_family
        :param list plugin_family_list: name of the plugin family under which plugin listed.
        :return: list of plugin families with their status
        :rtype: dict
        """
        plugin_families_with_status = {}
        for row in self.rows:
            if not plugin_family_list:
                plugin_families_with_status.update({row.name: row.status})
            elif plugin_family_list and (row.name in plugin_family_list):
                plugin_families_with_status.update({row.name: row.status})

        return plugin_families_with_status

    def toggle_plugin_family(self, plugin_family_list: list) -> None:
        """
        Toggles the state of plugin family
        :param list plugin_family_list: list of plugin family names
        :return: None
        """
        [row.status_family.click() for row in self.rows if row.name in plugin_family_list]

    def click_on_plugins_family(self, plugin_family: str) -> None:
        """
        View list of all plugins by clicking on it
        :param str plugin_family: name of the plugins family
        :return: None
        """
        for row in self.rows:
            log.debug("Comparing '%s' with '%s'.", row.name, plugin_family)
            if row.name == plugin_family:
                row.plugin_family_name.click()
                break
        else:
            log.warning("Plugins Family: '%s' not found in the plugin_family list", plugin_family)


class PluginsRecords(WebiumWebElement):
    """Defines the key names for Plugin Records returned by PluginsList"""
    status_plugin = Find(by=By.CSS_SELECTOR, value='.plugin-family-plugin-status')
    plugin_name = Find(by=By.CSS_SELECTOR, value='.plugin-family-plugin-name')
    plugin_id = Find(by=By.CSS_SELECTOR, value='.plugin-family-plugin-id')


class PluginsList(CATBasePage):
    """Returns a list containing Plugins displayed on the Plugin Tab against a plugin family."""
    plugin_list = Finds(PluginsRecords, by=By.CSS_SELECTOR, value='tr.plugin-family-plugin')
    plugin_id_list = Finds(PluginsRecords, by=By.CSS_SELECTOR, value='.plugin-family-plugin-id')

    def get_all_plugins(self, plugin_family: str) -> list:
        """
        Returns the list of all plugins under specified plugin family
        :param str plugin_family: name of the plugin family under which plugins are listed.
        :return: list of all plugins
        :rtype: list
        """
        PluginFamilyList().click_on_plugins_family(plugin_family=plugin_family)
        LoadingCircle(TIME_FIVE_SECONDS)
        return [row.plugin_name.text for row in self.plugin_list]

    def get_plugins_status(self, plugin_family: str, plugin_name_list: list = None) -> dict:
        """
        Returns list of all plugins with their status if no plugin name specified else return status of specific plugin
        :param str plugin_family: name of the plugin family under which plugin listed.
        :param list plugin_name_list: list of the plugin by name
        :return: list of all plugins with their status
        :rtype: dict
        """
        plugins_with_status = {}
        PluginFamilyList().click_on_plugins_family(plugin_family=plugin_family)
        LoadingCircle(TIME_FIVE_SECONDS)
        for row in self.plugin_list:
            if not plugin_name_list:
                plugins_with_status.update({row.plugin_name.text: row.status_plugin.text})
            elif plugin_name_list and (row.plugin_name.text in plugin_name_list):
                plugins_with_status.update({row.plugin_name.text: row.status_plugin.text})

        return plugins_with_status

    def toggle_plugins(self, plugin_family: str, plugin_name_list: list = [], plugin_id_list: list = []) -> None:
        """
        Toggles the state of plugins
        :param str plugin_family: name of the plugin family under which plugin listed.
        :param list plugin_name_list: list of plugins by name
        :param list plugin_id_list: list of plugins by id
        :return: None
        """
        PluginFamilyList().click_on_plugins_family(plugin_family=plugin_family)
        LoadingCircle(TIME_FIVE_SECONDS)
        for row in self.plugin_list:
            if (row.plugin_name.text in plugin_name_list) or (row.plugin_id.text in plugin_id_list):
                row.status_plugin.click()
                LoadingCircle(WAIT_SHORT)

    def click_on_plugins(self, plugin_family: str, plugins_name: str) -> None:
        """
        View plugins details by clicking on it
        :param str plugin_family: name of the plugins family under which plugin listed.
        :param str plugins_name: name of the plugin
        :return: None
        """
        PluginFamilyList().click_on_plugins_family(plugin_family=plugin_family)
        LoadingCircle(TIME_FIVE_SECONDS)
        for row in self.plugin_list:
            log.debug("Comparing '%s' with '%s'.", row.plugin_name, plugins_name)
            if row.plugin_name.text == plugins_name:
                row.plugin_name.click()
                break
        else:
            log.warning("Plugin: '%s' not found in the plugins list under '%s'", plugins_name, plugin_family)


class PluginDetailsWindow(UnsavedChangesModal):
    """Page Object for plugin details window."""
    plugin_details = Find(by=By.CSS_SELECTOR, value='.modal .policy-plugin-details')
    plugin_details_sections = Finds(by=By.CSS_SELECTOR, value='.modal .policy-plugin-details section')

    @property
    def details_window_title(self):
        """Returns window title."""
        return self.unsaved_changes_title.text

    def get_section_data(self) -> dict:
        """
        Returns data within a particular section block
        :return: every section listed in window
        :rtype: dict
        """
        section_details = {}
        for section in self.plugin_details_sections:
            section_details.update(
                {section.find_element(By.CSS_SELECTOR, 'h5').text: section.find_element(By.CSS_SELECTOR, 'div').text})

        return section_details
