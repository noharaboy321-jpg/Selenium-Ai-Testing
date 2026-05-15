"""
Page Object classes for Side navigation.

:copyright: Tenable Network Security, 2024
:date: July 21, 2017
:last_modified: July 19, 2024
:author: @rdutta, @jamreliya, @ntarwani, @yshah, @kpanchal, @mdabra
"""

from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver import ActionChains
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement

from catium.lib.log.log import create_logger
from catium.lib.webium import Find, Finds
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.link import Link
from catium.lib.webium.controls.text_field import TextField
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.generic.generic_modals import ActionCloseModal, UnsavedChangesModal

log = create_logger()


class FolderRenamingWindow(UnsavedChangesModal):
    """Page objects for renaming folder window."""
    name_field = Find(TextField, by=By.CSS_SELECTOR, value='.edit-folder-name')


class SideNav(NessusBasePage):
    """Page Object for the SideNav of Nessus Manager."""
    sidenav_links = Finds(Link, by=By.CSS_SELECTOR, value='#sidenav a')
    rename = Find(by=By.CSS_SELECTOR, value='#rename-folder')
    delete = Find(by=By.CSS_SELECTOR, value='#delete-folder')
    show_hide_link = Find(Clickable, by=By.CSS_SELECTOR, value='span[data-group="Tenable"]')
    scan_count = Finds(by=By.CSS_SELECTOR, value='span.count')
    rss_header = Find(by=By.CSS_SELECTOR, value='#rss-feed .content h1')
    feed_right_arrow_key = Find(Clickable, by=By.CSS_SELECTOR, value='.chevron-right')
    feed_left_arrow_key = Find(Clickable, by=By.CSS_SELECTOR, value='.chevron-left')
    collapse_menu_icon = Find(by=By.CSS_SELECTOR, value='#sidenav-toggle')
    resizer = Find(by=By.CSS_SELECTOR, value='.sidenav-resizer')
    read_more_link = Find(Clickable, by=By.CSS_SELECTOR, value='.read-more')
    rss_feed = Find(by=By.CSS_SELECTOR, value='p.title')
    newspaper_icon = Find(by=By.CSS_SELECTOR, value='.glyphicons.svg-icon.newspaper')
    rss_feed_modal = Find(by=By.CSS_SELECTOR, value='#rss-feed')
    tool_tip_element = Find(by=By.CSS_SELECTOR, value="div.tipsy-inner")
    folder_items = Finds(by=By.CSS_SELECTOR, value="i.folder")
    header_title = Find(by=By.CSS_SELECTOR, value='#titlebar h1')
    agent_updates_tab = Find(by=By.CSS_SELECTOR, value="a[href='#/sensors/agent-updates']")
    agent_profiles_tab = Find(by=By.CSS_SELECTOR, value="a[href='#/sensors/agent-profiles']")
    resources_section_links = Finds(by=By.CSS_SELECTOR, value='li span[data-group="Resources"] ~ div span')
    scan_tab_on_header = Find(Clickable, by=By.CSS_SELECTOR, value='a[href="#/scans/folders/my-scans"]')
    search_textbox = Find(TextField, by=By.CSS_SELECTOR, value='input[data-search="search-scans"]')
    my_scan_tab = Find(Clickable, by=By.CSS_SELECTOR, value='a[href="#/scans/folders/my-scans"][data-id="3"]')
    scanner_show_hide_link = Find(by=By.CSS_SELECTOR, value='#sidenav > ul > li:nth-child(2) > span.toggle-sidenav')
    settings_tab = Find(Clickable, by=By.CSS_SELECTOR, value='[data-topnav-menu="settings"]')
    search_box = Find(Clickable, by=By.CLASS_NAME, value='.advanced-search')


    def __init__(self):
        super().__init__()
        self.required_elements = ['sidenav_links']

    def get_sidenav_item(self, element_name: str) -> WebElement:
        """
        Get dynamic element for sidenav item after collapse
        :param str element_name: element for policy/plugin rules/customized report/community/research
        :return: Items listed in side_nav (after collapse)
        :rtype: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value='i.{}'.format(element_name), context=self)

    def get_sidenav_element(self, element_name: str) -> WebElement:
        """
        Get dynamic element for all elements under sidenav.
        :param str element_name: folders/resources/settings/accounts
        :return: elements listed in side_nav
        :rtype: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value='#sidenav a[title*="{}"]'.format(element_name), context=self)

    def get_custom_folder_expand_icon(self, folder_name: str) -> WebElement:
        """
        Get dynamic element for expand icon of custom folders.
        :param str folder_name: folder name
        :param str folder_name : folder name
        :return: expand icon element of custom folder
        :rtype: WebElement
        """
        expand_icon = self.get_sidenav_element(element_name=folder_name)
        expand_icon.location_once_scrolled_into_view
        self.get_sidenav_element(element_name=folder_name).click()
        return Find(by=By.CSS_SELECTOR, value='#sidenav ul li div a[title="{} "] i[class="fontawesome down"]'.
                    format(folder_name), context=self)

    def get_hide_show_link(self, side_nav_option: str, side_nav_sub_option: str) -> WebElement:
        """
        :param str side_nav_option: folders/resources/settings/accounts
        :param str side_nav_sub_option: Sub Element from side nav options
        :return: link element for 'Hide/show' whichever visible
        :rtype: WebElement
        """
        self.move_to_element(element=self.get_sidenav_element(element_name=side_nav_sub_option))
        return Find(by=By.CSS_SELECTOR, value='#sidenav span[data-group="{}"]'.format(side_nav_option), context=self)

    def get_all_sidenav_folders_name(self) -> list:
        """
        Returns list of Side Nav folders
        :return: List of all folders
        :rtype: list
        """
        folders_list = Finds(by=By.CSS_SELECTOR, value='#sidenav div[data-name="Folders"] a', context=self)
        try:
            return [folder.find_element(By.TAG_NAME, 'span').text for folder in folders_list]
        except NoSuchElementException:
            return []

    def click_by_link_text(self, link_text: str) -> None:
        """
        Clicks a link in the sidenav if the link is there.
        :param str link_text: Text for the link in the sidenav_links to click.
        :return: None
        """
        log.debug('Searching for ' + link_text + " in sidenav.")
        for link in self.sidenav_links:
            log.debug("Comparing " + link.text + " to " + link_text)
            if link.get_attribute('title') == link_text:
                log.debug("Text found. Clicking " + link_text)
                link.click()
                break
        else:
            raise NoSuchElementException("Element with the link text " + link_text + " not found.")

    def get_all_sidenav_links(self) -> list:
        """
        get all available link options under side navigation
        :return: list
        """
        return [link.text for link in self.sidenav_links]

    def delete_custom_folder(self, folder_name: str) -> None:
        """
        Delete a custom/created folder.
        :param str folder_name: folder to be deleted.
        """
        self.get_custom_folder_expand_icon(folder_name=folder_name).click()
        self.delete.click()

        action_modal = ActionCloseModal()
        action_modal.accept_action()

    def rename_custom_folder(self, current_folder_name: str, new_folder_name: str) -> None:
        """
        Rename a custom/created folder.
        :param str current_folder_name: folder's current name.
        :param str new_folder_name: folder name to be renamed.
        :param str new_folder_name : folder name to be renamed.
        """
        self.get_custom_folder_expand_icon(folder_name=current_folder_name).click()
        self.rename.click()
        FolderRenamingWindow().name_field.value = new_folder_name
        ActionCloseModal().accept_action()

    def get_unread_scan_count(self) -> int:
        """
        Get unread scan count next to 'My Scans' folder

        :return: unread scan count
        :rtype: int
        """
        count = 0
        for scan_count in self.scan_count:
            count += int(scan_count.text)
        return int(count)

    def get_section_show_hide_link(self, section_name: str, side_nav_sub_option: str) -> WebElement:
        """
        Get dynamic element for 'Hide/show' link of different section

        :param str section_name: Section name from side navigation pane
        :param str side_nav_sub_option: Sub Element from side nav options
        :return: link element for 'Hide/show' whichever visible
        :rtype: WebElement
        """
        # self.move_to_element(element=self.get_sidenav_element(element_name=side_nav_sub_option))
        element_icon = self.get_sidenav_element(element_name=side_nav_sub_option)
        element_icon.location_once_scrolled_into_view

        return Find(by=By.XPATH, value='.//span[@class="nav-title" and contains(text(), "{}")]//'
                                       'following-sibling::span'.format(section_name), context=self)

    def get_sidenav_width(self) -> int:
        """
        Get the current width of the side navigation pane.
        :return: Width of the side navigation pane in pixels.
        :rtype: int
        """
        return Find(by=By.CSS_SELECTOR, value='#sidenav', context=self).element.size['width']

    def drag_sidenav(self, direction: str, amount: int) -> None:
        """
        Resize the side navigation pane to a specific width.
        :param str direction: Direction to resize the side navigation pane ('in' or 'out').
        :param int amount: Amount in width to resize the side navigation pane to.
        """
        if direction == "in":
            amount = -amount
        action = ActionChains(self._driver)
        action.drag_and_drop_by_offset(self.resizer.element, amount, 0).perform()
