"""
Header Base PageObject

:copyright: Tenable Network Security, 2017
:date: July 21, 2017
:last_modified: April 18, 2023
:author: @jamreliya, @kpanchal, krpatel
"""
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By

from catium.lib.log import create_logger
from catium.lib.webium import Find, Finds
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.link import Link
from nessus.pageobjects.basepage import NessusBasePage

log = create_logger()


class HeaderBasePage(NessusBasePage):
    """Base Page Object for the Header of Nessus Manager"""

    logo_link = Find(by=By.CSS_SELECTOR, value='header > .logo')
    top_nav_links = Finds(Link, by=By.CSS_SELECTOR, value='header > .topnav-menu')
    settings_link = Find(by=By.CSS_SELECTOR, value='header > a[href="#/settings/about"]')
    sensors_tab = Find(by=By.CSS_SELECTOR, value='header > a[href="#/sensors/agents"]')
    scan_link = Find(by=By.CSS_SELECTOR, value='header > a[href="#/scans/folders/my-scans"]')
    notification_icon = Find(by=By.CSS_SELECTOR, value='.menu-notifications')
    clear_notification = Find(by=By.CSS_SELECTOR, value='#menu-notifications-clear')
    user_name_text = Find(by=By.CSS_SELECTOR, value='.user-menu__text')
    notification_box = Finds(by=By.CSS_SELECTOR, value='.notification')
    notification_history_box = Find(by=By.CSS_SELECTOR, value='#notification-history')
    notification_box_close_button = Find(by=By.CSS_SELECTOR, value='.notification-history-header i')
    notification_history_link = Find(by=By.CSS_SELECTOR, value='#menu-notifications-view-logs')
    resource_menu_icon = Find(Clickable, by=By.CSS_SELECTOR, value='.menu-resource')
    whats_new_link = Find(Clickable, by=By.CSS_SELECTOR, value='a[title="What\'s New"]')
    documentation_link = Find(Clickable, by=By.CSS_SELECTOR, value='a[title="Documentation"]')
    community_link = Find(Clickable, by=By.CSS_SELECTOR, value='a[title="Community"]')
    research_link = Find(Clickable, by=By.CSS_SELECTOR, value='a[title="Research"]')
    plugin_release_notes_link = Find(Clickable, by=By.CSS_SELECTOR, value='a[title="Plugin Release Notes"]')
    new_page_header = Find(by=By.CSS_SELECTOR, value='h1')
    linking_key_on_sensors_tab = Find(by=By.CSS_SELECTOR, value='.no-edit')
    feed_status_banner = Find(by=By.CSS_SELECTOR, value=".feed_status_banner")
    linked_scanner = Find(Clickable, by=By.CSS_SELECTOR, value='a[href="#/sensors/scanners"]')
    cluster_page = Find(Clickable, by=By.CSS_SELECTOR, value='a[href="#/sensors/agent-cluster-migration"]')
    linking_key_text = Find(by=By.CSS_SELECTOR, value='span.key')
    logs_tab_of_scanner = Find(Clickable, by=By.CSS_SELECTOR, value='[data-name ="Logs"]')
    request_logs = Find(Clickable, by=By.CSS_SELECTOR, value='a[id="request-logs"]')

    def __init__(self):
        super().__init__()
        self.required_elements = ['logo_link']

    def click_by_link_text(self, link_text: str) -> None:
        """
        Clicks a link in the topnav if the link is there.
        :param link_text: Text for the link in the topnav_links to click.
        :return: None
        """
        log.debug('Searching for ' + link_text + " in topnav.")
        for link in self.top_nav_links:
            log.debug("Comparing " + link.text + " to " + link_text)
            if link_text.lower() in link.text.lower():
                log.debug("Text found. Clicking " + link_text)
                link.click()
                break
        else:
            raise NoSuchElementException("Element with the link text " + link_text + " not found.")

    def clear_notification_history(self) -> None:
        """Clears Notification list"""

        self.notification_icon.click()
        try:
            self.clear_notification.click()
        except NoSuchElementException:
            log.warning("Notification list is already empty")

    def get_all_notifications_from_notification_box(self) -> dict:
        """
        Clicks on notification link and gets all the notifications

        :return: dictionary with success and error elements
        :rtype: dict
        """
        error, success = [], []
        self.notification_icon.click()

        [error.append(notification.text.split('\n')[0]) if "Error" in notification.text
         else success.append(notification.text.split('\n')[0]) for notification in self.notification_box]

        return {"Success": list(set(success)), "Error": list(set(error))}
