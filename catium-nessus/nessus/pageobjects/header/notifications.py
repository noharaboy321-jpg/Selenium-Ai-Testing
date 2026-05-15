from selenium.common.exceptions import StaleElementReferenceException, WebDriverException, ElementNotVisibleException
from selenium.webdriver.common.by import By

from catium.lib.config import Config
from catium.lib.const import WAIT_NORMAL
from catium.lib.const.base_constants import TIME_TEN_SECONDS
from catium.lib.log import create_logger
from catium.lib.webium import Find, Finds
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.link import Link
from catium.lib.webium.controls.webium_element import WebiumWebElement
from catium.lib.webium.wait import wait
from nessus.helpers.cli_command import execute
from nessus.helpers.nessus_ui.settings import login_helper_after_server_restart
from nessus.helpers.nessuscli.helper import get_nessus_cli, stop_nessus, start_nessus
from nessus.helpers.notifications import get_notification_element
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.shared.loading import LoadingCircle

log = create_logger()
is_offer_notification_dismissed = False
is_scan_wizard_disabled = False
is_welcome_banner_handled = False
is_pendo_guide_modal_visible = False


class Notification(WebiumWebElement):
    notification = Find(by=By.CSS_SELECTOR, value='#notifications > div.notification > span')

    def loaded(self):
        """Waits for the text to appear in the notification. Very important."""
        wait(lambda: len(self.notification.text) > 0, waiting_for='Notification Text to populate.')


class NotificationError(Notification):
    notification = Find(by=By.CSS_SELECTOR, value='#notifications > div.error > span')


class NotificationSuccess(Notification):
    notification = Find(by=By.CSS_SELECTOR, value='#notifications > div.success > span')


class Notifications(NessusBasePage):
    """Page Object which returns a list of all active notifications"""

    results = Finds(Notification, by=By.CSS_SELECTOR, value='#notifications > div.notification')
    errors_msgs = Finds(NotificationError, by=By.CSS_SELECTOR, value='#notifications > div.error')
    successes_msgs = Finds(NotificationSuccess, by=By.CSS_SELECTOR, value='#notifications > div.success')
    notification_link = Find(Link, by=By.CSS_SELECTOR, value='.notification a')
    success_notifications = Finds(by=By.CSS_SELECTOR, value="#notifications > div.success > div.notification-message")
    error_notifications = Finds(by=By.CSS_SELECTOR, value="#notifications > div.error > div.notification-message")

    def __init__(self):
        super().__init__()

        if not Config.CAT_USE_SAUCE:
            wait(lambda: len(self.results) > 0, waiting_for='Notification List to populate.')
            log.debug("Notifications at load: %s",
                      self.execute_jscript('return window.localStorage.getItem("nessus.notifications")'))

    @property
    def successes(self):
        """ Return list of WebElements of success notifications """
        if Config.CAT_USE_SAUCE:
            return get_notification_element(element_for="success")
        else:
            wait(lambda: self.successes_msgs, waiting_for="Success messages to get loaded.")
            return [message.text for message in self.successes_msgs]

    @property
    def errors(self):
        """ Return list of WebElements of error notifications """
        if Config.CAT_USE_SAUCE:
            return get_notification_element(element_for="error")
        else:
            wait(lambda: self.errors_msgs, waiting_for="Error messages to get loaded.")
            return [message.text for message in self.errors_msgs]

    def list(self, dismiss_list=[]):
        """
        Build parsed list of notifications in order they appeared

        :param list dismiss_list: notifications that appear in this list will be dismissed
        :returns: list of {'text': str, 'permanent': bool} dicts
        """
        notifications = []
        for el in self.results:
            m = {}
            m['text'] = el.find_element(By.CSS_SELECTOR, '.notification-message').text
            m['permanent'] = len(el.find_elements(By.CSS_SELECTOR, '.bin')) == 0
            notifications.append(m)
            if m['text'] in dismiss_list:
                el.find_element(By.CSS_SELECTOR, '.bin').click()
            else:
                el.find_element(By.CSS_SELECTOR, '.remove').click()
        return notifications


def disable_initial_scan_wizard_nessus_home() -> None:
    """ Dismiss if offer notification appears. (Especially for Nessus Home) """

    output = execute(get_nessus_cli(), ['fix', '--get', 'show_initial_scan_wizard'])['stdout']
    if any(value.lower() in output.lower() for value in ['yes', 'Could not retrieve value']):
        execute(get_nessus_cli(), ['fix', '--set', 'show_initial_scan_wizard=no'])
        stop_nessus()
        start_nessus()
        login_helper_after_server_restart()


def close_welcome_banner_for_nessus_pro():
    """ Close the welcome banner after first login with fresh install. """
    global is_welcome_banner_handled

    if not is_welcome_banner_handled:
        action_close_modal = ActionCloseModal()

        if action_close_modal.is_element_present("welcome_banner_title"):
            log.info('Welcome banner is visible after fresh installation.')
            action_close_modal.close_button.click()
            action_close_modal.wait_for_modal_closed()
        else:
            log.info('"Welcome to Nessus Professional 10" banner is already closed')

        is_welcome_banner_handled = True


def close_welcome_banner_for_nessus_expert():
    close_welcome_banner_for_nessus_pro()


def close_pendo_guide_container_banner_for_nessus_pro():
    """ Close the welcome banner after first login with fresh install. """
    global is_pendo_guide_modal_visible

    action_close_modal = ActionCloseModal()
    is_pendo_guide_container_visible = action_close_modal.is_element_present("pendo_guide_container",
                                                                             timeout=WAIT_NORMAL)
    log.debug("Pendo guide container handled :: {}, Pendo guide container visible :: {}".format(
        is_pendo_guide_modal_visible, is_pendo_guide_container_visible))

    if not is_pendo_guide_modal_visible or is_pendo_guide_container_visible:
        if action_close_modal.is_element_present("pendo_guide_container"):
            log.info('"Welcome to Nessus 10" guide modal is visible after fresh installation.')
            action_close_modal.container_close_icon.click()
            wait(lambda: not action_close_modal.is_element_present("pendo_guide_container"),
                 waiting_for='"Welcome to Nessus 10" guide modal gets closed')
        else:
            log.info('"Welcome to Nessus 10" guide modal is already closed')

        is_pendo_guide_modal_visible = True


def close_pendo_guide_container_banner_for_nessus_expert():
    close_pendo_guide_container_banner_for_nessus_pro()


class NotificationActions(NessusBasePage):
    """Page Object which defines actions to perform upon active notifications"""

    notification = Find(by=By.CSS_SELECTOR, value='#notifications > div.notification > span')
    remove_notifications = Finds(by=By.CSS_SELECTOR, value='div.notification .remove')
    modal = Find(by=By.CSS_SELECTOR, value='.modal')
    modal_dismiss = Find(by=By.CSS_SELECTOR, value='.modal-footer .modal-close')
    modal_close = Find(by=By.CSS_SELECTOR, value='div.modal-close .remove')
    offer_notifications = Finds(Notification, by=By.CSS_SELECTOR, value='#notifications > div.notification')
    dismiss_notification_icon = Find(Clickable, by=By.CSS_SELECTOR, value='div.notification .bin')
    offer_notification_msg = Find(by=By.CSS_SELECTOR, value='.notification-message')

    def remove_all(self):
        # clear any login notifications
        for item in self.remove_notifications:
            try:
                item.click()
                log.debug('Removing notification.')
            except StaleElementReferenceException:
                log.debug('Stale element might have been already removed.')
                continue
            except WebDriverException:
                log.debug('No notifications exist or some other event.')
        wait(lambda: not self.is_element_present('notification'), waiting_for='Notification List to clear.')

        # close any modal notifications
        while self.is_element_present('modal'):
            self.modal_close.click()


    def dismiss_offer_notifications_nessus_home(self) -> None:
        """ Dismiss if offer notification/modal appears. (Especially for Nessus Home) """
        global is_offer_notification_dismissed

        if not is_offer_notification_dismissed:
            try:
                self.refresh()
                wait(lambda: self.is_element_present('dismiss_notification_icon'), timeout_seconds=TIME_TEN_SECONDS,
                     waiting_for='Notification to come up after page refresh')

                for _ in self.offer_notifications:
                    if any(word in self.offer_notification_msg.text for word in ['offer', 'lucky', 'code']):
                        log.debug('Offer notification appears after fresh installation.')
                        self.dismiss_notification_icon.click()
                        log.info('Offer notification dismissed.')
            except:
                log.info('Attempted to dismiss offer notifications if it appears.')
                pass

            is_offer_notification_dismissed = True


class ModalNotifications(NessusBasePage):
    """Page Object for modal notification lists"""

    modal = Find(by=By.CSS_SELECTOR, value='.modal')
    modal_title = Find(by=By.CSS_SELECTOR, value='.modal-title')
    modal_text = Find(by=By.CSS_SELECTOR, value='.modal-text')
    modal_dismiss = Find(by=By.CSS_SELECTOR, value='.modal-footer .modal-close')
    modal_acknowledge = Find(by=By.CSS_SELECTOR, value='.modal-footer .modal-action')
    modal_link = Find(Link, by=By.CSS_SELECTOR, value='.modal-text a')

    def __init__(self):
        super().__init__()
        wait(lambda: self.is_element_present('modal'), waiting_for='first modal to appear.')

    def list(self, dismiss_list=[]):
        """
        Build parsed list of modal banner notifications in order they appeared

        :param list dismiss_list: notifications that appear in this list will be dismissed
        :returns: list of {'title': str, 'text': str, 'permanent': bool} dicts
        """
        notifications = []
        while self.is_element_present('modal'):
            m = {}
            wait(lambda: self.is_element_present('modal_text'), waiting_for='modal text to appear.')
            m['title'] = self.modal_title.text
            m['text'] = self.modal_text.text
            m['acknowledge'] = self.is_element_present('modal_acknowledge')
            m['permanent'] = not self.is_element_present('modal_acknowledge')
            notifications.append(m)
            if m['text'] in dismiss_list:
                self.modal_acknowledge.click()
                LoadingCircle(WAIT_NORMAL)
            else:
                self.modal_dismiss.click()
        return notifications


class FeedBannerNotifications(NessusBasePage):
    """Page Object for feed banner notification lists"""

    update_banner = Find(by=By.CSS_SELECTOR, value='.update')
    feed_banner = Find(by=By.CSS_SELECTOR, value='.feed_notification_banner')
    feed_banner_text = Find(by=By.CSS_SELECTOR, value='.feed_notification_banner span')
    feed_banner_acknowledge = Find(by=By.CSS_SELECTOR, value='div[data-domselect="banners-acknowledge"] '
                                                             'a[data-domselect="dismiss-banner"]')
    feed_banner_next = Find(by=By.CSS_SELECTOR, value='div[data-domselect="multiple-banners-toggle"] '
                                                      'a[data-domselect="next"]')
    feed_banner_link = Find(Link, by=By.CSS_SELECTOR, value='.feed_notification_banner a')

    def __init__(self):
        super().__init__()
        # To avoid updated banner of new release of Nessus.
        # e.g. "A new version of Nessus is available and ready to install."
        if self.is_element_present('update_banner'):
            self.feed_banner_next.click()
        wait(lambda: self.is_element_present('feed_banner'), waiting_for='first modal to appear.')

    def list(self, dismiss_list=[]):
        """
        Build parsed list of 'feed' banner notifications in order they appeared

        :param list dismiss_list: notifications that appear in this list will be dismissed
        :returns: list of {'text': str, 'permanent': bool} dicts
        """
        notifications = []
        seen = []
        while True:
            m = {}
            m['text'] = self.feed_banner_text.text
            if m['text'] in seen:
                break
            m['permanent'] = not self.is_element_present('feed_banner_acknowledge')
            seen.append(m['text'])
            notifications.append(m)
            if m['text'] in dismiss_list:
                self.feed_banner_acknowledge.click()
            elif self.feed_banner_next:
                self.feed_banner_next.click()
        return notifications
