""""
Nessus page classes for about page in Settings

:copyright: Tenable Network Security, 2017
:date: December 29, 2017
:last_modified: Aug 09, 2024
:author: @rdutta, @smadan, @jchavda, @kpanchal, @krpatel.ctr
"""
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement
from selenium.webdriver.support import expected_conditions
from selenium.webdriver.support.expected_conditions import invisibility_of_element_located

from catium.lib.cat_registry import cat_registry
from catium.lib.const import WAIT_NORMAL, TIME_THIRTY_MINUTES
from catium.lib.const.base_constants import TIME_THREE_MINUTES, WAIT_SHORT
from catium.lib.log import create_logger
from catium.lib.webium import Find, Finds
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.table import GenericTableRow
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.driver import get_driver
from catium.lib.webium.wait import wait
from nessus.controls.radio_group import RadioGroupNessus
from nessus.lib.message.messages import Messages
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.generic.object_list import ObjectList
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.shared.loading import LoadingCircle

log = create_logger()


@cat_registry.route('settings/about')
class About(NessusBasePage):
    """Page Object class for About page in Nessus."""

    overview_tab = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="Overview"]')
    update_to_pro8_tab = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="Upgrade"]')
    software_update_tab = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="Software Update"]')
    plugin_detail_locale_tab = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="Plugin Locale"]')
    encryption_password_tab = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="Master Password"]')
    license_utilization_tab = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="License Utilization"]')
    modal_overlay = Find(by=By.CSS_SELECTOR, value='#modal-overlay')
    download_log = Find(Clickable, by=By.CSS_SELECTOR, value='#open-download-modal')
    download_button = Find(by=By.CSS_SELECTOR, value='#download-logs')
    download_cancel_button = Find(Clickable, by=By.CSS_SELECTOR, value='#download-cancel')
    sanitize_ips_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='.checkbox.large-checkbox')
    pro_store_page_content = Find(by=By.CSS_SELECTOR, value="div#cleverContent")
    buy_now_in_notification = Find(Clickable, by=By.CSS_SELECTOR, value='.history-message a')
    purchase_complete_button = Find(Clickable, by=By.CSS_SELECTOR, value=".button.secondary.modal-action")
    modal = Find(by=By.CSS_SELECTOR, value='.modal')
    plugin_locals_tab = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="Plugin Locale"]')
    tabs_of_about = Finds(by=By.CSS_SELECTOR, value='#tabs a')

    def __init__(self):
        super().__init__()

    def get_debug_log_type(self, log_type: str) -> WebElement:
        """
        Get debug log type from Download logs window.
        :param str log_type: Debug log type - Basic and Extended
        :return: debug log type from download logs pop up window.
        :rtype: WebElement
        """
        return Find(RadioGroupNessus, by=By.CSS_SELECTOR, value='.radio[aria-label="{}"]'.format(log_type),
                    context=self)

    def download_logs(self, debug_log_type: str = "Basic logs", sanitize_ips: bool = False) -> None:
        """
        Method to Download Logs under About page
        :param str debug_log_type: Debug logs type selection
        :param bool sanitize_ips: sanitize ips for debug option
        :return: None
        """
        self.download_log.click()
        self.get_debug_log_type(log_type=debug_log_type).click()
        self.sanitize_ips_checkbox.set_checked(sanitize_ips)
        self.download_button.click()


class UpdateActivationCodeWindow:
    """Page objects for activation code window."""
    activation_code_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="Activation Code"]')


class OverView(About, UpdateActivationCodeWindow):
    """Page Object for overview tab in about page under Settings in Nessus."""

    product_labels = Finds(by=By.CSS_SELECTOR, value='div[class*="floatleft"]:nth-child(1) > div > label')
    plugins_labels = Finds(by=By.CSS_SELECTOR, value='div[class*="floatleft"]:nth-child(2)  > div > label')
    feed_status = Find(by=By.CSS_SELECTOR, value='label > i.glyphicons.alert.inline')
    clear_feed_status_link = Find(Clickable, by=By.CSS_SELECTOR, value='.clear-feed-error > a')
    update_plugins_tip = Find(Clickable, by=By.CSS_SELECTOR, value='.inline-update.add-tip')
    last_updated = Find(by=By.XPATH, value=".//*[text()='Last Updated']/following-sibling::span[1]")
    expiration_date = Find(by=By.XPATH, value="//*[text()='License Expiration']/following-sibling::span")
    plugin_set = Find(by=By.XPATH, value=".//*[text()='Plugin Set']/following-sibling::span")
    activation_code = Find(by=By.CSS_SELECTOR, value='.form-group > span[data-name="Activation Code"]')
    update_activation_code_tip = Find(Clickable, by=By.CSS_SELECTOR, value='.scanner-register.glyphicons.edit')
    policy_template_version = Find(by=By.CSS_SELECTOR, value='[data-domselect="policy_template_version"]')
    registration_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value="select[data-name='Registration']")
    nessus_license_field = Find(TextField, by=By.CSS_SELECTOR, value='textarea[data-name="Nessus License"]')
    challenge_code = Find(by=By.CSS_SELECTOR, value="span[data-name='Challenge']")
    challenge_code_text = Find(by=By.CSS_SELECTOR, value="span[class='challenge']")
    update_activation_code_area = Find(TextField, by=By.CSS_SELECTOR, value='[aria-label="Activation Code"]')
    used_hosts = Find(Clickable, by=By.CSS_SELECTOR, value=".view-used-ips")
    nessus_version = Find(by=By.CSS_SELECTOR, value='[data-name="Version"]')
    buy_now_on_overview_page = Find(Clickable, by=By.CSS_SELECTOR, value='.no-edit a[data-action="buy-pro"]')
    plugin_values = Finds(by=By.CSS_SELECTOR, value='div[class*="floatleft"]:nth-child(2)  > div > span')
    upgrade_to_pro_link = Find(by=By.XPATH, value='//a[@data-action="buy-nessus-pro"]')
    manual_software_update_button = Find(by=By.CSS_SELECTOR, value='#manual-software-update')
    continue_on_button = Find(by=By.CSS_SELECTOR, value='a[class="button secondary floatleft modal-action"]')

    def get_about_page_labels(self, element) -> list:
        """
        Return the list of labels displayed in the page.
        :param element: page class element
        :return: List
        """
        return [label.text.strip() for label in element]

    def reactivate_controller(self, activation_code: str) -> None:
        """
        Update the activation code and apply it.
        :param activation_code: new activation code
        :return: None
        """
        self.update_activation_code_tip.click()
        self.activation_code_field.value = activation_code
        LoadingCircle(WAIT_NORMAL)
        ActionCloseModal().accept_action()

        LoadingCircle(WAIT_NORMAL)
        wait(lambda: invisibility_of_element_located((By.CSS_SELECTOR, '.nosession-content.preauth-content'))(
            get_driver()), timeout_seconds=TIME_THIRTY_MINUTES, waiting_for="Plugins to be updated,after reactivation.")

    def check_for_plugin_date_update(self, last_updated: str, plugin_set_id: str) -> bool:
        """
        return True if UI updated and False if UI is not update
        :param str last_updated: last updated date
        :param str plugin_set_id: plugin set id
        :return: False if UI is updated otherwise True
        :rtype: bool
        """
        self.refresh()
        return not (last_updated == self.last_updated.text and plugin_set_id == self.plugin_set.text)


@cat_registry.route(r'encryption-password')
class MasterPassword(About):
    """Page objects for Master Password"""
    new_password_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="New Password"]')
    existing_password_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="Old Password"]')
    eyeball_icon = Find(Clickable, by=By.CSS_SELECTOR, value='i[data-domselect="Show Password"]')
    save_button = Find(Clickable, by=By.CSS_SELECTOR, value='#master-password-save')
    cancel_button = Find(Clickable, by=By.CSS_SELECTOR, value='#content a[href="#/settings/about"]')
    encryption_pwd_description = Find(by=By.CSS_SELECTOR, value=".description-copy")
    encryption_pwd_desc_icon = Find(by=By.CSS_SELECTOR, value=".glyphicons.master-password")

    def __init__(self):
        super().__init__()

    def is_eye_icon_enabled(self) -> bool:
        """Returns True if hide password is enabled."""
        return True if 'enabled' in self.eyeball_icon.get_css_classes() else False

    def get_new_password_input_type(self) -> str:
        """Return type of new_password field."""
        return self.new_password_field.get_attribute('type')

    def set_master_password(self, new_password: str = '', existing_password: str = '') -> None:
        """
        Method for setting master password
        :param str new_password:  password value for new password field.
        :param str existing_password: password value for existing password field.
        :return: None
        """
        if new_password and self.is_element_present('new_password_field'):
            self.new_password_field.value = new_password
        if existing_password and self.is_element_present('existing_password_field'):
            self.existing_password_field.value = existing_password
        self.save_button.click()


@cat_registry.route(r'software-update')
class SoftwareUpdate(About):
    """Page objects for Software Update"""
    radio_group_options = Find(RadioGroupNessus, by=By.CSS_SELECTOR, value="div[data-radio-family='Software Update']"
                                                                           " div[class*='radio']")
    update_all_components = Find(RadioGroupNessus, by=By.CSS_SELECTOR, value='div[data-value="all"]')
    update_plugins = Find(RadioGroupNessus, by=By.CSS_SELECTOR, value='div[data-value="plugins"]')
    disabled = Find(RadioGroupNessus, by=By.CSS_SELECTOR,
                    value='div[data-radio-family="Software Update"] div[data-value="disabled"]')
    update_frequency = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='#update-frequency>div>select')
    update_server = Find(TextField, by=By.CSS_SELECTOR, value='input[ data-name="custom_host"]')
    save_button = Find(Clickable, by=By.CSS_SELECTOR, value='#software-update-save')
    cancel_button = Find(Clickable, by=By.CSS_SELECTOR, value='#content a[href="#/settings/about"]')
    update_frequency_custom_tip = Find(Clickable, by=By.CSS_SELECTOR, value='i[data-name="update_frequency_custom"]')
    update_frequency_default_tip = Find(Clickable, by=By.CSS_SELECTOR, value='i[data-name="update_frequency_default"]')
    hours_label = Find(by=By.CSS_SELECTOR, value='span[data-name="update_frequency_desc"]')
    update_frequency_in_hours = Find(TextField, by=By.CSS_SELECTOR, value='#update-frequency .validate.medium')
    update_frequency_remove_icon = Find(Clickable, by=By.CSS_SELECTOR, value='#update-frequency .remove')
    manual_software_update = Find(by=By.CSS_SELECTOR, value='#manual-software-update')
    update_option_labels = Finds(by=By.CSS_SELECTOR, value='div[aria-label="Version Update"] > span.radio-label')
    selected_option = Find(by=By.CSS_SELECTOR,
                           value='div[aria-label="Version Update"] > div.radio.checked + span.radio-label')
    update_options = Finds(by=By.CSS_SELECTOR, value='div.radio')
    modal_acknowledge = Find(by=By.CSS_SELECTOR, value='.modal-footer .modal-action')

    def __init__(self):
        super().__init__()

    def get_software_update_options_for_managed_scanner(self) -> list:
        """
        Return list of software update options labels.
        :return: List of software update options
        :rtype: list
        """
        update_options = []
        for option in self.update_option_labels:
            update_options.append(option.text)
        return update_options

    def get_selected_update_option(self) -> str:
        """
        Return selected update option label
        :return: selected update option label
        :rtype: str
        """
        if self.selected_option:
            return self.selected_option.text
        else:
            return ""

    def get_element_of_selected_version_update_option(self, locator_value: str) -> WebElement:
        """
        Returns web element to selected given version update option under software update tab

        :param str locator_value: locator value according to nessus ui version
        :return: Web element to get automatic update option
        :rtype: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value='div.radio.checked[data-radio-family="{}"]'.format(locator_value),
                    context=self)

    def get_selected_software_update_choice(self, locator_value: str):
        """
        Return selected update choice ("ea","ga","stable)

        :param str locator_value: locator value according to nessus ui version
        :return: selected update choice
        :rtype: str
        """
        wait(lambda: expected_conditions.element_to_be_clickable(
            (By.CSS_SELECTOR, 'div.radio.checked[data-radio-family="{}"]'.format(locator_value))),
             timeout_seconds=TIME_THREE_MINUTES, sleep_seconds=WAIT_NORMAL)

        return self.get_element_of_selected_version_update_option(locator_value=locator_value).get_attribute(
            'data-value')

    def click_and_save_software_update_option(self, option: str, accept_warning: bool = True) -> None:
        """
        Select Software update option, clicks on save button and handles the alert pop-up.
        :param str option: update option which needs to be selected
        :param bool accept_warning: True if Version update warning pop-up needs to be accepted else False
        :return: None
        """
        for update_option in self.update_options:
            if update_option.get_attribute("data-value") == option:
                update_option.click()
                break

        self.save_button.click()

        if accept_warning:
            try:
                version_update_modal = ActionCloseModal()
                version_update_modal.accept_action()
                version_update_modal.wait_for_modal_closed()
            except:
                log.warning("Same setting has already been saved.")

    def get_element_of_software_update_radio_button(self, update_option: str) -> WebElement:
        """
        Returns web element to select given automatic update option under software update tab

        :param str update_option: automatic update option to be select
        :return: Web element to click automatic update option
        :rtype: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value='div[id="software-update-radios"] div[data-value="{}"]'.format(
            update_option), context=self)

    def change_software_update_settings(self, **kwargs) -> None:
        """
        Method for changing software update settings
        :return: None
        """
        radio_option = kwargs.get('radio_option', 'all')
        frequency_option = kwargs.get('frequency_option', 'Daily')
        server_value = kwargs.get('server_value', 'plugins-internal-staging.cloud.aws.tenablesecurity.com')

        self.get_element_of_software_update_radio_button(update_option=radio_option).click()
        self.update_frequency.select_by_visible_text(frequency_option)
        self.update_server.value = server_value
        self.save_button.click()


def get_plugin_locales_labels(element) -> list:
    """
    Return the list of labels displayed in the page.
    :param element: page class element
    :return: List
    """
    return [label.text.strip() for label in element]


@cat_registry.route(r'plugin-detail-locale')
class PluginDetailLocale(About):
    """Page objects for Plugin Detail Locale"""
    enable_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div[data-domselect="enable-plugin-locales"]')
    save_button = Find(Clickable, by=By.CSS_SELECTOR, value='#language-save')
    continue_button = Find(Clickable, by=By.CSS_SELECTOR, value=".button.secondary.modal-action")
    plugin_locals_tab = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="Plugin Locale"]')
    page_lables = Finds(by=By.CSS_SELECTOR, value='.form-group .bold')
    checkbox = Find(by=By.CSS_SELECTOR, value='.form-group .checkbox')
    checkbox_description = Find(by=By.CSS_SELECTOR, value='.form-group .exclude-checkbox-description')
    locales_hint = Find(by=By.CSS_SELECTOR, value='.form-group .locales-hint')
    disabled_en = Find(by=By.CSS_SELECTOR, value='.disabled [data-value="en"]')
    enabled_en = Find(by=By.CSS_SELECTOR, value='[data-value="en"]')
    select_locale_input = Find(by=By.CSS_SELECTOR, value='[placeholder="Select locales"]')
    locales_dropdown_textfield = Find(TextField, by=By.CSS_SELECTOR, value='.select2-search input')
    no_result_dropdown = Find(by=By.CSS_SELECTOR, value='[aria-live="assertive"]')
    dropdown_area = Find(by=By.CSS_SELECTOR, value='.select2-results ul')
    dropdown_labels = Finds(by=By.CSS_SELECTOR, value='.select2-results ul li')
    remove_locales = Find(Clickable, by=By.CSS_SELECTOR, value='.select2-selection__choice__remove')
    selected_locale_option = Find(by=By.CSS_SELECTOR, value=".select2-selection span[title='{}']")
    report_modal_local_dropdown = Find(by=By.CSS_SELECTOR, value='.select2-selection--single [title=English]')
    report_modal_locale_area = Find(by=By.CSS_SELECTOR, value='.select2-results ul')
    generate_report_button = Find(Clickable, by=By.CSS_SELECTOR, value='#report-save')

    def __init__(self):
        super().__init__()

    def select_dropdown_labels(self, element) -> None:
        """
        Click on the dropdown labels according to params

        :param: element to be clicked
        :return: None
        """
        for dropdown in self.dropdown_labels:
            if dropdown.text == element:
                dropdown.click()
                break

    def save_the_locales(self):
        """
        Save the selected locales using UI

        :return: None
        """
        self.save_button.click()
        action_modal = ActionCloseModal()
        assert action_modal.is_element_present('modal'), 'warning modal is not available'
        action_modal.action_button.click()
        action_modal.wait_for_modal_closed(timeout_seconds=WAIT_NORMAL)

    def get_locale_on_report(self, element) -> WebElement:
        """
        Get the element of dropdown buttons

        :param element: element string
        :return: WebElement
        """

        return Find(by=By.CSS_SELECTOR, value=".select2-selection span[title='{}']".format(element), context=self)

    def get_radio_buttons(self, element) -> WebElement:
        """
        Get the element of radio buttons for plugin locales

        :param: element string
        :return: WebElement
        """

        return Find(by=By.CSS_SELECTOR, value='.radio[data-value="{}"]'.format(element), context=self)


@cat_registry.route(r'upgrade')
class UpdateToPro8(About):
    """Page objects for Update to Pro 8"""
    upgrade_nessus_into_prov8_button = Find(Clickable, by=By.CSS_SELECTOR,
                                            value='#content a[data-domselect="npv8_upgrade_learn_more"]')
    remind_me_later_in_popup_window = Find(by=By.CSS_SELECTOR, value='div[class="update-modal-buttons"] .modal-close')
    license_agreement_link_in_popup_window = Find(by=By.CSS_SELECTOR, value='a[target=_blank]')
    update_to_nessus_button_in_popup_window = Find(Clickable, by=By.CSS_SELECTOR,
                                                   value='.update-modal-buttons a.button')
    checkbox_in_popup_window = Find(CheckboxDiv, by=By.CSS_SELECTOR,
                                    value='input[data-domselect="npv8_upgrade_license_agreement"]')
    upgrade_icon = Find(by=By.CSS_SELECTOR, value='i.glyphicons.upgrade')
    downgrade_icon = Find(by=By.CSS_SELECTOR, value='i.glyphicons.revert')
    downgrade_nessus_into_legacy_button = Find(Clickable, by=By.CSS_SELECTOR,
                                               value='a[data-domselect="npv8_downgrade"]')
    update_link = Find(by=By.CSS_SELECTOR, value='.npv8_update a[data-domselect="npv8_upgrade_learn_more"]')

    def is_update_button_disabled(self) -> bool:
        """It will check the status of update of Nessus Professional 8
           :return: bool
        """
        return 'disabled' in self.update_to_nessus_button_in_popup_window.get_attribute('class')

    def upgrade_nessus_into_prov8(self) -> None:
        """
        upgrade the nessus into prov8
        :return: None
        """
        self.upgrade_nessus_into_prov8_button.click()
        self.checkbox_in_popup_window.check()
        self.update_to_nessus_button_in_popup_window.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.update_to_pro, \
            "did not get message for Upgraded to Pro 8"

        modal_dialog = ActionCloseModal()
        modal_dialog.close_button.click()
        modal_dialog.wait_for_modal_closed()


@cat_registry.route(r'assets')
class LicenseUtilization(About):
    """Page objects for License Utilization"""

    license_utilization_description = Find(by=By.CSS_SELECTOR, value='.description-copy')
    no_results = Find(by=By.CSS_SELECTOR, value='.empty-results')
    search_box = Find(by=By.XPATH, value='//input[@data-domselect="searchInput"]')


class HostsRecord(GenericTableRow):
    """Defines the key names for Hosts Records returned by HostsList."""

    host_ip = Find(by=By.CSS_SELECTOR, value='td:nth-child(1)')
    host_name = Find(by=By.CSS_SELECTOR, value='td:nth-child(2)')
    host_first_scanned = Find(by=By.CSS_SELECTOR, value='td:nth-child(3)')
    host_last_scanned = Find(by=By.CSS_SELECTOR, value='td:nth-child(4)')

    @property
    def ip(self):
        """ Returns name attribute of a row """
        return self.host_ip.text

    @property
    def name(self):
        """ Returns name attribute of a row """
        return self.host_name.text

    @property
    def first_scanned(self):
        """ Returns user role attribute of a row """
        return self.host_first_scanned.text

    @property
    def last_scanned(self):
        """ Returns last login attribute of a row """
        return self.host_last_scanned.text


class HostsList(ObjectList):
    """ Returns a list containing hosts displayed on the License Utilization tab for About Page. """

    configure_button = None
    generics_map = {GenericTableRow: HostsRecord}

    def is_target_in_list(self, target: str) -> bool:
        """
        This method will check if the target is present in host lists on License Utilization tab
        :param target: Ip address or DNS name of the host
        :return: True is target is present else False
        :rtype: Boolean
        """
        try:
            if target in [hosts.host_ip.text for hosts in self.rows] or \
                    target in [hosts.host_name.text for hosts in self.rows]:
                return True
        except NoSuchElementException:
            pass
        return False
