""""
Nessus test cases related to Update to Pro8 tab
in about page under Settings

:copyright: Tenable Network Security, 2018
:date: April 02, 2018
:author: @mameta
"""
import pytest
from selenium.webdriver.common.by import By
from selenium.webdriver.support.expected_conditions import visibility_of_element_located, \
    invisibility_of_element_located

from catium.lib.const import WAIT_NORMAL
from catium.lib.const.base_constants import WAIT_SHORT
from catium.lib.log import create_logger
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.windows_handler import WindowsHandler
from nessus.lib.const import Nessus
from nessus.pageobjects.about.about_page import About, UpdateToPro8
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.shared.loading import LoadingCircle

log = create_logger()


@pytest.mark.nessus_settings_1
@pytest.mark.nessus_legacy
@pytest.mark.usefixtures('login')
class TestUpdateToPro8:
    """
    Covers "Update to Pro8" tab related test cases in about page under Settings.
    # NQA-1085 : automation test for Settings - About-Update to Pro8.
    """
    def test_visibility_of_update_to_pro8_tab(self):
        """
        Test "Update to Pro8" tab is present/visible in about page
        1. Navigate to About page under Settings.
        2. Verify visibility of "Update to Pro8" tab.
        """
        about_page = About()
        about_page.open()
        LoadingCircle(WAIT_NORMAL)
        assert visibility_of_element_located((about_page.update_to_pro8_tab.we_by,
                                              about_page.update_to_pro8_tab.we_value))(get_driver_no_init()), \
            "Update to Pro8 tab is invisible."

    def test_update_to_pro8_button_and_popup_window(self):
        """
        Test "Update to Pro8" tab is present/visible in about page
        1. Navigate to About page under Settings.
        2. Verify the presence of “Update to Nessus Pro v8” button and corresponding pop-up window
        """
        about_page = About()
        about_page.open()
        LoadingCircle(WAIT_NORMAL)
        about_page.update_to_pro8_tab.click()
        update_to_pro8_tab = UpdateToPro8()
        assert visibility_of_element_located((update_to_pro8_tab.upgrade_nessus_into_prov8_button.we_by,
                                              update_to_pro8_tab.upgrade_nessus_into_prov8_button.we_value))(
            get_driver_no_init()), "Update to Pro8 tab is invisible."

        update_to_pro8_tab.upgrade_nessus_into_prov8_button.click()
        LoadingCircle(WAIT_SHORT)

        assert visibility_of_element_located((By.CSS_SELECTOR, '.modal'))(get_driver_no_init()), \
            'update-modal pop up is not visible'

        about_page.click_offset(element=about_page.modal_overlay, x_offset=12, y_offset=12)
        LoadingCircle(WAIT_SHORT)

        assert invisibility_of_element_located((By.CSS_SELECTOR, '.modal'))(get_driver_no_init()), \
            'update-modal pop up is visible'

    def test_nessus_professional_popup_window_close(self):
        """
        1. Navigate to About page under Settings.
        2. Verify “X” icon in “Nessus Professional v8” window
        """
        about_page = About()
        about_page.open()

        LoadingCircle(WAIT_NORMAL)
        about_page.update_to_pro8_tab.click()

        update_to_pro8_tab = UpdateToPro8()
        update_to_pro8_tab.upgrade_nessus_into_prov8_button.click()
        action_close_modal = ActionCloseModal()
        action_close_modal.close_button.click()
        action_close_modal.wait_for_modal_closed()

        assert invisibility_of_element_located((By.CSS_SELECTOR, '.modal'))(get_driver_no_init()), \
            'update-modal pop up is visible'

    def test_remind_me_later_link_popup_window(self):
        """
        1. Navigate to About page under Settings.
        2. click on “Update to Pro 8” tab.
        3. verify “Remind me later” link is present in “Nessus Professional v8” window
        """
        about_page = About()
        about_page.open()
        LoadingCircle(WAIT_NORMAL)
        about_page.update_to_pro8_tab.click()

        update_to_pro8_tab = UpdateToPro8()
        update_to_pro8_tab.upgrade_nessus_into_prov8_button.click()
        assert visibility_of_element_located((update_to_pro8_tab.remind_me_later_in_popup_window.we_by,
                                              update_to_pro8_tab.remind_me_later_in_popup_window.we_value))(
            get_driver_no_init()), "Remind me Later Link is invisible."
        update_to_pro8_tab.remind_me_later_in_popup_window.click()

        assert invisibility_of_element_located((By.CSS_SELECTOR, '.modal'))(get_driver_no_init()), \
            'update-modal pop up is visible'

    def test_license_subscription_agreement_popup_window(self):
        """
        1. Navigate to About page under Settings.
        2. click on “Update to Pro 8” tab.
        3. Verify “Nessus Software License and Subscription Agreement” documentation link
        """
        about_page = About()
        about_page.open()
        LoadingCircle(WAIT_NORMAL)
        about_page.update_to_pro8_tab.click()

        update_to_pro8_tab = UpdateToPro8()
        update_to_pro8_tab.upgrade_nessus_into_prov8_button.click()
        assert visibility_of_element_located((update_to_pro8_tab.license_agreement_link_in_popup_window.we_by,
                                              update_to_pro8_tab.license_agreement_link_in_popup_window.we_value))(
            get_driver_no_init()), "License agreement Link is invisible."

        update_to_pro8_tab.license_agreement_link_in_popup_window.click()

        window_handler = WindowsHandler()
        window_ids_for_agreement = window_handler.handles[1]
        window_handler.switch_to_window(window_ids_for_agreement)
        LoadingCircle(WAIT_NORMAL)

        assert get_driver_no_init().current_url == Nessus.About.UPDATE_TO_PRO8_LICENSE_AGREEMENT_URL, \
            "License agreement URL is differ from the expected"

        window_ids = window_handler.handles[0]
        window_handler.switch_to_window(window_ids)

        action_close_modal = ActionCloseModal()
        action_close_modal.close_button.click()
        action_close_modal.wait_for_modal_closed()

        assert invisibility_of_element_located((By.CSS_SELECTOR, '.modal'))(get_driver_no_init()), \
            'update-modal pop up is visible'

    def test_nessus_professional_button_popup_window(self):
        """
        1. Navigate to About page under Settings.
        2. click on “Update to Pro 8” tab.
        3. Verify state of “Update to Nessus Professional 8” button is depending upon the checkbox
        """
        about_page = About()
        about_page.open()

        LoadingCircle(WAIT_NORMAL)
        about_page.update_to_pro8_tab.click()

        update_to_pro8_tab = UpdateToPro8()
        update_to_pro8_tab.upgrade_nessus_into_prov8_button.click()
        assert update_to_pro8_tab.is_update_button_disabled(), "update to pro 8 tab is not disable"

        update_to_pro8_tab.checkbox_in_popup_window.click()
        assert not update_to_pro8_tab.is_update_button_disabled(), "update to pro 8 tab is enable"
        ActionCloseModal().close_button.click()

    def test_description_logo_icon_in_update_to_pro8_tab(self):
        """
        1. Navigate to About page under Settings.
        2. click on “Update to Pro 8” tab.
        3. Verify the logo_icon changes with update or downgrade
        """
        about_page = About()
        about_page.open()
        LoadingCircle(WAIT_NORMAL)
        about_page.update_to_pro8_tab.click()

        update_to_pro8_tab = UpdateToPro8()
        assert update_to_pro8_tab.is_element_present('upgrade_nessus_into_prov8_button'), \
            'update to nessus pro v8 button is not present'

        update_to_pro8_tab.upgrade_nessus_into_prov8()
        LoadingCircle(WAIT_SHORT)

        assert update_to_pro8_tab.downgrade_icon.is_displayed(), "'logo_icon indicating to revert' is not present"

        assert update_to_pro8_tab.is_element_present('downgrade_nessus_into_legacy_button'), \
            'Restore Nessus Professional Legacy button is not present'

        update_to_pro8_tab.downgrade_nessus_into_legacy_button.click()
        LoadingCircle(WAIT_NORMAL)

        assert update_to_pro8_tab.upgrade_icon.is_displayed(), "'logo_icon indicating to update' is not present"

    def test_upgraded_version_of_nessus_professional(self):
        """
        1. Navigate to About page under Settings.
        2. click on “Update to Pro 8” tab.
        3. Click on “Update to Nessus Pro v8” button in window and verify update is successful.
        4. verify presence of “Restore Nessus Professional Legacy” button and absence of “Update to Nessus Pro v8”
        button after update
        """
        about_page = About()
        about_page.open()

        LoadingCircle(WAIT_NORMAL)
        about_page.update_to_pro8_tab.click()

        update_to_pro8_tab = UpdateToPro8()
        update_to_pro8_tab.upgrade_nessus_into_prov8()
        LoadingCircle(WAIT_SHORT)

        assert about_page.update_to_pro8_tab.text == 'Revert from Pro 8', \
            "Nessus is already point to Legacy Professional"

        assert update_to_pro8_tab.is_element_present('downgrade_nessus_into_legacy_button'), \
            "Restore Nessus Professional Legacy button is not present"

        assert not update_to_pro8_tab.is_element_present('upgrade_nessus_into_prov8_button'), \
            "Update to Nessus Pro 8 button is present"

        update_to_pro8_tab.downgrade_nessus_into_legacy_button.click()
        LoadingCircle(WAIT_NORMAL)

        assert update_to_pro8_tab.is_element_present('upgrade_nessus_into_prov8_button'), \
            "Update to Nessus Pro 8 button is not present"

    def test_downgraded_version_of_nessus_professional(self):
        """
        Pre-condition: Product should be updated to Nessus Pro8
        1. Navigate to About page under Settings.
        2. click on “Update to Pro 8” tab.
        3. Verify Revert Nessus Professional Pro 8 to Nessus Professional Legacy.
        """
        about_page = About()
        about_page.open()

        LoadingCircle(WAIT_NORMAL)
        about_page.update_to_pro8_tab.click()
        update_to_pro8_tab = UpdateToPro8()

        if update_to_pro8_tab.is_element_present('upgrade_nessus_into_prov8_button'):
            update_to_pro8_tab.upgrade_nessus_into_prov8()

        assert update_to_pro8_tab.is_element_present('downgrade_nessus_into_legacy_button'), \
            "Restore Nessus Professional Legacy button is not present"

        update_to_pro8_tab.downgrade_nessus_into_legacy_button.click()
        LoadingCircle(WAIT_NORMAL)

        assert about_page.update_to_pro8_tab.text == 'Update to Pro 8', \
            "Nessus is already point to Legacy Professional"

        assert update_to_pro8_tab.is_element_present('upgrade_nessus_into_prov8_button'), \
            "Update to Nessus Pro 8 button is not present"

        assert not update_to_pro8_tab.is_element_present('downgrade_nessus_into_legacy_button'),\
            "Restore Nessus Professional Legacy button is present"


@pytest.mark.nessus_settings_1
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestUpdateToProFunctionality:
    """
    Test update to pro functionality for Nessus Pro or Nessus Manager
    """
    def test_update_to_pro_tab(self):
        """
        Verify that update to pro functionality is
        not available for Nessus Pro or Nessus Manager.
        """
        if not invisibility_of_element_located((By.CSS_SELECTOR, '.modal'))(get_driver_no_init()):
            log.info('welcome to Nessus Pro Pop up is visible')
            actionclosemodal = ActionCloseModal()
            actionclosemodal.close_button.click()
            actionclosemodal.wait_for_modal_closed()

        about_page = About()
        about_page.open()

        LoadingCircle(WAIT_NORMAL)
        assert not about_page.is_element_present('update_to_pro8_tab'), \
            "Update to Nessus Pro 8 tab is present"
