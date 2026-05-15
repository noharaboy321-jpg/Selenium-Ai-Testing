import time

import pytest

from nessus.pageobjects.profiles.profiles_page import ProfilesPage
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.lib.const.constants import Nessus
from nessus.lib.message.messages import Messages
from nessus.pageobjects.sidenav.sidenav import SideNav
from catium.lib.log import create_logger
from catium.lib.webium.wait import wait
from nessus.pageobjects.upgrade_assistant.upgrade_assistant_page import UpgradeAssistantPage
from nessus.pageobjects.about.about_page import About, PluginDetailLocale, SoftwareUpdate
from nessus.pageobjects.generic.generic_modals import ActionCloseModal

log = create_logger()


def update_option_is_clickable(update_option) -> bool:
    """
    Helper method to check if the given update option is clickable
    """
    try:
        update_option.click()
        return True
    except Exception:
        return False


@pytest.mark.offline_mode
@pytest.mark.parametrize('test_data_file', [{'settings': {'offline_mode': 'yes'}}], indirect=True)
@pytest.mark.usefixtures('configure_advanced_settings_and_env_variables', 'nessus_api_login', 'login')
class TestOfflineModeDisabledUI:
    """
    NES-18193:
    Test cases to ensure UI functionalities are disabled for offline mode
    """
    cat = None

    @pytest.mark.xray(test_key='NES-18193')
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_expert
    def test_upgrade_assistant_disabled(self) -> None:
        """
        Validates upgrade assistant tab is disabled, and errors when attempting to navigate to upgrade assistant page
        """
        About().open()
        assert (
            SideNav().get_sidenav_element(Nessus.SideNavSettings.UPGRADE_ASSISTANT).get_attribute("class") == "disabled"
            , "Expected upgrade assistant tab to be disabled"
        )
        upgrade_assistant_page = UpgradeAssistantPage()
        upgrade_assistant_page.open()
        time.sleep(1)
        assert "error" in upgrade_assistant_page.current_url, "Expected to error when navigating to upgrade assistant page"

    @pytest.mark.xray(test_key='NES-18193')
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_expert
    @pytest.mark.jira("NES-18449")
    def test_plugin_detail_locale_disabled(self) -> None:
        """
        Validates plugin detail locale tab is disabled, and errors when attempting to update plugin locale
        """
        about_page = About()
        about_page.open()
        assert about_page.plugin_detail_locale_tab.get_attribute("class") == "disabled", "Expected plugin detail locale tab to be disabled"
        plugin_locale_page = PluginDetailLocale()
        plugin_locale_page.open()
        plugin_locale_page.save_button.click()
        assert (
            Notifications().errors[-1] in Messages.NotificationMessages.offline_mode_route_error
            , "Expected error notification after trying to update plugin detail locale"
        )

    @pytest.mark.xray(test_key='NES-18193')
    @pytest.mark.nessus_manager
    def test_agent_profiles_disabled(self) -> None:
        """
        Validates agents profile tab is disabled, and errors when attempting to create new agent profile
        """
        HeaderBasePage().sensors_tab.click()
        assert SideNav().agent_profiles_tab.get_attribute("class") == "disabled", "Expected agent profile to be disabled"
        agent_profiles_page = ProfilesPage()
        agent_profiles_page.open()
        agent_profiles_page.create_agent_profile(profile_name="test", profile_description="test", expect_failure=True)
        assert (
            Notifications().errors[-1] in Messages.NotificationMessages.offline_mode_route_error
            , "Expected error notification after trying to create new agent profile"
        )

    @pytest.mark.xray(test_key='NES-18415')
    @pytest.mark.xray(test_key='NES-18193')
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_manager
    def test_manual_update_buttons_disabled(self) -> None:
        """
        NES-18415
        Validates "Update all components" and "Update plugins" radio buttons should be disabled and not clickable.
        """
        about_page = About()
        about_page.open()
        about_page.software_update_tab.click()
        software_update = SoftwareUpdate()
        wait(lambda: software_update.is_element_present("manual_software_update"),
             waiting_for="Manual Software Update button to get visible")
        software_update.manual_software_update.click()
        manual_update_modal = ActionCloseModal()
        wait(lambda: manual_update_modal.is_element_present("modal"),
             waiting_for="Manual Software Update modal to get visible")
        expected_states = {
            "Update all components": "disabled", "Update plugins": "disabled", "Upload your own plugin archive": "enabled"
        }
        for update_option in manual_update_modal.modal_content_radio:
            if expected_states[update_option.text] == "disabled":
                assert "disabled" in update_option.get_attribute("class"), f"Expected {update_option.text} to be disabled"
                assert not update_option_is_clickable(update_option), f"Expected {update_option.text} to not be clickable"
            else:
                assert "disabled" not in update_option.get_attribute("class"), f"Expected {update_option.text} to be enabled"
                assert update_option_is_clickable(update_option), f"Expected {update_option.text} to be clickable"
