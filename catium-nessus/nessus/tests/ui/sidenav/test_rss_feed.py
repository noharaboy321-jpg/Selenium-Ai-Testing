"""
Nessus RSS feed related test cases

:copyright: Tenable Network Security, 2019
:date: July 29, 2019
:last_modified: July 29, 2019
:author: @yshah
"""
import pytest

from catium.lib.const.base_constants import TIME_FIVE_SECONDS, WAIT_SHORT
from catium.lib.webium.wait import wait
from nessus.pageobjects.advanced_settings.advanced_settings_page import AdvancedSettingsPage, AdvancedSettingsList
from nessus.pageobjects.sidenav.sidenav import SideNav


@pytest.mark.nessus_settings_2
@pytest.mark.nessus_home
@pytest.mark.usefixtures('login')
class TestRSSFeedModal:
    """This class covers the test cases related to RSS Feed modal in nessus home"""

    @pytest.mark.xray(test_key='NES-13771')
    @pytest.mark.xfail(reason="NES-9911 waiting for file to be added to feed")
    def test_visibility_of_default_locators_on_rss_feed_modal(self):
        """
        NES-9844: NES-9821 RSS feeds in Nessus Essentials
        NES-13771 : Verify RSS feeds

        Scenarios:
            [x] Visibility of RSS header, article name, Read more link text and feed arrow key on hover.

        Steps:
        1. Go to side navigation.
        2. Verify rss_header, read_more_link, rss_feed are visible on UI and feed_right_arrow_key, feed_left_arrow_key
        is not visible on UI.
        3. Hover over read_more_link.
        4. Verify feed_right_arrow_key and feed_left_arrow_key are visible now.
        """
        side_nav = SideNav()
        wait(lambda: side_nav.is_element_present("rss_header"), timeout_seconds=TIME_FIVE_SECONDS)

        # Verify rss_header, read_more_link, rss_feed is visible on UI
        assert all(side_nav.is_element_present(element) for element in ["rss_header", "read_more_link", "rss_feed"]), \
            "Element is not present in the RSS Feed modal"

        # Verify both the keys(feed_right_arrow_key and feed_left_arrow_key) are not visible on UI
        assert not any(side_nav.is_element_present(element) for element in ["feed_right_arrow_key",
                                                                            "feed_left_arrow_key"]), \
            "Both Feed arrow keys are present on the modal"

        # Verify the RSS header should be "Tenable News"
        assert side_nav.rss_header.text == "Tenable News", "RSS modal header text is different, actual text is {}" \
            .format(side_nav.rss_header.text)

        # Verify RSS Feed is not empty
        assert side_nav.rss_feed.text, "RSS feed title is empty"
        side_nav.move_to_element(side_nav.read_more_link)

        # Verify both the keys(feed_right_arrow_key and feed_left_arrow_key) are now visible on UI
        assert all(side_nav.is_element_present(element) for element in ["feed_right_arrow_key", "feed_left_arrow_key"]) \
            , "Both Feed arrow keys are not present on the modal"

    @pytest.mark.xfail(reason="NES-9911 waiting for file to be added to feed")
    def test_click_on_arrow_should_change_the_article(self):
        """
        NES-9844: NES-9821 RSS feeds in Nessus Essentials

        Scenarios:
            [x] Click on feed arrow key should change the article.

        Steps:
        1. Go to side navigation.
        2. Hover over read_more_link.
        3. Click on the feed_right_arrow_key and wait till article title changes
        4. Verify the title should not be same as last article title.
        """
        side_nav = SideNav()
        wait(lambda: side_nav.is_element_present("rss_header"), timeout_seconds=TIME_FIVE_SECONDS)
        article = side_nav.rss_feed.text
        side_nav.move_to_element(side_nav.read_more_link)
        side_nav.feed_right_arrow_key.click()
        wait(lambda: side_nav.rss_feed.text != article, timeout_seconds=WAIT_SHORT * 2)

        # Verify the title should not be same as last article title
        assert side_nav.rss_feed.text != article, \
            "Feed right arrow key is not working because it is showing same text is, {}".format(side_nav.rss_feed.text)
        new_article = side_nav.rss_feed.text
        side_nav.feed_left_arrow_key.click()
        wait(lambda: side_nav.rss_feed.text == article, timeout_seconds=WAIT_SHORT * 2)

        # Verify the title should not be same as last article title
        assert side_nav.rss_feed.text != new_article, \
            "Feed left arrow key is not working because it is showing same text as, {}".format(side_nav.rss_feed.text)

    @pytest.mark.xray(test_key='NES-13783')
    @pytest.mark.xfail(reason="NES-9911 waiting for file to be added to feed")
    def test_behaviour_when_click_on_read_more_link_text(self):
        """
        NES-9844: NES-9821 RSS feeds in Nessus Essentials
        NES-13783 Verify use of 'Read More' link

        Scenarios:
            [x] Click on read more link text should open a new tab and verify the URL too.

        Steps:
        1. Go to side navigation.
        2. Hover over read_more_link.
        3. Click on the read more link text and get the URL from new tab.
        4. Verify the URL is starting with "https://www.tenable.com/blog"
        """
        side_nav = SideNav()
        wait(lambda: side_nav.is_element_present("rss_header"), timeout_seconds=TIME_FIVE_SECONDS)
        side_nav.read_more_link.click()
        url = side_nav.switch_window_and_get_url()

        # Verify the URL is starting with "https://www.tenable.com/blog"
        assert url.startswith("https://www.tenable.com/blog"), \
            "It is being redirecting to different URL, URL is {}".format(url)

    @pytest.mark.xfail(reason="NES-9911 waiting for file to be added to feed")
    def test_visibility_of_news_icon_when_side_nav_collapsed(self):
        """
         NES-9844: NES-9821 RSS feeds in Nessus Essentials

         Scenarios:
             [x] On Collapse, RSS feed must be changed to newpaper icon.
             [x] On Expand, RSS feed must be changed to RSS Feed modal.

         Steps:
         1. Go to side navigation.
         2. Verify paper icon is not visible.
         3. Click on the collapsed menu icon and verify the newspaper icon is visible on UI.
         4. Expand it and verify the newspaper icon is not visible on UI.
         """
        side_nav = SideNav()
        wait(lambda: side_nav.is_element_present("rss_header"), timeout_seconds=TIME_FIVE_SECONDS)

        # Verify newspaper icon is not visible.
        assert not side_nav.is_element_present(
            'newspaper_icon'), "Newspaper icon is visible on side nav bar in expanded state"
        side_nav.collapse_menu_icon.click()

        # Verify newspaper icon is visible when click on collapsed icon.
        assert side_nav.is_element_present(
            'newspaper_icon'), "Newspaper icon is not visible on side nav bar in collapsed state"
        side_nav.collapse_menu_icon.click()

        # Verify newspaper icon is not visible.
        assert not side_nav.is_element_present(
            'newspaper_icon'), "Newspaper icon is visible on side nav bar in expanded state"

        # Verify RSS Feed modal is visible.
        assert side_nav.is_element_present("rss_feed_modal"), "RSS Feed modal is not visible"

    @pytest.mark.xray(test_key='NES-13914')
    @pytest.mark.parametrize("empty_trash_and_create_or_import_bulk_scan", [{'scan_count': 20, 'import_scan': False}],
                             indirect=True)
    def test_verify_rss_feed_when_page_scrollbar_exists(self, empty_trash_and_create_or_import_bulk_scan):
        """
        NES-13914 : Verify carousel when scroll bar exist on right/left

        Tested Scenario:
        [X] Verify that RSS feed is visible when window scrollbar is visible
        """
        side_nav = SideNav()
        wait(lambda: side_nav.is_element_present("rss_header"), timeout_seconds=TIME_FIVE_SECONDS)

        assert side_nav.is_element_present('rss_feed_modal')

    @pytest.mark.xray(test_key='NES-13851')
    def test_verify_rss_feed_exists_even_after_switching_pages(self):
        """
        NES-13851 : Verify Tenable News carousel consistency.

        Tested Scenario:
        [X] Verify that RSS feed is visible when navigating to pages
        """
        side_nav = SideNav()
        wait(lambda: side_nav.is_element_present("rss_header"), timeout_seconds=TIME_FIVE_SECONDS)

        assert side_nav.is_element_present('rss_feed_modal')
        wait(lambda: side_nav.is_element_present("settings_tab"), timeout_seconds=TIME_FIVE_SECONDS)
        side_nav.settings_tab.click()

        wait(lambda: side_nav.is_element_present("rss_header"), timeout_seconds=TIME_FIVE_SECONDS)
        assert side_nav.is_element_present('rss_feed_modal')


@pytest.mark.nessus_settings_2
@pytest.mark.usefixtures('login')
@pytest.mark.parametrize('advanced_setting_info', [{"name": "Disable Tenable News", "identifier": "disable_rss",
                                                    "default_value": "No"}])
class TestDisableRSSFeedSetting:
    @pytest.mark.xfail(reason="NES-9911 waiting for file to be added to feed")
    @pytest.mark.nessus_home
    def test_disable_rss_advanced_setting_visibility(self, advanced_setting_info):
        """
        NES-9892 : UI Tests for Disable RSS Feeds setting (NES-9864)

        Scenarios:
            [x] Verify that Advanced setting having Name "Disable Tenable News" is present and
                having default value set to "No"

        Steps:
        1. Login to Nessus.
        2. Verify that Advanced setting having Name "Disable Tenable News" is present and
            having default value set to "No"
        3. Check if RSS feed is present while "disable_rss" is set to "No"
        4. Logout from Nessus
        """

        setting_identifier = advanced_setting_info['identifier']

        advanced_setting = AdvancedSettingsPage()
        advanced_setting.open()
        wait(lambda: advanced_setting.is_element_present('search_textbox'),
             waiting_for="Advanced setting page to load properly")

        advanced_setting.search_textbox.value = setting_identifier

        advanced_setting_list = AdvancedSettingsList()

        wait(lambda: advanced_setting_list.get_settings_names_by_tab(), timeout_seconds=TIME_FIVE_SECONDS,
             waiting_for="Advanced settings to get populated for given search")

        # Verify that advanced setting having name 'Disable Tenable News' is present
        assert advanced_setting_info['name'] in advanced_setting_list.get_settings_names_by_tab(), \
            "Advanced setting having name 'Disable Tenable News' is not appearing"

        # Verify that advanced setting having identifier 'disable_rss' is present
        assert setting_identifier in advanced_setting_list.get_setting_identifiers_by_tab(), \
            "Advanced setting having identifier 'disable_rss' is not appearing"

        # Verify that default value for 'disable_rss' is 'No'
        assert advanced_setting_list.get_settings_value(setting_identifier)[0] == advanced_setting_info[
            'default_value'], "Default value for 'disable_rss' is not 'No'"

        # Verify that RSS feed is present
        assert SideNav().is_element_present("rss_feed"), \
            "RSS feed is not appearing even though default value for disable_rss is 'No'"

    @pytest.mark.nessus_home
    def test_verify_disable_rss_setting_to_yes(self, advanced_setting_info):
        """
        NES-9892 : UI Tests for Disable RSS Feeds setting (NES-9864)

        Scenarios:
            [x] Verify that RSS feed disappears when advance setting for disable_rss is set to "Yes"

        Steps:
        1. Login to Nessus.
        2. Modify the advanced setting value for "disable_rss" to "Yes"
        3. Verify that RSS feed disappears
        4. Logout from Nessus
        """

        setting_identifier = advanced_setting_info['identifier']
        default_setting_value = advanced_setting_info['default_value']

        advanced_setting = AdvancedSettingsPage()
        side_nav = SideNav()
        advanced_setting.open()
        wait(lambda: advanced_setting.is_element_present('search_textbox'),
             waiting_for="Advanced setting page to load properly")

        advanced_setting.search_textbox.value = setting_identifier

        advanced_setting_list = AdvancedSettingsList()

        wait(lambda: advanced_setting_list.get_settings_names_by_tab(), timeout_seconds=TIME_FIVE_SECONDS,
             waiting_for="Advanced settings to get populated for given search")

        advanced_setting_list.edit_or_add_setting(setting_name=setting_identifier, setting_value="Yes")

        try:
            wait(lambda: advanced_setting.is_element_present('search_textbox'),
                 waiting_for="Advanced setting page to load properly")
            # Verify that RSS feed is not present
            assert not side_nav.is_element_present("rss_feed"), \
                "RSS feed is appearing even though value for disable_rss is set to 'Yes'"

        finally:
            advanced_setting_list.edit_or_add_setting(setting_name=setting_identifier,
                                                      setting_value=default_setting_value)
            wait(lambda: advanced_setting.is_element_present('search_textbox'),
                 waiting_for="Advanced setting page to load properly")

    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    def test_no_disable_rss_setting_for_nessus_manager_and_professional(self, advanced_setting_info):
        """
        NES-9892 : UI Tests for Disable RSS Feeds setting (NES-9864)

        Scenarios:
            [x] Verify that Advanced setting having Name "Disable Tenable News" is not present.
            (Nessus Manager / Nessus Professional)

        Steps:
        1. Login to Nessus.
        2. Verify that Advanced setting having Name "Disable Tenable News" is not present.
        3. Logout from Nessus.
        """

        advanced_setting = AdvancedSettingsPage()
        advanced_setting.open()
        wait(lambda: advanced_setting.is_element_present('search_textbox'),
             waiting_for="Advanced setting page to load properly")

        advanced_setting.search_textbox.value = advanced_setting_info['identifier']

        advanced_setting_list = AdvancedSettingsList()

        wait(lambda: advanced_setting_list.get_settings_names_by_tab() or advanced_setting_list.
             is_element_present('empty_advanced_settings'), timeout_seconds=TIME_FIVE_SECONDS,
             waiting_for="Advanced settings to get populated for given search")

        # Verify that advanced setting having name 'Disable Tenable News' is not present
        assert advanced_setting_info['name'] not in advanced_setting_list.get_settings_names_by_tab(), \
            "Advanced setting having name 'Disable Tenable News' is appearing for Nessus Manager / Nessus Professional"

        # Verify that RSS feed is not present
        assert not SideNav().is_element_present("rss_feed"), \
            "RSS feed is appearing for Nessus Manager / Nessus Professional"
