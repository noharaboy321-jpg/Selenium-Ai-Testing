"""
Tests for resource menu links from Header

:copyright: Tenable Network Security, 2017
:date: Jul 16, 2021
:author: @kpanchal.ctr
"""

import pytest

from catium.helpers.sleep_lib import sleep
from catium.lib.const.base_constants import TIME_THREE_SECONDS, TIME_THIRTY_SECONDS, TIME_TEN_SECONDS, WAIT_SHORT, \
    WAIT_LONG
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from catium.lib.webium.windows_handler import WindowsHandler
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.scanner import restart_scanner, wait_for_scanner_to_be_ready
from nessus.helpers.system import is_pro
from nessus.pageobjects.header.header_base import HeaderBasePage


@pytest.fixture(scope='class')
def enable_user_guides_setting() -> None:
    """ Fixture to enable user guides setting from advanced settings """
    nessus_api = NessusAPI()
    nessus_api.login()

    if is_pro():
        for setting in ["send_telemetry", "disable_guides"]:
            nessus_api.settings.update(settings={"setting.0.name": setting, "setting.0.value": "true",
                                                 "setting.0.action": "edit"})

        restart_scanner(api=nessus_api)
        wait_for_scanner_to_be_ready(api=nessus_api)
        sleep(WAIT_LONG, reason="Waiting for Nessus UI to be ready")


@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('enable_user_guides_setting', 'login')
class TestResourceMenuLinks:
    """ Covers resource menu links related tests """

    @pytest.mark.parametrize("link_type", ['whats_new', 'documentation'])
    def test_verify_whats_new_and_documentation_links_redirects_to_correct_url(self, link_type):
        """
        NES-12472: [UI] Verify that "what's new" and "documents" link on admin user popup redirect to proper url
        NES-13189 [Automation]: Update automated tests for "What's new" and "Documentation" links visibility

        Steps:
        1. Click on "Question" icon on top right corner in main page
        2. Click on "What's new"/"Documentation" button and verify that user redirects to proper url

        Scenario Tested:
            [x] Verify that "what's new" and "documents" link in resource menu dropdown redirects to proper url
        """
        header_page = HeaderBasePage()
        wait(lambda: header_page.is_element_present("resource_menu_icon"), waiting_for="Header page icon gets loaded")

        header_page.resource_menu_icon.click()

        assert header_page.is_element_present('whats_new_link'), \
            "What's new link is not available under resource menu dropdown."

        assert header_page.is_element_present('documentation_link'), \
            "Documentation link is not available under resource menu dropdown."

        if link_type == "whats_new":
            header_page.whats_new_link.click()
        else:
            header_page.documentation_link.click()

        windows_handler = WindowsHandler()
        sleep(sleep_time=TIME_THREE_SECONDS, reason='Wait for new tab to open')
        windows_handler.switch_to_window(windows_handler.handles[-1])

        wait(lambda: header_page.is_element_present('new_page_header', timeout=TIME_THIRTY_SECONDS))
        header_text = header_page.new_page_header.text

        assert "Nessus Release Notes" in header_text if link_type == "whats_new" else \
            "Welcome to Nessus" in header_text, \
            "User did not redirect to proper page after clicking on {} button".format(link_type)

        current_url = get_driver_no_init().current_url

        assert "docs.tenable.com" in current_url, "User redirected to incorrect URL."

        assert "releasenotes" in current_url if link_type == "whats_new" else \
            "GettingStarted" in current_url, "User redirected to incorrect URL."

    def test_visibility_of_links_in_resource_menu_dropdown(self):
        """
        NES-9085 - UI test that links show up based on links.json file
        NES-13190 [Automation]: Update automated tests for "Community", "Research" and "Plugin Release Notes" links
                                visibility

        Scenarios tested:
            [x] Click on "Question" icon on top right corner should show both the link text.
            [x] Click on "Question" icon on top right corner should hide both the link text.

        Steps:
        1. Go to scans page.
        2. Verify click on "Question" icon on top right corner should show/hide link text respectively.
        """
        header_page = HeaderBasePage()
        wait(lambda: header_page.is_element_present("resource_menu_icon"), waiting_for="Header page icon gets loaded")

        header_page.resource_menu_icon.click()

        # Verify 'What's New' and 'Documentation' links must be visible
        assert header_page.is_element_present("whats_new_link", timeout=TIME_TEN_SECONDS), \
            "'Community' link is not present under resource menu dropdown."

        assert header_page.is_element_present("documentation_link", timeout=TIME_TEN_SECONDS), \
            "'Research' link is not present under resource menu dropdown."

        # Verify 'Community', 'Research' and 'Plugin Release Notes' links must be visible
        assert header_page.is_element_present("community_link", timeout=TIME_TEN_SECONDS), \
            "'Community' link is not present under resource menu dropdown."

        assert header_page.is_element_present("research_link", timeout=TIME_TEN_SECONDS), \
            "'Research' link is not present under resource menu dropdown."

        assert header_page.is_element_present("plugin_release_notes_link", timeout=TIME_TEN_SECONDS), \
            "'Plugin Release Notes' link is not present under resource menu dropdown."

        header_page.resource_menu_icon.click()

        # Verify 'What's New' and 'Documentation' links should not be visible
        assert not header_page.is_element_present("whats_new_link", timeout=TIME_TEN_SECONDS), \
            "'Community' link is not present under resource menu dropdown."

        assert not header_page.is_element_present("documentation_link", timeout=TIME_TEN_SECONDS), \
            "'Research' link is not present under resource menu dropdown."

        # Verify community link and research link should not be visible
        assert not header_page.is_element_present("community_link"), \
            "'Community' link is visible yet after clicking again on resource menu icon."

        assert not header_page.is_element_present("research_link"), \
            "'Research' link is visible yet after clicking again on resource menu icon."

        assert not header_page.is_element_present("plugin_release_notes_link"), \
            "'Plugin Release Notes' link is visible yet after clicking again on resource menu icon."

    @pytest.mark.xray(test_key='NES-14294')
    @pytest.mark.parametrize("link_text, link", [
        ("Community", "https://community.tenable.com/s/"), ("Research", "https://www.tenable.com/research"),
        ("Plugin Release Notes", "https://www.tenable.com/plugins/nessus/release-notes")])
    def test_verify_community_and_research_links_redirects_to_correct_url(self, link_text, link):
        """
        NES-9085 - UI test that links show up based on links.json file
        NES-13190 [Automation]: Update automated tests for "Community", "Research" and "Plugin Release Notes" links
                                visibility
        NES-14294 : Verify the navigation for Resource Center(?) links

        Scenarios tested:
            [x] Click on 'Community' link must be redirect to 'https://community.tenable.com' url
            [x] Click on 'Research' link must be redirect to 'https://www.tenable.com/research' url
            [x] Click on 'Plugin Release Notes' link must be redirect to
                'https://www.tenable.com/plugins/nessus/release-notes' url

        Steps:
        1. Go to scans page.
        2. Verify click on Community link and research link must be redirect to respective link mentioned in scenarios
         tested.
        """
        header_page = HeaderBasePage()
        wait(lambda: header_page.is_element_present("resource_menu_icon"), waiting_for="Header page icon gets loaded")

        header_page.resource_menu_icon.click()

        if link_text == "Community":
            header_page.community_link.click()
        elif link_text == "Research":
            header_page.research_link.click()
        else:
            header_page.plugin_release_notes_link.click()

        windows_handler = WindowsHandler(driver=get_driver_no_init())
        windows_handler.switch_to_window(windows_handler.handles[-1])
        sleep(sleep_time=WAIT_SHORT, reason="waiting for page switch")

        # Verify click on link text is redirecting to correct url
        assert link == get_driver_no_init().current_url, \
            "Clicking on %s is not being redirecting to link %s" % (link_text, link)

        windows_handler.switch_to_window(windows_handler.handles[0])
        sleep(sleep_time=WAIT_SHORT, reason="waiting for page switch")
