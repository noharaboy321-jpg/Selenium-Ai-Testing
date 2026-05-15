""""
Nessus test cases related to top-level sensor tab

:copyright: Tenable Network Security, 2019
:date: October 14, 2018
:last_modified: October 21, 2019
:author: @vsoni.ctr
"""
import pytest

from catium.lib.const import TIME_THIRTY_SECONDS
from catium.lib.webium.wait import wait
from nessus.lib.const import Nessus
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.sidenav.sidenav import SideNav


@pytest.mark.nessus_settings_1
@pytest.mark.usefixtures('login')
class TestSensorsLinkOnHeaders:

    @pytest.mark.sensor_manager
    def test_sensor_tab_visibility_on_headers_for_manager(self):
        """
        NES-10169: UI test for NES-10093 - Top level "Sensors" link

        Scenario Tested:
            [x] Test Visibility of top level "Sensors" tab

        Steps:
        1. Login to Nessus.
        2. Verify that "Sensors" tab appears on main page.
        3. Logout from Nessus
        """
        header_page = HeaderBasePage()

        assert wait(lambda: header_page.is_element_present('sensors_tab'), timeout_seconds=TIME_THIRTY_SECONDS,
                    waiting_for='Sensors tab to appear on Nessus main page headers'), \
            "'Sensors' tab is not appearing on headers for Manager."

    @pytest.mark.sensor_manager
    def test_verify_tabs_under_sensors_tab(self):
        """
        NES-10169: UI test for NES-10093 - Top level "Sensors" link

        Scenario Tested:
            [x] Verify the tabs under top level "Sensors" tab.

        Steps:
        1. Login to Nessus.
        2. Wait till "Sensors" tab appears on main page.
        3. Verify these tabs are present - "Scanners", "Linked Agents", "Groups", "Cluster Migration",
            "Blackout Windows" and "Agent Activity"
        4. Logout from Nessus.
        """

        header_page = HeaderBasePage()
        side_nav = SideNav()
        wait(lambda: header_page.is_element_present('sensors_tab'), timeout_seconds=TIME_THIRTY_SECONDS,
             waiting_for='Sensors tab to appear on Nessus main page headers')
        header_page.sensors_tab.click()
        assert all([side_nav.get_sidenav_element(element_name).is_displayed() for element_name in
                    Nessus.SideNavResources.SENSOR_LINK_TABS]), \
            "One or more tabs are not appearing inside sensors tab"
