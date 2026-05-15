"""
Nessus agents blackout window related test cases
:copyright: Tenable Network Security, 2020
:created: June 05, 2020
:last_modified: Dec 10, 2020
:author: @vsoni.ctr, @kpanchal.ctr
"""
from datetime import datetime

import pytest
import pytz
from selenium.webdriver.support.expected_conditions import visibility_of_element_located
from waiting import wait

from catium.helpers.sleep_lib import sleep
from catium.lib.const.base_constants import TIME_SIXTY_SECONDS, TIME_FIVE_MINUTES, TIME_TEN_SECONDS
from catium.lib.log.log import create_logger
from catium.lib.util.util import random_name
from catium.lib.webium.driver import get_driver
from catium.lib.webium.wait import wait as webium_wait
from nessus.helpers.nessus_agent import get_latest_log_file_entries
from nessus.lib.const.constants import Nessus, API, NessusAgentFilePath
from nessus.lib.message.messages import Messages
from nessus.pageobjects.agents.agent_blackout_windows_page import AgentBlackoutWindowsPage, AgentBlackoutWindowList, \
    AgentBlackoutWindowSettingsPage
from nessus.pageobjects.agents.create_agent_blackout_window_page import CreateBlackoutWindowPage
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.scans.scan_trash_page import ScansTrashPage
from nessus.pageobjects.scans.scans_page import ScansPage, ScanList

log = create_logger()
SCAN_DISABLED_IN_BW = "Scans disabled due to an active blackout window"


def wait_till_blackout_window_disabled(bw_name: str) -> None:
    """
    This function will wait till scheduled blackout window gets disabled
    :param str bw_name: Name of blackout window
    :return: None
    """
    bw_list = AgentBlackoutWindowList()
    AgentBlackoutWindowsPage().open()
    bw_list.loaded()
    bw_list.click_on_created_window(new_blackout_window_name=bw_name)
    create_bw = CreateBlackoutWindowPage()
    webium_wait(lambda: CreateBlackoutWindowPage().is_element_present('frequency'))
    timezone = create_bw.time_zone.value
    end_time = create_bw.end_time.value
    wait(lambda: int(pytz.utc.localize(datetime.utcnow()).astimezone(pytz.timezone(timezone)).minute) == int(
        end_time.split(":")[1]), sleep_seconds=TIME_TEN_SECONDS, timeout_seconds=TIME_FIVE_MINUTES * 4,
         waiting_for="Wait till blackout window gets disabled")


def create_agent_scan_and_verify_scan_behavior_for_created_blackout_window(bw_type: str, agent_group: str,
                                                                           agent_ip: str, bw_name: str = "") -> None:
    """
    This function create agent scan and verifies scan behavior as per the scheduled/permanent blackout window.
    :param str bw_type: 'scheduled' or 'permanent'
    :param agent_group: Agent group name
    :param agent_ip: IP address of agent
    :param bw_name: Name of scheduled blackout window
    :return: None
    """
    # Creating agent scan in Nessus Manager
    scan_page = ScansPage()
    scan_list = ScanList()
    new_scan_name = random_name(prefix=Nessus.TemplateNames.BASIC_AGENT)
    scan_page.create_new_scan(scan_template=Nessus.TemplateNames.BASIC_AGENT,
                              scan_type=Nessus.Scan.ScanTemplateTabs.AGENT_TAB,
                              description='Created an {} with automation'.format(Nessus.TemplateNames.BASIC_AGENT),
                              scan_name=new_scan_name, add_configuration=False,
                              agent_group=agent_group)
    try:
        scan_list.launch_scan(scan_name=new_scan_name)
        sleep(TIME_SIXTY_SECONDS, reason="Blackout window to block the scan")
        scan_pending = scan_page.get_scan_status(scan_name=new_scan_name, scan_status=API.Scan.Status.PENDING)
        assert visibility_of_element_located((scan_pending.we_by, scan_pending.we_value))(get_driver()), \
            "During {} blackout window after launching the scan, it does not have 'pending' status".format(bw_type)

        backend_logs = get_latest_log_file_entries(agent_ip=agent_ip, no_of_entries=25, file=NessusAgentFilePath.
                                                   NESSUS_AGENT_BACKEND_LOGS)
        log.debug("Logs from backend.log file :: {}".format(backend_logs))

        assert [True for log_line in backend_logs if any([log_message in log_line for log_message in [
            Messages.NessusAgent.SCAN_DISABLED_IN_FREEZE, SCAN_DISABLED_IN_BW]])], \
            "Scan disabled message is missing in Nessus agent's backend.log ."

        # Verify that scan gets launched and completed successfully after created blackout window is disabled.
        if bw_type == "scheduled":
            wait_till_blackout_window_disabled(bw_name=bw_name)
        elif bw_type == "permanent":
            AgentBlackoutWindowSettingsPage().enable_or_disable_agent_settings(
                option_list=[{'setting_name': 'Enforce permanent blackout window', 'setting_action': 'disable'}])

        HeaderBasePage().scan_link.click()
        scan_list.loaded()
        assert scan_list.launch_scan_and_wait_for_status(launch_scan=False, scan_name=new_scan_name,
                                                         status=API.Scan.Status.COMPLETED), \
            "Scan does not launched/completed after the blackout window is inactive."
    finally:
        scan_list.delete_scan(scan_name=new_scan_name)
        ScansTrashPage().delete_scan_from_trash(scan_name=new_scan_name)


@pytest.mark.nessus_manager
@pytest.mark.real_agent
class TestAgentBlackoutWindow:
    """Test cases to cover Agent blackout window functionality in Nessus Manager"""

    @pytest.mark.parametrize('configure_agent_settings_options',
                             [{'setting_options_list': [
                                 {'setting_name': Nessus.Agents.Settings.PREVENT_SCAN, 'setting_action': 'enable'},
                                 {'setting_name': Nessus.Agents.Settings.PERMANENT_BLACKOUT_WINDOW,
                                  'setting_action': 'enable'},
                                 {'setting_name': Nessus.Agents.Settings.PREVENT_CORE_UPDATES,
                                  'setting_action': 'disable'},
                                 {'setting_name': Nessus.Agents.Settings.PREVENT_PLUGIN_UPDATES,
                                  'setting_action': 'disable'}]}],
                             indirect=True)
    @pytest.mark.usefixtures('login', 'configure_agent_settings_options', 'create_agent_group_with_real_agent')
    def test_agent_scan_in_permanent_blackout_window(self, create_agent_group_with_real_agent):
        """
        NES-11474 : UI test to confirm blackout window works
        Scenario Tested:
            [x] Verify that agent scan disabled when permanent blackout window is enabled.
        Steps:
        1. Enable option for "permanent blackout window" from agent settings.
        2. Enable "Prevent agent scan" option from agent settings.
        3. Link a agent with Nessus manager and add the agent to new agent group.
        4. Create a agent scan and launch it.
        5. Verify that scan is disabled due to active blackout window in agent backend.log.
        6. Disable Permanent blackout window
        7. Verify scan gets launched and completed successfully once the blackout window is inactive.
        """
        HeaderBasePage().scan_link.click()

        create_agent_scan_and_verify_scan_behavior_for_created_blackout_window(
            bw_type="permanent", agent_group=create_agent_group_with_real_agent['agent_group_name'],
            agent_ip=create_agent_group_with_real_agent['agent_ip'])

    @pytest.mark.parametrize('configure_agent_settings_options',
                             [{'setting_options_list': [
                                 {'setting_name': Nessus.Agents.Settings.PREVENT_SCAN, 'setting_action': 'enable'},
                                 {'setting_name': Nessus.Agents.Settings.PERMANENT_BLACKOUT_WINDOW,
                                  'setting_action': 'disable'},
                                 {'setting_name': Nessus.Agents.Settings.PREVENT_CORE_UPDATES,
                                  'setting_action': 'disable'},
                                 {'setting_name': Nessus.Agents.Settings.PREVENT_PLUGIN_UPDATES,
                                  'setting_action': 'disable'}]}],
                             indirect=True)
    @pytest.mark.parametrize('create_new_blackout_window_and_wait_till_activation', [{'is_time_set': True,
                                                                                      'bw_duration': 7}],
                             indirect=True)
    @pytest.mark.usefixtures('login', 'configure_agent_settings_options',
                             'create_new_blackout_window_and_wait_till_activation',
                             'create_agent_group_with_real_agent')
    def test_agent_scan_in_scheduled_blackout_window(self, create_new_blackout_window_and_wait_till_activation,
                                                     create_agent_group_with_real_agent):
        """
        NES-11474 : UI test to confirm blackout window works
        Scenario Tested:
            [x] Verify that agent scan disabled when scheduled blackout window is active.
        Steps:
        1. Create a blackout window and wait till it gets activated.
        2. Enable "Prevent agent scan" option from agent settings.
        3. Link a agent with Nessus manager and add the agent to new agent group.
        4. Create a agent scan and launch it.
        5. Verify that scan is disabled due to active blackout window in agent backend.log.
        6. Wait till schedule blackout window gets disabled.
        7. Verify scan gets launched and completed successfully once the blackout window is inactive.
        """

        # Checking if blackout window is created successfully and populated in blackout windows list
        AgentBlackoutWindowsPage().open()
        blackout_window_name = create_new_blackout_window_and_wait_till_activation
        bw_list = AgentBlackoutWindowList()

        assert blackout_window_name in bw_list.blackout_window_all_names, \
            "Scheduled Blackout window was not created successfully"

        HeaderBasePage().scan_link.click()

        create_agent_scan_and_verify_scan_behavior_for_created_blackout_window(
            bw_type="scheduled", agent_group=create_agent_group_with_real_agent['agent_group_name'],
            agent_ip=create_agent_group_with_real_agent['agent_ip'], bw_name=blackout_window_name)
