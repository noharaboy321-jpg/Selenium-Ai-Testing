"""
Testcases related to Nessus agent channel update
Test the different agent update channels with goat-feed-server.
:copyright: Tenable Network Security, 2020
:date: May 4th, 2020
:author: vsoni.ctr
"""
import json

import pytest
from packaging.version import parse
from waiting import wait
from waiting.exceptions import TimeoutExpired

from catium.helpers.sleep_lib import sleep
from catium.lib.const.base_constants import TIME_TEN_MINUTES, TIME_TEN_SECONDS, TIME_FIVE_MINUTES
from catium.lib.log.log import create_logger
from catium.lib.ssh.ssh import SSH
from nessus.helpers.nessus_agent import get_fix_parameter_in_nessus_agent, set_fix_parameter_in_nessus_agent, \
    get_nessus_agent_version, trigger_agent_update_checks, get_expected_nessus_agent_build_and_version_for_given_channel

log = create_logger()


@pytest.fixture(scope="class")
def enable_debug_logs_for_nessus_agent():
    """This fixture will enable debug logs for nessus-agent"""
    ssh = SSH()
    log_file_path = "/opt/nessus_agent/var/nessus/log.json"

    # Checking if log.json file does exist at path  /opt/nessus_agent/var/nessus/
    if ssh.path_exist(log_file_path):
        log_file = ssh.read_from_file(log_file_path)
        log_dict = json.loads(str(log_file.decode('utf8')))

        # Enable debug mode by adding 'debug' tag if not present in backend.log file's tags in log.json file
        if 'debug' not in log_dict["reporters"][1]['tags']:
            log_dict["reporters"][1]['tags'].insert(0, 'debug')
        log_json = json.dumps(log_dict, indent=4)
        ssh.write_to_file(log_file_path, text=str(log_json))
        ssh.execute(command="supervisorctl restart nessusagent")
    else:
        log.warning("log.json file not found at /opt/nessus_agent/var/nessus")


@pytest.mark.usefixtures("enable_debug_logs_for_nessus_agent", "link_agent_to_tenable_io")
@pytest.mark.nessus_agent
class TestNessusAgentUpdateChannel:

    def test_default_nessus_agent_update_channel(self):
        """
        NES-11258: Design and Implement CLI test cases to verify the Agent Update plan
        Scenario Tested:
            [x] Verify that default value for fix parameter "agent_update_channel" is "ga".

        Steps:
        1. Get fix parameter "agent_update_channel" and verify that its value is set to "ga".
        """
        ssh = SSH()

        # Waiting for fix parameter to get loaded after fresh install of nessus agent.
        wait(lambda: get_fix_parameter_in_nessus_agent(
            parameter_name="agent_update_channel", ssh=ssh, is_secure=False) != "", timeout_seconds=TIME_FIVE_MINUTES,
             sleep_seconds=TIME_TEN_SECONDS, waiting_for="")
        default_update_channel = get_fix_parameter_in_nessus_agent(parameter_name="agent_update_channel", ssh=ssh,
                                                                   is_secure=False)
        # Verify default value for "agent_update_channel"
        assert default_update_channel == "ga", "'ga' is not selected as by default agent update channel."

    @pytest.mark.parametrize("choice_option", ["ea", "stable", "ga"])
    def test_verify_agent_version_and_build_update_using_agent_update_plan(self, choice_option):
        """
        NES-11258: Design and Implement CLI test cases to verify the Agent Update plan
        Scenario Tested:
            [x] Verify Agent version/build gets modified by selecting different option for
                fix parameter "agent_update_channel".

        Steps:
        1. Link agent to Tenable i.o.
        2. Set value for "agent_update_channel" to "ea/ga/stable".
        3. Verify the value successfully set to respected value for "agent_update_channel".
        4. Verify that agent version/build gets updated via goat-feed server.
        """
        ssh = SSH()
        original_agent_version = get_nessus_agent_version(ssh=ssh)
        log.info("Original agent version/build is : {}".format(original_agent_version))

        expected_agent_version = get_expected_nessus_agent_build_and_version_for_given_channel(
            ssh=ssh, update_channel=choice_option)

        set_fix_parameter_in_nessus_agent(parameter_name="agent_update_channel",
                                          parameter_value=choice_option, ssh=ssh)

        # Verify that value for fix parameter "agent_update_channel" set successfully.
        assert get_fix_parameter_in_nessus_agent(ssh=ssh, parameter_name="agent_update_channel") == choice_option, \
            "Agent update channel does not saved successfully."
        trigger_agent_update_checks(ssh=ssh)

        # Agent upgrade/downgrade is not possible in agent versions less than 7.7.0
        expected_update = parse(expected_agent_version[0]) >= parse('7.7.0')

        # As build downgrade for same version is not possible, setting expected update as False
        if parse(original_agent_version[0]) == parse(expected_agent_version[0]) and \
                int(original_agent_version[1]) > int(expected_agent_version[1]):
            expected_update = False

        if expected_update:
            # Verify that Agent version/build gets changed to expected value as per channel selected.
            try:
                wait(lambda: get_nessus_agent_version(ssh=ssh) == expected_agent_version,
                     timeout_seconds=TIME_TEN_MINUTES, sleep_seconds=TIME_TEN_SECONDS,
                     waiting_for="Agent version to get updated as per selected channel.")
            except TimeoutExpired:
                raise AssertionError("Agent version/build does not update to {}".format(expected_agent_version))
            log.info("Updated agent version/build is : {}".format(get_nessus_agent_version(ssh=ssh)))
        else:
            # Verify that Agent version/build remains on same version/build.
            sleep(180, reason="Waiting for the build ")
            assert get_nessus_agent_version(ssh=ssh) == original_agent_version, \
                "Nessus version/build is not same as {} but changed to {}.".format(original_agent_version,
                                                                                   get_nessus_agent_version(ssh=ssh))

    def test_verify_nessus_agent_log_files_after_update(self):
        """
        NES-11665: Adjust automation for agent upgrade/downgrade
        Scenario Tested:
            [x] Verify nessus agent log files after update via "agent_update_channel".

        Steps:
        1. Verify if any errors detected in backend.log after updating Nessus-agent
        2. Verify if any errors detected in nessusd.dump after updating Nessus-agent
        """
        ssh = SSH()
        backend_log = ssh.execute("cat /opt/nessus_agent/var/nessus/logs/backend.log")
        nessusd_dump = ssh.execute("cat /opt/nessus_agent/var/nessus/logs/nessusd.dump")

        # Printing backend.log file for debug purpose
        log.debug("Printing backend.log file")
        for output in backend_log:
            log.debug(output)

        # Printing nessusd.dump file for debug purpose
        log.debug("Printing nessusd.dump file")
        for output in nessusd_dump:
            log.debug(output)

        # Verifying if any errors detected in backend.log after updating Nessus-agent
        assert not any([output for output in backend_log if all(["Error" in output, "downgrader" in output])]), \
            "Error detected in backend.log while updating Nessus-agent via agent update channel"

        # Verifying if any errors detected in nessusd.dump after updating Nessus-agent
        assert not any([output for output in nessusd_dump if all(["Error" in output,
                                                                  "global_db_get_version" in output])]), \
            "Error detected in nessusd.dump while updating Nessus-agent via agent update channel"
