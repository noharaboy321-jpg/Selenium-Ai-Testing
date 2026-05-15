"""

TEST CASE: https://jira.corp.tenablesecurity.com/browse/CI-17966

:copyright: Tenable Network Security, 2018
:date: Feb 23rd, 2018
:author: @jmcneil
"""

import pytest

from catium.lib.const.base_constants import TIME_THREE_MINUTES, TIME_FIFTEEN_MINUTES
from catium.lib.log import create_logger
from nessus.helpers.dockernessus.lib.constants import ControllerType
from nessus.helpers.dockernessus.lib.system import agent_logreader
from tenableio.lib.const import API
from tenableio.helpers.scans import wait_for_severities, check_vuln_info_available
from tenableio.helpers.scan_job import create_scan_job, launch_scan, wait_scan_state
from tenableio.models.scan_model import ScanModel


SCAN_INFO_PLUGIN = 19506
log = create_logger()


@pytest.mark.agent
@pytest.mark.io_onprem
@pytest.mark.long_running
@pytest.mark.usefixtures("docker_agent")
class TestAgentOnPremAgentScanning:
    """Test Nessus Agent ability to download plugins from T.io Onprem."""

    cat = None
    controller_type = ControllerType.onprem

    def test_onprem_agent_scanning(self, docker_agent):
        """
        Confirm agents can link to T.io Onprem, download a plugin-set and run scans.

        1. Start Nessus Agent Docker container passing it the controller configuration and grabbing the container id.
        2. Poll logs inside of Docker container and wait for initialization script to complete successfully.
        3. Check the status of the Nessus Agent using nessuscli to ensure it is linked and accepting jobs.
        4. Confirm the plugins get installed by watching for the log entry in backend.log.
        5. Launch an Advanced Agent scan and ensure scan results are made available.
        6. Confirm plugin output from Nessus Scan Information (19506) plugin is available.
        """
        # Ensure plugins get installed
        plugins_installed = agent_logreader.wait_for_agentdb_install(cid=docker_agent.cid)
        assert plugins_installed, "Plugins failed to install correctly or there was an issue parsing backend.log."
        log.info("Agent plugins finished installing in Docker container %s.", docker_agent.cid)

        # Launch a scan and make sure it completes. Note: group_id == uuid in scan policy.
        ScanModel.agent_group_id = [docker_agent.agent_group_details['uuid']]
        ScanModel.default_template = "Advanced Agent Scan"
        ScanModel.name = "Automation - T.io Agent Scanning"
        model = ScanModel()
        scan_info = create_scan_job(scan=model, api_session=docker_agent.controller_api,
                                    container_username=docker_agent.override_user,
                                    container_password=docker_agent.override_pass)
        assert scan_info, "Failed to create scan from model. Output: {0}".format(scan_info)
        log.info("Agent scan with ID %s was successfully "
                 "created in container %s.", scan_info["id"], docker_agent.container_details["uuid"])

        # Launch the scan and wait for it to complete.
        launch_scan(scan={"id": scan_info["id"]}, api=docker_agent.controller_api)
        scan_running = wait_scan_state(api=docker_agent.controller_api,
                                       scan_id=scan_info["id"],
                                       end_state=API.Scan.Status.RUNNING,
                                       timeout=TIME_THREE_MINUTES)
        assert scan_running, "The Agent scan did not start or 3m timeout has expired."
        log.info("Agent scan with ID %s has started running in container %s, "
                 "waiting for it to complete.", scan_info["id"], docker_agent.container_details["uuid"])

        scan_completed = wait_scan_state(api=docker_agent.controller_api,
                                         scan_id=scan_info["id"],
                                         end_state=API.Scan.Status.COMPLETED,
                                         timeout=TIME_FIFTEEN_MINUTES)

        assert scan_completed, "The Agent scan did not complete or 15m timeout has expired."
        log.info("Agent scan with ID %s has completed successfully "
                 "in container %s.", scan_info["id"], docker_agent.container_details["uuid"])

        # Check to make sure plugin results from Nessus Scan Information plugin are received.
        wait_for_severities(api=docker_agent.controller_api, scan_id=scan_info["id"])
        plugin_output_available = check_vuln_info_available(api=docker_agent.controller_api,
                                                            scan_id=scan_info["id"], plugin_id=SCAN_INFO_PLUGIN)
        assert plugin_output_available, "Nessus Scan information ({0}) " \
                                        "plugin output is not available in " \
                                        "scan {1} in container {2}.".format(SCAN_INFO_PLUGIN,
                                                                            scan_info["id"],
                                                                            docker_agent.container_details["uuid"])
