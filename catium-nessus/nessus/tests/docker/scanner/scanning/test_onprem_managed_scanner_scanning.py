"""

TEST CASE: https://jira.corp.tenablesecurity.com/browse/CI-17966

:copyright: Tenable Network Security, 2018
:date: Feb 28th, 2018
:author: @jmcneil
"""

import pytest

from catium.lib.const.base_constants import TIME_THIRTY_MINUTES
from catium.lib.log import create_logger
from nessus.helpers.dockernessus.lib.constants import ControllerType
from tenableio.lib.const import API
from tenableio.helpers.scans import wait_for_severities, check_vuln_info_available
from tenableio.helpers.scan_job import create_scan_job, launch_scan, wait_scan_state
from tenableio.models.scan_model import ScanModel


SCAN_INFO_PLUGIN = 19506
log = create_logger()


@pytest.mark.scanner
@pytest.mark.io_onprem
@pytest.mark.long_running
@pytest.mark.usefixtures("docker_managed_scanner")
class TestManagedScannerScanning:
    """Test Nessus Managed Scanner scanning on T.io Onprem."""

    cat = None
    controller_type = ControllerType.onprem
    fetch_key = True
    linked = True
    wait_for_plugin_loading = True

    def test_onprem_managed_scanner_scanning(self, docker_managed_scanner):
        """
        Confirm managed scanners can link to T.io Onprem, download a plugin-set and run scans.

        1. Start Nessus Docker container passing it the controller configuration and grabbing the container id.
        2. Poll logs inside of Docker container and wait for initialization script to complete successfully.
        3. Check the status of the managed Nessus using nessuscli to ensure it is linked and accepting jobs.
        4. Confirm plugins get installed by watching for the log entry in backend.log.
        5. Launch an Advanced Scan and ensure scan results are made available.
        6. Confirm plugin output from Nessus Scan Information (19506) plugin is available.
        """
        # Create the scan model and scan policy:
        ScanModel.text_targets = "localhost"
        ScanModel.name = "Automation - T.io Managed Scanner Scanning - {0}".format(docker_managed_scanner.scanner_name)
        ScanModel.scanner_id = docker_managed_scanner.linking_details["id"]
        model = ScanModel()
        scan_info = create_scan_job(scan=model, api_session=docker_managed_scanner.controller_api,
                                    container_username=docker_managed_scanner.override_user,
                                    container_password=docker_managed_scanner.override_pass)
        assert scan_info, "Failed to create scan from model. Output: {0}".format(scan_info)
        log.info("Nessus Scan scan with ID %s was successfully "
                 "created in container %s.", scan_info["id"], docker_managed_scanner.container_details["uuid"])

        # Launch the scan and wait for it to complete.
        launch_scan(scan={"id": scan_info["id"]}, api=docker_managed_scanner.controller_api)
        scan_running = wait_scan_state(api=docker_managed_scanner.controller_api,
                                       scan_id=scan_info["id"],
                                       end_state=API.Scan.Status.RUNNING,
                                       timeout=TIME_THIRTY_MINUTES)
        assert scan_running, "The Nessus scan did not start or 10m timeout has expired."
        log.info("Nessus scan with ID %s has started running in container %s, "
                 "waiting for it to complete.", scan_info["id"], docker_managed_scanner.container_details["uuid"])

        scan_completed = wait_scan_state(api=docker_managed_scanner.controller_api,
                                         scan_id=scan_info["id"],
                                         end_state=API.Scan.Status.COMPLETED,
                                         timeout=TIME_THIRTY_MINUTES)

        assert scan_completed, "The Nessus scan did not complete or 15m timeout has expired."
        log.info("Nessus scan with ID %s has completed successfully "
                 "in container %s.", scan_info["id"], docker_managed_scanner.container_details["uuid"])

        # Check to make sure plugin results from Nessus Scan Information plugin are received.
        wait_for_severities(api=docker_managed_scanner.controller_api, scan_id=scan_info["id"])
        plugin_output_available = check_vuln_info_available(api=docker_managed_scanner.controller_api,
                                                            scan_id=scan_info["id"], plugin_id=SCAN_INFO_PLUGIN)
        assert plugin_output_available, "Nessus Scan information ({0}) plugin output is not available in scan {1} in " \
                                        "container {2}.".format(SCAN_INFO_PLUGIN, scan_info["id"],
                                                                docker_managed_scanner.container_details["uuid"])
