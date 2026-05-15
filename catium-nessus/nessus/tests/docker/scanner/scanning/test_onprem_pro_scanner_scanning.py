"""
TEST CASE: Automation - Implement Nessus Professional scanner tests

:copyright: Tenable Network Security, 2018
:date: March 22 2018
:author: @sshah
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
@pytest.mark.usefixtures("link_proscanner_to_onprem")
class TestProScannerScanning:
    """Test Nessus Pro Scanner scanning on T.io Onprem."""

    cat = None
    controller_type = ControllerType.onprem
    fetch_key = True
    linked = True
    wait_for_plugin_loading = True

    def test_onprem_pro_scanner_scanning(self, link_proscanner_to_onprem ):

        """
        Confirm pro scanners can link to T.io Onprem, download a plugin-set and run scans.

        1. Start Nessus Docker container passing it the controller configuration and grabbing the container id.
        2. Poll logs inside of Docker container and wait for initialization script to complete successfully.
        3. Confirm plugins get installed by watching for the log entry in backend.log.
        4. Launch an Advanced Scan and ensure scan results are made available.
        5. Confirm plugin output from Nessus Scan Information (19506) plugin is available.
        """
        # Create the scan model and scan policy:
        ScanModel.text_targets = "localhost"
        ScanModel.name = "Automation - T.io Pro Scanner Scanning - {0}".format(link_proscanner_to_onprem.scanner_name)
        ScanModel.scanner_id = link_proscanner_to_onprem.linking_details["id"]
        log.debug("Scanner id is %s", ScanModel.scanner_id)
        model = ScanModel()
        scan_info = create_scan_job(scan=model, api_session=link_proscanner_to_onprem.controller_api,
                                    container_username=link_proscanner_to_onprem.override_user,
                                    container_password=link_proscanner_to_onprem.override_pass)
        assert scan_info, "Failed to create scan from model. Output: {0}".format(scan_info)
        log.info("Nessus Scan with ID %s was successfully "
                 "created in container %s.", scan_info["id"], link_proscanner_to_onprem.container_details["uuid"])

        # Launch the scan and wait for it to complete.
        launch_scan(scan={"id": scan_info["id"]}, api=link_proscanner_to_onprem.controller_api)
        scan_running = wait_scan_state(api=link_proscanner_to_onprem.controller_api,
                                       scan_id=scan_info["id"],
                                       end_state=API.Scan.Status.RUNNING,
                                       timeout=TIME_THIRTY_MINUTES)
        assert scan_running, "The Nessus scan did not start or 10m timeout has expired."
        log.info("Nessus scan with ID %s has started running in container %s, "
                 "waiting for it to complete.", scan_info["id"], link_proscanner_to_onprem.container_details["uuid"])

        scan_completed = wait_scan_state(api=link_proscanner_to_onprem.controller_api,
                                         scan_id=scan_info["id"],
                                         end_state=API.Scan.Status.COMPLETED,
                                         timeout=TIME_THIRTY_MINUTES)

        assert scan_completed, "The Nessus scan did not complete or 15m timeout has expired."
        log.info("Nessus scan with ID %s has completed successfully "
                 "in container %s.", scan_info["id"], link_proscanner_to_onprem.container_details["uuid"])

        # Check to make sure plugin results from Nessus Scan Information plugin are received.
        wait_for_severities(api=link_proscanner_to_onprem.controller_api, scan_id=scan_info["id"])
        plugin_output_available = check_vuln_info_available(api=link_proscanner_to_onprem.controller_api,
                                                            scan_id=scan_info["id"], plugin_id=SCAN_INFO_PLUGIN)
        assert plugin_output_available, "Nessus Scan information ({0}) plugin output is not available in scan {1} in " \
                                        "container {2}.".format(SCAN_INFO_PLUGIN, scan_info["id"],
                                                                link_proscanner_to_onprem.container_details["uuid"])
