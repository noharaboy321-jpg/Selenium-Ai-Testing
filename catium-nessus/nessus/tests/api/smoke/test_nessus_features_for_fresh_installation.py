"""
Nessus scan feature/linking to tenable-io verification after fresh installation of Nessus
:copyright: Tenable Network Security, 2020
:date: May 26, 2020
:last_modified: July 15, 2020
:author: @vsoni, @kpanchal
"""
from http import HTTPStatus
from uuid import uuid4

import pytest
from requests.exceptions import RequestException
from tenableio.apiobjects.tenablecloud_api import TenableCloudAPI
from tenableio.helpers.container import delete_container
from waiting import wait
from waiting.exceptions import TimeoutExpired

from catium.helpers.testdata import get_file_path
from catium.lib.const import TIME_THIRTY_MINUTES
from catium.lib.const.base_constants import TIME_TEN_SECONDS, TIME_TEN_MINUTES, TIME_FIVE_SECONDS, \
    TIME_FIVE_MINUTES
from catium.lib.log.log import create_logger
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.nessus_link_to_tio import wait_for_scanner_to_become_online_in_tio, add_tenable_io_container
from nessus.helpers.waiters import wait_scan_state, wait_for_scanner_status
from nessus.lib.config import NessusConfig
from nessus.lib.const import API, Nessus
from nessus.tests.conftest import delete_and_unlink_nessus_from_tenableio

log = create_logger()


@pytest.mark.usefixtures('nessus_api_login')
class TestNessusScanEndpoint:
    """Tests for Nessus scan Endpoint"""
    cat = None

    @pytest.mark.parametrize('test_data_file', [pytest.param(
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
         'scan_type': 'advanced'})], indirect=True)
    @pytest.mark.nessus_pro_smoke
    def test_create_launch_scan_and_verify_result(self, create_scan):
        """
            Creates a new scan on the fresh installed Nessus.
            Scenarios tested:
              [x] Successfully create a scan
              [x] Launch the created scan and verify it gets 'running' status successfully
              [x] Verify that launch scan gets 'completed' status.
              [x] Verify scan result after completion
        """
        # Get Scan related information for newly created scan and verify its 200 response
        scan_id = create_scan['scan']['id']
        scans = self.cat.api.scans.get_scans()['scans']
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code
        # Verify scan exists in list.
        assert scan_id in [scan['id'] for scan in scans], 'Failed to create scan'

        assert self.cat.api.scans.details(scan_id)['info']['name'] == "Advanced scan", "Scan Name is incorrect"

        self.cat.api.scans.launch(scan_id)

        # Verify scan launch operation
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code
        assert self.cat.api.scans.get_status(scan_id) == API.Scan.Status.RUNNING, \
            "Scan does not get 'running' state after it gets launched"

        result = wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                 timeout=TIME_THIRTY_MINUTES)
        # Verify scan is pass or fail to complete
        assert result, "Scan failed to complete."

        # Get scan details after completion and verify the same.
        scan_details = self.cat.api.scans.details(scan_id)
        assert len(scan_details['vulnerabilities']) >= 1, "Scan failed to get vulnerabilities"
        assert len(scan_details['history']) == 1, "scan history count should be only one. Actual count is : {}". \
            format(len(scan_details['history']))
        assert scan_details['hosts'][0]['hostname'] == Nessus.Scan.Target.PUB_TARGET_3, "Scan hostname is incorrect"


@pytest.mark.nessus_pro_smoke
class TestLinkNessusProToTenableIO:
    def test_nessus_pro_link_to_tenable_io(self):
        """
        NES-11371: Implement automation to verify Nessus linking to Tenable.io works properly

        Scenarios tested:
              [x] Link Nessus Pro to Tenable-io and verify no exceptions/errors while linking.
              [x] Verify that linked scanner appears in Tenable.io
              [x] Verify that linked Nessus scanner's server properties populated correctly.
        """

        scanner_name = "test_nessus_scanner_%s" % uuid4().hex[:6]
        container_details = add_tenable_io_container()
        api = TenableCloudAPI()
        api.login(username=container_details['container'].model.contact,
                  password=container_details['container'].model.password)
        try:
            # get linking key from create_tio_container fixture
            linking_key = container_details['linking_key']

            nessus_api = NessusAPI()
            nessus_api.login()

            # Verify Nessus link to tenable.io works properly.
            try:
                nessus_api.scanners.link_to_cloud(manager_host=NessusConfig.CAT_TIO_URL,
                                                  linking_key=linking_key,
                                                  scanner_name=scanner_name,
                                                  manager_port="443",
                                                  use_proxy=False,
                                                  register=True)
            except RequestException as exception:
                raise AssertionError("Error while linking Nessus pro with tenable io. "
                                     "Exception is : {}".format(exception))
            wait(lambda: [scanner for scanner in api.scanners.get_list()['scanners']
                          if scanner_name == scanner['name']],
                 sleep_seconds=TIME_TEN_SECONDS, timeout_seconds=TIME_TEN_MINUTES,
                 waiting_for="Scanner to appear in scanners list")

            # Verify that scanner appears in Tenable-io.
            assert scanner_name in [scanner['name'] for scanner in api.scanners.get_list()['scanners']], \
                "scanner does not appear in Tenable-io scanners."

            # Verify if scanner becomes online in Tenable-io
            assert wait_for_scanner_to_become_online_in_tio(scanner_name=scanner_name, api=api), \
                "Scanner does not become online in Tenable-io within ten minutes of time."

            wait_for_scanner_status(api=nessus_api, status=API.Status.LOADING, timeout=TIME_TEN_MINUTES,
                                    sleep_interval=TIME_FIVE_SECONDS, msg='Availability of Nessus scanner')

            wait_for_scanner_status(api=nessus_api, status=API.Status.READY, timeout=TIME_THIRTY_MINUTES,
                                    msg='Availability of Nessus scanner API after linking to t.io.',
                                    sleep_interval=TIME_FIVE_SECONDS)
            server_properties = nessus_api.server.properties()

            # Verify if server properties populated correctly for nessus scanner
            assert server_properties['nessus_ui_build'] is not None, "Nessus build should not be empty."

            assert server_properties['nessus_ui_version'] is not None, "Nessus Version should not be empty."

        finally:
            delete_and_unlink_nessus_from_tenableio(api, scanner_name)
            delete_container(container_uuid=container_details['container'].model.uuid)
            try:
                wait_for_scanner_status(api=nessus_api, status=API.Status.LOADING, timeout=TIME_FIVE_MINUTES,
                                        msg='Availability of Nessus scanner API after linking to t.io.',
                                        sleep_interval=TIME_FIVE_SECONDS)
            except TimeoutExpired:
                log.warning("Nessus does not get 'loading' state after unlink from tenable.io")
            wait_for_scanner_status(api=nessus_api, status=API.Status.READY, timeout=TIME_TEN_MINUTES,
                                    msg='Availability of Nessus scanner API after linking to t.io.',
                                    sleep_interval=TIME_FIVE_SECONDS)
