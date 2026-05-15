"""
Nessus Live Results functionality verification
"""
import pytest
from waiting import wait

from catium.helpers.sleep_lib import sleep
from catium.helpers.testdata import get_file_path, load_testdata
from catium.lib.const import TIME_TEN_SECONDS, TIME_THIRTY_SECONDS, TIME_TWO_MINUTES, TIME_FIVE_MINUTES
from nessus.helpers.cli_command import execute
from nessus.helpers.nessuscli.helper import get_nessus_cli
from nessus.helpers.waiters import wait_scan_state, wait_for_scanner_status
from nessus.lib.const import API


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('nessus_api_login')
class TestNessusLiveResults:
    """Tests for Nessus live results"""
    cat = None

    def run_scan_briefly(self, scan_id):
        """launch the given scan, wait for it to start, then stop it and wait for it to stop running"""
        self.cat.api.scans.launch(scan_id)
        wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.RUNNING,
                        timeout=TIME_THIRTY_SECONDS)
        self.cat.api.scans.stop(scan_id)

        def has_stopped():
            status = self.cat.api.scans.get_status(scan_id)
            return status not in [API.Scan.Status.RUNNING, API.Scan.Status.STOPPING]

        wait(has_stopped, timeout_seconds=TIME_THIRTY_SECONDS, waiting_for='scan to stop.')

    def read_telemetry_metric(self, metric):
        """read the requested telmetry metric, defaulting to 0 if not set"""
        metrics = self.cat.api.server.peek_telemetry()['metrics']
        return metrics[metric] if metric in metrics else 0

    @pytest.mark.incompatible
    @pytest.mark.usefixtures('enable_qa_mode_in_nessus', 'nessus_api_login')
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
         'scan_type': 'advanced'},
    ], indirect=True)
    def test_live_results_scan_telemetry(self, create_scan, test_data_file):
        """
        Creates a new scan on the given scanner, enables live
        results, runs the scan for a few seconds, and verifies
        telemetry increased.

        Scenarios tested:
        [x] Live Results can be enabled
        [x] Live Results scans can be run
        [x] Live Results scans increment telemetry
        [ ] Live Results has an effect
        """

        scan_id = create_scan['scan']['id']

        # Enable Live Results
        payload = load_testdata(test_data_file['scan_json_path'])
        payload['settings']['live_results'] = True
        self.cat.api.scans.configure(scan_id, payload)

        # Get telemetry before running scan
        orig_scan_count = self.read_telemetry_metric('live_results.network_scan')

        # Run the scan (and cancel it after a few seconds, to keep the test short)
        self.run_scan_briefly(scan_id)
        sleep(TIME_TEN_SECONDS, reason="scan to be processed.")

        # Get telemetry after running scan, it should have incremented live_results.network_scan by 1
        def is_incremented_by_one():
            new_scan_count = self.read_telemetry_metric('live_results.network_scan')
            return new_scan_count == orig_scan_count + 1

        wait(is_incremented_by_one, timeout_seconds=TIME_THIRTY_SECONDS,
             waiting_for='telemetry to increment for live results scan.')
        sleep(TIME_TWO_MINUTES, reason="scan to be processed.")

    @pytest.mark.xfail(reason='NES-11528 making xfail for now due to flakiness on Windows platform')
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
         'scan_type': 'advanced'}], indirect=True)
    def test_live_results_rescan_telemetry(self, create_scan, test_data_file):
        """
        Creates a new scan on the given scanner, enables live
        results, runs the scan for a few seconds, triggers
        a rescan, and verifies telemetry increased.

        Scenarios tested:
        [x] Live Results rescans will run when triggered
        [x] Live Results rescans increment telemetry
        [ ] Live Results has an effect
        """
        # Setting value for live_results to "false" initially.
        execute(get_nessus_cli(), ['fix', '--secure', '--set', 'live_results=false'])

        # Waiting till Nessus server status is ready.
        try:
            wait_for_scanner_status(api=self.cat.api, timeout=TIME_TWO_MINUTES, status=API.Status.LOADING,
                                    msg='Waiting for server to finish loading.')
        finally:
            wait_for_scanner_status(api=self.cat.api, timeout=TIME_FIVE_MINUTES, status=API.Status.READY,
                                    msg='Waiting for server to finish loading.')
        scan_id = create_scan['scan']['id']

        # Enable Live Results
        payload = load_testdata(test_data_file['scan_json_path'])
        payload['settings']['live_results'] = True
        self.cat.api.scans.configure(scan_id, payload)

        # Run the scan to get a baseline (and cancel it after a few seconds, to keep the test short)
        self.run_scan_briefly(scan_id)
        sleep(TIME_TEN_SECONDS, reason="scan to be processed.")

        # Get the telemetry value before rescan to see if it increments
        orig_rescan_count = self.read_telemetry_metric('live_results.offline_scan')

        # Set this magic value which triggers live results rescans
        # (normally this is set during a plugins update)
        execute(get_nessus_cli(), ['fix', '--secure', '--set', 'live_results=true'])

        # Get telemetry after running scan, it should have incremented live_results.offline_scan by 1
        def is_incremented_by_one():
            try:
                new_rescan_count = self.read_telemetry_metric('live_results.offline_scan')
                return new_rescan_count > orig_rescan_count
            except:
                pass

        wait(is_incremented_by_one, timeout_seconds=TIME_FIVE_MINUTES,
             waiting_for='telemetry to increment for live results rescan.')
        sleep(TIME_TWO_MINUTES, reason="scan to be processed.")
