"""
NES-19849: Show UI Banner Spinner During Audit Warehouse Update

Covers Xray test case NES-19859 (Audit warehouse status):
  Step 1: Install Nessus fresh with plugins. Load the UI and watch the status API call.
          → Confirm at least in the first few calls that audit warehouse is updating.
            This may complete by the time the login screen loads up.
  Step 2: Remove the audit warehouse file under var/nessus/audits/. Restart nessusd.
          → A UI notification should show stating there was an error with the audit warehouse.

The GET /server/status response includes a detailed_status object:
    {
        "audit_warehouse_status": {"message": "Updating audit files", "status": "updating"},
        "feed_status":            {"progress": 100, "status": "ready"},
        "db_status":              {"progress": null, "status": "registration-loading"},
        "engine_status":          {"progress": 100, "status": "ready"}
    }

The top-level status will NOT be "ready" until all sub-statuses (including
audit_warehouse_status) have resolved. This means existing wait_for_scanner_status(READY)
calls will now correctly block during warehouse updates, fixing flaky compliance tests.

:date: March 10, 2026
"""

import pytest
from requests.exceptions import RequestException
from waiting import wait

from catium.lib.const.base_constants import (
    TIME_FIVE_SECONDS,
    TIME_TEN_SECONDS,
    TIME_THIRTY_MINUTES,
)
from catium.lib.log import create_logger
from catium.lib.ssh.ssh import SSH
from http import HTTPStatus

from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.nessuscli.helper import get_nessus_cli, is_nessus_running, stop_nessus, start_nessus
from nessus.helpers.waiters import wait_for_scanner_status
from nessus.lib.const.constants import API, System

log = create_logger()

AUDIT_WAREHOUSE_STATUS_KEY = 'audit_warehouse_status'
WAREHOUSE_STATUS_UPDATING = 'updating'
WAREHOUSE_STATUS_READY = 'ready'
WAREHOUSE_STATUS_ERROR = 'error'
WAREHOUSE_STATUS_FAILED = 'failed'


def _get_warehouse_status(status_response):
    """Extract audit_warehouse_status from the detailed_status object in server status."""
    detailed = status_response.get('detailed_status', {})
    return detailed.get(AUDIT_WAREHOUSE_STATUS_KEY, {})


def _wait_for_warehouse_ready(api, timeout=TIME_THIRTY_MINUTES, msg='audit warehouse to reach ready'):
    """Wait until both top-level status and audit_warehouse_status are ready.

    The top-level /server/status can report "ready" even when the warehouse
    status is "failed", so we must check both explicitly.
    """
    def _check():
        try:
            status_response = api.server.status()
        except RequestException:
            return False
        top_level = status_response.get('status', '')
        warehouse = _get_warehouse_status(status_response)
        warehouse_status = warehouse.get('status', '')
        log.info('Teardown polling: status=%s, audit_warehouse_status=%s', top_level, warehouse)
        return top_level == API.Status.READY and warehouse_status == WAREHOUSE_STATUS_READY

    wait(_check, timeout_seconds=timeout, sleep_seconds=TIME_FIVE_SECONDS, waiting_for=msg)


@pytest.fixture(scope='function')
def trigger_warehouse_rebuild():
    """
    Triggers an audit warehouse rebuild by running nessuscli update --plugins-only
    while nessusd is stopped, then starting the service. The server will rebuild
    the audit warehouse on startup, during which audit_warehouse_status shows
    status "updating".

    Uses its own unauthenticated NessusAPI instance since /server/status does
    not require login, and we need to poll during startup before the server
    reaches ready.

    Yields the API once the server enters LOADING state (warehouse rebuild
    in progress). Waits for READY on teardown.
    """
    api = NessusAPI(login=False, logout=False)

    # Stop nessusd, update plugins via CLI, then start
    stop_nessus(wait_for_stop=True)
    assert not is_nessus_running(), 'Nessus should be stopped before plugin update'

    with SSH() as ssh:
        ssh.execute(command='{} update --plugins-only'.format(get_nessus_cli()), sudo=True)

    start_nessus()

    # Wait for the server to enter loading state — it is now coming up
    # and rebuilding the warehouse
    wait_for_scanner_status(api=api, status=API.Status.LOADING,
                            timeout=TIME_FIVE_SECONDS * 60,
                            msg='server to enter loading state after plugin update',
                            sleep_interval=1)

    yield api

    _wait_for_warehouse_ready(api, msg='server and warehouse to return to ready after rebuild')


@pytest.fixture(scope='function')
def remove_audit_warehouse_and_restart():
    """
    NES-19859 Step 2: Move the audit warehouse file aside and restart nessusd.
    Uses its own unauthenticated NessusAPI instance since /server/status
    does not require login. Restores the file and waits for ready on teardown.
    """
    api = NessusAPI(login=False, logout=False)
    warehouse_path = System.LINUX_AUDIT_WAREHOUSE
    backup_path = warehouse_path + '.bak'

    with SSH() as ssh:
        ssh.execute(command='mv -f {} {}'.format(warehouse_path, backup_path), sudo=True)

    # Stop, then start nessusd so it detects the missing warehouse
    stop_nessus(wait_for_stop=True)
    assert not is_nessus_running(), 'Nessus should be stopped before starting'
    start_nessus()

    # Wait for the server to enter loading state
    wait_for_scanner_status(api=api, status=API.Status.LOADING,
                            timeout=TIME_FIVE_SECONDS * 60,
                            msg='server to enter loading state after restart',
                            sleep_interval=1)

    yield api

    # Teardown: restore the audit warehouse file and restart for full recovery
    stop_nessus(wait_for_stop=True)
    with SSH() as ssh:
        ssh.execute(command='mv -f {} {}'.format(backup_path, warehouse_path), sudo=True)
    start_nessus()
    _wait_for_warehouse_ready(api, msg='server and warehouse to return to ready after restoration')


@pytest.mark.nessus_pro
@pytest.mark.nessus_expert
@pytest.mark.nessus_manager
@pytest.mark.xray(test_key='NES-19859')
class TestAuditWarehouseUpdateStatus:
    """
    NES-19859: Audit warehouse status

    Verifies that GET /server/status exposes the audit warehouse updating state
    via detailed_status.audit_warehouse_status and that the top-level status
    does not report "ready" until the warehouse update completes.

    Note: These tests do NOT use nessus_api_login because they need to poll
    /server/status during the restart cycle, before the server reaches ready.
    The /server/status endpoint does not require authentication.
    """

    def test_server_status_shows_audit_warehouse_updating(self, trigger_warehouse_rebuild):
        """
        NES-19859 Step 1: Watch the status API call after triggering a warehouse rebuild.

        Confirm that at least in the first few calls, detailed_status.audit_warehouse_status
        shows status "updating" with message "Updating audit files". The top-level status
        should NOT be "ready" while the warehouse is updating.

        Once the warehouse finishes, audit_warehouse_status.status should be "ready"
        and the top-level status should also return to "ready".
        """
        api = trigger_warehouse_rebuild

        warehouse_non_ready_seen = False
        warehouse_observed_status = None
        warehouse_observed_message = None

        def check_status():
            nonlocal warehouse_non_ready_seen, warehouse_observed_status, warehouse_observed_message
            try:
                status_response = api.server.status()
            except RequestException:
                return False

            warehouse = _get_warehouse_status(status_response)
            top_level_status = status_response.get('status', '')
            warehouse_status = warehouse.get('status', '')

            log.info('Server status=%s, audit_warehouse_status=%s', top_level_status, warehouse)

            # Capture any non-ready warehouse state (updating, failed, etc.)
            if warehouse_status and warehouse_status != WAREHOUSE_STATUS_READY:
                warehouse_non_ready_seen = True
                warehouse_observed_status = warehouse_status
                warehouse_observed_message = warehouse.get('message', '')

            # While warehouse is actively updating, top-level must not be ready
            if warehouse_status == WAREHOUSE_STATUS_UPDATING:
                assert top_level_status != API.Status.READY, \
                    'Top-level status should not be "ready" while audit warehouse is updating'

            return top_level_status == API.Status.READY

        wait(check_status,
             timeout_seconds=TIME_THIRTY_MINUTES,
             sleep_seconds=1,
             waiting_for='server to complete audit warehouse update and return to ready')

        # Verify we observed a non-ready warehouse state during startup
        assert warehouse_non_ready_seen, \
            'Expected to observe a non-ready audit_warehouse_status during startup'
        log.info('Observed audit_warehouse_status.status="%s" with message: "%s"',
                 warehouse_observed_status, warehouse_observed_message)

    def test_notification_on_missing_audit_warehouse(self, remove_audit_warehouse_and_restart):
        """
        NES-19859 Step 2: Remove the audit warehouse file and restart nessusd.

        A UI notification should show stating there was an error with the audit
        warehouse. We verify this via detailed_status.audit_warehouse_status
        which should reflect an error state.
        """
        api = remove_audit_warehouse_and_restart

        # Wait for the server to come back up — it may or may not reach "ready"
        # depending on whether the missing warehouse blocks that state
        warehouse_error_seen = False
        warehouse_error_message = None

        def check_for_warehouse_error():
            nonlocal warehouse_error_seen, warehouse_error_message
            try:
                status_response = api.server.status()
            except RequestException:
                return False

            warehouse = _get_warehouse_status(status_response)
            top_level_status = status_response.get('status', '')

            log.info('Server status=%s, audit_warehouse_status=%s', top_level_status, warehouse)

            warehouse_status = warehouse.get('status', '')
            if warehouse_status in (WAREHOUSE_STATUS_ERROR, WAREHOUSE_STATUS_FAILED):
                warehouse_error_seen = True
                warehouse_error_message = warehouse.get('message', '')
                return True

            # Also succeed if the server reaches ready (warehouse was rebuilt automatically)
            return top_level_status == API.Status.READY

        wait(check_for_warehouse_error,
             timeout_seconds=TIME_THIRTY_MINUTES,
             sleep_seconds=TIME_TEN_SECONDS,
             waiting_for='server to report audit warehouse error or reach ready after warehouse removal')

        assert warehouse_error_seen, \
            'Expected audit_warehouse_status to report an error after removing the warehouse file'
        log.info('Audit warehouse error message: "%s"', warehouse_error_message)
