"""
Test cases for plugins telemetry data
:copyright: Tenable Network Security, 2019
:date: March 01, 2023
:author: @xxia, @krpatel.ctr
"""
import pytest

from catium.helpers.sleep_lib import sleep
from catium.lib.const import TIME_SIXTY_SECONDS, TIME_THIRTY_MINUTES
from catium.lib.log import create_logger
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.nessuscli.helper import stop_nessus, start_nessus
from nessus.helpers.waiters import wait_for_scanner_status
from nessus.lib.const import API

log = create_logger()


@pytest.mark.nessus_home
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('copy_plugin_files')
@pytest.mark.parametrize('copy_plugin_files', [[
    'plugin_feed_info.inc',
    'custom_plugin-1.nasl',
    'custom_plugin-2.nasl',
    'nnm_plugin-1.nasl',
    'nnm_plugin-2.nasl',
    'bad_custom_plugin-1.nasl',
    'bad_custom_plugin-2.nasl',
    'bad_custom_plugin-3.nasl',
    'bad_ubuntu_USN-12-1-1.nasl',
    'bad_ubuntu_USN-12-1-2.nasl',
    'bad_ubuntu_USN-12-1-3.nasl',
    'bad_ubuntu_USN-12-1-4.nasl',
    'bad_ubuntu_USN-12-1-5.nasl',
    'bad_ubuntu_USN-12-1-6.nasl',
    'bad_ubuntu_USN-12-1-7.nasl',
    'bad_ubuntu_USN-12-1-8.nasl',
    'bad_ubuntu_USN-12-1-9.nasl',
    'bad_ubuntu_USN-12-1.nasl',
    'bad_ubuntu_USN-122-1.nasl',
]], indirect=True)
class TestPluginTelemetry:
    """Test cases for Nessus Plugins Telemetry data"""

    @pytest.mark.xray(test_key='NES-15181')
    @pytest.mark.xfail(reason='NES-11528 making xfail for now due to flakiness on Windows platform')
    def test_plugin_telemetry(self):
        """
        NES-15181: Verify that with the help of telemetry_period, the user is able to get telemetry in every 1 hr

        Scenario Tested:
        [x] Verify that with the help of telemetry_period, the user is able to get telemetry in every 1 hr
        [x] The telemetry should contain
            plugins.tenable_failed_to_compile_count
            plugins.custom_failed_to_compile_count
            plugins.failed_plugin_names
            plugins.failed_to_compile_count
            plugins.non_nessus_plugins_count
            plugins.custom_plugins_count
            plugins.non_nessus_plugins_count
        """
        log.debug('Copy plugin files to plugins directory')

        # 1. copy plugin files to the plugins directory

        # 2. the new plugin_feed_info.inc should trigger the new plugin compilation
        print("Stopping nessus...")
        stop_nessus()
        print("Starting nessus...")
        start_nessus()
        print("Compiling plugins...")

        nessus_api = NessusAPI()
        wait_for_scanner_status(api=nessus_api, status=API.Status.READY, timeout=TIME_THIRTY_MINUTES,
                                msg='Waiting for server to be in ready state.')
        nessus_api.login()

        print("wait 1 min for telemetry data ready...")
        sleep(TIME_SIXTY_SECONDS, "wait for 1 min so the scanner telemetry data is ready")

        # 3. peek telemetry to verify
        response = nessus_api.server.peek_telemetry()
        print(response)
        assert response["metrics"]["plugins.tenable_failed_to_compile_count"] == 11
        assert response["metrics"]["plugins.custom_failed_to_compile_count"] == 3
        assert response["metrics"]["plugins.failed_to_compile_count"] == 14
        assert response["metrics"]["plugins.failed_plugin_names"].count("bad_") == 10
        assert response["metrics"]["plugins.custom_plugins_count"] == 2
        assert response["metrics"]["plugins.non_nessus_plugins_count"] == 2
