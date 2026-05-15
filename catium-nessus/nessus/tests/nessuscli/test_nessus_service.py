"""
Test cases to Verify Nessus service logs

:copyright: Tenable Network Security, 2020
:date: Nov 18, 2020
:last_modified: Nov 18, 2020
:author: @kpanchal
"""

import datetime
import json

import pytest
from waiting.exceptions import TimeoutExpired

from catium.helpers.sleep_lib import sleep
from catium.lib.activation_code_generator.activation_code_generator import ActivationCodeGenerator
from catium.lib.const.base_constants import TIME_TWO_MINUTES, WAIT_NORMAL, TIME_FIFTEEN_MINUTES, TIME_SIXTY_SECONDS
from catium.lib.log.log import create_logger
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.nessuscli.helper import get_system_datetime, stop_nessus, start_nessus
from nessus.helpers.nessuscli.logchecker import is_log_entries
from nessus.helpers.waiters import wait_for_scanner_status
from nessus.lib.config.environment_variables import NESSUS_LOGS_DIR
from nessus.lib.const.constants import API, NessusCli, Nessus

log = create_logger()


class TestNessusServiceCommands:
    """ Test nessus services commands """

    @pytest.mark.parametrize("test_details", [
        pytest.param({'product_type': ActivationCodeGenerator.NESSUS_MANAGER,
                      'license_type': Nessus.Manager.NESSUS_MANAGER}, marks=pytest.mark.nessus_manager),
        pytest.param({'product_type': ActivationCodeGenerator.NESSUS_PROFESSIONAL,
                      'license_type': Nessus.Professional.NESSUS_PROFESSIONAL}, marks=pytest.mark.nessus_pro)])
    def test_license_info_log_each_time_after_reload(self, test_details):
        """
        NES-12186: [CLI] Verify Nessus logs license info each time it reloads [NES-11779]

        Scenario Tested:
        [x] Verify Nessus logs license info each time it reloads
        """
        nessus_api = NessusAPI()

        for _ in range(3):
            start_timestamp = get_system_datetime()
            end_timestamp = start_timestamp + datetime.timedelta(minutes=30)

            stop_nessus()
            start_nessus()
            sleep(sleep_time=TIME_SIXTY_SECONDS, reason='for reload to take effect.')

            # Wait for two minutes to get "loading" state of Nessus and if not found then execution will continue.
            try:
                wait_for_scanner_status(api=nessus_api, timeout=TIME_TWO_MINUTES, status=API.Status.LOADING,
                                        msg='server to be loading state.', sleep_interval=WAIT_NORMAL)
            except TimeoutExpired:
                log.warning("Loading state was not found within two minutes of wait.")

            wait_for_scanner_status(api=nessus_api, timeout=TIME_FIFTEEN_MINUTES, status=API.Status.READY,
                                    msg='server to finish loading.', sleep_interval=WAIT_NORMAL)

            sleep(sleep_time=TIME_SIXTY_SECONDS, reason='for reload to take effect.')

            expected_log = is_log_entries(log_dir=NESSUS_LOGS_DIR, file_name=NessusCli.BACKEND_LOG,
                                          log_entry="license:", start_timestamp=start_timestamp,
                                          end_timestamp=end_timestamp, max_lines_per_file=100, log_line=True)
            log.debug("License info log :: {}".format(expected_log))

            assert expected_log, 'Failed to get license info log from backend.logs after nessus reload...'

            log_entry = expected_log.split('] ')[3]
            unexpected_info = ["drm", "update_login", "update_password", "activation_code"]

            assert all([item not in log_entry for item in unexpected_info]), \
                'All or one of the key info from "{}" is available in license info log.'.format(unexpected_info)

            license_info_details = json.loads(log_entry.lstrip("license: "))

            log.info(
                f"license type is {license_info_details['type']} and license name is {license_info_details['name']}")

            assert all([license_info_details['type'] == test_details['product_type'],
                        license_info_details['name'] == test_details['license_type']]), \
                'Getting invalid product type/name from license info log.'
