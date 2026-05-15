"""
Nessus Pro channel update and package upgrade/downgrade related tests

:copyright: Tenable Network Security, 2020
:date: November 24, 2020
:last_modified: November 25, 2020
:author: @vsoni
"""

import pytest
from packaging.version import parse
from waiting import wait

from catium.lib.activation_code_generator.activation_code_generator import ActivationCodeGenerator
from catium.lib.const.base_constants import TIME_TEN_MINUTES, TIME_FIVE_MINUTES, TIME_FIVE_SECONDS
from catium.lib.log.log import create_logger
from catium.lib.ssh.ssh import SSH
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.nessuscli.helper import start_nessus, stop_nessus, get_install_update_command, get_installed_os, \
    get_nessus_cli
from nessus.helpers.scanner import wait_for_scanner_to_be_ready
from nessus.helpers.software_update import get_nessus_version_and_build_using_api, set_software_update_channel, \
    clean_up_log_files_before_software_update, verify_no_errors_while_software_update, \
    verify_scan_gets_executed_properly_after_software_update, is_nessus_updated
from nessus.helpers.waiters import wait_for_scanner_status
from nessus.lib.const.constants import API, NessusInstallation

log = create_logger()


@pytest.fixture()
def disable_signature_verification():
    """Disable signature verification by setting secure fix parameter feed_no_sig as 'yes'."""
    with SSH() as ssh:
        ssh.execute("{} fix --set --secure feed_no_sig=yes".format(get_nessus_cli()))

    api = NessusAPI()
    wait_for_scanner_status(api=api, status=API.Status.LOADING, timeout=TIME_FIVE_MINUTES,
                            sleep_interval=TIME_FIVE_SECONDS, msg='Wait for loading')
    wait_for_scanner_status(api=api, status=API.Status.READY, timeout=TIME_TEN_MINUTES,
                            sleep_interval=TIME_FIVE_SECONDS, msg='Availability of Nessus scanner')


def verify_nessus_downgrades_upgrades(update_channel: str, api: NessusAPI) -> None:
    """
    This method change the update channel to given channel and verifies that Nessus is downgraded or not
    Then it force upgrades to release-next build of Nessus and verifies that Nessus upgraded or not
    After each update operation (downgrade/upgrade), it verifies that
        1. There are no errors present in backend.log, nessusd.messages and nessusd.dump log files.
        2. Scan gets created, launched and completed successfully.
    :param str update_channel: Channel to which Nessus needs to downgraded (ga/stable)
    :param NessusAPI api: Instance of Nessus API
    :return: None
    """
    ssh = SSH()
    original_nessus_version, original_nessus_build = get_nessus_version_and_build_using_api()
    log.info("Original Nessus version details : {}-{}".format(original_nessus_version, original_nessus_build))

    clean_up_log_files_before_software_update()

    set_software_update_channel(api=api, update_channel=update_channel)
    api.settings.add_software_updates_setting()

    wait_for_scanner_to_be_ready(api=api)

    wait(lambda: is_nessus_updated(update_operation="downgrade", original_version=original_nessus_version),
         timeout_seconds=TIME_TEN_MINUTES * 2, waiting_for="Nessus to get downgraded.")

    downgraded_nessus_version, downgraded_nessus_build = get_nessus_version_and_build_using_api()
    log.info("Downgraded Nessus version details : {}-{}".format(downgraded_nessus_version, downgraded_nessus_build))

    assert parse(downgraded_nessus_version) < parse(original_nessus_version), \
        "Nessus did not update to {} channel".format(update_channel)

    assert verify_scan_gets_executed_properly_after_software_update(api=api), \
        "Issue while scan execution after Nessus downgrade to {} channel.".format(update_channel)

    assert verify_no_errors_while_software_update(), "Received error in log files after Nessus downgrade"

    clean_up_log_files_before_software_update()

    stop_nessus()
    installed_os = get_installed_os()
    ssh.execute("{} {}".format(get_install_update_command(installed_os=installed_os, operation="force_upgrade"),
                               NessusInstallation.BUILD_PATH[installed_os]))
    start_nessus()

    wait_for_scanner_to_be_ready(api=api)
    wait(lambda: is_nessus_updated(update_operation="upgrade", original_version=downgraded_nessus_version),
         timeout_seconds=TIME_TEN_MINUTES, waiting_for="Nessus to get upgraded.")

    upgraded_nessus_version, upgraded_nessus_build = get_nessus_version_and_build_using_api()
    log.info("Upgraded Nessus version details : {}-{}".format(upgraded_nessus_version, upgraded_nessus_build))

    assert parse(upgraded_nessus_version) > parse(downgraded_nessus_version), \
        "Nessus did not upgrade successfully."

    assert verify_scan_gets_executed_properly_after_software_update(api=api), \
        "Issue while scan execution after Nessus upgrade."

    assert verify_no_errors_while_software_update(), "Received error in log files after Nessus upgrade."


@pytest.mark.nessus_pro_upgrade_downgrade
class TestNessusProUpgradeDowngrade:
    """Nessus Pro channel update and package upgrade related tests"""
    cat = None

    @pytest.mark.usefixtures('disable_signature_verification', 'nessus_api_login')
    def test_verify_ga_channel_downgrades_nessus(self):
        """
        NES-12303: [API Automation] : Channel update for Nessus Pro

        Scenario Tested:
            [x] Verify that Nessus downgrades to GA channel and then upgrades to release-next build successfully

        Test Steps:
            1. Select the nessus pro update channel to "GA"
            2. Verify that Nessus downgrades to GA channel's build
            3. Verify that scan execution performed without any errors.
            4. Verify that there is not any error present in backend.log, nessusd.messages and nessusd.dump files
            5. Force upgrade nessus to release-next build and verify that Nessus upgraded
            6. Verify step-3 and step-4
        """
        verify_nessus_downgrades_upgrades(update_channel="ga", api=self.cat.api)

    @pytest.mark.parametrize('fresh_install_nessus', [ActivationCodeGenerator.NESSUS_PROFESSIONAL], indirect=True)
    @pytest.mark.usefixtures('fresh_install_nessus', 'disable_signature_verification', 'nessus_api_login')
    def test_verify_stable_channel_downgrades_nessus(self):
        """
        NES-12303: [API Automation] : Channel update for Nessus Pro

        Scenario Tested:
            [x] Verify that Nessus downgrades to Stable channel and then upgrades to release-next build successfully

        Test Steps:
            1. Select the nessus pro update channel to "Stable"
            2. Verify that Nessus downgrades to Stable channel's build
            3. Verify that scan execution performed without any errors.
            4. Verify that there is not any error present in backend.log, nessusd.messages and nessusd.dump files
            5. Force upgrade nessus to release-next build and verify that Nessus upgraded
            6. Verify step-3 and step-4
        """
        verify_nessus_downgrades_upgrades(update_channel="stable", api=self.cat.api)
