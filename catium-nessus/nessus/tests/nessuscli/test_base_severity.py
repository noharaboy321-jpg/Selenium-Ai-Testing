"""
Test the severity basis related CLI commands.

:copyright: Tenable Network Security, 2017
:date: March 22, 2021
:last_modified: July 30, 2024
:author: @kpanchal, @krpatel
"""
import os

import pytest
from waiting import TimeoutExpired, wait

from catium.lib.const import TIME_FIFTEEN_MINUTES, TIME_SIXTY_SECONDS
from catium.lib.log import create_logger
from catium.lib.ssh import SSH
from nessus.helpers.nessuscli.helper import get_nessus_cli
from nessus.lib.config.environment_variables import NESSUS_LOGS_DIR
from nessus.lib.const import NessusCli
from nessus.lib.message.messages import Messages

log = create_logger()


def is_log_found(log_dir: str, file_name: str, message: str) -> bool:
    """
    Check if given log message is present in nessus logs

    :param str log_dir: log file dir path
    :param str file_name: log file name
    :param str message: expected message in a log file to be verified
    :return: True if entry present otherwise False
    :rtype: bool
    """
    log_file = os.path.join(log_dir, file_name)
    with SSH() as ssh:
        nessus_logs = ssh.execute("cat {}".format(log_file))

    for log_message in nessus_logs:
        if message in log_message:
            log.info("'{}' log message found in {}".format(message, log_file))
            return True


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
class TestSeverityBasisCommands:
    """ Tests of severity basis related CLI commands """

    @pytest.mark.xfail(reason="Making xfail the test for now due to flakiness")
    @pytest.mark.parametrize('setting_details', [{'name': 'severity_basis', 'value': 'cvss_v3'}])
    def test_verify_default_severity_basis_value(self, setting_details):
        """
        NES-12484 :  Verify default severity setting is set to cvss_v3 on 8.14.0 fresh install

        Scenario Tested:
            [x] Verify that default severity_basis value is set to "cvss_v3".
        """
        expected_log = Messages.NessusCli.GLOBAL_DB_UPGRADE_COMPLETE

        try:
            wait(lambda: is_log_found(log_dir=NESSUS_LOGS_DIR, file_name=NessusCli.BACKEND_LOG,
                                      message=expected_log), timeout_seconds=TIME_FIFTEEN_MINUTES,
                 sleep_seconds=TIME_SIXTY_SECONDS)
            log.info("global db upgrade has already been completed.")
        except TimeoutExpired:
            log.warning('{} is not present in "backend.log" file'.format(expected_log))

        with SSH() as ssh:
            severity_basis_value = ssh.execute("{} fix --list | grep '{}'".format(
                get_nessus_cli(), setting_details.get('name')))[0].split(":")[1].strip()

        assert severity_basis_value == setting_details.get('value'), "Default value for severity_basis is incorrect."

    @pytest.mark.xray(test_key='NES-18253')
    @pytest.mark.parametrize('setting_details', [{'name': 'severity_basis', 'value': 'cvss_v4'}])
    def test_verify_default_severity_basis_value_change_to_cvssv4(self, setting_details):
        """
        NES-18253 :  [E2E][CLI] Verify advanced setting 'severity_basis' value to cvss_v4

        Scenario Tested:
            [x] severity base value is set via command line.
        """
        with SSH() as ssh:
            output = ssh.execute("{} fix --set '{}'={}".format(
                get_nessus_cli(), setting_details.get('name'), setting_details.get('value')))

            assert "Successfully set 'severity_basis' to 'cvss_v4'." in output

            severity_basis_value = ssh.execute("{} fix --list | grep '{}'".format(
                get_nessus_cli(), setting_details.get('name')))[0].split(":")[1].strip()

        assert severity_basis_value == setting_details.get(
            'value'), "Severity basis not set to cvss_v4 after command line."

