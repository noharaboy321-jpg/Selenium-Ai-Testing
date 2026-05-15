"""
Test cases to verify Nessus features/directories/settings when Nessus is fresh installed

:copyright: Tenable Network Security, 2021
:date: Feb 25, 2021
:last_modified: Feb 28, 2022
:author: @vsoni, @kpanchal
"""
import pytest

from catium.lib.ssh import SSH
from nessus.helpers.nessuscli.helper import path_join, get_nessus_var_dir, get_command, get_nessus_backend_log, \
    get_nessus_com_dir
from nessus.lib.config.environment_variables import NESSUS_PLATFORM
from nessus.lib.const import NessusCli, OperatingSystems

sudo = True if NESSUS_PLATFORM in [OperatingSystems.MAC, OperatingSystems.MAC_OS] else None


@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
class TestNessusFeaturesOnFreshInstall:
    """Tests to verify Nessus when it is fresh installed"""

    def test_verify_plugins_severity_db_file_on_fresh_installation(self):
        """
        NES-12674 : [CLI-Automation] Verify the plugins-severities.db is being created in the nessus state dir
                    after a new nessus installation.

        Scenario Tested:
            [x] Verify the plugins-severities.db is being created in the nessus state dir
                after a new nessus installation.
        """

        with SSH() as ssh:
            plugins_severity_db_file = path_join(path_dir_list=[get_nessus_var_dir(), 'plugins-severities.db'])

            assert ssh.path_is_file(remote_path=plugins_severity_db_file), \
                "plugins-severities.db is not present in Nessus var directory."

            file_size_op = ssh.execute(get_command("get_file_size").format(plugins_severity_db_file))[0]
            replaced_file_size = file_size_op.split()[4] if \
                NESSUS_PLATFORM in [OperatingSystems.MAC, OperatingSystems.MAC_OS] else file_size_op

            assert int(replaced_file_size) > 0, "plugins-severities.db is present but it is empty."

    def test_verify_certs_are_confirmed_logs_in_backend_log(self):
        """
        NES-12904: CLI-Automation for NES-12391 : Verification of cacert.pem and servercert.pem in debug report, logs

        Scenario Tested:
            [x] Verify that servercert is confirmed / does not match with cacert related logs populated in backend.log
        """
        get_read_file_content_command = get_command(operation="display_content")

        with SSH() as ssh:
            nessusd_backend_file_content = ssh.execute("{} {}".format(
                get_read_file_content_command, get_nessus_backend_log()), sudo=sudo)

        nessus_com_dir = get_nessus_com_dir()

        # Verify that servercert is confirmed / does not match with cacert related logs populated in backend.log
        assert [file_line for file_line in nessusd_backend_file_content if
                NessusCli.ServerCertAndCaCert.CERT_CONFIRMED.format(nessus_com_dir, nessus_com_dir) in file_line or
                NessusCli.ServerCertAndCaCert.CERT_NOT_MATCH.format(nessus_com_dir, nessus_com_dir) in file_line], \
            "servercert is confirmed / does not match with cacert related logs does not populated in backend.log"
