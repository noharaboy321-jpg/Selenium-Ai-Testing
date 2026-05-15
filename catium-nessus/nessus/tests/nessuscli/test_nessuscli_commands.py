"""
Test cases to verify nessuscli commands

:copyright: Tenable Network Security, 2020
:date: Sep 17, 2019
:last_modified: Dec 20, 2021
:author: @vsoni, @kpanchal, @krpatel
"""
import os
import re
import time
from contextlib import contextmanager

import pytest

from catium.helpers.sleep_lib import sleep
from catium.lib.const import TIME_FIVE_SECONDS
from catium.lib.log.log import create_logger
from catium.lib.ssh.ssh import SSH
from nessus.helpers.nessuscli.helper import get_nessus_cli, path_join, get_nessus_var_dir, get_command, stop_nessus, \
    start_nessus, is_nessus_running, get_nessus_com_dir
from nessus.lib.config.environment_variables import NESSUS_PLATFORM
from nessus.lib.const.constants import NessusCli
from nessus.lib.const.constants import OperatingSystems

log = create_logger()
sudo = True if NESSUS_PLATFORM == OperatingSystems.MAC_OS else None

NESSUSD_DB = '/Library/Nessus/run/etc/nessus/nessusd.db' if NESSUS_PLATFORM == OperatingSystems.MAC_OS else \
    '/opt/nessus/etc/nessus/nessusd.db'
NESSUSD_CONF = '/Library/Nessus/run/etc/nessus/nessusd.conf.imported' if NESSUS_PLATFORM == OperatingSystems.MAC_OS \
    else '/opt/nessus/etc/nessus/nessusd.conf.imported'
NESSUSD_RULES = '/Library/Nessus/run/etc/nessus/nessusd.rules' if NESSUS_PLATFORM == OperatingSystems.MAC_OS \
    else '/opt/nessus/etc/nessus/nessusd.rules'
NESSUSD_FETCH = '/Library/Nessus/run/etc/nessus/nessus-fetch.db' if NESSUS_PLATFORM == OperatingSystems.MAC_OS \
    else '/opt/nessus/etc/nessus/nessus-fetch.db'
CA_CERT = '/Library/Nessus/run/com/nessus/CA/cacert.pem' if NESSUS_PLATFORM == OperatingSystems.MAC_OS else \
    '/opt/nessus/com/nessus/CA/cacert.pem'
SERVER_CERT = '/Library/Nessus/run/com/nessus/CA/servercert.pem' if NESSUS_PLATFORM == OperatingSystems.MAC_OS else \
    '/opt/nessus/com/nessus/CA/servercert.pem'

log = create_logger()

BACKUP_FILES_LIST = [path_join(path_dir_list=[get_nessus_var_dir(), "nessus_org.pem"]),
                     path_join(path_dir_list=[get_nessus_var_dir(), "users/admin/auth/hash"]),
                     path_join(path_dir_list=[get_nessus_var_dir(), "users/admin/auth/admin"]),
                     path_join(path_dir_list=[get_nessus_var_dir(), "users/admin/auth/rules"]),
                     path_join(path_dir_list=[get_nessus_var_dir(), "uuid"]),
                     path_join(path_dir_list=[get_nessus_var_dir(), "master.key"]),
                     path_join(path_dir_list=[get_nessus_var_dir(), "log.json"]),
                     path_join(path_dir_list=[get_nessus_var_dir(), "migrate.db"]),
                     NESSUSD_DB, NESSUSD_RULES, NESSUSD_FETCH, CA_CERT, SERVER_CERT,
                     path_join(path_dir_list=[get_nessus_var_dir(), "CA/cakey.pem"]),
                     path_join(path_dir_list=[get_nessus_var_dir(), "CA/serverkey.pem"]),
                     path_join(path_dir_list=[get_nessus_var_dir(), "global.db"])]

@pytest.mark.nessus_mat
@pytest.mark.nessus_cli
@pytest.mark.nessus_smoke
class TestNessuscliHelpCommand:
    """Test cases related to 'Nessuscli --help' command"""

    @pytest.mark.parametrize('license_type', [
        pytest.param("Nessus Professional", marks=(pytest.mark.nessus_pro, pytest.mark.nessus_pro)),
        pytest.param("Nessus Essential", marks=(pytest.mark.nessus_home, pytest.mark.nessus_home))])
    @pytest.mark.parametrize("help_cmd_list", [['bug-report-generator', 'user', 'update', 'backup', 'mkcert', 'fix',
                                                'dump', 'fetch']])
    def test_nessus_help_command(self, help_cmd_list, license_type):
        """
        NES-11995: Test the nessuscli 'help' Command
        Scenario Tested:
            [x] Verify that 'nessuscli --help' command output shows all required command options in detail.
        """
        with SSH() as ssh:
            help_command_output = ssh.execute(command="{} --help".format(get_nessus_cli()), sudo=sudo)
            log.debug("Help command output is : {}".format(help_command_output))
            command_headers = NessusCli.NessuscliHelp.CMD_HEADERS_LIST_WO

            # Verify that all command headers are present in 'nessuscli -help' command output
            assert set(command_headers).issubset(set(help_command_output)), \
                "One or more command headers are missing in help command output."

            # Verify that all commands are properly listed in help command output
            for cmd_keyword in help_cmd_list:
                assert NessusCli.NessuscliHelp.HELP_CMD_VALIDATIONS[cmd_keyword] == [
                    command for command in help_command_output if cmd_keyword in command], \
                    "{} related commands are not properly documented in help command output.".format(cmd_keyword)

    @pytest.mark.parametrize('license_type', [
        pytest.param("Nessus Manager", marks=(pytest.mark.nessus_manager, pytest.mark.nessus_manager))])
    @pytest.mark.parametrize("help_cmd_list", [['bug-report-generator', 'user', 'update', 'backup', 'mkcert', 'fix',
                                                'manager', 'dump', 'fetch']])
    def test_nessus_help_command_manager(self, help_cmd_list, license_type):
        """
        NES-11995: Test the nessuscli 'help' Command
        Scenario Tested:
            [x] Verify that 'nessuscli --help' command output shows all required command options in detail.
        """
        with SSH() as ssh:
            help_command_output = ssh.execute(command="{} --help".format(get_nessus_cli()), sudo=sudo)
            log.debug("Help command output is : {}".format(help_command_output))
            command_headers = NessusCli.NessuscliHelp.CMD_HEADERS_LIST

            # Verify that all command headers are present in 'nessuscli -help' command output
            assert set(command_headers).issubset(set(help_command_output)), \
                "One or more command headers are missing in help command output."
            # Verify that all commands are properly listed in help command output
            for cmd_keyword in help_cmd_list:
                assert NessusCli.NessuscliHelp.HELP_CMD_VALIDATIONS[cmd_keyword] == [
                    command for command in help_command_output if cmd_keyword in command], \
                    "{} related commands are not properly documented in help command output.".format(cmd_keyword)


@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
class TestNessusBackUpCommands:
    """Test cases related to 'Nessuscli --backup' command"""

    @pytest.mark.skip_nessustc
    def test_create_nessus_backup(self):
        """
        NES-12016: CLI Automation for nessuscli backup related commands

        Scenario Tested:
            [x] Verify that 'nessuscli backup --create' command output shows all necessary files generated successfully.
        """
        with SSH() as ssh:
            backup_output = ssh.execute("{} {} {}".format(get_nessus_cli(), NessusCli.BackupAndRestore.BACKUP_COMMAND,
                                          NessusCli.BackupAndRestore.BACKUP_FILE_NAME))

            log.info("{} output is : {}".format(NessusCli.BackupAndRestore.BACKUP_COMMAND, backup_output))

            sleep(sleep_time=TIME_FIVE_SECONDS, reason='waiting for backup to get created')

            all_files = ssh.execute("ls {}".format(get_nessus_var_dir()))

            backup_file = [file for file in all_files if "nessus_backup" in file][0]

            backup_tar_file = path_join(path_dir_list=[get_nessus_var_dir(),
                                                       backup_file])

            assert ssh.path_exist(backup_tar_file), "Backup tar file was not created successfully!"

            try:
                # Verify if all necessary files backed up properly in 'backup --create' command output.
                for file in BACKUP_FILES_LIST:
                    regex = r'.*adding {} as .*.data.*'.format(file)
                    assert [output_line for output_line in backup_output if re.search(regex, output_line)], \
                        "Backup for file {} has not been generated via 'backup --create' command.".format(file)
            finally:
                ssh.execute("{} {}".format(get_command("remove_file"), backup_file), sudo=sudo)

    @pytest.mark.skip_nessustc
    def test_restore_backup_files(self):
        """
        NES-12016: CLI Automation for nessuscli backup related commands

        Scenario Tested:
            [x] Verify that 'nessuscli backup --restore' command fails when nessus service is 'running'
            [x] Verify that 'nessuscli backup --restore' command output shows all necessary files restored successfully
                (While nessus service is stopped)
        """
        with SSH() as ssh:
            ssh.execute("{} {} {}".format(get_nessus_cli(), NessusCli.BackupAndRestore.BACKUP_COMMAND,
                                          NessusCli.BackupAndRestore.BACKUP_FILE_NAME))

            sleep(sleep_time=TIME_FIVE_SECONDS, reason='waiting for backup to get created')

            all_files = ssh.execute("ls {}".format(get_nessus_var_dir()))

            backup_file = [file for file in all_files if "nessus_backup" in file][0]

            backup_tar_file = path_join(path_dir_list=[get_nessus_var_dir(),
                                                       backup_file])

            assert ssh.path_exist(backup_tar_file), "Backup tar file was not created successfully!"

            try:
                # Verify 'backup --restore' command shows error when nessus service is running.
                assert NessusCli.BackupAndRestore.RESTORE_FAILURE in ssh.execute("{} {} {}".format(
                    get_nessus_cli(), NessusCli.BackupAndRestore.RESTORE_COMMAND, backup_tar_file)), \
                    "'backup --restore' command does not show failure message when nessus service is running!"

                stop_nessus()

                restore_backup_output = ssh.execute("{} {} {}".format(
                    get_nessus_cli(), NessusCli.BackupAndRestore.RESTORE_COMMAND, backup_tar_file))

                log.info("'{}' command output is : {}".format(NessusCli.BackupAndRestore.RESTORE_COMMAND,
                                                              restore_backup_output))

                assert NessusCli.BackupAndRestore.DB_VERSION_CHECK_PASSED in restore_backup_output, \
                    "'{}' message is not present in 'backup --restore' command execution's output".format(
                        NessusCli.BackupAndRestore.DB_VERSION_CHECK_PASSED)

                # Verify all necessary files restored properly using 'backup --restore' command.
                for file in BACKUP_FILES_LIST:
                    regex = r'Restoring {} succeeded.'.format(file)
                    assert [output_line for output_line in restore_backup_output if re.search(regex, output_line)], \
                        "'{}' file has not been restored properly via 'backup --restore' command.".format(file)
            finally:
                start_nessus()
                ssh.execute("{} {}".format(get_command("remove_file"), backup_tar_file))


@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
class TestNessusImportCertsCommands:
    """"Tests for 'import-certs' command"""

    @contextmanager
    def copy_cert_files_to_tmp_directory(self, servercert_file: str, cacert_file: str, server_key_file: str) -> None:
        """
        This helper copies all (servercert, cacert, serverkey) files to /tmp directory.
        :param str servercert_file: Path where servercert file needs to be copied.
        :param str cacert_file: Path where cacert file needs to be copied.
        :param str server_key_file: Path where server_key file needs to be copied.
        returns: None
        """
        with SSH() as ssh:
            ssh.execute("cp {} {}".format(os.path.join(get_nessus_com_dir(), NessusCli.ImportCerts.SERVER_CERT_PEM),
                                          servercert_file), sudo=sudo)
            ssh.execute("cp {} {}".format(os.path.join(get_nessus_var_dir(), NessusCli.ImportCerts.SERVER_KEY_PEM),
                                          server_key_file), sudo=sudo)
            ssh.execute("cp {} {}".format(os.path.join(get_nessus_com_dir(), NessusCli.ImportCerts.CA_CERT_PEM),
                                          cacert_file), sudo=sudo)
            yield
            ssh.execute("{} {}".format(get_command(operation="remove_file"), servercert_file), sudo=sudo)
            ssh.execute("{} {}".format(get_command(operation="remove_file"), cacert_file), sudo=sudo)
            ssh.execute("{} {}".format(get_command(operation="remove_file"), server_key_file), sudo=sudo)

    def test_import_certs_help_command(self):
        """
        NES-12908 : [Automation] Verify that "/opt/nessus/sbin/nessuscli import-certs" command works properly with
                    positive and negative scenarios

        Scenario Tested:
            [x] Verify that 'import-certs --help' command works properly.
        """
        with SSH() as ssh:
            output = ssh.execute("{} {}".format(get_nessus_cli(), NessusCli.ImportCerts.IMPORT_CERTS_HELP_COMMAND),
                                 sudo=sudo)

        # Verify that 'import-certs --help' command works properly.
        assert NessusCli.ImportCerts.IMPORT_CERTS_HELP.issubset([output.strip() for output in output]), \
            "'import-certs --help' command output is not properly displayed."

    @pytest.mark.parametrize('import_cert', ['serverkey', 'servercert', 'cacert', 'all'])
    def test_import_certs_with_confirmable_cert_files(self, import_cert):
        """
        NES-12908 : [Automation] Verify that "/opt/nessus/sbin/nessuscli import-certs" command works properly with
                    positive and negative scenarios

        Scenario Tested:
            [x] Verify that 'import-certs' command works properly when correct servercert.pem file is given.
            [x] Verify that 'import-certs' command works properly when correct cacert.pem file is given.
            [x] Verify that 'import-certs' command works properly when correct servercert.pem and cacert.pem files are
                given.
        """
        with self.copy_cert_files_to_tmp_directory(servercert_file=NessusCli.ImportCerts.CORRECT_SERVER_CERT_PEM,
                                                   cacert_file=NessusCli.ImportCerts.CORRECT_CA_CERT_PEM,
                                                   server_key_file=NessusCli.ImportCerts.CORRECT_SERVER_KEY_PEM):
            with SSH() as ssh:
                import_cert_command = "{} {}".format(get_nessus_cli(), NessusCli.ImportCerts.IMPORT_CERT_COMMAND)

                if import_cert in ["servercert", "all"]:
                    import_cert_command = import_cert_command + " --servercert={}".format(
                        NessusCli.ImportCerts.CORRECT_SERVER_CERT_PEM)
                if import_cert in ["serverkey", "all"]:
                    import_cert_command = import_cert_command + " --serverkey={}".format(
                        NessusCli.ImportCerts.CORRECT_SERVER_KEY_PEM)
                if import_cert in ["cacert", "all"]:
                    import_cert_command = import_cert_command + " --cacert={}".format(
                        NessusCli.ImportCerts.CORRECT_CA_CERT_PEM)

                current_epoc_time = int(time.time())
                sleep(1, reason="Waiting for one second for the import cert operation to be in sync with epoc seconds.")
                import_cert_command_output = ssh.execute(import_cert_command, sudo=sudo)
                [import_cert_command_output.remove(op) for op in import_cert_command_output if "cert" not in op]

                expected_output_for_successful_import_cert = NessusCli.ImportCerts. \
                    SUCCESSFUL_BOTH_CERTS if import_cert == "all" else NessusCli.ImportCerts.PROVIDE_NECESSARY_INPUTS

                # Verify that 'import-certs' command output is as expected.
                assert import_cert_command_output == expected_output_for_successful_import_cert, \
                    "Output for 'import-certs' command is not as expected."

                ca_dir_path = os.path.join(get_nessus_com_dir(), NessusCli.ImportCerts.CA_DIR_PATH)
                server_key_dir_path = os.path.join(get_nessus_var_dir(), NessusCli.ImportCerts.CA_DIR_PATH)
                list_of_files = ssh.execute("{} {}".format(get_command(operation='display_directory_content'),
                                                           ca_dir_path), sudo=sudo)

                # Verify that the servercert.pem and cacert.pem and serverkey.pem files are backed up
                # when 'import-certs' command executed.
                if import_cert == 'all':
                    assert any([cert_file for cert_file in list_of_files if 'servercert.pem' in cert_file and len(
                        cert_file.split('.')) == 3 and int(cert_file.split('.')[2]) > current_epoc_time]), \
                        "servercert.pem file has not been backed up at this directory {}".format(ca_dir_path)

                    assert any([cert_file for cert_file in list_of_files if 'cacert.pem' in cert_file and len(
                        cert_file.split('.')) == 3 and int(cert_file.split('.')[2]) > current_epoc_time]), \
                        "cacert.pem file has not been backed up at this directory {}".format(ca_dir_path)

                    assert any([cert_file for cert_file in ssh.execute("{} {}".format(get_command(
                        operation='display_directory_content'), server_key_dir_path), sudo=sudo) if
                                'serverkey.pem' in cert_file and len(cert_file.split('.')) == 3 and int(
                                    cert_file.split('.')[2]) > current_epoc_time]), \
                        "serverkey.pem file has not been backed up at this directory {}".format(ca_dir_path)

    @pytest.mark.parametrize('import_cert', ['servercert', 'cacert', 'serverkey', 'all'])
    def test_import_certs_with_non_confirmable_cert_files(self, import_cert):
        """
        NES-12908 : [Automation] Verify that "/opt/nessus/sbin/nessuscli import-certs" command works properly with
                    positive and negative scenarios

        Scenario Tested:
            [x] Verify that 'import-certs' command works properly when incorrect servercert.pem file is given.
            [x] Verify that 'import-certs' command works properly when incorrect cacert.pem file is given.
            [x] Verify that 'import-certs' command works properly when
                incorrect servercert.pem and cacert.pem files are given.
        """
        with self.copy_cert_files_to_tmp_directory(servercert_file=NessusCli.ImportCerts.INCORRECT_SERVER_CERT_PEM,
                                                   cacert_file=NessusCli.ImportCerts.INCORRECT_CA_CERT_PEM,
                                                   server_key_file=NessusCli.ImportCerts.INCORRECT_SERVER_KEY_PEM):
            with SSH() as ssh:
                if import_cert in ['servercert', 'all']:
                    ssh.write_to_file(remote_file_path=NessusCli.ImportCerts.INCORRECT_SERVER_CERT_PEM, text="abc")
                elif import_cert in ['cacert', 'all']:
                    ssh.write_to_file(remote_file_path=NessusCli.ImportCerts.INCORRECT_CA_CERT_PEM, text="abc")
                elif import_cert in ['serverkey', 'all']:
                    ssh.write_to_file(remote_file_path=NessusCli.ImportCerts.INCORRECT_SERVER_KEY_PEM, text="abc")

                import_cert_command = "{} {} --cacert={} --servercert={} --serverkey={}".format(
                    get_nessus_cli(), NessusCli.ImportCerts.IMPORT_CERT_COMMAND,
                    NessusCli.ImportCerts.INCORRECT_CA_CERT_PEM, NessusCli.ImportCerts.INCORRECT_SERVER_CERT_PEM,
                    NessusCli.ImportCerts.INCORRECT_SERVER_KEY_PEM)

                import_cert_output = ssh.execute(import_cert_command)

                assert NessusCli.ImportCerts.UNSUCCESSFUL_SERVER_CERT if import_cert != "serverkey" else \
                    NessusCli.ImportCerts.UNSUCCESSFUL_SERVER_KEY in import_cert_output, ""

    @pytest.mark.parametrize("import_cert", ['servercert', 'cacert', 'serverkey'])
    def test_import_certs_with_incorrect_pem_file_paths(self, import_cert):
        """
        NES-12908 : [Automation] Verify that "/opt/nessus/sbin/nessuscli import-certs" command works properly with
                    positive and negative scenarios

        Scenario Tested:
            [x] Verify that 'import-certs' command works properly when servercert.pem file's path is incorrect.
            [x] Verify that 'import-certs' command works properly when cacert.pem file's path is incorrect.
        """
        with self.copy_cert_files_to_tmp_directory(servercert_file=NessusCli.ImportCerts.CORRECT_SERVER_CERT_PEM,
                                                   cacert_file=NessusCli.ImportCerts.CORRECT_CA_CERT_PEM,
                                                   server_key_file=NessusCli.ImportCerts.CORRECT_SERVER_KEY_PEM):
            with SSH() as ssh:
                import_cert_command = "{} {}".format(get_nessus_cli(), NessusCli.ImportCerts.IMPORT_CERT_COMMAND)

                import_cert_command = import_cert_command + " --servercert={}".format(
                    NessusCli.ImportCerts.INCORRECT_CERT_PEM_FILE_PATH if import_cert == "servercert" else
                    NessusCli.ImportCerts.CORRECT_SERVER_CERT_PEM) + " --cacert={}".format(
                    NessusCli.ImportCerts.INCORRECT_CERT_PEM_FILE_PATH if import_cert == "cacert" else
                    NessusCli.ImportCerts.CORRECT_CA_CERT_PEM) + " --serverkey={}".format(
                    NessusCli.ImportCerts.INCORRECT_CERT_PEM_FILE_PATH if import_cert == "serverkey" else
                    NessusCli.ImportCerts.CORRECT_CA_CERT_PEM)

                import_cert_output = ssh.execute(command=import_cert_command)

                # Verify 'import-certs' command when servercert or cacert file paths are incorrect.
                assert NessusCli.ImportCerts.INCORRECT_PATH_ERROR[import_cert] in import_cert_output, \
                    "'import-certs' command output is not as expected when incorrect " \
                    "servercert or cacert or serverkey file paths are given."

    def test_import_certs_when_cert_file_paths_are_empty(self):
        """
        NES-12947 : Verify 'Import --certs' command works properly in Nessus.

        Scenario Tested:
            [x] Verify that 'import --certs' command gives proper output when
                file paths for servercert or cacert is not given.
        """
        with SSH() as ssh:
            import_cert_command = "{} {} --cacert= --servercert= --serverkey=".format(
                get_nessus_cli(), NessusCli.ImportCerts.IMPORT_CERT_COMMAND)

            import_cert_output = ssh.execute(command=import_cert_command)

            # Verify that 'import --certs' command gives proper output
            # when servercert / cacert / serverkey file paths are not given.
            assert any([NessusCli.ImportCerts.PROVIDE_NECESSARY_INPUTS[0] == op for op in import_cert_output if
                        "server certificate" in op]), \
                "'import --certs' command output is not as expected when file paths are missing."

    def test_verify_nessus_service_is_running_after_executing_import_certs_command(self):
        """
        NES-12947 : Verify 'Import --certs' command works properly in Nessus.

        Scenario Tested:
            [x] Verify that Nessus service remains in 'running' state after executing 'import --certs' command.
        """
        with self.copy_cert_files_to_tmp_directory(servercert_file=NessusCli.ImportCerts.CORRECT_SERVER_CERT_PEM,
                                                   cacert_file=NessusCli.ImportCerts.CORRECT_CA_CERT_PEM,
                                                   server_key_file=NessusCli.ImportCerts.CORRECT_SERVER_KEY_PEM):
            with SSH() as ssh:
                import_cert_command = "{} {} --cacert={} --servercert={} --serverkey={}".format(
                    get_nessus_cli(), NessusCli.ImportCerts.IMPORT_CERT_COMMAND,
                    NessusCli.ImportCerts.CORRECT_CA_CERT_PEM, NessusCli.ImportCerts.CORRECT_SERVER_CERT_PEM,
                    NessusCli.ImportCerts.CORRECT_SERVER_KEY_PEM)

                import_cert_output = ssh.execute(command=import_cert_command)
                [import_cert_output.remove(op) for op in import_cert_output if "cert" not in op]

                assert import_cert_output == NessusCli.ImportCerts.SUCCESSFUL_BOTH_CERTS, \
                    "'import-certs' command was not executed successfully."

                # Verify that Nessus service is running after executing 'import --certs" command.
                assert is_nessus_running(), "Nessus service is not running after executing 'import --certs' command."
