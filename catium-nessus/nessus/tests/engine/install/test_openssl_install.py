"""
Test cases pertaining to the Nessus install and OpenSSL
:copyright: Tenable Network Security, 2023
:last_modified: October 30, 2023
:author: @stellex
"""
import fileinput
import sys
from os import fdopen, remove
from shutil import copymode, move
from tempfile import mkstemp

import pytest

from catium.lib.const import TIME_FIVE_MINUTES
from catium.lib.ssh import SSH
from nessus.lib.const.constants import OperatingSystems

from nessus.helpers.nessuscli.helper import get_command, path_join, get_nessus_lib_dir, get_nessus_bin_dir, \
    get_os_name, get_nessus_conf_dir


@pytest.mark.nessus_engine
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
class TestOpenSSLInstall:
    """
    Tests related to Nessus install and OpenSSL
    """

    # Setup test variables
    cat = None

    BIN_DIRECTORY = get_nessus_bin_dir()

    @pytest.mark.parametrize('add_test_file', [{'file_path': '/tmp/', 'file_name': ['openssl.cnf', 'libwrite_file.so']}], indirect=True)
    def test_attempt_custom_openssl_cnf(self, add_test_file):
        """
        Test verifies a custom OpenSSL cannot be used to execute a library during Nessus install. Test will first
        validate that using openssl.cnf to execute a .so file still works, then attempts to do that via the Nessus
        install. The attempt during the Nessus install should not work, while the initial attempt using just the OpenSSL
        binary should to verify this test case is still setup correctly.
        """

        # Getting commands and Nessus directories
        move_files = get_command("move_file")
        remove_file = get_command("remove_file")
        create_directory = get_command("create_directory")
        bin_directory = get_nessus_bin_dir()
        lib_directory = get_nessus_lib_dir()

        # Setup files to trigger execution via OpenSSL. Sudo is explicitly NOT used as that is the vulnerability.
        with SSH() as ssh:
            # Gathering information and setting up
            ssh.execute(command=f"{remove_file} /tmp/test_file.txt")
            check_installed_os = ssh.execute(command='cat /etc/os-release')
            installed_os = check_installed_os[0].split('=')[1].split()[0].strip('"')
            ssh.execute(command="chmod 777 /tmp/")

            # Getting OpenSSL install directory from Nessus
            openssl_install_directory = ssh.execute(f"{bin_directory}/openssl version -d")[0].replace("OPENSSLDIR:", "").replace(" ", "").replace('"', '')

            # Creating directory for us to dump our custom files in to try to get them to execute & inputting directory into openssl.cnf
            ssh.execute(command=create_directory.format(openssl_install_directory), sudo=False)
            sed_output = ssh.execute(command=f"sed -i 's~module = /<nessus_openssl_install_directory>/libwrite_file.so~module = {openssl_install_directory}/libwrite_file.so~' /tmp/openssl.cnf", sudo=True)

            for file in add_test_file:
                ssh.execute(command=f"{move_files} {file} {openssl_install_directory}", sudo=False)

            # Running OpenSSL against custom openssl.cnf to verify it will indeed create a file from the .so
            ssh.execute(command=f"{bin_directory}/openssl fipsinstall -out ~/fipsmodule.conf -module {lib_directory}/fips.so", sudo=False)
            test_file_exists = ssh.execute(command=f"find /tmp/test_file.txt")

            assert test_file_exists[0] == "/tmp/test_file.txt", "Test file was not successfully created, please " \
                                                                "re-evaluate the setup for this test case"

            ssh.execute(command=f"{remove_file} /tmp/test_file.txt")

            # Gathering Nessus install package data
            nessus_package_type = 'deb' if installed_os in ['Ubuntu', 'Debian'] else 'rpm'

            find_nessus_package = ssh.execute(command='find / -name "Nessus-*.{}"'.format(nessus_package_type))

            install_command = f"rpm -ivh --force {find_nessus_package[0]}" if nessus_package_type == "rpm" else f"dpkg -i {find_nessus_package[0]}"

            install_nessus_output = ssh.execute(command=install_command,
                                                timeout=TIME_FIVE_MINUTES)

            # Validating Nessus install did NOT create the file from the custom .so
            test_file_exists = ssh.execute(command=f"find /tmp/test_file.txt")

            assert test_file_exists[0] != "/tmp/test_file.txt", "Test file was successfully created and should not have been"
