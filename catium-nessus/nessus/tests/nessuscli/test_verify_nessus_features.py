"""
Test cases to verify  features of Nessus.

:copyright: Tenable Network Security, 2021
:date: Sep 15, 2021
:last_modified: Sep 27, 2021
:author: @vsoni.ctr
"""
import os
import re

import pytest

from catium.lib.log.log import create_logger
from catium.lib.ssh import SSH
from nessus.helpers.nessuscli.helper import get_command, get_nessus_var_dir
from nessus.lib.config.environment_variables import NESSUS_PLATFORM
from nessus.lib.const import NessusCli
from nessus.lib.const import OperatingSystems

log = create_logger()
META_INF_FILE_PATH = "META-INF"
ORG_FILE_PATH = "org"
MANIFEST_MF_FILE_PATH = "META-INF/MANIFEST.MF"
FOP_JAR_FILE = "report-engine/fop.jar"


@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
class TestFopJarFileExtraction:
    """ Tests related to FOP.jar file extraction in Nessus. """

    @staticmethod
    def remove_extracted_files_from_fop_jar():
        """
        This function removes extracted files from fop.jar file located at /opt/nessus/var/nessus/report-engine/
        """
        with SSH() as ssh:
            [ssh.execute("{} {}".format(get_command("remove_file"), file)) for file in
             [META_INF_FILE_PATH, ORG_FILE_PATH]]

    def test_verify_fop_jar_file_is_present_after_plugin_update(self):
        """
        NES-13466 : Verify the MANIFEST.MF file contains 'common-io-2.8.0.jar' after extracting fop.jar file

        Scenario Tested:
            [x] Verify that 'fop.jar' is present after plugin update in nessus
        """
        fop_jar_file_path = os.path.join(get_nessus_var_dir(), FOP_JAR_FILE)

        with SSH() as ssh:
            file_size_op = ssh.execute(get_command("get_file_size").format(fop_jar_file_path))[0]
            replaced_file_size = file_size_op.split()[4] if \
                NESSUS_PLATFORM in [OperatingSystems.MAC, OperatingSystems.MAC_OS] else file_size_op

            assert ssh.path_exist(remote_path=fop_jar_file_path) and int(replaced_file_size) > 0, \
                "{} file is not present or empty".format(fop_jar_file_path)

    @pytest.mark.xray(test_key='NES-15571')
    @pytest.mark.skip_ubuntu
    @pytest.mark.skip_centos7
    def test_verify_manifest_mf_file_after_extracting_fop_jar_file(self):
        """
        NES-13466 : Verify the MANIFEST.MF file contains 'common-io-2.8.0.jar' after extracting fop.jar file
        NES-15571 : Verify the version of FOP should be 2.6

        Scenario Tested:
            [x] Verify that after extracting FOP.jar file, the newly generated MANIFEST.MF file contains
                'common-io-2.8.0.jar'.
            [x] Verify last updated time for MANIFEST-MF files is 15th June, 2021.
            [x] Verify that fop.jar file version should be '2.6'.
        """
        fop_jar_file_path = os.path.join(get_nessus_var_dir(), FOP_JAR_FILE)

        with SSH() as ssh:
            if NESSUS_PLATFORM not in [OperatingSystems.MAC, OperatingSystems.MAC_OS]:
                check_installed_os = ssh.execute(command='cat /etc/os-release')
                installed_os = check_installed_os[0].split('=')[1].split()[0].strip('"')
                log.debug("Installed OS :: {}".format(installed_os))

                if installed_os == "Kali":
                    pytest.xfail("file is getting present sometimes and sometimes not. Hence, skipped for "
                                     "'Kali' OS only to avoid the flakiness of plan.")

            try:
                self.remove_extracted_files_from_fop_jar()
                ssh.execute("{} {}".format("unzip", fop_jar_file_path))

                file_size_op = ssh.execute(get_command("get_file_size").format(fop_jar_file_path))[0]
                replaced_file_size = file_size_op.split()[1] if \
                    NESSUS_PLATFORM in [OperatingSystems.MAC, OperatingSystems.MAC_OS] else file_size_op

                assert ssh.path_exist(remote_path=META_INF_FILE_PATH) and int(replaced_file_size) > 0, \
                    "{} file is not present or empty".format(META_INF_FILE_PATH)

                manifest_mf_file_contents = list(filter(None, ssh.execute("{} {}".format(
                    get_command("display_content"), MANIFEST_MF_FILE_PATH))))

                expected_jar_files = ['batik-all', 'commons-io', 'commons-logging', 'xercesImpl', 'xml-apis',
                                      'xml-apis-ext', 'xmlgraphics-commons']

                for jar_file in expected_jar_files:
                    content_string = "".join([out.strip() for out in manifest_mf_file_contents])
                    search_pattern = r'{}-(.*).jar'.format(jar_file)

                    assert re.search(search_pattern, content_string).group(), \
                        "'{}' is not present in MANIFEST.MF file.".format(jar_file)

                fop_jar_file_info = {}

                for content in manifest_mf_file_contents:
                    if ":" in content:
                        split_content = content.split(":")
                        fop_jar_file_info[split_content[0].strip()] = split_content[1].strip()

                assert ['Implementation-Version' in fop_jar_file_info], \
                    "Implementation-Version is not in fop jar file info."
            finally:
                self.remove_extracted_files_from_fop_jar()
