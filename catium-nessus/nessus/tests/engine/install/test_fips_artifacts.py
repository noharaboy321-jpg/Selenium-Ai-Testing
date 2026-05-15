"""
FIPS artifact locations
Test cases to verify FIPS files are installed in the correct locations
:copyright: Tenable Network Security, 2022
:last_modified: September 22, 2022
:author: @stellex
"""

import pytest
from catium.lib.ssh import SSH
from nessus.lib.const.constants import OperatingSystems

from nessus.helpers.nessuscli.helper import get_command, path_join, get_nessus_lib_dir, get_nessus_bin_dir, \
    get_os_name, get_nessus_conf_dir

@pytest.mark.nessus_engine
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
class TestFipsArtifactLocations:
    """
    Tests for FIPS artifact locations on install
    """

    # Setup test variables
    cat = None

    @pytest.mark.xray(test_key='SCE-3311')
    def test_fips_artifacts(self):
        """
        Verifies FIPS-specific files are installed in the correct location
        """

        # Prepare files to verify
        file_list = []
        os_name = get_os_name()
        lib_directory = get_nessus_lib_dir()
        bin_directory = get_nessus_bin_dir()
        file_list.append({'file_name': 'openssl', 'file_directory': bin_directory})

        if os_name == OperatingSystems.WINDOWS:
            file_extension = 'dll'
        elif os_name in [OperatingSystems.FREEBSD, OperatingSystems.LINUX]:
            file_extension = 'so'
        else:
            file_extension = 'dylib'

        fips_legacy_dir = lib_directory if os_name != OperatingSystems.WINDOWS else bin_directory
        conf_dir = get_nessus_conf_dir()
        file_list.append({'file_name': f"fips.{file_extension}", 'file_directory': fips_legacy_dir})
        file_list.append({'file_name': f"legacy.{file_extension}", 'file_directory': fips_legacy_dir})
        file_list.append({'file_name': f"fipsmodule.cnf", 'file_directory': conf_dir})

        display_content = get_command(operation='display_content')
        with SSH() as ssh:
            for file in file_list:
                if os_name == OperatingSystems.WINDOWS:
                    file_path = path_join([file['file_directory'], file['file_name']]).replace("\\", "\\\\").replace(" ", "\\ ")
                else:
                    file_path = path_join([file['file_directory'], file['file_name']])
                file_content = ssh.execute(f"{display_content} {file_path}")

                if len(file_content) != 0:
                    assert "No such file or directory" not in file_content[0], f"{file['file_name']} not found in " \
                                                                               f"{file['file_directory']}"
