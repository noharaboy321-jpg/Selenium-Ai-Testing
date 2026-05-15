"""
Tests to verify FIPS settings
:copyright: Tenable Network Security, 2023
:created: January 19, 2023
:last_modified: January 19, 2023
:author: @stellex
"""
import re

import pytest
from catium.lib.const import TIME_FIVE_MINUTES, TIME_FIVE_SECONDS
from catium.lib.ssh import SSH

from nessus.helpers.waiters import wait_for_scanner_status

from nessus.helpers.nessuscli.fix import set, get
from nessus.helpers.nessuscli.helper import get_nessus_conf_dir, stop_nessus, start_nessus, get_command, \
    get_nessus_log_dir, path_join, get_os_name
from nessus.lib.const import API, OperatingSystems


@pytest.mark.nessus_engine
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
class TestMaxHostsSetting:
    """
    Tests for global.max_hosts setting
    """

    # Setup test variables
    cat = None
    conf_directory = get_nessus_conf_dir()
    log_dir = get_nessus_log_dir() if get_os_name() != OperatingSystems.WINDOWS else get_nessus_log_dir() + "\\"

    @pytest.mark.parametrize('delete_files', [{'file_pattern_to_delete': [log_dir + 'nessusd.messages'],
                                               'restart_nessus': True}], indirect=True)
    @pytest.mark.xray(test_key='SCE-3434')
    def test_global_max_hosts(self, nessus_api_login, delete_files):
        """
        Test verifies value of global.max_hosts in settings matches what is being reported in nessusd.messages
        """

        os_windows = True if get_os_name() == OperatingSystems.WINDOWS else False
        os_freebsd = True if get_os_name() == OperatingSystems.FREEBSD else False

        sudo = False if get_os_name() in [OperatingSystems.WINDOWS, OperatingSystems.FREEBSD] else True
        get_output = get("global.max_hosts", sudo=sudo)
        current_max_hosts_setting = get_output["stdout"].replace("The current value for 'global.max_hosts' is '", "").replace("'.", "")

        log_dir = get_nessus_log_dir()
        file = path_join([log_dir, 'nessusd.messages']) if not os_windows else path_join([log_dir, 'nessusd.messages'])\
            .replace("\\", "\\\\")
        display_content = get_command(operation='display_content')
        with SSH() as ssh:
            messages_file = ssh.execute(f"{display_content} {file}", sudo=sudo)

        setting_line = None
        system_line = None
        for line in messages_file:
            if 'Setting Scanner: ' in line:
                setting_line = line
            if re.match(r".*System has [\d()]+ cores? and [\d()]+MB of RAM", line):
                system_line = line
        if setting_line is None:
            pytest.fail(f"Settings line was not found in nessusd.messages: {messages_file}")
        if system_line is None:
            pytest.fail(f"System line was not found in nessusd.messages: {messages_file}")

        assert f"global.max_hosts={current_max_hosts_setting}" in setting_line, \
            f"global.max_hosts={current_max_hosts_setting} was not found in {setting_line}"

        core = re.search(r"[\d()]+ core", system_line).group(0).replace(" core", "")
        ram = re.search(r"[\d()]+MB of RAM", system_line).group(0).replace("MB of RAM", "")

        # truncate division to get to nearest multiple of 5
        old_default_max_hosts = int(core) * (int(ram) // 30) // 5 * 5

        stop_nessus()
        delete_file = get_command(operation='remove_file')
        with SSH() as ssh:
            delete_file_output = ssh.execute(f"{delete_file} {file}", sudo=sudo)
        set_output = set("global.max_hosts", old_default_max_hosts, sudo=sudo)
        start_nessus()

        wait_for_scanner_status(api=nessus_api_login, status=API.Status.LOADING, timeout=TIME_FIVE_MINUTES,
                                msg='Availability of Nessus scanner', sleep_interval=TIME_FIVE_SECONDS)
        wait_for_scanner_status(api=nessus_api_login, status=API.Status.READY, timeout=TIME_FIVE_MINUTES,
                                msg='Availability of Nessus scanner', sleep_interval=TIME_FIVE_SECONDS)

        with SSH() as ssh:
            messages_file = ssh.execute(f"{display_content} {file}", sudo=sudo)
        setting_line = None
        override_line_found = False
        for line in messages_file:
            if 'Setting Scanner: ' in line:
                setting_line = line
            if f"Overriding legacy default global.max_hosts value ({old_default_max_hosts}) with new default" in line:
                override_line_found = True
        assert override_line_found, f"Override line not found in nessusd.messages: {messages_file}"
        if setting_line is None:
            pytest.fail(f"Settings line was not found in nessusd.messages: {messages_file}")

        get_output = get("global.max_hosts", sudo=sudo)
        current_max_hosts_setting = get_output["stdout"].replace("The current value for 'global.max_hosts' is '", "").replace("'.", "")

        assert current_max_hosts_setting != str(old_default_max_hosts), f"Current global.max_hosts setting is equal " \
                                                                        f"old default of {old_default_max_hosts}"

        assert f"global.max_hosts={current_max_hosts_setting}" in setting_line, \
            f"global.max_hosts={current_max_hosts_setting} was not found in {setting_line}"
