"""
    Fixtures for Nessus Settings
    :copyright: Tenable Network Security, 2022
    :date: September 6, 2022
    :author: @stellex
"""
import os
from typing import TYPE_CHECKING

import pytest
from catium.lib.const import TIME_FIVE_SECONDS, TIME_FIVE_MINUTES

from catium.lib.log import create_logger
from catium.lib.ssh import SSH

from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.nessusd_rules import update_nessusd_rules_file, replace_nessusd_rules_file

from nessus.helpers.waiters import wait_for_scanner_status

from nessus.helpers.nessuscli.fix import set, delete

from nessus.helpers.nessuscli.helper import get_command, set_nessus_env_variables, stop_nessus, start_nessus, \
    get_nessus_var_dir, path_join, get_os_name
from nessus.lib.const import API, OperatingSystems

if TYPE_CHECKING:
    from catium.lib.typechecking import SubRequest

log = create_logger()


@pytest.fixture()
def configure_advanced_settings_and_env_variables(request: 'SubRequest', nessus_api_handler: NessusAPI,
                                                  test_data_file: dict):
    """
    ends CLI commands to set advanced settings for Nessus and/or Nessus environment variables. Packaged together
    so the test will only need one restart to activate all settings/variables instead of two.
    """

    restart = test_data_file['restart'] if 'restart' in test_data_file.keys() else True
    cleanup_settings = test_data_file['cleanup_settings'] if 'cleanup_settings' in test_data_file.keys() else False

    if restart:
        stop_nessus()
    settings_output = []
    env_vars_output = []

    sudo = False if get_os_name() in [OperatingSystems.WINDOWS, OperatingSystems.FREEBSD] else True

    if 'settings' in test_data_file.keys():
        settings_dict = test_data_file['settings']
        for setting in settings_dict.keys():
            if settings_dict[setting] is not None:
                output = set(setting, settings_dict[setting], sudo=sudo)
                settings_output.append(output)
            else:
                output = delete(setting, sudo=sudo)
                settings_output.append(output)

    if 'environment_variables' in test_data_file.keys():
        if test_data_file['environment_variables'] is not None:
            env_vars_output = set_nessus_env_variables(environment_variables=test_data_file['environment_variables'],
                                                       restart=False)

    var_directory = get_nessus_var_dir()
    remove_file = get_command('remove_file')
    with SSH() as ssh:
        ssh.execute('{} {}'.format(remove_file, path_join(path_dir_list=[var_directory, 'nessusd.restart'])), sudo=sudo)

    if restart:
        start_nessus()

        wait_for_scanner_status(api=nessus_api_handler, status=API.Status.LOADING, timeout=TIME_FIVE_MINUTES,
                                msg='Availability of Nessus scanner', sleep_interval=TIME_FIVE_SECONDS)
        wait_for_scanner_status(api=nessus_api_handler, status=API.Status.READY, timeout=TIME_FIVE_MINUTES,
                                msg='Availability of Nessus scanner', sleep_interval=TIME_FIVE_SECONDS)

        nessus_api_handler.login()

    yield settings_output, env_vars_output

    if cleanup_settings:
        if restart:
            stop_nessus()
        settings_output = []

        if 'settings' in test_data_file.keys():
            settings_dict = test_data_file['settings']
            for setting in settings_dict.keys():
                output = delete(setting, sudo=sudo)
                settings_output.append(output)

        if restart:
            start_nessus()

            wait_for_scanner_status(api=nessus_api_handler, status=API.Status.LOADING, timeout=TIME_FIVE_MINUTES,
                                    msg='Availability of Nessus scanner', sleep_interval=TIME_FIVE_SECONDS)
            wait_for_scanner_status(api=nessus_api_handler, status=API.Status.READY, timeout=TIME_FIVE_MINUTES,
                                    msg='Availability of Nessus scanner', sleep_interval=TIME_FIVE_SECONDS)

            nessus_api_handler.login()


@pytest.fixture()
def set_nessus_rules(request: 'SubRequest', nessus_api_handler: NessusAPI, test_data_file: dict):
    rules = test_data_file['rules']
    append_to_existing = test_data_file['append_rules'] if 'append_rules' in test_data_file.keys() else False
    cleanup_rules = test_data_file['cleanup_rules'] if 'cleanup_rules' in test_data_file.keys() else False

    if rules is not None:
        stop_nessus()

        if not append_to_existing:
            replace_nessusd_rules_file(None)

        for rule in rules:
            update_nessusd_rules_file(rule)

        start_nessus()

        wait_for_scanner_status(api=nessus_api_handler, status=API.Status.LOADING, timeout=TIME_FIVE_MINUTES,
                                msg='Availability of Nessus scanner', sleep_interval=TIME_FIVE_SECONDS)
        wait_for_scanner_status(api=nessus_api_handler, status=API.Status.READY, timeout=TIME_FIVE_MINUTES,
                                msg='Availability of Nessus scanner', sleep_interval=TIME_FIVE_SECONDS)

        nessus_api_handler.login()

        yield

        if cleanup_rules:
            stop_nessus()

            replace_nessusd_rules_file(None)

            start_nessus()

            wait_for_scanner_status(api=nessus_api_handler, status=API.Status.LOADING, timeout=TIME_FIVE_MINUTES,
                                    msg='Availability of Nessus scanner', sleep_interval=TIME_FIVE_SECONDS)
            wait_for_scanner_status(api=nessus_api_handler, status=API.Status.READY, timeout=TIME_FIVE_MINUTES,
                                    msg='Availability of Nessus scanner', sleep_interval=TIME_FIVE_SECONDS)

            nessus_api_handler.login()
    else:
        yield
