"""
Nessus CLI helper module

:copyright: Tenable Network Security, 2017
:date: March 24, 2020
:last_modified: April 18, 2023
:author: @jamreliya, @kpanchal, @krpatel
"""
import json
import os
from datetime import datetime

import requests
from waiting.exceptions import TimeoutExpired
from waiting import wait

from catium.helpers.site_configuration_fetcher import get_site_environ
from catium.helpers.sleep_lib import sleep
from catium.lib.activation_code_generator.activation_code_generator import ActivationCodeGenerator, ActivationCodes
from catium.lib.config.environment_variables import CommonConfig
from catium.lib.const.base_constants import TIME_TEN_SECONDS, TIME_TWENTY_SECONDS, \
    TIME_FIVE_MINUTES, TIME_TEN_MINUTES, TIME_THIRTY_MINUTES
from catium.lib.const.base_constants import TIME_THIRTY_SECONDS
from catium.lib.log.log import create_logger
from catium.lib.ssh.ssh import SSH
from catium.lib.webium.driver import get_driver_no_init
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.cli_command import execute
from nessus.helpers.waiters import wait_for_scanner_status
from nessus.lib.config import NessusConfig
from nessus.lib.config.environment_variables import NESSUS_PLATFORM, NESSUSCLI_EXE, NESSUSD_DUMP, NESSUSD_MESSAGES, \
    NESSUS_BACKEND_LOGS, NESSUS_SERVER_LOG, NESSUSD_EXE, NESSUS_DATA_DIR, NESSUS_PLUGIN_DIR, NESSUS_LOGS_DIR, \
    NESSUS_TEMPLATE_DIR, NESSUS_COM_DIR, NESSUS_SBIN_DIR, NESSUS_CONF_DIR, NESSUS_LIB_DIR, \
    NESSUS_BIN_DIR
from nessus.lib.const import Nessus
from nessus.lib.const.constants import NessusCli, API, NessusFilePath, OperatingSystems, SSHCommands, NessusInstallation

log = create_logger()

# TODO:
# create on-demand-manager, on-demand-pro entries to site-config
nessus = None
NESSUS_VERSION = get_site_environ('CAT_NESSUS_VERSION', 'NESSUS_VERSION')

if NESSUS_VERSION:
    if NESSUS_VERSION.lower() in ('nessus professional', 'professional', 'pro'):
        nessus = "professional"
    elif NESSUS_VERSION.lower() in ('nessus manager', 'manager'):
        nessus = "manager"
    elif NESSUS_VERSION.lower() in ('nessus home', 'home'):
        nessus = "home"


def get_system_datetime(datetime_format: str = NessusCli.LINUX_TIMESTAMP_DMYHMS) -> datetime:
    """
    Get current date and time as returned by `date` command from remote host
    :param str datetime_format: date format in which date should be
    :return: datetime object
    :rtype : datetime
    """
    os_name = get_os_name()
    datetime_command = 'powershell get-date -format' if os_name == OperatingSystems.WINDOWS else 'date'

    if os_name == OperatingSystems.LINUX or os_name == OperatingSystems.FREEBSD or os_name in \
            [OperatingSystems.MAC, OperatingSystems.MAC_OS]:
        command_args = '+' + datetime_format
    else:
        command_args = NessusCli.WINDOWS_TIMESTAMP_DMYHMS

    system_date_string = execute(command=datetime_command, args=[f'"{command_args}"'])
    log.debug("System date time output :: {}".format(system_date_string))
    system_date = datetime.strptime(system_date_string['stdout'].rstrip('\n'), datetime_format)
    log.debug('[%s] System datetime: %s', SSH().ssh_ip, str(system_date))

    return system_date


def register_nessus() -> None:
    """
    This will register nessus from CLI
    :return: None
    """

    assert nessus is not None, "NESSUS_VERSION was not set or was not understood"

    if nessus == "professional" or nessus == "manager":
        post_data = {'expiredays': 365, 'type': nessus, 'ips': 256}
    else:
        post_data = {'expiredays': 365, 'type': nessus, }

    response = requests.post(ActivationCodeGenerator.url, data=post_data, timeout=TIME_TEN_SECONDS)
    api = NessusAPI()
    activation_code = response.json()['code']
    nessus_cli = get_nessus_cli()
    with SSH() as ssh:
        ssh.execute(command=' {} fix --secure --set custom_host={}'
                    .format(nessus_cli, CommonConfig.CAT_PLUGIN_FEED_HOST))
        ssh.execute(command='{} fetch --register-only {}'.format(nessus_cli, activation_code))
        stop_nessus()
        ssh.execute(command='{} update --plugins-only'.format(nessus_cli))
        start_nessus()

    try:
        wait_for_scanner_status(api=api, status=API.Status.LOADING, timeout=TIME_FIVE_MINUTES,
                                msg='Nessus to get loading status.')
    except TimeoutExpired:
        log.warning("Nessus did not get 'loading' status after new registration")
    wait_for_scanner_status(api=api, status=API.Status.READY, timeout=TIME_TEN_MINUTES * 4,
                            msg='Nessus registration to complete.')


def register_nessus_license_type(license_type: str, code_generator_url: str = None) -> None:
    """
    This will register nessus professional from CLI

    :param str license_type: type of license i.e. home, manager, professional
    :param str code_generator_url: code generator URL to generate activation code
    :return: None
    """
    nessus_cli = get_nessus_cli()

    if license_type == ActivationCodeGenerator.NESSUS_MANAGER:
        post_data = {'expiredays': Nessus.DEFAULT_EXPIRATION_DAYS, 'type': license_type, 'ips': 256, 'scanners': 2,
                     'agents': 256, 'scannerMode': ActivationCodes.Nessus.Mode.Full}
    else:
        post_data = {'expiredays': Nessus.DEFAULT_EXPIRATION_DAYS, 'type': license_type}

    if license_type == ActivationCodeGenerator.NESSUS_PROFESSIONAL:
        post_data['scan-api-enabled'] = 1

    if code_generator_url is None:
        code_generator_url = ActivationCodeGenerator.url
        custom_host = CommonConfig.CAT_PLUGIN_FEED_HOST
    else:
        custom_host = code_generator_url.split("/")[2]

    response = requests.post(code_generator_url, data=post_data, timeout=TIME_TEN_SECONDS)

    with SSH() as ssh:
        ssh.execute(command=' {} fix --secure --set custom_host="{}"'.format(nessus_cli, custom_host))
        ssh.execute(command='{} fetch --register-only {}'.format(nessus_cli, response.json()['code']))
        ssh.execute(command='{} update --plugins-only'.format(nessus_cli))

    sleep(sleep_time=TIME_THIRTY_SECONDS, reason='for plugins download to begin.')
    wait_for_scanner_status(api=NessusAPI(), status=API.Status.READY, timeout=TIME_THIRTY_MINUTES,
                            msg='download and registration to complete. ')
    get_driver_no_init().refresh()


def expire_nessus() -> None:
    """
    This will register nessus from CLI with an expired license
    :return: None
    """
    post_data = {'expiredays': -1, 'type': nessus}
    response = requests.post(ActivationCodeGenerator.url, data=post_data, timeout=TIME_TEN_SECONDS)
    activation_code = response.json()['code']
    nessus_cli = get_nessus_cli()

    api = NessusAPI()
    with SSH() as ssh:
        ssh.execute(command='{} fix --secure --set custom_host={}'.format(
            nessus_cli, CommonConfig.CAT_PLUGIN_FEED_HOST))

        stop_nessus()
        ssh.execute(command='{} fetch --register-only {}'.format(nessus_cli, activation_code))
        start_nessus()

        try:
            wait_for_scanner_status(api=api, status=API.Status.LOADING, timeout=TIME_FIVE_MINUTES,
                                    msg='registration to complete.')
        except TimeoutExpired:
            log.warning("Nessus did not get 'loading' status after registration with expire day as '-1'")

        wait_for_scanner_status(api=api, status=API.Status.READY, timeout=TIME_TEN_MINUTES * 4,
                                msg='registration to complete.')

    sleep(sleep_time=TIME_TWENTY_SECONDS, reason='nessus to restart')


def get_nessus_cli():
    """This function will return nessus cli path for Nessus according to operating system."""
    os_name = get_os_name()

    if os_name == OperatingSystems.WINDOWS:
        return NessusFilePath.Windows.NESSUS_CLI
    elif os_name == OperatingSystems.FREEBSD:
        return NessusFilePath.FreeBSD.NESSUS_CLI
    elif os_name == OperatingSystems.LINUX:
        return NessusFilePath.Linux.NESSUS_CLI
    elif os_name == OperatingSystems.MAC_OS:
        return NessusFilePath.MacOS.NESSUS_CLI
    else:
        return NESSUSCLI_EXE


def get_nessusd_dump():
    """This function will return "nessusd.dump" path for Nessus according to operating system."""
    os_name = get_os_name()

    if os_name == OperatingSystems.WINDOWS:
        return NessusFilePath.Windows.NESSUSD_DUMP
    elif os_name == OperatingSystems.FREEBSD:
        return NessusFilePath.FreeBSD.NESSUSD_DUMP
    elif os_name == OperatingSystems.LINUX:
        return NessusFilePath.Linux.NESSUSD_DUMP
    else:
        return NESSUSD_DUMP


def get_nessusd_messages():
    """This function will return "nessusd.messages" path for Nessus according to operating system."""
    os_name = get_os_name()

    if os_name == OperatingSystems.WINDOWS:
        return NessusFilePath.Windows.NESSUSD_MESSAGES
    elif os_name == OperatingSystems.FREEBSD:
        return NessusFilePath.FreeBSD.NESSUSD_MESSAGES
    elif os_name == OperatingSystems.LINUX:
        return NessusFilePath.Linux.NESSUSD_MESSAGES
    else:
        return NESSUSD_MESSAGES


def get_nessus_backend_log():
    """This function will return "backend.log" path for Nessus according to operating system."""
    os_name = get_os_name()

    if os_name == OperatingSystems.WINDOWS:
        return NessusFilePath.Windows.NESSUS_BACKEND_LOGS
    elif os_name == OperatingSystems.FREEBSD:
        return NessusFilePath.FreeBSD.NESSUS_BACKEND_LOGS
    elif os_name == OperatingSystems.LINUX:
        return NessusFilePath.Linux.NESSUS_BACKEND_LOGS
    else:
        return NESSUS_BACKEND_LOGS


def get_nessus_www_sever():
    """This function will return "www_server.log" path for Nessus according to operating system."""
    os_name = get_os_name()

    if os_name == OperatingSystems.WINDOWS:
        return NessusFilePath.Windows.NESSUS_SERVER_LOG
    elif os_name == OperatingSystems.FREEBSD:
        return NessusFilePath.FreeBSD.NESSUS_SERVER_LOG
    elif os_name == OperatingSystems.LINUX:
        return NessusFilePath.Linux.NESSUS_SERVER_LOG
    else:
        return NESSUS_SERVER_LOG


def get_nessusd():
    """This function will return nessusd path for Nessus according to operating system."""
    os_name = get_os_name()

    if os_name == OperatingSystems.WINDOWS:
        return NessusFilePath.Windows.NESSUSD
    elif os_name == OperatingSystems.LINUX:
        return NessusFilePath.Linux.NESSUSD
    elif os_name == OperatingSystems.FREEBSD:
        return NessusFilePath.FreeBSD.NESSUSD
    else:
        return NESSUSD_EXE


def get_nessus_var_dir():
    """This function will return var directory path for Nessus according to operating system."""
    os_name = get_os_name()

    if os_name == OperatingSystems.WINDOWS:
        return NessusFilePath.Windows.NESSUS_VAR
    elif os_name == OperatingSystems.FREEBSD:
        return NessusFilePath.FreeBSD.NESSUS_VAR
    elif os_name == OperatingSystems.LINUX:
        return NessusFilePath.Linux.NESSUS_VAR
    else:
        return NESSUS_DATA_DIR


def get_nessus_sbin_dir():
    """This function will return sbin directory path for Nessus according to operating system."""
    os_name = get_os_name()

    if os_name == OperatingSystems.WINDOWS:
        return NessusFilePath.Windows.NESSUS_SBIN
    elif os_name == OperatingSystems.FREEBSD:
        return NessusFilePath.FreeBSD.NESSUS_SBIN
    elif os_name == OperatingSystems.LINUX:
        return NessusFilePath.Linux.NESSUS_SBIN
    else:
        return NESSUS_SBIN_DIR


def get_nessus_plugin_dir():
    """This function will return plugin directory path for Nessus according to operating system."""
    os_name = get_os_name()

    if os_name == OperatingSystems.WINDOWS:
        return NessusFilePath.Windows.NESSUS_PLUGIN_DIR
    elif os_name == OperatingSystems.FREEBSD:
        return NessusFilePath.FreeBSD.NESSUS_PLUGIN_DIR
    elif os_name == OperatingSystems.LINUX:
        return NessusFilePath.Linux.NESSUS_PLUGIN_DIR
    else:
        return NESSUS_PLUGIN_DIR


def get_nessus_template_dir():
    os_name = get_os_name()

    if os_name == OperatingSystems.WINDOWS:
        return NessusFilePath.Windows.NESSUS_TEMPLATE_DIR
    elif os_name == OperatingSystems.FREEBSD:
        return NessusFilePath.FreeBSD.NESSUS_TEMPLATE_DIR
    elif os_name == OperatingSystems.LINUX:
        return NessusFilePath.Linux.NESSUS_TEMPLATE_DIR
    else:
        return NESSUS_TEMPLATE_DIR


def get_command(operation: str) -> str:
    os_name = get_os_name()

    if os_name == OperatingSystems.WINDOWS:
        return SSHCommands.Windows.COMMAND[operation]
    elif os_name == OperatingSystems.MAC_OS:
        return SSHCommands.MacOS.COMMAND[operation]
    else:
        return SSHCommands.Linux.COMMAND[operation]


def path_join(path_dir_list: list) -> str:
    """
    This function will return directory path according after joining as per the operating system.
    :param path_dir_list: list of directory paths
    :return path : Final path after joining all path directories.
    :rtype: str
    """
    path = ''

    for path_part in path_dir_list:
        path = os.path.join(path, path_part)
    if NESSUS_PLATFORM == OperatingSystems.WINDOWS:
        return path.replace('/', '\\')
    elif NESSUS_PLATFORM == OperatingSystems.LINUX:
        return path.replace('\\', '/')
    else:
        return path


def get_os_name():
    """This function will return name of operating system of the machine where Nessus is installed."""

    return NESSUS_PLATFORM


def stop_nessus(url_or_ip=None, wait_for_stop: bool = False, api: NessusAPI = None, timeout: int = 15) -> None:
    """
    Stop Nessus service with optional waiting capabilities
    
    :param str url_or_ip: Target server URL or IP (optional)
    :param bool wait_for_stop: Wait for service to stop completely (default: False for backward compatibility)
    :param NessusAPI api: API instance for waiting operations (auto-created if needed)
    :param int timeout: Timeout for stop waiting in seconds (default: 15)
    :return: None
    """
    os_name = get_os_name()

    if os_name == OperatingSystems.WINDOWS:
        with SSH(url_or_ip=url_or_ip) as ssh:
            ssh.execute(command='sc stop "Tenable Nessus"')
    elif os_name == OperatingSystems.LINUX:
        with SSH(url_or_ip=url_or_ip) as ssh:
            output = ssh.execute(command="supervisorctl stop nessusd", sudo=True)
        if all(['command not found' in op for op in output]):
            with SSH(url_or_ip=url_or_ip) as ssh:
                ssh.execute(command='systemctl stop nessusd', sudo=True)
        elif all(['nessusd: stopped' not in op for op in output]):
            with SSH(url_or_ip=url_or_ip) as ssh:
                ssh.execute(command='systemctl stop nessusd', sudo=True)
    elif os_name == OperatingSystems.FREEBSD:
        with SSH(url_or_ip=url_or_ip) as ssh:
            ssh.execute(command='service nessusd stop')
    elif os_name in [OperatingSystems.MAC, OperatingSystems.MAC_OS]:
        with SSH(url_or_ip=url_or_ip) as ssh:
            ssh.execute(command='launchctl unload -w /Library/LaunchDaemons/com.tenablesecurity.nessusd.plist',
                        sudo=True)
    else:
        raise Exception("The support of cli commands for {} is not present".format(os_name))
    
    # Optional waiting for stop completion
    if wait_for_stop:
        if api is None:
            api = NessusAPI()
            
        def _is_stopped():
            try:
                api.server.status()
                return False  # Still responding
            except Exception:
                return True  # Service stopped (expected connection failures)
        
        try:
            wait(lambda: _is_stopped(), sleep_seconds=1, timeout_seconds=timeout, 
                 waiting_for="Nessus service to stop")
        except Exception:
            log.debug("Nessus stop detection timed out after %d seconds", timeout)


def stop_nessusd() -> None:
    """
    This function will stop nessusd without stopping the service.
    :return: None
    """

    create_file = get_command("create_file").format(path_join(path_dir_list=[get_nessus_var_dir(), "nessusd.shutdown"]))
    with SSH() as ssh:
        ssh.execute(command=create_file)


def start_nessus(url_or_ip=None, wait_level: str = None, api: NessusAPI = None, 
                 timeout: int = 60, fallback_sleep: int = 15) -> None:
    """
    Start Nessus service with optional waiting capabilities
    
    :param str url_or_ip: Target server URL or IP (optional)
    :param str wait_level: Level of waiting after start (default: None for backward compatibility)
                          - None: No waiting (original behavior)
                          - 'responsive': Wait for basic API responsiveness
                          - 'ready': Wait for full scanner ready state (plugins loaded, etc.)
    :param NessusAPI api: API instance for waiting operations (auto-created if needed)
    :param int timeout: Timeout for waiting operations in seconds (default: 60)
    :param int fallback_sleep: Fallback sleep if dynamic waiting fails (default: 15)
    :return: None
    """
    os_name = get_os_name()

    if os_name == OperatingSystems.WINDOWS:
        with SSH(url_or_ip=url_or_ip) as ssh:
            ssh.execute(command='sc start "Tenable Nessus"')
    elif os_name == OperatingSystems.LINUX:
        with SSH(url_or_ip=url_or_ip) as ssh:
            output = ssh.execute(command="supervisorctl start nessusd", sudo=True)
        if all(['command not found' in op for op in output]):
            with SSH(url_or_ip=url_or_ip) as ssh:
                ssh.execute(command='systemctl start nessusd', sudo=True)
        elif all(['nessusd: started' not in op for op in output]):
            with SSH(url_or_ip=url_or_ip) as ssh:
                ssh.execute(command='systemctl start nessusd', sudo=True)
    elif os_name == OperatingSystems.FREEBSD:
        with SSH(url_or_ip=url_or_ip) as ssh:
            ssh.execute(command='service nessusd start')
    elif os_name in [OperatingSystems.MAC, OperatingSystems.MAC_OS]:
        with SSH(url_or_ip=url_or_ip) as ssh:
            ssh.execute(command='launchctl load -w /Library/LaunchDaemons/com.tenablesecurity.nessusd.plist', sudo=True)
    else:
        raise Exception("The support of cli commands for {} is not present".format(os_name))
    
    # Optional waiting based on specified level
    if wait_level:
        if api is None:
            api = NessusAPI()
            
        if wait_level == 'responsive':
            def _is_responsive():
                try:
                    api.server.status()
                    return True  # Service responding
                except Exception:
                    return False  # Still starting (expected connection failures)
            
            try:
                wait(lambda: _is_responsive(), sleep_seconds=2, timeout_seconds=timeout, 
                     waiting_for="Nessus service to become responsive")
                log.debug("Nessus service is responsive")
            except Exception:
                log.debug("Dynamic wait timed out, using fallback sleep of %d seconds", fallback_sleep)
                sleep(fallback_sleep, reason="Fallback wait for Nessus to start")
                
        elif wait_level == 'ready':
            # Import here to avoid circular imports
            from nessus.helpers.scanner import wait_for_scanner_to_be_ready
            wait_for_scanner_to_be_ready(api, is_login_required=False)
        else:
            raise ValueError(f"Invalid wait_level '{wait_level}'. Valid options: 'responsive', 'ready'")


def set_nessus_env_variables(environment_variables: dict, restart: bool = True, set_variable: bool = True) -> list:
    """
    This function will start nessus
    :param environment_variables: list of environment variables to be set on the system before nessusd starts. Format is
        variable_name=value ex: ['NESSUS_SCAN_POLICY_DUMP=True']
    :param restart: boolean to indicate whether Nessus should be restarted within this function or not.
    :param set_variable: boolean to indicate whether to set or unset environment variable.
    :return: None
    """
    os_name = get_os_name()
    nessus_directory = get_nessusd()
    output_list = []
    if set_variable:
        linux_command = "set"
        win_command = "set"
    else:
        linux_command = "unset"
        win_command = "setx"

    with SSH() as ssh:
        if os_name == OperatingSystems.WINDOWS:
            ssh.change_working_directory(nessus_directory)
            for variable in environment_variables.keys():
                output_list.append(
                    ssh.execute(command=f"{win_command} {variable}={environment_variables[variable]}", sudo=True))
            # ssh.execute(command='nessusd.exe')
        elif os_name in [OperatingSystems.LINUX, OperatingSystems.MAC, OperatingSystems.MAC_OS]:
            env_vars_string = ''
            for variable in environment_variables.keys():
                if set_variable:
                    output_list.append(ssh.execute(
                        command=f"systemctl {linux_command}-environment {variable}={environment_variables[variable]}",
                        sudo=True))
                else:
                    output_list.append(
                        ssh.execute(command=f"systemctl {linux_command}-environment {variable}", sudo=True))
            # ssh.execute(command=env_vars_string + " " + nessus_directory)
        else:
            raise Exception(f"The support of cli commands for {os_name} is not present")

    if restart:
        start_nessus()

    return output_list


def get_installed_os() -> str:
    """Returns installed OS for Linux"""
    with SSH() as ssh:
        return ssh.execute(command='{} {}'.format(get_command(
            'display_content'), NessusInstallation.OS_RELEASE_FILE_PATH))[0].split('=')[1].split()[0].strip('"')


def get_install_update_command(operation: str, installed_os: str = "") -> str:
    """
    This helper method return command as required for particular OS
    :param str operation: Nessus install/update related operation for which command is needed
    :param str installed_os: Installed OS
    :return: command for given operation
    :rtype: str
    """
    if not installed_os:
        installed_os = get_installed_os()
    return NessusInstallation.OS_COMMANDS[installed_os][operation]


def get_nessus_log_dir():
    """This function will return log directory path for Nessus according to operating system."""
    os_name = get_os_name()

    if os_name == OperatingSystems.WINDOWS:
        return NessusFilePath.Windows.NESSUS_LOGS_DIR
    elif os_name == OperatingSystems.FREEBSD:
        return NessusFilePath.FreeBSD.NESSUS_LOGS_DIR
    elif os_name == OperatingSystems.LINUX:
        return NessusFilePath.Linux.NESSUS_LOGS_DIR
    else:
        return NESSUS_LOGS_DIR


def get_nessus_conf_dir():
    """This function will return conf directory path for Nessus according to operating system."""
    os_name = get_os_name()

    if os_name == OperatingSystems.WINDOWS:
        return NessusFilePath.Windows.NESSUS_CONF
    elif os_name == OperatingSystems.FREEBSD:
        return NessusFilePath.FreeBSD.NESSUS_CONF
    elif os_name == OperatingSystems.LINUX:
        return NessusFilePath.Linux.NESSUS_CONF
    else:
        return NESSUS_CONF_DIR


def get_nessus_bin_dir():
    """This function will return bin directory path for Nessus according to operating system."""
    os_name = get_os_name()

    if os_name == OperatingSystems.WINDOWS:
        return NessusFilePath.Windows.NESSUS_BIN
    elif os_name == OperatingSystems.FREEBSD:
        return NessusFilePath.FreeBSD.NESSUS_BIN
    elif os_name == OperatingSystems.LINUX:
        return NessusFilePath.Linux.NESSUS_BIN
    else:
        return NESSUS_BIN_DIR


def get_nessus_lib_dir():
    """This function will return conf directory path for Nessus according to operating system."""
    os_name = get_os_name()

    if os_name == OperatingSystems.WINDOWS:
        return NessusFilePath.Windows.NESSUS_LIB
    elif os_name == OperatingSystems.FREEBSD:
        return NessusFilePath.FreeBSD.NESSUS_LIB
    elif os_name == OperatingSystems.LINUX:
        return NessusFilePath.Linux.NESSUS_LIB
    else:
        return NESSUS_LIB_DIR


def is_nessus_running() -> bool:
    """This helper returns True if Nessus service is running."""
    os_name = get_os_name()

    with SSH() as ssh:
        if NESSUS_PLATFORM not in [OperatingSystems.MAC, OperatingSystems.MAC_OS]:
            log.debug('Check installed OS')
            check_installed_os = ssh.execute(command='cat /etc/os-release')
            installed_os = check_installed_os[0].split('=')[1].split()[0].strip('"')
            log.info("Installed OS :: {}".format(installed_os))

        if os_name == OperatingSystems.WINDOWS:
            output = ssh.execute(command='sc status "Tenable Nessus"')
            return True if any(['running' in output_line.lower() for output_line in output]) else False
        elif os_name == OperatingSystems.LINUX:
            if installed_os == "SLES":
                output = ssh.execute(command='sudo systemctl status nessusd')
                return True if any(['running' in output_line.lower() for output_line in output]) else False
            else:
                supervisorctl_output = ssh.execute(command="supervisorctl status nessusd")
                nessusd_output = ssh.execute(command='service nessusd status')
                return True if (any(['running' in output_line.lower() for output_line in supervisorctl_output]) or
                                any(['running' in output_line.lower() for output_line in nessusd_output])) else False
        elif os_name == OperatingSystems.FREEBSD:
            output = ssh.execute(command='service nessusd status')
            return True if any(['running' in output_line.lower() for output_line in output]) else False
        elif os_name == OperatingSystems.MAC_OS:
            output = ssh.execute(command='launchctl print system/com.tenablesecurity.nessusd')
            return True if any(['running' in output_line.lower() for output_line in output]) else False
        else:
            raise Exception("The support of cli commands for {} is not present".format(os_name))


def get_nessus_version_from_feed_server(channel: str = "ga") -> str:
    """ Returns Nessus version of given channel from Feed server """
    nessus_version = json.loads(requests.get(url="https://{}/info".format(NessusConfig.CAT_PLUGIN_FEED_HOST)).content.
                                decode('utf-8'))["nessus_build_channels"]

    return nessus_version[channel]["version"]


def get_file_list_from_nessus_directory(nessus_dir: str) -> list:
    """
    Returns list of files available under given Nessus directory

    :param str nessus_dir: Nessus directory from where files to be fetched
    :return: files available under given directory
    :rtype: list
    """
    with SSH() as ssh:
        files_under_logs_dir = ssh.execute("ls {}".format(nessus_dir))

    return files_under_logs_dir


def delete_file_from_nessus_directory(file_name: str, nessus_dir: str) -> None:
    """
    Deletes given file from given Nessus directory

    :param str file_name: file name to be deleted
    :param str nessus_dir: Nessus directory from where file to be deleted
    :return: None
    """
    with SSH() as ssh:
        ssh.execute("rm -rf {}".format(os.path.join(nessus_dir, file_name)))


def get_nessus_report_engine_dir():
    """ This function will return report engine directory path for Nessus according to operating system """
    os_name = get_os_name()

    if os_name == OperatingSystems.WINDOWS:
        return NessusFilePath.Windows.REPORT_ENGINE_DIR
    elif os_name == OperatingSystems.FREEBSD:
        return NessusFilePath.FreeBSD.REPORT_ENGINE_DIR
    else:
        return NessusFilePath.Linux.REPORT_ENGINE_DIR


def get_nessus_com_dir():
    """This function will return com directory path for Nessus according to operating system."""
    os_name = get_os_name()

    if os_name == OperatingSystems.WINDOWS:
        return NessusFilePath.Windows.NESSUS_COM_DIR
    elif os_name == OperatingSystems.FREEBSD:
        return NessusFilePath.FreeBSD.NESSUS_COM_DIR
    elif os_name == OperatingSystems.LINUX:
        return NessusFilePath.Linux.NESSUS_COM_DIR
    else:
        return NESSUS_COM_DIR


def get_agent_version_from_feed_server(channel: str) -> str:
    """ Returns Agent version of given channel from Feed server """
    agent_version = json.loads(requests.get(url="https://{}/info".format(NessusConfig.CAT_PLUGIN_FEED_HOST)).content.
                               decode('utf-8'))["agent_build_channels"]

    return agent_version[channel]["version"]


def is_ssl_connection_successful(openssl_output, expected_protocol=None):
    """
    Analyze openssl s_client output to determine if connection was successful
    
    :param openssl_output: Raw output from openssl s_client command
    :param expected_protocol: Expected protocol for strict validation (e.g., "TLSv1.2")
    :return: True if connection successful and meets protocol requirements, False otherwise
    :rtype: bool
    """
    if not openssl_output:
        return False

    failure_indicators = [
        'connect:errno', 'Connection refused', 'sslv3 alert handshake failure',
        'no protocols available', 'wrong version number', 'tlsv1 alert protocol version',
        'no peer certificate available', 'Cipher is (NONE)'
    ]
    
    for failure in failure_indicators:
        if failure.lower() in openssl_output.lower():
            return False

    success_indicators = [
        'BEGIN CERTIFICATE', 'Cipher is ECDHE', 'Cipher is AES', 'Cipher is TLS_'
    ]
    
    connection_established = False
    for success in success_indicators:
        if success.lower() in openssl_output.lower():
            connection_established = True
            break

    if not connection_established:
        return False

    if expected_protocol:
        # Simple string parsing instead of regex
        for line in openssl_output.split('\n'):
            if 'Protocol' in line and ':' in line:
                # Extract protocol after the colon
                protocol_part = line.split(':', 1)[1].strip()
                # Look for TLS version pattern
                if protocol_part.startswith('TLSv'):
                    actual_protocol = protocol_part.split()[0]  # Get first word
                    if expected_protocol != actual_protocol:
                        return False
                    break

    return True
