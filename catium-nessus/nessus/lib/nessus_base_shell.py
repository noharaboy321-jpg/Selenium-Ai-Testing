"""
This module defines common base class for Nessus and Nessus Agent.

:copyright: Tenable Network Security, 2018
:date: November 23, 2018
:author: @ntarwani, @yjain, @jchavda
"""

import re
from abc import abstractmethod
import pexpect.pxssh
from waiting import wait
from waiting.exceptions import TimeoutExpired

from catium.lib.cli.baseshell import BaseShell, log
from catium.lib.const import TIME_SIXTY_SECONDS, TIME_FIVE_SECONDS


class Re(object):
    """Pre-compiled regular expressions used in this module"""
    list_config_keyvalue_pair = re.compile(r'(?P<key>[^:]+):(?P<value>.*)')
    config_keyvalue_pair = re.compile(r"'(\w+)'")


class NessusBaseShell(BaseShell):
    """
    Parent class of NessusShell and AgentShell. It provides implementation of functions common to both,
    NessusShell and AgentShell as well as declares some abstract hook methods.
    """

    # "cmd_repo" will be filled by child classes(NessusShell or NessusAgentShell).
    # e. g.
    # {
    #     "LINUX": 'linux',
    #     "OSX": 'macos',
    #     "WINDOWS": 'windows',
    #     "FILES_STRUCTURE": {
    #         "LOG_CONFIGURATION_FILE": "log.json",
    #         "BACKEND_LOG": "backend.log",
    #         "WINDOWS": {
    #             "BASE_DIR": "C:/Program Files/Tenable/Nessus",
    #             "VAR_DIR": "C:/ProgramData/Tenable/Nessus~1/nessus",
    #             "LOGS_DIR": "C:/ProgramData/Tenable/Nessus/nessus/logs",
    #             "BINARY": "C:/Program Files/Tenable/Nessus/nessuscli",
    #             "UUID_FILE": "'HKLM\Software\Tenable' /v TAG /f"
    #         },
    #         "LINUX": {
    #             "BASE_DIR": "/opt/nessus/",
    #             "VAR_DIR": "/opt/nessus/var/nessus/",
    #             "LOGS_DIR": "/opt/nessus/var/nessus/logs/",
    #             "binary": "/opt/nessus/sbin/nessuscli",
    #             "UUID_FILE": "/etc/tenable_tag"
    #         }
    #    }
    # }
    cmd_repo = {}

    def __init__(self, host, username, password):
        super().__init__(host, username, password)

    # region properties
    @property
    def bin(self) -> str:
        """
        Get binary path of product

        :return: String containing path of binary path(e.g. "opt/nessus/sbin/nessuscli")
        :rtype: str
        """
        files_layout = self._files_layout()
        return files_layout['binary']

    @property
    def logs(self):
        """
        Return absolute path to Nessus log file(s).

        :return: Path to Nessus log files
        :rtype: str
        :raise: EnvironmentError, in case of unsupported platform
        """
        files_layout = self._files_layout()
        return files_layout['LOGS_DIR']

    # endregion

    # region abstract methods
    @abstractmethod
    def before_service_start(self, *args, **kwargs):
        """
        This abstract method is hook for doing some pre processing before service-start

        :param tuple args: List of positional arguments
        :param dict kwargs: List of keyword arguments
        """

    @abstractmethod
    def after_service_start(self, *args, **kwargs):
        """
        This abstract method is hook for doing some post processing after service-start

        :param tuple args: List of positional arguments
        :param dict kwargs: List of keyword arguments
        """

    @abstractmethod
    def before_service_stop(self, *args, **kwargs):
        """
        This abstract method is hook for doing some pre processing before service-stop

        :param tuple args: List of positional arguments
        :param dict kwargs: List of keyword arguments
        """

    @abstractmethod
    def after_service_stop(self, *args, **kwargs):
        """
        This abstract method is hook for doing some post processing after service-stop

        :param tuple args: List of positional arguments
        :param dict kwargs: List of keyword arguments
        """

    @abstractmethod
    def before_service_restart(self, *args, **kwargs):
        """
        This abstract method is hook for doing some pre processing before service-restart

        :param tuple args: List of positional arguments
        :param dict kwargs: List of keyword arguments
        """

    @abstractmethod
    def after_service_restart(self, *args, **kwargs):
        """
        This abstract method is hook for doing some post processing after service-restart

        :param tuple args: List of positional arguments
        :param dict kwargs: List of keyword arguments
       """
    # endregion

    # region functions for parameters
    def list_param(self, quiet: bool = True, secure: bool = True) -> dict:
        """
        Get list of configurations/preferences of the product.

        :param bool quiet: if True do not echo current config settings to test log. default: True
        :param bool secure: boolean for using --secure in cli command
        :return: dictionary containing configurations for the product
        :rtype: dict
        """

        command = ("{} fix {} --list".format(self.bin, "--secure" if secure else ""))
        response = self.command(command, quiet=quiet)

        value_dict = dict()

        for item in response:
            match = Re.list_config_keyvalue_pair.search(item)
            if match:
                key = match.group('key')
                value_dict[key] = match.group('value').strip()
            else:
                if item != '':
                    log.debug("Ignored line: '%s'", item)
        return value_dict

    def get_param(self, param: str, quiet: bool = True, secure: bool = True) -> dict:
        """
        Get particular configurations/preferences of the product.

        :param str param: name of configuration whose value is to be get
        :param bool secure: boolean for using --secure in cli command
        :param bool quiet: if True do not echo current config settings to test log. default: True
        :return: dictionary containing configuration for specific parameter for the product
        :rtype: dict
        """
        command = ("{} fix {} --get '{}'".format(self.bin, "--secure" if secure else "", param))
        response = self.command(command, quiet=quiet)

        value_dict = dict()

        for item in response:
            match = Re.config_keyvalue_pair.findall(item)
            if match and len(match) > 1:
                key = match[0].strip()
                value_dict[key] = match[1].strip()
            elif len(match) <= 1 and "Could not retrieve value for" in match[0]:
                log.debug("Configuration setting not present in list: %s", ("\n".join(match[0])))

        if response and response[0] != '':
            log.debug("Configuration setting command returned message: %s", ("\n".join(response)))

        return value_dict

    def set_param(self, key: str, value: str, secure: bool = True) -> tuple:
        """
        Update existing configuration key-value pair.

        :param str key: Name of config parameter
        :param str value: Value of config parameter
        :param bool secure: boolean for using --secure in cli command
        :return: Command output lines
        :rtype: tuple
        """

        command = ("{} fix {} --set '{}'='{}'".format(self.bin, "--secure" if secure else "", key, value))
        output = self.command(command)

        if output and output[0] != '':
            log.debug("Configuration setting command returned message: %s", ("\n".join(output)))

        return output

    def delete_param(self, key: str, secure: bool = True) -> tuple:
        """
        Delete custom configuration key.

        :param str key: key name
        :param bool secure: boolean for using --secure in cli command
        :return: command output lines as tuple
        :rtype: tuple
        """

        command = ("{} fix {} --delete '{}'".format(self.bin, "--secure" if secure else "", key))
        output = self.command(command)

        if output and output[0] != '':
            log.debug("Configuration setting command returned message: %s", "\n".join(output))

        return output

    def reset_param(self, proceed: bool = True) -> None:
        """
        Resets configurations of the product

        :param Boolean proceed: boolean for proceed with reset configurations or not
        :rtype: None
        """
        self.stop_service()
        pexp = pexpect.pxssh.pxssh()
        pexp.login(server=self.ssh_host, username=self.ssh_username, password=self.ssh_password)
        pexp.sendline("{} fix --reset".format(self.bin))
        pexp.sendline("y" if proceed else "n")
        self.start_service()

    # endregion

    # region service related functions
    def _start_service(self) -> tuple:
        """
        Send command to start service

        :return: Output of start service command
        :rtype: tuple
        """
        return self.command(self.cmd_repo["SERVICE_START"][self.target_os])

    def start_service(self, *args, **kwargs) -> tuple:
        """
        This method does:
            - Doing some pre processing before service start
            - Start the service
            - Doing some post processing after service is started

        :param tuple args: List of positional arguments
        :param dict kwargs: List of keyword arguments
        :return: Output of service start command
        :rtype: tuple
        """
        self.before_service_start(*args, **kwargs)
        out = self._start_service()
        self.after_service_start(*args, **kwargs)
        return out

    def restart_service(self, *args, **kwargs) -> tuple:
        """
        This method does:
            - Doing some pre processing before service restart
            - Restart the service
            - Doing some post processing after service is restarted

        :param tuple args: List of positional arguments
        :param dict kwargs: List of keyword arguments
        :return: Output of service restart command
        :rtype: tuple
        """
        self.before_service_restart(*args, **kwargs)
        out_start = self._stop_service()
        out_stop = self._start_service()
        self.after_service_restart(*args, **kwargs)

        return out_start, out_stop

    def _stop_service(self) -> tuple:
        """
        Send command to stop service

        :return: output of command sent for stop service
        :rtype: tuple
        """

        return self.command(self.cmd_repo["SERVICE_STOP"][self.target_os])

    def stop_service(self, *args, **kwargs) -> tuple:
        """
        This method does:
            - Doing some pre processing before service stop
            - Stop the service
            - Doing some post processing after service is stopped

        :param tuple args: List of positional arguments
        :param dict kwargs: List of keyword arguments
        :return: Output of service stop command
        :rtype: tuple
        """
        self.before_service_stop(*args, **kwargs)
        out = self._stop_service()
        self.after_service_stop(*args, **kwargs)

        return out

    def service_status(self) -> tuple:
        """
        Return service name, pid and status of service.

        :return: Tuple containing dictionary of service {name: pid} and status ('running')
        :rtype: tuple
        :raise: EnvironmentError, in case of unsupported OS platform of the host
        """
        service_statuses = dict()
        cmd_output = self.command(self.cmd_repo["SERVICE_STATUS"][self.target_os])
        try:
            for line in cmd_output:
                match_obj = re.findall('running|dead|stopped', line, re.IGNORECASE)
                if match_obj:
                    status = match_obj[0].lower()
                    service_statuses[self.cmd_repo["SERVICE_NAME"][self.target_os]] = self.pid(
                        service_name=self.cmd_repo["SERVICE_NAME"][self.target_os])
                    return service_statuses, status
        except re.error:
            log.warning('Exception observed while checking Agent Service', exc_info=True)

        log.debug('[%s] %s service running status: %s', self.ssh_host,
                  self.cmd_repo["SERVICE_NAME"][self.target_os], service_statuses)

    def pid(self, service_name: str, expect_multiple_pids: bool = False) -> tuple:
        """
        Returns pid(s) of specified service.
        ..note:: Method returns empty string if service process is not running

        :param str service_name: Service name
        :param bool expect_multiple_pids: Flag to specify if multiple PIDs are expected; default: False
        :return: PID(s) for specified process
        :rtype: tuple
        :raise: EnvironmentError
                - in case of unsupported OS platform of the host
                - in case multiple PIDs are expected but got one or no PID
        """
        op_sys = self.os_detection()

        pid_command = '{} {} {}'.format(self.cmd_repo["SERVICE_PID_PREFIX_CMD"][op_sys], service_name,
                                        self.cmd_repo["SERVICE_PID_SUFFIX_CMD"][op_sys])

        output = self.command(pid_command)
        log.debug("Output of pid command %s", output)
        pids = []

        for line in output:
            pids += [pid for pid in line.split()]

        if expect_multiple_pids and len(pids) < 2:
            raise EnvironmentError('Expecting multiple PIDs; got following PID(s): {}'.format(pids))
        log.debug('[%s] PID(s) for "%s" service: %s', self.ssh_host, service_name, pids)

        return tuple(pids) if pids else ()

    def _files_layout(self) -> dict:
        """
        Get dictionary of file structure based on os

        :return: Dictionary of configuration keys and values
        :rtype: dict
        """
        return self.cmd_repo["FILES_STRUCTURE"][self.target_os]

    def get_svc_mgmt_cmds(self) -> tuple:
        """
        Method to get start|stop|restart product service commands

        :return: start|stop|restart product service commands
        :rtype: tuple
        """
        start_cmd = self.cmd_repo["SERVICE_START"][self.target_os]
        stop_cmd = self.cmd_repo["SERVICE_STOP"][self.target_os]
        restart_cmd = self.cmd_repo["SERVICE_STATUS"][self.target_os]

        return start_cmd, stop_cmd, restart_cmd

    def get_svc_commands(self) -> tuple:
        """
        Method to get start|stop|restart product service commands and the product services names based on specified OS.

        :return: start|stop|restart product service commands and the product services names
        :rtype: tuple
        """
        start_cmd, stop_cmd, restart_cmd = self.get_svc_mgmt_cmds()
        return start_cmd, stop_cmd, restart_cmd

    def get_service_name(self) -> str:
        """
        This method returns the name of the service, after taking into consideration the product version.

        :return: service name
        :rtype: str
        """
        return self.cmd_repo["SERVICE_NAME"][self.target_os]

    # endregion

    # region other utility functions
    def get_help_screen(self) -> tuple:
        """
        Displays a list of Nessus commands.

        :return: Commandline output of help command
        :rtype: tuple
        """

        output = self.command("{} --help".format(self.bin))
        return output

    def get_version(self) -> tuple:
        """
        Display version of Nessus/Agent build

        :return: Commandline output of get version command
        :rtype: tuple
        """
        output = self.command("{} -v".format(self.bin))

        if output and output[0] != '':
            log.debug("Configuration setting command returned message: %s", "\n".join(output))

        return output

    def generate_bug_report(self, full_mode: bool = False, ipv_subnet: bool = False,
                            file_path: str = None, quiet: bool = False, full: bool = False,
                            scrub: bool = False) -> bool:
        """
        generate bug report by sending interactive command.

        :param bool full_mode: Generate bug report with full mode; default: False
        :param bool ipv_subnet: Option for sanitize IPV subnet; default: False
        :param str file_path: path of a file to be generated; default: None
        :param bool quiet: --quiet parameter for command; default: False
        :param bool full: --full option for additional system information; default: False
        :param bool scrub: --scrub option for remove the first two chunks of IP addresses; default: False
        :return: Return True if bug report file is created else False
        :rtype: bool
        """

        file_location = file_path if file_path else self.cmd_repo["BUG_REPORT_FILE"][self.target_os]
        if self.file_exist(file_location):
            self.delete_file(file_location)

        # used pexpect for interactive remote commands
        pexp = pexpect.pxssh.pxssh()
        pexp.login(self.ssh_host, self.ssh_username, self.ssh_password)

        # execute nessuspath bug-report-generator
        command = "{} bug-report-generator {} {} {}".format(
            self.bin, "--quiet" if quiet else "",
            "--full" if full else "",
            "--scrub" if scrub else ""
        )
        pexp.sendline(command)

        # Send Y/N for "Run in "full" mode?"
        pexp.sendline("y" if full_mode else "n")

        # Send Y/N for "Sanitize IPv4 subnets?"
        pexp.sendline("y" if ipv_subnet else "n")

        # Send file location for "Bug report file name?"
        pexp.sendline(file_location)

        try:
            wait(lambda: self.file_exist(file_location), timeout_seconds=TIME_SIXTY_SECONDS,
                 sleep_seconds=TIME_FIVE_SECONDS)
            return True
        except TimeoutExpired:
            return False
            # endregion
