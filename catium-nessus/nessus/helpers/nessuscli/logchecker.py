"""
Nessus Log checker implementation which check log

:copyright: Tenable Network Security, 2017
:date: Feb 07, 2018
:last_modified: Feb 17, 2022
:author: @jamreliya, @kpanchal.ctr
"""

import os
import re
from datetime import datetime

from catium.lib.log.log import create_logger
from catium.lib.ssh import SSH
from nessus.helpers.cli_command import execute
from nessus.helpers.nessuscli.helper import get_os_name
from nessus.lib.const import OperatingSystems

log = create_logger()


def is_log_entries(log_dir: str, file_name: str, log_entry: str, start_timestamp: datetime, end_timestamp: datetime,
                   max_lines_per_file: int = 10, log_line: bool = False) -> bool:
    """
    read log file and return its log_entry exist or not
    :param str log_dir: directory of the log file
    :param str file_name: name of the log file
    :param str log_entry: log entry looking into the log file
    :param datetime start_timestamp: Start time of the log entry within logs
    :param datetime end_timestamp: End time of the log entry within logs
    :param int max_lines_per_file: number of line to read
    :return: True if entry present otherwise False
    :rtype: bool
    """

    log_file = os.path.join(log_dir, file_name)
    with SSH() as ssh:
        if not ssh.path_exist(log_file):
            raise FileNotFoundError('"{}" file not found in host {}'.format(log_file, ssh.ssh_ip))

    if get_os_name() == OperatingSystems.LINUX:
        log_entries = execute(command='tail -n %d' % max_lines_per_file, args=[log_file])
    else:
        log_entries = execute(command='powershell get-content {} -tail'.format(log_file), args=[max_lines_per_file])

    for line in tuple(log_entries['stdout'].split('\n')):
        if log_entry not in line:
            continue
        log_timestamp, _, _ = line.partition('[info]')
        log_timestamp = log_timestamp.split()[0].strip('[')
        datetime_obj = datetime.strptime(log_timestamp.split('.')[0], '%d/%b/%Y:%H:%M:%S')
        if start_timestamp <= datetime_obj <= end_timestamp:
            log.debug('Log entry "%s" found in log file, within specified range of time: (%s, %s)', log_entry,
                      start_timestamp, end_timestamp)
            return True if not log_line else line
    else:
        log.debug('Log entry "%s" not found in log file, within specified range of time: (%s, %s)', log_entry,
                  start_timestamp, end_timestamp)
        return False


def read_from_file(filename: str, file_mode: str = 'r') -> str:
    """
    Reads the content of specified file and returns it's content
    .. note:: Filename can be specified either by relative path or absolute path; if filename is specified
    as relative path, the file is looked only within current directory.

    :param str filename: Filename to be read
    :param str file_mode: Mode of file to be opened; default: 'r' (read mode)
    :return: Content of file as string
    :rtype: str
    :raise: FileNotFoundError, in case specified filename is not found
    """
    if not os.path.exists(filename):
        raise FileNotFoundError('"{}" file not found in host'.format(filename))
    with open(filename, file_mode) as file:
        contents = file.read()
    return contents


def read_from_file_on_remote(filename: str) -> str:
    """
    Reads the content of specified file from the remote machine and returns it's content

    :param str filename: Filename to be read
    :return: Content of file as string
    :rtype: str
    :raise: FileNotFoundError, in case specified filename is not found
    """
    with SSH() as ssh:
        if not ssh.path_exist(filename):
            raise FileNotFoundError('"{}" file not found in host {}'.format(filename, ssh.ssh_ip))
    if get_os_name() == OperatingSystems.LINUX:
        log_entries = execute(command='cat', args=[filename])
    else:
        log_entries = execute(command='type', args=[filename.replace('/', '\\')])
    return log_entries['stdout']


def verify_log_entry_in_specific_time_range(log_dir: str, file_name: str, log_entry: str, start_timestamp: datetime,
                                            end_timestamp: datetime) -> bool:
    """
    Read log file and return True if log exist in given time range

    :param str log_dir: directory of the log file
    :param str file_name: name of the log file
    :param str log_entry: log entry looking into the log file
    :param datetime start_timestamp: Start time of the log entry within logs
    :param datetime end_timestamp: End time of the log entry within logs
    :return: True if entry present otherwise False
    :rtype: bool
    """
    log_file = os.path.join(log_dir, file_name)

    with SSH() as ssh:
        if not ssh.path_exist(log_file):
            raise FileNotFoundError('"{}" file not found in host {}'.format(log_file, ssh.ssh_ip))

        log_entries = ssh.execute(command='cat {} | grep "{}"'.format(log_file, log_entry))
        log.debug("Logs from '{}' file :: {}".format(log_file, log_entries))

        try:
            for line in log_entries:
                if bool(re.search(r'.[0-3][0-9]/', line)):
                    log_timestamp = line.partition('] [')[0].split()[0].strip('[')
                    datetime_obj = datetime.strptime(log_timestamp.split('.')[0], '%d/%b/%Y:%H:%M:%S')

                    if (log_entry in line) and (start_timestamp <= datetime_obj <= end_timestamp):
                        log.debug(
                            'Log entry "{}" found in "{}" log file, within specified range of time: ({}, {})'.format(
                                log_entry, log_file, start_timestamp, end_timestamp))
                        return True
                    else:
                        continue
                else:
                    log.debug(
                        'Log entry "{}" not found in "{}" log file, within specified range of time: ({}, {})'.format(
                            log_entry, log_file, start_timestamp, end_timestamp))
                    return False
        except Exception as e:
            log.warning("Throws an exception while verifying logs :: {}".format(e))
