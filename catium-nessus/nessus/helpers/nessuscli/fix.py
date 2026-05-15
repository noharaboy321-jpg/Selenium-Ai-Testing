"""
:copyright: Tenable Network Security, 2017
:date: September 7, 2017
:author: @pellsworth
"""

import re
from nessus.helpers.cli_command import execute
from nessus.helpers.nessuscli.helper import get_nessus_cli, stop_nessus, start_nessus


def get_value(key: str = '', secure: bool = False) -> str:
    """ Call nessuscli fix --get, returning the value"""
    result = get(key=key, secure=secure)
    match = re.search('\'' + key + '\' is \'([^\']+)\'', result['stdout'])
    return match.group(1)


def list(secure: bool = False) -> dict:
    """ Call nessuscli fix --list, returning the stdout/stderr/exitcode """
    args = ['fix']

    if secure:
        args.append('--secure')

    args.append('--list')

    return execute(command=get_nessus_cli(), args=args)


def get(key: str = '', secure: bool = False, sudo: bool = None) -> dict:
    """ Call nessuscli fix --get, returning the stdout/stderr/exitcode """

    args = ['fix']

    if secure:
        args.append('--secure')

    args.append('--get')
    args.append(key)

    return execute(command=get_nessus_cli(), args=args, sudo=sudo)


def set(key: str = '', value: str = '', secure: bool = False, sudo: bool = None, restart: bool = False) -> dict:
    """ Call nessuscli fix --set, returning the stdout/stderr/exitcode """

    args = ['fix']

    if secure:
        args.append('--secure')

    args.append('--set')
    args.append(f"{key}={value}")

    output = execute(command=get_nessus_cli(), args=args, sudo=sudo)

    if restart:
        stop_nessus()
        start_nessus()

    return output


def delete(key: str = '', secure: bool = False, sudo: bool = None, restart: bool = False) -> dict:
    """ Call nessuscli fix --delete, returning the stdout/stderr/exitcode """

    args = ['fix']

    if secure:
        args.append('--secure')

    args.append('--delete')
    args.append(key)

    output = execute(command=get_nessus_cli(), args=args, sudo=sudo)

    if restart:
        stop_nessus()
        start_nessus()

    return output


def list_interfaces() -> dict:
    """ Call nessuscli fix --list-interfaces, returning the stdout/stderr/exitcode """
    return execute(command=get_nessus_cli(), args=['fix', '--list-interfaces'])
