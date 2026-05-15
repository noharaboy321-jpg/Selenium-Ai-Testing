"""
:copyright: Tenable Network Security, 2017
:date: September 12, 2017
:author: @pellsworth, @krpatel
"""

from nessus.helpers.cli_command import execute, created_pexpect
from nessus.helpers.nessuscli.helper import get_nessus_cli


def code_in_use() -> dict:
    return execute(get_nessus_cli(), ['fetch', '--code-in-use'])


def check() -> dict:
    return execute(get_nessus_cli(), ['fetch', '--check'])


def register(serial: str = '') -> dict:
    return execute(get_nessus_cli(), ['fetch', '--register', serial])


def register_only(serial: str = '') -> dict:
    return execute(get_nessus_cli(), ['fetch', '--register-only', serial])


def challenge(serial: str = '') -> dict:
    return execute(get_nessus_cli(), ['fetch', '--challenge', serial])


def register_offline(license_file: str = '') -> dict:
    cmd = created_pexpect(get_nessus_cli(), ['fetch', '--register-offline', license_file])
    try:
        cmd.expect('Warning! Performing this action will delete plugins*')
        cmd.sendline('y\n')
        cmd.expect('thank you*')
        cmd.sendline('')
        data = cmd.read()
        cmd.close()
        return {'rc': cmd.exitstatus, 'stdout': data.decode('utf-8'), 'stderr': ''}

    except:
        cmd.close()
        return {'rc': cmd.exitstatus, 'stdout': cmd.before.decode('utf-8'), 'stderr': ''}
