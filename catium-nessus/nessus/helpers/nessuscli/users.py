"""
:copyright: Tenable Network Security, 2017
:date: September 7, 2017
:author:
"""

from nessus.helpers.cli_command import created_pexpect, execute
from nessus.helpers.nessuscli.helper import get_nessus_cli
from nessus.lib.config.environment_variables import NESSUS_PLATFORM
from nessus.lib.const import OperatingSystems

sudo = True if NESSUS_PLATFORM == OperatingSystems.MAC_OS else None


def lsuser(args: list = []) -> dict:
    return execute(get_nessus_cli(), ['lsuser'] + args)


def adduser(username: str = '', password: str = '', passconfirm: str = '', sysadmin: bool = False, rules: str = '',
            fail: bool = False, nessus_url: str = None, ssh_args: dict = None, cli_path: str = get_nessus_cli(),
            override_sudo: bool = None, nessus_platform=NESSUS_PLATFORM) -> dict:
    if fail:
        return execute(get_nessus_cli(), ['adduser', username])
    else:
        if ssh_args is None:
            if nessus_url:
                ssh_args = {'url_or_ip': nessus_url}
        au_sudo = sudo if override_sudo is None else override_sudo
        au = created_pexpect(cli_path, ['adduser', username], ssh_args=ssh_args, sudo=au_sudo, nessus_platform=nessus_platform)
        # pellsworth@TNS5313L:/opt/nessus$ sudo ./sbin/nessuscli adduser test
        #     Login password:
        #     Login password (again):
        #     Do you want this user to be a Nessus 'system administrator' user (can upload plugins, etc.)? (y/n) [n]: n
        #     User rules
        #     ----------
        #     nessusd has a rules system which allows you to restrict the hosts
        #     that test has the right to test. For instance, you may want
        #     him to be able to scan his own host only.
        #
        #     Please see the Nessus Command Line Reference for the rules syntax
        #
        #     Enter the rules for this user, and enter a BLANK LINE once you are done :
        #     (the user can have an empty rules set)
        #
        #
        #
        #     Login    : test
        #     Password : ***********
        #     Is that ok? (y/n) [n]: y
        #     An error occurred

        try:
            au.expect('password:')
            au.sendline(password)
            au.expect('password \(again\):')
            au.sendline(passconfirm)
            au.expect('\(y/n\) \[n]:')
            if sysadmin:
                au.sendline('y')
            else:
                au.sendline('n')
            au.expect('empty rules set\)')
            au.sendline(rules)
            au.expect('\(y/n\) \[n\]:')
            au.sendline('y')
            au.expect('y')
            data = au.read()
            au.close()
            return {'rc': au.exitstatus, 'stdout': data.decode('utf-8'), 'stderr': ''}
        except:
            au.close()
            return {'rc': au.exitstatus, 'stdout': au.before.decode('utf-8'), 'stderr': ''}


def chpasswd(username: str = '', password: str = '', passconfirm: str = '', fail: bool = False) -> dict:
    if fail:
        return execute(get_nessus_cli(), ['chpasswd', username])
    else:
        au = created_pexpect(get_nessus_cli(), ['chpasswd', username], sudo=sudo)
        # pellsworth@TNS5313L:/opt/nessus$ sudo ./sbin/nessuscli adduser test
        #     Login password:
        #     Login password (again):
        #     Do you want this user to be a Nessus 'system administrator' user (can upload plugins, etc.)? (y/n) [n]: n
        #     User rules
        #     ----------
        #     nessusd has a rules system which allows you to restrict the hosts
        #     that test has the right to test. For instance, you may want
        #     him to be able to scan his own host only.
        #
        #     Please see the Nessus Command Line Reference for the rules syntax
        #
        #     Enter the rules for this user, and enter a BLANK LINE once you are done :
        #     (the user can have an empty rules set)
        #
        #
        #
        #     Login    : test
        #     Password : ***********
        #     Is that ok? (y/n) [n]: y
        #     An error occurred

        try:
            au.expect('ew password:\s*')
            au.sendline(password)
            au.expect('ew password \(again\):\s*')
            au.sendline(passconfirm)
            if password != passconfirm:
                au.expect('ew password:\s*')
                data = au.before
                au.sendline('')
            else:
                data = au.read()
            au.close()
            return {'rc': au.status, 'stdout': data.decode('utf-8'), 'stderr': ''}
        except:
            au.close()
            return {'rc': au.exitstatus, 'stdout': au.before.decode('utf-8'), 'stderr': ''}


def rmuser(username: str = '', nessus_url: str = None, ssh_args: dict = None, cli_path: str = get_nessus_cli(),
           override_sudo: bool = None, nessus_platform=NESSUS_PLATFORM) -> dict:
    if ssh_args is None:
        if nessus_url:
            ssh_args = {'url_or_ip': nessus_url}

    au_sudo = sudo if override_sudo is None else override_sudo
    dictionary = execute(command=cli_path, args=['lsuser'], ssh_args=ssh_args, sudo=au_sudo)
    if username in dictionary['stdout']:
        au_sudo = sudo if override_sudo is None else override_sudo
        au = created_pexpect(cli_path, ['rmuser', username], ssh_args=ssh_args, sudo=au_sudo, nessus_platform=nessus_platform)
        try:
            au.expect('Are you sure you want to delete this user?')
            au.sendline('y')
            data = au.read()
            au.close()
            return {'rc': au.status, 'stdout': data.decode('utf-8'), 'stderr': ''}
        except:
            au.close()
            return {'rc': au.status, 'stdout': au.before.decode('utf-8'), 'stderr': ''}
    else:
        return execute(command=get_nessus_cli(), args=['rmuser', username], ssh_args=ssh_args)
