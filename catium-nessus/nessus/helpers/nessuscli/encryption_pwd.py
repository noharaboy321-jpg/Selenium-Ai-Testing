"""
Nessus CLI helper to set or remove master/encryption password

:copyright: Tenable Network Security, 2021
:date: Feb 09, 2021
:last_modified: Feb 09, 2021
:author: @kpanchal
"""

from nessus.helpers.cli_command import created_pexpect
from nessus.helpers.nessuscli.helper import get_nessusd
from nessus.lib.config.environment_variables import NESSUS_PLATFORM
from nessus.lib.const import OperatingSystems

sudo = True if NESSUS_PLATFORM == OperatingSystems.MAC_OS else None


def set_or_remove_encryption_password(key_word: str = 'encryption', new_password: str = '',
                                      confirm_new_pwd: str = '', old_password: str = '') -> dict:
    """
    This helper function will set or remove master/encryption password

    :param str key_word: key word like encryption/master
    :param str new_password: password to be set
    :param str confirm_new_pwd: enter new password as confirm password
    :param str old_password: old password
    :return: CLI command output
    :rtype: dict
    
    NOTE: Keep 'new_password' and 'confirm_new_pwd' blank to remove master/encryption password
    """
    ep_cmnd = created_pexpect(get_nessusd(), ['--set-{}-passwd'.format(key_word)], sudo=sudo)

    try:
        if old_password:
            ep_cmnd.expect('Old password :')
            ep_cmnd.sendline(old_password)

        ep_cmnd.expect('New password :')
        ep_cmnd.sendline(new_password)
        ep_cmnd.expect('Again :')
        ep_cmnd.sendline(confirm_new_pwd)

        data = ep_cmnd.read()
        ep_cmnd.close()
        return {'rc': ep_cmnd.exitstatus, 'stdout': data.decode('utf-8'), 'stderr': ''}
    except:
        ep_cmnd.close()
        return {'rc': ep_cmnd.exitstatus, 'stdout': ep_cmnd.before.decode('utf-8'), 'stderr': ''}
