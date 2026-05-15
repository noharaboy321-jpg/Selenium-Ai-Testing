"""
:copyright: Tenable Network Security, 2017
:date: September 12, 2017
:author: @pellsworth
"""

from nessus.helpers.cli_command import created_pexpect
from nessus.helpers.nessuscli.helper import get_nessus_cli
from nessus.lib.config.environment_variables import NESSUS_PLATFORM
from nessus.lib.const import OperatingSystems

sudo = True if NESSUS_PLATFORM == OperatingSystems.MAC_OS else None


def mkcert_client(username: str = '', admin: bool = True, rules: str = '', days: str = '365') -> dict:
    cmd = created_pexpect(get_nessus_cli(), ['mkcert-client'], sudo=sudo)

    try:
        # Nessus username for user:
        cmd.expect('username for user:\s*')
        cmd.sendline(username)
        cmd.expect('as soon as their certificate is created\? \(y/n\) \[y\]:\s*')
        cmd.sendline('y')
        cmd.expect('an administrator\? \(y/n\) \[n\]:\s*')
        if admin:
            cmd.sendline('y')
        else:
            cmd.sendline('n')
        cmd.expect('empty rules set\)\s*')
        cmd.sendline(rules)
        cmd.expect('certificate life time in days \[365\]:\s*')
        cmd.sendline(days)
        cmd.expect('letter country code \[US\]:')
        cmd.sendline('US')
        cmd.expect('province name \[NY\]:')
        cmd.sendline('AU')
        cmd.expect('City \[New York\]:')
        cmd.sendline('Autocity')
        cmd.expect('Organization \[Nessus Users United\]:')
        cmd.sendline('Automation Users')
        cmd.expect('unit \[nessus-users\]:')
        cmd.sendline('automation-users')
        cmd.expect('Email \[none\@none.com\]:')
        cmd.sendline('automation@tenable.com')
        cmd.expect('Is this ok\? \(y/n\) \[n\]:')
        cmd.sendline('y')
        cmd.expect('another cert\? \(y/n\) \[y\]:')
        cmd.sendline('n')
        cmd.read()
        cmd.close()
        return {'rc': cmd.status, 'stdout': cmd.before.decode('utf-8'), 'stderr': ''}
    except:
        cmd.close()
        return {'rc': cmd.status, 'stdout': cmd.before.decode('utf-8'), 'stderr': ''}


def mkcert(host_name: str = 'localhost') -> dict:
    cmd = created_pexpect(get_nessus_cli(), ['mkcert'], sudo=sudo)

    try:
        # Nessus username for user:
        cmd.expect('CA certificate life time in days \[1460\]:')
        cmd.sendline('1460')
        cmd.expect('Server certificate life time in days \[365\]:')
        cmd.sendline('365')
        cmd.expect('letter country code \[US\]:')
        cmd.sendline('US')
        cmd.expect('province name \[NY\]:')
        cmd.sendline('AU')
        cmd.expect('city \[New York\]:')
        cmd.sendline('Autocity')
        cmd.expect('organization \[Nessus Users United\]:')
        cmd.sendline('Automation Users')
        cmd.expect('This host name \[localhost\]:')
        cmd.sendline(host_name)
        cmd.expect('Is this ok\? \(y/n\) \[n\]:')
        cmd.sendline('y')
        data = cmd.read()
        cmd.close()
        return {'rc': cmd.status, 'stdout': data.decode('utf-8'), 'stderr': ''}
    except:
        cmd.close()
        return {'rc': cmd.status, 'stdout': cmd.before.decode('utf-8'), 'stderr': ''}
