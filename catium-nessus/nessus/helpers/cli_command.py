"""
Helper for pexpect stuff

:date: Sept 7 2017
:last_modified: March 25, 2021
:authors: @mkeeler @pellsworth, @kpanchal
"""
import os
import platform
import subprocess

import pexpect

from catium.lib.ssh import SSH
from catium.lib.util.util import is_ci_environment
from nessus.lib.config.environment_variables import NESSUS_PLATFORM
from nessus.lib.const import OperatingSystems

if platform.system() in ['Linux', 'Darwin']:
    import pexpect.pxssh
import shutil

from pexpect import popen_spawn
from catium.lib.config import Config
from catium.lib.log import create_logger
from catium.lib.url import Url
from nessus.lib.config import environment_variables as nessus_config, NessusConfig

logger = create_logger()
system_os = platform.system()


def cmd_sudo_prefix(command: str, sudo: bool = None) -> str:
    """
    Prefix command with sudo if set directly or by CAT_SSH_USE_SUDO
    :param command: command to run
    :param sudo: use sudo; None for env var value
    :return: command string
    """
    if sudo is None:
        sudo = NessusConfig.CAT_SSH_USE_SUDO

    if sudo:
        command = "sudo -S -p '' {}".format(command)

    return command


def execute(command: str, args: list, ssh_args: dict = None, sudo: bool = None, execute_locally: bool = False) -> dict:
    """
    Execute a command locally or via ssh

    :param command - binary to run
    :param args - args to pass binary
    :param bool sudo: use sudo for commands
    :param bool execute_locally: override NESSUS_CLI_LOCAL config and execute locally instead of remotely
    :param ssh_args - if using ssh these can override the options. The dict can hold the same values
                as would be passed to catium.lib.ssh.SSH
    """
    if ssh_args is None:
        ssh_args = {}

    if nessus_config.NESSUS_CLI_LOCAL or execute_locally:
        logger.debug('Executing %s command locally' % command)
        proc_args = [command]
        proc_args.extend(args)

        if system_os in ['Linux', 'Darwin']:
            proc = subprocess.run(proc_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            proc = subprocess.Popen(proc_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

        if system_os == 'Windows':
            output_details = {'stdout': proc.stdout.read().decode('utf-8'), 'stderr': proc.stderr.read().decode('utf-8')}
        else:
            output_details = {'stdout': proc.stdout.decode('utf-8'), 'stderr': proc.stderr.decode('utf-8')}

        return dict(rc=proc.returncode, stdout=output_details['stdout'], stderr=output_details['stderr'])
    else:
        command = cmd_sudo_prefix(command, sudo)
        logger.debug('Executing %s command remotely' % command)
        cmd = '{0} {1}'.format(command, ' '.join(('{0}'.format(x) for x in args)))
        with SSH(**ssh_args) as ssh_conn:
            stdout, stderr = ssh_conn.raw_execute(cmd, sudo=sudo)

        # out = stdout.read()
        # err = stderr.read()
        return dict(stdout="\n".join(stdout), stderr="\n".join(stderr))


def created_pexpect(command: str, args: list, ssh_args: dict = None, sudo: bool = None, nessus_platform = NESSUS_PLATFORM):
    """
    Initializes a pexpect object either locally or via ssh

    :param str command: binary to run
    :param list args: args to pass binary
    :param bool sudo: use sudo for commands
    :param ssh_args: if using ssh these can override the options. The dict can hold the same values as
                would be passed to catium.lib.ssh.SSH
    """
    if ssh_args is None:
        ssh_args = {}

    cmd = '{0} {1}'.format(command, ' '.join(('"{0}"'.format(x) for x in args)))
    logger.debug("CLI command to be execute :: {}".format(cmd))

    if nessus_config.NESSUS_CLI_LOCAL:
        if system_os == 'Linux':
            return pexpect.spawn(cmd)
        else:
            return pexpect.popen_spawn.PopenSpawn(cmd)
    else:
        url_or_ip = ssh_args.get('url_or_ip', NessusConfig.CAT_NESSUS_URL)
        username = ssh_args.get('username', Config.CAT_SSH_USERNAME)
        password = ssh_args.get('password', Config.CAT_SSH_PASSWORD)
        port = ssh_args.get('port', NessusConfig.CAT_SSH_PORT)
        public_key = ssh_args.get('public_key_path', None)
        url_obj = Url(url_or_ip)
        ssh_ip = url_obj.hostname if url_obj.hostname else url_or_ip
        if not all([url_or_ip, username, port]):
            raise AttributeError("Initialisation attributes must be valid. "
                                 "Given values: url: %s, username: %s, port: %i" % (url_or_ip, username, port))

        if not any([password, public_key]) and not is_ci_environment():
            raise AttributeError("Either password or public_key_path must be defined")

        if public_key is not None and not is_ci_environment():
            if not os.path.isfile(public_key):
                raise IOError("Invalid public key path")

        pexp = pexpect.pxssh.pxssh(options={"StrictHostKeyChecking": "no"})
        logger.info('ssh_ip:%s, port:%s' % (ssh_ip, port))
        pexp.login(ssh_ip, username, password, port=port, ssh_key=public_key,
                   auto_prompt_reset=nessus_platform != OperatingSystems.MAC_OS)
        cmd = cmd_sudo_prefix(cmd, sudo)
        pexp.sendline(cmd)
        return pexp


def upload(file: str, remote_file: str, ssh_args: dict = None) -> None:
    """
    Install a file in the nessus location (locally or via ssh)

    :param str file: local filename
    :param str remote_file: remote filename
    :param dict ssh_args: if using ssh these can override the options. The dict can hold the same values as would be
                          passed to catium.lib.ssh.SSH
    """
    if ssh_args is None:
        ssh_args = {}

    if nessus_config.NESSUS_CLI_LOCAL:
        logger.debug('Copying %s to %s locally' % (file, remote_file))
        shutil.copyfile(file, remote_file)
    else:
        logger.debug('Copying %s to %s remotely' % (file, remote_file))
        with SSH(**ssh_args) as ssh_conn:
            ssh_conn.send_file(file, remote_file)
