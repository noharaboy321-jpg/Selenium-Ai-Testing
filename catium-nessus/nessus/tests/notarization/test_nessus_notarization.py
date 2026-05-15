"""
Test cases to verify Nessus notarization

:copyright: Tenable Network Security, 2020
:date: May 14, 2021
:author: kdass.ctr
"""
import os
from subprocess import run, PIPE, STDOUT

import pytest

from catium.lib.ssh import SSH
from catium.lib.log import create_logger

log = create_logger('logger')


class TestNessusNotarization:
    """ Test whether Nessus build is notarized or not"""

    aws_build_cache = '10.254.130.228'
    build_branch = os.getenv('BUILD_BRANCH', 'release-next')
    build_latest = 'Nessus-latest.dmg'
    commands = {
        'change_permission_pem': 'chmod 600 nessus-automation.pem',
        'latest_build': 'ssh -i nessus-automation.pem ' + \
                        '-oUserKnownHostsFile=/dev/null -oStrictHostKeyChecking=no ' + \
                        'ec2-user@{0} find nessus-builds/{1} -name *.dmg | sort | tail -n 1',
        'mount': 'hdiutil attach {0}/{1}',
        'rename_file': 'mv {0}/{1} {0}/{2}',
        'scp': 'scp -i nessus-automation.pem ' \
               '-oUserKnownHostsFile=/dev/null -oStrictHostKeyChecking=no ' + \
               'ec2-user@{0}:nessus-builds/{1}/{2} /{3}/',
        'spctl': 'spctl --assess --verbose=4 --type install {0}/{1}',
        'unmount': 'hdiutil detach {0}'
    }

    download_path = '/tmp'
    file_name = 'Install\ Nessus.pkg'

    def run_cmd(self, cmd):
        """
        Wrapper to run commands in shell
        :param str cmd: Command to run
        :return: output as list
        """
        return run(cmd.split(), stdout=PIPE, stderr=STDOUT).stdout.decode('utf-8')

    def get_build_name(self):
        """
        Returns build name if defined in env variable else returns latest build name from storage
        """
        return os.getenv('build_name', self.run_cmd(
            self.commands.get('latest_build').format(self.aws_build_cache, self.build_branch)).split('/')[-1])

    @pytest.fixture
    def get_build_from_aws(self):
        """ Fetches dmg file from AWS build instance """
        log.debug("Fixture init: Fetching Build from AWS")
        self.run_cmd(self.commands.get('change_permission_pem'))
        file_name = self.get_build_name()
        log.debug(
            self.run_cmd(self.commands.get('scp').format(self.aws_build_cache, self.build_branch, file_name,
                                                         self.download_path)))

        self.run_cmd(self.commands.get('rename_file').format(self.download_path, file_name, self.build_latest))

    @pytest.fixture
    def get_connection(self):
        """
        Get mac host SSH connection
        :return: SSH object
        """
        log.debug("Fixture Init: Initializing SSH connection")
        ssh = SSH(url_or_ip=os.getenv('CAT_SSH_IP'), username=os.getenv('CAT_SSH_USERNAME'),
                  password=os.getenv('CAT_SSH_PASSWORD'))
        yield ssh
        log.debug("Fixture TearDown: Closing SSH connection")
        ssh.disconnect()

    @pytest.fixture
    def get_build_to_host(self, get_connection):
        """
        Transfer build from test instance to MAC host
        :param get_connection: SSH connection object
        """
        ssh = get_connection
        log.debug("Fixture Init: Transferring Build to mac host")
        ssh.send_file('{}/{}'.format(self.download_path, self.build_latest),
                      '{}/{}'.format(self.download_path, self.build_latest), use_sudo=True)
        yield
        log.debug("Fixture TearDown: Removing build file")
        ssh.remove_file('{}/{}'.format(self.download_path, self.build_latest))

    @pytest.fixture
    def mount_image(self, get_connection, get_build_to_host):
        """
        Mounts a dmg file
        :param get_connection: ssh connection object
        :param get_build_to_host: fixture to transfer build to mac host
        :return: str: file mount path
        """
        ssh = get_connection
        log.debug("Fixture Init: Mounting dmg file")
        mount_output = ssh.execute(self.commands.get('mount').format(self.download_path, self.build_latest))
        mount_path = mount_output[-1].split('\t')[-1]
        # parsing empty spaces
        mount_path = mount_path.replace(' ', '\ ')
        yield mount_path
        log.debug("Fixture Teardown: Unmounting image file")
        ssh.execute(self.commands.get('unmount').format(mount_path))

    def test_nessus_build_notarized(self, get_connection, get_build_from_aws, mount_image):
        """Test whether an nessus build is notarized or not
        Steps:
        1. Transfer build from AWS storage to mac host
        2. Mount dmg file.
        3. Run spctl to check if build is notarized or not.
        """
        spctl_output = get_connection.execute(self.commands.get('spctl').format(mount_image, self.file_name))
        assert 'accepted' in spctl_output[0].split(':')[1], 'Package was not accepted. Output: {}'.format(spctl_output)
        assert 'source=Notarized Developer ID' in spctl_output[1], 'Package was not notarized. Output: {}'.format(
            spctl_output)
