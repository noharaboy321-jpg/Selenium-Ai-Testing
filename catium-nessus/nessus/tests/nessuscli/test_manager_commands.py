"""
Nessus CLI "Manager Commands" Tests

:copyright: Tenable Network Security, 2018
:date: May 24th, 2021
:last_modified: June 08, 2021
:author: @kpanchal
"""
import os
import re
import subprocess

import pytest

from catium.lib.config import Config
from catium.lib.log.log import create_logger
from catium.lib.ssh.ssh import SSH
from catium.lib.util.util import random_name
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.agents import get_agent_id_from_list
from nessus.helpers.nessuscli.helper import get_nessus_cli, get_command, get_nessus_version_from_feed_server
from nessus.helpers.sensor_proxy.sensor_proxy import unlink_agent_from_master
from nessus.lib.const import NessusCli
from nessus.tests.conftest import link_agent_to_master

log = create_logger()


@pytest.mark.nessus_manager
@pytest.mark.real_agent
class TestNessusCLIManagerCommands:
    """ Test "nessuscli manager" commands """

    @staticmethod
    def link_agent_to_manager() -> str:
        """ Links Agent to Manager using given host and port """
        nessus_api = NessusAPI()
        nessus_api.login()

        manager_host = re.sub(r'.*//(.*):.*', r'\1', Config.CAT_URL)
        manager_port = int(re.sub(r'.*:(\d+).*', r'\1', Config.CAT_URL))

        linking_key = nessus_api.scanners.get_agent_linking_key()['key']
        docker_network = os.getenv('DOCKER_NETWORK')

        if not docker_network:
            docker_network = random_name('autonet-')
            subprocess.run(('docker network create %s' % docker_network).split())

        linked_agent_name = link_agent_to_master(docker_network=docker_network, master_host=manager_host,
                                                 master_port=manager_port, linking_key=linking_key)['name']

        linked_agent_id = get_agent_id_from_list(api=nessus_api, agent_name=linked_agent_name)[0]
        linked_agent_details = nessus_api.agents.get_agent_details(agent_id=linked_agent_id)

        return linked_agent_details

    @pytest.mark.parametrize('link_agent', [False, True])
    def test_download_core_command(self, link_agent):
        """
        NES-13049 [Automation]: Verify that CLI command "download-core" functioning properly

        Scenario Tested:
        [x] Verify that "download-core" command should be functioning properly.
        """
        agent_details = {}
        expected_tar_file = None
        nessus_cli_path = get_nessus_cli()

        if link_agent:
            agent_details = self.link_agent_to_manager()

        try:
            with SSH() as ssh:
                nessus_version = get_nessus_version_from_feed_server()

                help_command_output = ssh.execute(command="{} --help".format(nessus_cli_path))

                assert NessusCli.NessuscliHelp.HELP_CMD_VALIDATIONS["manager"] == [
                    command for command in help_command_output if "manager" in command], \
                    "manager related commands are not properly documented in help command output."

                download_core_cmnd_output = ssh.execute(command="{} manager download-core".format(nessus_cli_path))
                log.debug("Download core command Output :: {}".format(download_core_cmnd_output))

                expected_outputs = ["Remote Core: cached UI version not available",
                                    "Remote Core: UI update available (cached ver 0.0.0, available ver {}): "
                                    "cleaning outdated UI files;".format(nessus_version),
                                    "Remote Core: Agent update available"]

                if link_agent:
                    expected_tar_file = "nessus-agent-{}.tar.gz".format(agent_details['upgrade_distro'])

                    expected_outputs.extend(["Remote Core: {} complete".format(expected_tar_file),
                                             "Remote Core: writing new agent version file"])

                assert any([output in cmnd_output for cmnd_output in download_core_cmnd_output for output in
                            expected_outputs]), "Command output is missing or getting invalid output."

                file_path = "/opt/nessus/var/nessus/remote/{}".format(expected_tar_file)

                if link_agent:
                    assert ssh.path_exist(remote_path=file_path) and int(ssh.execute(get_command(
                        "get_file_size").format(file_path))[0]) > 0, \
                        "'{}' tar file is missing under remote directory after executing 'download-core' CLI " \
                        "command.".format(expected_tar_file)
                else:
                    assert not ssh.path_exist(remote_path=file_path), \
                        "'{}' tar file exists under remote directory after executing 'download-core' CLI command " \
                        "even if agent is not linked.".format(expected_tar_file)
        finally:
            if link_agent:
                unlink_agent_from_master(container_name=agent_details['name'])
