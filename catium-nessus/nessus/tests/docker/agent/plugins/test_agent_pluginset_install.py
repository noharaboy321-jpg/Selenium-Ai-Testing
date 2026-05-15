"""

TEST CASE: https://jira.corp.tenablesecurity.com/browse/NES-3285
           https://jira.corp.tenablesecurity.com/browse/NES-3286

:copyright: Tenable Network Security, 2017
:date: Aug 30 2017
:author: @jmcneil
"""

import pytest

from nessus.helpers.dockernessus.lib.constants import ControllerType
from nessus.helpers.dockernessus.lib.system import agent_logreader
from nessus.lib.config import docker_config


TENABLEIO_KEY = docker_config.TENABLEIO_CONFIG["key"]
TENABLEIO_DEV_KEY = docker_config.TENABLEIO_DEV_CONFIG["key"]


@pytest.mark.agent
@pytest.mark.long_running
@pytest.mark.usefixtures("docker_agent")
class TestAgentPluginDownloads:
    """Test Nessus Agent ability to download plugins from Nessus Manager."""

    cat = None
    fetch_key = True

    def test_agent_pluginset_install_manager(self, docker_agent):
        """
        Confirm agents can link to a Nessus Manager and download a pluginset.

        1. Start Agent container and get container id.
        2. Poll logs inside of Docker container and wait for initialization script to complete successfully.
        3. Check the status of the Nessus Agent using nessuscli to ensure it linked and accepting jobs.
        4. Confirm the plugins get installed by watching for the log entry in backend.log.
        """

        plugins_installed = agent_logreader.wait_for_agentdb_install(cid=docker_agent.cid)
        assert plugins_installed, "Plugins failed to install correctly or there was an issue parsing backend.log."


@pytest.mark.agent
@pytest.mark.long_running
@pytest.mark.usefixtures("docker_agent")
class TestAgentTioPluginDownloads:
    """Test Nessus Agent ability to download plugins from Tenable.io."""

    cat = None
    linking_key = TENABLEIO_KEY
    controller_type = ControllerType.tenableio

    def test_agent_pluginset_install_tio(self, docker_agent):
        """
        Confirm agents can link to Tenable.io (qa-staging) and download a plugin-set.

        1. Start Agent container and get container id.
        2. Poll logs inside of Docker container and wait for initialization script to complete successfully.
        3. Check the status of the Nessus Agent using nessuscli to ensure it linked and accepting jobs.
        4. Confirm the plugins get installed by watching for the log entry in backend.log.
        """

        plugins_installed = agent_logreader.wait_for_agentdb_install(cid=docker_agent.cid)
        assert plugins_installed, "Plugins failed to install correctly or there was an issue parsing backend.log."


@pytest.mark.agent
@pytest.mark.long_running
@pytest.mark.usefixtures("docker_agent")
class TestAgentTioDevPluginDownloads:
    """Test Nessus Agent ability to download plugins from Tenable.io develop using a proxy."""

    cat = None
    linking_key = TENABLEIO_DEV_KEY
    controller_type = ControllerType.tenableio_dev

    def test_agent_pluginset_install_tio_dev_proxy(self, docker_agent):
        """
        Confirm agents can link to Tenable.io (qa-milestone) and download a plugin-set.

        1. Start Agent container and get container id.
        2. Poll logs inside of Docker container and wait for initialization script to complete successfully.
        3. Check the status of the Nessus Agent using nessuscli to ensure it linked and accepting jobs.
        4. Confirm the plugins get installed by watching for the log entry in backend.log.
        """

        plugins_installed = agent_logreader.wait_for_agentdb_install(cid=docker_agent.cid)
        assert plugins_installed, "Plugins failed to install correctly or there was an issue parsing backend.log."
