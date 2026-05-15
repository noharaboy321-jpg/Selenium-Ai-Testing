"""

TEST CASE: https://jira.corp.tenablesecurity.com/browse/NES-3285
           https://jira.corp.tenablesecurity.com/browse/NES-3286
           https://jira.corp.tenablesecurity.com/browse/CI-17966

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
class TestAgentPluginDownloadsProxy:
    """Test Nessus Agent ability to download plugins using a proxy."""

    cat = None
    fetch_key = True
    use_proxy = True

    def test_agent_pluginset_install_manager_proxy(self, docker_agent):
        """
        Confirm agents can link to a Nessus Manager and download a pluginset through a proxy server.

        1. Start Agent container and get container id.
        2. Poll logs inside of Docker container and wait for initialization script to complete successfully.
        3. Check the status of the Nessus Agent using nessuscli to ensure it linked and accepting jobs.
        4. Confirm the plugins get installed by watching for the log entry in backend.log.
        """

        plugins_installed = agent_logreader.wait_for_agentdb_install(cid=docker_agent.cid)
        assert plugins_installed, "Plugins failed to install correctly or there was an issue parsing backend.log."


@pytest.mark.agent
@pytest.mark.io_onprem
@pytest.mark.long_running
@pytest.mark.usefixtures("docker_agent")
class TestAgentOnPremPluginDownloadsProxy:
    """Test Nessus Agent ability to download plugins from T.io Onprem while connecting through a proxy."""

    cat = None
    fetch_key = True
    controller_type = ControllerType.onprem
    use_proxy = True

    def test_agent_pluginset_install_onprem_proxy(self, docker_agent):
        """
        Confirm agents can link to T.io Onprem and download a plugin-set while connecting through
        a proxy server.

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
class TestAgentTioPluginDownloadsProxy:
    """Test Nessus Agent ability to download plugins from Tenable.io using a proxy."""

    cat = None
    linking_key = TENABLEIO_KEY
    controller_type = ControllerType.tenableio
    use_proxy = True

    def test_agent_pluginset_install_tio_proxy(self, docker_agent):
        """
        Confirm agents can link to Tenable.io (qa-staging) and download a pluginset through a proxy server.

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
class TestAgentTioDevPluginDownloadsProxy:
    """Test Nessus Agent ability to download plugins from Tenable.io develop using a proxy."""

    cat = None
    linking_key = TENABLEIO_DEV_KEY
    controller_type = ControllerType.tenableio
    use_proxy = True

    def test_agent_pluginset_install_tio_dev_proxy(self, docker_agent):
        """
        Confirm agents can link to Tenable.io (qa-milestone) and download a pluginset through a proxy server.

        1. Start Agent container and get container id.
        2. Poll logs inside of Docker container and wait for initialization script to complete successfully.
        3. Check the status of the Nessus Agent using nessuscli to ensure it linked and accepting jobs.
        4. Confirm the plugins get installed by watching for the log entry in backend.log.
        """

        plugins_installed = agent_logreader.wait_for_agentdb_install(cid=docker_agent.cid)
        assert plugins_installed, "Plugins failed to install correctly or there was an issue parsing backend.log."
