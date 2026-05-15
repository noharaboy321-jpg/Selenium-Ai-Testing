"""
Nessus Agent Profile in Cluster Tests

:copyright: Tenable Network Security, 2024
"""

import pytest
import subprocess
from waiting import TimeoutExpired, wait

from catium.helpers.sleep_lib import sleep
from catium.lib.const import WAIT_NORMAL, TIME_TEN_SECONDS, TIME_TEN_MINUTES
from catium.lib.log import create_logger
from nessus.tests.api.misc.test_scan_wizard import reload_nessus
from nessus.helpers.scanner import wait_for_scanner_to_be_ready

log = create_logger()

# This test will take long time as we need parent node download the core file first
# then need to wait for the child node to download the core files and then wait for the
# agent to update from the new core file, mark it skip for now unless we can figure out
# how to make the time short enough to run the automation.
@pytest.mark.skip(reason="testing will take long time")
@pytest.mark.nessus_manager
@pytest.mark.cluster_manager
@pytest.mark.parametrize('create_manager_cluster', [{'total_nodes': 1, 'total_agents': 1}], indirect=True)
class TestAgentProfile:
    """ Test for Agent profile with cluster-setup
    """

    cat = None

    @pytest.mark.xray(test_key='NES-18074')
    @pytest.mark.parametrize("version_digits", [pytest.param(3, id="3_digit_version")])
    @pytest.mark.usefixtures('nessus_api_login')
    def test_agent_profile(self, create_manager_cluster, create_valid_profile_endpoint):
        """
            1. Setup cluster
            2. Create a new agent profile, make sure the version is different from tha agent's version
            3. Assign the agent to the profile
            4. Verify the agent has the correct profile
            5. Verify the parent node contains the agent version core file, if not reload parent node and wait
            6. Verify the child node contains the agent version core file, if not reload child node and wait
            7. Verify the agent's version is changed to the version defined in the profile

        Scenarios tested:
        [X] Verify Agent can be assigned to a profile
        [x] Verify Agent version is adjusted to the version specified by the profile
        """

        cluster_node = create_manager_cluster['nodes'][0]
        agent_ids = [(agent['id']) for agent in create_manager_cluster['agents']]
        agent_id = agent_ids[0]
        agent = self.cat.api.agents.get_agent_details(agent_id)
        agent_version = agent['core_version']
        profile = create_valid_profile_endpoint
        profile_uuid = profile['profile_uuid']
        if profile['config']['version'] == agent_version :
            versions = self.cat.api.settings.agent_versions()
            for key in versions["versions_in_feed"]:
                version = versions["versions_in_feed"][key]
                if key.count('.') == 2 and version['version'] != agent_version:
                    agent_version = version['version']
                    break
            profile['config']['version'] = agent_version
            self.cat.api.profiles.update_profile(profile_uuid,
                                                 payload={"name": profile['name'],
                                                          "description": profile['description'],
                                                          "config": {"version": agent_version}})

        self.cat.api.profiles.add_profile_members(profile_uuid, None, agent_ids)
        assert self.cat.api.http_status_code == 200, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        agent = self.cat.api.agents.get_agent_details(agent_id)
        assert agent["profile_uuid"] == profile_uuid

        # verify if the new agent version has been downloaded to NM parent node already
        response = self.cat.api.remote.get_remote_agent_updates(params={
            "platform": agent["platform"], "distro": agent["distro"], "upgrade_distro": agent["upgrade_distro"], "version": agent_version})

        if not("ui_version" in response and response["ui_version"] == agent_version):
            # reload nessus to make sure the agent core version is downloaded to NM parent node
            self.cat.api.server.restart(payload={'soft': True})
            wait(lambda: self.cat.api.remote.get_remote_agent_updates(params={
                "platform": agent["platform"], "distro": agent["distro"],
                "upgrade_distro": agent["upgrade_distro"], "version": agent_version})['core_version'] == agent_version,
                 timeout_seconds=TIME_TEN_MINUTES, sleep_seconds=TIME_TEN_SECONDS, waiting_for='Cluster parent node agent version available')

        try:
            cmd = 'docker exec %s /opt/nessus/sbin/nessuscli reload' % (cluster_node['name'])
            subprocess.run(cmd.split())
            sleep(WAIT_NORMAL, reason="For for agent reload")

            wait(lambda: self.cat.api.agents.get_agent_details(agent_id=agent_id)['core_version'] == profile['config']['version'],
                 timeout_seconds=TIME_TEN_MINUTES, sleep_seconds=TIME_TEN_SECONDS, waiting_for='Cluster agent version updated')
        except TimeoutExpired:
            agent = self.cat.api.agents.get_agent_details(agent_id)
            log.info("agent-details:{}".format(agent))
            assert False, f"agent version is {agent['core_version']}, not updated to {profile['config']['version']}"

