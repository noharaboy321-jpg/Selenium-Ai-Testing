"""
Clustered Nessus Manager Upgrade/Downgrade tests

:copyright: Tenable Network Security, 2020
:date: Nov 23, 2020
:last_modified: Nov 26, 2020
:author: @kpanchal
"""

import subprocess
from http import HTTPStatus

import pytest
import random
from waiting import wait

from catium.helpers.testdata import get_file_path
from catium.lib.const.base_constants import TIME_THIRTY_MINUTES, TIME_TEN_MINUTES, \
    TIME_THIRTY_SECONDS
from catium.lib.log.log import create_logger
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.nessuscli.helper import stop_nessus, start_nessus
from nessus.helpers.scan import create_scan_helper
from nessus.helpers.scanner import wait_for_scanner_to_be_ready
from nessus.helpers.software_update import get_nessus_version_and_build_using_api, \
    clean_up_log_files_before_software_update, verify_no_errors_while_software_update, upgrade_nessus_package, \
    download_nessus_installer_from_nexus
from nessus.helpers.waiters import wait_scan_state
from nessus.lib.const.constants import API, Nessus

log = create_logger()


@pytest.mark.cluster_manager_upgrade_downgrade
@pytest.mark.parametrize('create_manager_cluster', [{'total_nodes': 3, 'total_agents': 3}], indirect=True)
@pytest.mark.usefixtures('create_manager_cluster', 'nessus_api_login')
class TestClusterManagerUpgradeDowngrade:
    """ Tests related to Upgrade/Downgrade in Cluster Nessus Manager (Cluster Manager) """

    cat = None

    @staticmethod
    def verify_cluster_group_after_upgrade_downgrade(api: NessusAPI, group_id: str) -> None:
        """
        Verifies that created cluster groups are intact after upgrading/downgrading clustered NM

        :param Object api: Nessus api object
        :param str group_id: cluster group id
        :return: None
        """
        response = api.clustergroups.list()

        assert api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(api.http_status_code)

        cluster_group_ids = [group['id'] for group in response['cluster_groups']]

        assert group_id in cluster_group_ids, 'Created cluster group is not exist in cluster groups...'

    @staticmethod
    def verify_cluster_node_and_agents_after_upgrade_downgrade(api: NessusAPI, node_ids: list,
                                                               agents_ids: list) -> None:
        """
        Verifies that linked agents and associated nodes are available in cluster group after upgrading/downgrading
        clustered NM

        :param Object api: Nessus api object
        :param list node_ids: list of associated node ids
        :param list agents_ids: list of linked agent ids
        :return: None
        """
        log.info("Verify linked cluster agents after upgrade/downgrade")
        default_cluster_group_id = API.ClusterGroup.DEFAULT_CLUSTER_GROUP_ID

        agents_response = api.clustergroups.get_cluster_group_agents(cluster_group_id=default_cluster_group_id)

        assert api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(api.http_status_code)

        linked_agents_ids = [agent['id'] for agent in agents_response['agents']]

        assert all([agent_id in linked_agents_ids for agent_id in agents_ids]), \
            'Linked cluster agents are not available after Nessus upgrade/downgrade.'

        log.info("Verify associated cluster nodes after upgrade/downgrade")
        nodes_response = api.clustergroups.get_cluster_group_nodes(cluster_group_id=default_cluster_group_id)

        assert api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(api.http_status_code)

        associated_nodes_ids = [node['id'] for node in nodes_response['nodes']]

        assert all([node_id in associated_nodes_ids for node_id in node_ids]), \
            'Associated cluster nodes are not available after Nessus upgrade/downgrade.'

    @staticmethod
    def verify_scan_launched_successfully_after_upgrade_downgrade(api: NessusAPI, agents_ids: list) -> None:
        """
        Verifies that scan gets launched successfully after upgrading/downgrading clustered NM

        :param Object api: Nessus api object
        :param list agents_ids: List of linked agent ids
        :return: None
        """
        agent_id = random.sample(agents_ids, k=1)[0]

        agent_details = api.agents.get_agent_details(agent_id=agent_id)

        assert api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(api.http_status_code)

        node_restart = subprocess.check_output("docker exec {} supervisorctl restart nessusd".format(
            agent_details['node_name']).split(), stderr=subprocess.PIPE).decode('utf-8')
        log.debug("Node restart output is : {}".format(node_restart))

        log.info("Wait for agent become online")
        wait(lambda: api.agents.get_agent_details(agent_id=agent_id)['status'] == Nessus.Agents.AgentStatus.ONLINE,
             timeout_seconds=TIME_TEN_MINUTES * 2, sleep_seconds=TIME_THIRTY_SECONDS,
             waiting_for='Cluster agent to get online status!!')

        scan_file = get_file_path('nessus/tests/api/scan/test_data/test_advanced_agent_scan.json')

        agent_scan = create_scan_helper(api_handler=api, file_name=scan_file, template_title="agent_advanced",
                                        change_scan_name=True, **{'agent_name': agent_details['name'],
                                                                  'agent_status_check': False})[0]

        agent_scan_id = agent_scan['scan']['id']

        log.info("Launch created agent scan")
        api.scans.launch(scan_id=agent_scan_id)

        assert api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(api.http_status_code)

        log.info("Wait for scan to be completed")
        wait_scan_state(api=api, scan_id=agent_scan_id, end_state=API.Scan.Status.COMPLETED,
                        timeout=TIME_THIRTY_MINUTES)

        log.debug("Get scan details after getting completed")
        scan_details = api.scans.details(scan_id=agent_scan_id)

        assert api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(api.http_status_code)

        # Verify that agent scan completed successfully.
        assert scan_details['info']['status'] == API.Scan.Status.COMPLETED, "Scan status is not 'completed' yet."

    def verify_cluster_groups_linked_agents_nodes_and_agent_scan_after_upgrade_downgrade(
            self, nessus_api: NessusAPI, cluster_group_id: str, node_ids: list, agent_ids: list) -> None:
        """
        Verifies that cluster groups, linked agents and associated nodes are available after upgrade/downgrade Nessus

        :param Object nessus_api: Nessus api object
        :param str cluster_group_id: Cluster group id
        :param list node_ids: list of associated nodes id
        :param list agent_ids: list of linked agents id
        :return: None
        """
        log.info("Verify cluster groups after upgrade/downgrade Nessus")
        self.verify_cluster_group_after_upgrade_downgrade(api=nessus_api, group_id=cluster_group_id)

        log.info("Verify cluster agents and associated nodes after upgrade/downgrade Nessus")
        self.verify_cluster_node_and_agents_after_upgrade_downgrade(api=nessus_api, node_ids=node_ids,
                                                                    agents_ids=agent_ids)

        log.info("Verify that scan gets launched successfully after upgrade/downgrade Nessus.")
        self.verify_scan_launched_successfully_after_upgrade_downgrade(api=nessus_api, agents_ids=agent_ids)

        try:
            log.info("Verify no errors detected during clustered Nessus upgrade/downgrade")
            assert verify_no_errors_while_software_update(), "Received error in log files after Nessus downgrade"
        except AssertionError:
            log.info("Error while downgrading the Nessus and performing scan")

    @staticmethod
    def upgrade_downgrade_nessus_and_wait_for_nessus_to_be_ready(nessus_api: NessusAPI, channel: str) -> None:
        """
        Upgrades/Downgrades Nessus and wait to be in ready state

        :param Object nessus_api: Nessus api object
        :param str channel: software upgrade/downgrade channel (e.g: EA/GA/Stable)
        :return: None
        """
        installer_pckg_path = download_nessus_installer_from_nexus(channel=channel)
        log.debug("Nessus {} Installer package path :: {}".format(channel.upper(), installer_pckg_path))

        log.info("Stop Nessus service")
        stop_nessus()

        log.info("Upgrade/Downgrade Nessus to {} by using downloaded installer".format(channel.upper()))
        upgrade_nessus_package(nessus_installer_path=installer_pckg_path, force=True)

        log.info("Start Nessus service")
        start_nessus()

        wait_for_scanner_to_be_ready(api=nessus_api)

    # API_Tested# GET /cluster-groups
    # API_Tested# GET /agents?{cluster_group_id}
    @pytest.mark.usefixtures('nessus_api_login', 'add_new_cluster_group')
    def test_upgrade_downgrade_with_clustered_manager(self, create_manager_cluster, add_new_cluster_group):
        """
        NES-12310: [API Automation] Clustered NM upgrade / downgrade

        Steps:
        1. NM would be installed —> enable clustering
        2. Link 2 child nodes
        3. Link 2-3 Agents
        4. Download GA installer from Nexus
        5. Rpm -Uvh <gA installer> —force (downgrades Nessus)
        6. Make sure cluster groups are intact
        7. Make sure Agents are still linked
        8. Make sure no errors in any Nessus log files after downgrade
        9. Make sure Agent scans are working fine.
        10. Upgrade NM back (rpm -Uvh </install/ dir installer> —force
        11. Make sure cluster groups are intact
        12. Make sure Agents are still linked
        13. Make sure no errors in any Nessus log files after downgrade
        14. Make sure Agent scans are working fine.
        """
        node_ids = [node['id'] for node in create_manager_cluster['nodes']]
        agent_ids = [agent['id'] for agent in create_manager_cluster['agents']]

        created_cluster_group_id = add_new_cluster_group['id']

        log.info("Verify that scan gets launched successfully before downgrade the Nessus.")
        self.verify_scan_launched_successfully_after_upgrade_downgrade(api=self.cat.api, agents_ids=agent_ids)

        log.info("Nessus version details before downgrading to GA")
        original_nessus_version, original_nessus_build = get_nessus_version_and_build_using_api()
        log.info("Nessus Version :: {} and Nessus UI Build :: {}".format(original_nessus_version,
                                                                         original_nessus_build))

        clean_up_log_files_before_software_update()

        self.upgrade_downgrade_nessus_and_wait_for_nessus_to_be_ready(nessus_api=self.cat.api, channel='ga')

        log.info("Nessus Details after downgrading to GA and before upgrading to EA")
        downgraded_nessus_version, downgraded_nessus_build = get_nessus_version_and_build_using_api()
        log.info("Nessus Version :: {} and Nessus UI Build :: {}".format(downgraded_nessus_version,
                                                                         downgraded_nessus_build))

        self.verify_cluster_groups_linked_agents_nodes_and_agent_scan_after_upgrade_downgrade(
            nessus_api=self.cat.api, cluster_group_id=created_cluster_group_id, node_ids=node_ids, agent_ids=agent_ids)

        clean_up_log_files_before_software_update()

        self.upgrade_downgrade_nessus_and_wait_for_nessus_to_be_ready(nessus_api=self.cat.api, channel='ea')

        log.info("Nessus Details after upgrading to EA")
        upgraded_nessus_version, upgraded_nessus_build = get_nessus_version_and_build_using_api()
        log.info("Nessus Version :: {} and Nessus UI Build :: {}".format(upgraded_nessus_version,
                                                                         upgraded_nessus_build))

        self.verify_cluster_groups_linked_agents_nodes_and_agent_scan_after_upgrade_downgrade(
            nessus_api=self.cat.api, cluster_group_id=created_cluster_group_id, node_ids=node_ids, agent_ids=agent_ids)
