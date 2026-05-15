"""
Tests of cluster-group Create/Read/Update/Delete APIs

:copyright: Tenable Network Security, 2017
:date: July 25, 2017
:last_modified: May 12, 2021
:author: @mdriscoll, @vsoni, @kpanchal
"""
import json
import re
from http import HTTPStatus
from random import randint

import pytest
from requests import HTTPError

from catium.lib.config import Config
from catium.lib.log import create_logger
from catium.lib.util import random_name

log = create_logger()


@pytest.mark.cluster_manager
@pytest.mark.usefixtures('create_manager_cluster', 'nessus_api_login')
class TestClusterGroups:
    """ Test Cluster Groups """

    cat = None

    def test_create_update_read_delete(self):
        """
        Basic CRUD happy path:
        - Create a cluster group
        - List cluster groups
        - Read original name
        - Update its name
        - Read changed name
        - Delete it
        - List cluster groups
        """
        names = [random_name('cg-'), random_name('cg-')]
        cluster_group_id = self.cat.api.clustergroups.add({'name': names[0]})['cluster_group_id']
        assert cluster_group_id

        cluster_groups = self.cat.api.clustergroups.list()['cluster_groups']
        assert cluster_group_id in [cg['id'] for cg in cluster_groups], 'Cluster Group not found in list'

        cluster_group = self.cat.api.clustergroups.get(cluster_group_id)['cluster_group']
        assert cluster_group['name'] == names[0], 'Name was not set'

        self.cat.api.clustergroups.update(cluster_group_id, {'name': names[1]})

        cluster_group = self.cat.api.clustergroups.get(cluster_group_id)['cluster_group']
        assert cluster_group['name'] == names[1], 'Name did not update'

        self.cat.api.clustergroups.delete(cluster_group_id)

        cluster_groups = self.cat.api.clustergroups.list()['cluster_groups']
        assert cluster_group_id not in [cg['id'] for cg in cluster_groups], 'Cluster Group found in list after delete'


@pytest.mark.cluster_manager
@pytest.mark.usefixtures('create_manager_cluster', 'nessus_api_login')
class TestClusterMigrationSettings:
    """ Test for Agent Cluster Migration Settings Endpoint """

    cat = None

    # API_Tested# PUT /agents/cluster-migration
    @pytest.mark.parametrize('cluster_migration_enabled', [True, False])
    def test_verify_cluster_migration_settings(self, cluster_migration_enabled):
        """
        NES-12230: [API] Verify user is able to fetch current cluster-migration settings

        Scenarios tested:
        [X] Verify user is able to fetch current cluster-migration settings
        """
        linking_key = self.cat.api.scanners.get_node_linking_key()['key']
        cluster_host = re.sub(r'.*//(.*):.*', r'\1', Config.CAT_URL)
        cluster_port = re.sub(r'.*:(\d+).*', r'\1', Config.CAT_URL)

        payload_data = {"cluster_migration_enabled": cluster_migration_enabled,
                        "cluster_migration_cluster_host": cluster_host, "cluster_migration_cluster_port": cluster_port,
                        "cluster_migration_linking_key": linking_key}

        self.cat.api.agents.edit_cluster_migration(payload=payload_data)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        cluster_migration_setting_details = self.cat.api.agents.get_cluster_migration()

        assert cluster_migration_setting_details == payload_data, \
            'Agent cluster migration settings are not saved properly.'


@pytest.mark.cluster_manager
@pytest.mark.usefixtures('create_manager_cluster', 'nessus_api_login')
class TestAdvancedClusterTabSettings:
    """ Tests for Cluster tab Settings from Advanced settings """

    cat = None

    @pytest.mark.parametrize('setting_identifier', ['agent_cluster_scan_cutoff', 'agent_blacklist_duration_days',
                                                    'agent_node_global_max_default'])
    @pytest.mark.parametrize('value_type', ['min', 'default', 'max'])
    def test_verify_min_default_and_max_value_of_settings_under_cluster_tab(self, setting_identifier, value_type):
        """
        NES-13022: [Automation]: Verify the default settings value under cluster tab from Advanced settings

        Scenario Tested:
        [x] Verify default value of agent_blacklist_duration_days
        [x] Verify default value of agent_cluster_scan_cutoff
        [x] Verify default value of agent_node_global_max_default
        """
        settings_details = {"agent_cluster_scan_cutoff": {"min": 300, "default": 3600},
                            "agent_blacklist_duration_days": {"min": 0, "default": 7},
                            "agent_node_global_max_default": {"min": 0, "default": 10000, "max": 20000}}

        cluster_settings_list = self.cat.api.settings.get_list(version=3)['settings']['Clustering']['settings']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        if value_type == "max":
            if setting_identifier == "agent_node_global_max_default":
                max_setting_value = [setting['max'] for setting in cluster_settings_list if setting['setting'] ==
                                     setting_identifier][0]

                assert settings_details[setting_identifier][value_type] == max_setting_value, \
                    "'{}' setting value is getting mismatched for '{}' setting identifier.".format(
                        value_type.upper(), setting_identifier)
            else:
                assert [value_type not in setting for setting in cluster_settings_list if
                        setting_identifier in ["agent_cluster_scan_cutoff", "agent_blacklist_duration_days"]], \
                    "'{}' setting value was present for '{}' setting identifier which should not be.".format(
                        value_type.upper(), setting_identifier)
        else:
            default_setting_value = [setting['default'] for setting in cluster_settings_list if setting['setting'] ==
                                     setting_identifier][0]

            minimum_setting_value = [setting['min'] for setting in cluster_settings_list if setting['setting'] ==
                                     setting_identifier][0]

            expected_setting_value = default_setting_value if value_type == "default" else minimum_setting_value

            assert settings_details[setting_identifier][value_type] == expected_setting_value, \
                "'{}' setting value is getting mismatched for '{}' setting identifier.".format(
                    value_type.upper(), setting_identifier)

    @pytest.mark.parametrize('setting_value', [-1, 0, randint(1, 299)])
    def test_cluster_scan_cutoff_setting_value_not_allowed_the_value_less_than_300(self, setting_value):
        """
        NES-13022: [Automation]: Verify the default settings value under cluster tab from Advanced settings

        Scenario Tested:
        [x] Verify that 'agent_cluster_scan_cutoff' setting does not allowed the value less than 300.
        """
        log.debug("Verified for setting value :: {}".format(setting_value))
        setting_payload = {"setting.0.name": "agent_cluster_scan_cutoff", "setting.0.value": setting_value,
                           "setting.0.action": "edit"}

        with pytest.raises(HTTPError):
            self.cat.api.settings.update(settings=setting_payload)

        assert self.cat.api.http_status_code == HTTPStatus.BAD_REQUEST, \
            'Expected 400, got %s instead.' % self.cat.api.http_status_code

        error_msg_from_response = json.loads(self.cat.api.http_text)['error']
        expected_error_msg = "agent_cluster_scan_cutoff was invalid: Minimum value for Agent Clustering Scan " \
                             "Cutoff is 300"

        assert error_msg_from_response == expected_error_msg, "Expected '{}' error msg, got '{}' instead.".format(
            expected_error_msg, error_msg_from_response)
