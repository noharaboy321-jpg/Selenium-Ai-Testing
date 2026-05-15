"""
Nessus Agent Cluster Setup Endpoints Test

:copyright: Tenable Network Security, 2020
:date: Nov 04, 2020
:last_modified: Nov 03, 2020
:author: @kpanchal
"""

import json
from http import HTTPStatus

import pytest
import re
from requests.exceptions import HTTPError

from catium.lib.config import Config
from catium.lib.log import create_logger
from catium.lib.network.network import random_ip_address

log = create_logger()


@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login')
class TestAgentClusterMigration:
    """ Test for Agent Cluster Migration Endpoint """

    cat = None

    # API_Tested# PUT /agents/cluster-migration
    @pytest.mark.parametrize('migration_settings_field', [
        'cluster_migration_cluster_host', 'cluster_migration_cluster_port', 'cluster_migration_linking_key'])
    @pytest.mark.parametrize('invalid_value', ['', None])
    @pytest.mark.parametrize('cluster_migration_enabled', [True, False])
    def test_save_cluster_migration_settings_with_invalid_values(self, migration_settings_field, invalid_value,
                                                                 cluster_migration_enabled):
        """
        NES-12231: [API] [Negative] Cluster migration setting save	

        Scenarios tested:
        [X] Verify error is thrown in the following conditions when trying to save cluster-migration settings
            - without cluster_migration_cluster_host
            - without cluster_migration_cluster_port
            - without cluster_migration_linking_key
            - giving invalid cluster_migration_cluster_host, cluster_migration_cluster_port and
              cluster_migration_linking_key
        """
        random_ip = random_ip_address(ipv4=True)
        linking_key = self.cat.api.scanners.get_node_linking_key()['key']
        cluster_host = re.sub(r'.*//(.*):.*', r'\1', Config.CAT_URL)
        cluster_port = re.sub(r'.*:(\d+).*', r'\1', Config.CAT_URL)

        payload_data = {"cluster_migration_enabled": cluster_migration_enabled,
                        "cluster_migration_cluster_host": cluster_host, "cluster_migration_cluster_port": cluster_port,
                        "cluster_migration_linking_key": linking_key}

        if 'host' in migration_settings_field:
            invalid_value = random_ip

        payload_data.update({migration_settings_field: invalid_value})

        with pytest.raises(HTTPError):
            self.cat.api.agents.edit_cluster_migration(payload=payload_data)

        assert self.cat.api.http_status_code == HTTPStatus.BAD_REQUEST, \
            'Expected 400, got {} instead.'.format(self.cat.api.http_status_code)

        error_msg_from_response = json.loads(self.cat.api.http_text)['error']

        error_msg_when_migration_enabled = 'To enable the cluster migration, the parent node host, port, and linking ' \
                                           'key settings must be set.'
        error_msg_when_migration_disabled = 'Migration settings not saved: '

        expected_error_msg = error_msg_when_migration_enabled if cluster_migration_enabled else \
            error_msg_when_migration_disabled

        if 'host' in migration_settings_field:
            expected_error_msg = error_msg_when_migration_disabled

        assert expected_error_msg in error_msg_from_response, \
            "Expected '{}' error msg, got '{}' instead.".format(expected_error_msg, error_msg_from_response)
