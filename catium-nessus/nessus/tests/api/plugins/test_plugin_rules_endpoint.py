"""
Nessus Plugin Rules Endpoint related Test

:copyright: Tenable Network Security, 2018
:date: August, 2018
:last_modified: Oct 19, 2020
:author: @mameta, @kpanchal
"""

from http import HTTPStatus

import pytest
import random
from requests.exceptions import HTTPError

from catium.lib.util import random_name


@pytest.mark.nessus_home
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login')
class TestPluginRulesEndpoint:
    """
    NQA-26: Create additional tests for Plugin-Rules

    Scenarios missing:
        [ ] Creating a plugin rule
        [ ] Creating a plugin rule with invalid data
    """
    cat = None

    # API Tested# Get /plugin-rules
    @pytest.mark.nessus_mat
    @pytest.mark.parametrize('create_plugin_rules', [{'plugin_list': [
        {"host": random_name(prefix="plugin_rule_"), "plugin_id": random.randint(1000, 2000), "type": "exclude"}]}],
                             indirect=True)
    def test_get_plugin_rules_list(self, create_plugin_rules):
        """
        get plugin rules list

        Scenarios tested:
            [x] Successfully get the plugin rules list.
        """
        assert self.cat.api.plugins.list_plugin_rules()['plugin_rules'], \
            "plugin rules list is not available"

    # API Tested# Delete /plugin-rules
    @pytest.mark.nessus_mat
    @pytest.mark.parametrize('create_plugin_rules', [{'plugin_list': [
        {"host": random_name(prefix="plugin_rule_"), "plugin_id": random.randint(1000, 2000), "type": "exclude"},
        {"host": random_name(prefix="plugin_rule_"), "plugin_id": random.randint(1000, 2000), "type": "exclude"},
        {"host": random_name(prefix="plugin_rule_"), "plugin_id": random.randint(1000, 2000), "type": "exclude"}]}],
                             indirect=True)
    def test_delete_plugin_rule_list(self, create_plugin_rules):
        """
        test delete list of plugin rules

        Scenarios tested:
            [x] Delete (via the bulk delete) a plugin rule from the list
            [ ] Attempt to delete in bulk a list of plugin rules where one does not exist
            [ ] Attempt to delete in bulk an empty list.
        """
        assert self.cat.api.plugins.list_plugin_rules()['plugin_rules'], \
            "plugin rules list is not available"

        plugin_ids_to_delete = [create_plugin_rules[0]['plugin_response_id'],
                                create_plugin_rules[1]['plugin_response_id']]

        self.cat.api.plugins.bulk_delete(id_list=plugin_ids_to_delete)

        plugin_rules = self.cat.api.plugins.list_plugin_rules()['plugin_rules']
        plugin_rules_ids = [plugin_rule['id'] for plugin_rule in plugin_rules]
        assert all(plugin_rule_id not in plugin_rules_ids for plugin_rule_id in plugin_ids_to_delete), \
            'Plugin Rule is not deleted successfully'

    # API_Tested# GET /plugin-rules/{plugin_rule_id}
    @pytest.mark.nessus_mat
    @pytest.mark.parametrize('create_plugin_rules', [{'plugin_list': [
        {"host": random_name(prefix="plugin_rule_"), "plugin_id": random.randint(1000, 2000), "type": "exclude"}]}],
                             indirect=True)
    def test_get_specific_plugin_rules(self, create_plugin_rules):
        """
        test get specific plugin rule

        Scenarios tested:
            [x] Get a specific plugin rule
            [ ] Attempt to get a plugin rule that doesn't exist
        """
        plugin_response_id = create_plugin_rules[0]['plugin_response_id']
        plugin_rule_details = self.cat.api.plugins.get_plugin_rule(plugin_response_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert plugin_rule_details['id'] == plugin_response_id, \
            'Error: Plugin id did not match'

    # API Tested# Delete /plugin-rules/{plugin_rule_id}
    @pytest.mark.parametrize('create_plugin_rules', [{'plugin_list': [
        {"host": random_name(prefix="plugin_rule_"), "plugin_id": random.randint(1000, 2000), "type": "exclude"},
        {"host": random_name(prefix="plugin_rule_"), "plugin_id": random.randint(1000, 2000), "type": "exclude"}]}],
                             indirect=True)
    def test_delete_specific_plugin_rule(self, create_plugin_rules):
        """
        test delete specific plugin rule

        Scenarios tested:
            [x] Delete a specific plugin rule
            [ ] Attempt to delete a plugin rule that doesn't exist
        """
        plugin_response_id = create_plugin_rules[0]['plugin_response_id']

        self.cat.api.plugins.delete_plugin_rule(plugin_response_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        plugin_rules = self.cat.api.plugins.list_plugin_rules()['plugin_rules']

        plugin_rules_ids = [plugin_rule['id'] for plugin_rule in plugin_rules]
        assert plugin_response_id not in plugin_rules_ids, 'Plugin rule is not deleted successfully'

    # API Tested# PUT /plugin-rules/{plugin_rule_id}
    @pytest.mark.nessus_mat
    @pytest.mark.parametrize('create_plugin_rules', [{'plugin_list': [
        {"host": random_name(prefix="plugin_rule_"), "plugin_id": random.randint(1000, 2000), "type": "exclude"}]}],
                             indirect=True)
    def test_edit_specific_plugin_rule(self, create_plugin_rules):
        """
        test edit specific plugin rule

        Scenarios tested:
            [x] Modify a specific plugin rule
            [ ] Attempt to modify a plugin rule that doesn't exist
            [ ] Attempt to modify a plugin rule with invalid data
        """
        plugin_response_id = create_plugin_rules[0]['plugin_response_id']

        updated_plugin_payload = {"host": random_name(prefix="plugin_rule_"),
                                  "plugin_id": random.randint(1000, 2000),
                                  "type": "recast_high",
                                  }
        self.cat.api.plugins.edit_plugin_rule(plugin_id=plugin_response_id, data=updated_plugin_payload)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        plugin_rule_details = self.cat.api.plugins.get_plugin_rule(plugin_response_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code
        assert plugin_rule_details['host'] == updated_plugin_payload['host'], \
            'Error while setting host to %s ' % format(updated_plugin_payload['host'])
        assert plugin_rule_details['type'] == updated_plugin_payload['type'], \
            'Error while setting type to %s ' % format(updated_plugin_payload['type'])
        assert plugin_rule_details['plugin_id'] == updated_plugin_payload['plugin_id'], \
            'Error while setting plugin_id to %s.' % format(updated_plugin_payload['plugin_id'])

    # API Tested# POST /plugin-rules/{plugin_rule_id}
    @pytest.mark.parametrize('plugin_id', ['xyz', '123.45', '1x2y3z', ' '])
    def test_string_or_empty_value_not_allowed_as_plugin_id(self, plugin_id):
        """
        NES-12157: [Negative] [API] [Negative] Verify plugin rule with plugin-id as string/empty is not allowed	

        Scenarios tested:
            [x] Verify plugin rule with plugin-id as string, empty or decimal value is not allowed.
        """
        plugin_rule_payload = {"host": random_name(prefix="plugin_rule_"), "plugin_id": plugin_id, "type": "exclude"}

        with pytest.raises(HTTPError):
            self.cat.api.plugins.add_plugin_rules(data=plugin_rule_payload)

        assert self.cat.api.http_status_code == HTTPStatus.BAD_REQUEST, \
            'Expected 400, got %s instead.' % self.cat.api.http_status_code
