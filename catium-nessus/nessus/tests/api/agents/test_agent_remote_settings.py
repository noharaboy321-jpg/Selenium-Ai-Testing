"""
Test cases for Agent's Remote Settings Endpoints

:copyright: Tenable Network Security, 2020
:date: October 30, 2020
:last_modified: October 30, 2020
:author: @vsoni
"""

import pytest


@pytest.mark.nessus_mat
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login')
class TestAgentRemoteSettings:
    """ Test Cases for Agent's remote settings Endpoints"""
    cat = None

    # API_Tested# GET agents/{agent_id}/settings
    @pytest.mark.parametrize('nessus_create_nessus_agent', [[1, 'None']], indirect=True)
    def test_get_remote_agent_settings(self, nessus_create_nessus_agent):
        """
        NES-12233 : [API] Remote Agent settings
        Scenario Tested:
            [x] Verify that agent's remote setting can be retrieved.
        """
        added_agent_id = nessus_create_nessus_agent[0]

        agent_settings = self.cat.api.agents.get_remote_settings(agent_id=added_agent_id)

        # Verify agent's remote settings are not empty.
        assert agent_settings['settings'], "Agent's remote settings are not available"

    # API_Tested# POST agents/{agent_id}/restart
    @pytest.mark.parametrize('nessus_create_nessus_agent', [[1, 'None']], indirect=True)
    @pytest.mark.parametrize('restart_agent_payload', [{"idle": False, "hard": False},
                                                       {"idle": True, "hard": True},
                                                       {"idle": True, "hard": False},
                                                       {"idle": False, "hard": True}])
    def test_restart_agent_from_nessus_manager(self, nessus_create_nessus_agent, restart_agent_payload):
        """
        NES-12233 : [API] Remote Agent settings
        Scenario Tested:
            [x] Verify that agent can be restarted from Nessus Manager (with different combinations)
        """

        added_agent_id = nessus_create_nessus_agent[0]
        restart_agent = self.cat.api.agents.restart_remote_agent(agent_id=added_agent_id,
                                                                 payload=restart_agent_payload)
        assert restart_agent['id'] is not None, "Restart request ID is None."
        assert restart_agent['type'] == "restart", "Restart request type should be restart"

    # API_Tested# POST agents/{agent_id}/settings
    # API_Tested# GET agents/{agent_id}/settings
    @pytest.mark.parametrize('nessus_create_nessus_agent', [[1, 'None']], indirect=True)
    def test_verify_add_remote_settings_for_agent(self, nessus_create_nessus_agent):
        """
        NES-12233 : [API] Remote Agent settings
        Scenario Tested:
            [x] Verify that agent remote setting can be added
        """
        added_agent_id = nessus_create_nessus_agent[0]
        payload = {"settings": [{"setting": "update_hostname", "value": "no"},
                                {"setting": "scan_performance_mode", "value": "medium"},
                                {"setting": "plugin_load_performance_mode", "value": "high"},
                                {"setting": "backend_log_level", "value": "normal"}]}

        self.cat.api.agents.set_remote_settings(agent_id=added_agent_id, payload=payload)

        agent_remote_settings = self.cat.api.agents.get_remote_settings(agent_id=added_agent_id)

        current_settings = [setting['setting'] for setting in agent_remote_settings['settings']['current']]

        assert set([setting['setting'] for setting in payload['settings']]) == set(current_settings), \
            "Remote settings does not reflected after saving them."

    # API_Tested# POST agents/{agent_id}/settings
    # API_Tested# PUT agents/{agent_id}/settings
    # API_Tested# GET agents/{agent_id}/settings
    @pytest.mark.parametrize('nessus_create_nessus_agent', [[1, 'None']], indirect=True)
    def test_verify_agent_remote_settings_can_be_applied_to_agent_from_nm(self, nessus_create_nessus_agent):
        """
        NES-12233 : [API] Remote Agent settings
        Scenario Tested:
            [x] Verify that agent settings can be applied to agent from Nessus Manager.
        """
        added_agent_id = nessus_create_nessus_agent[0]
        payload = {"settings": [{"setting": "scan_performance_mode", "value": "medium"},
                                {"setting": "plugin_load_performance_mode", "value": "high"},
                                {"setting": "backend_log_level", "value": "normal"}]}
        self.cat.api.agents.set_remote_settings(agent_id=added_agent_id, payload=payload)
        agent_remote_settings = self.cat.api.agents.get_remote_settings(agent_id=added_agent_id)

        assert len(agent_remote_settings['settings']['current']) == len(payload['settings']), \
            "Remote agent settings have not been added yet."

        # Verify that all settings are having status 'staged' initially
        assert all([setting['status'] == "staged" for setting in agent_remote_settings['settings']['current']]), \
            "All remote settings don't have 'staged' status as of now."

        self.cat.api.agents.apply_staged_remote_settings(agent_id=added_agent_id, payload={})

        agent_remote_settings_after_applied = self.cat.api.agents.get_remote_settings(agent_id=added_agent_id)

        # Verify that all settings' status modified to 'pending' or 'applied' after applying changes to agent
        assert all([setting['status'] in ['pending', 'applied'] for setting in agent_remote_settings_after_applied[
            'settings']['current']]), \
            "Remote settings are not in 'pending' or 'applied' status after applying changes to agent."
