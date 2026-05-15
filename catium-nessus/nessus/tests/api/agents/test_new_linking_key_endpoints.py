"""
Test cases related to New agent, scanner and child node linking keys.

:copyright: Tenable Network Security, 2017
:date: May 15, 2023
:last_modified:
:author: @krpatel.ctr
"""
from http import HTTPStatus

import pytest

from catium.lib.log.log import create_logger
from nessus.apiobjects.endpoints.scanners import random_alphanumeric_string_for_linking_key

log = create_logger()


@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login')
class TestNewLinkingKeys:
    """Tests related to Agents Page in Nessus Manager"""

    cat = None

    @pytest.mark.xray(test_key='NES-17430')
    def test_set_linking_key_for_agent_API(self):
        """
        NES-17430 : Validate agent Linking Keys in API.

        Scenario Tested:
        [x] Verify API linking keys are updated after change.

        Steps:
        1. Setting up Nessus Manager
        2. Taking random 64 characters key to set
        3. using the set method of agent linking key
        4. using the get method of agent linking key.
        5. Verify both the result is same
        """

        # Generating random 64 character keys
        agent_key = random_alphanumeric_string_for_linking_key(64)

        # setting the new agent linking key to nessus manager
        self.cat.api.agent_groups.set_agent_linking_key(agent_key=agent_key)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    @pytest.mark.xray(test_key='NES-17431')
    def test_set_linking_key_for_scanner_API(self):
        """
        NES-17431 : Validate scanner Linking Keys in API.

        Scenario Tested:
        [x] Verify able to set linking key for scanner using API.

        Steps:
        1. Setting up Nessus Manager
        2. Taking random 64 characters key to set
        3. using the set method of scanner linking key

        """
        # Generating random 64 character keys
        scanner_key = random_alphanumeric_string_for_linking_key(64)

        # setting the new agent linking key to nessus manager
        self.cat.api.agent_groups.set_scanner_linking_key(scanner_key=scanner_key)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    @pytest.mark.xray(test_key='NES-16272')
    def test_set_and_get_linking_key_for_agent_API(self):
        """
        NES-16272 : Validate ability to set linking keys through API for agent.

        Scenario Tested:
        [x] Verify API linking keys are updated after change.

        Steps:
        1. Setting up Nessus Manager
        2. Taking random 64 characters key to set
        3. using the set method of agent linking key
        4. using the get method of agent linking key.
        5. Verify both the result is same
        """

        # Generating random 64 character keys
        agent_key = random_alphanumeric_string_for_linking_key(64)

        # setting the new agent linking key to nessus manager
        self.cat.api.agent_groups.set_agent_linking_key(agent_key=agent_key)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        linking_key = self.cat.api.scanners.get_agent_linking_key()['key']
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Verify newly set linking key via API is reflected on API
        assert agent_key == linking_key, "Linking key is not matched."

    @pytest.mark.xray(test_key='NES-17429')
    def test_set_and_get_linking_key_for_scanner_API(self):
        """
        NES-17429 : Validate ability to set linking keys through API for scanner.

        Scenario Tested:
        [x] Verify API linking keys are updated for scanner.

        Steps:
        1. Setting up Nessus Manager
        2. Taking random 64 characters key to set
        3. using the set method of scanner linking key
        4. using the get method of scanner linking key.
        5. Comparing the results of linking keys.
        """
        # Generating random 64 character keys
        scanner_key = random_alphanumeric_string_for_linking_key(64)

        # setting the new agent linking key to nessus manager
        self.cat.api.agent_groups.set_scanner_linking_key(scanner_key=scanner_key)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        linking_key = self.cat.api.scanners.get_scanner_linking_key()['key']
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Verify newly set linking key via API is reflected on API
        assert scanner_key == linking_key, "Linking key is not matched."
