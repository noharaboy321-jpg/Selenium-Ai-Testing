"""
Test cases for Nessus Agent filtering.

:copyright: Tenable Network Security, 2019
:date: July 2, 2019
:last_modified: Nov 09, 2020
:author: @pellsworth, @kpanchal
"""

import time
from datetime import datetime, timedelta
from http import HTTPStatus

import pytest
from requests.exceptions import HTTPError

from catium.helpers.testdata import load_testdata


@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login')
class TestAgentFilters:
    """ Test Cases for Nessus Agents Filters"""
    cat = None
    today = datetime.now().strftime("%Y/%m/%d")
    yesterday = datetime.strftime(datetime.now() - timedelta(1), '%Y/%m/%d')

    @pytest.mark.incompatible
    @pytest.mark.parametrize('nessus_create_nessus_agent', [
        [3, 'None', load_testdata('nessus/tests/api/agents/test_data/three_agents.json')]], indirect=True)
    @pytest.mark.parametrize('filter_and_expected', [
        ['filter.0.quality=eq&filter.0.filter=name&filter.0.value=three_agents_1', ['three_agents_1']],
        ['filter.0.quality=match&filter.0.filter=ip&filter.0.value=1.0.0.3', ['three_agents_3']],
        ['filter.0.quality=match&filter.0.filter=ip&filter.0.value=1.0.0.0', []],
        ['filter.0.quality=neq&filter.0.filter=name&filter.0.value=three_agents_1', ['three_agents_2',
                                                                                     'three_agents_3']],
        ['filter.0.quality=nmatch&filter.0.filter=ip&filter.0.value=1.0.0.3', ['three_agents_1', 'three_agents_2']],
        ['filter.search_type=or&filter.0.quality=match&filter.0.filter=ip&filter.0.value=1.0.0.3&filter.1.quality='
         'match&filter.1.filter=ip&filter.1.value=1.0.0.1', ['three_agents_1', 'three_agents_3']],
        ['filter.0.quality=match&filter.0.filter=platform&filter.0.value=DARWIN', ['three_agents_3']],
        ['filter.0.quality=nmatch&filter.0.filter=platform&filter.0.value=Windows', ['three_agents_2',
                                                                                     'three_agents_3']],
        ['filter.0.quality=neq&filter.0.filter=distro&filter.0.value=ubuntu1110-x86-64', ['three_agents_1',
                                                                                          'three_agents_3']],
        ['filter.0.quality=eq&filter.0.filter=distro&filter.0.value=win-x86-64', ['three_agents_1']],
        ['filter.0.quality=neq&filter.0.filter=groups&filter.0.value=three_agents_group', ['three_agents_2',
                                                                                           'three_agents_3']],
        ['filter.0.quality=neq&filter.0.filter=core_version&filter.0.value=7.4.2', ['three_agents_1',
                                                                                    'three_agents_3']],
        ['search=DARWIN', ['three_agents_3']],
        ['search=macosx', ['three_agents_3']],
        ['search=three_agents_3', ['three_agents_3']],
        ['search=three_agents', ['three_agents_1', 'three_agents_2', 'three_agents_3']],
        ['search=1.0.0.3', ['three_agents_3']],
        ['filter.0.quality=match&filter.0.filter=name&filter.0.value=three_agents',
         ['three_agents_1', 'three_agents_2', 'three_agents_3']],
        ['search=ABCDEFG&filter.0.quality=match&filter.0.filter=platform&filter.0.value=DARWIN', []],
        ['search=1.0.0.3&filter.0.quality=match&filter.0.filter=platform&filter.0.value=DARWIN', ['three_agents_3']],
        ['search=1.0.0.3&filter.0.quality=nmatch&filter.0.filter=platform&filter.0.value=DARWIN', []],
        ['search=three_agents_&limit=1&offset=0', ['three_agents_1']],
        ['search=three_agents_&limit=1&offset=1', ['three_agents_2']],
        ['search=three_agents_&limit=2&offset=0', ['three_agents_1', 'three_agents_2']],
        ['search=three_agents_&limit=2&offset=2', ['three_agents_3']],
        ['search=three_agents_&filter.0.quality=eq&filter.0.filter=groups&filter.0.value=None', ['three_agents_2',
                                                                                                 'three_agents_3']],
        ['search=three_agents_&filter.0.quality=neq&filter.0.filter=groups&filter.0.value=None', ['three_agents_1']],
        ['search=three_agents_&filter.0.quality=eq&filter.0.filter=groups&filter.0.value=three_agents_group',
         ['three_agents_1']],
        ['filter.0.quality=nmatch&filter.0.filter=name&filter.0.value=three_agents', []],
        ['search=7.4.2', ['three_agents_2']],
        ['search=three_agents_group', ['three_agents_1']],
        ['search=three_agents&filter.0.quality=date-gt&filter.0.filter=last_connect&filter.0.value=' + yesterday,
         ['three_agents_1', 'three_agents_2', 'three_agents_3']],
        ['search=three_agents&filter.0.quality=date-lt&filter.0.filter=last_connect&filter.0.value=' + today, []],
        ['search=three_agents&filter.0.quality=date-eq&filter.0.filter=last_connect&filter.0.value=' + today,
         ['three_agents_1', 'three_agents_2', 'three_agents_3']],
        ['search=three_agents&filter.0.quality=date-neq&filter.0.filter=last_connect&filter.0.value=' + today, []],
        ['search=three_agents&filter.0.quality=date-gt&filter.0.filter=plugin_feed_id&filter.0.value=2019/02/01',
         ['three_agents_3']],
        ['search=three_agents&filter.0.quality=date-gt&filter.0.filter=linked_on&filter.0.value=' + yesterday,
         ['three_agents_1', 'three_agents_2', 'three_agents_3']],
        ['search=three_agents&filter.0.quality=eq&filter.0.filter=status&filter.0.value=online',
         ['three_agents_1', 'three_agents_2', 'three_agents_3']],
        ['search=three_agents&filter.0.quality=neq&filter.0.filter=status&filter.0.value=online', []],
        ['filter.0.quality=eq&filter.0.filter=status&filter.0.value=processing', []],
        ['filter.0.quality=neq&filter.0.filter=status&filter.0.value=initializing',
         ['three_agents_1', 'three_agents_2', 'three_agents_3']],
        ['search=three_agents&filter.0.quality=eq&filter.0.filter=status&filter.0.value=online',
         ['three_agents_1', 'three_agents_2', 'three_agents_3'], {"sleep": 10}],
        ['search=three_agents&filter.0.quality=eq&filter.0.filter=status&filter.0.value=online',
         ['three_agents_1', 'three_agents_2', 'three_agents_3'], {"sleep": 18}],
        ['search=three_agents&filter.0.quality=eq&filter.0.filter=status&filter.0.value=offline',
         ['three_agents_1', 'three_agents_2', 'three_agents_3'], {"sleep": 1210}]])
    def test_get_agents_by_advanced_filter_qs(self, nessus_create_nessus_agent, filter_and_expected):
        """
            Tests various filter combinations.

            Scenarios tested:
              [x] Filter using OR
              [x] Filter using AND
              [x] Filter using eq
              [x] Filter using neq
              [x] Filter using match
              [x] Filter agents by IP
              [x] Filter agents by platform
              [x] Filter agents by distro
              [x] Filter agents by group
              [x] Filter agents by last_connect (date-gt)
              [x] Filter agents by last_connect (date-lt)
              [x] Filter agents by last_connect (date-eq)
              [x] Filter agents by last_connect (date-neq)
              [x] Filter agents by plugin_feed_id (eq)
              [x] Filter agents by linked_on
              [x] Filter agents by status (online)
              [x] Filter agents by status (online, sleep 10s before checking)
              [x] Filter agents by status (online, sleep 18s before checking)
              [x] Filter agents by status (offline, sleep 1210s before checking)
              [x] Filter agents by search term (platform)
              [x] Filter agents by search term (core version)
              [x] Filter agents by search term (distro)
              [x] Filter agents by search term (name)
              [x] Filter agents by search term (IP)
              [x] Filter agents by search term (groups)
              [x] Filter agents by filter AND search term
              [x] Test limit and offset options
              [x] Test filtering by not being a part of any groups
              [x] Test filtering by being a part of any group
        """
        options = {}

        if len(filter_and_expected) > 2 and filter_and_expected[2]:
            options = filter_and_expected[2]

        if 'sleep' in options:
            time.sleep(options['sleep'])

        # Login to API again in case session timed out due to long sleep in above step.
        try:
            agents = self.cat.api.agents.agents_list(filters=filter_and_expected[0])['agents']
        except HTTPError as error:
            if self.cat.api.http_status_code == HTTPStatus.UNAUTHORIZED:
                self.cat.api.login()
                agents = self.cat.api.agents.agents_list(filters=filter_and_expected[0])['agents']
            else:
                raise Exception("Received Error : {} ".format(error))

        total = 0

        for name in filter_and_expected[1]:
            found = False

            for agent in agents:
                if agent['name'] == name:
                    found = True
                    total += 1
                    break

            assert found, 'Agent ' + name + ' was not found'

        assert total == len(filter_and_expected[1]), 'Expected agents and list of returned agents did not match.'

    @pytest.mark.parametrize('nessus_create_nessus_agent', [
        [3, 'None', load_testdata('nessus/tests/api/agents/test_data/three_agents.json')]], indirect=True)
    @pytest.mark.parametrize('filter_and_expected', [
        [{"select_all": True}, []],
        [{"search": "three_agents_1"}, ['three_agents_2', 'three_agents_3']],
        [{"search": "three_agents_1", "select_all": True}, ['three_agents_2', 'three_agents_3']],
        [{"ids": "IDS"}, []],
        [{"exclude_ids": "IDS"}, ['three_agents_1', 'three_agents_2', 'three_agents_3']],
        [{"exclude_ids": "IDS", "select_all": True}, []],
        [{"search": "ABCDEFG"}, ['three_agents_1', 'three_agents_2', 'three_agents_3']],
        [{"filter.0.quality": "match", "filter.0.filter": "platform", "filter.0.value": "DARWIN"},
         ['three_agents_1', 'three_agents_2']]])
    def test_delete_agents_by_advanced_filter(self, nessus_create_nessus_agent, filter_and_expected):
        """
            Tests various filter combinations when deleting agents that aren't
            tested by getting agents.

            Scenarios tested:
              [x] Delete using select_all
              [x] Delete using a search
              [x] Delete using search + select_all (invalid; select_all will be disabled)
              [x] Delete using inclusive IDs
              [x] Delete using exclusive IDs (no select_all: invalid)
              [x] Delete using exclusive IDs and select_all
              [x] Delete using a filter that matches nothing
              [x] Delete using select_all and a filter
        """

        created_ids = nessus_create_nessus_agent
        filters = filter_and_expected[0]

        if 'ids' in filters and filters['ids'] == 'IDS':
            filters['ids'] = created_ids

        if 'exclude_ids' in filters and filters['exclude_ids'] == 'IDS':
            filters['exclude_ids'] = created_ids

        self.cat.api.agents.delete_multiple_filtered(filter_and_expected[0])
        agents = self.cat.api.agents.agents_list(filters='search=three_agents_')['agents']
        agent_count = 0

        if agents:
            agent_count = len(agents)

        total = 0
        for name in filter_and_expected[1]:
            found = False

            for agent in agents:
                # ignore finding agents we didn't create.
                if 'three_agents_' not in agent['name']:
                    agent_count -= 1
                    continue

                if agent['name'] == name:
                    found = True
                    total += 1
                    break

            assert found, 'Agent ' + name + ' was not found'

        assert total == agent_count, 'Expected agents and list of returned agents did not match.'
