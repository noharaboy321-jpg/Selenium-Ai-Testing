"""
Test cases for Nessus Agent filtering inside agent group.

:copyright: Tenable Network Security, 2020
:date: Oct 27, 2020
:last_modified: Oct 28, 2020
:author: @vsoni
"""

from datetime import datetime

import pytest

from catium.helpers.testdata import load_testdata


@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login')
class TestAgentFiltersInAgentGroup:
    """ Test Cases for Nessus Agents filters in agent group"""
    cat = None
    today = datetime.now().strftime("%Y/%m/%d")

    @pytest.mark.parametrize('nessus_create_nessus_agent', [[3, 'None', load_testdata(
        'nessus/tests/api/agents/test_data/agents_in_agent_group.json')]], indirect=True)
    @pytest.mark.parametrize('agents_filter', [
        {'filter_query': "filter.0.filter=name&filter.0.quality=eq&filter.0.value=automation_agent_1",
         'expected_agents': ["automation_agent_1"]},
        {'filter_query': "filter.0.filter=name&filter.0.quality=match&filter.0.value=automation_agent",
         'expected_agents': ["automation_agent_1", "automation_agent_2", "automation_agent_3"]},
        {'filter_query': "filter.0.filter=name&filter.0.quality=match&filter.0.value=nessus_agent",
         'expected_agents': []},
        {'filter_query': "filter.0.filter=ip&filter.0.quality=eq&filter.0.value=1.0.0.2",
         'expected_agents': ["automation_agent_2"]},
        {'filter_query': "filter.0.filter=ip&filter.0.quality=neq&filter.0.value=1.0.0.1",
         'expected_agents': ["automation_agent_2", "automation_agent_3"]},
        {'filter_query': "filter.0.filter=ip&filter.0.quality=nmatch&filter.0.value=1.2.3",
         'expected_agents': ["automation_agent_1", "automation_agent_2", "automation_agent_3"]},
        {'filter_query': "filter.0.filter=status&filter.0.quality=eq&filter.0.value=online",
         'expected_agents': ["automation_agent_1", "automation_agent_2", "automation_agent_3"]},
        {'filter_query': "filter.0.filter=status&filter.0.quality=neq&filter.0.value=online",
         'expected_agents': []},
        {'filter_query': "filter.0.filter=platform&filter.0.quality=match&filter.0.value=windows",
         'expected_agents': ["automation_agent_1"]},
        {'filter_query': "filter.0.filter=plugin_feed_id&filter.0.quality=date-lt&filter.0.value={}".format(today),
         'expected_agents': ["automation_agent_1", "automation_agent_2", "automation_agent_3"]},
        {'filter_query': "filter.0.filter=plugin_feed_id&filter.0.quality=date-eq&filter.0.value={}".format(today),
         'expected_agents': []},
        {'filter_query': "filter.0.filter=core_version&filter.0.quality=eq&filter.0.value=7.4.0",
         'expected_agents': ["automation_agent_3"]},
        {'filter_query': "filter.0.filter=core_version&filter.0.quality=neq&filter.0.value=7.4.1",
         'expected_agents': ["automation_agent_2", "automation_agent_3"]},
        {'filter_query': "filter.0.filter=core_version&filter.0.quality=match&filter.0.value=7.4",
         'expected_agents': ["automation_agent_1", "automation_agent_2", "automation_agent_3"]},
        {'filter_query': "filter.0.filter=distro&filter.0.quality=match&filter.0.value=macos",
         'expected_agents': ["automation_agent_3"]},
        {'filter_query': "filter.0.filter=distro&filter.0.quality=nmatch&filter.0.value=ubuntu",
         'expected_agents': ["automation_agent_1", "automation_agent_3"]},
        {'filter_query': "filter.search_type=and&filter.0.filter=distro&filter.0.quality=nmatch&filter.0.value=ubuntu&"
                         "filter.1.filter=ip&filter.1.quality=eq&filter.1.value=1.0.0.1",
         'expected_agents': ["automation_agent_1"]},
        {'filter_query': "filter.search_type=or&filter.0.filter=distro&filter.0.quality=match&filter.0.value=ubuntu&"
                         "filter.1.filter=ip&filter.1.quality=eq&filter.1.value=1.0.0.1",
         'expected_agents': ["automation_agent_1", "automation_agent_2"]},
        {'filter_query': "filter.search_type=and&filter.0.filter=ip&filter.0.quality=eq&filter.0.value=1.0.0.1&"
                         "filter.1.filter=name&filter.1.quality=eq&filter.1.value=automation_agent_1&"
                         "filter.2.filter=platform&filter.2.quality=match&filter.2.value=windows&"
                         "filter.3.filter=status&filter.3.quality=eq&filter.3.value=online",
         'expected_agents': ["automation_agent_1"]},
        {'filter_query': "filter.search_type=or&"
                         "filter.0.filter=plugin_feed_id&filter.0.quality=date-eq&filter.0.value={}&"
                         "filter.1.filter=ip&filter.1.quality=eq&filter.1.value=1.2.3.4&"
                         "filter.2.filter=status&filter.2.quality=eq&filter.2.value=offline&"
                         "filter.3.filter=core_version&filter.3.quality=eq&filter.3.value=6.2.2&"
                         "filter.4.filter=name&filter.4.quality=eq&filter.4.value=automation_agent_3".format(today),
         'expected_agents': ["automation_agent_3"]}])
    def test_verify_agents_filtering_in_agent_group(self, nessus_create_nessus_agent, agents_filter):
        """
        NES-12161 : [API] Verify Agent filtering in Agent group
        Scenario Tested:
            Verify agent filters with below parameters works as expected in agent group.
            [x] Filter with 'name' and 'eq'
            [x] Filter with 'name' and 'match'
            [x] Filter with 'name' and 'match' (Negative scenario)
            [x] Filter with 'ip' and 'eq'
            [x] Filter with 'ip' and 'new'
            [x] Filter with 'ip' and 'nmatch'
            [x] Filter with 'status' and 'eq'
            [x] Filter with 'status' and 'neq'
            [x] Filter with 'platform' and 'match'
            [x] Filter with 'plugin_feed_id' and 'date-lt'
            [x] Filter with 'plugin_feed_id' and 'date-eq'
            [x] Filter with 'core_version' and 'eq'
            [x] Filter with 'core_version' and 'neq'
            [x] Filter with 'core_version' and 'match'
            [x] Filter with 'distro' and 'match'
            [x] Filter with 'distro' and 'nmatch'
            [x] Filter with 'and' type - 1. 'distro' and 'nmatch', 2. 'ip' and 'eq'
            [x] Filter with 'or' type - 1.'distro' and 'match', 2. 'ip' and 'eq'
            [x] Filter with 'and' type - 1. 'ip' and 'eq', 2. 'name' and 'eq'
                , 3. 'platform' and 'match', 4. 'status' and 'eq'
            [x] Filter with 'or' type - 1. 'plugin_feed_id' and 'date-eq', 2. 'ip' and 'eq'
                , 3. 'status' and 'eq', 4. 'core_Version' and 'eq', 5. 'name' and 'eq'
        """
        associated_agent_group_name = [agent['groups'][0] for agent in self.cat.api.agents.get_agents(scanner_id=1)[
            'agents'] if agent['id'] == nessus_create_nessus_agent[0]][0]

        agent_group_id = [group['id'] for group in self.cat.api.agent_groups.get_list(scanner_id=1)['groups'] if group[
            'name'] == associated_agent_group_name][0]

        # Search agents by applying agent filter in agent group.
        agents_output = self.cat.api.agent_groups.get_agents_in_agent_groups(
            group_id=agent_group_id, filter_query=agents_filter['filter_query'])['agents']

        # Verify that agents list for the filter query is as expected.
        if agents_filter['expected_agents']:
            assert set([agent['name'] for agent in agents_output]) == set(agents_filter['expected_agents']), \
                "Agent filter output is not correct when query is : {}".format(agents_filter['filter_query'])
        else:
            assert agents_output is None, \
                "There are agents present in the output for the filter :{}".format(agents_filter['filter_query'])
