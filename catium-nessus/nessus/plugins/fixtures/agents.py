"""
Fixtures to set Nessus Agents

:copyright: Tenable Network Security, 2017
:date: Aug 07 2017
:last_modified: May 05, 2020
:author: @ivargas, @jyerge, @kpanchal
"""

from datetime import datetime
from http import HTTPStatus
from random import randint, randrange
from typing import TYPE_CHECKING

import pytest
from requests.exceptions import HTTPError
from waiting import wait

from catium.lib.const import STRING_NONE
from catium.lib.const.base_constants import TIME_FIFTEEN_MINUTES, TIME_TEN_SECONDS
from catium.lib.log import create_logger
from catium.lib.ssh.ssh import SSH
from catium.lib.util import random_name
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.agents import choose_agent_info
from nessus.helpers.scanner import wait_for_scanner_to_be_ready
from nessus.helpers.sensor_proxy.sensor_proxy import check_agent_status
from nessus.lib.config import NessusConfig
from nessus.tests.conftest import create_tio_container
from tenableio.apiobjects.tenablecloud_api import TenableCloudAPI

if TYPE_CHECKING:
    from catium.lib.typechecking import SubRequest

log = create_logger()


@pytest.fixture()
def create_agent_group(request: 'SubRequest', nessus_api_handler: NessusAPI):
    """Creates a new  agent group"""
    log.debug('fixture init: Create an agent group')
    agent_group = {'id': ''}  # TODO: remove this line, not used.
    scanner_id = 1
    agent_name = random_name(prefix='agent-group-')
    agent_group = nessus_api_handler.agent_groups.create(scanner_id, agent_name)
    agent_group.update({'name': agent_name})
    yield agent_group
    log.debug('fixture teardown: Remove agent group %s', agent_group['id'])
    if request.config.getoption('enable_cleanup') and \
            (request.config.getoption('cleanup_on_failure') or not getattr(request.cls, 'has_failed', False)):
        try:
            nessus_api_handler.agent_groups.delete(scanner_id, agent_group['id'])
        except Exception:
            log.warning("Unable to delete agent in clean up. Agent may have been deleted by test or may be running.")
    else:
        log.info('Agent Group still exists: Scanner ID: %s Agent Group ID: %s', scanner_id, agent_group['id'])
        request.instance.cleanup_info = 'Scanner ID: %s Agent Group ID: %s' % (scanner_id, agent_group['id'])


@pytest.fixture()
def num_of_agent_groups(request: 'SubRequest') -> int:
    """Returns number of objects requested for fixture functions"""
    param = getattr(request, 'param', 2)
    log.debug('fixture init: Number of agent groups: %s', param)
    return param


@pytest.fixture()
def create_list_of_agent_groups(request: 'SubRequest', nessus_api_handler: NessusAPI, num_of_agent_groups: int): \
        # pylint: disable=redefined-outer-name
    """Creates a list of agent groups"""
    log.debug('fixture init: Create list of agent groups')
    scanner_id = 1
    agent_group_list = []
    agent_name = None
    for _ in range(num_of_agent_groups):
        agent_name = random_name(prefix='agent-group-')
        agent_group = nessus_api_handler.agent_groups.create(scanner_id, agent_name)
        agent_group.update({'name': agent_name})
        agent_group_list.append(agent_group)
    yield agent_group_list.copy()
    log.debug('fixture init: Delete list of agent groups: %s', agent_group_list)
    if request.config.getoption('enable_cleanup') and \
            (request.config.getoption('cleanup_on_failure') or not getattr(request.cls, 'has_failed', False)):
        for agent_group in agent_group_list:
            try:
                nessus_api_handler.agent_groups.delete(scanner_id, agent_group['id'])
            except Exception:
                log.warning("Unable to delete agent in clean up. Agent may have been deleted by test or may be running")
    else:
        for agent_group in agent_group_list:
            log.info('Agent Group still exists, with id: %s %s', agent_name, agent_group['id'])
        request.instance.cleanup_info = 'Agent Groups:\n' + '\n'.join(agent['name'] for agent in agent_group_list)


@pytest.fixture()
def add_agent_locally(request: 'SubRequest', nessus_api_handler: NessusAPI) -> dict:
    """
    Adds a fake agent

    .. note:: This fixture requires an active API session
    """
    log.debug('fixture init: add_agent_locally: Adds a fake agent')
    return nessus_api_handler.agents.add_fake_agent()


@pytest.fixture(scope='function')
def nessus_create_nessus_agent(request: 'SubRequest', nessus_api_login):
    """
    Fixture to create a Nessus Agent(s).  This fixture requires an amount of agents to create, as well as a
    linking key.  For example:

        @pytest.mark.parametrize('nessus_create_nessus_agent',
                                 [[1, CAT_NESSUS_MANAGER_LINKING_KEY]], indirect=True)

    The above code would create a single agent.

        @pytest.mark.parametrize('nessus_create_nessus_agent',
                                 [[3, CAT_NESSUS_MANAGER_LINKING_KEY]], indirect=True)

    The above code would create 3 agents.
    """
    log.debug('fixture init: nessus_create_nessus_agent: Create a Nessus agent')
    agent_ids = []
    created_groups = []
    created_group_ids = []
    return_full_agent = len(request.param) > 3 and request.param[3] == 'full'

    try:
        num_of_agents = request.param[0]
        if request.param[1] == STRING_NONE:
            linking_key = nessus_api_login.settings.get_key()['key']
        else:
            linking_key = request.param[1]

        for i in range(num_of_agents):
            uuid = str(randint(10000000, 99999999)) + "-0000-0000-0000-" + \
                   str(randint(100000, 999999)) + str(randint(100000, 999999))

            ipv4 = ["{0}.{1}.{2}.{3}".format(randrange(1, 254),
                                             randrange(1, 254),
                                             randrange(1, 254),
                                             randrange(1, 254))
                    ]

            # we can be given a hash of agent info to use.
            groups = ["All", None]
            if len(request.param) > 2 and request.param[2] != STRING_NONE:
                os_platform = request.param[2][i]['platform']
                distro = request.param[2][i]['distro']
                name = request.param[2][i]['name']
                if 'upgrade_distro' in request.param[2][i].keys():
                    upgrade_distro = request.param[2][i]['upgrade_distro']

                if 'groups' in request.param[2][i]:
                    groups = request.param[2][i]['groups']
            else:
                os_platform, distro, upgrade_distro = choose_agent_info()
                name = random_name(prefix="automation-")

            for group in groups:
                if not group:
                    continue

                if group not in created_groups:
                    # Deleting agent group if agent group with same name already exist.
                    if nessus_api_login.agent_groups.get_list(scanner_id=1)['groups']:
                        for agent_group_info in nessus_api_login.agent_groups.get_list(scanner_id=1)['groups']:
                            if agent_group_info['name'] == group:
                                nessus_api_login.agent_groups.delete(scanner_id=1, group_id=agent_group_info['id'])
                    ret = nessus_api_login.agent_groups.create(scanner_id=1, name=group)
                    created_group_ids.append(ret['id'])
                    created_groups.append(group)

            data = {
                "name": name,
                "groups": groups,
                "distro": distro,
                "platform": os_platform,
                "key": linking_key,
                "uuid": uuid,
                "ips": {
                    "v4": ipv4,
                    "v6": None,
                }
            }

            # If 5th element of param is True, then it will set upgrade_distro
            if len(request.param) > 4 and request.param[4]:
                data['upgrade_distro'] = upgrade_distro

            response = nessus_api_login.agents.add_agents(agent_info=data)

            if len(request.param) > 2 and request.param[2] != STRING_NONE:
                payload = request.param[2][i]
                token = response['token']

                agentApi = NessusAPI()
                agentApi.add_header({'ms-agent': 'token=' + token})
                agentApi.remote.edit_remote_agent(payload=payload)

            agents = nessus_api_login.agents.get_agents(scanner_id=1)['agents']
            for agent in agents:
                if agent['name'] == data['name']:
                    if return_full_agent:
                        agent['token'] = response['token']
                        agent_ids.append(agent)
                    else:
                        agent_ids.append(agent['id'])
        yield agent_ids
    except AttributeError:
        pytest.fail('No request parameters found, cannot load user data.')
    finally:
        log.debug('fixture teardown: nessus_create_nessus_agent: Removing agents')
        for agent in agent_ids:
            agent_id = agent

            if return_full_agent:
                agent_id = agent['id']

            try:
                nessus_api_login.agents.delete(scanner_id=1, agent_id=agent_id)
            except Exception as exc:
                if nessus_api_login.http_status_code == HTTPStatus.NOT_FOUND:
                    log.warning('Agents "%s" already deleted', agent_ids)
                else:
                    log.warning('Deleting agent "%s" failed: %s', agent_id, exc)
        for group_id in created_group_ids:
            try:
                nessus_api_login.agent_groups.delete(1, group_id)
            except Exception as exc:
                if nessus_api_login.http_status_code == HTTPStatus.NOT_FOUND:
                    log.warning('Agent group id "%s" already deleted', group_id)
                else:
                    log.warning('Deleting agent group id "%s" failed: %s', group_id, exc)


@pytest.fixture(scope='function')
def nessus_create_nessus_agent_group(request: 'SubRequest', nessus_api_login):
    """
    Fixture to create a Nessus Agent Group(s).  This fixture requires an amount of groups to create.  For example:

        @pytest.mark.parametrize('nessus_create_nessus_agent_group', [[1]], indirect=True)

    The above code would create a single agent group.

        @pytest.mark.parametrize('nessus_create_nessus_agent_group', [[3]], indirect=True)

    The above code would create 3 agent groups.
    """
    log.debug('fixture init: nessus_create_nessus_agent_group: Create a Nessus agent group')
    group_ids = []
    try:
        num_of_groups = request.param[0]
        for _ in range(num_of_groups):
            group_name = random_name(prefix="automation-")
            nessus_api_login.agent_groups.create(scanner_id=1, name=group_name)
            groups = nessus_api_login.agent_groups.get_list(scanner_id=1)['groups']
            for group in groups:
                if group['name'] == group_name:
                    group_ids.append(group['id'])
        yield group_ids
    finally:
        log.debug('fixture teardown: nessus_create_nessus_agent_group: Removing agent groups')
        try:
            for group_id in group_ids:
                nessus_api_login.agent_groups.delete(scanner_id=1, group_id=group_id)
        except Exception as exc:
            if nessus_api_login.http_status_code == HTTPStatus.NOT_FOUND:
                log.warning('Group "%s" already deleted', id)
            else:
                log.warning('Deleting group "%s" failed: %s', id, exc)


@pytest.fixture()
def create_exclusion(request: 'SubRequest', nessus_api_handler: NessusAPI):
    """Creates a new exclusion"""
    log.debug('fixture init: create_exclusion: Create a new exclusion')
    name = random_name('exclusion-')
    scanner_id = nessus_api_handler.scanners.get_list()['scanners'][0]['id']  # get first scanner id
    date = datetime.now().strftime('%Y-%m-%d %H')
    starttime = date + ":00:00"
    endtime = date + ":30:00"
    payload = {"name": name, "description": "", "agent_group_id": None,
               "schedule": {"enabled": True,
                            "rrules": {"freq": "MONTHLY", "interval": 1,
                                       "bysetpos": 4, "byweekday": "2"},
                            "timezone": "America/New_York",
                            "starttime": starttime,
                            "endtime": endtime}
               }
    exclusion = nessus_api_handler.exclusions.create(scanner_id, payload)

    yield exclusion, scanner_id
    log.debug('fixture teardown: create_exclusion: Remove exclusion %s %s', exclusion, scanner_id)
    if request.config.getoption('enable_cleanup') and \
            (request.config.getoption('cleanup_on_failure') or not getattr(request.cls, 'has_failed', False)):
        try:
            nessus_api_handler.exclusions.delete(exclusion['id'], scanner_id)
        except HTTPError as exc:
            log.warning("Unable to delete Exclusion in clean up. Exclusion may have been deleted by test. "
                        "Error:%s", exc)
    else:
        log.info('Exclusion still exists with ID: %s', exclusion['id'])
        request.instance.cleanup_info = 'Exclusion ID %s' % exclusion['id']


@pytest.fixture()
def agent_config_settings(request: 'SubRequest', nessus_api_handler: NessusAPI):
    """Set the Agent Config settings"""
    log.debug('fixture init: agent_config_settings: Set Agent Config settings')
    config_settings = nessus_api_handler.agents.get_config()
    try:
        payload = request.param['payload']
        nessus_api_handler.agents.edit_config(payload)
        yield payload
        nessus_api_handler.agents.edit_config(config_settings)
        # there may be an issue in this area, because nessus triggers a restart
        # on this API call but only if the cluster switch is enabled.  If so,
        # consider fixing it by adding an explicit soft restart / wait_for_ready
        wait_for_scanner_to_be_ready(api=nessus_api_handler)
    except HTTPError:
        log.warning("Unable to retrieved Agent Config Detail")


@pytest.fixture(scope="class")
def link_agent_to_tenable_io(request: 'SubRequest'):
    """ Link real agent with tenable.io and wait for agent to be online """
    log.debug('fixture init: Link real agent to tenable.io')

    agent_name = random_name(prefix="Agent-")
    tenable_site = NessusConfig.CAT_TIO_URL
    ssh = SSH()

    try:
        container_details = create_tio_container(request, tenable_site.split('.')[0])

        output = ssh.execute("/opt/nessus_agent/sbin/nessuscli agent link --key={} --host={} --port=443 --name={}"
                             .format(container_details['linking_key'], tenable_site, agent_name))

        assert any(["Successfully linked to {}:443".format(tenable_site) in output_log for output_log in output]), \
            "Error in agent link to Tenable i.o. Linking output is : {}".format(output)

        tio_api = TenableCloudAPI()
        tio_api.login(username=container_details['container'].model.contact,
                      password=container_details['container'].model.password)

        scanner_id = tio_api.scanners.get_local_scanner_id()
        linked_agents = tio_api.agents.get_agents(scanner_id=scanner_id)['agents']
        linked_agent_ip = [value for value in linked_agents if value['name'] == agent_name][0]['ip']
        log.info("Linked agent IP :: {}".format(linked_agent_ip))

        # Wait for the Agent status of the Agent to come on line
        wait(lambda: check_agent_status(api=tio_api, agent_name=agent_name, scanner_id=scanner_id),
             timeout_seconds=TIME_FIFTEEN_MINUTES, sleep_seconds=TIME_TEN_SECONDS, waiting_for='agent to be online')

        linked_agents = tio_api.agents.get_agents(scanner_id=scanner_id)['agents']
        log.info("Linked agents :: {}".format(linked_agents))

        yield {'agent_name': agent_name, 'agent_ip': linked_agent_ip}

    finally:
        output = ssh.execute("/opt/nessus_agent/sbin/nessuscli agent unlink")
        log.info("Unlink output is : {}".format(output))
