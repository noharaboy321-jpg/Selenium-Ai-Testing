"""
:copyright: Tenable Network Security, 2017
:date: June 19, 2017
:last_modified: March 25, 2019
:author: @cdombrowski, @rdutta, @ntarwani
"""
import threading
from contextlib import contextmanager
from datetime import datetime
from http import HTTPStatus
from random import choice, randint, randrange

from catium.lib.const.base_constants import STRING_ON
from catium.lib.log import create_logger
from catium.lib.util import random_name
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.lib.const import API

log = create_logger()


def choose_agent_info():
    """
    Returns a random platform/distro combination for agent creation.
    """
    agent_info = (
        # platform, distro, upgrade_distro
        ["DARWIN", "macosx", "macos"],
        ["LINUX", "es7-x86-64", "el7-x86-64"],
        ["LINUX", "el8-x86-64", "el8-x86-64"],
        ["LINUX", "debian6-x86-64", "debian"],
        ["LINUX", "ubuntu1110-x86-64", "ubuntu-x86-64"],
        ["WINDOWS", "win-x86-64", "windows-x86-64"],
    )
    os_platform, distro, upgrade_distro = choice(agent_info)
    return os_platform, distro, upgrade_distro


def sorting(L):
    """
    Returns the splited value for the argument passed to sort.
    """

    splitup = L.split(' ')
    return splitup[1], splitup[0]


def check_agent_linked(agent_name: str, api: NessusAPI) -> bool:
    """
    Returns true if linked agent exist
    :param str agent_name: Name of agent
    :param api: existing Nessus API session
    :return: True if agent found
    :rtype: bool
    """
    agents_list = api.agents.get_agents(scanner_id=1)['agents']
    if agents_list:
        for agent in agents_list:
            if agent_name == agent['name']:
                return True
        return False
    else:
        return False


def get_online_linked_agent(api: NessusAPI) -> list:
    """
    Returns name of the agent(s) if any agent linked to product with online status
    :param api: Nessus API session object
    :return: list of agent_name if one/more agent linked and its status is online
    :rtype: list
    """
    agents_list = api.agents.get_agents(scanner_id=1)['agents']
    if agents_list:
        return [agent['name'] for agent in agents_list if agent['status'] == STRING_ON]
    else:
        log.warning("Not able to fetch any agent from agents_list.")
        return []


def get_agent_id_from_list(api: NessusAPI, agent_name: str) -> tuple:
    """
    Helper to get agent id for a particular agent
    :param NessusAPI api: API object
    :param str agent_name: name of agent whose id is required
    :return: agent id
    :rtype: int
    """
    agent_id = None
    agent_status = None
    agents_detail = api.agents.get_agents(scanner_id=1)['agents'] or []
    for agent in agents_detail:
        if agent['name'] == agent_name:
            agent_id = agent['id']
            agent_status = agent['status']
            break
    else:
        log.warning("Agent %s not found under the list" % agent_name)

    return agent_id, agent_status


def add_multiple_agents_with_multi_threading(api: NessusAPI, num_of_agents: int, num_thread: int = 5) -> list:
    """
    Helper to create multiple agents using multi threading concept
    :param NessusAPI api: api object for agent
    :param int num_of_agents: Number of agents to be added
    :param int num_thread: Number of threads to be created to add agents
    :return: List of agent ids
    :rtype: list
    """
    agent_ids = []
    agents_name = []
    thread_list = []
    linking_key = api.settings.get_key()['key']
    agent_per_thread = int(num_of_agents / num_thread)
    remaining_agents = int(num_of_agents % num_thread)
    agent_batch = [agent_per_thread for _ in range(num_thread)]
    if remaining_agents > 0:
        agent_batch.append(remaining_agents)

    def add_agents(batch_size: int) -> None:
        """
        Method to add multiple agents
        :param int batch_size: Number of agents to be added in one thread
        :return: None
        """

        for _ in range(batch_size):
            uuid = str(randint(10000000, 99999999)) + "-0000-0000-0000-" + \
                   str(randint(100000, 999999)) + str(randint(100000, 999999))

            ipv4 = ["{0}.{1}.{2}.{3}".format(randrange(1, 254),
                                             randrange(1, 254),
                                             randrange(1, 254),
                                             randrange(1, 254))]

            os_platform, distro, _ = choose_agent_info()

            data = {"name": random_name(prefix="automation-"), "groups": ["All", None], "distro": distro,
                    "platform": os_platform, "key": linking_key, "uuid": uuid, "ips": {"v4": ipv4, "v6": []}}

            api.agents.add_agents(agent_info=data)

            agents_name.append(data['name'])

    for batch in agent_batch:
        agent_thread = threading.Thread(target=add_agents, args=(batch,))
        thread_list.append(agent_thread)
        agent_thread.start()

    for thread in thread_list:
        thread.join()

    agents = api.agents.get_agents(scanner_id=1)['agents']
    for name in agents_name:
        for agent in agents:
            if agent['name'] == name:
                agent_ids.append(agent['id'])
                break

    return agent_ids


@contextmanager
def add_multiple_agents(api: NessusAPI, num_of_agents: int) -> list:
    """
    Helper to create multiple agents
    :param NessusAPI api: api object for agent
    :param str num_of_agents: Number of agents to be added
    :return: List of agent ids
    :rtype: list
    """
    agent_ids = add_multiple_agents_with_multi_threading(api=api, num_of_agents=num_of_agents)

    yield agent_ids

    try:
        api.agents.delete_multiple(agent_ids=agent_ids)
    except Exception as exc:
        if api.http_status_code == HTTPStatus.NOT_FOUND:
            log.warning('Agents "%s" already deleted', agent_ids)
        else:
            log.warning('Deleting agents failed: %s', exc)


def get_agent_name(api: NessusAPI, agent_id: int) -> str:
    """
    Retrieve agent name for the agent using agent id
    :param NessusAPI api: Nessus API object
    :param int agent_id: agent id to fetch agent name
    :return: agent name for the given id
    :rtype: str
    """
    agents = api.agents.get_agents(scanner_id=1)['agents']
    for agent in agents:
        if agent['id'] == agent_id:
            agent_name = agent['name']
            break

    return agent_name


def create_freeze_window_via_api(api: NessusAPI):
    """ Helper function to create new freeze window using api """
    date = datetime.now().strftime('%Y-%m-%d %H')
    scanner_id = api.scanners.get_list()['scanners'][0]['id']

    payload = {"name": random_name('Freeze Window - '), "description": "", "agent_group_id": None,
               "schedule": {"enabled": True, "rrules": {"freq": API.Schedule.Frequencies.FREQ_MONTHLY, "interval": 1,
                                                        "bysetpos": 4, "byweekday": "2"},
                            "timezone": "America/New_York", "starttime": date + ":00:00", "endtime": date + ":30:00"}}

    created_exclusion = api.exclusions.create(scanner_id, payload)

    return created_exclusion['name']
