"""
Nessus Agents Endpoint
"""
from requests.exceptions import HTTPError

from catium.lib import const
from catium.lib.api.base_api_object import ResponseObject
from catium.lib.log import create_logger
from catium.lib.util import random_agent_uuid
from nessus.apiobjects import routes

log = create_logger()


class AgentsEndpoint(object):
    """Agents API Endpoint"""

    def __init__(self, cls):
        self._cls = cls

    def add_agents(self, agent_info: dict) -> ResponseObject:
        """
        Adds an agent to Nessus Manager.

        :param dict agent_info:    A dict containing agent information.
        """
        resource = '/remote/agent'
        response = self._cls.request(const.HTTPMethods.POST, resource, json=agent_info)
        return ResponseObject(response)

    def delete(self, scanner_id: int, agent_id: int):
        """
        Delete agent from given scanner

        :param int scanner_id: Scanner ID
        :param int agent_id: Agent ID
        """
        resource = '%s/%s/%s/%s' % (routes.SCANNERS, scanner_id, routes.AGENTS, agent_id)
        self._cls.request(const.HTTPMethods.DELETE, resource)
        log.debug('Deleted agent ID %s', agent_id)

    def delete_multiple_filtered(self, payload):
        """
        Delete multiple of agents from scanner.

        :param dict payload: payload expressing IDs or filters.
        """
        resource = '%s/' % routes.AGENTS
        self._cls.request(const.HTTPMethods.DELETE, resource, json=payload)

    def delete_multiple(self, agent_ids: list, stream: bool = False):
        """
        Delete list of agents from scanner.

        :param int agent_ids: Agent ID
        :param bool stream: False if need to get response text else True
        """
        resource = '%s/' % routes.AGENTS
        self._cls.request(const.HTTPMethods.DELETE, resource, json={'ids': agent_ids}, stream=stream)
        log.debug('Deleted agent IDs %s', agent_ids)

    def get_agents(self, scanner_id: int, stream: bool = False) -> ResponseObject:
        """
        Returns the agent list for the given scanner

        :param int scanner_id: Scanner ID
        :param bool stream: False if need to get response text else True
        """
        resource = '%s/%s/%s' % (routes.SCANNERS, scanner_id, routes.AGENTS)
        response = self._cls.request(const.HTTPMethods.GET, resource, stream=stream)
        return ResponseObject(response)

    def get_agent_details(self, agent_id: int) -> ResponseObject:
        """
        Get details for a specific agent

        :param int agent_id: Agent ID
        """
        resource = 'agents/{aid}'.format(aid=agent_id)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def add_fake_agent(self, **kwargs) -> dict:
        """
        Adds a fake agent

        :returns: dict
        """
        linking_key = self._cls.scanners.get_scanner_key(1)['key']
        agent_uuid = random_agent_uuid()
        agent_name = kwargs.get('agent_name', agent_uuid)
        payload = {
            'agent_uuid': agent_uuid,
            'distro': 'win-x86-64',
            'key': linking_key,
            'name': agent_name,
            'platform': const.PLATFORM_WINDOWS.upper(),
        }

        groups = kwargs.get('groups', None)
        if groups:
            payload['groups'] = groups

        try:
            self._cls.add_header({'ms-agent': 'token=' + linking_key})
            response = ResponseObject(self._cls.request(const.HTTPMethods.POST, routes.REMOTE_AGENT, json=payload))
        except HTTPError as error:
            log.error("Request threw %s: %s", error.__class__.__name__, error)
            raise
        finally:
            self._cls.remove_header('MS-Agent')
        ret = {'name': agent_name, 'agent_uuid': agent_uuid, 'token': response['token']}
        if 'msg' in response:
            ret['msg'] = response['msg']
        return ret

    def agents_list(self, filters=None) -> ResponseObject:
        """
        Return a list of agents

        :return: Response message containing list of agents
        :rtype: ResponseObject
        """
        url = routes.AGENTS

        if filters:
            url += "?" + filters

        response = self._cls.request(const.HTTPMethods.GET, url)
        return ResponseObject(response)

    def delete_agent(self, agent_id: int) -> ResponseObject:
        """
        Remove the specified agent

        :param int agent_id: id of the agent to be deleted
        :return: Response message for the DELETE method
        :rtype: ResponseObject
        """
        resource = '%s/%s' % (routes.AGENTS, agent_id)
        response = self._cls.request(const.HTTPMethods.DELETE, resource)
        return ResponseObject(response)

    def exclusions_list(self) -> ResponseObject:
        """
        Get a list of exclusions

        :return: Response message containing list of exclusions
        :rtype: ResponseObject
        """
        resource = '%s/exclusions' % routes.AGENTS
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def exclusions_add(self, data: dict) -> ResponseObject:
        """
        Add exclusions

        :param dict data: Payload to be passed for the request
        :return: Returns response message for POST method while adding exclusions
        :rtype: ResponseObject
        """
        resource = '%s/exclusions' % routes.AGENTS
        response = self._cls.request(const.HTTPMethods.POST, resource, json=data)
        return ResponseObject(response)

    def get_exclusion(self, exclusion_id: int) -> ResponseObject:
        """
        Get the specific exclusion information

        :param int exclusion_id: specific exclusion id for getting details
        :return: Response message containing exclusion details
        :rtype: ResponseObject
        """
        resource = '%s/exclusions/%s' % (routes.AGENTS, exclusion_id)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def edit_exclusion(self, exclusion_id: int, data: dict) -> ResponseObject:
        """
        Update the specified exclusion

        :param int exclusion_id: id for the exclusion to be edited
        :param dict data: Payload to be sent for PUT method
        :return: Response message for editing the exclusion
        :rtype: ResponseObject
        """
        resource = '%s/exclusions/%s' % (routes.AGENTS, exclusion_id)
        response = self._cls.request(const.HTTPMethods.PUT, resource, json=data)
        return ResponseObject(response)

    def remove_exclusion(self, exclusion_id: int) -> ResponseObject:
        """
        Remove the specified exclusion

        :param int exclusion_id: id of the exclusion to be deleted
        :return: Response message for deleting the exclusion
        :rtype: ResponseObject
        """
        resource = '%s/exclusions/%s' % (routes.AGENTS, exclusion_id)
        response = self._cls.request(const.HTTPMethods.DELETE, resource)
        return ResponseObject(response)

    def get_config(self) -> ResponseObject:
        """
        Get the configuration for agents

        :return: Response message containing config details
        :rtype: ResponseObject
        """
        resource = '%s/config' % routes.AGENTS
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def edit_config(self, data: dict) -> ResponseObject:
        """
        Update the agents configuration

        :param dict data: Payload to be passed for editing settings
        :return: Response message for editing the config settings
        :rtype: ResponseObject
        """
        resource = '%s/config' % routes.AGENTS
        response = self._cls.request(const.HTTPMethods.PUT, resource, json=data)
        return ResponseObject(response)

    def create_log_request_directive(self, agent_id: int, data: dict) -> ResponseObject:
        """
        create logs directive for agent

        :param int agent_id: agent id of agent
        :param dict data: payload for creating logs directive
        :return: response of directive creation
        :rtype: ResponseObject
        """
        resource = '%s/%s/get-logs' % (routes.AGENTS, agent_id)
        response = self._cls.request(const.HTTPMethods.POST, resource, json=data)
        return ResponseObject(response)

    # POST /agents/{agent_id}/download-log
    def download_logs(self, agent_id: int, data: dict = None) -> str:
        """
        Get download logs

        :param int agent_id: Id of agent
        :param dict data: Optional payload (e.g. {"log": "filename.log"})
        :return: response of download log
        :rtype: str
        """
        resource = '%s/%s/download-log' % (routes.AGENTS, agent_id)
        response = self._cls.request(const.HTTPMethods.POST, resource, json=data)
        return str(response.content)

    # DELETE /agents/unlink
    def agent_unlink(self, agent_id: int) -> ResponseObject:
        """
        Agent Unlink

        :param int agent_id: Id of agent
        :return: response of agent unlink
        :rtype: ResponseObject
        """
        resource = '%s/%s/unlink' % (routes.AGENTS, agent_id)
        response = self._cls.request(const.HTTPMethods.DELETE, resource)
        return ResponseObject(response)

    # DELETE  /directives/{directives_id}
    def delete_directive(self, directives_id: str) -> ResponseObject:
        """
        Delete directive

        :param str directives_id: Id of directive which get from log request
        :return: response of delete directive
        :rtype: ResponseObject
        """
        resource = '/directives/%s' % directives_id
        response = self._cls.request(const.HTTPMethods.DELETE, resource)
        return ResponseObject(response)

    def get_cluster_migration(self) -> ResponseObject:
        """
        Get cluster migration details
        
        :return: response of cluster migration setting details
        :rtype: ResponseObject
        """
        resource = '%s/cluster-migration' % routes.AGENTS
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def edit_cluster_migration(self, payload: dict) -> ResponseObject:
        """
        Update the cluster migration settings
        
        :param dict payload: Payload to be passed for cluster migration settings
        for eg: payload = {"cluster_migration_enabled": True, "cluster_migration_cluster_host": Parent node IP/ host,
                   "cluster_migration_cluster_port": linking port,
                   "cluster_migration_linking_key": linking key}
        :return: Response message for editing the cluster migration settings
        :rtype: ResponseObject
        """
        resource = '%s/cluster-migration' % routes.AGENTS
        response = self._cls.request(const.HTTPMethods.PUT, resource, json=payload)
        return ResponseObject(response)

    def export_agents(self, export_format: str = "csv") -> ResponseObject:
        """
        Export all agents in linked in Nessus Manager
        :param str export_format: Format to export agent lists
        :return: Response message containing token for agent exports
        :rtype: ResponseObject
        """
        resource = '%s/export' % routes.AGENTS
        response = self._cls.request(const.HTTPMethods.POST, resource, json={"format": export_format})
        return ResponseObject(response)

    def restart_remote_agent(self, agent_id: int, payload: dict) -> ResponseObject:
        """
        Restart Agent from NM remote settings

        :param int agent_id: Id of agent
        :param dict payload: Payload for restarting Agent
        for eg: payload = {"idle":False,"hard":False}

        :return: response of modifying settings
        :rtype: ResponseObject
        """
        resource = '%s/%s/restart' % (routes.AGENTS, agent_id)
        response = self._cls.request(const.HTTPMethods.POST, resource, json=payload)
        return ResponseObject(response)

    def set_remote_settings(self, agent_id: int, payload: dict) -> ResponseObject:
        """
        Set Agent settings from NM remote settings

        :param int agent_id: Id of agent
        :param dict payload: Payload for modifying Agent settings
        for eg: payload = {{"settings":[{"setting":"log_whole_attack","value":"false"}]}

        :return: response of modified settings
        :rtype: ResponseObject
        """
        resource = '%s/%s/%s' % (routes.AGENTS, agent_id, routes.SETTINGS)
        response = self._cls.request(const.HTTPMethods.POST, resource, json=payload)
        return ResponseObject(response)

    def unlink_multiple_agents(self, agent_ids: list) -> ResponseObject:
        """
        Unlink list of agents simultaneously.

        :param list agent_ids: linked Agent ID's
        :rtype: ResponseObject
        """
        resource = '%s/unlink' % routes.AGENTS
        response = self._cls.request(const.HTTPMethods.DELETE, resource, json={'ids': agent_ids})
        log.debug('Unlinked agent IDs %s', agent_ids)
        return ResponseObject(response)

    def apply_staged_remote_settings(self, agent_id: int, payload: dict) -> ResponseObject:
        """
        Apply staged Agent settings from NM remote settings

        :param int agent_id: Id of agent
        :param dict payload: Payload for applying Agent settings

        :return: response of modified settings
        :rtype: ResponseObject
        """
        resource = '%s/%s/%s' % (routes.AGENTS, agent_id, routes.SETTINGS)
        response = self._cls.request(const.HTTPMethods.PUT, resource, json=payload)
        return ResponseObject(response)

    def get_remote_settings(self, agent_id: int) -> ResponseObject:
        """
        Get Agent settings from NM remote settings

        :param int agent_id: Id of agent
        :return: response of existing settings
        :rtype: ResponseObject
        """
        resource = '%s/%s/%s' % (routes.AGENTS, agent_id, routes.SETTINGS)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def get_agent_update_channels_info_from_manager(self):
        """
        Get Agent update channels from NM agent updates page

        :return: response of agents/update-channels api endpoint
        :rtype: ResponseObject
        """
        resource = '%s/%s' % (routes.AGENTS, routes.UPDATE_CHANNELS)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def get_latest_agent_update_channels_endpoint(self):
        """
        Return the latest agent channels for endpoint

        :return: response of agents/update-channels api endpoint
        :rtype: ResponseObject
        """
        resource = '%s/%s/%s' % (routes.AGENTS, routes.UPDATE_CHANNELS, routes.LATEST)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def put_agent_update_channels_from_manager(self, payload: dict) -> ResponseObject:
        """
        PUT request for Agent update channels from NM agent updates page.

        payload: request payload in dict format
        :return: response of agents/update-channels api endpoint
        :rtype: ResponseObject
        """
        resource = '%s/%s' % (routes.AGENTS, routes.UPDATE_CHANNELS)
        response = self._cls.request(const.HTTPMethods.PUT, resource, json=payload)
        return ResponseObject(response)
