"""
Nessus Agent Groups Endpoint
"""
from nessus.apiobjects import routes
from catium.lib import const
from catium.lib.api.base_api_object import ResponseObject
from catium.lib.log import create_logger

log = create_logger()


class AgentGroupsEndpoint(object):
    """Agent Groups API Endpoint"""

    def __init__(self, cls):
        self._cls = cls

    def add_agent(self, scanner_id: int, group_id: int, agent_id: int):
        """
        Add agent to given agent group

        :param int scanner_id: Scanner ID
        :param int group_id: Agent Group ID
        :param int agent_id: Agent ID
        """
        resource = '%s/%s/agent-groups/%s/agents/%s' % (routes.SCANNERS, scanner_id, group_id, agent_id)
        self._cls.request(const.HTTPMethods.PUT, resource)

    def add_agents(self, group_id: int, agent_ids: list, stream:bool =False):
        """
        Adds the agents to given agent group

        :param int scanner_id: Scanner ID
        :param int group_id: Agent Group ID
        :param list agent_ids: List of Agent IDs
        :param bool stream: False if need to get response text else True
        """
        resource = '%s/%s/agents' % (routes.AGENT_GROUPS, group_id)
        self._cls.request(const.HTTPMethods.PUT, resource, json={'ids': agent_ids}, stream=stream)

    def configure(self, scanner_id: int, group_id: int, name: str, stream: bool=False):
        """
        Change the name of an agent group

        :param int scanner_id: Scanner ID
        :param int group_id: Agent Group ID
        :param str name: Name for the agent group
        :param bool stream: False if need to get response text else True
        """
        resource = '%s/%s/agent-groups/%s' % (routes.SCANNERS, scanner_id, group_id)
        self._cls.request(const.HTTPMethods.PUT, resource, json={'name': name}, stream=stream)

    def create(self, scanner_id: int, name: str, stream: bool=False) -> ResponseObject:
        """
        Create agent group on given scanner

        :param int scanner_id: Scanner ID
        :param str name: Name for the agent group
        :param bool stream: False if need to get response text else True
        """
        resource = '%s/%s/agent-groups' % (routes.SCANNERS, scanner_id)
        response = self._cls.request(const.HTTPMethods.POST, resource, json={'name': name}, stream=stream)
        return ResponseObject(response)

    def delete(self, scanner_id: int, group_id: int, stream: bool=False):
        """
        Delete agent group from given scanner

        :param int scanner_id: Scanner ID
        :param int group_id: Agent Group ID
        :param bool stream: False if need to get response text else True
        """
        resource = '%s/%s/agent-groups/%s' % (routes.SCANNERS, scanner_id, group_id)
        self._cls.request(const.HTTPMethods.DELETE, resource, stream=stream)
        log.debug('Deleted agent group ID %s', group_id)

    def delete_agent(self, scanner_id: int, group_id: int, agent_id: int):
        """
        Deletes an agent from the given agent group

        :param int scanner_id: Scanner ID
        :param int group_id: Agent Group ID
        :param int agent_id: ID of agent to remove
        """
        resource = '%s/%s/agent-groups/%s/agents/%s' % (routes.SCANNERS, scanner_id, group_id, agent_id)
        self._cls.request(const.HTTPMethods.DELETE, resource)

    def delete_agents(self, group_id: int, agent_ids: list, stream: bool=False):
        """
        Deletes a list of agents from the given agent group

        :param int group_id: Agent Group ID
        :param list agent_ids: List of IDs to remove
        :param bool stream: False if need to get response text else True
        """
        resource = '%s/%s/agents' % (routes.AGENT_GROUPS, group_id)
        self._cls.request(const.HTTPMethods.DELETE, resource, json={'ids': agent_ids}, stream=stream)

    def details(self, scanner_id: int, group_id: int, stream: bool=False) -> ResponseObject:
        """
        Returns details for the given agent group

        :param int scanner_id: Scanner ID
        :param int group_id: ID of agent group to query
        :param bool stream: False if need to get response text else True
        """
        resource = '%s/%s/agent-groups/%s' % (routes.SCANNERS, scanner_id, group_id)
        response = self._cls.request(const.HTTPMethods.GET, resource, stream=stream)
        return ResponseObject(response)

    def get_list(self, scanner_id: int, stream: bool=False) -> ResponseObject:
        """
        Returns the agent groups for the given scanner

        :param int scanner_id: Scanner ID
        :param bool stream: False if need to get response text else True
        """
        resource = '%s/%s/agent-groups' % (routes.SCANNERS, scanner_id)
        response = self._cls.request(const.HTTPMethods.GET, resource, stream=stream)
        return ResponseObject(response)

    def agent_group_list(self) -> ResponseObject:
        """
        Returns list of agent groups
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.AGENT_GROUPS)
        return ResponseObject(response)

    def create_agent_group(self, name: str) -> ResponseObject:
        """
        Create agent group

        :param str name: Name for the agent group
        """
        response = self._cls.request(const.HTTPMethods.POST, routes.AGENT_GROUPS, json={'name': name})
        return ResponseObject(response)

    def delete_groups(self, id_list: list) -> ResponseObject:
        """
        remove agent groups specified by group id
        :param list id_list: list of group ids to delete
        :return: return response of delete request
        :rtype: ResponseObject
        """
        payload = {"ids": id_list}
        response = self._cls.request(const.HTTPMethods.DELETE, routes.AGENT_GROUPS, json=payload)
        return ResponseObject(response)

    def get_agent_group(self, group_id: int) -> ResponseObject:
        """
        Get the details of the specific agent group
        """
        resource = '%s/%s' % (routes.AGENT_GROUPS, group_id)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def update_agent_group(self, group_id: int, data: dict) -> ResponseObject:
        """
        Update the specified agent group
        """
        resource = '%s/%s' % (routes.AGENT_GROUPS, group_id)
        response = self._cls.request(const.HTTPMethods.PUT, resource, json=data)
        return ResponseObject(response)

    def delete_agent_group(self, group_id: int) -> ResponseObject:
        """
        Remove the specified agent group
        """
        resource = '%s/%s' % (routes.AGENT_GROUPS, group_id)
        response = self._cls.request(const.HTTPMethods.DELETE, resource)
        return ResponseObject(response)

    def list_agents(self, group_id: int) -> ResponseObject:
        """
        Get a list of agents in the specified agent group
        """
        resource = '%s/%s/agents' % (routes.AGENT_GROUPS, group_id)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def update_agent(self, group_id: int, agent_id: int) -> ResponseObject:
        """
        Update an agent in an agent group
        """
        resource = '%s/%s/agents/%s' % (routes.AGENT_GROUPS, group_id, agent_id)
        response = self._cls.request(const.HTTPMethods.PUT, resource)
        return ResponseObject(response)

    def delete_this_agent(self, group_id: int, agent_id: int) -> ResponseObject:
        """
        Remove the specified agent from the specified agent group
        """
        resource = '%s/%s/agents/%s' % (routes.AGENT_GROUPS, group_id, agent_id)
        response = self._cls.request(const.HTTPMethods.DELETE, resource)
        return ResponseObject(response)

    def add_agents_using_filter(self, filter_dict: dict, group_id: int) -> None:
        """
        Add agents to agent group as per the filter given
        :param dict filter_dict: Filter to get agents
        :param int group_id: Agent Group ID
        :return: None
        """
        resource = '%s/agents' % routes.AGENT_GROUPS
        payload = filter_dict
        if group_id:
            payload["groups"] = [str(group_id)]
        self._cls.request(const.HTTPMethods.PUT, resource, json=payload)

    def delete_agents_using_filter(self, group_id: int, filter_dict: dict):
        """
        Deletes agents from the given agent group as per the filter data given.

        :param int group_id: Agent Group ID
        :param dict filter_dict: Filter of agents which needs to be removed
        :return: None
        """
        resource = '%s/%s/agents' % (routes.AGENT_GROUPS, group_id)
        self._cls.request(const.HTTPMethods.DELETE, resource, json=filter_dict)

    def get_agents_in_agent_groups(self, group_id, filter_query) -> ResponseObject:
        """
        Returns agents list in agent group as per the filter query.
        :param int group_id: Agent Group ID
        :param str filter_query: Query to apply filter for agents in agent group
        :return: response which has agents list
        :rtype: ResponseObject
        """
        resource = '%s/%s?%s' % (routes.AGENT_GROUPS, group_id, filter_query)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def set_scanner_linking_key(self, scanner_key,
                                linking_key_type: str = routes.LINKING_KEY_TYPES[0]) -> ResponseObject:
        """
        Set the key of the requested scanner for 10.4.0+
        :param str linking_key_type: Linking key type - routes.LINKING_KEY_TYPES
        :param scanner_key: keys 64 chars
        :return: ResponseObject
        """
        # scanner_key = random_alphanumeric_string_for_linking_key(64)
        scanner_payload = {"linkingKey": f"{scanner_key}"}

        response = self._cls.request(const.HTTPMethods.PUT, routes.LINKING_KEYS + '/' + linking_key_type,
                                     json=scanner_payload)
        return ResponseObject(response)

    def set_agent_linking_key(self, agent_key, linking_key_type: str = routes.LINKING_KEY_TYPES[1]) -> ResponseObject:
        """
        Set the key of the requested agent for 10.4.0+
        :param str linking_key_type: Linking key type - routes.LINKING_KEY_TYPES
        :param agent_key: keys 64 char.
        :return: ResponseObject
        """
        # agent_key = random_alphanumeric_string_for_linking_key(64)
        agent_payload = {"linkingKey": f"{agent_key}"}

        response = self._cls.request(const.HTTPMethods.PUT, routes.LINKING_KEYS + '/' + linking_key_type,
                                     json=agent_payload)
        return ResponseObject(response)

    def set_child_node_linking_key(self, node_key, linking_key_type: str = routes.LINKING_KEY_TYPES[2]) -> ResponseObject:
        """
        Set the key of the requested child node for 10.4.0+
        :param str linking_key_type: Linking key type - routes.LINKING_KEY_TYPES
        :param node_key: key 64 chars
        :return: ResponseObject
        """
        # node_key = random_alphanumeric_string_for_linking_key(64)
        node_payload = {"linkingKey": f"{node_key}"}

        response = self._cls.request(const.HTTPMethods.PUT, routes.LINKING_KEYS + '/' + linking_key_type,
                                     json=node_payload)
        return ResponseObject(response)
