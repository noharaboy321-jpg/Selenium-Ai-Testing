"""
Nessus Cluster Groups Endpoint
"""
from catium.lib import const
from catium.lib.api.base_api_object import ResponseObject
from catium.lib.log import create_logger
# pylint: disable=too-few-public-methods
from nessus.apiobjects import routes

log = create_logger()


class ClusterGroupsEndpoint:
    """ClusterGroups API Endpoint"""

    def __init__(self, cls):
        self._cls = cls

    def add(self, cluster_group: str) -> ResponseObject:
        """
        Create a cluster group.

        :param str cluster_group: cluster group name
        :return: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.POST, '/%s' % routes.CLUSTER_GROUPS,
                                     json={'cluster_group': cluster_group})
        return ResponseObject(response)

    def get(self, cluster_group_id: int) -> ResponseObject:
        """
        Get a single cluster group's info.

        :param int cluster_group_id: cluster group id
        :return: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, '/%s/%d' % (routes.CLUSTER_GROUPS, cluster_group_id))
        return ResponseObject(response)

    def list(self) -> ResponseObject:
        """
        List the cluster groups.

        :return: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, '/%s' % routes.CLUSTER_GROUPS)
        return ResponseObject(response)

    def update(self, cluster_group_id: int, cluster_group: dict) -> ResponseObject:
        """
        Update a cluster group.

        :param int cluster_group_id: cluster group id
        :param dict cluster_group: details of cluster group to be update
        :return: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.PUT, '/%s/%d' % (routes.CLUSTER_GROUPS, cluster_group_id),
                                     json=cluster_group)
        return ResponseObject(response)

    def delete(self, cluster_group_id: int) -> ResponseObject:
        """
        Delete a cluster group.

        :param int cluster_group_id: cluster group id
        :return: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.DELETE, '/%s/%d' % (routes.CLUSTER_GROUPS, cluster_group_id))
        return ResponseObject(response)

    def assign_node(self, cluster_group_id: int, node_id: int) -> ResponseObject:
        """
        Assign a node to a cluster group.

        :param int cluster_group_id: cluster group id
        :param int node_id: node id to be moved
        :return: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.PUT, '/%s/member/%d' % (routes.CLUSTER_GROUPS, node_id),
                                     json={'cluster_group_id': cluster_group_id})
        return ResponseObject(response)

    def assign_agents(self, cluster_group_id: int, agent_ids: list) -> ResponseObject:
        """
        Assign agents to a cluster group.

        :param int cluster_group_id: cluster group id
        :param list agent_ids: list of agent ids to be assigned
        :return: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.PUT, '/%s/%d/agents' % (routes.CLUSTER_GROUPS, cluster_group_id),
                                     json={'ids': agent_ids})
        return ResponseObject(response)

    def get_cluster_group_agents(self, cluster_group_id: int) -> ResponseObject:
        """
        Fetch agents associated with particular cluster group.

        :param int cluster_group_id: cluster group id
        :return: ResponseObject
        """
        resource = "/%s?cluster_group_id=%d" % (routes.AGENTS, cluster_group_id)

        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def get_cluster_group_nodes(self, cluster_group_id: int) -> ResponseObject:
        """
        Fetch nodes associated with particular cluster group.

        :param int cluster_group_id: cluster group id
        :return: ResponseObject
        """
        resource = "/%s?cluster_group_id=%d" % (routes.NODES, cluster_group_id)

        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def get_assigned_cluster_group_agents(self, cluster_group_id: int) -> ResponseObject:
        """
        Returns assigned cluster agents from given cluster group.

        :param int cluster_group_id: cluster group id
        :return: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, '/%s/%d/agents' % (routes.CLUSTER_GROUPS, cluster_group_id))
        return ResponseObject(response)
