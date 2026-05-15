"""
Nessus Nodes Endpoint
"""
# pylint: disable=too-few-public-methods
from catium.lib import const
from catium.lib.api.base_api_object import ResponseObject
from catium.lib.log import create_logger
from nessus.apiobjects import routes

log = create_logger()


class NodesEndpoint:
    """Nodes API Endpoint"""

    def __init__(self, cls):
        self._cls = cls

    def get(self, node_id: int) -> ResponseObject:
        """
        Get the details for one node.

        :param int node_id: child node id
        :return: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, '/%s/%d' % (routes.NODES, node_id))
        return ResponseObject(response)

    def list(self) -> ResponseObject:
        """
        List the nodes.

        :return: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, '/%s' % routes.NODES)
        return ResponseObject(response)

    def delete(self, node_id: int) -> ResponseObject:
        """
        Delete a node.

        :param int node_id: child node id
        :return: ResponseObject        
        """
        response = self._cls.request(const.HTTPMethods.DELETE, '/%s/%d' % (routes.NODES, node_id))
        return ResponseObject(response)

    def settings(self, node_id: int, settings: dict):
        """
        Adjust settings for this node.

        :param int node_id: child node id
        :param dict settings: child node settings to be updated
        :return: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.PUT, '/%s/%d' % (routes.NODES, node_id), json=settings)
        return ResponseObject(response)

    def rebalance(self, cluster_group_id: int = None) -> ResponseObject:
        """
        Rebalance the cluster (or cluster group if given)

        :param int cluster_group_id: cluster group id
        ":return: ResponseObject
        """
        payload = {'cluster_group_id': cluster_group_id}
        response = self._cls.request(const.HTTPMethods.POST, '/%s/rebalance' % routes.NODES, json=payload)
        return ResponseObject(response)
