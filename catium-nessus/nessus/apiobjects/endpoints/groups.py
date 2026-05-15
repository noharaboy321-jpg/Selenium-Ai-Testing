"""
Nessus Groups Endpoint
"""
from catium.lib import const
from catium.lib.api.base_api_object import ResponseObject
from catium.lib.log import create_logger
from nessus.apiobjects import routes

log = create_logger()


class GroupsEndpoint(object):
    """Groups API Endpoint"""

    def __init__(self, cls):
        self._cls = cls

    def add_user(self, group_id: int, user_id: int, stream: bool = False) -> ResponseObject:
        """
        Add user to group

        :param int group_id: Group ID
        :param int user_id: User ID
        :param bool stream: False if need to get response text else True
        """
        resource = '%s/%s/users/%s' % (routes.GROUPS, group_id, user_id)
        response = self._cls.request(const.HTTPMethods.POST, resource, stream=stream)
        return ResponseObject(response)

    def create(self, name: str, stream: bool = False) -> ResponseObject:
        """
        Create a group

        :param str name: Name of the group
        :param bool stream: False if need to get response text else True
        """
        response = self._cls.request(const.HTTPMethods.POST, routes.GROUPS, json={'name': name}, stream=stream)
        return ResponseObject(response)

    def delete(self, group_id: int, stream: bool = False):
        """
        Delete a group

        :param int group_id: Group ID
        :param bool stream: False if need to get response text else True
        """
        self._cls.request(const.HTTPMethods.DELETE, routes.GROUPS + '/' + str(group_id), stream=stream)
        log.debug('Deleted group ID %s', group_id)

    def delete_user(self, group_id: int, user_id: int, stream: bool = False):
        """
        Delete user from group

        :param int group_id: Group ID
        :param int user_id: User ID
        :param bool stream: False if need to get response text else True
        """
        resource = '%s/%s/users/%s' % (routes.GROUPS, group_id, user_id)
        self._cls.request(const.HTTPMethods.DELETE, resource, stream=stream)
        log.debug('Deleted user ID "%s" from group ID "%s"', group_id, user_id)

    def edit(self, group_id: int, name: str, stream: bool = False) -> ResponseObject:
        """
        Edit a group

        :param int group_id: Group ID
        :param str name: Name of the group
        :param bool stream: False if need to get response text else True
        """
        response = self._cls.request(const.HTTPMethods.PUT, routes.GROUPS + '/' + str(group_id),
                                     json={'name': name}, stream=stream)
        return ResponseObject(response)

    def get_groups(self, stream: bool = False) -> ResponseObject:
        """
        Get a list of groups

        :param bool stream: False if need to get response text else True
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.GROUPS, stream=stream)
        return ResponseObject(response)

    def list_users(self, group_id: int, stream: bool = False) -> ResponseObject:
        """
        Get a list of users in group

        :param int group_id: Group ID
        :param bool stream: False if need to get response text else True
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.GROUPS + '/' + str(group_id) + '/users',
                                     stream=stream)
        return ResponseObject(response)

    def bulk_delete(self, group_list: list) -> ResponseObject:
        """
        Delete all groups

        :param list group_list : list of group ids to delete
        :return ResponseObject : return response of delete request
        """
        payload = {"ids": group_list}
        response = self._cls.request(const.HTTPMethods.DELETE, routes.GROUPS, json=payload)
        return ResponseObject(response)

    def group_details(self, group_id: int) -> ResponseObject:
        """
        Returns group details of given group id

        :param int group_id: Group ID
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.GROUPS + '/' + str(group_id))
        return ResponseObject(response)
