"""
Nessus Agent Profiles Endpoint
"""
from nessus.apiobjects import routes
from catium.lib import const
from catium.lib.api.base_api_object import ResponseObject
from catium.lib.log import create_logger

log = create_logger()


class ProfilesEndpoint(object):
    """Profiles API Endpoint"""

    def __init__(self, cls):
        self._cls = cls

    def create(self, name: str, description: str, config: str) -> ResponseObject:
        """
        Create profile
        :param str name: Name for the profile
        :param str description: Description for the profile
        :param str config: Config data for the profile
        """
        response = self._cls.request(const.HTTPMethods.POST, routes.PROFILES,
                                     json={'name': name, 'description': description, 'config': config})
        return ResponseObject(response)

    def delete_profiles(self, uuid_list: list) -> ResponseObject:
        """
        remove profiles specified by profile_uuids
        :param list uuid_list: list of profile uuids to delete
        :return: return response of delete request
        :rtype: ResponseObject
        """
        payload = {"profile_uuids": uuid_list}
        response = self._cls.request(const.HTTPMethods.DELETE, routes.PROFILES, json=payload)
        return ResponseObject(response)

    def profile_list(self) -> ResponseObject:
        """
        Returns list of profiles
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.PROFILES)
        return ResponseObject(response)

    def get_profile(self, profile_uuid: str) -> ResponseObject:
        """
        Returns profile
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.PROFILES+ '/' + profile_uuid)
        return ResponseObject(response)

    def update_profile(self, profile_uuid: str, payload: dict) -> ResponseObject:
        """
        Returns updated profile if succeeded

        :param profile_uuid
        :param payload
        :returns: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.PUT, routes.PROFILES + '/' + profile_uuid, json=payload)
        return ResponseObject(response)

    def add_profile_members(self, profile_uuid: str, filters: str, agent_ids: list) -> ResponseObject:
        """
        Add agents to the profile
        """
        payload = {'ids': agent_ids}
        url = routes.PROFILES + '/' + profile_uuid + '/agents'
        if filters:
            url += "?" + filters
        response = self._cls.request(const.HTTPMethods.PUT, url, json=payload)
        return ResponseObject(response)

    def remove_profile_members(self, profile_uuid: str, filters: str, agent_ids: list) -> ResponseObject:
        """
        Remove agents from the profile
        """
        payload = {'ids': agent_ids}
        url = routes.PROFILES + '/' + profile_uuid + '/agents'
        if filters:
            url += "?" + filters
        response = self._cls.request(const.HTTPMethods.DELETE, url, json=payload)
        return ResponseObject(response)

    def get_profile_members(self, profile_uuid: str) -> ResponseObject:
        """
        Add agents to the profile
        """
        response = self._cls.request(const.HTTPMethods.GET,
            routes.PROFILES + '/' + profile_uuid + '/agents')
        return ResponseObject(response)


    def change_agent_profile(self, profile_uuid: str, agent_id: str) -> ResponseObject:
        """
        Change agent's profile
        """
        response = self._cls.request(const.HTTPMethods.PUT,
            routes.PROFILES + '/' + profile_uuid + '/agents/' + agent_id)
        return ResponseObject(response)

    def remove_agent_profile(self, profile_uuid: str, agent_id: int) -> ResponseObject:
        """
        Remove agent's profile
        """
        response = self._cls.request(const.HTTPMethods.DELETE,
            routes.PROFILES + '/' + profile_uuid + '/agents/' + agent_id)
        return ResponseObject(response)

    def bulk_remove_profile_members(self, filters: str, agent_ids: list) -> ResponseObject:
        """
        Bulk remove agent's profile
        """
        payload = {'ids': agent_ids}
        url = routes.PROFILES + '/agents'
        if filters:
            url += "?" + filters
        response = self._cls.request(const.HTTPMethods.DELETE, url, json=payload)
        return ResponseObject(response)
