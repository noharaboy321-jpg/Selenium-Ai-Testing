"""
Nessus Plugins Endpoint
"""
from catium.lib import const
from catium.lib.api.base_api_object import ResponseObject
from nessus.apiobjects import routes


class PluginsEndpoint(object):
    """Plugins API Endpoint"""

    def __init__(self, cls):
        self._cls = cls

    def families(self) -> ResponseObject:
        """Returns a list of plugin families"""
        response = self._cls.request(const.HTTPMethods.GET, routes.PLUGINS + '/families')
        return ResponseObject(response)

    def family_details(self, family_id: int) -> ResponseObject:
        """
        Returns a list of plugins in a family

        :param int family_id: ID of the family
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.PLUGINS + '/families/' + str(family_id))
        return ResponseObject(response)

    def plugin_details(self, plugin_id: int) -> ResponseObject:
        """
        Returns the details of a plugin

        :param int plugin_id: ID of the plugin
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.PLUGINS + '/plugin/' + str(plugin_id))
        return ResponseObject(response)

    def list_plugin_rules(self) -> ResponseObject:
        """
        Return the plugin rules list
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.PLUGIN_RULES)
        return ResponseObject(response)

    def add_plugin_rules(self, data: dict) -> ResponseObject:
        """
        Add/Edit plugin rules
        """
        response = self._cls.request(const.HTTPMethods.POST, routes.PLUGIN_RULES, json=data)
        return ResponseObject(response)

    def bulk_delete(self, id_list: list) -> ResponseObject:
        """
        Remove all plugin rules
        :param id_list: list of plugin ids to delete
        :return: response for delete all plugin rules
        :rtype: ResponseObject
        """
        payload = {"ids": id_list}
        response = self._cls.request(const.HTTPMethods.DELETE, routes.PLUGIN_RULES, json=payload)
        return ResponseObject(response)

    def get_plugin_rule(self, plugin_id: int) -> ResponseObject:
        """
        Get details for a plugin rule
        """
        resource = '%s/%s' % (routes.PLUGIN_RULES, plugin_id)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def edit_plugin_rule(self, plugin_id: int, data: dict) -> ResponseObject:
        """
        Update details for plugin rule
        """
        resource = '%s/%s' % (routes.PLUGIN_RULES, plugin_id)
        response = self._cls.request(const.HTTPMethods.PUT, resource, json=data)
        return ResponseObject(response)

    def delete_plugin_rule(self, plugin_id: int) -> ResponseObject:
        """
        Remove a plugin rule
        """
        resource = '%s/%s' % (routes.PLUGIN_RULES, plugin_id)
        response = self._cls.request(const.HTTPMethods.DELETE, resource)
        return ResponseObject(response)
