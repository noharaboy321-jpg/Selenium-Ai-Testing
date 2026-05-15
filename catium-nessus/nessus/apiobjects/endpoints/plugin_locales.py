"""
Nessus API Endpoint for plugin locales

:copyright: Tenable Network Security, 2024
:date: August 30, 2024.
:author: @krpatel
"""
from nessus.apiobjects import routes
from catium.lib import const
from catium.lib.api.base_api_object import ResponseObject


class PluginLocalesEndpoint(object):
    """Locales API Endpoint"""

    def __init__(self, cls):
        self._cls = cls

    def enable_disable_locales(self, data: dict) -> ResponseObject:
        """
        Enable or disable locales

        :param bool data: true or false
        """
        response = self._cls.request(const.HTTPMethods.PUT, routes.PLUGIN_LOCALES, json=data)
        return ResponseObject(response)

    def get_locales_details(self) -> ResponseObject:
        """
        get locales data

        :param : none
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.PLUGIN_LOCALES)
        return ResponseObject(response)

    def set_default_locales(self, data: dict) -> ResponseObject:
        """
        set locales data

        """
        response = self._cls.request(const.HTTPMethods.PUT, routes.PLUGIN_LOCALES, json=data)
        return ResponseObject(response)
