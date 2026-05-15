"""
Nessus API Endpoint for WAS

:copyright: Tenable Network Security, 2018
:date: August 07, 2018
:last_modified: August 22, 2018
:author: @jchavda
"""
from nessus.apiobjects import routes
from catium.lib import const
from catium.lib.api.base_api_object import ResponseObject


class WASEndpoint(object):
    """Settings API Endpoint"""

    def __init__(self, cls):
        self._cls = cls

    def toggle_was(self, data: dict) -> ResponseObject:
        """
        Enable or disable WAS

        :param bool data: true or false
        """
        response = self._cls.request(const.HTTPMethods.POST, routes.WAS, json=data)
        return ResponseObject(response)

    def download_was(self) -> ResponseObject:
        """
        Download WAS

        """
        response = self._cls.request(const.HTTPMethods.POST, routes.DOWNLOAD_WAS, json={})
        return ResponseObject(response)
