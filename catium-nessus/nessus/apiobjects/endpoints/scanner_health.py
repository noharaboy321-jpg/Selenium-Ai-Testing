"""
Nessus Scanner Health Endpoint

:copyright: Tenable Network Security, 2019
:date: May 28, 2019
:last_modified: June 04, 2019
:author: @kpanchal
"""

from catium.lib import const
from catium.lib.api.base_api_object import ResponseObject
from nessus.apiobjects import routes


class ScannerHealthEndpoint(object):
    """ Scanner Health API Endpoints """

    def __init__(self, cls):
        self._cls = cls

    def get_alerts(self, start_time: int=None, end_time: int=None) -> ResponseObject:
        """
        Retrieves information about alerts

        :param int start_time: Start time of scan
        :param int end_time: End time of scan
        :return: ResponseObject
        """
        resource = '%s/alerts' % routes.SCANNER_HEALTH
        params = {}

        if start_time:
            params['start_time'] = start_time
        if end_time:
            params['end_time'] = end_time

        response = self._cls.request(const.HTTPMethods.GET, resource, params=params)
        return ResponseObject(response)

    def get_stats(self, start_time: int=None, end_time: int=None, count: int=None) -> ResponseObject:
        """
        Retrieves information about Scanner Health

        :param int start_time: Start time of scan
        :param int end_time: End time of scan
        :param int count: Scan history count 
        :return: ResponseObject
        """
        resource = '%s/stats' % routes.SCANNER_HEALTH
        params = {}

        if start_time:
            params['start_time'] = start_time
        if end_time:
            params['end_time'] = end_time
        if count:
            params['count'] = count

        response = self._cls.request(const.HTTPMethods.GET, resource, params=params)
        return ResponseObject(response)
