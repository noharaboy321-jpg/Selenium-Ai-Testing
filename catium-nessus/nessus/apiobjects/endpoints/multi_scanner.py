"""
Nessus MultiScanner Endpoint
"""
from catium.lib import const
from catium.lib.api.base_api_object import ResponseObject
from nessus.apiobjects import routes


class MultiScannerEndpoint(object):
    """ Multi-scanner API Endpoint """

    def __init__(self, cls):
        self._cls = cls

    def register(self, payload: dict) -> ResponseObject:
        """
        Register multi-scanner

        :param dict payload: multi-scanner info as dict
        :return: Response for POST request
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.POST, routes.MULTI_SCANNER + '/register', json=payload)
        return ResponseObject(response)

    def delete(self) -> ResponseObject:
        """
        Delete multi-scanner

        :return: Response for POST request
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.POST, routes.MULTI_SCANNER + '/remote/delete')
        return ResponseObject(response)

    def edit(self, data: dict) -> ResponseObject:
        """
        Edit a multi-scanner remote object

        :param dict data: multi-scanner info as dict
        :return: Response for POST request
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.POST, routes.MULTI_SCANNER + '/remote/edit', json=data)
        return ResponseObject(response)

    def get_jobs(self, payload: dict) -> ResponseObject:
        """
        Get jobs for multi-scanner object

        :param dict payload: multi-scanner info as dict
        :return: Response for POST request
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.POST, routes.MULTI_SCANNER + '/remote/ping', json=payload)
        return ResponseObject(response)

    def edit_job(self,  data: dict) -> ResponseObject:
        """
        Edit a multi-scanner job

        :param dict data: multi-scanner job info as dict
        :return: Response for POST request
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.POST, routes.MULTI_SCANNER + '/remote/job', json=data)
        return ResponseObject(response)

    def get_policy(self, data: dict) -> ResponseObject:
        """
        Get policy for multi-scanner object
        :param dict data: multi-scanner policy info as dict
        :return: Response for POST request
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.POST, routes.MULTI_SCANNER + '/remote/policy', json=data)
        return ResponseObject(response)

    def file_upload(self, data: dict) -> ResponseObject:
        """
        Upload a file to a multi-scanner

        :param dict data: file info as dict
        :return: Response for POST request
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.POST, routes.MULTI_SCANNER + '/file/upload', json=data)
        return ResponseObject(response)
