"""
Nessus Tokens Endpoint
"""
from catium.lib import const
from catium.lib.api.base_api_object import ResponseObject
from catium.lib.log.log import create_logger
from nessus.apiobjects import routes

log = create_logger()


class TokensEndpoint(object):
    """Tokens API Endpoint"""

    def __init__(self, cls):
        self._cls = cls

    def download(self, token_id: str) -> ResponseObject:
        """
        Get token
        """
        resource = '%s/%s/download' % (routes.TOKENS, token_id)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def download_file(self, token_id: str) -> bytes:
        """
        Download file data for token
        """
        resource = '%s/%s/download' % (routes.TOKENS, token_id)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return response.content

    def status(self, token_id: str, stream: bool = False) -> ResponseObject:
        """
        Get the status of a token
        """
        resource = '%s/%s/status' % (routes.TOKENS, token_id)
        response = self._cls.request(const.HTTPMethods.GET, resource, stream=stream)
        if not stream:
            log.debug("Server response is : {}".format(response))
        return ResponseObject(response)

    def cancel(self, token_id: int) -> ResponseObject:
        """
        Delete the token
        :param str token_id: token to be delete
        :return: Response object for the request
        :rtype: ResponseObject
        """
        resource = '%s/%s/cancel' % (routes.TOKENS, token_id)
        response = self._cls.request(const.HTTPMethods.POST, resource)
        return ResponseObject(response)
