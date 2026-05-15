"""
Nessus Mail Endpoint
"""
from catium.lib import const
from catium.lib.api.base_api_object import ResponseObject
from catium.lib.log import create_logger
from nessus.apiobjects import routes

log = create_logger()


class MailEndpoint(object):
    """Mail API Endpoint"""

    def __init__(self, cls):
        self._cls = cls

    def change(self, smtp_auth: str, smtp_enc: str, **kwargs):
        """
        Change mail server settings

        :param str smtp_auth: Mail server authentication type
        :param str smtp_enc: Encryption protocol to use
        :param dict kwargs: Keyword arguments

        Kwargs:
            smtp_host (str): Mail server host
            smtp_port (int): Mail server port
            smtp_from (str): Sender of mail messages
            smtp_www_host (str): Host to use in email links
            smtp_user (str): Sender's username
            smtp_pass (str): Sender's password
        """
        kwargs.setdefault('smtp_host', None)
        kwargs.setdefault('smtp_port', None)
        kwargs.setdefault('smtp_from', None)
        kwargs.setdefault('smtp_www_host', None)
        kwargs.setdefault('smtp_user', None)
        kwargs.setdefault('smtp_pass', None)

        params = {(key, val) for (key, val) in kwargs.items() if val is not None}
        params.add({'smtp_auth': smtp_auth, 'smtp_enc': smtp_enc})

        self._cls.request(const.HTTPMethods.PUT, routes.MAIL, json=params)

    def view(self) -> ResponseObject:
        """Returns the mail server settings"""
        response = self._cls.request(const.HTTPMethods.GET, routes.MAIL)
        return ResponseObject(response)
