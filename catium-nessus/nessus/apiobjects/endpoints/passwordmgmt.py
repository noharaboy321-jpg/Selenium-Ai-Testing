"""Nessus password management  Endpoint"""

from catium.lib import const
from catium.lib.log import create_logger
from nessus.apiobjects import routes

log = create_logger()


class PasswordMgmtEndpoint(object):
    """password management API Endpoint"""

    def __init__(self, cls):
        self._cls = cls

    def configure(self, payload: dict):
        """
        Configure the password settings
        :param dict payload: used to pass param to POST request
        :return: none 
        """
        log.debug('Configuration param for password management: %s', payload)
        self._cls.request(const.HTTPMethods.POST, routes.PASSWORD_COMPLEXITY, json=payload)
