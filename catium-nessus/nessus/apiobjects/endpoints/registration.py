"""
Nessus Registration Endpoint
"""
from catium.lib import const
from catium.lib.api.base_api_object import ResponseObject
from catium.lib.log import create_logger
from nessus.apiobjects import routes

log = create_logger()


class RegistrationEndpoint:
    """Registration API Endpoint"""

    def __init__(self, cls):
        self._cls = cls

    def send_essentials_email(self, firstName: str = None, lastName: str = None, email: str = None) -> ResponseObject:
        """
        Send a Nessus Essentials activation email
        refer to the form on https://www.tenable.com/products/nessus/nessus-essentials

        :param str firstName: First Name
        :param str lastName: Last Name
        :param str email: Email Address
        :returns: API response
        :rtype: ResponseObject
        """
        payload = {}
        if firstName:
            payload['firstName'] = firstName
        if lastName:
            payload['lastName'] = lastName
        if email:
            payload['email'] = email
        resource = '%s/send-essentials-email' % (routes.REGISTRATION)
        response = self._cls.request(const.HTTPMethods.POST, resource, json=payload)
        return ResponseObject(response)
