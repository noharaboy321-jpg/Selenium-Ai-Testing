"""
Nessus Session Endpoint
"""
from nessus.apiobjects import routes
from catium.lib import const
from catium.lib.api.base_api_object import ResponseObject
from catium.lib.log import create_logger

log = create_logger()


class SessionEndpoint(object):
    """Session API Endpoint"""

    def __init__(self, cls):
        self._cls = cls

    def create(self, username: str, password: str) -> str:
        """
        Creates a new session token for the given user

        :param str username: Username
        :param str password: Password
        :returns: str, session token
        """
        credentials = {'username': username, 'password': password}
        response = self._cls.request(const.HTTPMethods.POST, routes.SESSION, json=credentials)
        session = ResponseObject(response)

        self._cls.session_token = session['token']
        self._cls.session_headers = {'X-Cookie': 'token=' + self._cls.session_token}
        log.debug('Nessus Session Token Generated: ' + self._cls.session_token)
        return session['token']

    def delete(self):
        """Destroys an active Nessus session"""
        response = self._cls.request(const.HTTPMethods.DELETE, routes.SESSION)
        log.debug('Deleted Nessus Session ' + self._cls.session_token)
        return ResponseObject(response)

    def edit(self, name: str, email: str):
        """
        Changes current user settings.

        :param str name: Full name for user
        :param str email: Email address for user
        """
        response = self._cls.request(const.HTTPMethods.PUT, routes.SESSION, json={'name': name, 'email': email})
        log.debug('Nessus session edited. (name: %s, email: %s)', name, email)
        return ResponseObject(response)

    def get(self) -> ResponseObject:
        """Returns the session data for the current user"""
        response = self._cls.request(const.HTTPMethods.GET, routes.SESSION)
        return ResponseObject(response)

    def password(self, current_password: str, new_password: str):
        """
        Changes password for the current user.

        :param str current_password: Current password for user
        :param str new_password: New password for user
        """
        params = {'current_password': current_password, 'password': new_password}
        response = self._cls.request(const.HTTPMethods.PUT, routes.SESSION + '/chpasswd', json=params)
        return ResponseObject(response)

    def generate_keys(self) -> ResponseObject:
        """Generates API keys for the current user"""
        response = self._cls.request(const.HTTPMethods.PUT, routes.SESSION + '/keys')
        return ResponseObject(response)
