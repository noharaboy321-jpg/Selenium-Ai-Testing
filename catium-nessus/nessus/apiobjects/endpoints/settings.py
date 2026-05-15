"""
Nessus API Endpoint for Settings

:copyright: Tenable Network Security, 2018
:date: August 07, 2018
:last_modified: August 22, 2018
:author: @jchavda
"""
from nessus.apiobjects import routes
from catium.lib import const
from catium.lib.api.base_api_object import ResponseObject


# TODO Change string formatting to use .format()
class SettingsEndpoint(object):
    """Settings API Endpoint"""

    def __init__(self, cls):
        self._cls = cls

    def get_link(self) -> ResponseObject:
        """
        Returns the local scanner Nessus Manager link settings

        :returns: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, '%s/scanner' % routes.SETTINGS)
        return ResponseObject(response)

    def get_list(self, version=None) -> ResponseObject:
        """
        Returns the list of advanced settings

        :returns: ResponseObject
        """
        headers = self._cls._session_headers.copy()
        if version:
            headers['X-API-Version'] = str(version)
        response = self._cls.request(const.HTTPMethods.GET, '%s/advanced' % routes.SETTINGS, headers=headers)
        return ResponseObject(response)

    def rekey(self, payload: dict=None) -> ResponseObject:
        """
        Generates a new linking key

        .. note:: A key is sequence of characters used to link external scanners agents to the scanner
        :param dict payload: Custom key value {"key":"qwees123sddf80adffdgdf8sdsdfassfg8dfssdcv8dfgcvsddfdgsd9sdfv0fds"}
        :returns: ResponseObject
        """
        if payload:
            response = self._cls.request(const.HTTPMethods.POST, '%s/scanner/rekey' % routes.SETTINGS, json=payload)
        else:
            response = self._cls.request(const.HTTPMethods.POST, '%s/scanner/rekey' % routes.SETTINGS)
        return ResponseObject(response)

    def get_key(self) -> ResponseObject:
        """
        Returns the key of the local scanner

        .. note:: A key is sequence of characters used to link external scanners agents to the scanner

        :returns: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, '%s/scanner/key' % routes.SETTINGS)
        return ResponseObject(response)

    # TODO: Convert to kwargs
    def set_link(self, name: str, host: str = None, port: int = None, key: str = None, use_proxy: bool = False,
                 unlink: bool = False) -> None:
        """
        Links the local scanner to a Nessus Manager

        :param str name: A name to identify the current scanner
        :param str host: IP/Hostname of the Nessus Manager
        :param int port: Port on the Nessus Manager to connect to
        :param str key: Key of the Nessus Manager to link to
        :param bool use_proxy: Set to True to use the configured proxy server to connect through
        :param bool unlink: Used to unlink scanner

        :returns: None
        """
        payload = {'name': name, 'use_proxy': use_proxy}

        if host and port:
            payload['linked_to'] = {'ip': host, 'port': port}
        if key:
            payload['key'] = key

        if unlink:
            payload['linked_to'] = None
        self._cls.request(const.HTTPMethods.PUT, '%s/scanner' % routes.SETTINGS, json=payload)

    def update(self, settings: dict) -> None:
        """
        Updates the advanced settings

        .. note:: You MUST first retrieve the existing settings via the get_list() call and update or append accordingly

        :param dict settings: New settings dictionary

        :returns: ResponseObject
        """
        self._cls.request(const.HTTPMethods.PUT, '%s/advanced' % routes.SETTINGS, json=settings)

# region LDAP Settings
    def get_ldap_settings(self) -> ResponseObject:
        """
        Gets the current LDAP Settings on the Nessus Manager.
        :returns: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, '%s/network/ldap' % routes.SETTINGS)
        return ResponseObject(response)

    def set_ldap_settings(self, settings: dict, stream:bool =False) -> None:
        """
        Updates LDAP Settings on the Nessus Scanner.

        :param dict settings: LDAP settings dictionary
        :param bool stream: False if need to get response text else True
        """
        self._cls.request(const.HTTPMethods.PUT, '%s/network/ldap' % routes.SETTINGS, json=settings, stream=stream)

    def test_ldap_settings(self, settings: dict, stream: bool=False) -> ResponseObject:
        """
        Tests the LDAP Settings on the Nessus Scanner.

        :param dict settings: LDAP settings dictionary
        :param bool stream: False if need to get response text else True
        :returns: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.POST, '%s/network/ldap/test' % routes.SETTINGS, json=settings,
                                     stream=stream)
        return ResponseObject(response)

    def search_ldap(self, name: dict, stream: bool=False) -> ResponseObject:
        """
        Searches for the specified user via LDAP.

        :param str name: LDAP User to search for
        :param bool stream: False if need to get response text else True
        :returns: ResponseObject
        """
        payload = {"name": name}
        response = self._cls.request(const.HTTPMethods.POST, '%s/network/ldap/search' % routes.SETTINGS, json=payload,
                                     stream=stream)
        return ResponseObject(response)
# endregion

# region SMTP Settings
    def test_smtp_settings(self, settings: dict) -> ResponseObject:
        """
        Tests the SMTP Settings on the Nessus Scanner.

        :param dict settings: SMTP settings dictionary
        :returns: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.POST, '%s/network/mail/test' % routes.SETTINGS, json=settings)
        return ResponseObject(response)

    def set_smtp_settings(self, settings: dict) -> None:
        """
        Updates SMTP Settings on the Nessus Scanner.

        :param dict settings: SMTP settings dictionary
        """
        self._cls.request(const.HTTPMethods.PUT, '%s/network/mail' % routes.SETTINGS, json=settings)

    def get_smtp_settings(self) -> None:
        """
        Retrieves SMTP Settings on the Nessus Scanner.

        :returns: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, '%s/network/mail' % routes.SETTINGS)
        return ResponseObject(response)
# endregion

    def test_proxy(self, host: str=None, port: int=None, username: str=None, password: str=None,
                   proxy_auth: str='auto', user_agent: str=None) -> ResponseObject:
        """
        Test Proxy Settings on the Nessus Scanner.
        :param str host: proxy host
        :param int port: proxy port 
        :param str username: proxy username
        :param str password: proxy password
        :param str proxy_auth: auth type for proxy
        :param str user_agent: proxy user agent
        :return: ResponseObject from test proxy
        :rtype ResponseObject
        """
        payload = {"proxy": host, "proxy_port": port, "proxy_username": username, "proxy_password": password,
                   "proxy_auth": proxy_auth, "user_agent": user_agent}
        response = self._cls.request(const.HTTPMethods.POST, '%s/network/proxy/test' % routes.SETTINGS, json=payload)
        return ResponseObject(response)

    def set_proxy(self, payload: dict):
        """
        Update Proxy Settings on the Nessus Scanner.
        :param payload: proxy host, port , Username, Password
        :return: ResponseObject from set proxy
        :rtype ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.PUT, routes.PROXY, json=payload)
        return ResponseObject(response)

    def set_password_complexity(self, payload: dict) -> ResponseObject:
        """
        Set Password Complexity on the Nessus
        :param payload: passwd_complexity, passwd_max_attempts, passwd_min_length
        :return: password complexity
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.POST, routes.PASSWORD_COMPLEXITY, json=payload)
        return ResponseObject(response)

    def get_setting_complexity(self) -> ResponseObject:
        """
        Get Password complexity.
        :returns: Password Complexity
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.PASSWORD_COMPLEXITY)
        return ResponseObject(response)

    def get_proxy_setting(self) -> ResponseObject:
        """
        Get Proxy server settings
        :return: Proxy value
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.PROXY)
        return ResponseObject(response)

    def get_software_updates_setting(self) -> ResponseObject:
        """
        Get Software update details
        :return: Settings of Software updates
        :rtype: ResponseObject
        """
        resource = '%s/software-update' % routes.SETTINGS
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def edit_software_updates_setting(self, payload: dict) -> ResponseObject:
        """
        Edit/Update Software Update Settings on the Nessus
        :param dict payload: A dict containing software update info.
        :return: ResponseObject from set software update
        :rtype: ResponseObject
        """
        resource = '%s/software-update' % routes.SETTINGS
        response = self._cls.request(const.HTTPMethods.PUT, resource, json=payload)
        return ResponseObject(response)

    def add_software_updates_setting(self) -> ResponseObject:
        """
        Add Software Update Settings on the Nessus
        :return: ResponseObject from set software update
        :rtype: ResponseObject
        """
        resource = '%s/software-update' % routes.SETTINGS
        response = self._cls.request(const.HTTPMethods.POST, resource)
        return ResponseObject(response)

    def delete_software_updates_setting(self) -> ResponseObject:
        """
        Delete Software Update Settings on the Nessus
        :return: ResponseObject from software update
        :rtype: ResponseObject
        """
        resource = '%s/software-update/' % routes.SETTINGS
        response = self._cls.request(const.HTTPMethods.DELETE, resource)
        return ResponseObject(response)

    def get_feed_type(self, feed_type: str) -> ResponseObject:
        """
        Get feed type
        :param str feed_type: feed type contains value like plugins, ui
        :return: Feed Type values
        :rtype: ResponseObject
        """
        resource = '/settings/software-update/%s' % feed_type
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def set_feed_type(self, feed_type: str) -> ResponseObject:
        """
        Set feed type
        :param str feed_type: feed type contains value like plugins, ui
        :return: Feed type values
        :rtype: ResponseObject
        """
        resource = '/settings/software-update/%s' % feed_type
        response = self._cls.request(const.HTTPMethods.POST, resource)
        return ResponseObject(response)

    def health_alerts(self) -> ResponseObject:
        """
        Get the current health alerts
        """
        resource = '/settings/health/alerts'
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def agent_versions(self) -> ResponseObject:
        """
        Get the current health alerts
        """
        resource = '/settings/agent-versions'
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)
