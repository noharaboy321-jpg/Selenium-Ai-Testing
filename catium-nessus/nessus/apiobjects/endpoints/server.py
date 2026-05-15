"""
Nessus API Endpoint for Server

:copyright: Tenable Network Security, 2017
:date: August 07, 2018
:last_modified: August 14, 2018
:author: @rdutta
"""

import mimetypes
import os

from catium.lib import const
from catium.lib.api.base_api_object import ResponseObject
from nessus.apiobjects import routes


class ServerEndpoint(object):
    """Server API Endpoint"""

    def __init__(self, cls):
        self._cls = cls

    def properties(self) -> ResponseObject:
        """
        Returns server version and other properties

        :return: responses from server related to properties
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.SERVER + '/properties')
        return ResponseObject(response)

    def status(self) -> ResponseObject:
        """
        Returns server status

        :return: status of server
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.SERVER + '/status')
        return ResponseObject(response)

    def get_custom_ca(self) -> ResponseObject:
        """
        Get custom CA

        :return: responses from server
        :rtype: ResponseObject
        """
        resource = '%s/customca' % routes.SERVER
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def get_master_password(self) -> ResponseObject:
        """
        Get Master password

        :return: responses from server
        :rtype: ResponseObject
        """
        resource = '%s/password' % routes.SERVER
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def register(self, code: str, stream: bool = False) -> None:
        """
        Register scanner using activation code

        :param str code: Activation code
        :param bool stream: True if need to get response text else False
        :returns: None
        """
        self._cls.request(const.HTTPMethods.POST, routes.SERVER + '/register', json={'code': code}, stream=stream)

    def restart(self, payload: dict = None) -> None:
        """
        Restart scanner

        :returns: None
        """
        self._cls.request(const.HTTPMethods.POST, routes.SERVER + '/restart', json=payload)

    def refresh_license(self, restart: bool = True) -> None:
        """
        Refresh Nessus license

        :param bool restart: restart Nessus after reloading the license and the license is changed
        :returns: {no_update: true} if the license is not changed
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.POST, routes.SERVER + '/refresh-license',
                                     json={'restart': restart})
        return ResponseObject(response)

    def clear_feed_error(self) -> ResponseObject:
        """
        Clear feed error from server

        :return: responses from server
        :rtype: ResponseObject
        """
        resource = '%s/clear-feed-error' % routes.SERVER
        response = self._cls.request(const.HTTPMethods.POST, resource)
        return ResponseObject(response)

    def upload_plugins(self, plugins_file: str) -> ResponseObject:
        """
        Upload plugins

        :param str plugins_file: plugins to upload
        :return: uploaded plugin file name
        :rtype: ResponseObject
        """
        if not os.path.exists(plugins_file):
            raise FileNotFoundError('The file "%s" does not exist.' % plugins_file)

        # Components of multipart POST to Nessus
        mime_type = mimetypes.guess_type(plugins_file)[0]
        if mime_type is None:
            mime_type = 'application/octet-stream'

        files = [('Filedata', (os.path.basename(plugins_file), open(plugins_file, 'rb'), mime_type))]
        resource = '%s/upload-plugins' % routes.SERVER
        response = self._cls.request(const.HTTPMethods.POST, resource, files=files)
        return ResponseObject(response)

    def update_plugins(self, data: dict, stream: bool = False) -> ResponseObject:
        """
        Update the specified plugin

        :param dict data: Data to be updated
        :param bool stream: True if need to get response text else False
        :return: responses from server
        :rtype: ResponseObject
        """
        resource = '%s/update-plugins' % routes.SERVER
        response = self._cls.request(const.HTTPMethods.POST, resource, json=data, stream=stream)
        return ResponseObject(response)

    def unlock(self, data: dict) -> None:
        """
        Unlock the server with set master password

        :param dict data: Master password required to unlock the server
                example: {'passwd': 'nessus'}
        :return: None
        """
        resource = '%s/unlock' % routes.SERVER
        self._cls.request(const.HTTPMethods.POST, resource, json=data)

    def upgrade_pro_7(self) -> None:
        """
        Upgrade to Nessus Pro 7

        :returns: None
        """
        self._cls.request(const.HTTPMethods.PUT, routes.SERVER + '/upgrade-to-pro-7')

    def downgrade_pro_7(self) -> None:
        """
        Downgrade from Nessus Pro 7

        :returns: None
        """
        self._cls.request(const.HTTPMethods.PUT, routes.SERVER + '/downgrade-from-pro-7')

    def edit_custom_ca(self, cert_data: dict) -> ResponseObject:
        """
        Edit custom CA

        :param dict cert_data: Data to be updated
        :return: responses from server
        :rtype: ResponseObject
        """
        resource = '%s/customca' % routes.SERVER
        response = self._cls.request(const.HTTPMethods.PUT, resource, json={'ca': cert_data})
        return ResponseObject(response)

    def edit_master_password(self, data: dict) -> None:
        """
        Edit Master password

        :param dict data: Data to be updated
                example: data={'new_password': Nessus.DEFAULT_PASSWORD, 'old_password': current_master_password}
        :return: None
        """
        resource = '%s/password' % routes.SERVER
        self._cls.request(const.HTTPMethods.PUT, resource, json=data)

    def post_bug_report(self, data: dict, stream: bool = False) -> ResponseObject:
        """
        Get the status of bug report

        :param data: pass payload in dict
                example: data={'full_mode': 0, "scrub_mode": 0}
        :param bool stream: True if need to get response text else False
        :return: response from server
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.POST, routes.SERVER + '/bug-report', json=data, stream=stream)
        return ResponseObject(response)

    def server_register(self, data: dict, stream: bool = False) -> ResponseObject:
        """
        Registration using activation code

        :param str data: activation code
        :param bool stream: True if need to get response text else False
        :return: response from server
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.POST, routes.SERVER + '/register', json=data, stream=stream)
        return ResponseObject(response)

    def acknowledge_notification(self, id: int) -> ResponseObject:
        """
        Acknowledge a notification (by id).

        :param int id: notification id
        :return: response from server
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.PUT, '%s/notifications/%s/acknowledge' % (routes.SERVER, id))
        return ResponseObject(response)

    def telemetry(self) -> ResponseObject:
        """
        Return telemetry data (to be pulled by SC).

        :return: response from server
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, '%s/telemetry' % routes.SERVER)
        return ResponseObject(response)

    def peek_telemetry(self, reset: bool = False) -> ResponseObject:
        """
        Return the telemetry data that will be sent on next push.

        :return: response from server
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.POST, '%s/telemetry-peek' % routes.SERVER)
        return ResponseObject(response)

    def get_rss_feeds(self) -> ResponseObject:
        """
        Return the RSS Feed data.

        :return: response from server
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, '%s/rss-feeds' % routes.SERVER)
        return ResponseObject(response)

    def get_notifications(self, last_modified: int = None) -> ResponseObject:
        """
        Returns notifications for the user to display

        :param int last_modified: only return the notifications after the last_modified timestamp
        :return: example: { notifications: [], feed_notifications: [], timestamp: xxx }
        :rtype: ResponseObject
        """
        payload = {}

        if last_modified:
            payload['last_modified'] = last_modified

        response = self._cls.request(const.HTTPMethods.GET, routes.SERVER + '/notifications', params=payload)
        return ResponseObject(response)

    def get_notification_history(self) -> ResponseObject:
        """
        Returns notifications that have been shown to the user

        :return: example: { notifications: []}
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.SERVER + '/notifications/history')
        return ResponseObject(response)

    def get_assets(self) -> ResponseObject:
        """
        Returns assets

        :return: example: { assets: []}
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.SERVER + '/assets')
        return ResponseObject(response)
