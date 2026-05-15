"""
Nessus Scanners Endpoint
"""
import random
import string

from catium.lib import const
from catium.lib.api.base_api_object import ResponseObject
from catium.lib.log import create_logger
from nessus.apiobjects import routes

log = create_logger()


def random_alphanumeric_string_for_linking_key(length):
    return ''.join(
        random.choices(
            string.ascii_letters + string.digits,
            k=length
        )
    )


class ScannersEndpoint(object):
    """Scanners API Endpoint"""

    def __init__(self, cls):
        self._cls = cls

    def add_remote_scanner(self, payload: dict) -> ResponseObject:
        """
        Add scanner
        :param payload: JSON Payload
        :return: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.POST, routes.REMOTE_SCANNER, json=payload)
        return ResponseObject(response)

    def control(self, scanner_id: int, scan_uuid: str, action: str):
        """
        Allows control of scans that are currently running on a scanner

        :param int scanner_id: Scanner ID
        :param str scan_uuid: Scan UUID
        :param str action: Action to perform on a scan.
            Supported Options: stop, pause, resume
        """
        payload = {'action': action}
        resource = '%s/%s/scans/%s/control' % (routes.SCANNERS, scanner_id, scan_uuid)
        self._cls.request(const.HTTPMethods.POST, resource, json=payload)

    def delete(self, scanner_id: int):
        """
        Deletes a scanner from the manager or container

        .. note:: This will unlink a remote scanner

        :param int scanner_id: Scanner ID
        """
        self._cls.request(const.HTTPMethods.DELETE, routes.SCANNERS + '/' + str(scanner_id))
        log.debug('Deleted Scanner ID ' + str(scanner_id))

    def details(self, scanner_id: int) -> ResponseObject:
        """
        Returns details for the given scanner

        :param int scanner_id: Scanner ID
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.SCANNERS + '/' + str(scanner_id))
        return ResponseObject(response)

    def edit(self, scanner_id: int, force_plugin_update: bool = False, force_ui_update: bool = False,
             finish_update: bool = False, registration_code: str = None, aws_update_interval: int = None):
        """
        Edit scanner

        :param int scanner_id: Scanner ID
        :param bool force_plugin_update: True to force plugin update. Default: False.
        :param bool force_ui_update: True to force a UI update. Default: False.
        :param bool finish_update: True to reboot scanner and run latest software update. Default: False.
        :param str registration_code: Sets the registration code for the scanner
        :param str aws_update_interval: Tells AWS scanners how frequently to check in with its manager
        """
        payload = {}

        if force_plugin_update:
            payload['force_plugin_update'] = 1
        if force_ui_update:
            payload['force_ui_update'] = 1
        if finish_update:
            payload['finish_update'] = 1
        if registration_code:
            payload['registration_code'] = registration_code
        if aws_update_interval:
            payload['aws_update_interval'] = aws_update_interval

        if not payload:
            payload = None

        self._cls.request(const.HTTPMethods.PUT, routes.SCANNERS + "/" + str(scanner_id), json=payload)

    def get_aws_targets(self, scanner_id: int) -> ResponseObject:
        """
        Returns a list of AWS scan targets

        .. note:: The requested scan should be an AWS scanner

        :param int scanner_id: Scanner ID
        """
        resource = '%s/%s/aws-targets' % (routes.SCANNERS, scanner_id)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def get_scanner_key(self, scanner_id: int) -> ResponseObject:
        """
        Returns the key of the requested scanner

        :param int scanner_id: Scanner ID
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.SCANNERS + '/' + str(scanner_id) + '/key')
        return ResponseObject(response)

    def get_linking_key(self) -> ResponseObject:
        """
        Returns the linking key for use when linking fake agents.

        :return: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.LINKING_KEY)
        return ResponseObject(response)

    def get_agent_linking_key(self, linking_key_type: str = routes.LINKING_KEY_TYPES[1]) -> ResponseObject:
        """
        Returns the key of the requested agent
        :param str linking_key_type: Linking key type - routes.LINKING_KEY_TYPES
        :return: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.LINKING_KEYS + '/' + linking_key_type)
        return ResponseObject(response)

    def get_node_linking_key(self, linking_key_type: str = routes.LINKING_KEY_TYPES[2]) -> ResponseObject:
        """
        Returns the key of the requested child node
        :param str linking_key_type: Linking key type - routes.LINKING_KEY_TYPES
        :return: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.LINKING_KEYS + '/' + linking_key_type)
        return ResponseObject(response)

    def get_scanner_linking_key(self, linking_key_type: str = routes.LINKING_KEY_TYPES[0]) -> ResponseObject:
        """
        Returns the key of the requested scanner for 10.4.0+ else it will use the older method of getting the keys
        :param str linking_key_type: Linking key type - routes.LINKING_KEY_TYPES
        :return: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.LINKING_KEYS + '/' + linking_key_type)
        return ResponseObject(response)

    def get_scans(self, scanner_id: int) -> ResponseObject:
        """
        Returns a list of scans running on the requested scanner

        :param int scanner_id: Scanner ID
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.SCANNERS + '/' + str(scanner_id) + '/scans')
        return ResponseObject(response)

    def link(self, scanner_id: int, link: bool = False):
        """
        Enables or disables the link state of the requested scanner

        :param int scanner_id: Scanner ID
        :param bool link: True to enable link otherwise False. Default: False.
        """
        self._cls.request(const.HTTPMethods.PUT, routes.SCANNERS + '/' + str(scanner_id) + '/link',
                          json={'link': 1 if link else 0})

    def link_to_cloud(self, scanner_name: str, manager_host: str, linking_key: str, manager_port: int = 443,
                      use_proxy: bool = False, register: bool = True):
        """
        Link a Nessus scanner to TenableCloud

        .. note:: ``register`` should be used when linking to a Tenable.io as a manged scanner. That is, the scanner
            receives its core, ui and plugin updates from Tenable.io.

        .. note:: ``register`` instructs the scanner to register itself during the linking process. This is typically
            done at scanner install/setup time.

        :param str scanner_name: Scanner name
        :param str manager_host: TenableCloud IP/Hostname to connect to
        :param str linking_key: Linking key from TenableCloud
        :param int manager_port: TenableCloud port to connect to
        :param bool use_proxy: Use a proxy to connect outbound
        :param bool register: Register scanner
        """
        payload = {'key': linking_key, 'name': scanner_name, 'use_proxy': use_proxy,
                   'linked_to': {'ip': manager_host, 'port': manager_port}}

        if register:
            payload['register'] = register

        self._cls.request(const.HTTPMethods.PUT, routes.SETTINGS + '/scanner', json=payload)

    def get_list(self) -> ResponseObject:
        """Returns a list of scanners"""
        response = self._cls.request(const.HTTPMethods.GET, routes.SCANNERS)
        return ResponseObject(response)

    def local_scans(self) -> ResponseObject:
        """Returns a list of scans running on the local scanner"""
        response = self._cls.request(const.HTTPMethods.GET, routes.SCANNERS + '/local/scans')
        return ResponseObject(response)

    def unlink_to_cloud(self, from_scanner=True):
        """Unlink Nessus scanner from TenableCloud"""
        payload = {'name': '', 'linked_to': None}
        if from_scanner:
            payload['key'] = ''
        self._cls.request(const.HTTPMethods.PUT, routes.SETTINGS + '/scanner', json=payload)

    def force_plugin_update(self, scanner_id: int, stream: bool = False):
        """
        Forces a plugin update on a scanner

        :param int scanner_id: Scanner ID
        :param bool stream: True if need to get response text else False
        """
        payload = {'force_plugin_update': 1}
        self._cls.request(const.HTTPMethods.PUT, routes.SCANNERS + '/' + str(scanner_id), json=payload, stream=stream)

    def unlink_to_scanner(self):
        """Unlink Nessus scanner"""
        payload = {'name': '', 'key': '', 'linked_to': ''}
        self._cls.request(const.HTTPMethods.PUT, routes.SETTINGS + '/scanner', json=payload)

    def get_agent_list_from_agent_group(self, agent_group_id: int) -> ResponseObject:
        """
        get agent list from agent group
        :param int agent_group_id: agent group id
        :return: response for agent list from agent group
        :rtype: ResponseObject
        """
        resource = 'agent-groups/%s' % (agent_group_id)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def agent_details(self, scanner_id: int, agent_id: int) -> ResponseObject:
        """
        get agent details
        :param int scanner_id: scanner id
        :param int agent_id: agent id
        :return: response for agent details
        :rtype: ResponseObject
        """
        resource = '%s/%s/%s/%s' % (routes.SCANNERS, scanner_id, routes.AGENTS, agent_id)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def get_blackout_window_details(self, scanner_id: int, exclusion_id: int) -> ResponseObject:
        """
        get blackout window details
        :param int scanner_id: scanner id
        :param int exclusion_id: blackout window/exclusion id
        :return: response for blackout window
        :rtype: ResponseObject
        """
        resource = '%s/%s/%s/exclusions/%s' % (routes.SCANNERS, scanner_id, routes.AGENTS, exclusion_id)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def edit_blackout_window_details(self, scanner_id: int, exclusion_id: int, data: dict) -> ResponseObject:
        """
        edit blackout window details
        :param int scanner_id: scanner id
        :param int exclusion_id: blackout window/exclusion id
        :param dict data: data
        :return: response for blackout window
        :rtype: ResponseObject
        """
        resource = '%s/%s/%s/exclusions/%s' % (routes.SCANNERS, scanner_id, routes.AGENTS, exclusion_id)
        response = self._cls.request(const.HTTPMethods.PUT, resource, json=data)
        return ResponseObject(response)

    def get_agent_settings(self, scanner_id: int) -> ResponseObject:
        """
        get agent settings
        :param int scanner_id: scanner id
        :return: response for agent setting
        :rtype: ResponseObject
        """
        resource = '%s/%s/%s/config' % (routes.SCANNERS, scanner_id, routes.AGENTS)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def edit_agent_settings(self, scanner_id: int, data: dict) -> ResponseObject:
        """
        edit agent setting
        :param int scanner_id: scanner id
        :param dict data: data
        :return: response for edit agent setting
        :rtype: ResponseObject
        """
        resource = '%s/%s/%s/config' % (routes.SCANNERS, scanner_id, routes.AGENTS)
        response = self._cls.request(const.HTTPMethods.PUT, resource, json=data)
        return ResponseObject(response)

    def delete_all_scanners(self, scanner_ids: list) -> ResponseObject:
        """
        delete all scanners
        :param list scanner_ids : List of Scanner Ids
        :return: response for delete all scanners
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.DELETE, routes.SCANNERS, json={'ids': scanner_ids})
        return ResponseObject(response)

    def create_scanner_logrequest_directive(self, scanner_id: int, data: dict) -> ResponseObject:
        """
        create logs directive for scanner
        :param int scanner_id: scanner id of scanner
        :param dict data: payload for creating logs directive
        :return: response of directive creation
        :rtype: ResponseObject
        """
        resource = '%s/%s/get-logs' % (routes.SCANNERS, scanner_id)
        response = self._cls.request(const.HTTPMethods.POST, resource, json=data)
        return ResponseObject(response)

    def local_load(self) -> str:
        """
        Get load of scans running on the local scanner
        :return: Load of scans running on the local scanner
        :rtype: str
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.SCANNERS + '/local/load')
        return response.content

    def download_log(self, scanner_id: int) -> ResponseObject:
        """
        download log
        :param int scanner_id: scanner id
        :return: response for token to download log
        :rtype: ResponseObject
        """
        resource = '%s/%s/download-log' % (routes.SCANNERS, scanner_id)
        response = self._cls.request(const.HTTPMethods.POST, resource)
        return ResponseObject(response)

    def delete_all_logs(self, scanner_id: int) -> ResponseObject:
        """
        Delete all the logs
        :param int scanner_id : Scanner ID
        :return: response for delete all logs
        :rtype: ResponseObject
        """
        resource = '%s/%s/logs' % (routes.SCANNERS, scanner_id)
        response = self._cls.request(const.HTTPMethods.DELETE, resource)
        return ResponseObject(response)

    def delete_log(self, scanner_id: int, log_id: str) -> ResponseObject:
        """
        Delete log
        :param int scanner_id : Scanner ID
        :param str Log Id : Log ID
        :return: response for deleted logs
        :rtype: ResponseObject
        """
        resource = '%s/%s/logs' % (routes.SCANNERS, scanner_id)
        response = self._cls.request(const.HTTPMethods.DELETE, resource, json={'id': log_id})
        return ResponseObject(response)

