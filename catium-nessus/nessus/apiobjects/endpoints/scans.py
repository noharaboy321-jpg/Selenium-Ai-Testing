"""
Nessus Scans Endpoint
"""
from requests.exceptions import HTTPError

from catium.lib import const
from catium.lib.api.base_api_object import ResponseObject
from catium.lib.errors import CatiumAPIObjectError
from catium.lib.log import create_logger
from nessus.apiobjects import routes
from nessus.helpers.metadata.scan import get_template_uuid
from nessus.lib.const import API
from nessus.models.scan import ScanModel

log = create_logger()


class ScansEndpoint(object):
    """Scans API Endpoint"""

    def __init__(self, cls):
        self._cls = cls

    def attachments(self, scan_id: int, attachment_id: int) -> ResponseObject:
        """
        Get the requested scan attachment file

        :param int scan_id: Scan ID
        :param int attachment_id: ID of the scan attachment
        :return: scan attachment token
        :rtype: ResponseObject
        """
        resource = '%s/%s/attachments/%s/prepare' % (routes.SCANS, scan_id, attachment_id)
        response = self._cls.request(const.HTTPMethods.POST, resource)
        return ResponseObject(response)

    def download_scan_attachment(self, attachment_taken: int) -> ResponseObject:
        """
        Download the requested scan attachment file by using given attachment token

        :param int attachment_taken: Scan attachment token
        :return: error message
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, 'tokens/%s/download' % attachment_taken)
        return response

    def configure(self, scan_id: int, payload: dict, stream: bool = False) -> ResponseObject:
        """
        Changes the schedule or policy parameters of a scan

        :param int scan_id: Scan ID
        :param dict payload: A raw payload
        :param bool stream: True if need to get response text else False
        :returns: Scan details
        :rtype: ResponseObject
        """
        resource = '%s/%s' % (routes.SCANS, scan_id)
        response = self._cls.request(const.HTTPMethods.PUT, resource, json=payload, stream=stream)
        return ResponseObject(response)

    def copy(self, scan_id: int, folder_id: str = None, history: bool = False, name: str = None) -> ResponseObject:
        """
        Copies the given scan

        :param int scan_id: Scan ID
        :param str folder_id: ID of the destination folder
        :param bool history: If True, the history of the scan will be copied
        :param str name: Name of the copied scan
        :returns: Scan details
        :rtype: ResponseObject
        """
        payload = {}
        if folder_id:
            payload['folder_id'] = folder_id
        if history:
            payload['history'] = history
        if name:
            payload['name'] = name
        resource = '%s/%s/copy' % (routes.SCANS, scan_id)
        response = self._cls.request(const.HTTPMethods.POST, resource, json=payload)
        return ResponseObject(response)

    def create_raw(self, payload) -> ResponseObject:
        """
        :param payload: payload passed in scan post request
        :return: response object
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.POST, routes.SCANS, json=payload)
        return ResponseObject(response)

    def create(self, model: ScanModel) -> ResponseObject:
        """
        Create a scan

        .. note:: Advanced Scan template is used if no UUID is specified

        :param object model: A ScanModel object
        :returns: An object representing the API response
        :rtype: ResponseObject
        """
        plugins = {}

        if model.uuid is None:
            template_list = self.get_templates()
            model.uuid = get_template_uuid(template_list, model.default_template)
        if model.plugins and isinstance(model.plugins, list):
            plugins = self._build_plugins(plugin_list=model.plugins)
        elif model.families and isinstance(model.families, list):
            plugins = self._build_plugins_by_family(family_list=model.families)

        payload = model.create_payload()
        payload['plugins'] = plugins

        response = self._cls.request(const.HTTPMethods.POST, routes.SCANS, json=payload)
        scan = ResponseObject(response)
        log.debug('Created Scan ID #%s using model', scan['scan']['id'])
        log.debug('Scan ID #%s was created using Scan Template UUID #%s', scan['scan']['id'], scan['scan']['uuid'])
        return scan

    def compliance_output(self, scan_id: int, host_id: int, plugin_id: int) -> ResponseObject:
        """
        Returns the compliance output for a given host

        :param int scan_id: Scan ID
        :param int host_id: ID of the host to retrieve
        :param int plugin_id: Compliance plugin ID
        :return: compliance output
        :rtype: ResponseObject
        """
        resource = '%s/%s/hosts/%s/compliance/%s' % (routes.SCANS, scan_id, host_id, plugin_id)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def delete(self, scan_id: int, stream: bool = False):
        """
        Delete a Scan

        :param int scan_id: Scan ID
        :param bool stream: True if need to get response text else False

        .. note:: Scans in running, paused or stopping states cannot be deleted
        """
        self._cls.request(const.HTTPMethods.DELETE, routes.SCANS + '/' + str(scan_id), stream=stream)
        log.debug('Deleted scan ID "%s"', scan_id)

    def delete_history(self, scan_id: int, history_id: str):
        """
        Deletes historical results from a scan

        :param int scan_id: Scan ID
        :param str history_id: ID of the results to delete
        """
        resource = '%s/%s/history/%s' % (routes.SCANS, scan_id, history_id)
        self._cls.request(const.HTTPMethods.DELETE, resource)

    def details(self, scan_id: int, mask: str = None, query: str = None) -> ResponseObject:
        """
        Returns details for the given scan

        :param int scan_id: Scan ID
        :param str mask: mask for scan like info, notes, filters etc.
        :param str query: other param of scan as query
        :return: details of given scan
        :rtype: ResponseObject
        """
        resource = "%s/%d" % (routes.SCANS, scan_id)
        if mask is not None:
            resource += "?mask=%s" % mask
        if query is not None:
            resource += query
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def get_status(self, scan_id: int) -> str:
        """
        Returns scan status

        :param int scan_id: Scan ID
        :return: status of specific scan.
        :rtype: str
        """
        return self._cls.scans.details(scan_id)['info']['status']

    def download(self, scan_id: int, file_id: str) -> ResponseObject:
        """
        Download an exported scan

        .. note:: Returns the RAW file content

        :param int scan_id: Scan ID
        :param str file_id: ID of the file to download
        :return: downloaded file ID with token.
        :rtype: ResponseObject
        """
        resource = '%s/%s/export/%s/download' % (routes.SCANS, scan_id, file_id)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return response

    def export(self, scan_id: int, export_format: str, extra_filters: dict = None, report_contents: dict = None,
               history_id: int = None, password: str = None, chapters: str = None, filter_params: dict = None,
               template_id: int = None) -> tuple:
        """
        Export the given scan

        :param int scan_id: Scan ID
        :param str export_format: File format to use.
            Supported Options: Nessus, HTML, PDF, CSV or DB
        :param dict extra_filters: for selected hosts or vulnerabilities
        :param dict report_contents: Report content options
        :param int history_id: ID of the historical data that should be exported. Optional.
        :param str password: Password used to encrypt database exports. Required when exporting as DB.
        :param str chapters: Chapters to include in the export, expects a semi-colon delimited string.
            Supported Options: vuln_hosts_summary, vuln_by_host, compliance_exec, remediations, vuln_by_plugin,
            compliance
        :param dict filter_params: for applied filter params
        :param int template_id: Template Id to export scan in 'PDF' or 'HTML'
        :returns: tuple, (Scan File ID, Token)
        :raises: CatiumAPIObjectError
        :raises: ScanNotFoundError if a Scan ID is provided and the Scan doesn't exist
        :rtype: tuple
        """
        resource = '%s/%s/export' % (routes.SCANS, scan_id)

        if export_format not in API.Scan.ExportFormats.VALID_FORMATS:
            raise CatiumAPIObjectError('Invalid Scan export format supplied: %s.' % export_format)

        if history_id:
            resource += '?=history_id=%s' % history_id

        payload = {'format': export_format}

        # A password is required if the export format is DB
        if export_format == API.Scan.ExportFormats.FORMAT_DB:
            if not password:
                raise CatiumAPIObjectError('A password is required when exporting a Scan as type DB.')
            payload['password'] = password

        if chapters:
            supplied_chapters = chapters.split(';')
            for chapter in supplied_chapters:
                if chapter not in API.Scan.Chapters.VALID_CHAPTERS:
                    raise CatiumAPIObjectError('Invalid chapter supplied: %s.' % chapter)
            payload['chapters'] = chapters

        if template_id:
            payload['template_id'] = template_id

        if report_contents:
            payload['reportContents'] = report_contents

        if filter_params:
            payload.update(filter_params)

        if extra_filters:
            if export_format in [API.Scan.ExportFormats.FORMAT_PDF, API.Scan.ExportFormats.FORMAT_HTML,
                                 API.Scan.ExportFormats.FORMAT_CSV]:
                payload['extraFilters'] = extra_filters
            else:
                payload.update(extra_filters)

        response = self._cls.request(const.HTTPMethods.POST, resource, json=payload)
        response = ResponseObject(response)
        return response['file'], response['token']

    def export_status(self, scan_id: int, file_id: int) -> str:
        """
        Checks the file status of an exported scan

        :param int scan_id: Scan ID
        :param int file_id: ID of the file to poll
        :return: Status of scan being exported
        :rtype: str
        """
        resource = '%s/%s/export/%s/status' % (routes.SCANS, scan_id, file_id)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        response = ResponseObject(response)
        return response['status']

    def host_details(self, scan_id: int, host_id: int, history_id: int = None) -> ResponseObject:
        """
        Returns details for the given host

        :param int scan_id: Scan ID
        :param int host_id: Host ID
        :param int history_id: History ID
        :return: details of given host
        :rtype: ResponseObject
        """
        resource = '%s/%s/hosts/%s' % (routes.SCANS, scan_id, host_id)
        if history_id:
            resource += '?history_id=%s' % history_id
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def import_scan(self, file: str, folder_id: int = None, password: str = None) -> ResponseObject:
        """
        Import an existing scan

        :param str file: Name of the file to import
        :param int folder_id: ID of the destination folder
        :param str password: Password for the file to import. Required for nessus.db imports.
        :return: list of imported scan.
        :rtype: ResponseObject
        """
        payload = {'file': file}
        if folder_id:
            payload['folder_id'] = folder_id
        if password:
            payload['password'] = password
        response = self._cls.request(const.HTTPMethods.POST, routes.SCANS + '/import', json=payload)
        return ResponseObject(response)

    def launch(self, scan_id: int, alt_targets: list = None, stream: bool = False) -> str:
        """
        Launches a scan

        :param int scan_id: Scan ID
        :param list alt_targets: If specified, these targets will be scanned instead of the default
        :param bool stream: True if need to get response text else False
        :returns: Scan UUID
        :rtype: str
        """
        resource = '%s/%s/launch' % (routes.SCANS, scan_id)
        payload = {}
        if alt_targets and len(alt_targets) > 0:
            payload['alt_targets'] = alt_targets
        response = self._cls.request(const.HTTPMethods.POST, resource, json=payload, stream=stream)
        response = ResponseObject(response)
        return response
    
    def pause(self, scan_id: int, alt_targets: list = None, stream: bool = False) -> str:
        """
        Pauses a scan

        :param int scan_id: Scan ID
        :param list alt_targets: If specified, these targets will be scanned instead of the default
        :param bool stream: True if need to get response text else False
        :returns: Scan UUID
        :rtype: str
        """
        resource = '%s/%s/pause' % (routes.SCANS, scan_id)
        payload = {}
        if alt_targets and len(alt_targets) > 0:
            payload['alt_targets'] = alt_targets
        self._cls.request(const.HTTPMethods.POST, resource, json=payload, stream=stream)

    def resume(self, scan_id: int, alt_targets: list = None, stream: bool = False) -> str:
        """
        Resumes a scan

        :param int scan_id: Scan ID
        :param list alt_targets: If specified, these targets will be scanned instead of the default
        :param bool stream: True if need to get response text else False
        :returns: Scan UUID
        :rtype: str
        """
        resource = '%s/%s/resume' % (routes.SCANS, scan_id)
        payload = {}
        if alt_targets and len(alt_targets) > 0:
            payload['alt_targets'] = alt_targets
        self._cls.request(const.HTTPMethods.POST, resource, json=payload, stream=stream)


    def get_audit_trail(self, scan_id: int, plugin_id: int = None, hostname: str = None) -> ResponseObject:
        """
        Retrieve a Scans audit trail

        .. note:: ``plugin_id`` OR ``hostname`` is required

        :param int scan_id: Scan ID
        :param int plugin_id:  Plugin ID
        :param str hostname: Hostname
        :return: ResponseObject
        :raises: AttributeError
        :rtype: ResponseObject
        """
        if all([not plugin_id, not hostname]):
            raise AttributeError('One of plugin_id or hostname must be supplied.')
        resource = '{}/{}/trails'.format(routes.SCANS, scan_id)
        params = {}
        if plugin_id:
            params['plugin_id'] = plugin_id
        if hostname:
            params['hostname'] = hostname
        response = self._cls.request(const.HTTPMethods.GET, resource, params=params)
        return ResponseObject(response)

    def get_kb(self, scan_id: int, host_id: int) -> dict:
        """
        Download Scan KB

        .. note:: This method returns the RAW file content as Bytes and can be written out to a file

        :param int scan_id: Scan ID
        :param int host_id: Host ID
        :return: Bytes
        :rtype: dict
        """
        params = {'token': self._cls.session_token}
        resource = '{}/{}/hosts/{}/kb'.format(routes.SCANS, scan_id, host_id)

        # Remove the X-Cookie header, this request does not send the X-Cookie header
        try:
            log.debug('Removing X-Cookie header')
            self._cls.remove_header('X-Cookie')
            response = self._cls.request(const.HTTPMethods.GET, resource, params=params)
            return response.content
        except HTTPError:
            log.exception('Request Error')
            raise
        finally:
            log.debug('Restoring X-Cookie header')
            self._cls.add_header({'X-Cookie': 'token=' + self._cls.session_token})

    def prepare_kb(self, scan_id: int, host_id: int) -> ResponseObject:
        """
        Prepares a KB for the given scan and host

        :param int scan_id: Scan ID
        :param int host_id: Host ID
        :return: ResponseObject
        :rtype: ResponseObject
        """
        resource = '{}/{}/hosts/{}/kb/prepare'.format(routes.SCANS, scan_id, host_id)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def get_web_scanner_plugin_attachments(self, scan_id: int) -> dict:
        """
        Get Scan Logs Attachment

        .. note:: This method returns the RAW file content as Bytes and can be written out to a file

        :param int scan_id: Scan ID
        :return: Bytes
        :rtype: dict
        """
        params = {'token': self._cls.session_token}
        resource = '{}/{}/plugins/172036?limit=2500'.format(routes.SCANS, scan_id)

        # Remove the X-Cookie header, this request does not send the X-Cookie header
        try:
            log.debug('Removing X-Cookie header')
            self._cls.remove_header('X-Cookie')
            response = self._cls.request(const.HTTPMethods.GET, resource, params=params)
            return response.content
        except HTTPError:
            log.exception('Request Error')
            raise
        finally:
            log.debug('Restoring X-Cookie header')
            self._cls.add_header({'X-Cookie': 'token=' + self._cls.session_token})

    def get_scans(self, folder_id: int = None, last_modification_date: int = None) -> ResponseObject:
        """
        Returns the scan list

        :param int folder_id: ID of the folder whose scans should be listed
        :param int last_modification_date: Limit the results to those that have only changed since this time
        :returns: A list (i.e. dict) of scans
        :rtype: ResponseObject
        """
        payload = {}

        if folder_id:
            payload['folder_id'] = folder_id

        if last_modification_date:
            payload['last_modification_date'] = last_modification_date

        response = self._cls.request(const.HTTPMethods.GET, routes.SCANS, params=payload)
        return ResponseObject(response)

    def plugin_output(self, scan_id: int, host_id: int, plugin_id: int, history_id: int = None) -> ResponseObject:
        """
        Returns the output for a given plugin

        :param int scan_id: Scan ID
        :param int host_id: ID of the host to retrieve
        :param int plugin_id: ID of the plugin to retrieve
        :param int history_id: ID of the historical data that should be returned. Optional.
        :return: plugin output details
        :rtype: ResponseObject
        """
        resource = '%s/%s/hosts/%s/plugins/%s' % (routes.SCANS, scan_id, host_id, plugin_id)

        if history_id:
            resource += '?history_id=%s' % history_id

        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def read_status(self, scan_id: int, read: bool = False) -> ResponseObject:
        """
        Changes the read status of a scan
        :param int scan_id: Scan ID
        :param bool read: If True, scan has been read. If False, scan has not been read.
        :return: read status
        :rtype: ResponseObject
        """
        resource = '%s/%s/status' % (routes.SCANS, scan_id)
        response = self._cls.request(const.HTTPMethods.PUT, resource, json={'read': read})
        return ResponseObject(response)

    def schedule(self, scan_id: int, enabled: bool = False) -> ResponseObject:
        """
        Enables or disables a scan schedule

        :param int scan_id: Scan ID
        :param bool enabled: True to enable or False to disable scan schedule. Default: False.
        :returns: Scan schedule
        :rtype: ResponseObject
        """
        resource = '%s/%s/schedule' % (routes.SCANS, scan_id)
        response = self._cls.request(const.HTTPMethods.PUT, resource, json={'enabled': enabled})
        return ResponseObject(response)

    def stop(self, scan_id: int):
        """
        Stops a scan

        :param int scan_id: Scan ID
        """
        resource = '%s/%s/stop' % (routes.SCANS, scan_id)
        self._cls.request(const.HTTPMethods.POST, resource)

    def timezones(self) -> ResponseObject:
        """
        Returns a timezone list for creating a scan

        :return: list of timezone for created scan
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.SCANS + '/timezones')
        return ResponseObject(response)

    def get_templates(self) -> ResponseObject:
        """
        Returns a list of scan templates

        :return: list of scan templates
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.EDITOR + '/scan/templates')
        return ResponseObject(response)

    def get_history_details(self, scan_id: int, host_id: int, history_id: int, plugin_id: int) -> ResponseObject:
        """
        Returns details for the given host and plugin

        :param int scan_id: Scan ID
        :param int host_id: Host ID
        :param int history_id: History ID
        :param int plugin_id: Plugin ID
        :return: history detail
        :rtype: ResponseObject
        """
        resource = '%s/%s/hosts/%s/plugins/%s' % (routes.SCANS, scan_id, host_id, plugin_id)
        if history_id:
            resource += '?history_id=%s' % history_id
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def move(self, scan_id: int, folder_id: str = None, stream: bool = False):
        """
        Move the given scan to specified folder as per folder_id

        :param int scan_id: Scan ID
        :param str folder_id: ID of the destination folder
        :param bool stream: True if need to get response text else False
        """
        payload = {}
        if folder_id:
            payload['folder_id'] = folder_id

        resource = '%s/%s/folder' % (routes.SCANS, scan_id)
        response = self._cls.request(const.HTTPMethods.PUT, resource, json=payload, stream=stream)
        return ResponseObject(response)

    def _build_plugins(self, plugin_list: list) -> dict:
        """
        Builds the required plugin dictionary, enabling only the plugins specified

        .. note:: Invalid plugin IDs are ignored

        :param list plugin_list: A list of plugin IDs
        :rtype: dict
        """
        _family_map = {}
        families = {'plugins': {}}
        updates = {}
        family_id = {}

        # Build a dict to disable all plugins
        response = self._cls.plugins.families()
        for family in response['families']:
            _family_map[family['name']] = family['id']
            families['plugins'].update({family['name']: {'status': 'disabled'}})

        for plugin in plugin_list:
            response = self._cls.plugins.plugin_details(plugin)

            if response['family_name'] not in updates.keys():
                updates.update({response['family_name']: []})

            # Add plugin to the family list
            updates[response['family_name']].append(plugin)

            # Track family ID
            family_id.update({response['family_name']: _family_map[response['family_name']]})

        # Build stubs
        for fam, fam_id in family_id.items():
            families['plugins'][fam]['status'] = 'mixed'
            families['plugins'][fam]['individual'] = {}
            families['plugins'][fam]['mixedDefault'] = 'enabled'

            # Disable every plugin in the family
            all_disabled = {}
            response = self._cls.plugins.family_details(fam_id)
            for plugin_record in response['plugins']:
                all_disabled.update({str(plugin_record['id']): 'disabled'})
            families['plugins'][fam]['individual'].update(all_disabled)

        # Enable desired plugins
        for fam, p_ids in updates.items():
            for pid in p_ids:
                families['plugins'][fam]['individual'][str(pid)] = 'enabled'

        return families['plugins']

    def _build_plugins_by_family(self, family_list: list) -> dict:
        """
        Builds the required plugin dictionary, enabling only the plugins specified

        .. note:: Invalid plugin IDs are ignored

        :param list plugin_list: A list of plugin IDs
        :rtype: dict
        """
        _family_map = {}
        families = {'plugins': {}}
        updates = {}
        family_id = {}

        # Build a dict to disable all plugins
        response = self._cls.plugins.families()
        for family in response['families']:
            _family_map[family['name']] = family['id']
            families['plugins'].update({family['name']: {'status': 'disabled'}})

        for family in family_list:
            updates.update({family: []})

            # Track family ID
            family_id.update({family: _family_map[family]})

        # Build stubs
        for fam, fam_id in family_id.items():
            families['plugins'][fam]['status'] = 'enabled'

        return families['plugins']

    def modify_plugin_severity(self, scan_id: int, host_id: int, plugin_id: int, payload: dict = None) \
            -> ResponseObject:
        """
        Modify the given plugin severity

        :param int scan_id: Scan ID
        :param int host_id: ID of the host to retrieve
        :param int plugin_id: ID of the plugin to retrieve
        :param dict payload: used to pass param
        :return: plugin severity details
        :rtype: ResponseObject
        """
        resource = '%s/%s/hosts/%s/plugins/%s' % (routes.SCANS, scan_id, host_id, plugin_id)

        response = self._cls.request(const.HTTPMethods.PUT, resource, json=payload)
        return ResponseObject(response)

    def diff_scan_history(self, scan_id: int, diff_id: int, history_id: int) -> ResponseObject:
        """
        Method for diffing two different scan results
        :param int scan_id: scan id used in performing the scan history diff.
        :param int diff_id: History id to be used as the primary diff.
        :param int history_id: History id for the primary diff id to diff against.
        :return: Scan results
        :rtype: ResponseObject
        """

        payload = {'diff_id': diff_id}
        resource = '%s/%s/diff?history_id=%s' % (routes.SCANS, scan_id, history_id)

        response = self._cls.request(const.HTTPMethods.POST, resource, json=payload)
        return ResponseObject(response)

    def export_diff_scan_history(self, scan_id: int, export_format: str, diff_id: int, history_id: int,
                                 password: str = None, chapters: str = None) -> tuple:
        """
        Export the diff of two scan histories

        :param int scan_id: Scan ID
        :param str export_format: File format to use.
            Supported Options: Nessus, HTML, PDF, CSV or DB
        :param int diff_id: History id to be used as the primary diff.
        :param int history_id: History id for the primary diff id to diff against.
        :param str password: Password used to encrypt database exports. Required when exporting as DB.
        :param str chapters: Chapters to include in the export, expects a semi-colon delimited string.
            Supported Options: vuln_hosts_summary, vuln_by_host, compliance_exec, remediations, vuln_by_plugin,
            compliance
        :returns: tuple, (Scan File ID, Token)
        :raises: CatiumAPIObjectError
        :raises: ScanNotFoundError if a Scan ID is provided and the Scan doesn't exist
        :return: Scan histories
        :rtype: tuple
        """

        resource = '%s/%s/export?diff_id=%s&history_id=%s' % (routes.SCANS, scan_id, diff_id, history_id)
        if export_format not in API.Scan.ExportFormats.VALID_FORMATS:
            raise CatiumAPIObjectError('Invalid Scan export format supplied: %s.' % export_format)
        payload = {'format': export_format}

        # A password is required if the export format is DB
        if export_format == API.Scan.ExportFormats.FORMAT_DB:
            if not password:
                raise CatiumAPIObjectError('A password is required when exporting a Scan as type DB.')
            payload['password'] = password

        if chapters:
            supplied_chapters = chapters.split(',')
            for chapter in supplied_chapters:
                if chapter not in API.Scan.Chapters.VALID_CHAPTERS:
                    raise CatiumAPIObjectError('Invalid chapter supplied: %s.' % chapter)
            payload['chapters'] = chapters

        response = self._cls.request(const.HTTPMethods.POST, resource, json=payload)
        response = ResponseObject(response)
        return response['file'], response['token']

    def compliance(self, scan_id: int, compliance_id: int) -> ResponseObject:
        """
        Returns Compliance output for Scan.
        :param int scan_id: Scan ID
        :param int compliance_id: Compliance ID
        :return: Compliance details of scan
        :rtype: ResponseObject
        """
        resource = '%s/%s/compliance/%s' % (routes.SCANS, scan_id, compliance_id)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def delete_host(self, scan_id: int, host_id: int) -> None:
        """
        Delete specific host from Scan.
        :param int scan_id: Scan ID
        :param int host_id: Host ID
        :return: None
        """
        self._cls.request(const.HTTPMethods.DELETE, routes.SCANS + '/' + str(scan_id) + '/hosts/' + str(host_id))

    def vulnerabilities(self, scan_id: int, plugin_id: int) -> ResponseObject:
        """
        Returns specific plugin details under vulnerability of Scan.
        :param int scan_id: Scan ID
        :param int plugin_id: Plugin ID
        :return: Vulnerability details of scan
        :rtype: ResponseObject
        """
        response = self._cls.request(
            const.HTTPMethods.GET, routes.SCANS + '/' + str(scan_id) + '/' + routes.PLUGINS + '/' + str(plugin_id))
        return ResponseObject(response)

    def cancel_export(self, scan_id: int, export_id: int) -> None:
        """
        Cancel export for Scan.
        :param int scan_id: Scan ID
        :param int export_id: Export ID
        :return: None
        """
        self._cls.request(const.HTTPMethods.DELETE, routes.SCANS + '/' + str(scan_id) + '/export/' + str(export_id))

    def export_format_details(self, scan_id: int, schedule_id: int) -> ResponseObject:
        """
        Returns format details of Scan.
        :param int scan_id: Scan ID
        :param int schedule_id: Schedule ID
        :return: export format details of scan.
        :rtype: ResponseObject
        """
        resource = '%s/%s/export/formats?schedule_id=%s' % (routes.SCANS, scan_id, schedule_id)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        response = ResponseObject(response)

        assert response['report_options']

        return response

    def delete_bulk_scans(self, id_list: list) -> ResponseObject:
        """
        Delete all scans from trash.
        :param list id_list: Scan id's which need to delete.
        :return: scan_id of deleted scan.
        :rtype: ResponseObject
        """
        payload = {"ids": id_list}
        response = self._cls.request(const.HTTPMethods.DELETE, routes.SCANS, json=payload)
        return ResponseObject(response)

    def enable_dashboard(self, scan_id: int, enabled: bool = False) -> None:
        """
        Enable Dashboard for Scan.
        :param int scan_id: Scan ID
        :param bool enabled: True or False
        :return: None
        """
        resource = routes.SCANS + '/' + str(scan_id) + '/' + routes.DASHBOARD
        self._cls.request(const.HTTPMethods.PUT, resource, json={'enabled': enabled})

    def snooze_plugin(self, scan_id: int, plugin_id: int, days: int) -> ResponseObject:
        """
        Snooze the specific plugin of the specific scan.
        :param int scan_id: Scan ID
        :param int plugin_id: Plugin ID
        :param int days: number of days to snooze plugin
        :return: Response for snooze plugin
        :rtype: ResponseObject
        """
        resource = "{}/{}/{}/{}/{}".format(
            routes.SCANS,
            str(scan_id),
            routes.PLUGINS,
            str(plugin_id),
            routes.SNOOZE
        )
        payload = {"days": days}
        response = self._cls.request(
            const.HTTPMethods.POST, resource, json=payload)
        return ResponseObject(response)

    def get_host_vulnerability(self, scan_id: int, host_id: int, plugin_id: int) -> ResponseObject:
        """
        Get vulnerability for specific host

        :param int scan_id: Scan ID
        :param int host_id: ID of the host to retrieve
        :param int plugin_id: ID of the plugin to retrieve
        :return: vulnerability for specific host
        :rtype: ResponseObject
        """
        resource = '{}/{}/{}/{}/{}/{}'.format(
            routes.SCANS,
            str(scan_id),
            routes.HOSTS,
            str(host_id),
            routes.PLUGINS,
            str(plugin_id)
        )

        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def delete_offline_plugins(self, scan_id: int) -> ResponseObject:
        """
        Deletes Offline plugins from scan.

        :param int scan_id: Scan ID
        :return: Response for Delete offline plugin
        :rtype: ResponseObject
        """
        resource = '{}/{}/{}'.format(routes.SCANS, scan_id, routes.OFFLINE)
        response = self._cls.request(const.HTTPMethods.DELETE, resource)
        return ResponseObject(response)

    def update_plugin_severity(self, scan_id: int, plugin_id: int, payload: dict = None) -> ResponseObject:
        """
        Update the plugin severity

        :param int scan_id: Scan ID
        :param int plugin_id: Plugin ID
        :param dict payload: used to pass param
        :return: response for updated plugin severity
        :rtype: ResponseObject
        """
        resource = '{}/{}/{}/{}'.format(routes.SCANS, scan_id, routes.PLUGINS, plugin_id)
        response = self._cls.request(const.HTTPMethods.PUT, resource, json=payload)
        return ResponseObject(response)

    def force_stop(self, scan_id: int):
        """
        Stops a scan forcefully

        :param int scan_id: Scan ID
        """
        resource = '%s/%s/kill' % (routes.SCANS, scan_id)
        self._cls.request(const.HTTPMethods.POST, resource)

    def get_scan_result_history(self, scan_id, history_id) -> ResponseObject:
        """
        Returns scan result for given history_id

        :param int scan_id: Scan ID
        :param int history_id: History ID for given scan
        :return : Scan result for given history_id
        :rtype: ResponseObject:
        """
        resource = '%s/%s?history_id=%s' % (routes.SCANS, scan_id, history_id)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def wake_snoozed_plugin(self, scan_id: int, plugin_id: int) -> ResponseObject:
        """
        Wake up the specific plugin of the specific scan.

        :param int scan_id: Scan ID
        :param int plugin_id: Plugin ID
        :return: Response for wake plugin
        :rtype: ResponseObject
        """
        resource = "{}/{}/{}/{}/{}".format(routes.SCANS, str(scan_id), routes.PLUGINS, str(plugin_id),
                                           routes.SNOOZE)
        response = self._cls.request(const.HTTPMethods.DELETE, resource)

        return ResponseObject(response)

    def update_severity_base(self, scan_id: int, history_id: int = None, payload: dict = None) -> ResponseObject:
        """
        Updates severity base value of given scan

        :param int scan_id: Scan ID
        :param int history_id: History ID for given scan
        :param dict payload: used to pass param
        :return: Response for wake plugin
        :rtype: ResponseObject
        """
        resource = '{}/{}/{}'.format(routes.SCANS, str(scan_id), routes.SEVERITY_BASE)

        if history_id:
            resource += '?history_id=%s' % history_id

        response = self._cls.request(const.HTTPMethods.PUT, resource, json=payload)

        return ResponseObject(response)

    def get_used_plugins(self, scan_id: int) -> ResponseObject:
        """
        Returns list of plugins used in scan

        :param int scan_id: Scan ID
        :return: list of plugins
        :rtype: ResponseObject
        """
        resource = '{}/{}/{}'.format(routes.SCANS, scan_id, routes.PLUGINS)
        response = self._cls.request(const.HTTPMethods.GET, resource)

        return ResponseObject(response)
