"""
Nessus Waiting helpers
"""
from http import HTTPStatus

from requests.exceptions import RequestException
from waiting import TimeoutExpired, wait

from catium.lib.const import API, TIME_FIVE_SECONDS, TIME_TEN_MINUTES, TIME_THIRTY_MINUTES, TIME_THIRTY_SECONDS, \
    TIME_TWO_MINUTES, WAIT_NORMAL, TIME_TEN_SECONDS
from catium.lib.log import create_logger
from catium.lib.url import Url
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.apiobjects.xmlrpc_api import XmlRpcAPI
from nessus.helpers.settings import get_current_advanced_settings
from nessus.lib.config import NessusConfig
from nessus.lib.const import Scanner

log = create_logger()


def wait_for_scanner_login(api: NessusAPI, username: str, password: str, timeout: int, msg: str,
                           sleep_interval: int = TIME_FIVE_SECONDS) -> None:
    """
    Wait for scanner to login successfully

    .. note:: Handles 503s gracefully

    :param NessusAPI api: NessusAPI instance
    :param str username: Username
    :param str password: Password
    :param int timeout: Timeout
    :param str msg: Timeout message
    :param int sleep_interval: How many seconds to sleep per interval
    :raises: TimeoutExpired
    """

    def _wait_for_login() -> bool:
        log.debug('Waiting for server login to succeed for %s', Url(api.session_url).hostname)
        try:
            api.login(username=username, password=password)
            if api.http_status_code == HTTPStatus.OK:
                return True
        except RequestException as exception:
            log.debug('Request Error: %s', exception)
            if api.http_status_code == HTTPStatus.SERVICE_UNAVAILABLE:
                log.debug('Ignoring server response: service unavailable (%d)', HTTPStatus.SERVICE_UNAVAILABLE)
        return False

    wait(lambda: _wait_for_login(), sleep_seconds=sleep_interval, timeout_seconds=timeout, waiting_for=msg)


def wait_for_scanner_registration(api: NessusAPI, code: str, timeout: int, msg: str,
                                  sleep_interval: int = TIME_FIVE_SECONDS) -> None:
    """
    Wait for scanner registration (i.e. register call)

    .. note:: This method handles 503s gracefully

    :param NessusAPI api: NessusAPI instance
    :param str code: Activation code
    :param int timeout: Timeout
    :param str msg: Timeout message
    :param int sleep_interval: How many seconds to sleep per interval
    :raises: TimeoutExpired
    """

    def _wait_for_registration() -> bool:
        log.debug('Waiting for server registration to succeed for %s', Url(api.session_url).hostname)
        try:
            api.server.register(code=code)
            if api.http_status_code == HTTPStatus.OK:
                return True
        except RequestException as exception:
            log.debug('Request Error: %s', exception)
            if api.http_status_code == HTTPStatus.SERVICE_UNAVAILABLE:
                log.debug('Ignoring server response: service unavailable (%d)', HTTPStatus.SERVICE_UNAVAILABLE)
        return False

    wait(lambda: _wait_for_registration(), sleep_seconds=sleep_interval, timeout_seconds=timeout, waiting_for=msg)


def wait_for_scanner_status(api: NessusAPI, status: str, timeout: int, msg: str,
                            sleep_interval: int = TIME_FIVE_SECONDS) -> None:
    """
    Wait for scanner status

    :param NessusAPI api: NessusAPI instance
    :param str status: Status
    :param int timeout: Timeout
    :param str msg: Timeout message
    :param int sleep_interval: How many seconds to sleep per interval
    :raises: TimeoutExpired
    """

    def _match_server_status() -> bool:
        log.debug('Waiting for server %s status to match status "%s"', Url(api.session_url).hostname, status)
        try:
            response = api.server.status()
            if response.get('status') == status:
                return True
        except RequestException as exception:
            log.debug('Request Error: %s', exception)
            if api.http_status_code == HTTPStatus.SERVICE_UNAVAILABLE:
                log.debug('Ignoring server response: service unavailable (%d)', HTTPStatus.SERVICE_UNAVAILABLE)
        return False

    wait(lambda: _match_server_status(), sleep_seconds=sleep_interval, timeout_seconds=timeout, waiting_for=msg)


def wait_for_plugins(api: NessusAPI, timeout: int = TIME_THIRTY_MINUTES) -> None:
    """
    Wait for plugin set to fully update.

    :param NessusAPI api: NessusAPI instance
    :param int timeout: Timeout in seconds. Default 30 minutes.
    :raises: TimeoutExpired
    """

    def _plugins_updated() -> bool:
        log.debug('Waiting for plugins to fully update for %s', Url(api.session_url).netloc)
        try:
            response = api.server.status()
            if response.get('pluginData') is True and response.get('initLevel') == 4 and response.get('status') == 'ready':
                return True
            else:
                api.server.restart()
                if api.http_status_code == HTTPStatus.OK:
                    log.debug('Nessus restart initiated because plugin-set found N/A')
                # Wait till server status switch to loading
                wait_for_scanner_status(api=api, status='loading',
                                        timeout=TIME_TEN_MINUTES, msg='Availability of Nessus scanner',
                                        sleep_interval=TIME_FIVE_SECONDS)

                # Wait till server is ready
                wait_for_scanner_status(api=api, status=API.Status.READY,
                                        timeout=TIME_TEN_MINUTES, msg='Availability of Nessus scanner',
                                        sleep_interval=TIME_FIVE_SECONDS)
        except RequestException as exception:
            log.debug('Request Error: %s', exception)

            if api.http_status_code == HTTPStatus.SERVICE_UNAVAILABLE:
                log.debug('Ignoring server response: service unavailable (%d)', HTTPStatus.SERVICE_UNAVAILABLE)
        return False

    wait(lambda: _plugins_updated(), sleep_seconds=TIME_TEN_SECONDS, timeout_seconds=timeout,
         waiting_for='Plugins to fully load.')


def wait_for_scan(api: NessusAPI, scan_id: int, status: str, timeout: int = TIME_TWO_MINUTES) -> None:
    """
    Wait for a scan status

    .. note:: Default, we wait 2 minutes for a scan's status to not equal RUNNING

    :param NessusAPI api: NessusAPI instance
    :param int scan_id: Scan ID
    :param str status: Status to wait for, see API.Scan.Status for valid statuses
    :param int timeout: Time to wait for scan to complete (or error). Default: TIME_TWO_MINUTES.
    :raises: TimeoutExpired
    """
    wait(lambda: api.scans.details(scan_id)['info']['status'] == status, sleep_seconds=TIME_FIVE_SECONDS,
         waiting_for='Scan to finish.', timeout_seconds=timeout)


def wait_scan_state(api: NessusAPI, scan_id: int, end_state: str, timeout: int, action: str = None) -> bool:
    """
    method to wait for certain scans to be used directly with asserts

    :param NessusAPI api: Which  api to use
    :param int scan_id: id of scan used
    :param str end_state: state expected in wait
    :param int timeout: total wait time
    :param str action: Callback method, i.e. this method is invoked if supplied

    :return: wait_results
    :rtype: bool
    """
    if action:
        getattr(api.scans, action)(scan_id)
    try:
        wait(lambda: api.scans.get_status(scan_id) == end_state, timeout_seconds=timeout,
             waiting_for='Scan to go state %s' % end_state, sleep_seconds=WAIT_NORMAL)
        return True
    except TimeoutExpired:
        raise Exception("Scan with scan_id:{} did not get '{}' status within {} seconds of waiting".
                        format(scan_id, end_state, timeout))


def wait_for_scanner_restart(api: NessusAPI, timeout: int, msg: str, sleep_interval: int = TIME_FIVE_SECONDS) -> None:
    """
    Wait for scanner registration (i.e. register call)

    .. note:: This method handles 503s gracefully

    :param NessusAPI api: NessusAPI instance
    :param int timeout: Timeout
    :param str msg: Timeout message
    :param int sleep_interval: How many seconds to sleep per interval
    :raises: TimeoutExpired
    """

    def _wait_for_registration() -> bool:
        log.debug('Waiting for server registration to succeed for %s', Url(api.session_url).hostname)
        try:
            api.server.restart()
            if api.http_status_code == HTTPStatus.OK:
                return True
        except RequestException as exception:
            log.debug('Request Error: %s', exception)

            if api.http_status_code == HTTPStatus.SERVICE_UNAVAILABLE:
                log.debug('Ignoring server response: service unavailable (%d)', HTTPStatus.SERVICE_UNAVAILABLE)
        return False

    wait(lambda: _wait_for_registration(), sleep_seconds=sleep_interval, timeout_seconds=timeout, waiting_for=msg)


def wait_for_scanner_to_link(api: NessusAPI, key: str, scanner_name: str, timeout: int, msg: str,
                             register: bool = False, sleep_interval: int = TIME_FIVE_SECONDS) -> None:
    """
    Wait for a Nessus scanner to link to a tenableio site or Nessus Manager

    .. note:: This method handles 503s gracefully
    .. note:: Register should only be applied when dealing with Managed scanners

    :param NessusAPI api: NessusAPI instance
    :param str key: Linking key
    :param str scanner_name: Scanner name
    :param int timeout: Timeout
    :param str msg: Timeout message
    :param bool register: Register scanner during linking
    :param int sleep_interval: How many seconds to sleep per interval
    :raises: TimeoutExpired
    """

    def _wait_for_registration() -> bool:
        log.debug('Waiting for scanner "%s" to be linked to "%s"', scanner_name, Url(api.session_url).hostname)
        manager_host = Url(NessusConfig.CAT_NESSUS_URL).hostname
        try:
            api.scanners.link_to_cloud(manager_host=manager_host, linking_key=key, scanner_name=scanner_name,
                                       register=register)
            if api.http_status_code == HTTPStatus.OK:
                return True
        except RequestException as exception:
            log.debug('Request Error: %s', exception)

            if api.http_status_code == HTTPStatus.SERVICE_UNAVAILABLE:
                log.debug('Ignoring server response: service unavailable (%d)', HTTPStatus.SERVICE_UNAVAILABLE)
        return False

    wait(lambda: _wait_for_registration(), sleep_seconds=sleep_interval, timeout_seconds=timeout, waiting_for=msg)


def wait_for_new_advanced_preference(api: NessusAPI, setting_name: str, sleep_interval: int = TIME_THIRTY_SECONDS,
                                     timeout: int = TIME_TEN_MINUTES, added_setting=True) -> None:
    """
    Wait for the new preference to appear in Nessus' advanced settings before proceeding.

    :param api: NessusAPI instance
    :param setting_name: Setting that was changed.
    :param sleep_interval: How long to sleep in between attempts.
    :param timeout: How long to keep checking for setting.
    :param added_setting: New Setting has been added or not.
    :raises: TimeoutExpired
    """

    def _settings_updated() -> bool:
        try:
            advanced_settings = get_current_advanced_settings(api)
            if setting_name in advanced_settings:
                log.debug('%s found in advanced settings.', setting_name)
                return added_setting
            else:
                log.debug('Waiting for settings to update for %s', setting_name)
        except RequestException as exception:
            log.debug('Request Error: %s', exception)
        if api.http_status_code == HTTPStatus.SERVICE_UNAVAILABLE:
            log.debug('Ignoring server response: service unavailable (%d)', HTTPStatus.SERVICE_UNAVAILABLE)
        return not added_setting

    wait(lambda: _settings_updated(), sleep_seconds=sleep_interval, timeout_seconds=timeout,
         waiting_for='Scan advanced settings to take effect')


def wait_for_export_to_complete(api: NessusAPI, scan_id: int = None, file_id: int = None,
                                sleep_interval: int = TIME_FIVE_SECONDS, timeout: int = TIME_TEN_MINUTES) -> None:
    """
    Wait for export to be in a 'ready' state before downloading.

    :param NessusAPI api:        NessusAPI instance
    :param str scan_id:          Scan ID that is being exported.
    :param int file_id:          File ID that was generated during export of above scan.
    :param int sleep_interval:   How many seconds to sleep per interval
    :param int timeout:          Length of time to check status before timing out if status is not '200'
    :raises: TimeoutExpired
    """

    # TODO: resolve type conflict for scan_id. Is it a str or an int? Type checker is complaining.
    def _wait_for_export_to_complete() -> bool:
        log.debug('Waiting for Scan ID: "%s" (File ID: "%s") to finish exporting.', scan_id, file_id)
        try:
            api.scans.export_status(scan_id, file_id)
            if API.Status.READY in api.http_text:
                return True
        except RequestException as exception:
            log.debug('Request Error: %s', exception)

            if api.http_status_code == HTTPStatus.NOT_FOUND:
                log.debug('Ignoring server response: service unavailable (%d)', HTTPStatus.NOT_FOUND)
        return False

    wait(lambda: _wait_for_export_to_complete(), sleep_seconds=sleep_interval, timeout_seconds=timeout,
         waiting_for=Scanner.Strings.EXPORT_STATUS_OK)


def wait_for_xmlrpc_scan_to_completed(api: XmlRpcAPI, scan_uuid: str) -> None:
    """
    Method to check xmlrpc scan to be in a 'completed' status before xmlrpc report downloading.

    :param api: xmlrpc API instance
    :param str scan_uuid: XMLRPC scan uuid
    :return: None
    :rtype: None
    """

    def is_xmlrpc_scan_completed() -> bool:
        r1 = api.xmlrpc.list()
        reports = r1.findall("./contents/reports/report")
        for report in reports:
            if scan_uuid == report.find('./name').text:
                return report.find('./status').text == 'completed'
        return False

    wait(lambda: is_xmlrpc_scan_completed(), sleep_seconds=TIME_FIVE_SECONDS, waiting_for='xmlrpc Scan to completed.',
         timeout_seconds=TIME_THIRTY_MINUTES)
