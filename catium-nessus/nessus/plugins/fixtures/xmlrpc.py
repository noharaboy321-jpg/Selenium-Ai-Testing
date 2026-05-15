"""
This file contains fixtures of xmlrpc.

:copyright: Tenable Network Security, 2019
:date: Jan 10, 2019
:last_modified: April 17, 2020
:author: @lambaliya, @kpanchal.ctr
"""

import pytest
from _pytest.fixtures import SubRequest
from requests import HTTPError
from waiting import wait

from catium.lib.const import TIME_FIVE_SECONDS, TIME_TEN_MINUTES
from catium.lib.const.base_constants import TIME_TWO_MINUTES, WAIT_SHORT
from catium.lib.log import create_logger
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.apiobjects.xmlrpc_api import XmlRpcAPI
from nessus.helpers.waiters import wait_for_scanner_status
from nessus.lib.const import API, random_name

log = create_logger()


@pytest.fixture()
def nessus_xmlrpc_api_login(request: 'SubRequest', store_nessus_api_instance: bool) -> NessusAPI:
    """
    Automatic API login for Nessus XMLRPC
    If used in product integration testing when more than one product involved i.e. SC and Nessus
    and no need to preserve Nessus XMLRPC API session as request.instance.cat.api object then
    nessus_xmlrpc_api_login fixture should be used with store_nessus_api_instance parameter set to 'False'

    .. note:: Uses the environment variables CAT_URL, CAT_NESSUS_USERNAME and CAT_NESSUS_PASSWORD
    """
    log.debug('fixture init: nessus_xmlrpc_api_login: Automatic login for Nessus XMLRPC')

    api = XmlRpcAPI()
    wait_for_scanner_status(api=api, status=API.Status.READY,
                            timeout=TIME_TEN_MINUTES, msg='Availability of Nessus scanner',
                            sleep_interval=TIME_FIVE_SECONDS)
    api.login()
    if store_nessus_api_instance:
        request.instance.cat.api = api
    yield api
    wait_for_scanner_status(api=api, status=API.Status.READY,
                            timeout=TIME_TEN_MINUTES, msg='Availability of Nessus scanner',
                            sleep_interval=TIME_FIVE_SECONDS)
    try:
        api.logout()
    except HTTPError as exc:
        log.warning('fixture failed to logout: %s', exc)


@pytest.fixture()
def add_xmlrpc_policy(request: 'SubRequest', nessus_xmlrpc_api_login):
    """ Creating new xml rpc policy"""
    api = nessus_xmlrpc_api_login
    param = getattr(request, "param", None)
    policy_id = param.get("policy_id") if param and param.get("policy_id") else 1
    policy_name = param.get("policy_name") if param and param.get("policy_name") \
        else random_name(prefix="xml_rpc_policy_")

    payload = {
        "policy_id": policy_id,
        "policy_name": policy_name
    }
    policy_root = api.xmlrpc.add_policy(payload)

    yield policy_root

    try:
        api.xmlrpc.delete_policy(policy_id)
    except HTTPError as exc:
        log.warning('fixture failed to delete policy: %s', exc)


@pytest.fixture()
def add_xmlrpc_scan(request: 'SubRequest', nessus_xmlrpc_api_login, add_xmlrpc_policy):
    """ Creating new xml rpc scan"""
    api = nessus_xmlrpc_api_login
    root = add_xmlrpc_policy

    policy_id_element = root.find('./contents/policy/policyID')
    policy_name_element = root.find('./contents/policy/policyName')

    if policy_id_element is None and policy_name_element is None:
        raise Exception("policyID or policyName not found")

    param = getattr(request, "param", None)
    target = param.get("target") if param and param.get("target") else "127.0.0.1"

    payload = {"policy_id": policy_id_element.text, "scan_name": policy_name_element.text, "target": target}
    scan_xml = api.xmlrpc.new_scan(payload)

    def xmlrpc_scan_status(uuid: str):
        status = ''
        xmlrpc_scan_list = api.xmlrpc.list_scans().findall("./contents/scans/scanList/scan")[::-1]

        for i in range(len(xmlrpc_scan_list)):
            if xmlrpc_scan_list[i][2].text == uuid:
                status = xmlrpc_scan_list[i][4].text
                break

        log.info('XMLRPC Scan status :: {}'.format(status))
        return status == API.Scan.Status.RUNNING

    wait(lambda: xmlrpc_scan_status(uuid=scan_xml.find("./contents/scan/uuid").text), sleep_seconds=WAIT_SHORT,
         timeout_seconds=TIME_TWO_MINUTES, waiting_for='To get started running XMLRPC scan')

    yield scan_xml

    try:
        # Delete Scan
        api.session_headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        api.xmlrpc.reset(report_name=scan_xml.find('./contents/scan/scan_name').text)
    except HTTPError as exc:
        log.debug('fixture failed to delete scan: %s', exc)
