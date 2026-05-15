"""
Fixtures for Scans

:copyright: Tenable Network Security, 2017
:date: Aug 08 2017
:last_modified: Nov 27, 2020
:author: @ivargas, @jyerge, @kpanchal
"""
import json
from http import HTTPStatus
from typing import TYPE_CHECKING

import pytest
from requests.exceptions import HTTPError

from catium.helpers.testdata import load_testdata, get_file_path
from catium.lib.api.base_api_object import ResponseObject
from catium.lib.log import create_logger
from catium.lib.util import random_name
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.nessuscli.helper import expire_nessus, register_nessus
from nessus.helpers.scan import create_scan_helper, create_scan_with_custom_plugin_set
from nessus.helpers.scan_class import Scan
from nessus.helpers.scanner import create_scanner
from nessus.models.scan import ScanModel

if TYPE_CHECKING:
    from catium.lib.typechecking import SubRequest

log = create_logger()


@pytest.fixture()
def get_policy_templates(request: 'SubRequest', nessus_api_handler: NessusAPI):
    """Gets the list of policy templates"""
    log.debug('fixture init: get_policy_templates: Get list of policy templates')
    templates = nessus_api_handler.editor.get_templates('policy')
    return templates['templates']


@pytest.fixture()
def get_scan_templates(request: 'SubRequest', nessus_api_handler: NessusAPI):
    """Gets the list of scan templates"""
    templates = nessus_api_handler.editor.get_templates('scan')
    return templates['templates']


@pytest.fixture()
def get_folder_dictionary(request: 'SubRequest', nessus_api_login):
    """
    Automatic API Folder Retrieval.  Returns dictionary of folder names to folder ids.
    """
    log.debug('fixture init: get_folder_dictionary: Gets dictionary of folder names')
    folder_dictionary = {}
    folders = nessus_api_login.folders.get_folders()['folders']
    for folder in folders:
        folder_dictionary[folder['name']] = folder['id']
    request.cls.cat.folders = folder_dictionary


@pytest.fixture()
def create_folder(request: 'SubRequest', nessus_api_login):
    """
    Automatic API Folder Creation.  Creates a randomly named folder and then deletes the folder when finished.
    """
    log.debug('fixture init: create_folder: Creates a folder')
    folder_id = None
    folder = random_name(prefix='nessus_')
    try:
        nessus_api_login.folders.create(name=folder)
        folder_id = json.loads(nessus_api_login.http_text)['id']
        request.cls.cat.folder_id = folder_id
        yield folder_id
    finally:
        try:
            nessus_api_login.folders.delete(folder_id=folder_id)
        except Exception as exc:
            log.warning('Deleting folder "%s" failed: %s', folder_id, exc)


@pytest.fixture()
def create_scan(request: 'SubRequest', nessus_api_handler: NessusAPI, test_data_file: dict) -> ResponseObject:
    """Creates a new scan"""
    log.debug('fixture init: create_scan: Create a Scan')

    scan_data = load_testdata(test_data_file['scan_json_path'])
    scan, scan_model = create_scan_helper(nessus_api_handler, file_name=test_data_file['scan_json_path'],
                                          template_title=test_data_file['scan_type'])

    yield scan

    log.debug('fixture teardown: create_scan: Removing scan')
    if request.config.getoption('enable_cleanup') and \
            (request.config.getoption('cleanup_on_failure') or not getattr(request.cls, 'has_failed', False)):
        try:
            nessus_api_handler.scans.delete(scan['scan']['id'])
            if 'agent_group_id' in scan_data['settings'].keys():
                nessus_api_handler.agent_groups.delete(scan_model.scanner_id, scan_model.agent_group_id)
        except HTTPError as exc:
            log.warning("Unable to delete scan in clean up. Scan may have been deleted by test or may be running."
                        "Error:%s", exc)
    else:
        log.info('Scan Model exists, with ID: %s', scan['scan']['id'])
        request.instance.cleanup_info = 'Scan model id: %s' % scan['scan']['id']


@pytest.fixture()
def create_scan_class(request: 'SubRequest', nessus_api_handler: NessusAPI, test_data_file: dict) -> Scan:
    """Creates a new scan"""
    log.debug('fixture init: create_scan: Create a Scan')
    create_scan = test_data_file['create_scan'] if 'create_scan' in test_data_file.keys() else True

    scan = Scan(scan_data_path=test_data_file['scan_json_path'], scan_type=test_data_file['scan_type'],
                api_handler=nessus_api_handler)
    if create_scan:
        scan.create_scan()

    yield scan

    log.debug('fixture teardown: create_scan: Removing scan')
    if request.config.getoption('enable_cleanup') and \
            (request.config.getoption('cleanup_on_failure') or not getattr(request.cls, 'has_failed', False)):
        try:
            scan.delete_scan()
            if 'agent_group_id' in scan.scan_test_data['settings'].keys():
                nessus_api_handler.agent_groups.delete(scan.scan_model.scanner_id, scan.scan_model.agent_group_id)
        except HTTPError as exc:
            log.warning("Unable to delete scan in clean up. Scan may have been deleted by test or may be running."
                        f"Error:{exc}")
    else:
        log.info(f'Scan Model exists, with ID: {scan.id}')
        request.instance.cleanup_info = f'Scan model id: {scan.id}'


@pytest.fixture()
def create_scan_no_teardown(request: 'SubRequest', nessus_api_handler: NessusAPI, test_data_file: dict) -> Scan:
    """Creates a new scan"""
    log.debug('fixture init: create_scan: Create a Scan')
    create_scan = test_data_file['create_scan'] if 'create_scan' in test_data_file.keys() else True

    scan = Scan(scan_data_path=test_data_file['scan_json_path'], scan_type=test_data_file['scan_type'],
                api_handler=nessus_api_handler)
    if create_scan:
        scan.create_scan()

    return scan


@pytest.fixture()
def add_scanner_locally(request: 'SubRequest', nessus_api_handler: NessusAPI) -> dict:
    """
    Adds a local scanner

    .. note:: This fixture requires an active API session
    """
    log.debug('fixture init: add_scanner_locally: Adds a local scanner')

    scanner_detail = request.param['scanner_details'] if hasattr(request, 'param') and 'scanner_details' in \
                                                                                       request.param else {}

    is_multi_scanner = request.param['is_multi_scanner'] if hasattr(request,
                                                                    'param') and 'is_multi_scanner' in request.param \
        else False

    scanner_info = create_scanner(api=nessus_api_handler, scanner_details=scanner_detail,
                                  is_multi_scanner=is_multi_scanner)

    yield scanner_info

    log.debug('fixture teardown: add_scanner_locally: Removing scanner %s', scanner_info['id'])
    if request.config.getoption('enable_cleanup') and \
            (request.config.getoption('cleanup_on_failure') or not getattr(request.cls, 'has_failed', False)):
        try:
            for scanner in nessus_api_handler.scanners.get_list()['scanners']:
                if scanner['name'] == scanner_info['name']:
                    nessus_api_handler.scanners.delete(scanner_info['id'])
        except HTTPError as exc:
            log.warning("Unable to delete scan in clean up. Scan "
                        "may have been deleted by test or may be running. Error: %s", exc)
    else:
        log.info('Scanner still exists: Scanner ID: %s', scanner_info['id'])
        request.instance.cleanup_info = 'Scanner ID: %s' % (scanner_info['id'])


@pytest.fixture()
def create_scan_with_scanner(request: 'SubRequest', nessus_api_handler: NessusAPI,
                             add_scanner_locally) -> ResponseObject:
    """Creates a new scan with scanner attached"""
    log.debug('fixture init: create_scan_with_scanner: Create a Scan')

    scanner_info = add_scanner_locally
    payload = {
        'name': 'scan-with-additional-scanner',
        'description': 'Created automatically by Automation',
        'text_targets': '127.0.0.1',
        'scanner_id': scanner_info['id'],
        'enabled': True,
        'autogen': False
    }

    scan_model = ScanModel(**payload)
    scan = nessus_api_handler.scans.create(model=scan_model)
    log.debug("Scanner id is %s", scanner_info['id'])

    yield scan['scan'], scanner_info

    log.debug('fixture teardown: create_scan_with_scanner: Removing scan')
    if request.config.getoption('enable_cleanup') and \
            (request.config.getoption('cleanup_on_failure') or not getattr(request.cls, 'has_failed', False)):
        try:
            nessus_api_handler.scans.delete(scan['scan']['id'])
        except HTTPError as exc:
            log.warning("Unable to delete scan in clean up. Scan may have been deleted by test or may be running."
                        "Error:%s", exc)
    else:
        log.info('Scan ID exists, with ID: %s', scan['scan']['id'])
        request.instance.cleanup_info = 'Scan ID: %s' % scan['scan']['id']


@pytest.fixture()
def expire_license():
    """ This fixture will set the license to expired by one day and restore it on tear down """
    try:
        expire_nessus()
    except:
        log.error(msg="Unable to reset the existing license")
        raise Exception("There is issue while registering Nessus having expire_days as '-1'")
    else:
        yield
    finally:
        register_nessus()


@pytest.fixture()
def import_scan_via_api(request: 'SubRequest'):
    """
    fixture to import a scan file via API

    e.g.: @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Agent_Scan.db',
                                                            'file_path': 'nessus/tests/ui/scans/test_data/',
                                                            'password': 'password', "encrypted": True}], indirect=True)
    """
    scan_file_name = request.param.get('file_name')
    scan_file_path = request.param.get('file_path')
    response = None

    if not (scan_file_name and scan_file_path):
        log.error("Import not possible as filename and/or file path is missing.")
        return

    try:
        scan_file = get_file_path(scan_file_path + scan_file_name)
        file_uploaded = request.instance.cat.api.file.upload(file=scan_file, encrypted=request.param.get(
            'encrypted', None))

        response = request.instance.cat.api.scans.import_scan(
            file_uploaded, folder_id=None, password=request.param.get('password', None))

        assert request.instance.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % request.instance.cat.api.http_status_code

        yield {'name': response['scan']['name'], 'id': response['scan']['id']}

    finally:
        if response:
            request.cls.cat.api.scans.delete(response['scan']['id'])


@pytest.fixture()
def create_scan_with_plugin_data(request: 'SubRequest', nessus_api_handler: NessusAPI, test_data_file: dict) -> ResponseObject:
    """Creates a new scan with certain plugins enabled or disabled"""
    log.debug('fixture init: create_scan: Create a Scan')

    scan_data = load_testdata(test_data_file['scan_json_path'])
    scan, scan_model = create_scan_with_custom_plugin_set(nessus_api_handler, file_name=test_data_file['scan_json_path'],
                                                          template_title=test_data_file['scan_type'])

    yield scan

    log.debug('fixture teardown: create_scan: Removing scan')
    if request.config.getoption('enable_cleanup') and \
            (request.config.getoption('cleanup_on_failure') or not getattr(request.cls, 'has_failed', False)):
        try:
            nessus_api_handler.scans.delete(scan['scan']['id'])
            if 'agent_group_id' in scan_data['settings'].keys():
                nessus_api_handler.agent_groups.delete(scan_model.scanner_id, scan_model.agent_group_id)
        except HTTPError as exc:
            log.warning("Unable to delete scan in clean up. Scan may have been deleted by test or may be running."
                        "Error:%s", exc)
    else:
        log.info('Scan Model exists, with ID: %s', scan['scan']['id'])
        request.instance.cleanup_info = 'Scan model id: %s' % scan['scan']['id']
