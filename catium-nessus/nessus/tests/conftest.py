"""
Top level conftest to provide hooks and plugins for Nessus automation

:copyright: Tenable Network Security, 2017
:date: Mar 02, 2017
:last_modified: Sept 09, 2021
:author: @jyerge, @rdutta, @kpanchal
"""

import json
import re
import string
import subprocess
import uuid
from random import randrange
from uuid import uuid4

import pytz
import requests
from _pytest.fixtures import SubRequest
from docker.errors import ImageNotFound
from paramiko import SSHException
from waiting import wait as waiting_wait

from catium.helpers.site_configuration_fetcher import product_and_site
from catium.lib.api.base_api_object import ResponseObject
from catium.lib.cat_registry import autodiscover
from catium.lib.config.environment_variables import CommonConfig
from catium.lib.const import PLATFORM_WINDOWS, \
    HTTPMethods, TIME_TEN_SECONDS, \
    TIME_THREE_MINUTES, TIME_FIFTEEN_SECONDS
from catium.lib.const.base_constants import STRING_YES
from catium.lib.util import random_agent_uuid
from nessus.apiobjects import routes
from nessus.helpers.cli_command import execute
from nessus.helpers.dockernessus import docker_nessus
from nessus.helpers.dockernessus.lib.general import clean_up
from nessus.helpers.nessuscli.helper import get_nessus_cli, get_command, \
    get_nessusd
from nessus.helpers.report_template import get_custom_template_id
from nessus.helpers.scanner import wait_for_scanner_to_be_ready
from nessus.helpers.server import is_pro_7
from nessus.helpers.waiters import  wait_scan_state
from nessus.lib.config import docker_config, NessusConfig
from nessus.lib.const.constants import NessusInstallation
from nessus.tests.api.misc.test_scan_wizard import reload_nessus
from tenableio.apiobjects.tenablecloud_api import TenableCloudAPI
from tenableio.helpers.container import create_container, delete_container
from tenableio.lib.agent_shell import PlatformServiceCommands
from tenableio.models.container_model import ContainerModel

import os
import random

from datetime import datetime, timedelta
from random import randint
from typing import TYPE_CHECKING

import pytest
from requests import HTTPError, RequestException
from selenium.common.exceptions import NoSuchElementException, StaleElementReferenceException
from waiting.exceptions import TimeoutExpired
from catium.helpers.sleep_lib import sleep
from catium.helpers.testdata import get_file_path
from catium.lib.activation_code_generator.activation_code_generator import ActivationCodeGenerator
from catium.lib.config import Config
from catium.lib.const import TIME_SIXTY_SECONDS, TIME_THREE_SECONDS, WAIT_NORMAL, HTTPStatus
from catium.lib.const import TIME_TEN_MINUTES
from catium.lib.const import WAIT_SHORT
from catium.lib.const.base_constants import WAIT_LONG, TIME_FIVE_MINUTES, TIME_FIVE_SECONDS, \
    TIME_FIFTEEN_MINUTES, TIME_THIRTY_MINUTES, TIME_TWO_MINUTES
from catium.lib.errors import CatiumInvalidPasswordError, CatiumInvalidUsernameError, CatiumLoginError, \
    CatiumPageLoadError
from catium.lib.log import create_logger
from catium.lib.ssh.ssh import SSH
from catium.lib.util import random_name
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.license import start_nessus_and_wait_till_it_becomes_ready
from nessus.helpers.nessuscli import fix
from nessus.helpers.nessuscli.helper import get_os_name, stop_nessus, start_nessus
from nessus.helpers.polling_ui import polling_ui
from nessus.helpers.scan import empty_trash_folder
from nessus.helpers.software_update import get_nessus_version_details
from nessus.helpers.system import is_home, is_pro, is_expert
from nessus.helpers.waiters import wait_for_scanner_status, wait_for_plugins
from nessus.lib.const.constants import API, Nessus, OperatingSystems
from nessus.models.scan import ScanModel
from nessus.pageobjects.header.notifications import NotificationActions, disable_initial_scan_wizard_nessus_home, \
    close_welcome_banner_for_nessus_pro, close_pendo_guide_container_banner_for_nessus_pro, \
    close_pendo_guide_container_banner_for_nessus_expert, close_welcome_banner_for_nessus_expert
from nessus.pageobjects.header.user_menu import UserMenu
from nessus.pageobjects.login.login_page import LoginPage
from nessus.pageobjects.scans.scans_page import ScansPage, ScanList
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav



if TYPE_CHECKING:
    from catium.lib.typechecking import SubRequest

log = create_logger()
pytest_plugins = ['nessus.plugins.fixtures.agents', 'nessus.plugins.fixtures.nessus_plugins',
                  'nessus.plugins.fixtures.policies', 'nessus.plugins.fixtures.scans',
                  'nessus.plugins.fixtures.users', 'nessus.plugins.version_marker',
                  'nessus.plugins.fixtures.api_handler', 'nessus.plugins.fixtures.login',
                  'nessus.plugins.fixtures.custom_ca', 'nessus.plugins.fixtures.server',
                  'nessus.plugins.fixtures.agents_new_endpoints', 'nessus.plugins.fixtures.setting',
                  'nessus.plugins.deployment.fixtures', 'nessus.plugins.fixtures.xmlrpc',
                  'nessus.plugins.fixtures.nessus_settings', 'nessus.plugins.fixtures.system',
                  'nessus.plugins.fixtures.was', 'nessus.plugins.fixtures.profiles', 'nessus.plugins.fixtures.locales']


@pytest.hookimpl(tryfirst=True)
def pytest_collectstart(collector):  # pylint: disable=unused-argument
    """ Collects the cat_registry at start of tests. """
    autodiscover(["./nessus/models", "./nessus/pageobjects"], print_collection=True)


@pytest.fixture()
def login(request: 'SubRequest', driver_instance):  # pylint: disable=unused-argument
    """Automatically logs into Nessus with configured username and password before each test"""
    if request.node.get_closest_marker('disable_logout'):
        perform_logout = False
    else:
        perform_logout = True
    api = NessusAPI()
    try:
        plugin_status = api.server.status()['pluginSet']
        log.debug("Nessus plugin-set status is : {}".format(plugin_status))
    except (RequestException, KeyError):
        start_nessus()
        log.info("Got error while fetching plugin status.")
    try:
        # Skipping pluginSet property check for <10 Nessus as it was not available
        if is_pro():
            ver = get_nessus_version_details()['nessus_ui_version']
            nes_ver = ver.split(".")

            if int(nes_ver[0]) < 10:
                log.info("Skipping pluginSet check for 8x Nessus version")
                pass
            else:
                wait_for_plugins(api=api, timeout=TIME_THIRTY_MINUTES)
        else:
            wait_for_plugins(api=api, timeout=TIME_THIRTY_MINUTES)
    except TimeoutExpired:
        log.info("Nessus plugins are not loaded after waiting for Thirty minutes")
        try:
            log.info("Server plugin-set is : {}".format(api.server.status()['pluginSet']))
        except:
            pass
    try:
        start_nessus_and_wait_till_it_becomes_ready()
        login_page = LoginPage()
        login_page.refresh()
        login_page.do_login()

        if is_home():
            keep_wizard_enabled = request.param['keep_wizard_enabled'] if hasattr(
                request, 'param') and 'keep_wizard_enabled' in request.param else False

            if not keep_wizard_enabled:
                disable_initial_scan_wizard_nessus_home()

            NotificationActions().dismiss_offer_notifications_nessus_home()
        elif is_pro():
            close_pendo_guide_container_banner_for_nessus_pro()
            close_welcome_banner_for_nessus_pro()
        elif is_expert():
            close_pendo_guide_container_banner_for_nessus_expert()
            close_welcome_banner_for_nessus_expert()

    except (CatiumInvalidPasswordError, CatiumInvalidUsernameError, CatiumLoginError, CatiumPageLoadError,
            TimeoutExpired):
        log.exception('Login fixture failed to complete login.')
        raise
    else:
        yield
    finally:
        if perform_logout:
            LoadingCircle(0)
            NotificationActions().remove_all()
            user_menu = UserMenu()
            if user_menu.is_element_present('user_menu_dropdown'):
                try:
                    user_menu.logout()
                except (NoSuchElementException, StaleElementReferenceException):
                    log.warning("Error while performing logout")
            else:
                log.warning("Unable to logout from UI in fixture teardown")


@pytest.fixture(scope='class')
def nessus_class_api_login(request: 'SubRequest'):
    """
    Automatic API login fixture for Nessus at the class scope

    .. note:: If you have a test class where the API session can be reused for each test method, please use this fixture
    .. note:: Uses the environment variables CAT_URL, CAT_NESSUS_USERNAME and CAT_NESSUS_PASSWORD
    """
    log.debug('fixture init: nessus_class_api_login: Class scope Nessus API Login')
    api = NessusAPI()
    api.login()
    request.cls.cat.api = api
    yield api
    log.debug('fixture teardown: nessus_class_api_login: Class scope Nessus API logout')
    api.logout()


@pytest.fixture()
def get_nessus_server_properties(request: 'SubRequest', nessus_api_login):
    """
    Automatic API Server Properties retrieval.  Returns server properties.
    """
    log.debug('fixture init: get_nessus_server_properties: Get server properties')
    properties = nessus_api_login.server.properties()
    request.cls.cat.server_properties = properties
    yield properties
    log.debug('fixture teardown: get_nessus_server_properties: end body')


@pytest.fixture()
def empty_trash_and_create_or_import_bulk_scan(request: 'SubRequest', create_new_folder):
    """
    Empty trash folder and create or import bulk scans (by default import scan will be done)
    """
    # Deletes all scans from trash folder and imports bulk scans
    empty_trash_folder()

    scan_count = request.param['scan_count']
    import_scan = request.param['import_scan'] if hasattr(request, 'param') and 'import_scan' in request.param else True
    response = None
    responses = []

    nessus_api = NessusAPI()
    nessus_api.login()

    try:
        folder_detail = create_new_folder
        log.info('Folder created successfully.')

        scans_details = {'name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
                         'text_targets': 'localhost', 'folder_id': folder_detail[0]}
        scan_name = scans_details['name']

        if import_scan:
            scan_file = get_file_path('nessus/tests/ui/scans/test_data/' + 'Test_Advanced_Scan_NES-8592.nessus')
            file_uploaded = nessus_api.file.upload(file=scan_file)

        for count in range(scan_count):
            if import_scan:
                response = nessus_api.scans.import_scan(file_uploaded, folder_id=folder_detail[0])
            else:
                scans_details['name'] += " - " + str(count)
                scan_model = ScanModel(**scans_details)
                responses.append(nessus_api.scans.create(model=scan_model))
                scans_details['name'] = scan_name

        log.info('Scans created successfully.')
        scan_page = ScansPage()
        scan_page.refresh()

        SideNav().get_sidenav_element(element_name=folder_detail[1]).click()
        ScanList().loaded()

        if import_scan:
            yield response['scan']['name'], folder_detail
        else:
            yield [response['scan']['name'] for response in responses], scan_count, folder_detail

    finally:
        scan_ids = [scan['id'] for scan in nessus_api.scans.get_scans()['scans']]
        [nessus_api.scans.stop(scan_id=scan_id) for scan_id in scan_ids if nessus_api.scans.get_status(
            scan_id=scan_id) == API.Scan.Status.RUNNING]
        sleep(TIME_TWO_MINUTES, reason="waiting for scans to get stopped")

        if scan_ids:
            nessus_api.scans.delete_bulk_scans(id_list=scan_ids)
        else:
            log.debug("Did not get any Scans. May be, It was deleted from test side.")

        nessus_api.logout()
        empty_trash_folder()


@pytest.fixture(scope='function')
def set_api_header(request: 'SubRequest'):
    """
    Sets the X-API-Version header to match what is being passed in as a request parameter.
    API v2 Example:
        @pytest.mark.parametrize('set_api_header', [{"api_version": "2"}], indirect=True)

    This will default to API v1 if api_version is not in the request parameter.
    """
    log.debug('fixture init: set_api_header: Set API version in header')
    api_version = request.param['api_version'] if 'api_version' in request.param else "1"
    request.instance.cat.api.add_header({'X-API-Version': api_version})
    yield api_version
    log.debug('fixture teardown: set_api_header: Remove API version from header')
    request.instance.cat.api.remove_header('X-API-Version')


@pytest.fixture()
def import_scan(request: 'SubRequest'):
    """
    Import scan
    """
    log.debug('fixture init: import_scan')
    scan_name = request.param['scan']['filename'] if 'scan' in request.param else 'unknown_scan'
    encrypted = request.param['scan']['encrypted'] \
        if 'scan' in request.param and 'encrypted' in request.param['scan'] else None
    password = request.param['scan']['password'] \
        if 'scan' in request.param and 'password' in request.param['scan'] else None
    file = get_file_path('nessus/tests/api/scan/test_data/' + scan_name)
    fileuploaded = request.instance.cat.api.file.upload(file=file, encrypted=encrypted)
    if scan_name == 'Non-UTF8_scan.db' and password is not None:
        log.info("Password from scan param is : {}".format(request.param['scan']['password']))
        log.info("Password from script is : {}".format(password))
    imported_scan = request.instance.cat.api.scans.import_scan(fileuploaded, folder_id=None, password=password)
    request.cls.cat.scan_id = imported_scan['scan']['id']
    yield imported_scan['scan']['id']
    log.debug('fixture teardown: import_scan')
    request.instance.cat.api.scans.delete(imported_scan['scan']['id'])


@pytest.fixture()
def revert_nessus_pro_7_setting(request: 'SubRequest'):
    """
    Revert nessus pro 7 setting
    """
    properties = request.instance.cat.api.server.properties()
    was_upgraded = is_pro_7(properties)
    yield
    properties = request.instance.cat.api.server.properties()
    is_upgraded = is_pro_7(properties)

    if was_upgraded and not is_upgraded:
        request.instance.cat.api.server.upgrade_pro_7()
    elif not was_upgraded and is_upgraded:
        request.instance.cat.api.server.downgrade_pro_7()


@pytest.fixture()
def no_automation_api_key(request: 'SubRequest'):
    """
    No automation api key
    """
    request.instance.cat.api.disable_automation_api_key()
    yield
    request.instance.cat.api.enable_automation_api_key()


@pytest.fixture()
def skip_pro_scan_api_enabled(request: 'SubRequest', nessus_api_login):
    """
    Skip the test cases when is pro 7 and the flag scan-api-enabled is on
    """
    if request.node.get_closest_marker('skip_pro_scan_api_enabled'):
        properties = nessus_api_login.server.properties()
        log.debug('skip_scan_api_enabled Get server properties %s', properties)

        if is_pro_7(properties):
            if (('license' in properties) and ('scan-api-enabled' in properties['license']
            ) and (properties['license']['scan-api-enabled'] == 1)):
                pytest.xfail("skip if scan api is enabled")


@pytest.fixture()
def skip_pro_scan_api_disabled(request: 'SubRequest', nessus_api_login):
    """
    Skip the test cases when is pro 7 and the flag scan-api-enabled is off
    """
    if request.node.get_closest_marker('skip_pro_scan_api_disabled'):
        properties = nessus_api_login.server.properties()
        log.debug('skip_scan_api_enabled Get server properties %s', properties)

        if is_pro_7(properties):
            if ((not ('license' in properties) and ('scan-api-enabled' in properties['license']
            ) and (properties['license']['scan-api-enabled'] == 1))):
                pytest.xfail("skip if scan api is disabled")


@pytest.fixture(scope='session', autouse=True)
def use_docker_for_primary_scanner(request: 'SubRequest'):
    """
    Use docker for primary scanner
    """
    full_image_name = None
    cid = None

    if docker_config.USE_DOCKER_AS_PRIMARY_NESSUS:
        log.info('fixture init: creating a scanner in docker')

        try:
            image_name = "{0}/{1}".format(docker_config.LAB_DOCKER_REGISTRY, docker_config.DOCKER_SCANNER_IMAGE)
            full_image_name = "{0}:{1}".format(image_name, docker_config.DOCKER_TAG)
            cid = docker_nessus.start_scanner(
                expose_port=False,
                full_image_name=full_image_name,
                publish_all_ports=True)

            # TODO: This should probably specifically get the 'nessus' exposed port, since there could be multiples.
            nessus_port = docker_nessus.get_exposed_port(cid)
            host = docker_config.DOCKER_SCANNER_HOST.split('//')[1].split(':')[0]
            NessusConfig.CAT_NESSUS_URL = "https://{}:{}".format(host, nessus_port)
            Config.NESSUS_CONTAINER = docker_nessus.get(cid=cid)
        except ImageNotFound:
            print("Docker image %s is not available on the Docker host.", full_image_name)

        assert cid, "Docker container failed to start."

        log.info('CID of Nessus container for this session is: ' + cid)

        if docker_config.WAIT_FOR_STATUS_AVAILABLE:
            log.info('fixture init: waiting for status available')
            api = NessusAPI()
            wait_for_scanner_status(api=api, status=API.Status.READY,
                                    timeout=TIME_TEN_MINUTES, msg='Availability of Nessus scanner',
                                    sleep_interval=TIME_FIVE_SECONDS)
            log.info('nessus has become available.')
            # Let the tests begin!
    yield

    if docker_config.USE_DOCKER_AS_PRIMARY_NESSUS:
        log.info('removing docker container scanner')
        clean_up(cid=cid, nessus_type='scanner', linked=False)


@pytest.fixture()
def create_plugin_rules(request: SubRequest, nessus_api_login):
    """ create plugin rules"""
    plugin_response_id = None
    created_plugins = []

    try:
        for plugin in request.param.get('plugin_list'):
            request.cls.cat.api.plugins.add_plugin_rules(data=plugin)
            assert request.cls.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % nessus_api_login.http_status_code

            for element in request.cls.cat.api.plugins.list_plugin_rules()['plugin_rules']:
                plugin_response_id = element['id'] if element['plugin_id'] == plugin['plugin_id'] else None

            created_plugins.append({'plugin_response_id': plugin_response_id, 'host_name': plugin['host'],
                                    'plugin_id': plugin['plugin_id']})
        yield created_plugins
    finally:
        # delete plugin
        for plugin in created_plugins:
            try:
                nessus_api_login.plugins.delete_plugin_rule(plugin['plugin_response_id'])
            except:
                log.debug('plugin rule is already deleted')


@pytest.fixture()
def enable_scan_wizard():
    """This fixture will enable fix parameter show_initial_scan_wizard"""
    nessus_cli = get_nessus_cli()
    execute(nessus_cli, ['fix', '--set', 'show_initial_scan_wizard=yes'])
    yield
    execute(nessus_cli, ['fix', '--set', 'show_initial_scan_wizard=no'])


def link_node_to_master(api, docker_network, master_host, master_port, linking_key, port_map):
    """ Start a node container and link it to the master, returning the node info """
    docker_registry = os.getenv('DOCKER_REGISTRY', 'docker-registry.cloud.aws.tenablesecurity.com:8888')
    child_container = docker_registry + '/services/nessus-centos7:release-next'
    name = random_name('nm-child-')

    cmd = 'docker run -d -p %s:8834 --rm --name %s --network %s %s' % (port_map, name, docker_network, child_container)
    subprocess.run(cmd.split())

    cmnd = 'docker exec %s /opt/nessus/sbin/nessuscli node link --name=%s --host=%s --port=%d --key=%s --self-host=%s' \
           ' --self-port=%d' % (name, name, master_host, master_port, linking_key, master_host, port_map)

    try:
        log.debug("Executing: %s" % cmnd)
        node_link_output = subprocess.check_output(cmnd.split(), stderr=subprocess.PIPE)
        log.info("Linked node output is : {}".format(node_link_output))
    except subprocess.CalledProcessError as e:
        log.error("Error, code %s" % e.returncode)
        stdout = e.output.decode('utf-8')
        stderr = e.stderr.decode('utf-8')

        if stdout:
            log.error(stdout)
            return stdout
        if stderr:
            log.error(stderr)

    def lookup_node_on_master():
        try:
            return [node for node in api.nodes.list()['nodes'] if node['name'] == name][0]
        except:
            pass

    waiting_wait(lookup_node_on_master, sleep_seconds=5, timeout_seconds=TIME_FIVE_MINUTES,
                 waiting_for='Node %s to link successfully' % name)

    return lookup_node_on_master()


def link_agent_to_master(docker_network, master_host, master_port, linking_key, api=None, agent_port=None) -> dict:
    """ Start an agent container and link it to the master, returning the agent info """
    agent_details = {}
    docker_registry = os.getenv('DOCKER_REGISTRY', 'docker-registry.cloud.aws.tenablesecurity.com:8888')
    agent_container = docker_registry + '/services/nessus-centos8-agent:release-next'
    name = random_name('agent-')

    if agent_port:
        cmd = 'docker run -d -p %s:22 --rm --name %s --network %s %s' % (agent_port, name, docker_network,
                                                                         agent_container)
    else:
        cmd = 'docker run -d --rm --name %s --network %s %s' % (name, docker_network, agent_container)

    subprocess.run(cmd.split())

    def link_cmd():
        cmnd = 'docker exec %s /opt/nessus_agent/sbin/nessuscli agent link --name=%s' % (name, name) + \
               ' --host=%s --port=%d --key=%s' % (master_host, master_port, linking_key)
        try:
            log.debug("Executing: %s" % cmnd)
            cmnd_output = subprocess.check_output(cmnd.split(), stderr=subprocess.PIPE)
            return b'Successfully linked' in cmnd_output
        except subprocess.CalledProcessError as e:
            log.error("Error, code %s" % e.returncode)
            stdout = e.output.decode('utf-8')
            stderr = e.stderr.decode('utf-8')

            if stdout:
                log.error(stdout)
                return stdout
            if stderr:
                log.error(stderr)

            pass

    # Retrying to link agent until it gets successfully linked!
    # Note: Retry works when node is not ready for agent to get linked!
    for _ in range(5):
        link_output = link_cmd()

        if type(link_output) != bool and "code 400: Node is not ready to link yet" in link_output:
            sleep(10, reason="Retrying to link agent!!")
        else:
            if type(link_output) != bool:
                agent_details['output'] = link_output.split('\n')[-2]

            break

    if api:
        def lookup_agent_on_master():
            try:
                return [agent for agent in api.agents.agents_list()['agents'] if agent['name'] == name][0]
            except (TypeError, IndexError, KeyError):
                pass

        waiting_wait(lookup_agent_on_master, sleep_seconds=3, timeout_seconds=60,
                     waiting_for='Agent %s to appear on master' % name)

        return lookup_agent_on_master()
    else:
        agent_details['name'] = name

        return agent_details


@pytest.fixture(scope='class')
def disable_cluster_parent_node():
    """This fixture set fix parameter 'cluster_parent_node' value to 'no'."""
    yield
    ssh = SSH()
    output = ssh.execute("{} fix --secure --get cluster_parent_node".format(get_nessus_cli()))[0]
    if not output.split('is')[1].split("'")[1] == 'no':
        ssh.execute("{} fix --secure --set cluster_parent_node=no".format(get_nessus_cli()))
        api = NessusAPI()
        try:
            wait_for_scanner_status(api=api, timeout=TIME_FIVE_MINUTES, status=API.Status.LOADING,
                                    msg='Waiting for server to finish loading.')
        except TimeoutExpired:
            log.warning("Nessus did not get 'loading' status after enabling cluster")
        wait_for_scanner_status(api=api, timeout=TIME_FIFTEEN_MINUTES, status=API.Status.READY,
                                msg='Waiting for server to finish loading.')


@pytest.fixture(scope='class')
def create_manager_cluster(request: SubRequest):
    """This fixture will enable clustering on the manager, connect two nodes, and an agent"""
    total_nodes = request.param['total_nodes'] if hasattr(request, 'param') and 'total_nodes' in request.param else 3
    total_agents = request.param['total_agents'] if hasattr(request, 'param') and 'total_agents' in request.param else 2
    log.info('Enabling clustering on master node')

    api = NessusAPI()
    wait_for_scanner_status(api=api, timeout=TIME_TEN_MINUTES, status=API.Status.READY,
                            msg='Waiting for server to finish loading.')
    api.login()
    api.agents.edit_config({'cluster': True})

    assert api.http_status_code == HTTPStatus.OK, 'Expected 200, got %s instead' % api.http_status_code

    try:
        wait_for_scanner_status(api=api, timeout=TIME_FIVE_MINUTES, status=API.Status.LOADING,
                                msg='Waiting for server to finish loading.')
    except TimeoutExpired:
        log.warning("Nessus did not get 'loading' status after enabling cluster")

    wait_for_scanner_status(api=api, timeout=TIME_FIFTEEN_MINUTES, status=API.Status.READY,
                            msg='Waiting for server to finish loading.')

    docker_network = os.getenv('DOCKER_NETWORK')

    if not docker_network:
        docker_network = random_name('autonet-')
        subprocess.run(('docker network create %s' % docker_network).split())

    master_host = re.sub(r'.*//(.*):.*', r'\1', Config.CAT_URL)
    master_port = int(re.sub(r'.*:(\d+).*', r'\1', Config.CAT_URL))
    linking_key = api.scanners.get_node_linking_key()['key']
    agent_linking_key = api.scanners.get_agent_linking_key()['key']

    children, agents = [], []

    try:
        log.info('Starting nodes and linking them to master')
        for _ in range(0, total_nodes):
            port_map = randint(33000, 33999)
            node = link_node_to_master(api, docker_network, master_host, master_port, linking_key, port_map)
            log.info('Linked node %s successfully', node['name'])

            waiting_wait(lambda: [linked_node for linked_node in api.nodes.list()['nodes'] if linked_node['name'] ==
                                  node['name']][0]['status'] == "online", sleep_seconds=TIME_THREE_SECONDS,
                         timeout_seconds=TIME_FIVE_MINUTES, waiting_for="Waiting for node to get online status")
            node['port_map'] = port_map
            children.append(node)

        log.info('Starting agents and linking them to master')
        for _ in range(0, total_agents):
            agent = link_agent_to_master(docker_network, master_host, master_port, agent_linking_key, api)
            log.info('Linked agent %s successfully', agent['name'])
            agents.append(agent)

        api.logout()

        yield {'nodes': children, 'agents': agents}

    finally:
        log.info('Destroying nodes and agents')

        api.login()
        for agent in agents:
            subprocess.run(('docker stop %s' % agent['name']).split())
            api.agents.delete_agent(agent['id'])

        for child in children:
            subprocess.run(('docker stop %s' % child['name']).split())
            try:
                api.nodes.delete(node_id=child['id'])
            except HTTPError:
                if not (api.http_status_code == HTTPStatus.BAD_REQUEST and
                        api._text == '{"error":"Cannot delete the last node in the default cluster group."}'):
                    raise Exception("Error while deleting node! Error is : {}".format(api._text))

        if docker_network.startswith('autonet-'):
            subprocess.run(('docker network rm %s' % docker_network).split())

        api.logout()
        execute(get_nessus_cli(), ['fix', '--secure', '--set', 'cluster_parent_node=no'])
        # Wait till Nessus becomes ready
        try:
            wait_for_scanner_status(api=api, timeout=TIME_FIVE_MINUTES, status=API.Status.LOADING,
                                    msg='Waiting for server to finish loading.')
        except TimeoutExpired:
            log.warning("Nessus did not get 'loading' status after enabling cluster")
        wait_for_scanner_status(api=api, timeout=TIME_FIFTEEN_MINUTES, status=API.Status.READY,
                                msg='Waiting for server to finish loading.')


def start_and_link_sensor_proxy(host, key, network):
    """ Start a Sensor Proxy container and link it to the provided Tenable.io host/port"""
    output = ""
    image_name = os.getenv('SPIMAGE', 'docker-registry.cloud.aws.tenablesecurity.com:8888/nessus/sensor-proxy:latest')
    name = random_name('sensor-proxy-')

    for cmd in [
        'docker run --network %s --name %s --rm -d -t -p :443 %s bash' % (network, name, image_name),
        'docker exec %s sed -ie s/cloud.tenable.com/%s/ /opt/sensor_proxy/config/sidecar.json' % (name, host),
        'docker exec %s cat /opt/sensor_proxy/config/sidecar.json' % name,
        'docker exec %s /opt/sensor_proxy/sbin/sidecar --cli --link --key=%s' % (name, key),
        'docker exec %s /opt/sensor_proxy/sbin/sensorproxy' % name
    ]:
        log.debug('executing: %s' % cmd)

        try:
            output = subprocess.check_output(cmd.split(), stderr=subprocess.PIPE)
            log.info("Output after executing docker commands :: :: {}".format(output))
        except subprocess.CalledProcessError as e:
            log.error("Error, code %s" % e.returncode)
            stdout = e.output.decode('utf-8')
            stderr = e.stderr.decode('utf-8')

            if stdout:
                log.error(stdout)
            if stderr:
                log.error(stderr)

            pass

    try:
        output = subprocess.check_output(('docker inspect %s' % name).split())
    except subprocess.CalledProcessError as e:
        log.error("Error, code %s" % e.returncode)
        stdout = e.output.decode('utf-8')
        stderr = e.stderr.decode('utf-8')

        if stdout:
            log.error(stdout)
        if stderr:
            log.error(stderr)

        pass

    container_data = json.loads(output)[0]

    def proxy_request():
        cmnd = 'docker exec %s curl -ks https://127.0.0.1/remote/properties' % name

        try:
            log.debug("Executing: %s" % cmnd)
            proxy_request_output = subprocess.check_output(cmnd.split(), stderr=subprocess.PIPE)
            # pylint: disable=unsupported-membership-test
            return b'nessus_ui_version' in proxy_request_output
        except subprocess.CalledProcessError as e:
            log.error("Error, code %s" % e.returncode)
            stdout = e.output.decode('utf-8')
            stderr = e.stderr.decode('utf-8')

            if stdout:
                log.error(stdout)
            if stderr:
                log.error(stderr)

            pass

    waiting_wait(proxy_request, sleep_seconds=5, timeout_seconds=30,
                 waiting_for='Sensor Proxy to become available on port 443')

    return container_data


def create_tio_container(request: SubRequest, tenableio_site: str = NessusConfig.CAT_TIO_URL.split('.')[0]) -> dict:
    outcome = {'product': 'tenableio', 'site': tenableio_site}
    container = None

    @request.addfinalizer
    def _teardown():
        """ Teardown section """
        log.info('*** Fixture "%s" teardown: Teardown Tenable.IO container ***', request.fixturename)
        # If enable cleanup is disabled, it will ignore cleanup for all tests.
        # If clean up on failure is disabled, then check that the test has not failed to clean up.
        # Otherwise log and skip clean up.
        with product_and_site(product=outcome['product'], site=outcome['site']):
            if container:
                delete_container(container_uuid=container.model.uuid)

    with product_and_site(product='tenableio', site=tenableio_site):
        container = create_container()
        log.info('Created container: %s' % container.details['name'])
        outcome['container'] = container
        api = TenableCloudAPI()
        api.login(username=container.model.contact, password=container.model.password)
        linking_key = api.scanners.get_linking_key()['key']
        outcome['linking_key'] = linking_key
        api.logout()

    return outcome


@pytest.fixture(scope='session')
def retry_tio_linking(request: 'SubRequest') -> int:
    """
    Return value for retry count to link with tio.
    :rtype int
    """
    return int(getattr(request, 'param', 3))


def delete_and_unlink_nessus_from_tenableio(tenable_api: TenableCloudAPI,
                                            scanner_name: str) -> None:
    """
    Deletes scanner from T.io and unlinks it from Nessus instance
    :param tenable_api: TenableCloudAPI instance
    :param scanner_name: scanner's name to unlink/delete
    """
    try:
        scanner_id = tenable_api.scanners.helper_get_scanner_id(name=scanner_name, uuid=False)
        if scanner_id is not None:
            log.debug("Deleting scanner with ID {}".format(scanner_id))
            tenable_api.scanners.delete(scanner_id)
    except Exception as ex:
        log.warning("Failed to delete Nessus Scanner from T.io. Error was {}".format(str(ex)))
    nessus_api = NessusAPI()

    try:
        nessus_api.login()
        nessus_api.scanners.unlink_to_cloud(from_scanner=True)
    except Exception as ex:
        log.warning("Failed to unlink Nessus. Error was {}".format(str(ex)))
    finally:
        try:
            nessus_api.logout()
        except Exception as e:
            log.warning("Unable to perform api logout. Exception is : {}".format(e))


@pytest.fixture(scope='session')
def get_api_handler(request: 'SubRequest'):
    """Wrapper fixture for API; if api is present in request.cls.cat use that API"""
    if not request.instance.cat.api:
        request.instance.cat.nessus_api = NessusAPI()
    yield
    request.instance.cat.nessus_api = None


@pytest.fixture(scope='session')
def link_scanner(request: 'SubRequest', retry_tio_linking):
    log.debug("Fixture init: Linking Nessus Scanner to T.io.")

    container_details = create_tio_container(request)
    scanner_name = "test_nessus_scanner_%s" % uuid4().hex[:6]

    # get linking key from create_tio_container fixture
    linking_key = container_details['linking_key']
    tenable_io_site = NessusConfig.CAT_TIO_URL

    nessus_api = NessusAPI()

    # Making sure Nessus is in ready state before test starts
    wait_for_scanner_status(api=nessus_api, status=API.Status.READY, timeout=TIME_TEN_MINUTES * 3,
                            msg='registration to complete.')
    nessus_api.login()
    api = TenableCloudAPI()
    api.login(username=container_details['container'].model.contact,
              password=container_details['container'].model.password)

    try:
        link_status = False
        for _ in range(0, retry_tio_linking):
            try:
                wait_for_scanner_status(api=nessus_api, status=API.Status.READY,
                                        timeout=TIME_FIFTEEN_MINUTES, msg='Availability of Nessus scanner API',
                                        sleep_interval=TIME_FIVE_SECONDS)
                nessus_api.scanners.link_to_cloud(manager_host=tenable_io_site,
                                                  linking_key=linking_key,
                                                  scanner_name=scanner_name,
                                                  manager_port="443",
                                                  use_proxy=False,
                                                  register=True)

                waiting_wait(lambda: [scanner for scanner in api.scanners.get_list()['scanners'] if scanner_name ==
                                      scanner['name']], sleep_seconds=TIME_TEN_SECONDS,
                             timeout_seconds=TIME_SIXTY_SECONDS, waiting_for="Scanner to appear in scanners list")
                log.debug('Successfully linked with Tenable.io, Scanner Name: %s', scanner_name)
                link_status = True
                break
            except Exception as ex:
                log.warning(
                    "Exception occurred while linking Nessus scanners to Tenable.io. Error is {}".format(str(ex)))
                delete_and_unlink_nessus_from_tenableio(api, scanner_name)
        if retry_tio_linking > 1:
            if not link_status:
                raise AssertionError('Failed to link Nessus to Tenable.io after 3 retries')
        wait_for_scanner_status(api=nessus_api, status=API.Status.LOADING, timeout=TIME_TEN_MINUTES,
                                sleep_interval=TIME_FIVE_SECONDS, msg='Availability of Nessus scanner')

        wait_for_scanner_status(api=nessus_api, status=API.Status.READY, timeout=TIME_TEN_MINUTES,
                                msg='Availability of Nessus scanner API after linking to t.io.',
                                sleep_interval=TIME_FIVE_SECONDS)
        yield scanner_name
    finally:
        log.debug("Fixture teardown: Unlinking Nessus Scanner and deleting Nessus scanner in T.io.")
        delete_and_unlink_nessus_from_tenableio(api, scanner_name)


def fake_sp_agent(host, key, groups=None):
    agent_uuid = random_agent_uuid()
    payload = {
        'agent_uuid': agent_uuid,
        'distro': 'win-x86-64',
        'key': key,
        'name': agent_uuid,
        'platform': PLATFORM_WINDOWS.upper(),
        'ips': {'v4': ["{0}.{1}.{2}.{3}".format(randrange(1, 254), randrange(1, 254), randrange(1, 254),
                                                randrange(1, 254))],
                'v6': None}
    }

    api = NessusAPI(url=host)

    if groups:
        payload['groups'] = groups

    try:
        response = ResponseObject(api.request(HTTPMethods.POST, routes.REMOTE_AGENT, json=payload))
    except HTTPError as error:
        log.error("Request threw %s: %s", error.__class__.__name__, error)
        raise

    return {'name': payload['name'], 'agent_uuid': payload['agent_uuid'], 'token': response['token']}


@pytest.fixture(scope='session')
def create_sensor_proxy_tio(request: SubRequest):
    """ This fixture will create a new Sensor Proxy container, link it to Tenable.io, and start its services. """

    log.info('Creating a new Sensor Proxy docker container and Tenable.io container.')

    docker_network = os.getenv('DOCKER_NETWORK')

    if not docker_network:
        docker_network = random_name('autonet-')
        subprocess.run(('docker network create %s' % docker_network).split())

    log.info("Creating Tenable.io container")
    container_details = create_tio_container(request)

    log.info("Creating and linking Sensor Proxy")
    proxy_container = start_and_link_sensor_proxy(host=NessusConfig.CAT_TIO_URL,
                                                  key=container_details['linking_key'], network=docker_network)

    sp_url = proxy_container['Name'].replace("/", "")

    if os.getenv('IS_RUNNING_IN_PYTESTER', "0") != "1":
        port = proxy_container['NetworkSettings']['Ports']['443/tcp'][0]['HostPort']
        sp_url = "localhost:" + port

    proxy_container['URL'] = sp_url
    yield {
        'proxy_container': proxy_container,
        'container': container_details['container'],
        'linking_key': container_details['linking_key'],
        'docker_network': docker_network
    }

    log.info("Tearing down Sensor Proxy and Tenable.io container setup.")
    subprocess.run(('docker stop %s' % proxy_container['Name']).split())
    subprocess.run('docker container prune -f'.split())
    subprocess.run(('docker network rm %s' % docker_network).split())


def link_scanner_to_master(docker_network: str, master_host: str, master_port: int, linking_key: str, api=None) -> dict:
    """
    Start a scanner and link it to the master, returning the scanner info

    :param str docker_network: docker network id/name
    :param str master_host: host name where scanner needs to be linked
    :param int master_port: port number like 443
    :param str linking_key: linking key of master host
    :param api: None
    :return: scanner details
    :rtype: dict
    """
    scanner_details = {}
    docker_registry = os.getenv('DOCKER_REGISTRY', 'docker-registry.cloud.aws.tenablesecurity.com:8888')
    scanner_container = docker_registry + '/services/nessus-centos7:release-next'
    name = random_name('scanner-')

    cmd = 'docker run -d --rm --name %s --network %s %s' % (name, docker_network, scanner_container)
    subprocess.run(cmd.split())

    def link_cmd():
        cmnd = 'docker exec %s /opt/nessus/sbin/nessuscli managed link --name=%s' % (name, name) + \
               ' --host=%s --port=%d --key=%s' % (master_host, master_port, linking_key)
        try:
            log.debug("Executing: %s" % cmnd)
            cmnd_output = subprocess.check_output(cmnd.split(), stderr=subprocess.PIPE)
            return b'Successfully linked' in cmnd_output
        except subprocess.CalledProcessError as e:
            log.error("Error, code %s" % e.returncode)
            stdout = e.output.decode('utf-8')
            stderr = e.stderr.decode('utf-8')

            if stdout:
                log.error(stdout)
                return stdout
            if stderr:
                log.error(stderr)

            pass

    link_output = link_cmd()

    if type(link_output) != bool:
        scanner_details['output'] = link_output.split('\n')[-2]

    if api:
        def lookup_scanner_on_master():
            try:
                return [scanner for scanner in api.scanners.get_list()['scanners'] if scanner['name'] == name][0]
            except (TypeError, IndexError, KeyError):
                pass

        waiting_wait(lookup_scanner_on_master, sleep_seconds=3, timeout_seconds=60,
                     waiting_for='Scanner %s to appear on master' % name)

        return lookup_scanner_on_master()
    else:
        scanner_details['name'] = name
        return scanner_details


def add_remote_scanner_sp(host, key):
    payload = {'name': random_name(prefix='scanner-'), 'key': key, 'suuid': random_agent_uuid(),
               'distro': 'es7-x86-64', 'platform': 'LINUX',
               'ips': {'v4': ["{0}.{1}.{2}.{3}".format(randrange(1, 254), randrange(1, 254), randrange(1, 254),
                                                       randrange(1, 254))],
                       'v6': None}
               }

    api = NessusAPI(url=host)

    try:
        response = ResponseObject(api.request(HTTPMethods.POST, routes.REMOTE_SCANNER, json=payload))
    except HTTPError as error:
        log.error("Request threw %s: %s", error.__class__.__name__, error)
        raise

    return {'name': payload['name'], 'suuid': payload['suuid'], 'token': response['token']}


@pytest.fixture(scope="session")
def create_agent_group_with_real_agent(request: SubRequest):
    """ This fixture is created to add real agent to Agent group in Nessus Manager."""
    log.debug('fixture init: Link agent to Nessus manager and add it to agent group.')
    api = NessusAPI()

    wait_for_scanner_status(api=api, status=API.Status.READY, timeout=TIME_TEN_MINUTES,
                            sleep_interval=TIME_FIVE_SECONDS, msg='Availability of Nessus scanner')

    api.login()
    docker_network = os.getenv('DOCKER_NETWORK')

    if not docker_network:
        docker_network = random_name('autonet-')
        subprocess.run(('docker network create %s' % docker_network).split())

    master_host = re.sub(r'.*//(.*):.*', r'\1', Config.CAT_URL)
    master_port = int(re.sub(r'.*:(\d+).*', r'\1', Config.CAT_URL))
    linking_key = api.scanners.get_agent_linking_key()['key']

    agent = link_agent_to_master(api=api, docker_network=docker_network, master_host=master_host,
                                 master_port=master_port, linking_key=linking_key)

    def is_agent_online(agent_id):
        try:
            return api.agents.get_agent_details(agent_id)['status'] == 'online'
        except:
            return None

    waiting_wait(lambda: is_agent_online(agent['id']), timeout_seconds=TIME_FIFTEEN_MINUTES, sleep_seconds=30,
                 waiting_for='agent %s to appear online' % id)

    agent_group_name = random_name(prefix="agent-group")
    agent_group = api.agent_groups.create(scanner_id=1, name=agent_group_name)
    api.agent_groups.add_agent(scanner_id=1, group_id=agent_group['id'], agent_id=agent['id'])

    yield {"agent_name": agent['name'], "agent_id": agent['id'], "agent_group_name": agent_group_name,
           "agent_group_id": agent_group['id'], "agent_ip": agent['ip']}
    subprocess.run(('docker stop %s' % agent['name']).split())
    if docker_network.startswith('autonet-'):
        subprocess.run(('docker network rm %s' % docker_network).split())
    try:
        api.agent_groups.delete(scanner_id=1, group_id=agent_group['id'])
        api.agents.delete(scanner_id=1, agent_id=agent['id'])
    except:
        log.warning("Error while deleting agent_group and/or linked agent.")


def link_child_node_to_parent_node() -> dict:
    """ Link child cluster node to parent node """

    docker_network = os.getenv('DOCKER_NETWORK')

    if not docker_network:
        docker_network = random_name('autonet-')
        subprocess.run(('docker network create %s' % docker_network).split())

    api = NessusAPI()
    api.login()

    master_host = re.sub(r'.*//(.*):.*', r'\1', Config.CAT_URL)
    master_port = int(re.sub(r'.*:(\d+).*', r'\1', Config.CAT_URL))
    linking_key = api.scanners.get_node_linking_key()['key']

    log.info('Link a new node to master')
    port_map = randint(33000, 33999)

    node = link_node_to_master(api, docker_network, master_host, master_port, linking_key, port_map)
    log.info('Linked node %s successfully', node['name'])

    waiting_wait(lambda: [linked_node for linked_node in api.nodes.list()['nodes'] if linked_node['name'] ==
                          node['name']][0]['status'] == "online", sleep_seconds=TIME_THREE_SECONDS,
                 timeout_seconds=TIME_FIVE_MINUTES, waiting_for="Waiting for node to get online status")

    node['port_map'] = port_map
    api.logout()

    return node


@pytest.fixture(scope="class")
def add_fake_cluster_agents(request: SubRequest):
    """This fixture will add fake agents in bulk."""
    total_agents = request.param['total_no_of_agents'] if hasattr(request, 'param') and 'total_no_of_agents' in \
                                                          request.param else 500
    new_node = link_child_node_to_parent_node()
    agent_names = []
    log.info("Linked node is : {}".format(new_node))
    api = NessusAPI()
    api.login()
    linking_key = api.scanners.get_agent_linking_key()['key']

    for i in range(total_agents):
        agent_uuid = random_agent_uuid()
        agent_name = random_name(prefix=random.choice(["Linux-", "Windows-", "MacOS-"]))
        payload = {
            'agent_uuid': agent_uuid,
            'distro': random.choice(["dist1", "dist2", "dist3"]),
            'key': linking_key,
            'name': agent_name,
            'platform': random.choice(["Linux", "Windows", "MacOS"]),
            'clusterCompatible': True,
            'node_request': True,
            'uuid': str(uuid.uuid4())
        }
        node_ip = re.sub(r'.*//(.*):.*', r'\1', Config.CAT_URL)

        def add_agent():
            """Adding agent to newly linked node and retrying till it gets linked successfully"""
            try:
                log.debug("Trying to add agent!!")
                resp = requests.post("https://%s:%s/remote/agent" % (node_ip, new_node["port_map"]), json=payload,
                                     verify=False)
                log.debug("Linking response is : {}".format(resp))
                return True if resp.status_code == 200 else False
            except Exception as e:
                log.warning("Got Error for the request. Error is : {}".format(e))
                return False

        # Adding agent to node
        try:
            waiting_wait(lambda: add_agent(), timeout_seconds=TIME_THREE_MINUTES, sleep_seconds=TIME_FIVE_SECONDS,
                         waiting_for="Agent to get linked.")
        except TimeoutExpired:
            raise AssertionError("Error while linking agent to node: {}".format(new_node['name']))
        agent_names.append(agent_name)

    def get_linked_agents():
        """Getting the linked agents count in cluster manager"""
        try:
            return len(api.agents.get_agents(scanner_id=1)['agents'])
        except TypeError:
            return 0

    # Wait till all agents gets populated in cluster manager.
    waiting_wait(lambda: get_linked_agents() >= total_agents, timeout_seconds=TIME_FIVE_MINUTES,
                 sleep_seconds=TIME_FIVE_SECONDS, waiting_for="All agents to get linked properly")
    api.logout()

    yield

    log.info("Delete added fake agents...")
    api.login()

    # Deleting linked agents
    for agent in api.agents.get_agents(scanner_id=1)['agents']:
        if agent['name'] in agent_names:
            try:
                api.agents.delete(scanner_id=1, agent_id=agent['id'])
            except Exception as e:
                log.warning("Got Error while deleting agent. Error is : {}".format(e))
        else:
            log.warning("This agent did not get deleted : {}".format(agent['name']))

    # Delete Node from cluster manager
    try:
        subprocess.run(('docker stop %s' % new_node['name']).split())
        api.nodes.delete(node_id=new_node['id'])
    except Exception as e:
        log.warning("Error while deleting node : {}. Error is : {}".format(new_node['name'], e))

    api.logout()


@pytest.fixture()
def add_new_cluster_group(request: SubRequest):
    """Add a cluster group in cluster manager"""
    cluster_group_name = random_name(prefix="cluster_group")
    cluster_group_id = request.instance.cat.api.clustergroups.add({'name': cluster_group_name})['cluster_group_id']
    yield {'name': cluster_group_name, 'id': cluster_group_id}
    try:
        request.instance.cat.api.clustergroups.delete(cluster_group_id)
    except HTTPError as e:
        log.warning("Unable to delete the cluster group : '{}'. Error is : {}".format(cluster_group_name, e))


@pytest.fixture()
def add_node_in_cluster_manager(request: SubRequest):
    """Add node in the cluster manager"""
    node = link_child_node_to_parent_node()
    yield node
    api = NessusAPI()
    try:
        wait_for_scanner_status(api=api, status=API.Status.READY,
                                timeout=TIME_FIVE_MINUTES, msg='Availability of Nessus scanner',
                                sleep_interval=TIME_FIVE_SECONDS)
        request.instance.cat.api.nodes.delete(node_id=node['id'])
    except HTTPError as e:
        log.warning("Unable to delete the node : '{}'. Error is : {}".format(node['name'], e))
        log.info("\n\n\nlist of all node:{}\n\nnode-details-of-extra-node:{}".format(
            request.instance.cat.api.nodes.list(), request.instance.cat.api.nodes.get(node_id=node['id'])))
    finally:
        wait_for_scanner_status(api=api, status=API.Status.READY,
                                timeout=TIME_FIVE_MINUTES, msg='Availability of Nessus scanner',
                                sleep_interval=TIME_FIVE_SECONDS)


@pytest.fixture(scope='class')
def disable_auto_update(request: SubRequest):
    """This fixture will disable auto_update in Nessus and wait till Nessus becomes ready."""
    with SSH() as ssh:
        ssh.execute("{} fix --set auto_update=no".format(get_nessus_cli()))
    api = NessusAPI()
    try:
        wait_for_scanner_status(api=api, status=API.Status.LOADING,
                                timeout=TIME_TWO_MINUTES, msg='Nessus to be in loading state',
                                sleep_interval=TIME_FIVE_SECONDS)
    except TimeoutExpired:
        log.warning("Nessus loading status not found!")
    finally:
        wait_for_scanner_status(api=api, status=API.Status.READY,
                                timeout=TIME_TEN_MINUTES, msg='Availability of Nessus scanner',
                                sleep_interval=TIME_TEN_SECONDS)


@pytest.fixture()
def delete_all_exclusions(request: 'SubRequest'):
    """Delete all exclusions in Nessus"""

    for exclusion in request.instance.cat.api.exclusions.get_exclusions(scanner_id=1)['exclusions']:
        request.instance.cat.api.exclusions.delete(exclusion['id'], 1)


@pytest.fixture()
def create_scheduled_blackout_window_and_wait_till_activated(request: SubRequest):
    """Create a scheduled blackout window for given time duration and wait till it gets activated"""

    log.debug('fixture init: create_exclusion: Create a new exclusion')

    bw_duration = request.param['bw_duration_minutes'] if \
        hasattr(request, 'param') and 'bw_duration_minutes' in request.param else 10
    timezone = 'America/New_York'
    start_time = (pytz.utc.localize(datetime.utcnow()) + timedelta(minutes=1)).astimezone(pytz.timezone(timezone))
    end_time = (pytz.utc.localize(datetime.utcnow()) + timedelta(minutes=bw_duration + 1)).astimezone(
        pytz.timezone(timezone))

    payload = {"name": random_name('exclusion-'), "description": "", "agent_group_id": None,
               "schedule": {"enabled": True, "rrules": {"freq": "ONETIME", "interval": 1},
                            "timezone": "Eastern Standard Time" if get_os_name() == OperatingSystems.WINDOWS
                            else timezone, "starttime": start_time.strftime('%Y-%m-%d %H:%M:00'),
                            "endtime": end_time.strftime('%Y-%m-%d %H:%M:00'), "launch": "ONETIME"}}

    exclusion = request.instance.cat.api.agents.exclusions_add(data=payload)
    waiting_wait(lambda: pytz.utc.localize(datetime.utcnow()).
                 astimezone(pytz.timezone(timezone)).minute == start_time.minute + 1,
                 sleep_seconds=WAIT_SHORT, timeout_seconds=TIME_FIVE_MINUTES,
                 waiting_for="blackout window gets enabled")
    yield exclusion
    log.debug('fixture teardown: create_exclusion: Remove exclusion %s ', exclusion)
    try:
        request.instance.cat.api.exclusions.delete(exclusion['id'], scanner_id=1)
    except HTTPError as exc:
        log.warning("Unable to delete Exclusion in clean up. Exclusion may have been deleted by test. Error:%s", exc)


@pytest.fixture(scope='class')
def disable_signature_verification():
    """Disable signature verification by setting secure fix parameter feed_no_sig as 'yes'."""
    with SSH() as ssh:
        ssh.execute("/opt/nessus/sbin/nessuscli fix --set --secure feed_no_sig=yes")

        stop_nessus()
        start_nessus()

    api = NessusAPI()
    wait_for_scanner_status(api=api, status=API.Status.LOADING, timeout=TIME_FIVE_MINUTES,
                            sleep_interval=TIME_FIVE_SECONDS, msg='Wait for loading')
    wait_for_scanner_status(api=api, status=API.Status.READY, timeout=TIME_TEN_MINUTES,
                            sleep_interval=TIME_FIVE_SECONDS, msg='Availability of Nessus scanner')


@pytest.fixture()
def fresh_install_nessus(request: SubRequest):
    """
    This fixture uninstalls the current Nessus and does fresh installation of Nessus.
    Make sure to put the nessus build in /install dir
    Pass the Nessus type in parameters
    For Ex:
        @pytest.mark.parametrize('fresh_install_nessus', ['professional'], indirect=True)
    """
    nessus_type = request.param

    os_commands = {'CentOS': {'search_nessus': 'rpm -qa | grep Nessus', 'remove_nessus': 'rpm -e ',
                              'install_nessus': 'rpm -ivh '}}
    ssh = SSH()

    installed_os = ssh.execute(command='{} {}'.format(get_command(
        'display_content'), NessusInstallation.OS_RELEASE_FILE_PATH))[0].split('=')[1].split()[0].strip('"')

    installed_nessus = ssh.execute(command=os_commands[installed_os]['search_nessus'])
    log.debug("Installed Nessus Packages :: {}".format(installed_nessus))

    stop_nessus()
    installed_nessus_package_name = installed_nessus[0] if installed_os == 'CentOS' else 'nessus'

    log.info("Removing Nessus package and nessus directory")
    ssh.execute(command=os_commands[installed_os]['remove_nessus'] + installed_nessus_package_name)
    ssh.execute(command='{} {}'.format(get_command(operation='remove_file'), NessusInstallation.NESSUS_DIR_PATH))

    install_nessus_output = ssh.execute(command=os_commands[installed_os]['install_nessus'] + NessusInstallation.
                                        BUILD_PATH[installed_os], timeout=TIME_FIVE_MINUTES)
    log.debug("Install Nessus output :: {}".format(install_nessus_output))
    start_nessus()

    log.info('Waits for Nessus to be ready to get registered')
    nessus_api = NessusAPI()
    wait_for_scanner_status(api=nessus_api, status=API.Status.REGISTER, timeout=TIME_FIVE_MINUTES,
                            msg='Waiting for nessus to get ready for register')

    log.info('Adding admin user into Nessus')
    nessus_api.users.create(payload=NessusInstallation.ADMIN_USER_PAYLOAD)

    log.info("Setting auto_update value to 'no'")
    ssh.execute("{} fix --set auto_update=no".format(get_nessus_cli()))
    ssh.execute(command='{} fix --secure --set custom_host="{}"'.format(get_nessus_cli(),
                                                                        CommonConfig.CAT_PLUGIN_FEED_HOST))

    activation_code = ActivationCodeGenerator().generate_code(code_type=nessus_type,
                                                              expiration_days=Nessus.DEFAULT_EXPIRATION_DAYS)

    register_nessus_output = ssh.execute("{} fetch --register-only {}".format(get_nessus_cli(), activation_code))

    # Verifies successful Nessus registration message
    assert any('Your Activation Code has been registered properly - thank you.' in register_output for
               register_output in register_nessus_output), 'Failed to register Nessus {}'.format(nessus_type)

    stop_nessus()
    ssh.execute("{} update --plugins-only".format(get_nessus_cli()), timeout=TIME_FIVE_MINUTES)
    start_nessus()

    wait_for_scanner_status(api=nessus_api, status=API.Status.READY, timeout=TIME_THIRTY_MINUTES,
                            msg='Waiting for Nessus to be Ready'), 'Nessus is failed to be ready...'

    nessus_details = nessus_api.server.properties()
    log.info("===== Installed Nessus Details =====")
    log.info("Nessus Type      :: {}".format(nessus_details['nessus_type']))
    log.info("Nessus Version   :: {}".format(nessus_details['nessus_ui_version']))
    log.info("Nessus UI Build  :: {}".format(nessus_details['nessus_ui_build']))
    log.info("====================================")
    return


@pytest.fixture()
def deploy_real_agent():
    """This fixture will create real agent"""
    log.info("Creating Real-Agent on docker")
    docker_network = os.getenv('DOCKER_NETWORK')

    if not docker_network:
        docker_network = random_name('autonet-')
        subprocess.run(('docker network create %s' % docker_network).split())

    docker_registry = os.getenv('DOCKER_REGISTRY', 'docker-registry.cloud.aws.tenablesecurity.com:8888')
    agent_container = docker_registry + '/services/nessus-centos8-agent:release-next'
    agent_name = random_name('agent-')
    agent_port = random.randint(31000, 32000)
    log.info("docker-network:{}".format(docker_network))

    try:
        cmd = 'docker run -d -p %s:22 --rm --name %s --network %s %s' % (agent_port, agent_name, docker_network,
                                                                         agent_container)
        subprocess.run(cmd.split())

        yield {'agent_name': agent_name, 'agent_port': agent_port}

    finally:
        log.info("Destroying Real-Agent on docker")
        subprocess.run(('docker stop %s' % agent_name).split())

        if docker_network.startswith('autonet-'):
            subprocess.run(('docker network rm %s' % docker_network).split())


@pytest.fixture()
def create_tenable_io_container() -> dict:
    """Creates tenable.io container with expiration as one day ahead and unique domain name"""

    container_model = ContainerModel.factory(autogen=True)
    container_domain = "{}.{}".format(''.join(random.choice(string.ascii_lowercase) for _ in range(6)),
                                      ''.join(random.choice(string.ascii_lowercase) for _ in range(3)))
    container_model['domains'] = [container_domain]
    container_model['contact'] = container_model['contact'].split('@')[0] + "@" + container_domain
    container_model['expiration'] += (24 * 60 * 60)
    container = create_container(container_model=container_model)
    yield {'container': container, 'domain': container_domain}
    if container:
        delete_container(container_uuid=container.model.uuid)


def link_agent_to_parent_node():
    """ Link agent to parent node """
    docker_network = os.getenv('DOCKER_NETWORK')

    if not docker_network:
        docker_network = random_name('autonet-')
        subprocess.run(('docker network create %s' % docker_network).split())

    api = NessusAPI()
    api.login()

    master_host = re.sub(r'.*//(.*):.*', r'\1', Config.CAT_URL)
    master_port = int(re.sub(r'.*:(\d+).*', r'\1', Config.CAT_URL))
    linking_key = api.scanners.get_agent_linking_key()['key']

    agent_port = random.randint(31000, 32000)
    agent = link_agent_to_master(docker_network, master_host, master_port, linking_key, api, agent_port)
    log.info('Linked agent %s successfully', agent['name'])

    api.logout()
    agent.update({"agent_port": agent_port})

    return agent


@pytest.fixture()
def link_agent_to_cluster(request: SubRequest, deploy_real_agent):
    """This fixture will link real agent to cluster manager"""
    is_link = request.param['is_link'] if hasattr(request, 'param') and 'is_link' in request.param else True
    is_unlink = request.param['is_unlink'] if hasattr(request, 'param') and 'is_unlink' in request.param else True
    is_proxy = request.param['is_proxy'] if hasattr(request, 'param') and 'is_proxy' in request.param else False
    log.info("fixture init: link_agent_to_cluster")

    nessus_api = NessusAPI()
    wait_for_scanner_status(api=nessus_api, timeout=TIME_TEN_MINUTES, status=API.Status.READY,
                            msg='Waiting for server to finish loading.')
    nessus_api.login()
    agent_name = deploy_real_agent['agent_name']
    agent_port = deploy_real_agent['agent_port']

    try:
        if is_link:
            master_host = re.sub(r'.*//(.*):.*', r'\1', Config.CAT_URL)
            master_port = int(re.sub(r'.*:(\d+).*', r'\1', Config.CAT_URL))
            linking_key = nessus_api.scanners.get_agent_linking_key()['key']
            link_cmd = "%s --name=%s --host=%s --port=%d --key=%s" % (
                PlatformServiceCommands.NessusAgent.LINK, agent_name, master_host, master_port, linking_key)

            if is_proxy:
                proxy_user_agent = random_name(prefix='proxy_user_agent')

                link_cmd = '%s --proxy-host=%s --proxy-port=%s --proxy-username=%s --proxy-password=%s ' \
                           '--proxy-agent=%s --debug' % \
                           (link_cmd, NessusConfig.CAT_PROXY_HOST, NessusConfig.CAT_PROXY_PORT,
                            NessusConfig.CAT_PROXY_USERNAME, NessusConfig.CAT_PROXY_PASSWORD, proxy_user_agent)

            def link_agent():
                try:
                    wait_for_scanner_status(
                        api=nessus_api, status=API.Status.READY, timeout=TIME_SIXTY_SECONDS, sleep_interval=WAIT_NORMAL,
                        msg='waiting for Nessus to get ready for linking agent')
                    log.info("fixture init: going to execute the linking command")
                    cmd_output = SSH(port=agent_port).execute(link_cmd)
                    return any([Nessus.Agents.AgentStatus.LINK_SUCCESSFUL in output for output in cmd_output])
                except (SSHException, TimeoutExpired):
                    log.info("Either Nessus was not ready to get linked or SSHException occurred")
                    return False

            for _ in range(5):
                if link_agent():
                    break
                else:
                    sleep(3, reason='Retrying to link agent')
            else:
                is_unlink = False
                raise AssertionError('Linking failed for real-agent, either due to SSHException'
                                     ' or due to agent linking failed')

        nessus_api.logout()

        yield {'agent_name': agent_name, 'agent_port': agent_port}

    finally:
        log.info("fixture teardown: link_agent_to_cluster")

        try:
            nessus_api.login()

            if is_unlink:
                SSH(port=agent_port).execute(PlatformServiceCommands.NessusAgent.UNLINK)

            # agent_details = [agent for agent in nessus_api.agents.agents_list()['agents']
            #                  if agent['name'] == agent_name][0]
            #
            # nessus_api.agents.delete_agent(agent_details['id'])
        finally:
            nessus_api.logout()


@pytest.fixture(scope="session")
def make_guides_pop_up_disable():
    """  This fixture will make disable the guide pop-up """
    try:
        disable_guides_value = fix.get(key="disable_guides")['stdout'].split()[6].rstrip(".").strip("'")
        log.info("'disable_guides' is set to '{}'.".format(disable_guides_value))

        if disable_guides_value != STRING_YES:
            fix.set(key="disable_guides", value=STRING_YES)
            stop_nessus()
            start_nessus()
            reload_nessus(api=NessusAPI())
            log.info("'disable_guides' is successfully set to 'yes'...")
    except Exception as e:
        log.warning("Could not retrieve the value... and throws an exception :: {}".format(e))


@pytest.fixture()
def add_tag_in_logs_json_file(request: SubRequest):
    """This fixture will add given tag in logs.json file"""

    tag_name = request.param.get('tag_name')
    log_file_path = "/opt/nessus/var/nessus/log.json"
    with SSH() as ssh:

        # Checking if log.json file does exist at path: /opt/nessus/var/nessus/
        if ssh.path_exist(log_file_path):
            log_file = ssh.read_from_file(log_file_path)
            log_dict = json.loads(str(log_file.decode('utf8')))

            # Add tag in log.json file if not present already
            if tag_name not in log_dict["reporters"][1]['tags']:
                log_dict["reporters"][1]['tags'].insert(0, tag_name)
            log_json = json.dumps(log_dict, indent=4)
            ssh.write_to_file(log_file_path, text=str(log_json))

            stop_nessus()
            start_nessus()
            sleep(sleep_time=TIME_SIXTY_SECONDS, reason='for reload to take effect.')

            wait_for_scanner_to_be_ready(api=NessusAPI())
        else:
            log.warning("log.json file not found at /opt/nessus_agent/var/nessus")


@pytest.fixture()
def remove_all_linked_scanners(request: SubRequest):
    """This fixture removes all linked scanners in Nessus Manager"""
    nessus_api = request.instance.cat.api
    scanner_ids_to_be_deleted = [scanner['id'] for scanner in nessus_api.scanners.get_list()['scanners'] if scanner[
        'name'] != 'Local Scanner']
    if scanner_ids_to_be_deleted:
        nessus_api.scanners.delete_all_scanners(scanner_ids=scanner_ids_to_be_deleted)


@pytest.fixture()
def delete_all_agents_in_nessus_manager():
    """This fixture removes all linked agents in Nessus Manager"""
    nessus_api = NessusAPI()
    nessus_api.login()
    agents_to_be_deleted = nessus_api.agents.agents_list()['agents']
    if agents_to_be_deleted:
        agent_ids = [agent['id'] for agent in agents_to_be_deleted]
        nessus_api.agents.delete_multiple(agent_ids=agent_ids)


@pytest.fixture()
def delete_all_agents_groups_in_nessus_manager():
    """This fixture removes all agent groups in Nessus Manager"""
    nessus_api = NessusAPI()
    nessus_api.login()
    agent_groups_to_be_deleted = nessus_api.agent_groups.get_list(scanner_id=1)['groups']

    if agent_groups_to_be_deleted:
        agent_group_ids = [agent_group['id'] for agent_group in agent_groups_to_be_deleted]
        nessus_api.agent_groups.delete_groups(id_list=agent_group_ids)


@pytest.fixture(scope='class')
def revert_password_settings_to_default():
    """Fixture to revert the password settings to its default value"""
    try:
        yield
    finally:
        api_object = NessusAPI()
        api_object.login()
        api_object.passwordmgmt.configure(payload={
            'passwd_complexity': False, 'session_timeout': 30, 'passwd_max_attempts': 0, 'passwd_min_length': 0,
            'passwd_notifications': False})

        with polling_ui():
            stop_nessus()
            start_nessus()
            wait_for_scanner_to_be_ready(api=api_object)


@pytest.fixture(scope='class')
def wait_for_plugin_families_to_be_available():
    """ This fixture updates the plugins if there is no plugin set available in Nessus """
    nessus_api = NessusAPI()
    nessus_api.login()

    if nessus_api.plugins.families()['families'] is None:
        with SSH() as ssh:
            ssh.execute("{} -R".format(get_nessusd()), timeout=TIME_TEN_MINUTES)

        stop_nessus()
        start_nessus()

        wait_for_scanner_to_be_ready(api=nessus_api)
        log.info("Re-compiled plugins to get plugin families.")
    else:
        log.info("Plugin families are already available.")

    waiting_wait(lambda: nessus_api.plugins.families()['families'] is not None, sleep_seconds=WAIT_LONG,
                 timeout_seconds=TIME_FIVE_MINUTES, waiting_for="plugins family get available")


@pytest.fixture()
def create_freeze_windows_with_new_endpoint(request: 'SubRequest'):
    """
    This fixture creates freeze windows in Nessus.
    For ex, below parameters creates five freeze windows in Nessus.
    @pytest.mark.parametrize('create_freeze_windows_with_new_endpoint', [
        (random_name(prefix='freeze-window-'), random_name(prefix='freeze-window-'),
         random_name(prefix='freeze-windows-'), random_name(prefix='freeze-windows-'),
         random_name(prefix='freeze-windows-'))], indirect=True)
    """
    date = datetime.now().strftime('%Y-%m-%d %H')
    scanner_id = request.instance.cat.api.scanners.get_list()['scanners'][0]['id']
    freeze_windows_list = []

    for freeze_window in request.param:
        payload = {"name": "", "description": "", "agent_group_id": None,
                   "schedule": {"enabled": True, "rrules": {"freq": API.Schedule.Frequencies.FREQ_MONTHLY,
                                                            "interval": 1, "bysetpos": 4, "byweekday": "2"},
                                "timezone": "America/New_York", "starttime": date + ":00:00",
                                "endtime": date + ":30:00"}}
        payload.update({'name': freeze_window})
        exclusion = request.instance.cat.api.exclusions.create(scanner_id, payload)
        freeze_windows_list.append({'name': freeze_window, 'id': exclusion['id']})
    yield freeze_windows_list
    try:
        for freeze_window in freeze_windows_list:
            request.instance.cat.api.exclusions.delete(exclusion_id=freeze_window['id'], scanner_id=scanner_id)
    except:
        log.warning("Unable to delete freeze windows.")


@pytest.fixture(scope="class")
def perform_cluster_agent_scan(request: 'SubRequest', create_manager_cluster):
    """
    This fixture syncs node with agents, creates agent group. It also creates scan and launch as per user passes params.
    For Ex, below code will create scan and launches the same.

    @pytest.mark.parametrize('perform_cluster_agent_scan', [{'create_scan': True, 'launch_scan': True}], indirect=True)
    """
    log.info(create_manager_cluster)
    nodes = [(node['name'], node['id']) for node in create_manager_cluster['nodes']]
    agents = [(agent['name'], agent['id']) for agent in create_manager_cluster['agents']]
    cluster_details = {'nodes': nodes, 'agents': agents}

    nessus_api = NessusAPI()
    nessus_api.login()

    # Link at least one agent with each node
    node_with_all_agents = [node for node in nodes if nessus_api.nodes.get(node_id=node[1])['agent_count'] == 3]
    node_agent_dict = {}

    if node_with_all_agents:
        other_node = [node for node in nodes if node not in node_with_all_agents]
        same_cluster_group = nessus_api.nodes.get(node_id=nodes[0][1])['cluster_group_id'] == nessus_api.nodes.get(
            node_id=nodes[1][1])['cluster_group_id']

        if same_cluster_group:
            cluster_group_name = random_name(prefix="Cluster-Group-")
            cluster_group_id = nessus_api.clustergroups.add(cluster_group={'name': cluster_group_name})[
                'cluster_group_id']
            nessus_api.clustergroups.assign_node(cluster_group_id=cluster_group_id, node_id=other_node[0][1])

        cluster_group_id = cluster_group_id if same_cluster_group else nessus_api.nodes.get(
            node_id=other_node[0][1])['cluster_group_id']
        nessus_api.clustergroups.assign_agents(cluster_group_id=cluster_group_id,
                                               agent_ids=[agents[0][1]])

    # Waiting till agent and nodes be in sync.
    waiting_wait(lambda: not [node for node in nodes if nessus_api.nodes.get(node_id=node[1])['agent_count'] == 3],
                 sleep_seconds=TIME_FIVE_SECONDS, timeout_seconds=TIME_FIVE_MINUTES,
                 waiting_for="Nodes and agent to be in sync properly.")

    for agent in agents:
        node_name = nessus_api.agents.get_agent_details(agent_id=agent[1])['node_name']

        if node_name in node_agent_dict.keys():
            present_agent_list = node_agent_dict[node_name]
            present_agent_list.append(agent[0])
            node_agent_dict.update({node_name: present_agent_list})
        else:
            node_agent_dict[node_name] = [agent[0]]

    cluster_details['node_agent_details'] = node_agent_dict

    # Create agent group and add all three agents to it.
    agent_group_name = random_name(prefix="Agent-Group-")
    agent_group_id = nessus_api.agent_groups.create(scanner_id=1, name=agent_group_name)['id']
    nessus_api.agent_groups.add_agents(group_id=agent_group_id, agent_ids=[int(agent[1]) for agent in agents])

    cluster_details['agent_group_name'] = agent_group_name
    cluster_details['agent_group_id'] = agent_group_id

    create_scan = request.param['create_scan'] if hasattr(request, 'param') and 'create_scan' in \
                                                  request.param else True
    launch_scan = request.param['launch_scan'] if hasattr(request, 'param') and 'launch_scan' in \
                                                  request.param else True

    # Create agent scan for agent group created above.
    if create_scan:
        scan_name = random_name(prefix="{} - ".format(Nessus.TemplateNames.BASIC_AGENT))

        scan_model = ScanModel()
        scan_model.name = scan_name
        scan_model.default_template = Nessus.TemplateNames.BASIC_AGENT
        scan_model.agent_group_id = [agent_group_id]

        agent_scan_detail = nessus_api.scans.create(scan_model)
        agent_scan_id = agent_scan_detail['scan']['id']
        cluster_details['scan_name'] = scan_name

        # Launch scan as per params given by user
        if launch_scan:
            nessus_api.scans.launch(scan_id=agent_scan_id)
            wait_scan_state(api=nessus_api, end_state=API.Scan.Status.COMPLETED, scan_id=agent_scan_id,
                            timeout=TIME_THIRTY_MINUTES)

            cluster_details['scan_status'] = nessus_api.scans.get_status(scan_id=agent_scan_id)

    yield cluster_details

    try:
        nessus_api.login()

        # removes new agent_scan, agent_group and cluster_group.
        nessus_api.agent_groups.delete(1, agent_group_id)
        nessus_api.scans.delete(scan_id=agent_scan_id)
        nessus_api.clustergroups.delete(cluster_group_id)
    except Exception as e:
        log.warning("Unable to delete agent_scan/agent_group and/or cluster_group. Error is : {}".format(e))


@pytest.fixture(scope="class")
def enable_dark_mode_theme():
    """ This fixture enables dark mode theme in Nessus """
    api_version = 3
    setting_tab = Nessus.AdvancedSettings.USER_INTERFACE_TAB
    setting_name = Nessus.AdvancedSettings.UI_THEME

    nessus_api = NessusAPI()
    nessus_api.login()

    try:
        setting_payload = {"setting.0.name": setting_name, "setting.0.action": "edit",
                           "setting.0.value": Nessus.AdvancedSettings.DARK_MODE.lower()}

        nessus_api.settings.update(settings=setting_payload)

        execute(get_nessus_cli(), ["reload"])
        wait_for_scanner_to_be_ready(api=nessus_api)

        yield
    finally:
        advanced_settings = nessus_api.settings.get_list(version=api_version)["settings"][setting_tab]["settings"]
        ui_theme_setting_id = [setting["id"] for setting in advanced_settings if setting["setting"] == setting_name][0]

        reset_setting_payload = {"setting.0.id": ui_theme_setting_id, "setting.0.action": "remove",
                                 "setting.0.name": setting_name}

        nessus_api.settings.update(settings=reset_setting_payload)

        execute(get_nessus_cli(), ["reload"])
        wait_for_scanner_to_be_ready(api=nessus_api)


@pytest.fixture()
def create_custom_template(request: 'SubRequest'):
    """
    This fixture creates custom template in Nessus.
    """
    chapters = request.param
    template_name = random_name(prefix="automation-template-")
    request.instance.cat.api.reports.create_custom_template(data={
        "name": template_name, "description": "Created By Automation", "chapters": chapters})
    template_id = get_custom_template_id(api=request.instance.cat.api, template_name=template_name)
    yield {'template_name': template_name, 'template_id': template_id, 'chapters': chapters}
    try:
        request.instance.cat.api.reports.delete_custom_template(template_id=template_id)
    except HTTPError:
        log.warning("Error while deleting custom template : {}".format(template_name))


@pytest.fixture()
def delete_all_scans_in_nessus():
    """This fixture will delete all scans in Nessus using API before the testcase starts"""
    nessus_api = NessusAPI()
    nessus_api.login()

    scans = nessus_api.scans.get_scans()
    if 'scans' in scans and scans['scans'] is not None:
        wait_required = False
        for scan in scans['scans']:
            if scan['status'] in [API.Scan.Status.RUNNING, API.Scan.Status.PAUSED]:
                log.info(msg='Stopping scan %d' % scan['id'])
                nessus_api.scans.stop(scan['id'])
                wait_required = True
        if wait_required:
            sleep(sleep_time=TIME_FIFTEEN_SECONDS, reason='for scans to stop.')

        for scan in scans['scans']:
            log.info(msg='Deleting scan %d' % scan['id'])
            try:
                nessus_api.scans.delete(scan['id'])
            except HTTPError:
                log.warning("Error while deleting scan with scan-id: {}".format(scan['id']))
    nessus_api.logout()


@pytest.fixture()
def add_fake_scanners(request: 'SubRequest'):
    """
    This fixture adds fake scanners with given prefixes.
    """
    scanner_name_prefixes = request.param.get('scanner_name_starts_with')
    scanner_names = []
    for prefix in scanner_name_prefixes:
        scanner_name = "{}_{}".format(prefix, random.randint(0, 99999))
        scanner_details = {'name': scanner_name,
                           'key': request.instance.cat.api.scanners.get_scanner_linking_key()['key'],
                           'suuid': random_agent_uuid(),
                           'distro': 'es6-x86-64', 'platform': 'LINUX'}
        request.instance.cat.api.scanners.add_remote_scanner(scanner_details)
        scanner_names.append(scanner_name)
        log.debug("{} has been linked successfully!".format(scanner_name))
    yield scanner_names
    try:
        for scanner in request.instance.cat.api.scanners.get_list()['scanners']:
            if scanner['name'] in scanner_names:
                request.instance.cat.api.scanners.delete(scanner['id'])
    finally:
        log.warning("Enable to delete fake scanners.")


@pytest.fixture()
def delete_files(request: 'SubRequest'):
    """
    This fixture will delete files
    """

    files = request.param.get('file_pattern_to_delete')
    restart_nessus = request.param.get('restart_nessus') if 'restart_nessus' in request.param.keys() else False

    if restart_nessus:
        stop_nessus()

    if not isinstance(files, list):
        files = [files]

    for file in files:
        file = file if get_os_name() != OperatingSystems.WINDOWS else file.replace("\\", "\\\\")

        delete_file = get_command(operation='remove_file')
        sudo = False if get_os_name() in [OperatingSystems.WINDOWS, OperatingSystems.FREEBSD] else True
        with SSH() as ssh:
            output = ssh.execute("{} {}".format(delete_file, file), sudo=sudo)

    if restart_nessus:
        start_nessus()
