"""
py.test fixtures, markers and configuration related to Docker based tests.

:copyright: Tenable Network Security, 2019
:date: Aug 30 2017
:last_modified: April 18, 2023
:author: @jmcneil, @yshah, @krpatel
"""
import os
import pytest
from docker.errors import ImageNotFound
from waiting import wait

from catium.lib.config.environment_variables import CommonConfig
from catium.lib.const.base_constants import TIME_FIFTEEN_MINUTES, TIME_FIVE_SECONDS, TIME_FIVE_MINUTES
from catium.lib.log import create_logger
from catium.lib.network.network import get_ip_from_url
from catium.lib.util import random_name
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.dockernessus import docker_nessus
from nessus.helpers.dockernessus.lib.general import build_target_list, clean_up
from nessus.helpers.dockernessus.lib.system import logreader
from nessus.helpers.waiters import wait_for_plugins, wait_for_scanner_status, wait_for_scanner_login
from nessus.lib.config import docker_config
from nessus.lib.const import API, Scanner

log = create_logger()


def check_scanner_status(scanner_name: str) -> bool:
    """
    Returns true if scanner status is online else returns False
    :param str scanner_name: Name of the scanner
    :return: returns the scanner status
    :rtype: bool
    """
    api = NessusAPI()
    api.login()
    scanner_list = api.scanners.get_list()
    for scanner in scanner_list["scanners"]:
        if scanner["name"] == scanner_name:
            return scanner["status"] == "on"
    return False


def get_scanner_id(scanner_name: str) -> int:
    """
    Returns the scanner id of linked scanner
    :param str scanner_name: Name of the scanner
    :return: returns the scanner id
    :rtype: int
    """
    api = NessusAPI()
    api.login()
    scanner_list = api.scanners.get_list()
    for scanner in scanner_list["scanners"]:
        if scanner["name"] == scanner_name:
            return scanner["id"]


class BaseDockerConfig(object):
    """Base configuration for Docker related tests and fixtures."""

    # Agent specific
    controller_host = docker_config.CONTROLLER_CONFIG["host"]
    controller_port = docker_config.CONTROLLER_CONFIG["port"]
    controller_url = docker_config.CONTROLLER_URL
    controller_api = None
    container_details = None
    override_user = None
    override_pass = None

    # Docker settings
    docker_host = docker_config.DOCKER_HOST
    expose_port = docker_config.AGENT_CONFIG["expose_port"]
    tag = docker_config.DOCKER_TAG
    full_image_name = None
    image_name = None
    test_name = None
    cid = None

    # Inspected during test:
    controller_type = "manager"
    fetch_key = False
    linked = False
    linking_key = None
    log_whole_attack = docker_config.LOG_WHOLE_ATTACK
    nessus_mode = "scanner"
    wait_for_plugin_loading = False
    use_proxy = False

    # General
    debug = docker_config.DEBUG
    nessus_username = docker_config.SCANNER_CONFIG["admin_user"]
    nessus_password = docker_config.SCANNER_CONFIG["admin_pass"]


class ScannerBaseConfig(BaseDockerConfig):
    """Settings specific to Docker Scanners."""
    nessus_mode = "scanner"
    upgrade_build = docker_config.SCANNER_CONFIG["upgrade_build"]

    # Scanner info
    nessus_ui_build = None
    nessus_ui_version = None
    platform = None
    scanner_boottime = None
    scanner_api = None
    scanner_url = docker_config.SCANNER_URL
    server_build = None
    server_version = None
    scanner_name = None
    linking_details = None

    # Scanner prefs
    auto_update = docker_config.AUTO_UPDATE
    no_user_mode = docker_config.NO_USER
    update_plugins = docker_config.UPDATE_PLUGINS

    no_root_mode = docker_config.NO_ROOT
    nessus_user = docker_config.NESSUS_USER
    nessus_group = docker_config.NESSUS_GROUP

    # Plugin prefs
    plugin_dev_branch = docker_config.PLUGIN_DEV_BRANCH
    plugin_set = None
    plugin_server = docker_config.PRODUCTION_PLUGIN_SERVER
    plugin_server_api = docker_config.PRODUCTION_PLUGIN_SERVER_API

    # Targets
    qa_bot_linux_targets = build_target_list(docker_config.QA_BOT_LINUX_TARGETS)
    qa_bot_windows_targets = build_target_list(docker_config.QA_BOT_WINDOWS_TARGETS)
    aix_targets = build_target_list(docker_config.AIX_TARGETS)
    cisco_targets = build_target_list(docker_config.CISCO_TARGETS)
    hpux_targets = build_target_list(docker_config.HPUX_TARGETS)
    juniper_targets = build_target_list(docker_config.JUNIPER_TARGETS)
    solaris_targets = build_target_list(docker_config.SOLARIS_TARGETS)


@pytest.fixture
def link_scanner_to_manager():
    """Fixture provides a single Docker scanner loaded with a pluginset and it will link scanner to nessus manager."""
    log.debug('fixture init: link_scanner_to_manager: Configuration object creation for scanner tests.')

    scanner_name = random_name(prefix='Scanner-')
    manager_port = CommonConfig.CAT_URL.split(":")[2]
    nessus_api = NessusAPI()
    nessus_api.login()
    linking_key = nessus_api.scanners.get_scanner_linking_key()['key']
    manager_host = get_ip_from_url(url=CommonConfig.CAT_URL)

    class TestConf(ScannerBaseConfig):
        """Settings specific to Docker Scanners."""
        nessus_mode = "pro"
        image_name = docker_config.SCANNING_TEST_IMAGE
        wait_for_plugin_loading = True

    # Start the scanner.
    TestConf.full_image_name = "{0}:{1}".format(TestConf.image_name, TestConf.tag)
    log.info("Starting Nessus Scanner using image: %s", TestConf.full_image_name)
    docker_nessus.api_client.pull(TestConf.image_name, tag=TestConf.tag)
    try:
        TestConf.cid = docker_nessus.start_scanner(TestConf.expose_port,
                                                   TestConf.full_image_name,
                                                   nessus_type=TestConf.nessus_mode,
                                                   proxy=TestConf.use_proxy,
                                                   extra={
                                                       "AUTO_UPDATE": TestConf.auto_update,
                                                       "CUSTOM_PLUGIN_BRANCH": TestConf.plugin_dev_branch,
                                                       "LOG_WHOLE_ATTACK": TestConf.log_whole_attack,
                                                       "NO_USER": TestConf.no_user_mode,
                                                       "NO_ROOT": TestConf.no_root_mode,
                                                       "PLUGIN_SERVER": TestConf.plugin_server,
                                                       "PLUGIN_SERVER_API": TestConf.plugin_server_api,
                                                       "UPDATE_PLUGINS": TestConf.update_plugins
                                                   })
    except ImageNotFound:
        log.error("Docker image %s is not available on the Docker host.", TestConf.full_image_name)
        pytest.fail("Docker image {0} is not available on the Docker host.".format(TestConf.full_image_name))

    assert TestConf.cid

    if os.getenv('IS_RUNNING_IN_PYTESTER'):
        """
        If running in a pytester container we can't connect to localhost:mapped_port, instead we put
        the container on the pytester's user-defined network and reach it directly.
        """
        docker_network = os.getenv('DOCKER_NETWORK')
        docker_nessus.api_client.connect_container_to_network(TestConf.cid, docker_network)
        short_hostname = docker_nessus.get(TestConf.cid).attrs['Config']['Hostname']
        TestConf.scanner_url = "https://{0}:8834".format(short_hostname)
        log.debug("New scanner is available at: %s", TestConf.scanner_url)
    else:
        # The port is ephemeral so grab which port was chosen
        container_port = docker_nessus.get_exposed_port(TestConf.cid)
        if container_port:
            TestConf.expose_port = container_port
        assert TestConf.expose_port != ""
        TestConf.scanner_url = "https://{0}:{1}".format(TestConf.docker_host, TestConf.expose_port)
        log.debug("New scanner is available at: %s", TestConf.scanner_url)

    # Ensure activation scripts are successful
    init_status, init_result = docker_nessus.wait_for_init(TestConf.cid)
    assert init_status

    # Initialize the api against newly activated scanner:
    TestConf.scanner_api = NessusAPI(login=False)
    TestConf.scanner_api.session_url = TestConf.scanner_url

    wait_for_scanner_status(api=TestConf.scanner_api, status=API.Status.READY,
                            timeout=TIME_FIFTEEN_MINUTES, msg='Availability of Nessus Professional scanner',
                            sleep_interval=TIME_FIVE_SECONDS)
    wait_for_scanner_login(api=TestConf.scanner_api, username=TestConf.nessus_username,
                           password=TestConf.nessus_password, timeout=TIME_FIFTEEN_MINUTES,
                           msg=Scanner.Strings.SCANNER_LOGIN_SUCCEED)
    wait_for_plugins(TestConf.scanner_api)

    # Collect version and build information
    nessus_info = TestConf.scanner_api.server.properties()
    TestConf.nessus_ui_build = nessus_info["nessus_ui_build"]
    TestConf.nessus_ui_version = nessus_info["nessus_ui_version"]
    TestConf.platform = nessus_info["platform"]
    TestConf.scanner_boottime = nessus_info["scanner_boottime"]
    TestConf.server_build = nessus_info["server_build"]
    TestConf.server_version = nessus_info["server_version"]
    TestConf.plugin_set = nessus_info["loaded_plugin_set"]

    log.info("Nessus %s Scanner build %s is loaded and ready for use with plugin-set: %s",
             TestConf.server_version, TestConf.server_build, TestConf.plugin_set)

    log.info("UI version: %s build: %s platform: %s",
             TestConf.nessus_ui_version, TestConf.nessus_ui_build, TestConf.platform)
    try:
        api = NessusAPI(url=TestConf.scanner_url)
        api.login()

        api.scanners.link_to_cloud(scanner_name=scanner_name, manager_port=manager_port,
                                   linking_key=linking_key, manager_host=manager_host)
        wait(lambda: check_scanner_status(scanner_name=scanner_name), timeout_seconds=TIME_FIVE_MINUTES,
             waiting_for="Scanner to be visible online", sleep_seconds=TIME_FIVE_SECONDS)
        scanner_id = get_scanner_id(scanner_name=scanner_name)
        yield TestConf, scanner_id, scanner_name
    finally:
        log.debug('fixture teardown: link_scanner_to_manager: Checking log files and cleaning up Docker containers.')
        logreader.check_nessus_dump(cid=TestConf.cid)

        # Login to Scanner to unlink to the manager
        api_nessus = NessusAPI(url=TestConf.scanner_url)
        api_nessus.login()
        api_nessus.scanners.unlink_to_scanner()

        # Login to manager to delete the added scanner
        api = NessusAPI()
        api.login()
        api.scanners.delete(scanner_id=get_scanner_id(scanner_name=scanner_name))
        clean_up(cid=TestConf.cid, nessus_type=TestConf.nessus_mode, linked=TestConf.linked)
