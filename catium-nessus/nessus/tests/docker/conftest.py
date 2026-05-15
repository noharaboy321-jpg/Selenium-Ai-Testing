"""
py.test fixtures, markers and configuration related to Docker based tests.

:copyright: Tenable Network Security, 2017
:date: Aug 30 2017
:author: @jmcneil
"""

import pytest
from catium.lib.const.base_constants import TIME_FIFTEEN_MINUTES, TIME_FIVE_SECONDS
from catium.lib.log import create_logger
from catium.lib.url import Url
from catium.lib.util import random_name
from docker.errors import ImageNotFound
from requests.exceptions import HTTPError
from tenableio.apiobjects.tenablecloud_api import TenableCloudAPI
from tenableio.helpers.scanner import wait_for_scanner_availability
from tenableio.lib.config import TioConfig

from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.dockernessus import docker_nessus
from nessus.helpers.dockernessus.lib.constants import ControllerType
from nessus.helpers.dockernessus.lib.general import clean_up
from nessus.helpers.dockernessus.lib.nessuscli import Nessuscli
from nessus.helpers.dockernessus.lib.system import logreader, agent_logreader
from nessus.helpers.waiters import wait_for_plugins, wait_for_scanner_status, wait_for_scanner_login
from nessus.lib.config import docker_config
from nessus.lib.const import API, Scanner
from nessus.lib.base_config_classes import BaseDockerConfig, ScannerBaseConfig

log = create_logger()
nessuscli = Nessuscli()
AGENT_IMAGES = docker_config.AGENT_TEST_IMAGES
SCANNER_IMAGES = docker_config.SCANNER_TEST_IMAGES

pytest_plugins = ['tenableio.plugins.fixtures.containers']


# Agent Fixtures
#
@pytest.fixture(scope="class", params=AGENT_IMAGES)
def docker_agent(request, tns_risky_create_tenablecloud_class_container):
    """Fixture provides Agent configurations, log checking and cleanup of the container during tear down."""

    log.debug('fixture init: docker_agent: Configuration object creation for agent tests.')

    class TestConf(BaseDockerConfig):
        """Settings specific to Docker Agents."""
        agent_group_details = None
        linked = True
        nessus_mode = "agent"
        upgrade_build = docker_config.AGENT_CONFIG["upgrade_build"]
        scanner_id = "0"

    if hasattr(request.cls, 'controller_type'):
        TestConf.controller_type = request.cls.controller_type

    if hasattr(request.cls, 'fetch_key'):
        TestConf.fetch_key = request.cls.fetch_key

    if hasattr(request.cls, 'linking_key'):
        TestConf.linking_key = request.cls.linking_key

    if hasattr(request.cls, 'linked'):
        TestConf.linked = request.cls.linked

    if hasattr(request.cls, 'use_proxy'):
        TestConf.use_proxy = request.cls.use_proxy

    # Dynamically create a T.io container / agent groups using existing fixture if needed
    if not TestConf.linking_key and TestConf.controller_type in [ControllerType.onprem,
                                                                 ControllerType.tenableio,
                                                                 ControllerType.tenableio_dev]:
        # Create a container to work with
        container_details = tns_risky_create_tenablecloud_class_container
        TestConf.container_details = container_details.details
        TestConf.override_user = request.cls.cat.container.model.contact
        TestConf.override_pass = request.cls.cat.container.model.password

        if not TestConf.override_user or not TestConf.override_pass:
            log.error("Failed to gather user/pass of newly created container. "
                      "Container details: %s ", TestConf.container_details)
            pytest.fail("Failed to gather user/pass of newly created container. "
                        "Container details: {0}".format(TestConf.container_details))

        # Ensure Agent group(s) exist
        try:
            TestConf.controller_api = TenableCloudAPI()
            TestConf.controller_api.login(username=TestConf.override_user, password=TestConf.override_pass)
            linking_key = TestConf.controller_api.scanners.get_linking_key()
            assert "key" in linking_key, "Failed to fetch the Linking key From Container"
            TestConf.linking_key = linking_key["key"]
            TestConf.agent_group_details = TestConf.controller_api.agent_groups.create(TestConf.scanner_id,
                                                                                       TestConf.agent_group)
        except HTTPError as error:
            log.debug("Failed to create group(s) named %s, "
                      "checking if it may already exists. Output: %s", TestConf.agent_group, str(error))

            group_details = TestConf.controller_api.agent_groups.get_list(TestConf.scanner_id)
            assert "groups" in group_details, "Failed to extract list of agent groups from the controller. " \
                                              "Output: {0}".format(str(group_details))
            for group in group_details["groups"]:
                if group["name"] == TestConf.agent_group:
                    TestConf.agent_group_details = group

        if not TestConf.agent_group_details:
            log.error("Failed to create agent group %s and it doesn't appear to exist already. This is unexpected.")
            pytest.fail("Failed to provision an Agent group for use.")
        else:
            log.debug("Details for Agent Group: %s", TestConf.agent_group_details)

    # Start Docker Agent
    TestConf.test_name = request.param[0]
    TestConf.image_name = request.param[1]
    TestConf.full_image_name = "{0}:{1}".format(TestConf.image_name, TestConf.tag)
    try:
        TestConf.cid = docker_nessus.start_agent(TestConf.expose_port,
                                                 TestConf.full_image_name,
                                                 proxy=TestConf.use_proxy,
                                                 controller_type=TestConf.controller_type,
                                                 key=TestConf.linking_key,
                                                 override_user=TestConf.override_user,
                                                 override_pass=TestConf.override_pass)
    except ImageNotFound:
        log.error("Docker image %s is not available on the Docker host.", TestConf.full_image_name)
        pytest.fail("Docker image {0} is not available on the Docker host.".format(TestConf.full_image_name))

    assert TestConf.cid, "Docker container failed to start using image {0}.".format(TestConf.full_image_name)
    log.info("Started agent using image %s cid: %s", TestConf.full_image_name, TestConf.cid)

    # Ensure init script inside the Docker container completes successfully
    status, init_result = docker_nessus.wait_for_init(TestConf.cid)
    assert status, "Initializing configuration script in container {0} has failed.".format(TestConf.cid)

    if not TestConf.linked:
        yield TestConf
    else:
        agent_status, link_message = nessuscli.agent.status(TestConf.cid)
        assert agent_status
        assert "jobs pending" in link_message, "Agent status command failed to show pending jobs " \
                                               "and appears unlinked. Output: {0}".format(str(link_message))

        yield TestConf

    # Teardown
    log.debug('fixture teardown: docker_agent: Checking log files and cleaning up Docker containers.')
    agent_logreader.check_nessus_dump(cid=TestConf.cid)
    clean_up(cid=TestConf.cid, nessus_type=TestConf.nessus_mode, linked=TestConf.linked)
    if TestConf.controller_api:
        TestConf.controller_api.logout()


# Scanner Fixtures
#
#
@pytest.fixture(scope="function", params=SCANNER_IMAGES)
def docker_scanner(request):
    """Fixture provides Scanner configurations, log checking and cleanup of the container during tear down."""
    log.debug('fixture init: docker_scanner: Configuration object creation for scanner tests.')

    class TestConf(ScannerBaseConfig):
        """Settings specific to Docker Scanners."""

    if hasattr(request.cls, 'controller_type'):
        TestConf.controller_type = request.cls.controller_type

    if hasattr(request.cls, 'fetch_key'):
        TestConf.fetch_key = request.cls.fetch_key

    if hasattr(request.cls, 'linking_key'):
        TestConf.linking_key = request.cls.linking_key

    if hasattr(request.cls, 'linked'):
        TestConf.linked = request.cls.linked

    if hasattr(request.cls, 'log_whole_attack'):
        TestConf.log_whole_attack = request.cls.log_whole_attack

    if hasattr(request.cls, 'nessus_mode'):
        TestConf.nessus_mode = request.cls.nessus_mode

    if hasattr(request.cls, 'scanning_test'):
        TestConf.scanning_test = request.cls.scanning_test

    if hasattr(request.cls, 'use_proxy'):
        TestConf.use_proxy = request.cls.use_proxy

    if hasattr(request.cls, 'wait_for_plugin_loading'):
        TestConf.wait_for_plugin_loading = request.cls.wait_for_plugin_loading

    TestConf.test_name = request.param[0]
    TestConf.image_name = request.param[1]

    # Start the scanner.
    TestConf.full_image_name = "{0}:{1}".format(TestConf.image_name, TestConf.tag)
    log.info("Starting Nessus Scanner using image: %s", TestConf.full_image_name)
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

    if not TestConf.wait_for_plugin_loading:
        yield TestConf

    else:
        # Initialize the api against newly activated scanner:
        TestConf.scanner_api = NessusAPI(login=False)
        TestConf.scanner_api.session_url = TestConf.scanner_url
        TestConf.scanner_api.login()
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

        yield TestConf

    log.debug('fixture teardown: docker_scanner: Checking log files and cleaning up Docker containers.')
    logreader.check_nessus_dump(cid=TestConf.cid)
    clean_up(cid=TestConf.cid, nessus_type=TestConf.nessus_mode, linked=TestConf.linked)


@pytest.fixture(scope="class")
def docker_managed_scanner(request, tns_risky_create_tenablecloud_class_container):
    """Fixture provides a single managed Docker scanner loaded with a plugin-set. This type of scanner typically gets
       a restricted license (tio / onprem) so it is unreliable to use the API like the docker_scanner and
       docker_scanning fixtures do. The log files are used to determine when plugins are finished installing.
       """
    log.debug('fixture init: docker_managed_scanner: Configuration object creation for managed scanner tests.')

    class TestConf(ScannerBaseConfig):
        """Settings specific to Docker Scanners."""
        nessus_mode = "managed"
        image_name = docker_config.SCANNING_TEST_IMAGE
        wait_for_plugin_loading = True

    if hasattr(request.cls, 'controller_type'):
        TestConf.controller_type = request.cls.controller_type

    if hasattr(request.cls, 'fetch_key'):
        TestConf.fetch_key = request.cls.fetch_key

    if hasattr(request.cls, 'linking_key'):
        TestConf.linking_key = request.cls.linking_key

    if hasattr(request.cls, 'linked'):
        TestConf.linked = request.cls.linked

    if hasattr(request.cls, 'log_whole_attack'):
        TestConf.log_whole_attack = request.cls.log_whole_attack

    if hasattr(request.cls, 'nessus_mode'):
        TestConf.nessus_mode = request.cls.nessus_mode

    if hasattr(request.cls, 'use_proxy'):
        TestConf.use_proxy = request.cls.use_proxy

    if hasattr(request.cls, 'wait_for_plugin_loading'):
        TestConf.wait_for_plugin_loading = request.cls.wait_for_plugin_loading

    # Dynamically create a T.io container / agent groups using existing fixture if needed
    if not TestConf.linking_key and TestConf.controller_type in [ControllerType.onprem,
                                                                 ControllerType.tenableio,
                                                                 ControllerType.tenableio_dev]:
        # Create a container to work with
        container_details = tns_risky_create_tenablecloud_class_container
        TestConf.container_details = container_details.details
        TestConf.override_user = request.cls.cat.container.model.contact
        TestConf.override_pass = request.cls.cat.container.model.password

        if not TestConf.override_user or not TestConf.override_pass:
            log.error("Failed to gather user/pass of newly created container. "
                      "Container details: %s ", TestConf.container_details)
            pytest.fail("Failed to gather user/pass of newly created container. "
                        "Container details: {0}".format(TestConf.container_details))

        TestConf.controller_api = TenableCloudAPI()
        TestConf.controller_api.login(username=TestConf.override_user, password=TestConf.override_pass)

    # Start the scanner.
    TestConf.full_image_name = "{0}:{1}".format(TestConf.image_name, TestConf.tag)
    TestConf.scanner_name = random_name('managed-scanner-')
    log.info("Starting Nessus Scanner using image: %s", TestConf.full_image_name)
    try:
        TestConf.cid = \
            docker_nessus.start_managed_scanner(TestConf.expose_port,
                                                TestConf.full_image_name,
                                                fetch_key=TestConf.fetch_key,
                                                controller_type=TestConf.controller_type,
                                                override_user=TestConf.override_user,
                                                override_pass=TestConf.override_pass,
                                                proxy=TestConf.use_proxy,
                                                extra={
                                                    "AUTO_UPDATE": TestConf.auto_update,
                                                    "CUSTOM_PLUGIN_BRANCH": TestConf.plugin_dev_branch,
                                                    "LOG_WHOLE_ATTACK": TestConf.log_whole_attack,
                                                    "NAME": TestConf.scanner_name,
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

    # The port is ephemeral so grab which port was chosen
    container_port = docker_nessus.get_exposed_port(TestConf.cid)
    if container_port:
        TestConf.expose_port = container_port
    assert TestConf.expose_port != ""
    TestConf.scanner_url = "https://{0}:{1}".format(TestConf.docker_host, TestConf.expose_port)
    log.debug("New managed scanner is available at: %s", TestConf.scanner_url)

    # Ensure activation scripts inside the Docker container are successful:
    init_status, init_result = docker_nessus.wait_for_init(TestConf.cid)
    assert init_status

    # Get the scanner ID other details to use for scan policy
    scanners_list = TestConf.controller_api.scanners.get_list()
    assert "scanners" in scanners_list, "Failed to extract list of scanners groups from the controller. " \
                                        "Output: {0}".format(str(scanners_list))
    for scanner in scanners_list["scanners"]:
        if scanner["name"] == TestConf.scanner_name:
            TestConf.linking_details = scanner

    if not TestConf.linking_details and TestConf.linked:
        log.error("Failed to obtain ID of linked scanner. Will be unable "
                  "to launch scan correctly.")
        pytest.fail("Failed to obtain ID of linked scanner. Will be unable "
                    "to launch scan correctly.")
    else:
        log.debug("Linking related details from controller "
                  "regarding scanner %s : \n%s", TestConf.scanner_name, TestConf.linking_details)

    if not TestConf.linked:
        yield TestConf

    else:
        # Ensure scanner is linked:
        managed_status, link_message = nessuscli.managed.status(TestConf.cid)
        assert managed_status
        assert "jobs pending" in link_message, "Scanner status command failed to show pending jobs " \
                                               "and appears unlinked. Output: {0}".format(str(link_message))

        if TestConf.wait_for_plugin_loading:

            # Ensure plugins get installed as best as possible.
            plugins_installed = logreader.wait_for_managed_plugins_install(cid=TestConf.cid)
            assert plugins_installed, "Nessus plugins failed to install correctly " \
                                      "or there was an issue parsing backend.log."
            log.info("Nessus plugins finished downloading "
                     "in Docker container %s. Waiting for them to process.", TestConf.cid)

            wait_for_scanner_availability(api=TestConf.controller_api,
                                          scanner_name=TestConf.scanner_name,
                                          timeout=TIME_FIFTEEN_MINUTES)

        yield TestConf

    # Teardown
    log.debug('fixture teardown: docker_managed_scanner: Checking log files and cleaning up Docker containers.')
    logreader.check_nessus_dump(cid=TestConf.cid)
    clean_up(cid=TestConf.cid, nessus_type=TestConf.nessus_mode, linked=TestConf.linked)
    if TestConf.controller_api:
        TestConf.controller_api.logout()


@pytest.fixture(scope="class")
def docker_scanning(request):
    """Fixture provides a single Docker scanner loaded with a pluginset and an api for use."""
    log.debug('fixture init: docker_scanning: Configuration object creation for scanner tests.')

    class TestConf(ScannerBaseConfig):
        """Settings specific to Docker Scanners."""
        nessus_mode = "pro"
        image_name = docker_config.SCANNING_TEST_IMAGE
        wait_for_plugin_loading = True

    if hasattr(request.cls, 'controller_type'):
        TestConf.controller_type = request.cls.controller_type

    if hasattr(request.cls, 'fetch_key'):
        TestConf.fetch_key = request.cls.fetch_key

    if hasattr(request.cls, 'linking_key'):
        TestConf.linking_key = request.cls.linking_key

    if hasattr(request.cls, 'linked'):
        TestConf.linked = request.cls.linked

    if hasattr(request.cls, 'log_whole_attack'):
        TestConf.log_whole_attack = request.cls.log_whole_attack

    if hasattr(request.cls, 'nessus_mode'):
        TestConf.nessus_mode = request.cls.nessus_mode

    if hasattr(request.cls, 'scanning_test'):
        TestConf.scanning_test = request.cls.scanning_test

    if hasattr(request.cls, 'use_proxy'):
        TestConf.use_proxy = request.cls.use_proxy

    if hasattr(request.cls, 'wait_for_plugin_loading'):
        TestConf.wait_for_plugin_loading = request.cls.wait_for_plugin_loading

    # Start the scanner.
    TestConf.full_image_name = "{0}:{1}".format(TestConf.image_name, TestConf.tag)
    log.info("Starting Nessus Scanner using image: %s", TestConf.full_image_name)
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

    if not TestConf.wait_for_plugin_loading:
        yield TestConf

    else:
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

        yield TestConf

    log.debug('fixture teardown: docker_scanning: Checking log files and cleaning up Docker containers.')
    logreader.check_nessus_dump(cid=TestConf.cid)
    clean_up(cid=TestConf.cid, nessus_type=TestConf.nessus_mode, linked=TestConf.linked)


@pytest.fixture(scope="class")
def link_proscanner_to_onprem(request, docker_scanning, tns_risky_create_tenablecloud_class_container):
    """
    :param docker_scanning: Fixture to create and launch nessus pro scanner
    :param tns_risky_create_tenablecloud_class_container: Fixture to create container
    :return:
    """
    log.debug('fixture init: link_proscanner_to_onprem: link pro scanner to onprem container')
    container_details = tns_risky_create_tenablecloud_class_container.details
    override_user = request.cls.cat.container.model.contact
    override_pass = request.cls.cat.container.model.password
    docker_scanning.override_user = override_user
    docker_scanning.override_pass = override_pass
    log.debug("Container username %s", request.cls.cat.container.model.contact)
    log.debug("Container Password %s", request.cls.cat.container.model.password)
    if not override_user or not override_pass:
     log.error("Failed to gather user/pass of newly created container. "
               "Container details: %s ", container_details)
     pytest.fail("Failed to gather user/pass of newly created container. "
                 "Container details: {0}".format(container_details))

    controller_api = TenableCloudAPI()
    controller_api.login(username=override_user, password=override_pass)
    linking_key = controller_api.scanners.get_linking_key()
    docker_scanning.scanner_name = random_name('pro-scanner-')
    docker_scanning.container_details = container_details
    docker_scanning.controller_api = controller_api
    nessus_api = NessusAPI(url=docker_scanning.scanner_url)
    nessus_api.login(username=docker_scanning.nessus_username, password=docker_scanning.nessus_password)
    request.cls.cat.nessus_api = nessus_api
    manager_host = Url(TioConfig.CAT_URL).hostname
    nessus_api.scanners.link_to_cloud(manager_host=manager_host, linking_key=linking_key["key"],
                                      scanner_name=docker_scanning.scanner_name, manager_port="443")
    scanners_list = controller_api.scanners.get_list()
    log.debug(scanners_list)

    assert "scanners" in scanners_list, "Failed to extract list of scanners groups from the controller. " \
                                        "Output: {0}".format(str(scanners_list))
    for scanner in scanners_list["scanners"]:
        if scanner["name"] == docker_scanning.scanner_name:
            docker_scanning.linking_details = scanner

    if not docker_scanning.linking_details and docker_scanning.linked:
        log.error("Failed to obtain ID of linked scanner. Will be unable "
                  "to launch scan correctly.")
        pytest.fail("Failed to obtain ID of linked scanner. Will be unable "
                    "to launch scan correctly.")
    else:
        log.debug("Linking related details from controller "
                  "regarding scanner %s : \n%s", docker_scanning.scanner_name, docker_scanning.linking_details)

    yield docker_scanning

    log.debug('fixture teardown: link_proscanner_to_onprem : logging out from nessus and controller API')
    nessus_api.logout()
    controller_api.logout()
