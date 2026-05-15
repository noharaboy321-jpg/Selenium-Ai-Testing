"""
:copyright: Tenable Network Security, 2017
:date: Aug 30 2017
:author: @jmcneil
"""

from subprocess import check_output

import re

from catium.helpers.sleep_lib import sleep
from catium.lib.const import TIME_FIVE_SECONDS
from nessus.helpers.dockernessus.lib.container import Container
from nessus.helpers.dockernessus.lib.image import Image
from .lib.constants import ENCODING, ControllerType


class DockerNessus(Container, Image):
    """Class provides api for working with local and remote Docker hosts."""

    def simulate_agents(self, expose_port, full_image_name, count=5, proxy=False, fetch_key=False,
                        key=None, groups=None, controller_type="manager", extra=None):
        """
        Not-so quick method to simulate a high connected agent count. This method will connect a specified amount of
        agents to a controller. Note: the agent is started, linked to the manager and then stopped without
        unlinking. This was a quick write and it is quicker to do this using the API.

        :param str expose_port: The port to expose on the Docker container. Default: random.
        :param str full_image_name: Docker image name, including tag.
        :param int count: The number of agents to connect to the manager.
        :param bool proxy: Use a proxy for container communications. Default: False.
        :param bool fetch_key: Flag to tell Agent in the container to fetch the key from the Manager.
        :param str key: The key from the Manager.
        :param str groups: Set a specific group for the agent to join. Default: nessus_config.agent_config["GROUP"]
        :param str controller_type: The type of controller configuration to use.
                                    Supports: manager, tenableio, tenableio_dev
        :param dict extra: Provide extra environment variables for container configuration here. This dict with be
        appended to the existing environment dictionary.
        :returns: Container ID or False if failed.
        :rtype: str

        .. code-block:: python

            docker_nessus.simulate_agents(agent_test.expose_port, full_image_name, count=1000, key="some-key")
            docker_nessus.simulate_agents(agent_test.expose_port, full_image_name,
                                          count=50, fetch_key=True, tenableio=True)
        """
        environment = dict()
        init_result = False

        if groups:
            self.agent_groups = groups
        environment["GROUPS"] = self.agent_groups

        if fetch_key:
            environment["FETCH_KEY"] = "yes"

        if not fetch_key and key:
            environment["KEY"] = key

        if controller_type == ControllerType.onprem:
            environment["MANAGER_IP"] = self.onprem_host
            environment["MANAGER_PORT"] = self.onprem_port
            environment["MANAGER_USER"] = self.onprem_container_user
            environment["MANAGER_PASS"] = self.onprem_container_pass

        elif controller_type == ControllerType.tenableio:
            environment["MANAGER_IP"] = self.tenableio_host
            environment["MANAGER_PORT"] = self.tenableio_port
            environment["MANAGER_USER"] = self.tenableio_container_user
            environment["MANAGER_PASS"] = self.tenableio_container_pass

        elif controller_type == ControllerType.tenableio_dev:
            environment["MANAGER_IP"] = self.tenableio_dev_host
            environment["MANAGER_PORT"] = self.tenableio_dev_port
            environment["MANAGER_USER"] = self.tenableio_dev_container_user
            environment["MANAGER_PASS"] = self.tenableio_dev_container_pass

        else:
            environment["MANAGER_IP"] = self.controller_host
            environment["MANAGER_PORT"] = self.controller_port
            environment["MANAGER_USER"] = self.controller_user
            environment["MANAGER_PASS"] = self.controller_pass

        if proxy:
            environment["PROXY"] = self.proxy_host
            environment["PROXY_PORT"] = self.proxy_port
            environment["PROXY_USER"] = self.proxy_user
            environment["PROXY_PASS"] = self.proxy_pass

        if extra and isinstance(extra, dict):
            environment = self.merge_dictionaries(environment, extra)

        ports = [8834]
        port_bindings = {8834: expose_port}

        num_started = 0
        while num_started <= count:
            cid = self.start(full_image_name, environment=environment, ports=ports, port_bindings=port_bindings)
            if not cid:
                return False

            num_started += 1
            status, init_result = self.wait_for_init(cid)
            if not status:
                return False, init_result

            stopped = self.stop(cid)
            if not stopped:
                return False, init_result

            removed = self.remove_container(cid)
            if not removed:
                return False, init_result

        self.logger.debug("Started %i agents successfully.", num_started-1)
        return True, init_result

    def start_agent(self, expose_port, full_image_name, fetch_key=False, key=None,
                    proxy=False, groups=None, controller_type="manager", extra=None,
                    override_user=None, override_pass=None):
        """
        Quick helper method to start an agent. Anything custom should use start method directly.
        Starts agent container and returns the container ID.

        :param str expose_port: The port to expose on the Docker container. Default: random.
        :param str full_image_name: Docker image name, including tag.
        :param bool proxy: Use a proxy for container communications. Default: False.
        :param bool fetch_key: Flag to tell Agent in the container to fetch the key from the Manager.
        :param str key: The key from the Manager.
        :param str groups: Set a specific group for the agent to join. Default: nessus_config.agent_config["GROUP"]
        :param str controller_type: The type of controller configuration to use.
                                    Supports: manager, tenableio, tenableio_dev
        :param dict extra: Provide extra environment variables for container configuration here. This dict with be
        appended to the existing environment dictionary.
        :param str override_user: Override the username configured in the environment with this user. This is helpful
        when a test dynamically creates the container and user as part of a fixture or test.
        :param str override_pass: Override the password configured in the environment with this user. This is helpful
        when a test dynamically creates the container and user as part of a fixture or test.
        :returns: Container ID or False if failed.
        :rtype: String

        .. code-block:: python
           :dedent: 4

            docker_nessus.start_agent(agent_test.expose_port, full_image_name, key="some-key")
            docker_nessus.start_agent(agent_test.expose_port, full_image_name, fetch_key=True)
        """
        environment = dict()

        if groups:
            self.agent_groups = groups
        environment["GROUPS"] = self.agent_groups

        if fetch_key:
            environment["FETCH_KEY"] = "yes"

        if not fetch_key and key:
            environment["KEY"] = key

        if controller_type == ControllerType.onprem:
            environment["MANAGER_IP"] = self.onprem_host
            environment["MANAGER_PORT"] = self.onprem_port
            environment["MANAGER_USER"] = self.onprem_container_user
            environment["MANAGER_PASS"] = self.onprem_container_pass

        elif controller_type == ControllerType.tenableio:
            environment["MANAGER_IP"] = self.tenableio_host
            environment["MANAGER_PORT"] = self.tenableio_port
            environment["MANAGER_USER"] = self.tenableio_container_user
            environment["MANAGER_PASS"] = self.tenableio_container_pass

        elif controller_type == ControllerType.tenableio_dev:
            environment["MANAGER_IP"] = self.tenableio_dev_host
            environment["MANAGER_PORT"] = self.tenableio_dev_port
            environment["MANAGER_USER"] = self.tenableio_dev_container_user
            environment["MANAGER_PASS"] = self.tenableio_dev_container_pass

        else:
            environment["MANAGER_IP"] = self.controller_host
            environment["MANAGER_PORT"] = self.controller_port
            environment["MANAGER_USER"] = self.controller_user
            environment["MANAGER_PASS"] = self.controller_pass

        if override_user:
            environment["MANAGER_USER"] = override_user
        if override_pass:
            environment["MANAGER_PASS"] = override_pass

        if proxy:
            environment["PROXY"] = self.proxy_host
            environment["PROXY_PORT"] = self.proxy_port
            environment["PROXY_USER"] = self.proxy_user
            environment["PROXY_PASS"] = self.proxy_pass

        if extra and isinstance(extra, dict):
            environment = self.merge_dictionaries(environment, extra)

        ports = [8834]
        port_bindings = {8834: expose_port}

        cid = self.start(full_image_name, environment=environment, ports=ports, port_bindings=port_bindings)
        return cid

    def start_managed_scanner(self, expose_port, full_image_name, fetch_key=False, no_user=False,
                              key=None, proxy=False, controller_type="manager", extra=None,
                              override_user=None, override_pass=None):
        """
        Quick method to start a managed scanner. Any custom requirements should use self.start() method directly.
        Start a managed scanner and return the container ID.

        :param int expose_port: The port to expose on the docker container. Default: random
        :param str full_image_name: Docker image name, including tag.
        :param bool fetch_key: Flag to enable scanner to fetch the key from the Manager/nCloud itself using REST API.
        :param bool no_user: Flag to enable no user mode on the scanner.
        :param str key: The key to use when linking to the Manager/nCloud.
        :param bool proxy: Use a proxy for container communications. Default: False.
        :param str controller_type: The type of controller configuration to use.
                                    Supports: manager, tenableio, tenableio_dev
        :param dict extra: Provide extra environment variables for container configuration here. This dict with be
        appended to the existing environment dictionary.
        :param str override_user: Override the username configured in the environment with this user. This is helpful
        when a test dynamically creates the container and user as part of a fixture or test.
        :param str override_pass: Override the password configured in the environment with this user. This is helpful
        when a test dynamically creates the container and user as part of a fixture or test.
        :return: Container ID or False if failed.

        .. code-block:: python
           :dedent: 4

            docker_nessus.start_managed_scanner(expose_port, full_image_name, key="some-key")
            docker_nessus.start_managed_scanner(expose_port, full_image_name, fetch_key=True)
        """
        environment = dict()

        if fetch_key:
            environment["FETCH_KEY"] = "yes"

        if not fetch_key and key:
            environment["KEY"] = key

        if controller_type == ControllerType.onprem:
            environment["MANAGER_IP"] = self.onprem_host
            environment["MANAGER_PORT"] = self.onprem_port
            environment["MANAGER_USER"] = self.onprem_container_user
            environment["MANAGER_PASS"] = self.onprem_container_pass

        elif controller_type == ControllerType.tenableio:
            environment["MANAGER_IP"] = self.tenableio_host
            environment["MANAGER_PORT"] = self.tenableio_port
            environment["MANAGER_USER"] = self.tenableio_container_user
            environment["MANAGER_PASS"] = self.tenableio_container_pass

        elif controller_type == ControllerType.tenableio_dev:
            environment["MANAGER_IP"] = self.tenableio_dev_host
            environment["MANAGER_PORT"] = self.tenableio_dev_port
            environment["MANAGER_USER"] = self.tenableio_dev_container_user
            environment["MANAGER_PASS"] = self.tenableio_dev_container_pass

        else:
            environment["MANAGER_IP"] = self.controller_host
            environment["MANAGER_PORT"] = self.controller_port
            environment["MANAGER_USER"] = self.controller_user
            environment["MANAGER_PASS"] = self.controller_pass

        if proxy:
            environment["PROXY"] = self.proxy_host
            environment["PROXY_PORT"] = self.proxy_port
            environment["PROXY_USER"] = self.proxy_user
            environment["PROXY_PASS"] = self.proxy_pass

        if override_user:
            environment["MANAGER_USER"] = override_user
        if override_pass:
            environment["MANAGER_PASS"] = override_pass

        if no_user:
            environment["NO_USER"] = no_user

        environment["TYPE"] = "managed"

        if extra and isinstance(extra, dict):
            environment = self.merge_dictionaries(environment, extra)

        ports = [8834]
        port_bindings = {8834: expose_port}

        cid = self.start(full_image_name, environment=environment, ports=ports, port_bindings=port_bindings)
        return cid

    def start_scanner(self, expose_port, full_image_name, nessus_type="pro", proxy=False,
                      use_staging=False, extra=None, publish_all_ports=False):
        """
        Start Nessus scanner container and activate it as nessus_type. Supports: home, pro, manager, none

        :param str expose_port: The port to run scanner on.
        :param str full_image_name: The full image name of the docker image to start, including tag.
        :param str nessus_type: Supports "home", "pro", "manager", "cloud" and "none".
        :param bool proxy: Flag to use the proxy configuration found in nessus_config.py.
        :param bool use_staging: Flag to use the staging server instead of default production replica.
        :param dict extra: Provide extra environment variables for container configuration here. This dict with be
        appended to the existing environment dictionary.
        :return: container ID or None if failed.

        .. code-block:: python
           :dedent: 4

            docker_nessus.start_scanner("443",
                                        docker-resgistry.lab.tenablesecurity.com/services/nessus-debian9:release,
                                        nessus_type="manager")
        """
        environment = dict()

        if nessus_type == ControllerType.manager:
            environment["TYPE"] = nessus_type
            environment["USERNAME"] = self.controller_user
            environment["PASSWORD"] = self.controller_pass

        else:
            # Default to scanner configuration
            environment["TYPE"] = nessus_type
            environment["USERNAME"] = self.scanner_user
            environment["PASSWORD"] = self.scanner_pass

        if proxy:
            environment["PROXY"] = self.proxy_host
            environment["PROXY_PORT"] = self.proxy_port
            environment["PROXY_USER"] = self.proxy_user
            environment["PROXY_PASS"] = self.proxy_pass

        if use_staging:
            environment["PLUGIN_SERVER"] = self.staging_plugin_server
            environment["PLUGIN_SERVER_API"] = self.staging_plugin_server_api

        if extra and isinstance(extra, dict):
            environment = self.merge_dictionaries(environment, extra)

        if not publish_all_ports:
            ports = [8834]
            port_bindings = {8834: expose_port}

            cid = self.start(full_image_name, environment=environment, ports=ports, port_bindings=port_bindings)
            return cid
        else:
            cid = self.run(image_name=full_image_name, environment=environment,
                           publish_all_ports=publish_all_ports)
            return cid

    def wait_for_init(self, cid):
        """
        Confirm if the configuration scripts inside the container (configure_agent.py | configure_scanner.py)
        have finished running, wait if not, and return exit status.

        :param str cid: Docker container id in which to check the logs.
        :return: True|False, line_that_matched|line_that_failed

        .. code-block:: python

            docker_nessus.wait_for_init(cid)
        """
        logs = None
        exited_pattern = "(.*)exited: configure_agent(.*)|(.*)exited: configure_scanner(.*)"
        success_pattern = re.compile(r"(.*)exited: configure_agent \(exit status 0; expected\)"
                                     r"|(.*)exited: configure_scanner \(exit status 0; expected\)")
        while not logs:
            logs = check_output(["docker", "logs", cid]).decode(ENCODING)

        # Ensure script has exited:
        script_exited = re.findall(exited_pattern, logs)
        while not script_exited:
            sleep(sleep_time=TIME_FIVE_SECONDS, reason='wait for script to exit')
            logs = check_output(["docker", "logs", cid]).decode(ENCODING)
            script_exited = re.findall(exited_pattern, logs)

        # Check to see if status is 0:
        match = success_pattern.search(logs)
        if not match:
            self.logger.error("Container configuration has failed for %s. Investigate: %s", cid, logs)
            return False, script_exited

        self.logger.debug("Container configuration completed for %s.", cid)
        return True, match.group(0)
