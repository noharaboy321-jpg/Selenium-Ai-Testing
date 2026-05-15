"""
Helper functions for Docker containers.

The code examples in the docstrings assume the module has been imported like so:

.. code-block:: python

    import dockernessus
    docker_nessus = dockernessus.DockerNessus()


:copyright: Tenable Network Security, 2017
:date: Aug 30 2017
:author: @jmcneil
"""
import io
import os
import re
import tarfile

from random import randint

from .session import Session
from .constants import ENCODING


class Container(Session):
    """Methods for working with Docker containers."""

    def check_container_logs(self, cid):
        """
        Check the logs of the Docker container for failed exit status from configure_agent.py | configure_scanner.py.
        There is another method wait_for_init() which can be used to ensure that container initialization has
        completed before calling this log checker.

        :param str cid: Docker container id in which to check the logs.
        :returns: True/False, line_that_matched/line_that_failed
        :rtype: Boolean

        .. code-block:: python

            container_logs = docker_nessus.check_container_logs(cid)
        """
        exited_line = "(.*)exited: configure_agent(.*)|(.*)exited: configure_scanner(.*)"
        good_status = re.compile("(.*)exit status 0(.*)")
        status_patten = re.compile("(.*)exit status(.*)")

        logs = self.logs(cid)
        if not logs:
            return False, "Failed to get logs from container."

        if re.findall(exited_line, logs):
            # Check for good status:
            match = good_status.search(logs)
            if match:
                return True, match.group(0)

            # Look for bad exit status. Configuration script should only ever exit 0.
            match2 = status_patten.search(logs)

            if not match2:
                self.logger.error("Failed to find exit status of configuration script. "
                                  "It may be still be running, but this is unexpected.")
                return False, match2.group(0)
            else:
                self.logger.error("Non-zero exit status, "
                                  "something bad occurred. Full line: \n %s", match2.group(0))

                return False, match2.group(0)

    def commit(self, cid, name, tag, message=None, author=None, command="/bin/bash", exposed=None, hostname="",
               volumes=None, environment=None, work_dir='', disable_network=False):
        """
        Commit a running Docker container to an image.

        :param str cid: The container ID to commit.
        :param str name: Image name up to the ':'. Typically the registry name and a subfolder. Ex:
                        docker-registry.lab.tenablesecurity.com/services/nessus-centos7
        :param str tag: The tag for the image. Usually a version or build. Ex: 6.12.0
        :param str message: The message for the commit.
        :param str author: Author of the image.
        :param str command: Default command the container should use if one is not specified.
        :param dict exposed: Ports that are exposed. Dict. {'80/tcp': {}}
        :param str hostname: The hostname to assign to the container.
        :param dict volumes: A dictionary of available volumes.
        :param dict environment: List of environment variables.
        :param str work_dir: The working directory for the container to use. Default: "".
        :param bool disable_network: Disable the network stack inside the container. Default: False
        :return: A dictionary containing image ID.
        :rtype: Dictionary

        .. code-block:: python

            docker_nessus.commit(cid=cid, "mynewimage", "latest")
        """
        return self.api_client.commit(cid, repository=name, tag=tag, message=message, author=author,
                                      conf={
                                          'Hostname': hostname,
                                          'User': '',
                                          'Memory': 0,
                                          'MemorySwap': 0,
                                          'AttachStdin': False,
                                          'AttachStdout': False,
                                          'AttachStderr': True,
                                          'PortSpecs': None,
                                          'Tty': False,
                                          'OpenStdin': False,
                                          'StdinOnce': False,
                                          'Env': environment,
                                          'Cmd': [command],
                                          'Volumes': volumes,
                                          'WorkingDir': work_dir,
                                          'DisableNetwork': disable_network,
                                          'ExposedPorts': exposed})

    def copy(self, cid, file_path, copy_to="/tmp/"):
        """
        Copy a file from a container onto the local file system.

        :param str cid: the ID of the container.
        :param str file_path: Full file path + name to copy.
        :param str copy_to: Path to copy the file on the local system.
        :returns: status, specified file, False / None if failed.
        :rtype: bool

        .. code-block:: python

           docker_nessus.copy(cid=cid, file_path=file_path, copy_to="/opt/myapp/config")
        """
        tarball = None

        file_name = os.path.basename(file_path)
        new_path = copy_to + "nessus_test_" + str(randint(1000000000000, 9999999999999)) + "/"

        # 1.20.x version of the API supports tarballing natively.
        try:
            tarball_obj, tarball_info = self.get_archive(cid, file_path)
            if all([tarball_obj,hasattr(tarball_obj, 'data')]):
                tarball = tarfile.open(fileobj=io.BytesIO(tarball_obj.data))
            elif all([tarball_obj, not hasattr(tarball_obj, 'data')]):
                tarball = tarfile.open(fileobj=io.BytesIO(tarball_obj.gi_frame.f_locals['response'].content))
        except Exception as exc:
            self.logger.info("Failed to copy file %s from container. "
                             "It may not exist. Attempting legacy copy. Error: %s", file_path, str(exc))
            try:
                # < 1.20.x does not support tarballing.
                response = self.api_client.copy(cid, file_path)  # pylint: disable=no-member

                if not response:
                    self.logger.debug("No response from Docker API. Response: %s", str(response))
                    return False, None

                tarball = tarfile.open(fileobj=io.BytesIO(response.data))
            except Exception as error:
                # docker.errors.APIError (500 when file does not exist)
                # tarfile.ReadError
                self.logger.info("Failed to copy file %s from container. "
                                 "It may not exist. Error: %s", file_path, str(error))
                return False, None

        if not tarball:
            self.logger.debug("Failed to create tarfile from response data.")
            return False, None

        if os.path.isdir(copy_to):
            tarball.extractall(path=new_path)
            return True, new_path + file_name
        else:
            copy_to = "/tmp/"
            tarball.extractall(path=copy_to)
            return True, new_path + file_name

    def destroy(self, cid, force=True):
        """
        Stop and forcefully remove specified Docker container.

        :param str cid: Docker container Id in which to destroy.
        :param bool force: Flag for forcefully remove the container. Default: True.
        :return: True if destroyed, False if failed.
        :rtype: Boolean

        .. code-block:: python

            docker_nessus.destroy(cid)
        """
        stopped = self.stop(cid)
        if not stopped:
            return False

        removed = self.remove_container(cid, force=force)
        return True if removed else False

    def diff(self, cid):
        """
        Grab the diff of a Docker container. This shows files inside the running container which have changed since
        the container started running.

        :param str cid: Docker container ID to grab the diff info for.
        :return: A list containing the container diffs.
        :rtype: List

        .. code-block:: python

            docker_nessus.diff(cid=cid)
        """
        return self.api_client.diff(cid)

    def get(self, cid):
        """
        Get a container.

        :param str cid: The container ID or name.
        :return: A container object.
        :rtype: Container Object

        .. code-block:: python
            docker_nessus.get(cid)
        """
        return self.client.containers.get(cid)

    def get_archive(self, cid, file_path):
        """
        Copy a file from a container in tarball stream format and return a dict with general information about the file.

        :param str cid: the ID of the container.
        :param str file_path: Full file path + name to copy.
        :returns: status, file info, False / None if failed.
        :rtype: bool

        .. code-block:: python

           docker_nessus.get_archive(cid=cid, file_path=file_path)
        """
        tarball_info = None

        # 1.20.x version of the API supports tarballing natively.
        try:
            tarball_info = self.api_client.get_archive(cid, file_path)
        except Exception as exc:
            self.logger.info("Failed to copy file %s from container. "
                             "It may not exist. Attempting legacy copy. Error: %s", file_path, str(exc))

        if not tarball_info:
            self.logger.debug("Failed to create tarfile from response data.")
            return False, None

        return tarball_info[0], tarball_info[1]

    def get_ip(self, cid):
        """
        Get the internal IP of a container.

        :param cid: Docker container id to return IP of.
        :return: Container IP or None if failed.

        .. code-block:: python

            container_ip = docker_nessus.get_ip(cid)
        """
        info = self.inspect(cid)
        ip_address = info["NetworkSettings"]["IPAddress"]

        if not ip_address:
            return None
        return ip_address

    def get_exposed_port(self, cid):
        """
        Get the port which is exposed on the running container.

        .. .warning At present this only supports one (and the first one found) exposed port on the container.

        :param str cid: Docker container ID.
        :return: exposed port or None if failed.
        :rtype: String

        .. code-block:: python

            docker_nessus.get_exposed_port(cid)
        """
        ports = self.get_ports(cid)
        exposed_port = None
        if not ports:
            self.logger.debug("There are no exposed ports on the container.")
            return exposed_port

        for port in ports.values():
            if port is None:
                pass
            else:
                if port[0]["HostIp"] == "0.0.0.0":
                    exposed_port = port[0]["HostPort"]

        self.logger.debug("Port %s is exposed on the container.", exposed_port)
        return exposed_port

    def get_ports(self, cid):
        """
        Get the ports of a running container.

        :param str cid: Docker container ID.
        :return: Port information , None if failed.

        .. code-block:: python

            docker_nessus.get_port(cid)
        """
        info = self.inspect(cid)
        ports = info["NetworkSettings"]["Ports"]
        self.logger.debug("The ports in use by the container are: %s", info["NetworkSettings"]["Ports"])
        return ports if ports else None

    def inspect(self, cid):
        """
        Inspect a Docker container ID or name and return the info.

        :param cid: Image ID or name to inspect.
        :return: docker inspect output, False if failed.

        .. code-block:: python

            docker_nessus.inspect(cid)
        """
        return self.api_client.inspect_container(cid)

    def kill(self, cid):
        """
        Kill a Docker container.

        :param str cid: Docker container ID to remove.
        :returns: True if removed, False if failed.
        :rtype: Boolean

        .. code-block:: python

            docker_nessus.kill(cid)
        """
        return self.api_client.kill(cid)

    def logs(self, cid, since=None):
        """
        Check the logs of the specified Docker container.

        :param str cid: Docker container ID to grab the logs for.
        :param datetime since: Datetime or int of the time you would like to show the logs from.
        :returns: container logs or None if failed.

        .. code-block:: python

            docker_nessus.logs(cid=cid)
        """
        logs = self.api_client.logs(cid, since=since)
        if not logs:
            return logs.decode(ENCODING)

        return None

    def prune_containers(self):
        """
        Delete all stopped containers.

        :return: A dict containing the containers which were pruned.
        :rtype: Dictionary

        .. code-block:: python
            docker_nessus.prune()
        """
        return self.client.containers.prune()

    def ps(self, show_all=False):
        """
        Get the running Docker containers.

        :param bool show_all: Flag to show all containers, even stopped.
        :returns: List of running containers or None if failed.

        .. code-block:: python

            docker_nessus.ps(show_all=True)
        """
        return self.api_client.containers(all=show_all)

    def remove_container(self, cid, force=False):
        """
        Remove specified Docker container.

        :param str cid: Docker container ID to remove.
        :param bool force: Forcefully remove the container. Use with caution.
        :return: True if removed, False if failed.
        :rtype: bool

        .. code-block:: python

            docker_nessus.remove_container(cid)
        """
        try:
            self.api_client.remove_container(cid, force=force)
            return True
        except Exception as exc:
            self.logger.error("Failed to remove container. Reason: %s", str(exc))
            return False

    def restart(self, cid):
        """
        Restart specified Docker container.

        :param str cid: Container ID in which to remove.
        :returns: True if container is restarted, False if failed.
        :rtype: bool

        .. code-block:: python

            docker_nessus.restart(cid)
        """
        return self.api_client.restart(cid)

    def run(self, image_name, command=None, detach=True, devices=None, dns=None, dns_search=None,
            entrypoint=None, environment=None, cap_add=None, ports=None, mac_address=None, network_mode="bridge",
            network_disabled=False, privileged=False, publish_all_ports=False, volumes=None, volumes_from=None,
            working_dir=None):
        """
        Run a Docker container. This method should be used over the start() method in nearly all cases.

        :param str image_name: Name of the image to start. Use full image name including tag.
        :param str command: Command to run in container, if not default.
        :param bool detach: Flag which if True, attaches to stdout container after it starts.
        :param list devices: Expose host devices into the container. Ex: ["/dev/ttyACM0:/dev/ttyACM0:rwm"]
        :param list dns: A list of custom DNS servers.
        :param list dns_search: A list of custom DNS search domains.
        :param str entrypoint: Override the containers entry point.
        :param dict environment: A dictionary or list of environment variables to inject into the container.
        :param list cap_add: Add additional capabilities to the container.
        :param dict ports: A dictionary containing all the ports to map. Example: {'8834/tcp': 8834}
        :param str mac_address: A specific mac address to use inside of the container.
        :param str network_mode: The networking mode for the container. Supports bridge, container, host and none.
        :param bool network_disabled: Disable networking inside the container all together.
        :param bool privileged: Give extend privs to the container.
        :param bool publish_all_ports: Publish all configured ports to the Docker host.
        :param list volumes: shared volumes configuration.
        :param list volumes_from: A list of container ID's or names to get volumes from.
        :param str working_dir: A path to set as the working directory inside of the container.
        :returns: cid or None if failed.
        :rtype: Container Object

        .. code-block:: python

            ports = {'8834/tcp': 8834}
            environment = dict()
            environment["MANAGER_IP"] = "192.168.2.55"
            environment["MANAGER_PORT"] = "8834"
            environment["MANAGER_USER"] = "admin"
            environment["MANAGER_PASS"] = "admin"
            cid = docker_nessus.run(full_image_name, environment=environment,
                                    ports=ports, port_bindings=port_bindings)
        """
        container = self.client.containers.run(image=image_name,
                                               cap_add=cap_add,
                                               command=command,
                                               detach=detach,
                                               devices=devices,
                                               dns=dns,
                                               dns_search=dns_search,
                                               entrypoint=entrypoint,
                                               environment=environment,
                                               mac_address=mac_address,
                                               network_disabled=network_disabled,
                                               network_mode=network_mode,
                                               ports=ports,
                                               privileged=privileged,
                                               publish_all_ports=publish_all_ports,
                                               volumes=volumes,
                                               volumes_from=volumes_from,
                                               working_dir=working_dir)

        return container.id

    def start(self, image_name, command=None, environment=None, binds=None, ports=None,
              port_bindings=None, volumes=None, extra=None):
        """
        Create and start a container. Can be used as an alternative to the run method.

        :param str image_name: Name of the image to start. Use full image name including tag.
        :param str command: Command to run in container, if not default.
        :param dict environment: A dictionary or list of environment variables to inject into the container.
        :param dict binds: A list or dict of shared volumes to configure.
        :param list ports: List of ports (int) to open inside the container. Ex: [8834] or [8834, 443]
        :param dict port_bindings: A dictionary containing the port binding for the container. Ex:
                    >>> port_bindings = {8834: 8000, 443: 9000}
                    Note: unlike the docker run command, the container port is on the left side,
                    and the exposed port that gets mapped on the host is on the right side. This is
                    easy to trip over. Also said: -p 8000:8834 == (8834: 8000} is docker-py.
        :param list volumes: shared volumes configuration.
        :param dict extra: Provide extra environment variables for container configuration here. This dict with be
        appended to the existing environment dictionary.
        :returns: cid or None if failed.
        :rtype: String

        .. code-block:: python

            ports = [8834]
            port_bindings = {8834: expose_port}
            environment = dict()
            environment["MANAGER_IP"] = "192.168.2.55"
            environment["MANAGER_PORT"] = "8834"
            environment["MANAGER_USER"] = "admin"
            environment["MANAGER_PASS"] = "admin"
            cid = docker_nessus.start(full_image_name, environment=environment,
                                      ports=ports, port_bindings=port_bindings)
        """
        config = self.api_client.create_host_config(
            binds=binds,
            port_bindings=port_bindings)

        if extra and isinstance(extra, dict):
            environment = self.merge_dictionaries(environment, extra)

        cid = self.api_client.create_container(image_name, command=command, ports=ports, environment=environment,
                                               volumes=volumes, host_config=config)
        if cid["Warnings"] is not None:
            self.logger.warning("The following warnings occurred "
                                "when starting the container:\n %s", cid["Warnings"])

        if cid["Id"]:
            self.api_client.start(cid["Id"])
            return cid["Id"]

        return None

    def stop(self, cid):
        """
        Stop specified Docker container.

        :param str cid: Docker container id in which to stop.
        :return: True if stopped, False if failed.
        :rtype: Boolean

        .. code-block:: python

            docker_nessus.stop(cid)
        """
        try:
            self.api_client.stop(cid)
            return True
        except Exception as exc:
            self.logger.error(exc)
            return False

    def top(self, cid):
        """
        Show top output of the container.

        :param str cid: Docker container to grab the top output from.
        :return: top output. False if failed.
        :rtype: Dictionary

        .. code-block:: python

            docker_nessus.top(cid)
        """
        return self.api_client.top(cid)
