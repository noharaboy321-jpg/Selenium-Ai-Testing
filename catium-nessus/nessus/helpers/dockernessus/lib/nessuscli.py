"""
Python version of nessuscli. Supprts local and Docker container modes.

:copyright: Tenable Network Security, 2017
:date: Aug 30 2017
:last_modified: March 25, 2021
:author: @jmcneil, @kpanchal
"""
import os
import platform
import re

from subprocess import call, check_output, CalledProcessError

if platform.system() == 'Linux':
    from pexpect import spawn, ExceptionPexpect
else:
    from pexpect import popen_spawn, ExceptionPexpect
from catium.lib.log import create_logger
from nessus.lib.config import docker_config

from .constants import ENCODING

system_os = platform.system()


class Base(object):
    """Base object for the nessuscli."""

    def __init__(self, cid=None, agent=False):
        """
        Module for working with nessuscli on a local system on within Docker containers. Supports Nessus scanners and
        Nessus Agents.

        :ivar str cid: Id of the Docker container in use.
        :ivar bol agent: Flag to enable usage of Nessus agent nessuscli location.
        """

        self.container_id = cid
        self.fnull = open(os.devnull, 'w')
        self.logger = create_logger()

        if agent:
            self.nessuscli = docker_config.AGENT_CONFIG['install_dir'] + "sbin/nessuscli"
            self.nessusd = docker_config.AGENT_CONFIG['install_dir'] + "sbin/nessusd"
        else:
            self.nessuscli = docker_config.SCANNER_CONFIG['install_dir'] + "sbin/nessuscli"
            self.nessusd = docker_config.SCANNER_CONFIG['install_dir'] + "sbin/nessusd"


class Agent(Base):
    """Any nessuscli commands specific to Agents."""

    def __init__(self, cid=None):
        Base.__init__(self, agent=True, cid=cid)

    def link(self, key, manager_ip, manager_port="8834", cid=None, ca_path=None, groups="All",
             proxy_host=None, proxy_port=None, proxy_user=None,
             proxy_pass=None, proxy_agent=None):
        """
        Link a Nessus Agent using the nessuscli tool and a key from the Manager. Supports local and Docker modes. Also
        supports linking using a proxy server.

        __TODO__ Update this to use check_output.

        :param str key: Key from the manager.
        :param str manager_ip: IP or DNS of the manager to link to.
        :param str manager_port: Port the Manager is listening on. Default: 8834
        :param str cid: Container Id to run the command in. Overrides self.container_id if provided.
        :param str ca_path: The path to the CA certificate the controller is using.
        :param str groups: A comma separated list of groups for the agent to join. =
        :param str proxy_host: DNS or IP of the proxy server.
        :param str proxy_port: Port of the proxy server.
        :param str proxy_user: username used for proxy auth.
        :param str proxy_pass: password used for proxy auth.
        :param str proxy_agent: Proxy agent to use.
        :return: True if linked, False if failed.
        :rtype: Boolean

        .. code-block:: python

            nessuscli.agentcli.link(key="some-key", manager_ip="172.26.19.42", cid="some-cid")
        """
        command_list = []

        if cid:
            self.container_id = cid

        if self.container_id:
            docker_commands_list = [
                "docker",
                "exec",
                self.container_id
            ]
            command_list.extend(docker_commands_list)

        all_commands_list = [
            self.nessuscli,
            "agent",
            "link",
            "--key={0}".format(key),
            "--host={0}".format(manager_ip),
            "--port={0}".format(manager_port),
            "--groups={0}".format(groups)
        ]
        command_list.extend(all_commands_list)

        if ca_path:
            command_list.extend("--ca-path={0}".format(str(ca_path)))

        if groups:
            command_list.append("--groups={0}".format(str(groups)))

        proxy_commands_list = [
            "--proxy_host={0}".format(proxy_host),
            "--proxy_port={0}".format(proxy_port),
            "--proxy_user={0}".format(proxy_user),
            "--proxy_pass={0}".format(proxy_pass),
            "--proxy_agent={0}".format(proxy_agent)
        ]

        if proxy_host and proxy_port:
            command_list.extend(proxy_commands_list)

        self.logger.debug("Running command: %s", str(command_list))

        try:
            agent_linked = check_output(command_list, stderr=self.fnull).decode(ENCODING)
        except CalledProcessError as error:
            self.logger.error("Failed to link Agent to controller. Error: %s", str(error.output))
            return False, error

        if re.findall("(.*)failed(.*)|(.*)error(.*)", agent_linked, re.IGNORECASE):
            return False, agent_linked

        return True, agent_linked

    def status(self, cid=None):
        """
        Check the status of the Nessus Agent using nessuscli.

        .. note::
            When an Agent is not linked to any controller, the return
            code for the agent status command is 2. This function returns this state as True / expected.

        :param str cid: The container ID or name of the Docker container. Overrides self.container_id if provided.
        :return: call status (True/False) and output from command itself. None if no output from command.
        :rtype: Boolean

        .. code-block:: python

            nessuscli.agentcli.status(cid="some-cid")
        """
        command_list = []

        if cid:
            self.container_id = cid

        if self.container_id:
            docker_commands_list = [
                "docker",
                "exec",
                self.container_id
            ]
            command_list.extend(docker_commands_list)

        all_commands_list = [
            self.nessuscli,
            "agent",
            "status"
        ]
        command_list.extend(all_commands_list)

        self.logger.debug("Running command: %s", str(command_list))

        try:
            agent_status = check_output(command_list, stderr=self.fnull).decode(ENCODING)

        except CalledProcessError as error:
            if error.returncode == 2:
                self.logger.warning("Caught exit return code 2, this usually means that the Agent is not linked to "
                                    "a controller.")
                agent_status = error.output.decode(ENCODING)
            else:
                self.logger.error("Failed to check agent status inside Docker container %s. "
                                  "Error: %s", str(cid), str(error))
                return False, error

        if re.findall("(.*)failed(.*)|(.*)error(.*)", agent_status, re.IGNORECASE):
            return False, agent_status

        return True, agent_status

    def unlink(self, cid=None, force=True):
        """
        Unlink the Nessus Agent from its controller using the nessuscli tool.

        .. note::

            When Agent is not linked to a controller, a return code of 2 is received from nessuscli. This
            returned as True/expected in this function.

        :param str cid: The ID of the Docker container. Overrides self.container_id if provided.
        :param bool force: Forcefully unlink the agent from a controller.
        :return: True if unlinked, False if failed.
        :rtype: Boolean

        .. code-block:: python

            nessuscli.agentcli.unlink()
            nessuscli.agentcli.unlink(cid="some-cid")
        """
        command_list = []

        if cid:
            self.container_id = cid

        if self.container_id:
            docker_commands_list = [
                "docker",
                "exec",
                self.container_id
            ]
            command_list.extend(docker_commands_list)

        all_commands_list = [
            self.nessuscli,
            "agent",
            "unlink"
        ]

        if force:
            all_commands_list.append("--force")
        command_list.extend(all_commands_list)

        self.logger.debug("Running command: %s", str(command_list))

        try:
            agent_unlinked = check_output(command_list, stderr=self.fnull).decode(ENCODING)
        except CalledProcessError as error:

            if error.returncode == 2:
                self.logger.warning("Caught exit return code 2, this usually means that the Agent is not linked to "
                                    "a controller.")
                agent_unlinked = error.output.decode(ENCODING)
            else:
                self.logger.error("Failed to unlink Agent. Error: %s", str(error.output))
                return False, error

        if not agent_unlinked:
            self.logger.error("Failed to unlink the Agent.")
            return False, None

        if re.findall("(.*)successfully unlinked(.*)|(.*)no host information found(.*)",
                      agent_unlinked,
                      re.IGNORECASE):
            return True, agent_unlinked

        return False, agent_unlinked


class BugReporting(Base):
    """The bug reporting commands of nessuscli command."""

    def __init__(self, cid=None):
        Base.__init__(self, cid=cid)


class Certificates(Base):
    """The bug reporting commands of nessuscli command."""

    def __init__(self, cid=None):
        Base.__init__(self, cid=cid)


class Fetch(Base):
    """The fetch commands of nessuscli command."""

    def __init__(self, cid=None):
        Base.__init__(self, cid=cid)

    def activate(self, code, activation_server=None, cid=None):
        """
        Activate Nessus using a provided activation code.

        :param str code: the activation code for Nessus.
        :param str activation_server: Custom activation server to use. Optional.
        :param str cid: If provided, run nessuscli inside the container instead of locally.
        :return: True if activated, False if not.
        :rtype: Boolean

        .. code-block:: python

            nessuscli.fetch.activate("activation-code")
        """

        activation_command_list = []
        plugin_server_command_list = []

        if cid:
            self.container_id = cid

        # Handle Docker
        docker_commands_list = [
            "docker",
            "exec",
            self.container_id
        ]

        if self.container_id:
            activation_command_list.extend(docker_commands_list)
            plugin_server_command_list.extend(docker_commands_list)

        # Handle custom plugin servers
        custom_server_commands = [
            self.nessuscli,
            "fix",
            "--secure",
            "--set",
            "custom_host={0}".format(str(activation_server))
        ]
        plugin_server_command_list.extend(custom_server_commands)

        if activation_server:
            self.logger.info("Setting custom activation/plugin server.")
            activation_server_set = call(plugin_server_command_list)

            if activation_server_set != 0:
                return False

        # Activation
        all_activation_commands = [
            self.nessuscli,
            "fetch",
            "--register",
            code
        ]
        activation_command_list.extend(all_activation_commands)

        self.logger.info("Activating Nessus using %s.", str(code))
        self.logger.debug("Activating using command(s): %s", str(activation_command_list))

        try:
            activated = check_output(activation_command_list, stderr=self.fnull).decode(ENCODING)

        except CalledProcessError as error:
            self.logger.error("Failed to activate Nessus. Error: %s", str(error.output))
            return False, error

        if not activated:
            self.logger.error("Failed to get Agent status.")
            return False, None

        if re.findall("(.*)failed(.*)|(.*)error(.*)|(.*)invalid activation code(.*)", activated, re.IGNORECASE):
            return False, activated

        self.logger.info("Successfully activated Nessus.")
        return True, activated


class Fix(Base):
    """Any commands related to nessuscli fix."""

    def __init__(self, cid=None):
        Base.__init__(self, cid=cid)

    def get_advanced_setting(self, setting=None, cid=None, secure=False):
        """
        Get the list of all or a specific advanced setting.

        :param str setting: An advanced setting to add or update in string format. Ex: force_ui_update=1
        :param str cid: The ID of the Docker container. Overrides self.container_id if provided.
        :param bool secure: Flag to enable secure mode for the setting being added / updated.
        :return: True if setting added, False if failed.
        :rtype: Boolean

        .. code-block:: python

            nessuscli.fix.set_advanced_setting("custom_setting=1")
            nessuscli.fix.set_advanced_Setting("custom_setting=1", cid=mycid)
        """
        command_list = []

        if cid:
            self.container_id = cid

        if self.container_id:
            docker_commands_list = ["docker", "exec", self.container_id]
            command_list.extend(docker_commands_list)

        all_commands_list = [self.nessuscli, "fix"]
        command_list.extend(all_commands_list)

        if secure:
            command_list.append("--secure")

        if setting:
            specific_setting = ["--get", str(setting)]
            command_list.extend(specific_setting)
        else:
            command_list.append("--list")

        self.logger.debug("Running command: %s", str(command_list))

        try:
            setting_info = check_output(command_list, stderr=self.fnull).decode(ENCODING)
        except CalledProcessError as error:
            self.logger.error("Failed fetch setting. Error: %s", str(error.output))
            return False, error

        if not re.findall("(.*)current value for(.*)|(.*)logfile(.*)", setting_info, re.IGNORECASE):
            return False, setting_info
        else:
            return True, setting_info

    def set_advanced_setting(self, setting, cid=None, secure=False):
        """
        Set an advanced setting into the global db.

        :param str setting: An advanced setting to add or update in string format. Ex: force_ui_update=1
        :param str cid: The ID of the Docker container. Overrides self.container_id if provided.
        :param bool secure: Flag to enable secure mode for the setting being added / updated.
        :return: True if setting added, False if failed.
        :rtype: Boolean

        .. code-block:: python

            nessuscli.fix.set_advanced_setting("custom_setting=1")
            nessuscli.fix.set_advanced_Setting("custom_setting=1", cid=mycid)
        """
        command_list = []

        if cid:
            self.container_id = cid

        if self.container_id:
            docker_commands_list = ["docker", "exec", self.container_id]
            command_list.extend(docker_commands_list)

        all_commands_list = [self.nessuscli, "fix", "--set"]
        command_list.extend(all_commands_list)

        if secure:
            command_list.append("--secure")

        command_list.append(setting)

        self.logger.debug("Running command: %s", str(command_list))

        try:
            setting_added = check_output(command_list, stderr=self.fnull).decode(ENCODING)
        except CalledProcessError as error:
            self.logger.error("Failed to set advanced setting. Error: %s", str(error.output))
            return False, error

        if setting_added:
            if not re.findall("(.*)successfully set(.*)", setting_added, re.IGNORECASE):
                return False, setting_added
            else:
                return True, setting_added

        self.logger.error("Failed to force a plugin update.")
        return False, None

    def force_plugin_update(self, cid=None):
        """
        Force an Agent to check for updates and reload them if available. Supported in 6.6.0+

        :param str cid: The container ID or name of the Docker container. Overrides self.container_id when provided.
        :returns: command status (True/False) and output from command. None if no output from command.
        :rtype: Boolean

        .. code-block:: python

            nessuscli.fix.force_plugin_update()
            nessuscli.fix.force_plugin_update(cid="containerId")
        """
        if cid:
            self.container_id = cid

        return self.set_advanced_setting("force_plugin_update=1", cid=cid)

    def force_ui_update(self, cid=None):
        """
        Force an Agent to check for updates and reload them if available. Supported in 6.6.0+

        :param str cid: The container ID or name of the Docker container. Overrides self.container_id when provided.
        :returns: command status (True/False) and output from command. None if no output from command.
        :rtype: Boolean

        .. code-block:: python

            nessuscli.fix.force_ui_update()
            nessuscli.fix.force_ui_update(cid="containerId")
        """
        if cid:
            self.container_id = cid

        return self.set_advanced_setting("feed_ui_last=1", cid=cid)


class Managed(Base):
    """
    Any commands related to managed scanners.
    """

    def __init__(self, cid=None):
        Base.__init__(self, cid=cid)

    def link(self, key, manager_ip, manager_port="8834", cid=None, ca_path=None,
             proxy_host=None, proxy_port=None, proxy_user=None, proxy_pass=None, proxy_agent=None):
        """
        Link a Nessus scanner to controller using the nessuscli tool. Supports local and docker modes.

        :param str key: The linking key from the controller/manager.
        :param str manager_ip: IP or DNS name of the manager to link to.
        :param str manager_port: Port the Manager is listening on.
        :param str cid: Container Id to run command inside. Provides a way to override self.container_id if needed.
        :param str ca_path: The path to the CA certificate the controller is using.
        :param str proxy_host: DNS or IP of proxy server.
        :param str proxy_port: Port of proxy server.
        :param str proxy_user: username used for proxy auth.
        :param str proxy_pass: password used for proxy auth.
        :param str proxy_agent: Proxy agent to use.
        :returns: True or False if failed, the status message
        :rtype: Boolean

        .. code-block:: python

            nessuscli.managed.link(key="some-key", manager_ip="my.manager.icn", manager_port="8834", cid="some-cid")
        """

        command_list = []

        if cid:
            self.container_id = cid

        if self.container_id:
            docker_commands_list = [
                "docker",
                "exec",
                self.container_id
            ]
            command_list.extend(docker_commands_list)

        all_commands_list = [
            self.nessuscli,
            "managed",
            "link",
            "--key={0}".format(key),
            "--host={0}".format(manager_ip),
            "--port={0}".format(manager_port)
        ]
        command_list.extend(all_commands_list)

        if ca_path:
            command_list.extend("--ca-path={0}".format(ca_path))

        proxy_commands_list = [
            "--proxy_host={0}".format(proxy_host),
            "--proxy_port={0}".format(proxy_port),
            "--proxy_user={0}".format(proxy_user),
            "--proxy_pass={0}".format(proxy_pass),
            "--proxy_agent={0}".format(proxy_agent)
        ]

        if proxy_host and proxy_port:
            command_list.extend(proxy_commands_list)

        self.logger.debug("Running command: %s", str(command_list))

        try:
            scanner_linked = check_output(command_list, stderr=self.fnull).decode(ENCODING)
        except CalledProcessError as error:
            self.logger.error("Failed to link managed scanner to controller. Error: %s", str(error.output))
            return False, error

        if re.findall("(.*)failed(.*)|(.*)error(.*)", scanner_linked, re.IGNORECASE):
            return False, scanner_linked

        return True, scanner_linked

    def status(self, cid=None):
        """
        Check the status of the Managed scanner using nessuscli.

        :param str cid: Container ID to run command in. Provides a way to override self.container_id if needed.
        :returns: True or False if failed.
        :rtype: Boolean

        .. code-block:: python

            nessuscli.managedcli.status(cid="some-cid")
        """
        command_list = []

        if cid:
            self.container_id = cid

        if self.container_id:
            docker_commands_list = [
                "docker",
                "exec",
                self.container_id
            ]
            command_list.extend(docker_commands_list)

        all_commands_list = [
            self.nessuscli,
            "managed",
            "status"
        ]
        command_list.extend(all_commands_list)

        self.logger.debug("Running command: %s", str(command_list))

        try:
            managed_status = check_output(command_list, stderr=self.fnull).decode(ENCODING)

        except CalledProcessError as error:
            if error.returncode == 2:
                self.logger.warning("Caught exit return code 2, this usually means that the managed scanner "
                                    "is not linked to a controller, but just giving you a heads up.")
                managed_status = error.output.decode(ENCODING)
            else:
                self.logger.error("Failed to check scanner status. Error: %s", str(error.output))
                return False, error

        if re.findall("(.*)failed(.*)|(.*)error(.*)", managed_status, re.IGNORECASE):
            return False, managed_status

        return True, managed_status

    def unlink(self, cid=None, force=True):
        """
        Unlink the Nessus scanner using the nessuscli tool.

        :param str cid: Container ID to run command in. Provides a way to override self.container_id if needed.
        :param bool force: Forcefully unlink the managed scanner.
        :returns: True or False if failed.
        :rtype: Boolean

        .. code-block:: python

            nessuscli.managed.unlink(cid="some-cid")
        """
        command_list = []

        if cid:
            self.container_id = cid

        if self.container_id:
            docker_commands_list = [
                "docker",
                "exec",
                self.container_id
            ]
            command_list.extend(docker_commands_list)

        all_commands_list = [
            self.nessuscli,
            "managed",
            "unlink"
        ]

        if force:
            all_commands_list.append("--force")

        command_list.extend(all_commands_list)

        self.logger.debug("Running command: %s", str(command_list))

        try:
            managed_unlinked = check_output(command_list, stderr=self.fnull).decode(ENCODING)
        except CalledProcessError as error:

            if error.returncode == 2:
                self.logger.warning("Caught exit return code 2, this usually means that the managed scanner"
                                    " is not linked to a controller, but just giving you a heads-up.")
                managed_unlinked = error.output.decode(ENCODING)
            else:
                self.logger.error("Failed to unlink managed scanner. Error: %s", str(error.output))
                return False, error

        if re.findall("(.*)successfully unlinked(.*)|(.*)no host information found(.*)",
                      managed_unlinked,
                      re.IGNORECASE):
            return True, managed_unlinked

        return False, managed_unlinked


class Scan(Base):
    """
    User administration commands.
    """

    def __init__(self, cid=None):
        Base.__init__(self, cid=cid)

    def analyze(self, scan_uuid, cid=None):
        """
        Analyze scan to make them load faster, in certain cases.

        :param str scan_uuid: The UUID of the scan to analyze.
        :param str cid: Container ID to run command in.
        :return: True/False from commands status and analyze results output.
        :rtype: Boolean

        .. code-block:: python

            nessuscli.scan.analyze(scan_uuid="user1", cid="some-cid")
        """
        command_list = []

        if cid:
            self.container_id = cid

        if self.container_id:
            docker_commands_list = [
                "docker",
                "exec",
                self.container_id
            ]
            command_list.extend(docker_commands_list)

        all_commands_list = [
            self.nessuscli,
            "analyze",
            "scan",
            scan_uuid
        ]
        command_list.extend(all_commands_list)

        self.logger.debug("Running command: %s", str(command_list))

        try:
            scan_analyzed = check_output(command_list, stderr=self.fnull).decode(ENCODING)
        except CalledProcessError as error:
            self.logger.error("Failed to analyze scan %s. Error: %s", str(scan_uuid), str(error.output))
            return False, error

        if re.findall("(.*)successfull(.*)",
                      scan_analyzed,
                      re.IGNORECASE):
            return True, scan_analyzed

        return False, scan_analyzed

    def run(self, policy, targets, report, cid=None):
        """
        Run a scan using the nessuscli.

        :param policy:
        :param targets:
        :param report:
        :param cid:
        :return:

        .. code-block:: python

            nessuscli.scan.run(policy="Custom_policy", targets="172.26.25.70", report="Nessuscli_scan", cid="somecid")
        """
        command_list = []

        if cid:
            self.container_id = cid

        if self.container_id:
            docker_commands_list = [
                "docker",
                "exec",
                self.container_id
            ]
            command_list.extend(docker_commands_list)

        all_commands_list = [
            self.nessuscli,
            "scan",
            policy,
            targets,
            report
        ]
        command_list.extend(all_commands_list)

        self.logger.debug("Running command: %s", str(command_list))

        try:
            scanned = check_output(command_list, stderr=self.fnull).decode(ENCODING)
        except CalledProcessError as error:
            self.logger.error("Failed to launch scan from policy %s. Error: %s", str(policy), str(error.output))
            return False, error

        if re.findall("(.*)successfull(.*)", scanned, re.IGNORECASE):
            return True, scanned

        return False, scanned


class SoftwareUpdate(Base):
    """
    The software update related commands of nessuscli.
    """

    def __init__(self, cid=None):
        Base.__init__(self, cid=cid)

    def update_all(self, cid=None):
        """
        Update Nessus scanner, both core and remote.

        :param str cid: If provided, run nessuscli inside the container instead of locally.
        :return: True if activated, False if not.
        :rtype: Boolean

        .. code-block:: python

            nessuscli.update.update_all(cid=cid)
        """
        command_list = []

        if cid:
            self.container_id = cid

        if self.container_id:
            docker_commands_list = [
                "docker",
                "exec",
                self.container_id
            ]
            command_list.extend(docker_commands_list)

        all_commands_list = [
            self.nessuscli,
            "update",
            "--all"
        ]
        command_list.extend(all_commands_list)

        self.logger.debug("Running command: %s", str(command_list))

        try:
            updated = check_output(command_list, stderr=self.fnull).decode(ENCODING)
        except CalledProcessError as error:
            self.logger.error("Failed to update all components. %s", str(error.output))
            return False, error

        if re.findall("(.*)successfull(.*)",
                      updated,
                      re.IGNORECASE):
            return True, updated

        return False, updated

    def update_plugins(self, cid=None):
        """
        Update the plugins on the scanner.

        :param str cid: If provided, run nessuscli inside the container instead of locally.
        :return: True if activated, False if not.
        :rtype: Boolean

        .. code-block:: python

            nessuscli.update.update_plugins(cid=cid)
        """
        command_list = []
        if cid:
            self.container_id = cid

        if self.container_id:
            docker_commands_list = [
                "docker",
                "exec",
                self.container_id
            ]
            command_list.extend(docker_commands_list)

        all_commands_list = [
            self.nessuscli,
            "update",
            "--plugins-only"
        ]
        command_list.extend(all_commands_list)

        self.logger.debug("Running command: %s", str(command_list))

        try:
            plugins_updated = check_output(command_list, stderr=self.fnull).decode(ENCODING)
        except CalledProcessError as error:
            self.logger.error("Failed to update plugins. %s", str(error.output))
            return False, error

        if re.findall("(.*)successfull(.*)", plugins_updated, re.IGNORECASE):
            return True, plugins_updated

        return False, plugins_updated


spawn = None
popen_spawn = None
class User(Base):
    """
    User administration commands.

    .. note::

        This class does not support Docker at this time. pexpect does not do well with the pty in Docker at this time.
        Should be possible to work around with dockerpty, but will revisit another time. User creation is handled
        during the init script inside of Docker Nessus and support has not been needed so far, but could be added if
        needed.
    """
    def add_user(self, username, password="password"):
        """
        Add user to Nessus using nessuscli tool.

        :param str username: The name of the user to add.
        :param str password: The password to set for the user.
        :return: True if added, False if failed.
        :rtype: Boolean

        .. code-block:: python

            nessuscli.user.add_user(username="user1", password="newpass", cid="some-cid")
        """
        self.logger.info("Adding user..")

        try:
            child = spawn(self.nessuscli + " adduser") if system_os == 'Linux' else popen_spawn.PopenSpawn(
                self.nessuscli + " adduser")
        except ExceptionPexpect as error:
            self.logger.error("Error running command. Is Nessus installed? Error: %s", str(error))
            return False

        child.expect('Login:')
        child.sendline(username)

        i = child.expect(['Login password:', 'already exists'])

        if i == 0:
            self.logger.info('Setting Password..')
            child.sendline(password)

            self.logger.info("Confirming Password..")
            child.expect('Login password .*')
            child.sendline(password)

            self.logger.info("Adding administrator privileges.")
            child.expect('Do you want this user to be .*')
            child.sendline('y')

            self.logger.info("No Rules needed..")
            child.expect('the user can have an empty rules set')
            child.sendline('')

            self.logger.info("Confirming user addition..")
            child.expect('Is that ok?')
            child.sendline('y\n')
            self.logger.info("Successfully added user: %s / %s", username, password)

            return True

        elif i == 1:
            self.logger.info('User %s exists. Skipping.', username)
            child.kill(0)
            return True

    def chpasswd(self, username, password):
        """
        Change the password of the Nessus user.

        :param str username: Username to change.
        :param str password: New password to set for the user.
        :return: True if user password is changed, False if not or user did not exist.
        :rtype: Boolean

        .. code-block:: python

            nessuscli.user.chpasswd(username="user1", password="newpass", cid="some-cid")
        """
        self.logger.info("Changing password:")

        try:
            child = spawn(self.nessuscli + " chpasswd") if system_os == 'Linux' else popen_spawn.PopenSpawn(
                self.nessuscli + " chpasswd")
        except ExceptionPexpect as error:
            self.logger.error("Error running command. Is Nessus installed? Error: %s", str(error))
            return False

        child.expect("Login to change:")
        child.sendline(username)

        i = child.expect(["New password:', 'This user does not exist"])
        if i == 0:
            self.logger.info('Setting Password..')
            child.sendline(password)

            self.logger.info("Confirming Password..")
            child.expect('New password (again).*')
            child.sendline(password)

            self.logger.info("Adding administrator privileges.")
            child.expect('Password changed for .*')

            self.logger.info("Successfully changed password for user: %s", username)
            return True

        elif i == 1:
            self.logger.info("User %s does not exist. Skipping.", username)
            child.kill(0)
            return False

        else:
            return False

    def remove_user(self, username):
        """
        Remove user from Nessus using nessuscli tool.

        :param str username: The username to remove.
        :return: True if user removed or doesn't exist, else return False.
        :rtype: Boolean

        .. code-block:: python

            nessuscli.user.remove_user(username="user1", cid="some-cid")
        """
        self.logger.info("Removing user..")

        try:
            child = spawn(self.nessuscli + " rmuser") if system_os == 'Linux' else popen_spawn.PopenSpawn(
                self.nessuscli + " rmuser")
        except ExceptionPexpect as error:
            self.logger.error("Error running command. Is Nessus installed? Error: %s", str(error))
            return False

        child.expect("Login to remove:")
        child.sendline(username)

        i = child.expect(["User removed', 'This user does not exist"])
        if i == 0:
            self.logger.info("Successfully removed user: %s", username)
            return True

        elif i == 1:
            self.logger.info("User %s does not exist. Skipping.", username)
            child.kill(0)
            return True
        else:
            return False


class Nessuscli:
    """Main nessuscli class."""

    def __init__(self, cid=None):
        self.container_id = cid

        self.agent = Agent(cid=self.container_id)
        self.fetch = Fetch(cid=self.container_id)
        self.fix = Fix(cid=self.container_id)
        self.managed = Managed(cid=self.container_id)
        self.scan = Scan(cid=self.container_id)
        self.update = SoftwareUpdate(cid=self.container_id)
        self.user = User()
