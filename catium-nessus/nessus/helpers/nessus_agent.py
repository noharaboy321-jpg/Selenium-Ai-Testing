"""
Helpers related to Nessus agent update channel
:copyright: Tenable Network Security, 2020
:date: May 04, 2020
:author: @vsoni.ctr
"""
import json
import re
import subprocess

from requests import HTTPError
from waiting import wait
from waiting.exceptions import TimeoutExpired

from catium.lib.const import TIME_THIRTY_SECONDS, TIME_THIRTY_MINUTES, TIME_FIVE_MINUTES, TIME_THREE_SECONDS, \
    TIME_TWO_MINUTES, TIME_FIVE_SECONDS, WAIT_NORMAL, TIME_TEN_SECONDS, TIME_TEN_MINUTES
from catium.lib.log.log import create_logger
from catium.lib.ssh.ssh import SSH
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.agents import get_agent_id_from_list
from nessus.lib.config import NessusConfig
from nessus.lib.const import Nessus
from tenableio.lib.agent_shell import ProductConfigs, PlatformServiceCommands

log = create_logger()


def get_fix_parameter_in_nessus_agent(parameter_name: str, ssh: SSH, is_secure: bool = False) -> str:
    """
    This helper function will return fix parameter value
    :param str parameter_name: Name of fix parameter
    :param SSH ssh: Instance of SSH() class
    :param bool is_secure: True if secure parameter needs to be fetched else False
    :return: Fix parameter value if parameter loaded or present else ""
    :rtype: str
    """
    fix_command = get_fix_command(is_secure=is_secure)
    execute_command = "{} --get {}".format(fix_command, parameter_name)
    output = ssh.execute(command=execute_command)
    parameter_value = ""
    try:
        parameter_value = output[0].split("is ")[1].split("'")[1]
    except IndexError:
        log.warning("Not able to fetch value for fix parameter: {}".format(parameter_name))
    return parameter_value


def set_fix_parameter_in_nessus_agent(parameter_name: str, ssh: SSH, parameter_value: str,
                                      is_secure: bool = False) -> str:
    """
    This helper function will set the fix parameter to given value
    :param str parameter_name: Name of fix parameter
    :param SSH ssh: Instance of SSH() class
    :param str parameter_value: Value to be set for particular parameter
    :param is_secure: True if secure parameter needs to be set else False
    :return: output while setting the fix parameter
    :rtype: str
    """
    fix_command = get_fix_command(is_secure=is_secure)
    execute_command = "{} --set {}={}".format(fix_command, parameter_name, parameter_value)
    output = ssh.execute(command=execute_command)
    return output[0]


def get_fix_command(is_secure: bool = False) -> str:
    """
    This helper function will return fix command which can be applicable to both get and set parameter value.
    :param bool is_secure: True if secure parameter needs to be set or get else False
    :return: fix command
    :rtype: bool
    """
    return "/opt/nessus_agent/sbin/nessuscli fix --secure" if is_secure else "/opt/nessus_agent/sbin/nessuscli fix"


def get_nessus_agent_version(ssh: SSH) -> tuple:
    """
    This helper function will return the current agent version and build
    :param SSH ssh: Instance of SSH() class
    :return: Nessus Agent version and build
    :rtype: tuple
    """
    output = ssh.execute(command="/opt/nessus_agent/sbin/nessuscli -v")[0]
    nessus_agent_version = output[output.find(')') + 1:output.rfind('[')].strip(' ')
    nessus_agent_build = int(re.sub(r'.*[XR]20(\d+).*', r'\1', output))
    return str(nessus_agent_version), str(nessus_agent_build)


def get_expected_nessus_agent_build_and_version_for_given_channel(ssh: SSH, update_channel: str) -> tuple:
    """
    This helper returns agent version and build as per the selected agent update channel.
    :param SSH ssh: Instance of SSH() class.
    :param str update_channel: Software Update Channel (EA/GA/Stable)
    :return: Nessus agent version and build
    :rtype: tuple
    """
    output = ssh.execute(command="/opt/nessus_agent/sbin/nessuscli fix --secure --get ms_token | grep 'current value'")
    token_value = output[0].split('is')[1].split("'")[1]
    update_output = ssh.execute(
        'curl -s -H "MS-agent: token={}" "https://{}/remote/agent/updates?platform=LINUX&distro=es7-x86-64&'
        'channel={}" | python -m json.tool'.format(token_value, NessusConfig.CAT_TIO_URL, update_channel))
    log.info("Update output is : {}".format(update_output))
    update_dict = json.loads("".join(update_output))
    agent_version = update_dict['ui_version']
    agent_build = update_dict['ui_build']
    return str(agent_version), str(agent_build)


def trigger_agent_update_checks(ssh: SSH) -> None:
    """
    This method will set few fix parameters to "0" so that nessus agent will check updates in background
    :param ssh: Instance of SSH() class
    :return: None
    """
    fix_parameter_list = ["feed_auto_last", "last_core_download", "feed_ui_last"]
    for parameter in fix_parameter_list:
        set_fix_parameter_in_nessus_agent(is_secure=True, parameter_name=parameter, ssh=ssh, parameter_value="0")


def is_log_entries(agent_ip: str, file: str, message: str, no_of_entries: int,
                   timeout_seconds: int = TIME_TEN_MINUTES) -> bool:
    """
    Check if log retrieval notification is present on agent machine within five minutes of time
    :param str agent_ip: IP of linked agent
    :param str file: file path to tail logs
    :param str message: message in a log file to be verified
    :param int no_of_entries: number of last few entries to get from log
    :param int timeout_seconds: time out for waiter method
    :return: True if log retrieval notification present in agent machine's backend.log else False
    :rtype: bool
    """
    try:
        wait(lambda: [logrequest_data for logrequest_data in
                      get_latest_log_file_entries(agent_ip=agent_ip, no_of_entries=no_of_entries, file=file)
                      if message in logrequest_data], sleep_seconds=TIME_THREE_SECONDS, timeout_seconds=timeout_seconds,
             waiting_for="Log entry to be appeared on agent's page")
        return True
    except TimeoutExpired:
        return False


def get_latest_log_file_entries(agent_ip: str, no_of_entries: int, file: str) -> list:
    """
    Get last few log entries in backend.log
    :param str agent_ip: IP of linked agent
    :param int no_of_entries: number of last few entries to get from log
    :param str file: file path to tail logs
    :return: last few entries in backend.log
    :rtype: tuple
    """
    ssh = SSH(url_or_ip=agent_ip, port=22)
    log_file = file
    return ssh.execute("tail -{0} {1}".format(no_of_entries, log_file))


def wait_for_agent_status_to_get_matched_in_manager(
        nessus_api: NessusAPI, agent_name: str, status_to_be_matched: str = Nessus.Agents.AgentStatus.ONLINE,
        sleep_timeout: float = TIME_THIRTY_SECONDS, timeout: float = TIME_THIRTY_MINUTES) -> bool:
    """
    Helper method to wait for agent status to get matched in manager
    :param NessusAPI nessus_api: instance of NessusAPI
    :param str agent_name: name of agent
    :param str status_to_be_matched: status of the agent in NM, i.e. 'online', 'offline' etc.
    :param float timeout: timeout for wait
    :param float sleep_timeout: sleep_seconds for wait
    :return: True if status matched in timeout or else false
    :rtype: bool
    """
    agent_id = get_agent_id_from_list(api=nessus_api, agent_name=agent_name)[0]
    try:
        wait(lambda: nessus_api.agents.get_agent_details(agent_id=agent_id) and
                     nessus_api.agents.get_agent_details(agent_id=agent_id)['status'] == status_to_be_matched,
             timeout_seconds=timeout, sleep_seconds=sleep_timeout, waiting_for='Cluster agent to get online')
        return True
    except TimeoutExpired:
        log.info("agent-details:{}".format(nessus_api.agents.get_agent_details(agent_id=agent_id)))
        return False


def wait_for_specific_entry_in_log_file(
        ssh_instance: SSH, log_file_path: str, log_entry_to_be_verified: str,
        timeout: float = TIME_THIRTY_MINUTES, sleep_timeout: float = TIME_THIRTY_SECONDS) -> bool:
    """
    Helper method to wait for specific entry in a log file
    :param SSH ssh_instance: instance of SSH
    :param str log_file_path: path of the log file
    :param str log_entry_to_be_verified: log entry to be verified
    :param float timeout: timeout for wait
    :param float sleep_timeout: sleep_seconds for wait
    :return: True if status matched in timeout or else false
    :rtype: bool
    """
    try:
        wait(lambda: ssh_instance.execute("grep -E '{}' {}".format(log_entry_to_be_verified, log_file_path)),
             timeout_seconds=timeout, sleep_seconds=sleep_timeout,
             waiting_for='log entry: "{}" to be available in {}'.format(log_entry_to_be_verified, log_file_path))
        return True
    except TimeoutExpired:
        log.info("###### Agent Backend-logs #######: {}".format('\n'.join(ssh_instance.execute("tail -n 200 {}".format(
            log_file_path)))))
        return False


def wait_for_agent_to_get_online_in_cluster(nessus_api: NessusAPI, cluster_child_node_name: str, agent_name: str,
                                            timeout: float = TIME_THIRTY_MINUTES) -> bool:
    """
    Helper method to wait for agent to get online in manager in cluster
    :param NessusAPI nessus_api: instance of NessusAPI
    :param str cluster_child_node_name: Name of cluster child node
    :param str agent_name: Name of agent
    :param float timeout: timeout for wait
    :return: true if agent gets online in given timeout else false
    :rtype: bool
    """
    subprocess.check_output("docker exec {} supervisorctl restart nessusd".format(
        cluster_child_node_name).split(), stderr=subprocess.PIPE).decode('utf-8')

    def lookup_agent_on_master():
        try:
            return [agent for agent in nessus_api.agents.agents_list()['agents'] if agent['name'] == agent_name][0]
        except (TypeError, IndexError, KeyError, HTTPError):
            return False

    wait(lookup_agent_on_master, sleep_seconds=WAIT_NORMAL, timeout_seconds=TIME_TWO_MINUTES,
         waiting_for='Agent {} to appear on master'.format(agent_name))
    return wait_for_agent_status_to_get_matched_in_manager(nessus_api=nessus_api, timeout=timeout,
                                                           agent_name=agent_name)


def modify_remote_agent_settings(nessus_api: NessusAPI, agent_id: str, agent_settings_name: str,
                                 new_setting_value: str):
    """
    Helper method to modify Agent's remote settings via NM
    :param NessusAPI nessus_api: instance of NessusAPI
    :param str agent_id: id of agent
    :param str agent_settings_name: name of the agent settings
    :param str new_setting_value: new value for the agent settings
    :return:  None
    """
    nessus_api.agents.set_remote_settings(agent_id=agent_id, payload={"settings": [{"setting": agent_settings_name,
                                                                                    "value": new_setting_value}]})
    try:
        # Wait for the remote agent settings to be staged
        wait(lambda: [settings for settings in nessus_api.agents.get_remote_settings(agent_id=agent_id)[
            "settings"]["current"] if settings["status"] == "staged" and settings["value"] == new_setting_value and
                      settings["setting"] == agent_settings_name], sleep_seconds=TIME_FIVE_SECONDS,
             timeout_seconds=TIME_TWO_MINUTES, waiting_for="Agent settings to be staged")
    except (TimeoutError, TimeoutExpired):
        raise AssertionError("Either remote agent settings isn't staged or waited long to get staged")

    # Applying staged settings to get reflected on Agent side
    nessus_api.agents.apply_staged_remote_settings(agent_id=agent_id, payload={})

    try:
        # Wait for the remote agent settings to be applied
        wait(lambda: [settings for settings in nessus_api.agents.get_remote_settings(agent_id=agent_id)[
            "settings"]["current"] if settings["status"] == "applied" and settings["value"] == new_setting_value
                      and settings["setting"] == agent_settings_name], sleep_seconds=TIME_FIVE_SECONDS,
             timeout_seconds=TIME_TWO_MINUTES, waiting_for="Agent settings to be applied")
    except (TimeoutError, TimeoutExpired):
        raise AssertionError("Either remote agent settings isn't applied or waited long to get applied")


def agent_service_status(ssh_instance: SSH) -> str:
    """
    Agent service status returns the current state of service, running/ dead
    :param SSH ssh_instance: instance of SSH
    :return: str running, dead, or stopped
    """
    cmd_output = ssh_instance.execute("supervisorctl status nessusagent")
    try:
        status = ''
        for line in cmd_output:
            match_obj = re.findall('running|dead|stopped|is not running', line, re.IGNORECASE)
            if match_obj:
                status = match_obj[0].lower()
        return status
    except re.error:
        log.warning('Exception observed while checking Agent Service', exc_info=True)


def action_on_agent_service(ssh_instance: SSH, action: str = 'restart'):
    """
    This helper method will perform action on the agent service
    :param SSH ssh_instance: instance of SSH
    :param str action: name of the service to be performed on agent i.e stop, start and restart
    :return: None
    """
    ssh_instance.execute("supervisorctl {} nessusagent".format(action))

    if action in ['stop', 'restart']:
        try:
            wait(lambda: agent_service_status(ssh_instance=ssh_instance) in ['dead', 'stopped', 'is not running'],
                 timeout_seconds=TIME_TWO_MINUTES,
                 waiting_for='Agent service to {}'.format(action),
                 sleep_seconds=WAIT_NORMAL)
        except TimeoutExpired:
            log.info("Agent-status: {}".format(agent_service_status(ssh_instance=ssh_instance)))
            raise AssertionError('waited long for agent to get {}'.format(action))

    if action in ['start', 'restart']:
        try:
            wait(lambda: agent_service_status(ssh_instance=ssh_instance) == 'running',
                 timeout_seconds=TIME_TWO_MINUTES,
                 waiting_for='Agent service to {}'.format(action),
                 sleep_seconds=WAIT_NORMAL)
        except TimeoutExpired:
            log.info("Agent-status: {}".format(agent_service_status(ssh_instance=ssh_instance)))
            raise AssertionError('waited long for agent to get {}'.format(action))
    log.info('Done Agent service {}'.format(action))


def reinstall_nessus_agent_on_docker(ssh_instance: SSH,
                                     install_path: dict = Nessus.Agents.InstallAgentOnAWS.BUILD_PATH):
    """
    This helper method will uninstall current Nessus-Agent and re-install the new build given at install_path
    :param SSH ssh_instance: instance of SSH.
    :param str install_path: Nessus agent build path
    :return: None
    """
    installed_os = 'CentOS8'
    install_path = install_path.get(installed_os)
    action_on_agent_service(ssh_instance=ssh_instance, action='stop')
    installed_agent = ssh_instance.execute(Nessus.Agents.InstallAgentOnAWS.OS_COMMANDS.get(installed_os).get(
        'search_agent'))[0]
    assert installed_agent, "Agent is not installed yet."

    uninstall_agent = Nessus.Agents.InstallAgentOnAWS.OS_COMMANDS.get(installed_os).get("remove_agent") + \
                      installed_agent
    ssh_instance.execute(uninstall_agent)

    assert ssh_instance.execute(Nessus.Agents.InstallAgentOnAWS.OS_COMMANDS.get(installed_os).get('search_agent')) \
           == [], "Agent uninstall was not successful"

    ssh_instance.execute("rm -rf {}".format(ProductConfigs.NessusAgent.File.BASE_DIR))
    ssh_instance.execute("{} {}".format(
        Nessus.Agents.InstallAgentOnAWS.OS_COMMANDS.get(installed_os).get('install_agent'), install_path))

    assert ssh_instance.execute(Nessus.Agents.InstallAgentOnAWS.OS_COMMANDS.get(installed_os).get('search_agent')) \
           != [], "Nessus Agent is not installed yet."

    action_on_agent_service(ssh_instance=ssh_instance, action='start')

    assert agent_service_status(ssh_instance=ssh_instance) == "running", \
        "Nessus Agent is not started after installing fresh agent"

    wait(lambda: not any([message for message in Nessus.Agents.InstallAgentOnAWS.PREFERENCE_RETRIEVE_FAILURES
                          if message in get_fix_parameter_in_nessus_agent(ssh=ssh_instance,
                                                                          parameter_name="listen_port")]),
         sleep_seconds=TIME_TEN_SECONDS, timeout_seconds=TIME_FIVE_MINUTES,
         waiting_for="Nessus agent preferences to get ready.")


def enable_debug_logs_for_agent(ssh_instance: SSH) -> None:
    """
    Fixture to enable debug logs in agent.
    :return: None
    """
    set_fix_parameter_in_nessus_agent(ssh=ssh_instance, parameter_name='backend_log_level', parameter_value='debug')
    ssh_instance.execute(PlatformServiceCommands.NessusAgent.RELOAD)
