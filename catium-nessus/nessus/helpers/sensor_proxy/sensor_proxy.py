"""
Helper functions related to Sensor Proxy

:copyright: Tenable Network Security, 2019
:date: Nov 11, 2019
:last_modified: Jan 12, 2021
:author: @kpanchal
"""
import subprocess

import os
import random
import re

from catium.lib.log.log import create_logger
from catium.lib.util.util import random_name
from nessus.lib.const.constants import API
from tenableio.apiobjects.tenablecloud_api import TenableCloudAPI

log = create_logger()


def link_sensor_proxy_to_tenable_io(**kwargs) -> str:
    """
    Link Sensor Proxy to Tenable.io

    :param kwargs: Sensor proxy container details
    :return: output of docker command
    :rtype: str
    """
    output = ''
    sensor_proxy_container = kwargs['proxy_container']['Name'].replace('/', '')
    linking_key = kwargs['linking_key']
    cmnd = 'docker exec %s /opt/sensor_proxy/sbin/sidecar --cli --link --key=%s' % (sensor_proxy_container, linking_key)

    try:
        output = subprocess.check_output(cmnd.split(), stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        stdout = e.output.decode('utf-8')
        stderr = e.stderr.decode('utf-8')

        if stdout:
            log.error(stdout)
            output = stdout
        if stderr:
            log.error(stderr)

        pass

    log.info('Sensor proxy is successfully linked to Tenable.io.')
    output = output.decode('utf-8') if type(output) == bytes else output
    return output


def unlink_sensor_proxy_from_tenable_io(**kwargs) -> str:
    """
    Unlink Sensor Proxy from Tenable.io

    :param kwargs: Sensor proxy container details
    :return: output of docker command
    :rtype: str
    """
    output = ''
    sensor_proxy_container = kwargs['proxy_container']['Name'].replace('/', '')
    cmnd = 'docker exec %s /opt/sensor_proxy/sbin/sidecar --cli --unlink' % sensor_proxy_container

    try:
        output = subprocess.check_output(cmnd.split(), stderr=subprocess.PIPE)
        log.debug('Unlink Sensor proxy output :: :: {}'.format(output))
    except subprocess.CalledProcessError as e:
        stdout = e.output.decode('utf-8')
        stderr = e.stderr.decode('utf-8')

        if stdout:
            log.error(stdout)
        if stderr:
            log.error(stderr)

        pass

    log.info('Sensor proxy is successfully unlinked from Tenable.io.')
    output = output.decode('utf-8') if type(output) == bytes else output
    return output


def unlink_nessus_scanner_from_master(container_name: str) -> str:
    """
    Unlink Nessus scanner from master

    :param str container_name: Nessus scanner container name
    :return: output of docker command
    :rtype: str
    """
    output = ''
    cmnd = 'docker exec %s /opt/nessus/sbin/nessuscli managed unlink' % container_name

    try:
        output = subprocess.check_output(cmnd.split(), stderr=subprocess.PIPE)
        log.debug('Unlink Scanner output :: :: {}'.format(output))
    except subprocess.CalledProcessError as e:
        stdout = e.output.decode('utf-8')
        stderr = e.stderr.decode('utf-8')

        if stdout:
            log.error(stdout)
            output = stdout
        if stderr:
            log.error(stderr)

        pass

    log.info('Nessus scanner is successfully unlinked.')
    output = output.decode('utf-8') if type(output) == bytes else output
    return output


def unlink_agent_from_master(container_name: str) -> str:
    """
    Unlink Agent from master

    :param str container_name: Agent container name
    :return: output of docker command
    :rtype: str
    """
    output = ''
    cmnd = 'docker exec %s /opt/nessus_agent/sbin/nessuscli agent unlink' % container_name

    try:
        output = subprocess.check_output(cmnd.split(), stderr=subprocess.PIPE)
        log.debug('Unlink Agent output :: :: {}'.format(output))
    except subprocess.CalledProcessError as e:
        stdout = e.output.decode('utf-8')
        stderr = e.stderr.decode('utf-8')

        if stdout:
            log.error(stdout)
            output = stdout
        if stderr:
            log.error(stderr)

        pass

    log.info('Nessus Agent is successfully unlinked.')
    output = output.decode('utf-8') if type(output) == bytes else output
    return output


def read_log_file_from_docker(container_name: str, docker_file_path: str) -> str:
    """
    Read logs from given log file path in docker

    :param str container_name:  Sensor proxy container name
    :param str docker_file_path: Log file path in docker
    :return: Logs from log file
    :rtype: str
    """
    output = ''
    cmnd = 'docker exec %s tail -n 100 %s' % (container_name, docker_file_path)

    try:
        output = subprocess.check_output(cmnd.split(), stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        log.error("Error, code %s" % e.returncode)
        stdout = e.output.decode('utf-8')
        stderr = e.stderr.decode('utf-8')

        if stdout:
            log.error(stdout)
        if stderr:
            log.error(stderr)

        pass

    output = output.decode('utf-8') if type(output) == bytes else output
    return output


def get_log_message_from_log_files(search_text: str, log_file: str, full_logs: bool = False, **kwargs):
    """
    Returns success log message from given log file after getting linked

    :param str search_text: text that need to be search in log
    :param str log_file: access.log / sidecar.log file path
    :param bool full_logs: True if need full logs else False
    :return: success log message
    """
    logs = []
    sensor_proxy_container_name = kwargs['proxy_container']['Name']
    log_file_path = '/opt/sensor_proxy/{}'.format(log_file)
    log_file_name = log_file_path.split('/')[-1]

    log_entry = read_log_file_from_docker(container_name=sensor_proxy_container_name.replace('/', ''),
                                          docker_file_path=log_file_path)

    for log_line in log_entry.split('\n')[::-1]:
        if re.search(search_text, log_line):
            logs.append(log_line)

    if full_logs:
        log.debug('Log messages from {} file :: :: {}'.format(log_file_name, logs))
        return logs
    else:
        log.debug('Log message from {} file :: :: {}'.format(log_file_name, logs[0]))
        return logs[0]


def check_scanner_status(api: None, scanner_name: str) -> bool:
    """
    Returns true if scanner status is online else returns False

    :param api: Tenable cloud API instance
    :param str scanner_name: Name of the scanner
    :return: returns the scanner status
    :rtype: bool
    """
    if not api:
        api = TenableCloudAPI()
    scanner_list = api.scanners.get_list()

    for scanner in scanner_list['scanners']:
        if scanner['name'] == scanner_name:
            return scanner['status'] == 'on'

    return False


def check_agent_status(api: None, agent_name: str, scanner_id: str) -> bool:
    """
    Returns true if agent status is online else returns False

    :param api: Tenable cloud API instance
    :param str agent_name: Name of the agent
    :param str scanner_id: Id of local scanner
    :return: returns the agent status
    :rtype: bool
    """
    if not api:
        api = TenableCloudAPI()
    agent_list = api.agents.get_agents(scanner_id=scanner_id)

    for agent in agent_list['agents']:
        if agent['name'] == agent_name:
            log.info("Agent status :: :: {}".format(agent['status']))
            return agent['status'] == 'on'

    return False


def get_process_id(pid_file: str, container_name: str) -> str:
    """
    Returns process id from given .pid file path

    :param str pid_file: pid file path
    :param str container_name: Sensor proxy container name
    :return: process id of given pid file
    :rtype: str
    """
    pid_file_path = '/opt/sensor_proxy/{}'.format(pid_file)
    pid_file_name = pid_file_path.split('/')[-1]

    process_id = read_log_file_from_docker(container_name=container_name, docker_file_path=pid_file_path)
    log.debug('Logs from {} :: :: {}'.format(pid_file_name, process_id))

    return process_id.rstrip('\n')


def get_socket_count(pid: str, container_name: str) -> int:
    """
    Returns count of sockets

    :param pid: process id of running Sensor Proxy
    :param str container_name: Sensor proxy container name
    :return: socket count
    :rtype: int
    """
    output = ''
    directory = '/proc/{}/fd/'.format(pid)
    cmnd = 'docker exec %s ls -rt1 %s' % (container_name, directory)

    try:
        output = subprocess.check_output(cmnd.split(), stderr=subprocess.PIPE)
        log.debug('File count :: :: {}'.format(output))
    except subprocess.CalledProcessError as e:
        log.error("Error, code %s" % e.returncode)
        stdout = e.output.decode('utf-8')
        stderr = e.stderr.decode('utf-8')

        if stdout:
            log.error(stdout)
        if stderr:
            log.error(stderr)

        pass

    return len(list(filter(None, output.decode('utf-8').split('\n'))))


def reload_sensor_proxy(container_name: str, process_id: str) -> None:
    """
    Reload/Restart sensor proxy

    :param str container_name: Sensor proxy container name
    :param str process_id: process id which need to be restart
    :return: None
    """
    cmnd = "docker exec %s kill -9 %s" % (container_name, process_id)

    try:
        subprocess.check_output(cmnd.split(), stderr=subprocess.PIPE)
        subprocess.call(['sleep', '30'])
    except subprocess.CalledProcessError as e:
        log.error("Error, code %s" % e.returncode)
        stdout = e.output.decode('utf-8')
        stderr = e.stderr.decode('utf-8')

        if stdout:
            log.error(stdout)
        if stderr:
            log.error(stderr)

        pass


def relink_agent_to_master(agent_name: str, host: str, port: int) -> str:
    """
    Relink agent to master

    :param str agent_name: Agent name which need to be link
    :param str host: Host ip from where agent need to be link
    :param int port: port
    :return: output log of docker command
    :rtype: str
    """
    output = ''
    cmnd = 'docker exec %s /opt/nessus_agent/sbin/nessuscli agent relink --name=%s' % (agent_name, agent_name) + \
           ' --host=%s --port=%d' % (host, port)

    try:
        output = subprocess.check_output(cmnd.split(), stderr=subprocess.PIPE)
        log.debug('Output after relink agent to SP :: :: {}'.format(output))
    except subprocess.CalledProcessError as e:
        log.error("Error, code %s" % e.returncode)
        stdout = e.output.decode('utf-8')
        stderr = e.stderr.decode('utf-8')

        if stdout:
            log.error(stdout)
        if stderr:
            log.error(stderr)

        pass

    output = output.decode('utf-8') if type(output) == bytes else output
    return output


def modify_json_file_value(actual_value: str, expected_value: str, **kwargs) -> None:
    """
    Modifies given value from sidecar.json file in docker container

    :param str actual_value: value which need to be modify
    :param str expected_value: value which need to be set
    :param kwargs: Sensor proxy container details
    :return: None
    """
    sensor_proxy_container = kwargs['proxy_container']['Name'].replace('/', '')
    cmnd = 'docker exec %s sed -ie s/%s/%s/ /opt/sensor_proxy/config/sidecar.json' % \
           (sensor_proxy_container, actual_value, expected_value)

    try:
        output = subprocess.check_output(cmnd.split(), stderr=subprocess.PIPE)
        log.debug('Response after modifying json file value :: :: {}'.format(output))
    except subprocess.CalledProcessError as e:
        stdout = e.output.decode('utf-8')
        stderr = e.stderr.decode('utf-8')

        if stdout:
            log.error(stdout)
        if stderr:
            log.error(stderr)

        pass

    log.info('Given value has been updated successfully from {} to {}.'.format(actual_value, expected_value))


def take_up_down_network_in_docker_container(network: str, container_name: str, take_up: bool = False) -> None:
    """
    Takes up or down network in docker container

    :param str network: docker network id/name
    :param str container_name: docker container name
    :param bool take_up: True if need to up network else False
    :return: None
    """
    network_operation = 'disconnect -f'

    if take_up:
        network_operation = 'connect'

    cmnd = 'docker network %s %s %s' % (network_operation, network, container_name)

    try:
        output = subprocess.check_output(cmnd.split(), stderr=subprocess.PIPE)
        log.debug('Output after taking up/down the network :: :: {}'.format(output))
    except subprocess.CalledProcessError as e:
        log.error("Error, code %s" % e.returncode)
        stdout = e.output.decode('utf-8')
        stderr = e.stderr.decode('utf-8')

        if stdout:
            log.error(stdout)
        if stderr:
            log.error(stderr)

        pass


def copy_files_between_containers(source_container: str, source_file_path: str, dest_container: str,
                                  dest_file_path: str, file_name: str) -> None:
    """
    Copies files from one container to another container in docker

    :param str source_container: source container name 
    :param str source_file_path: file path from Source container
    :param str dest_container: destination container name
    :param str dest_file_path: file path from destination container
    :param str file_name: file name which need to be copy
    :return: None
    """
    for cmnd in ['docker cp %s:%s /tmp/' % (source_container, source_file_path),
                 'docker cp /tmp/%s %s:%s' % (file_name, dest_container, dest_file_path)]:
        try:
            output = subprocess.check_output(cmnd.split(), stderr=subprocess.PIPE)
            log.debug('Output after copying files from one container to another container :: :: {}'.format(output))
        except subprocess.CalledProcessError as e:
            log.error("Error, code %s" % e.returncode)
            stdout = e.output.decode('utf-8')
            stderr = e.stderr.decode('utf-8')

            if stdout:
                log.error(stdout)
            if stderr:
                log.error(stderr)

            pass


def delete_file_from_container(container_name: str, file_path: str):
    """
    Deletes given file from docker container

    :param str container_name: docker container name
    :param str file_path: file path which needs to be delete
    :return: None
    """
    cmnd = 'docker exec %s rm -rf %s' % (container_name, file_path)

    try:
        output = subprocess.check_output(cmnd.split(), stderr=subprocess.PIPE)
        log.debug('Output after deleting file from container :: :: {}'.format(output))
    except subprocess.CalledProcessError as e:
        log.error("Error, code %s" % e.returncode)
        stdout = e.output.decode('utf-8')
        stderr = e.stderr.decode('utf-8')

        if stdout:
            log.error(stdout)
        if stderr:
            log.error(stderr)

        pass


def link_sensors_to_sensor_proxy(container: str, host: str, port: int, linking_key: str, sensor_type: str) -> str:
    """
    Links Sensors (Scanner/Agent) to Sensor Proxy

    :param str container: docker container name
    :param str host: Host ip of Sensors (Scanner/Agent)
    :param int port: port
    :param str linking_key: t.io linking key
    :param str sensor_type: Sensor type (Scanner/Agent)
    :return: docker command output
    :rtype: str
    """
    output = ''
    dir_type = 'nessus'

    if sensor_type == API.Settings.SensorProxy.SCANNER:
        cli_cmnd = 'managed'
    else:
        cli_cmnd = 'agent'
        dir_type = '_'.join([dir_type, cli_cmnd])

    cmnd = 'docker exec %s /opt/%s/sbin/nessuscli %s link --name=%s' % (container, dir_type, cli_cmnd, container) \
           + ' --host=%s --port=%d --key=%s' % (host, port, linking_key)

    try:
        log.debug("Executing: %s" % cmnd)
        output = subprocess.check_output(cmnd.split(), stderr=subprocess.PIPE)
        log.info("'{}' linked successfully to Sensor Proxy.".format(sensor_type.capitalize()))
    except subprocess.CalledProcessError as e:
        log.error("Error, code %s" % e.returncode)
        stdout = e.output.decode('utf-8')
        stderr = e.stderr.decode('utf-8')

        if stdout:
            log.error(stdout)
            output = stdout
            return output
        if stderr:
            log.error(stderr)

        pass

    output = output.decode('utf-8') if type(output) == bytes else output
    return output


def deploy_real_agent(docker_network, expose_port: bool = False):
    """ This helper function will deploy real agent"""
    docker_registry = os.getenv('DOCKER_REGISTRY', 'docker-registry.cloud.aws.tenablesecurity.com:8888')
    agent_container = docker_registry + '/services/nessus-centos8-agent:release-next'
    agent_name = random_name('agent-')
    agent_port = random.randint(31000, 32000)

    if expose_port:
        cmd = 'docker run -d -p %s:22 --rm --name %s --network %s %s' % (agent_port, agent_name, docker_network,
                                                                         agent_container)
    else:
        cmd = 'docker run -d --rm --name %s --network %s %s' % (agent_name, docker_network, agent_container)

    log.debug("Executing: %s" % cmd)
    subprocess.run(cmd.split())

    return {'agent_name': agent_name, 'agent_port': agent_port}


def set_fix_parameter_in_nessus_or_agent_container(container_name: str, sensor_type: str, parameter_name: str,
                                                   parameter_value: str, is_secure: bool = False) -> str:
    """
    Sets the fix parameter to given value

    :param str container_name: Agent container name
    :param str sensor_type: type of sensor (like Nessus or Agent)
    :param bool is_secure: True is secure or False
    :param str parameter_name: Name of parameter
    :param str parameter_value: value of parameter to set
    :return: output of docker command
    :rtype: str
    """
    output = ''
    args = ['fix']
    dir_type = 'nessus'

    if sensor_type == API.Settings.SensorProxy.AGENT:
        cli_cmnd = 'agent'
        dir_type = '_'.join([dir_type, cli_cmnd])

    if is_secure:
        args.append('--secure')

    args.append('--set')
    args.append('{}={}'.format(parameter_name, parameter_value))
    command = ' '.join([arg for arg in args])

    cmnd = 'docker exec %s /opt/%s/sbin/nessuscli %s' % (container_name, dir_type, command)
    log.debug("Executing :: {}".format(cmnd))

    try:
        subprocess.call(['sleep', '30'])
        output = subprocess.check_output(cmnd.split(), stderr=subprocess.PIPE)
        log.debug('Set Agent preference output :: :: {}'.format(output))
    except subprocess.CalledProcessError as e:
        stdout = e.output.decode('utf-8')
        stderr = e.stderr.decode('utf-8')

        if stdout:
            log.error(stdout)
            output = stdout
        if stderr:
            log.error(stderr)

        pass

    output = output.decode('utf-8') if type(output) == bytes else output
    return output


def deploy_nessus_scanner(docker_network, expose_port: bool = False):
    """ This helper function will deploy nessus scanner """
    docker_registry = os.getenv('DOCKER_REGISTRY', 'docker-registry.cloud.aws.tenablesecurity.com:8888')
    scanner_container = docker_registry + '/services/nessus-centos7:release-next'

    scanner_name = random_name('scanner-')
    scanner_port = random.randint(32000, 33000)

    if expose_port:
        cmd = 'docker run -d -p %s:22 --rm --name %s --network %s %s' % (scanner_port, scanner_name, docker_network,
                                                                         scanner_container)
    else:
        cmd = 'docker run -d --rm --name %s --network %s %s' % (scanner_name, docker_network, scanner_container)

    log.debug("Executing: %s" % cmd)
    subprocess.run(cmd.split())

    return {'scanner_name': scanner_name, 'scanner_port': scanner_port}


def verify_log_msg_from_backend_logs(scanner_name: str, log_message: str, file_path: str) -> bool:
    """
    Verifies that given log message is present in backend.log file

    :param str scanner_name: scanner name
    :param str log_message: list of logs to be verified
    :param str file_path: file path
    :return: True or False
    :rtype: bool
    """
    log_entries = read_log_file_from_docker(container_name=scanner_name, docker_file_path=file_path)

    for log_line in log_entries.split('\n')[::-1]:
        if log_message in log_line:
            log.debug("Got '{}' log message in '{}' log entry.".format(log_message, log_line))
            return True
