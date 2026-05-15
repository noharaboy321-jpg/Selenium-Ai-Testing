"""
:copyright: Tenable Network Security, 2017
:date: Aug 30 2017
:author: @jmcneil
"""

import docker

from catium.lib.log import create_logger
from nessus.lib.config import docker_config


class Session(object):
    """Provides a session to a Docker host."""

    def __init__(self, base_url="unix://var/run/docker.sock", use_env=False, version: str='1.26', **kwargs):
        """
        Initialize the Docker API session and configure instance.

        Proving the use_env flag during instantiation will read the these environment variables from the env that the
        script is running in. The environment variables used are the same as those used by the Docker
        command-line client.

        .. code-block:: bash

            DOCKER_HOST - The URL to the Docker host.
            DOCKER_TLS_VERIFY - Verify the host against a CA certificate.
            DOCKER_CERT_PATH - A path to a directory containing TLS certs for use when connecting to the Docker host.

        :ivar str base_url: Unix socket or tcp:// pointing at the Docker API to use.
        :ivar bool use_env: Use the environment to configure the docker client. Default: False
        :ivar bool verify_ssl: Flag to enable/disable verification of SSL certificate. Default: False
        """

        if use_env:
            self.client = docker.from_env(version=version)
        else:
            self.client = docker.DockerClient(version=version, base_url=base_url)

        self.api_client = docker.APIClient(base_url=base_url, version=version)

        # Scanner Configs
        self.scanner_user = kwargs.get('scanner_user', docker_config.SCANNER_CONFIG['admin_user'])
        self.scanner_pass = kwargs.get('scanner_pass', docker_config.SCANNER_CONFIG['admin_pass'])
        self.scanner_host = kwargs.get('scanner_host', docker_config.SCANNER_CONFIG['host'])
        self.scanner_port = kwargs.get('scanner_port', docker_config.SCANNER_CONFIG['port'])
        self.scanner_url = kwargs.get('scanner_url', docker_config.SCANNER_URL)

        # Controller Configs
        self.agent_groups = kwargs.get('agent_groups', docker_config.AGENT_CONFIG['groups'])

        # Nessus Manager
        self.controller_user = kwargs.get('controller_user', docker_config.CONTROLLER_CONFIG['admin_user'])
        self.controller_pass = kwargs.get('controller_pass', docker_config.CONTROLLER_CONFIG['admin_pass'])
        self.controller_host = kwargs.get('controller_host', docker_config.CONTROLLER_CONFIG['host'])
        self.controller_port = kwargs.get('controller_port', docker_config.CONTROLLER_CONFIG['port'])
        self.controller_url = kwargs.get('controller_url', docker_config.CONTROLLER_URL)

        # Tenable.io

        self.tenableio_sysadmin_user = kwargs.get('tenableio_sysadmin_user',
                                                  docker_config.TENABLEIO_CONFIG["sysadmin_user"])
        self.tenableio_sysadmin_pass = kwargs.get('tenableio_sysadmin_pass',
                                                  docker_config.TENABLEIO_CONFIG["sysadmin_pass"])
        self.tenableio_container_user = kwargs.get('tenableio_container_user',
                                                   docker_config.TENABLEIO_CONFIG["container_user"])
        self.tenableio_container_pass = kwargs.get('tenableio_container_pass',
                                                   docker_config.TENABLEIO_CONFIG["container_pass"])
        self.tenableio_host = kwargs.get('tenableio_host',
                                         docker_config.TENABLEIO_CONFIG["host"])
        self.tenableio_port = kwargs.get('tenableio_port',
                                         docker_config.TENABLEIO_CONFIG["port"])
        self.tenableio_url = kwargs.get('tenableio_url',
                                        docker_config.TENABLEIO_URL)

        # Tenable.io Dev
        self.tenableio_dev_sysadmin_user = kwargs.get('tenableio_dev_sysadmin_user',
                                                      docker_config.TENABLEIO_DEV_CONFIG["sysadmin_user"])
        self.tenableio_dev_sysadmin_pass = kwargs.get('tenableio_dev_sysadmin_pass',
                                                      docker_config.TENABLEIO_DEV_CONFIG["sysadmin_pass"])
        self.tenableio_dev_container_user = kwargs.get('tenableio_dev_container_user',
                                                       docker_config.TENABLEIO_DEV_CONFIG["container_user"])
        self.tenableio_dev_container_pass = kwargs.get('tenableio_dev_container_pass',
                                                       docker_config.TENABLEIO_DEV_CONFIG["container_pass"])
        self.tenableio_dev_host = kwargs.get('tenableio_dev_host',
                                             docker_config.TENABLEIO_DEV_CONFIG["host"])
        self.tenableio_dev_port = kwargs.get('tenableio_dev_port',
                                             docker_config.TENABLEIO_DEV_CONFIG["port"])
        self.tenableio_dev_url = kwargs.get('tenableio_dev_url',
                                            docker_config.TENABLEIO_DEV_URL)

        # Onprem
        self.onprem_sysadmin_user = kwargs.get('onprem_sysadmin_user',
                                               docker_config.ONPREM_CONFIG["sysadmin_user"])
        self.onprem_sysadmin_pass = kwargs.get('onprem_sysadmin_pass',
                                               docker_config.ONPREM_CONFIG["sysadmin_pass"])
        self.onprem_container_user = kwargs.get('onprem_container_user',
                                                docker_config.ONPREM_CONFIG["container_user"])
        self.onprem_container_pass = kwargs.get('onprem_container_pass',
                                                docker_config.ONPREM_CONFIG["container_pass"])
        self.onprem_host = kwargs.get('onprem_host', docker_config.ONPREM_CONFIG["host"])
        self.onprem_port = kwargs.get('onprem_port', docker_config.ONPREM_CONFIG["port"])
        self.onprem_url = kwargs.get('onprem_url', docker_config.ONPREM_URL)

        # Docker Host
        self.docker_host = kwargs.get('docker_host', docker_config.DOCKER_HOST)
        self.docker_timeout = kwargs.get('docker_timeout', docker_config.DOCKER_TIMEOUT)
        self.verify_ssl = kwargs.get('verify_ssl', docker_config.VERIFY_SSL)

        self.proxy_host = kwargs.get('proxy_host', docker_config.PROXY_SERVER_CONFIG["host"])
        self.proxy_port = kwargs.get('proxy_port', docker_config.PROXY_SERVER_CONFIG["port"])
        self.proxy_user = kwargs.get('proxy_user', docker_config.PROXY_SERVER_CONFIG["username"])
        self.proxy_pass = kwargs.get('proxy_pass', docker_config.PROXY_SERVER_CONFIG["password"])

        # Plugin servers.
        self.production_plugin_server = kwargs.get('production_plugin_server',
                                                   docker_config.PRODUCTION_PLUGIN_SERVER)
        self.production_plugin_server_api = kwargs.get('production_plugin_server_api',
                                                       docker_config.PRODUCTION_PLUGIN_SERVER_API)
        self.staging_plugin_server = kwargs.get('staging_plugin_server',
                                                docker_config.STAGING_PLUGIN_SERVER)
        self.staging_plugin_server_api = kwargs.get('staging_plugin_server_api',
                                                    docker_config.STAGING_PLUGIN_SERVER_API)

        self.logger = create_logger()

    def info(self):
        """
        Get information about the Docker engine and API.

        :returns: Docker relatd info in a dictionary. None if failed.
        :rtype: dict

        .. code-block:: python

           In [11]: docker_nessus.info()
           Out[11]:
            {'Architecture': 'x86_64',
             'BridgeNfIp6tables': True,
             'BridgeNfIptables': True,
             'CPUSet': True,
             'CPUShares': True,
             'CgroupDriver': 'cgroupfs',
             'ClusterAdvertise': '',
             'ClusterStore': '',
             'ContainerdCommit': {'Expected': '9048e5e50717ea4497b757314bad98ea3763c145',
              'ID': '9048e5e50717ea4497b757314bad98ea3763c145'},
             'Containers': 2,
             'ContainersPaused': 0,
             'ContainersRunning': 2,
             'ContainersStopped': 0,
             'CpuCfsPeriod': True,
             'CpuCfsQuota': True,
             'Debug': False,
             'DefaultRuntime': 'runc',
             'DockerRootDir': '/var/lib/docker',
             'Driver': 'aufs',
             'DriverStatus': [['Root Dir', '/var/lib/docker/aufs'],
              ['Backing Filesystem', 'extfs'],
              ['Dirs', '108'],
              ['Dirperm1 Supported', 'true']],
             'ExperimentalBuild': False,
             'HttpProxy': '',
             'HttpsProxy': '',
             'ID': 'R7XJ:7LGY:AA57:ADPW:ACHK:AV3M:PQX6:6SP7:SCQ2:ERBI:YPJH:2HCN',
             'IPv4Forwarding': True,
             'Images': 56,
             'IndexServerAddress': 'https://index.docker.io/v1/',
             'InitBinary': 'docker-init',
             'InitCommit': {'Expected': '949e6fa', 'ID': '949e6fa'},
             'Isolation': '',
             'KernelMemory': True,
             'KernelVersion': '3.16.0-30-generic',
             'Labels': None,
             'LiveRestoreEnabled': False,
             'LoggingDriver': 'json-file',
             'MemTotal': 2098765824,
             'MemoryLimit': True,
             'NCPU': 2,
             'NEventsListener': 0,
             'NFd': 28,
             'NGoroutines': 31,
             'Name': 'ubuntu14-local-dev',
             'NoProxy': '',
             'OSType': 'linux',
             'OomKillDisable': True,
             'OperatingSystem': 'Ubuntu 14.04.5 LTS',
             'Plugins': {'Authorization': [],
              'Network': ['bridge', 'host', 'macvlan', 'null', 'overlay'],
              'Volume': ['local']},
             'RegistryConfig': {'IndexConfigs': {'docker.io': {'Mirrors': [],
                'Name': 'docker.io',
                'Official': True,
                'Secure': True}},
              'InsecureRegistryCIDRs': ['127.0.0.0/8'],
              'Mirrors': []},
             'RuncCommit': {'Expected': '9c2d8d184e5da67c95d601382adf14862e4f2228',
              'ID': '9c2d8d184e5da67c95d601382adf14862e4f2228'},
             'Runtimes': {'runc': {'path': 'docker-runc'}},
             'SecurityOptions': ['name=apparmor'],
             'ServerVersion': '17.05.0-ce',
             'SwapLimit': False,
             'Swarm': {'ControlAvailable': False,
               'Error': '',
               'LocalNodeState': 'inactive',
               'NodeAddr': '',
               'NodeID': '',
               'RemoteManagers': None},
             'SystemStatus': None,
             'SystemTime': '2017-07-02T12:38:18.443713025-03:00'}
        """
        info = self.client.info()
        return info if info else None

    def login(self, registry, username, password, email):
        """
        Login into a Docker registry.

        :param str registry: IP or DNS of docker registry.
        :param str username: username for authentication.
        :param str password: password for authentication.
        :param str email: email address related to account.
        :returns: Dictionary containing Status and Identity token. False if failed.
        :rtype: dict

        .. code-block:: python
            In [14]: docker_nessus.login("hub.docker.com", "myuser@gmail.com", "mypassword", "myemail@gmail.com")
            Out[14]: {'IdentityToken': '', 'Status': 'Login Succeeded'}
        """
        logged_in = self.client.login(registry=registry, username=username, password=password, email=email)
        logged_in_2 = self.api_client.login(registry=registry, username=username, password=password, email=email)
        return logged_in if logged_in and logged_in_2 else False

    @staticmethod
    def merge_dictionaries(*dict_args):
        """
         Takes any number of dicts, shallow copies and merges into a new dict.
         Precedence goes to key value pairs in latter dicts. Python 2.7/3.4+ compliant.

        :param dict dict_args: Any number of dictionaries to merge together.
        :returns: A dictionary of all provided dicts.
        :rtype: dict

        .. code-block:: python
            extra_configuration = docker_nessus.merge_dictionaries(dictionary1, dictionary2, dictionary3)
        """

        new_dict = {}
        for dictionary in dict_args:
            new_dict.update(dictionary)
        return new_dict

    def search(self, search_term):
        """
        Search the docker hub for available images. Only supports docker hub at this time.

        :param str search_term: term to use during search.
        :returns: A list of dictionaries containing images that match the search. None if failed.
        :rtype: list of dicts

        .. code-block:: python
            results = dockernessus.search("graphite")
            for result in results:
                print(result["name"])

            {'description': 'Ready to use Graphite stack (Graphite-web + Carbon + Whisper)',
             'is_automated': True,
             'is_official': False,
             'name': 'creativearea/graphite',
             'star_count': 1},
        """

        results = self.api_client.search(search_term)
        return results if results else None

    def version(self):
        """
        Get version information about the Docker server and API.

        .. code-block:: python

            In [10]: docker_nessus.version()
            Out[10]:
            {'ApiVersion': '1.29',
             'Arch': 'amd64',
             'BuildTime': '2017-05-04T22:06:06.693142599+00:00',
             'GitCommit': '89658be',
             'GoVersion': 'go1.7.5',
             'KernelVersion': '3.16.0-30-generic',
             'MinAPIVersion': '1.12',
             'Os': 'linux',
             'Version': '17.05.0-ce'}

        :returns: A dict containing version and other information related to the Docker API. None if failed.
        :rtype: dict
        """
        info = self.client.version(api_version=True)
        return info if info else None
