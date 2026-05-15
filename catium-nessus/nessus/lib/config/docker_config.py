"""
Configurations for Docker related tests and libraries.

:copyright: Tenable Network Security, 2017
:date: Aug 30 2017
:author: @jmcneil
"""

import os

from catium.helpers.site_configuration_fetcher import get_site_environ
from catium.lib.config import Config
from nessus.lib.config import NessusConfig


def getvar(name, default=None):
    value_type = str if default is None else type(default)
    return get_site_environ(name, config_key=name, value_type=value_type, default=default)

# Docker Configurations:

# DEBUG. Enable framework debug mode, very verbose.
DEBUG = getvar("DOCKER_NESSUS_DEBUG", False)

# DOCKER_CLEAN. When set to 'yes', un-linking of agents/secondaries and general cleanup tasks
# occur automatically. You may want to turn this off when troubleshooting a failing test
# to gain access to the container after the test fails.
DOCKER_CLEAN = getvar("DOCKER_CLEAN", "yes")

# DOCKER_TAG. This is the tag of the docker image you want to test.
# Ex: docker-registry.lab.tenablesecurity.com/services/nessus-centos7:6.8.1
# "6.8.1" is the DOCKER_TAG above and is usually a version or git branch name.
DOCKER_TAG = getvar("DOCKER_TAG", "release")
if getvar("NESSUS_BRANCH"):
    DOCKER_TAG = getvar("NESSUS_BRANCH")

# DOCKER_HOST. The IP/host name of the Docker host.
DOCKER_HOST = getvar("DOCKER_HOST", "127.0.0.1")

# DOCKER_TIMEOUT. The HTTP timeout value.
DOCKER_TIMEOUT = getvar("DOCKER_TIMEOUT", 60)

# LAB_DOCKER_REGISTRY. The DNS or IP of the Docker registry to use, and credentials
LAB_DOCKER_REGISTRY = getvar("DOCKER_REGISTRY", "docker-registry.lab.tenablesecurity.com")
DOCKER_REGISTRY_USERNAME = getvar("DOCKER_REGISTRY_USERNAME")
DOCKER_REGISTRY_PASSWORD = getvar("DOCKER_REGISTRY_PASSWORD")
DOCKER_REGISTRY_EMAIL = getvar("DOCKER_REGISTRY_EMAIL")

# NESSUS_TYPE. The type/flavor of Nessus. Supports: home, pro, manager and sc-managed.
NESSUS_TYPE = getvar("DOCKER_NESSUS_TYPE", "pro")

if getvar("NESSUS_VERSION"):
    NESSUS_TYPE = getvar("NESSUS_VERSION")

    if NESSUS_TYPE == 'Nessus Manager':
        NESSUS_TYPE = 'manager'
    elif NESSUS_TYPE == 'Nessus Professional':
        NESSUS_TYPE = 'pro'
    elif NESSUS_TYPE == 'Nessus Home':
        NESSUS_TYPE = 'home'
    elif NESSUS_TYPE == 'Nessus Security Center Managed':
        NESSUS_TYPE = 'sc-managed'

# UPGRADE_BUILD_VERSION. The version upgrade tests for scanners and agents should be performed with.
UPGRADE_BUILD_VERSION = getvar("DOCKER_UPGRADE_BUILD_VERSION ", "6.10.9")

# VERIFY_SSL. The DNS or IP of the Docker registry to use.
VERIFY_SSL = getvar("DOCKER_VERIFY_SSL", False)

# Docker host to use for scanners
DOCKER_SCANNER_HOST = getvar("DOCKER_SCANNER_HOST", "unix://var/run/docker.sock")

# Docker host to use for agents
DOCKER_AGENT_HOSTS = []
for host in getvar("DOCKER_SCANNER_HOST", "unix://var/run/docker.sock").split(','):
    DOCKER_AGENT_HOSTS.append(host)

# Agent Configurations:
AGENT_CONFIG = dict(
    expose_port=getvar("DOCKER_AGENT_EXPOSE_PORT", ""),
    groups=getvar("DOCKER_AGENT_GROUPS", "Monitor"),
    install_dir=getvar("DOCKER_AGENT_INSTALL_DIR", "/opt/nessus_agent/"),
    upgrade_build=getvar("DOCKER_AGENT_UPGRADE_BUILD", UPGRADE_BUILD_VERSION)
)
AGENT_DB = "{0}{1}".format(AGENT_CONFIG["install_dir"], getvar("DOCKER_AGENT_DB", "var/nessus/agent.db"))
AGENT_PLUGIN_DIR = "{0}{1}".format(AGENT_CONFIG["install_dir"],
                                   getvar("DOCKER_AGENT_PLUGIN_DIR", "lib/nessus/plugins/"))

# AGENT_TEST_IMAGES.
# Default set of images to use during agent test cases. Tuple containing (["friendly_name", "docker_image_name"]).
AGENT_TEST_IMAGES = (
    ["CentOS 5 Agent", "{0}/services/nessus-centos5-agent".format(LAB_DOCKER_REGISTRY)],
    ["CentOS 6 Agent", "{0}/services/nessus-centos6-agent".format(LAB_DOCKER_REGISTRY)],
    ["CentOS 7 Agent", "{0}/services/nessus-centos7-agent".format(LAB_DOCKER_REGISTRY)],
    ["Debian 7 Agent", "{0}/services/nessus-debian7-agent".format(LAB_DOCKER_REGISTRY)],
    ["Debian 9 Agent", "{0}/services/nessus-debian9-agent".format(LAB_DOCKER_REGISTRY)],
    ["Fedora 23 Agent", "{0}/services/nessus-fedora23-agent".format(LAB_DOCKER_REGISTRY)],
    ["Fedora 25 Agent", "{0}/services/nessus-fedora25-agent".format(LAB_DOCKER_REGISTRY)],
    ["OpenSuSE 12 Agent", "{0}/services/nessus-opensuse12-agent".format(LAB_DOCKER_REGISTRY)],
    ["OpenSuSE 13 Agent", "{0}/services/nessus-opensuse13-agent".format(LAB_DOCKER_REGISTRY)],
    ["Ubuntu 14 Agent", "{0}/services/nessus-ubuntu14-agent".format(LAB_DOCKER_REGISTRY)],
    ["Ubuntu 16 Agent", "{0}/services/nessus-ubuntu16-agent".format(LAB_DOCKER_REGISTRY)],
    ["Ubuntu 16.10 Agent", "{0}/services/nessus-ubuntu1610-agent".format(LAB_DOCKER_REGISTRY)],
    ["Ubuntu 17.04 Agent", "{0}/services/nessus-ubuntu1704-agent".format(LAB_DOCKER_REGISTRY)],
)

# Nessus Controller Configurations for Agents:
#
CONTROLLER_CONFIG = dict(
    host=getvar("DOCKER_CONTROLLER_IP", "172.26.19.45"),
    port=getvar("DOCKER_CONTROLLER_PORT", "8834"),
    key=getvar("DOCKER_CONTROLLER_KEY", ""),
    admin_user=getvar("DOCKER_CONTROLLER_ADMIN_USER", "admin"),
    admin_pass=getvar("DOCKER_CONTROLLER_ADMIN_PASS", "admin"),
    expose_port=getvar("DOCKER_CONTROLLER_EXPOSE", ""),
    install_dir=getvar("DOCKER_CONTROLLER_INSTALL_DIR", "/opt/nessus/"),
    username=getvar("DOCKER_CONTROLLER_USER", "stduser"),
    password=getvar("DOCKER_CONTROLLER_PASS", "stdpass"),
    upgrade_build=getvar("CONTROLLER_UPGRADE_VERSION", UPGRADE_BUILD_VERSION),
)
CONTROLLER_URL = "https://{0}:{1}".format(CONTROLLER_CONFIG["host"], CONTROLLER_CONFIG["port"])
CONTROLLER_PLUGIN_DIR = "{0}{1}".format(CONTROLLER_CONFIG["install_dir"],
                                        getvar("DOCKER_CONTROLLER_PLUGIN_DIR", "lib/nessus/plugins/"))
CONTROLLER_LOG_DIR = "{0}{1}".format(CONTROLLER_CONFIG["install_dir"],
                                     getvar("DOCKER_CONTROLLER_PLUGIN_DIR", "var/nessus/logs/"))

ONPREM_CONFIG = dict(
    host=getvar("DOCKER_ONPREM_IP", "bal-lab-top-001.lab.tenablesecurity.com"),
    port=getvar("DOCKER_ONPREM_PORT", "443"),
    key=getvar("DOCKER_ONPREM_KEY", ""),
    sysadmin_user=getvar("DOCKER_ONPREM_SYSADMIN_USER", "admin@tenable.onprem"),
    sysadmin_pass=getvar("DOCKER_ONPREM_SYSADMIN_PASS", "ACl0ud1nAB0XCouldntB3"),
    container_user=getvar("DOCKER_ONPREM_CONTAINER_USER", "automation@onprem.com"),
    container_pass=getvar("DOCKER_ONPREM_CONTAINER_PASS", "Tenable@123"),
    expose_port=getvar("DOCKER_ONPREM_EXPOSE", "")
)
ONPREM_URL = Config.CAT_URL or "https://{0}:{1}".format(ONPREM_CONFIG["host"], ONPREM_CONFIG["port"])


TENABLEIO_CONFIG = dict(
    host=getvar("DOCKER_TENABLEIO_IP", "dev.cloud.aws.tenablesecurity.com"),
    port=getvar("DOCKER_TENABLEIO_PORT", "443"),
    key=getvar("DOCKER_TENABLEIO_KEY", "d6a4086beca68a0cf741f94d7b1af891cd9c4aef593fc7f74a5755647d43f605"),
    sysadmin_user=getvar("DOCKER_TENABLEIO_SYSADMIN_USER", "admin"),
    sysadmin_pass=getvar("DOCKER_TENABLEIO_SYSADMIN_PASS", "admin"),
    container_user=getvar("DOCKER_TENABLEIO_CONTAINER_USER", "automation@qa-staging.com"),
    container_pass=getvar("DOCKER_TENABLEIO_CONTAINER_PASS", "Tenable@123"),
    expose_port=getvar("DOCKER_TENABLEIO_EXPOSE", "")
)
TENABLEIO_URL = "https://{0}:{1}".format(TENABLEIO_CONFIG["host"], TENABLEIO_CONFIG["port"])


TENABLEIO_DEV_CONFIG = dict(
    host=getvar("DOCKER_TENABLEIO_DEV_IP", "dev.cloud.aws.tenablesecurity.com"),
    port=getvar("DOCKER_TENABLEIO_DEV_PORT", "443"),
    key=getvar("DOCKER_TENABLEIO_DEV_KEY", "1f4b87d7e35f5ffeb7d81a6cfb2ea4fe02ca197cef3ac97f374617a26df6d931"),
    sysadmin_user=getvar("DOCKER_TENABLEIO_DEV_SYSADMIN_USER", "admin"),
    sysadmin_pass=getvar("DOCKER_TENABLEIO_DEV_SYSADMIN_PASS", "admin"),
    container_user=getvar("DOCKER_TENABLEIO_DEV_CONTAINER_USER", "automation@qa-milestone.com"),
    container_pass=getvar("DOCKER_TENABLEIO_DEV_CONTAINER_PASS", "Tenable@123"),
    expose_port=getvar("DOCKER_TENABLEIO_DEV_EXPOSE", "")
)
TENABLEIO_DEV_URL = "https://{0}:{1}".format(TENABLEIO_DEV_CONFIG["host"], TENABLEIO_DEV_CONFIG["port"])


# Nessus Scanner Configuration:
#
SCANNER_CONFIG = dict(
    host=getvar("DOCKER_SCANNER_IP", "172.26.19.45"),
    port=getvar("DOCKER_SCANNER_PORT", "8834"),
    admin_user=getvar("DOCKER_SCANNER_ADMIN_USER", "admin"),
    admin_pass=getvar("DOCKER_SCANNER_ADMIN_PASS", "admin"),
    install_dir=getvar("DOCKER_SCANNER_INSTALL_DIR", "/opt/nessus/"),
    username=getvar("DOCKER_SCANNER_USERNAME", "stduser"),
    password=getvar("DOCKER_SCANNER_PASSWORD", "stdpass"),
    expose_port=getvar("DOCKER_SCANNER_EXPOSE", ""),
    upgrade_build=getvar("DOCKER_SCANNER_UPGRADE_BUILD", UPGRADE_BUILD_VERSION)
)
SCANNER_URL = NessusConfig.CAT_NESSUS_URL or "https://{0}:{1}".format(SCANNER_CONFIG["host"], SCANNER_CONFIG["port"])
SCANNER_PLUGIN_DIR = "{0}{1}".format(SCANNER_CONFIG["install_dir"],
                                     getvar("DOCKER_SCANNER_PLUGIN_DIR", "lib/nessus/plugins/"))
SCANNER_LOG_DIR = "{0}{1}".format(SCANNER_CONFIG["install_dir"],
                                  getvar("DOCKER_SCANNER_PLUGIN_DIR", "var/nessus/logs/"))

# SCANNER_TEST_IMAGES.
# Default set of Scanner/Manager containers to use. Tuple containing (["friendly_name", "docker_image_name"]).
# Most test cases use these default set of images, but more complex cases have images defined
# directly in the test case as needed.
SCANNER_TEST_IMAGES = (
    ["CentOS 5 Scanner", "{0}/services/nessus-centos5".format(LAB_DOCKER_REGISTRY)],
    ["CentOS 6 Scanner", "{0}/services/nessus-centos6".format(LAB_DOCKER_REGISTRY)],
    ["CentOS 7 Scanner", "{0}/services/nessus-centos7".format(LAB_DOCKER_REGISTRY)],
    ["Debian 7 Scanner", "{0}/services/nessus-debian7".format(LAB_DOCKER_REGISTRY)],
    ["Debian 9 Scanner", "{0}/services/nessus-debian9".format(LAB_DOCKER_REGISTRY)],
    ["Fedora 24 Scanner", "{0}/services/nessus-fedora24".format(LAB_DOCKER_REGISTRY)],
    ["Fedora 25 Scanner", "{0}/services/nessus-fedora25".format(LAB_DOCKER_REGISTRY)],
    ["Kali Rolling Scanner", "{0}/services/nessus-kali-rolling".format(LAB_DOCKER_REGISTRY)],
    ["OpenSuSE 11 Scanner", "{0}/services/nessus-opensuse11".format(LAB_DOCKER_REGISTRY)],
    ["OpenSuSE 12 Scanner", "{0}/services/nessus-opensuse12".format(LAB_DOCKER_REGISTRY)],
    ["Ubuntu 14 Scanner", "{0}/services/nessus-ubuntu14".format(LAB_DOCKER_REGISTRY)],
    ["Ubuntu 16 Scanner", "{0}/services/nessus-ubuntu16".format(LAB_DOCKER_REGISTRY)],
    ["Ubuntu 17.04 Scanner", "{0}/services/nessus-ubuntu1704".format(LAB_DOCKER_REGISTRY)],
)

# TODO: One place for specifying all images based on an OS type (CentOS 5, OpenSuSE 11, etc)
# for standardized site configurations.

# Plugin configurations
#
# CUSTOM_PLUGIN_BRANCH. Fetches plugins from plugin team's bamboo artifact's server and loads them into Nessus during
# activation.
PLUGIN_DEV_BRANCH = os.getenv("PLUGIN_DEV_BRANCH", "")

# PLUGIN_SERVERS. DNS or IP of the staging and prod plugin/registration servers.
PRODUCTION_PLUGIN_SERVER = os.getenv("PRODUCTION_PLUGIN_SERVER", "plugins-internal-prod.cloud.aws.tenablesecurity.com")
STAGING_PLUGIN_SERVER = os.getenv("STAGING_PLUGIN_SERVER", "plugins-internal-staging.cloud.aws.tenablesecurity.com")

# PLUGIN_SERVER_API's. DNS of IP of the staging plugin/registration server REST API's.
PRODUCTION_PLUGIN_SERVER_API = os.getenv("PLUGIN_SERVER_API", "https://plugins-internal-prod.cloud.aws.tenablesecurity.com/keygen/json.generate.php")
STAGING_PLUGIN_SERVER_API = os.getenv("STAGING_SERVER_API", "http://plugins-internal-staging.cloud.aws.tenablesecurity.com/keygen/generate")

# Scanning configuration:
# Scanning tests are done using the noqa image to avoid SIGABRT's while using NESSUS_QA_MODE.
DOCKER_REGISTRY = getvar("DOCKER_REGISTRY", "docker-registry.lab.tenablesecurity.com")
SCANNING_TEST_IMAGE = os.getenv("SCANNING_TEST_IMAGE",
                                DOCKER_REGISTRY + "/services/nessus-centos7-noqa")
SCANNING_SMB_CREDS = [
    ["admin", "LabPass1"],
    ["admin", "sapphire"],
    ["Admin", "QAbotTe$ting"],
    ["Administrator", "LabPass1"],
    ["Administrator", "QAbotTe$ting"],
    ["Administrator", "sapphire"],
    ["Administrator", "Tenable@123"],
]

SCANNING_SSH_CREDS = [
    ["admin", "sapphire"],
    ["admin", "LabPass1"],
    ["admin", "Trp3jumP"],
    ["netscreen", "LabPass1"],
    ["root", "sapphire"],
    ["root", "LabPass1"],
    ["root", "Tenable@123"],
]

# Scanner general options:
AUTO_UPDATE = os.getenv("DOCKER_AUTO_UPDATE", "no")
LOG_WHOLE_ATTACK = os.getenv("DOCKER_LOG_WHOLE_ATTACK", "no")
NO_USER = os.getenv("DOCKER_NO_USER", "no")
UPDATE_PLUGINS = os.getenv("DOCKER_UPDATE_PLUGINS", "yes")

# Nessus no root mode options:
NO_ROOT = os.getenv("DOCKER_NO_ROOT", "no")
NESSUS_USER = os.getenv("DOCKER_NESSUS_USER", "nessus")
NESSUS_GROUP = os.getenv("DOCKER_NESSUS_GROUP", "nessus")

# CUSTOM_PLUGIN_BRANCH. Fetches plugins from plugin team's bamboo artifact's server and loads them into Nessus during
# activation.
CUSTOM_PLUGIN_BRANCH = os.getenv("DOCKER_CUSTOM_PLUGIN_BRANCH", "")

# A default set of scan targets.
SCANNING_TEST_TARGETS = os.getenv("DOCKER_SCANNING_TEST_TARGETS", "")

# Targets for performance testing. These are a tuple because each
# host is scanned on its own and fed into pytest as parameters.
NESSUS_PERF_TARGETS = (
    ["qa-neslab-cent7", "10.10.100.100"],
    ["qa-neslab-ubun16", "10.10.100.101"],
    ["qa-neslab-Win10", "10.10.100.102"],
    ["qa-neslab-Win2016", "10.10.100.103"],
    ["qa-neslab-freebsd", "10.10.100.104"],
)

AIX_TARGETS = {
    "aix61": "172.26.0.236",
}

CISCO_TARGETS = {
    "cisco-2960g-12": "172.26.0.12",
    "cisco-3750g-15": "172.26.0.11",
}

HPUX_TARGETS = {
    "hpux-11": "172.26.0.45",
    "hpuxrisc-11": "172.26.0.63",
}

JUNIPER_TARGETS = {
    "juniper-ssg6": "172.26.0.15",
    "juniper-2350": "172.26.0.17",
}

SOLARIS_TARGETS = {
    "solaris11-sparc": "172.26.0.37",
}


QA_BOT_LINUX_TARGETS = {
    "np-qa-oraclelinux7": "172.25.18.61",
    "np-qa-scientific7": "172.25.18.62",
    "np-qa-deb8-64": "172.25.18.69",
    "np-qa-ubu1004-32": "172.25.18.102",
    "np-qa-ubu1004-64": "172.25.18.103",
    "np-qa-ubu1204-32": "172.25.18.108",
    "np-qa-ubu1204-64": "172.25.18.109",
    "np-qa-sles9-32": "172.25.18.112",
    "np-qa-sles10-32": "172.25.18.113",
    "np-qa-sles10-64": "172.25.18.114",
    "np-qa-sles11-32": "172.25.18.115",
    "np-qa-sles11-64": "172.25.18.116",
    "np-qa-centos5-32": "172.25.18.118",
    "np-qa-centos5-64": "172.25.18.119",
    "np-qa-centos6-32": "172.25.18.120",
    "np-qa-centos6-64": "172.25.18.121",
    "np-qa-centos7-64": "172.25.18.122",
    "np-qa-fed23-32": "172.25.18.134",
    "np-qa-fed23-64": "172.25.18.135",
    "np-qa-scientific5-64": "172.25.18.137",
    "np-qa-scientific6-32": "172.25.18.138",
    "np-qa-rhel4-32": "172.25.18.143",
    "np-qa-rhel4-64": "172.25.18.144",
    "np-qa-rhel5-32": "172.25.18.145",
    "np-qa-rhel5-64": "172.25.18.146",
    "np-qa-rhel6-32": "172.25.18.147",
    "np-qa-rhel6-64": "172.25.18.148",
    "np-qa-ubu1404-32": "172.25.18.149",
    "np-qa-ubu1404-64": "172.25.18.150",
    "np-qa-ubu1510-32": "172.25.18.151",
    "np-qa-ubu1510-64": "172.25.18.152",
    "np-qa-oraclelinux4-32": "172.25.18.155",
    "np-qa-oraclelinux-32": "172.25.18.156",
    "np-qa-oraclelinuxb-32": "172.25.18.157",
    "np-qa-oraclelinux5-64": "172.25.18.158",
    "np-qa-oraclelinux6-32": "172.25.18.159",
    "np-qa-osuse132-64": "172.25.18.165",
    "np-qa-osuse132": "172.25.18.166",
    "np-qa-deb7-32": "172.25.18.167",
    "np-qa-deb7-64": "172.25.18.168",
    "np-qa-osuse131-64": "172.25.18.173",
    "np-qa-osuse131-32": "172.25.18.174",
    "np-qa-slackware14-32": "172.25.18.175",
    "np-qa-slackware14-64": "172.25.18.176",
    "np-qa-rhel7-64": "172.25.18.178",
    "np-qa-ubu1604-32": "172.25.18.187",
    "np-qa-ubu1604-64": "172.26.18.188",
    "np-qa-fed22-32": "172.25.18.245",
    "np-qa-fed22-64": "172.25.18.246",
}


QA_BOT_WINDOWS_TARGETS = {
    "np-qa-Win10-64": "172.25.18.255",
    "np-qa-Win10-86": "172.25.18.254",
    "np-qa-Win2008-64": "172.25.19.9",
    "np-qa-Win2008-86": "172.25.19.6",
    "np-qa-Win2008R2": "172.25.19.0",
    "np-qa-Win2012": "172.25.19.2",
    "np-qa-Win2012-R2": "172.25.19.3",
    "np-qa-Win7-64": "172.25.19.5",
    "np-qa-Win7-86": "172.25.19.4",
    "np-qa-Win8.1-64": "172.25.19.8",
    "np-qa-Win8.1-86": "172.25.19.7",
}


# Full Image list.
# Some tests, such as the installation tests, test all available images. Tuple containing (["image name", "linux type"])

ALL_SCANNER_IMAGES = (
    ["{0}/services/nessus-centos5".format(LAB_DOCKER_REGISTRY), "centos"],
    ["{0}/services/nessus-centos6".format(LAB_DOCKER_REGISTRY), "centos"],
    ["{0}/services/nessus-centos7".format(LAB_DOCKER_REGISTRY), "centos"],
    ["{0}/services/nessus-debian7".format(LAB_DOCKER_REGISTRY), "debian"],
    ["{0}/services/nessus-debian8".format(LAB_DOCKER_REGISTRY), "debian"],
    ["{0}/services/nessus-debian9".format(LAB_DOCKER_REGISTRY), "debian"],
    ["{0}/services/nessus-kali-rolling".format(LAB_DOCKER_REGISTRY), "kali"],
    ["{0}/services/nessus-fedora20".format(LAB_DOCKER_REGISTRY), "fedora"],
    ["{0}/services/nessus-fedora23".format(LAB_DOCKER_REGISTRY), "fedora"],
    ["{0}/services/nessus-fedora24".format(LAB_DOCKER_REGISTRY), "fedora"],
    ["{0}/services/nessus-fedora25".format(LAB_DOCKER_REGISTRY), "fedora"],
    ["{0}/services/nessus-opensuse11".format(LAB_DOCKER_REGISTRY), "suse"],
    ["{0}/services/nessus-opensuse12".format(LAB_DOCKER_REGISTRY), "suse"],
    ["{0}/services/nessus-opensuse13".format(LAB_DOCKER_REGISTRY), "suse"],
    ["{0}/services/nessus-ubuntu12".format(LAB_DOCKER_REGISTRY), "ubuntu"],
    ["{0}/services/nessus-ubuntu14".format(LAB_DOCKER_REGISTRY), "ubuntu"],
    ["{0}/services/nessus-ubuntu16".format(LAB_DOCKER_REGISTRY), "ubuntu"],
    ["{0}/services/nessus-ubuntu1610".format(LAB_DOCKER_REGISTRY), "ubuntu"],
    ["{0}/services/nessus-ubuntu1704".format(LAB_DOCKER_REGISTRY), "ubuntu"],
)

ALL_AGENT_IMAGES = (
    ["{0}/services/nessus-centos5-agent".format(LAB_DOCKER_REGISTRY), "centos"],
    ["{0}/services/nessus-centos6-agent".format(LAB_DOCKER_REGISTRY), "centos"],
    ["{0}/services/nessus-centos7-agent".format(LAB_DOCKER_REGISTRY), "centos"],
    ["{0}/services/nessus-debian7-agent".format(LAB_DOCKER_REGISTRY), "debian"],
    ["{0}/services/nessus-debian8-agent".format(LAB_DOCKER_REGISTRY), "debian"],
    ["{0}/services/nessus-debian9-agent".format(LAB_DOCKER_REGISTRY), "debian"],
    ["{0}/services/nessus-fedora20-agent".format(LAB_DOCKER_REGISTRY), "fedora"],
    ["{0}/services/nessus-fedora23-agent".format(LAB_DOCKER_REGISTRY), "fedora"],
    ["{0}/services/nessus-opensuse12-agent".format(LAB_DOCKER_REGISTRY), "suse"],
    ["{0}/services/nessus-opensuse13-agent".format(LAB_DOCKER_REGISTRY), "suse"],
    ["{0}/services/nessus-ubuntu12-agent".format(LAB_DOCKER_REGISTRY), "ubuntu"],
    ["{0}/services/nessus-ubuntu14-agent".format(LAB_DOCKER_REGISTRY), "ubuntu"],
    ["{0}/services/nessus-ubuntu16-agent".format(LAB_DOCKER_REGISTRY), "ubuntu"],
    ["{0}/services/nessus-ubuntu1610-agent".format(LAB_DOCKER_REGISTRY), "ubuntu"],
    ["{0}/services/nessus-ubuntu1704-agent".format(LAB_DOCKER_REGISTRY), "ubuntu"],
)


# Proxy server related information.
PROXY_SERVER_CONFIG = dict(
    host=getvar("DOCKER_PROXY_HOST", "172.26.21.103"),
    port=getvar("DOCKER_PROXY_PORT", "3128"),
    username=getvar("DOCKER_PROXY_USER", "tenable"),
    password=getvar("DOCKER_PROXY_PASS", "tenable")
)

# Set the docker host to use.
DOCKER_API_VERSION = getvar("DOCKER_API_VERSION", "1.26")

USE_DOCKER_AS_PRIMARY_NESSUS = getvar("USE_DOCKER_AS_PRIMARY_NESSUS", False)
WAIT_FOR_STATUS_AVAILABLE = getvar("WAIT_FOR_STATUS_AVAILABLE", True)

DOCKER_SCANNER_IMAGE = getvar("DOCKER_SCANNER_IMAGE")
