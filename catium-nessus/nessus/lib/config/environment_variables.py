"""
    Nessus Environment Variables

    :automation-nessus environmental variables:
    :date: Apr 26, 2017
    :authors: @cdombrowski, @jyerge

    ## ## NOTE ## ##
    If any new environment variables are added to this file they must be also added to
    https://confluence.corp.tenablesecurity.com/display/AUTO/Environment+Variables
    ## ##  ##  ## ##
"""
import os
import sys

from catium.helpers.site_configuration_fetcher import get_site_environ
from catium.lib import const
from catium.lib.config import Config
from catium.lib.config_helper.configuration_wrapper import CatConfig
from nessus.lib.const import OperatingSystems, Scanner


class NessusEnvironmentConfig(metaclass=CatConfig):
    """Nessus configuration values"""

    CAT_NESSUS_URL = lambda: get_site_environ('CAT_NESSUS_URL', default=Config.CAT_URL, alt_variable='CAT_URL',
                                              config_key='URL')
    CAT_USER_DOMAIN = lambda: get_site_environ('CAT_USER_DOMAIN', default=const.DOMAIN)
    # Optional Environmental Variables related to Nessus DB Downloads.
    CAT_NESSUS_DB_DOWNLOAD = lambda: get_site_environ('CAT_NESSUS_DB_DOWNLOAD', default=Scanner.NESSUS_DB_DOWNLOAD)
    CAT_NESSUS_DB_PASSWORD = lambda: get_site_environ('CAT_NESSUS_DB_PASSWORD', default=Scanner.NESSUS_DB_PASSWORD)
    CAT_NESSUS_DB_DIRECTORY = lambda: get_site_environ('CAT_NESSUS_DB_DIRECTORY', default=Scanner.NESSUS_DB_DIRECTORY)
    CAT_NESSUS_DB_FILENAME = lambda: get_site_environ('CAT_NESSUS_DB_FILENAME', default=Scanner.NESSUS_DB_FILENAME)
    CAT_NESSUS_SCAN_NAME = lambda: get_site_environ('CAT_NESSUS_SCAN_NAME', default=Scanner.NESSUS_SCAN_NAME)
    CAT_NESSUS_MANAGER_LINKING_KEY = lambda: get_site_environ('CAT_NESSUS_MANAGER_LINKING_KEY',
                                                              default=Scanner.NESSUS_MANAGER_LINKING_KEY)
    CAT_NESSUS_PLATFORM = get_site_environ("CAT_NESSUS_PLATFORM", "NESSUS_PLATFORM")

    if not CAT_NESSUS_PLATFORM:
        if sys.platform.startswith('linux'):
            CAT_NESSUS_PLATFORM = OperatingSystems.LINUX
        elif sys.platform.startswith('freebsd'):
            CAT_NESSUS_PLATFORM = OperatingSystems.FREEBSD
        elif sys.platform.startswith('win'):
            CAT_NESSUS_PLATFORM = OperatingSystems.WINDOWS
        elif sys.platform.startswith('darwin'):
            CAT_NESSUS_PLATFORM = OperatingSystems.MAC
    CAT_LOADING_CIRCLE_TIMEOUT = lambda: get_site_environ('CAT_LOADING_CIRCLE_TIMEOUT', value_type=int, default=0)

    CAT_NESSUS_USERNAME = lambda: get_site_environ('CAT_NESSUS_USERNAME', required=True, alt_variable='CAT_USERNAME',
                                                   config_key='USERNAME')
    CAT_NESSUS_PASSWORD = lambda: get_site_environ('CAT_NESSUS_PASSWORD', required=True, alt_variable='CAT_PASSWORD',
                                                   config_key='PASSWORD')
    CAT_NESSUS_WARN_SLEEP = lambda: get_site_environ('CAT_NESSUS_WARN_SLEEP', 'NESSUS_WARN_SLEEP',
                                                     value_type=bool, default=True)
    CAT_PROXY_HOST = get_site_environ('CAT_PROXY_HOST', default=None, value_type=str)
    CAT_PROXY_PORT = get_site_environ('CAT_PROXY_PORT', default=None, value_type=str)
    CAT_PROXY_USERNAME = get_site_environ('CAT_PROXY_USERNAME', default=None, value_type=str)
    CAT_PROXY_PASSWORD = get_site_environ('CAT_PROXY_PASSWORD', default=None, value_type=str)
    CAT_TIO_URL = get_site_environ('CAT_TIO_URL', default='qa-staging.cloud.aws.tenablesecurity.com', value_type=str)


# Nessus installation environment variables
NESSUS_VERSION = get_site_environ('CAT_NESSUS_VERSION', 'NESSUS_VERSION')
NESSUS_VERSION_NUMBER = get_site_environ('CAT_NESSUS_VERSION_NUMBER', 'NESSUS_VERSION_NUMBER')
NESSUS_DIR = get_site_environ('CAT_NESSUS_DIR', 'NESSUS_DIR')
NESSUS_PLATFORM = get_site_environ("CAT_NESSUS_PLATFORM", "NESSUS_PLATFORM")

if not NESSUS_PLATFORM:
    if sys.platform.startswith('linux'):
        NESSUS_PLATFORM = OperatingSystems.LINUX
    elif sys.platform.startswith('freebsd'):
        NESSUS_PLATFORM = OperatingSystems.FREEBSD
    elif sys.platform.startswith('win'):
        NESSUS_PLATFORM = OperatingSystems.WINDOWS
    elif sys.platform.startswith('darwin'):
        NESSUS_PLATFORM = OperatingSystems.MAC


def get_default_nessus_dir():
    """ Returns default Nessus directory based on given platform """
    if NESSUS_PLATFORM == OperatingSystems.WINDOWS:
        return 'C:\\Program Files\\Tenable\\Nessus'
    elif NESSUS_PLATFORM == OperatingSystems.FREEBSD:
        return '/usr/local/nessus'
    elif NESSUS_PLATFORM in [OperatingSystems.MAC, OperatingSystems.MAC_OS]:
        return '/Library/Nessus/run'
    else:
        return '/opt/nessus'


NESSUS_SBIN_DIR = None
NESSUS_BIN_DIR = None
NESSUS_CONF_DIR = None
NESSUS_DATA_DIR = None
NESSUSCLI_EXE = None
NASL_EXE = None
NESSUS_DEBUG_TESTS = get_site_environ('CAT_NESSUS_DEBUG_TESTS', config_key='NESSUS_DEBUG_TESTS',
                                      value_type=bool, default=False)
NESSUS_LOGS_DIR = None
NESSUSD_DUMP = None
NESSUSD_MESSAGES = None
NESSUS_BACKEND_LOGS = None
NESSUS_SERVER_LOG = None
NESSUS_TEMPLATE_DIR = None
NESSUS_COM_DIR = None
DEFAULT_NESSUS_DIR = get_default_nessus_dir()

if NESSUS_PLATFORM == OperatingSystems.WINDOWS:
    NESSUS_DIR = DEFAULT_NESSUS_DIR
    NESSUS_SBIN_DIR = os.path.join(NESSUS_DIR, 'sbin')
    NESSUS_BIN_DIR = os.path.join(NESSUS_DIR, 'bin')
    NESSUS_CONF_DIR = 'C:\\ProgramData\\Tenable\\Nessus\\etc'
    NESSUS_DATA_DIR = 'C:\\ProgramData\\Tenable\\Nessus\\nessus'
    NESSUSCLI_EXE = os.path.join(NESSUS_SBIN_DIR, 'nessuscli.exe')
    NESSUS_LOGS_DIR = os.path.join(NESSUS_DATA_DIR, 'logs')
    NESSUS_PLUGIN_DIR = "C:\\ProgramData\\Tenable\\Nessus\\nessus\\plugins"
    NASL_EXE = os.path.join(NESSUS_BIN_DIR, 'nasl.exe')
    NESSUSD_EXE = os.path.join(NESSUS_SBIN_DIR, 'nessusd')
    NESSUS_LIB_DIR = "C:\\ProgramData\\Tenable\\Nessus\\nessus"
else:
    NESSUS_DIR = DEFAULT_NESSUS_DIR
    NESSUS_SBIN_DIR = os.path.join(NESSUS_DIR, 'sbin')
    NESSUS_BIN_DIR = os.path.join(NESSUS_DIR, 'bin')
    NESSUS_CONF_DIR = os.path.join(NESSUS_DIR, 'etc', 'nessus')
    NESSUS_LIB_DIR = os.path.join(NESSUS_DIR, 'lib', 'nessus')
    NESSUS_DATA_DIR = os.path.join(NESSUS_DIR, 'var', 'nessus')
    NESSUSCLI_EXE = os.path.join(NESSUS_SBIN_DIR, 'nessuscli')
    NASL_EXE = os.path.join(NESSUS_BIN_DIR, 'nasl')
    TAIL_COMMAND = 'tail -n %d'
    NESSUS_LOGS_DIR = os.path.join(NESSUS_DATA_DIR, 'logs')
    NESSUS_PLUGIN_DIR = os.path.join(NESSUS_DIR, 'lib', 'nessus', 'plugins')
    NESSUSD_EXE = os.path.join(NESSUS_SBIN_DIR, 'nessusd')
    NESSUSD_DUMP = os.path.join(NESSUS_LOGS_DIR, 'nessusd.dump')
    NESSUSD_MESSAGES = os.path.join(NESSUS_LOGS_DIR, 'nessusd.messages')
    NESSUS_BACKEND_LOGS = os.path.join(NESSUS_LOGS_DIR, 'backend.log')
    NESSUS_SERVER_LOG = os.path.join(NESSUS_LOGS_DIR, 'www_server.log')
    NESSUS_TEMPLATE_DIR = os.path.join(NESSUS_DATA_DIR, 'templates')
    NESSUS_COM_DIR = os.path.join(NESSUS_DIR, 'com', 'nessus')

NESSUS_CLI_LOCAL = get_site_environ('CAT_NESSUS_CLI_LOCAL', 'NESSUS_CLI_LOCAL', value_type=bool, default=True)
