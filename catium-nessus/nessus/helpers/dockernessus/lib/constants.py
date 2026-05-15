"""
Constants in use by Docker Nessus / Nessus Agent libraries.

:copyright: Tenable Network Security, 2017
:date: Aug 30 2017
:author: @jmcneil
"""

import os

CORE_INSTALL_WAIT_TIME = 10  # minutes
CORE_INSTALL_LOG_CHECK_TIME = 15  # seconds

ENCODING = 'utf-8'

FNULL = open(os.devnull, 'w')

NESSUSD_DUMP_EXCLUSIONS = [
    "Error initializing compliance DB"
]

AGENT_PLUGIN_INSTALL_WAIT_TIME = 10  # minutes
AGENT_PLUGIN_INSTALL_LOG_CHECK_TIME = 10  # seconds

SCANNER_PLUGIN_INSTALL_WAIT_TIME = 30  # minutes
SCANNER_PLUGIN_INSTALL_LOG_CHECK_TIME = 20  # seconds


class ControllerType:
    """Controller types supported by Docker Nessus."""
    manager = "manager"
    onprem = "onprem"
    tenableio = "tenableio"
    tenableio_dev = "tenableio_dev"
