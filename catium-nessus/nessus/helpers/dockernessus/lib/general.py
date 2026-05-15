#!/usr/bin/env python
"""
General purpose Nessus functions for Docker Nessus module. Import only.

:copyright: Tenable Network Security, 2017
:date: Aug 30 2017
:author: @jmcneil
"""

from catium.lib.log import create_logger
from nessus.lib.config.docker_config import DOCKER_CLEAN
from nessus.helpers.dockernessus import container
from nessus.helpers.dockernessus.lib.nessuscli import Nessuscli


logger = create_logger()
nessuscli = Nessuscli()


def build_target_list(target_list_dict=None):
    """
    Builds and returns a list of targets from a provided tuple. Used during creation of scan policies.

    :param dict target_list_dict: A tuple containing information about scan targets.
                                    Uses the form {"general_desc": "ip/dns"}
    :return: targets or None if failed.
    :rtype: Comma separated list or None.
    """

    targets = ""
    for item in target_list_dict.values():
        targets += item + ","

    return targets[:-1] if targets else None


def clean_up(cid=None, nessus_type="agent", linked=False):
    """
    Clean up after a test completes. Method provides a way to ensure containers are properly stopped and removed based
    on configuration. Supports Nessus and Nessus Agents. Should likely be called from a test fixture unless in unique
    tests and circumstances.

    Note: if CLEAN in nessus_config.py is not set to "yes" this function will not clean anything.

    :param str cid: The container ID.
    :param str nessus_type: The type of scanner being tested so it can be cleaned up accordingly. Default: agent
    :param bol linked: Specify if the container is linked to manager/ncloud/cloudiron or not. Agent or Managed scanner
                       will be unlinked before being removed when True. Default: False
    :returns: True if clean up completes, False if failed.
    :rtype: Boolean
    """
    if DOCKER_CLEAN != "yes":
        logger.info("CLEAN is not set to 'yes', not cleaning anything.")
        return True

    container_destroyed = False

    # dockerized agent
    if nessus_type == "agent" and cid:
        unlinked = nessuscli.agent.unlink(cid) if linked else False

        if not unlinked and linked:
            logger.error("Failed to unlink Nessus Agent in container: %s.", cid)

        container_destroyed = container.destroy(cid)

    # local agent
    elif nessus_type == "agent" and not cid:
        unlinked = nessuscli.agent.unlink() if linked else False

        if not unlinked and linked:
            logger.error("Failed to unlink local Nessus Agent.")

    # dockerized scanner
    elif nessus_type in ["scanner", "pro", "manager", "professional", "sc-managed"] and cid:
        container_destroyed = container.destroy(cid)

    # dockerized secondary
    elif nessus_type == "managed" and cid:
        unlinked = nessuscli.managed.unlink(cid) if linked else False

        if not unlinked and linked:
            logger.error("Failed to unlink managed Nessus scanner in container: %s.", cid)

        container_destroyed = container.destroy(cid)

    if not container_destroyed:
        return False

    return True
