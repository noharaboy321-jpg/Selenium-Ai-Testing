#!/usr/bin/env python

"""
Tools for working with files locally and inside of Docker containers.

:copyright: Tenable Network Security, 2017
:date: Aug 30 2017
:author: @jmcneil
"""

from datetime import datetime, timedelta
from subprocess import call, check_output

import os
import re

from catium.helpers.sleep_lib import sleep
from catium.lib.const import TIME_FIVE_SECONDS
from catium.lib.log import create_logger
from nessus.lib.config import docker_config
from .constants import CORE_INSTALL_WAIT_TIME, CORE_INSTALL_LOG_CHECK_TIME, ENCODING, FNULL, NESSUSD_DUMP_EXCLUSIONS, \
    AGENT_PLUGIN_INSTALL_LOG_CHECK_TIME, AGENT_PLUGIN_INSTALL_WAIT_TIME, \
    SCANNER_PLUGIN_INSTALL_LOG_CHECK_TIME, SCANNER_PLUGIN_INSTALL_WAIT_TIME
from .container import Container


class FileTools(object):
    """
    Various tools/methods which can be used for working with files.
    """

    def __init__(self, file_name=None, nessus_type="scanner"):
        """

        :param str file_name: Path to filename being worked with.
        :param str nessus_type: Type of scanner that is being worked with.
        """

        self.docker_client = Container()
        self.logger = create_logger()

        if file_name:
            self.file_name = file_name

        if nessus_type == "agent":
            self.install_dir = docker_config.AGENT_CONFIG["install_dir"]
        else:
            self.install_dir = docker_config.SCANNER_CONFIG["install_dir"]

        self.nessusd_dumpfile = self.install_dir + "var/nessus/logs/nessusd.dump"
        self.nessusd_messages = self.install_dir + "var/nessus/logs/nessusd.messages"
        self.nessusd_backendlog = self.install_dir + "var/nessus/logs/backend.log"
        self.nessusd_wwwserverlog = self.install_dir + "var/nessus/logs/www_server.log"

    @staticmethod
    def check_empty(file_name):
        """
        Check if a file is empty.

        :param str file_name: Name of the file to check.
        :return: True / size if empty, False / size if not.
        :rtype: Boolean
        """

        # Check to see if it is empty (the size is 0 bytes).
        file_size = os.stat(file_name).st_size
        if file_size == 0:
            return True, file_size

        return False, file_size

    @staticmethod
    def check_exists(file_name, cid=None):
        """
        Check if a file exists.

        :param str file_name: Name of the file to check. Full path if not in cwd.
        :param str cid: Container ID to look for file in.
        :return: True if exists, False if not.
        """

        if cid:
            exists = call(["docker", "exec", cid,
                           "stat", "-c", "%.19z", file_name], stdout=FNULL, stderr=FNULL)

            if exists == 0:
                exists = True
            else:
                exists = False
        else:
            # local fs
            exists = os.path.exists(file_name)

        return exists

    def check_modified_time(self, file_name, cid=None):
        """
        Check the last modified timestamp of a specified file. Supports local and Docker container.

        :param str file_name: Name of the file to check the last modified timestamp of.
        :param str cid: If provided it is assumed to check inside the docker container for specified file.
        :return: last modified time as datetime object or None.
        :rtype: Boolean
        """

        if not cid:
            file_exists = self.check_exists(file_name)

            if not file_exists:
                self.logger.debug("%s does not exist.", file_name)
                return None

            modified_time = datetime.fromtimestamp(os.path.getmtime(file_name))

        else:
            mod_time = check_output(["docker", "exec", cid,
                                     "stat", "-c", "%.19z", file_name]).decode(ENCODING).rstrip()

            if not mod_time:
                self.logger.debug("Failed to get timestamp of %s.", file_name)

            modified_time = datetime.strptime(mod_time, "%Y-%m-%d %H:%M:%S")

        if not modified_time:
            return None

        return modified_time

    def wait_for_creation(self, file_name, cid=None):
        """
        Wait for a file to be created.
        TODO: support a timedelta.

        :param str file_name: Name of the file to wait for.
        :param str cid: If provided it is assumed to check inside the docker container for specified file.
        :return: True when it exists, False on error.
        :rtype: Boolean
        """

        file_exists = self.check_exists(file_name, cid)
        while not file_exists:
            self.logger.debug("File does not exist yet, waiting: %s", file_name)
            sleep(sleep_time=TIME_FIVE_SECONDS, reason='wating for file to exist')
            file_exists = self.check_exists(file_name, cid)

        if file_exists:
            self.logger.debug("File exists: %s", file_name)
            sleep(sleep_time=TIME_FIVE_SECONDS, reason='wating for file')
            return True

        return False


class LogReader(FileTools):
    """
    Tool for working with log files.
    """

    def get_container_file_contents(self, cid, file_name, temp_dir="/tmp/"):
        """
        Get the contents of a file that lives inside a Docker container.

        :param str cid: The Docker container ID to use.
        :param str file_name: The name of the file to get the contents of.
        :param str temp_dir: The temporary working directory to use for file operations. Default: /tmp/
        :return: Contents of file or None
        """
        file_copied, full_filename = self.docker_client.copy(cid, file_name, copy_to=temp_dir)

        # Get contents and cleanup temp file:
        if file_copied and full_filename:
            logs = self.get_file_contents(full_filename)

            if os.path.isfile(full_filename):
                os.remove(full_filename)

            if os.path.isdir(os.path.dirname(full_filename)):
                os.removedirs(os.path.dirname(full_filename))

            return logs

        self.logger.debug("Failed to copy %s from container.", self.nessusd_dumpfile)
        return None

    def get_file_contents(self, file_name):
        """
        Get the contents of file and return them.

        :param str file_name: File name to open.
        :return: contents of file, None if failed to read.
        :rtype: List
        """
        # Make sure it exists:
        if not self.check_exists(file_name):
            self.logger.debug("File does not exist: %s", file_name)
            return None

        # If it is empty, just bail:
        is_empty, file_size = self.check_empty(file_name)
        if is_empty:
            self.logger.debug("File is empty: %s Size: %i", file_name, file_size)
            return None

        # Should be safe to open the file:
        try:
            with open(file_name, mode='r', encoding=ENCODING) as file_handle:
                file_contents = file_handle.readlines()
        except Exception as exc:
            self.logger.info(str(exc))
            return None

        if file_contents:
            filtered_contents = self.excludes_filter(file_contents, NESSUSD_DUMP_EXCLUSIONS)
            return filtered_contents

        return None

    @staticmethod
    def excludes_filter(line_list, filter_list):
        """
        Filter a list, remove any entries which match, and return the filtered list. Filters are configured
        in nessus_config.py or can be passed in on the fly.

        :param list line_list: A list of lines, either from a file or created manually, to run through and filter.
        :param list filter_list: This is a list of known entries to exclude from the provided list.
        :return:
        :rtype: List
        """

        for line in line_list:
            for line_filter in filter_list:
                if line_filter in line:
                    line_list.remove(line)

        return line_list

    def check_nessus_dump(self, cid=None, use_exclude_list=True, remote=False, temp_dir="/tmp/"):
        """
        Check the nessusd.dump file for new entries. If line does not match something in the exclude filter, display
        the entries. Supports local filesystem, remote (scp) or Docker containers.

        :param str cid: If provided, check inside docker container, else assume log file lives on local system.
        :param bool use_exclude_list: Flag to disable filtering of nessusd.dump file for known exclusions defined
                                      in nessus_config.py.
        :param bool remote: Flag to enable fetching of nessusd.dump file from a remote system, using SSH.
        :param str temp_dir: The temporary working directory to use for file operations. Default: /tmp/
        :return: True, None if failed.
        """
        file_contents = None

        # Local filesystem
        if not cid and not remote:
            file_contents = self.get_file_contents(self.nessusd_dumpfile)

        # From a container
        elif cid:

            # Copy the file from the container:
            file_copied, full_filename = self.docker_client.copy(cid, self.nessusd_dumpfile, copy_to=temp_dir)

            # Get contents:
            if file_copied and full_filename:
                file_contents = self.get_file_contents(full_filename)
                if os.path.isfile(full_filename):
                    os.remove(full_filename)

                if os.path.isdir(os.path.dirname(full_filename)):
                    os.removedirs(os.path.dirname(full_filename))
            else:
                self.logger.debug("Failed to copy %s from container.", self.nessusd_dumpfile)
                return None

        # No contents is not a bad thing here.
        if not file_contents:
            self.logger.debug("No entries in nessusd.dump.")
            return True
        else:
            # Check for entries to be excluded.
            if use_exclude_list:
                self.logger.debug("Starting to filter logfile contents.")
                new_contents = self.excludes_filter(file_contents, NESSUSD_DUMP_EXCLUSIONS)

                self.logger.info("The following entries are in nessusd.dump:")
                for line in new_contents:
                    self.logger.info(line.strip())

                if len(new_contents) < len(file_contents):
                    num_filtered = len(file_contents) - len(new_contents)
                    self.logger.debug("Note: %i lines matched the configured exclusion"
                                      "filters for nessusd.dump and have been removed.", num_filtered)

                return new_contents
            else:
                self.logger.info("The following entries are in nessusd.dump:")
                for line in file_contents:
                    self.logger.info(line.strip())
                return file_contents

    @staticmethod
    def search_list(search_term, lines):
        """
        Search through a list for a specified regex.

        :param regex search_term: The search term to look for in each list entry.
        :param list lines: A list of strings to search through.
        :returns: True if found, False if not
        :rtype: bool
        """
        if search_term is None or lines is None:
            return False

        found = [m.group(1) for l in lines for m in [search_term.search(l)] if m]
        if found:
            return True

        return False

    def wait_for_agentcore_install(self, cid, wait_time=CORE_INSTALL_WAIT_TIME):
        """
        Wait for a agent core to be installed. Watches backend.log and looks for "New agentdb installed" entry.
        Supports Docker Nessus only.

        :param cid: The Docker container ID of the agent to watch.
        :param wait_time: maximum amount of time to wait for the agent cores to be installed. Default: 10 mins.
        :return: True when installed, False on error.
        :rtype: Boolean
        """
        pattern = re.compile(".*(Downloading core: complete).*")
        search_start = datetime.now()
        wait_for = timedelta(minutes=wait_time)

        self.logger.debug("Waiting %s for agent cores to download and install.", str(wait_for))
        logs = self.get_container_file_contents(cid=cid, file_name=self.nessusd_backendlog)
        agentcore_installed = self.search_list(pattern, logs)
        while (not logs or not agentcore_installed) and (datetime.now() - search_start) <= wait_for:
            sleep(sleep_time=CORE_INSTALL_LOG_CHECK_TIME, reason='Waiting for agent cores to download and install')
            logs = self.get_container_file_contents(cid=cid, file_name=self.nessusd_backendlog)
            agentcore_installed = self.search_list(pattern, logs)
            self.logger.debug("Agent core update installed? %s", str(agentcore_installed))

        if agentcore_installed:
            return True

        return False

    def wait_for_agentdb_install(self, cid, wait_time=AGENT_PLUGIN_INSTALL_WAIT_TIME):
        """
        Wait for a new agentdb to be installed. Watches backend.log and looks for "New agentdb installed" entry.
        Supports Docker Nessus only.

        TODO:
            - update wait time to use constants file.
            - update re's as constants? maybe
            -

        :param cid: The Docker container ID of the agent to watch.
        :param wait_time: maximum amount of time to wait for the agentdb to be installed. Default: 10 mins.
        :return: True when installed, False on error.
        :rtype: Boolean
        """
        pattern = re.compile(".*(New agent.db installed).*")

        search_start = datetime.now()
        wait_for = timedelta(minutes=wait_time)
        self.logger.debug("Waiting up to %s for agent.db to download and install.", str(wait_for))

        logs = self.get_container_file_contents(cid=cid, file_name=self.nessusd_backendlog)
        agentdb_installed = self.search_list(pattern, logs)
        while (not logs or not agentdb_installed) and (datetime.now() - search_start) <= wait_for:
            sleep(sleep_time=AGENT_PLUGIN_INSTALL_LOG_CHECK_TIME,
                  reason='Waiting for agent.db to download and install.')
            logs = self.get_container_file_contents(cid=cid, file_name=self.nessusd_backendlog)
            agentdb_installed = self.search_list(pattern, logs)
            self.logger.debug("Agentdb has finished installing? %s", str(agentdb_installed))

        if agentdb_installed:
            return True

        return False

    def wait_for_managed_plugins_install(self, cid, wait_time=SCANNER_PLUGIN_INSTALL_WAIT_TIME):
        """
        Wait for new plugins to be installed on a managed scanner. Watches backend.log and looks for 
        "finished plugin update" entry in addition to making sure the secure settings show a pluginset.
        Supports Docker Nessus only and should only be used during first run / new scanner provisioning.

        There is no API available so need to use log files.

        :param cid: The Docker container ID of the agent to watch.
        :param wait_time: maximum amount of time to wait for the agentdb to be installed. Default: 10 mins.
        :return: True when installed, False on error.
        :rtype: Boolean
        """
        finished_pattern = re.compile(".*(nessusd-reloader: Reloading nessusd because|Nessus is reloading:) Update from manager.*")

        search_start = datetime.now()
        wait_for = timedelta(minutes=wait_time)
        self.logger.debug("Waiting up to %s for plugins to download and install.", str(wait_for))

        # Make sure plugins install:
        logs = self.get_container_file_contents(cid=cid, file_name=self.nessusd_messages)
        plugins_downloaded = self.search_list(finished_pattern, logs)
        while (not logs or not plugins_downloaded) and (datetime.now() - search_start) <= wait_for:
            sleep(sleep_time=SCANNER_PLUGIN_INSTALL_LOG_CHECK_TIME,
                  reason='Waiting for scanner plugins to download and install.')
            logs = self.get_container_file_contents(cid=cid, file_name=self.nessusd_messages)
            plugins_downloaded = self.search_list(finished_pattern, logs)
            self.logger.debug("Plugins have finished downloading? %s", str(plugins_downloaded))

        if not plugins_downloaded:
            return False

        return True


filetools = FileTools()
logreader = LogReader()
agent_filetools = FileTools(nessus_type="agent")
agent_logreader = LogReader(nessus_type="agent")
