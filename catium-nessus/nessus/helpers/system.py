"""
Nessus API System Helpers
"""
import re
import subprocess

import pytest
import requests

from catium.lib.const.base_constants import STRING_NONE
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.lib.config import NessusConfig, environment_variables as nessus_config
from nessus.lib.const import System
from nessus.plugins.fixtures.login import get_stored_nessus_api_instance


def get_audit_id(audit_filename: str, audit_display_name: str = None):
    """
    Utility method for retrieving the most up to date audit file from the audit_warehouse.audit DB in the Nessus
    directory.

    :param str audit_filename: Name of the audit filename retrieved from the test_data.json file.
    :param str audit_display_name: Name of the audit display_name retrieved from the test_data.json file.
    """
    digit_pattern = re.compile(r'\d{1,5}')
    if audit_display_name:
        query = ["sqlite3", System.LINUX_AUDIT_WAREHOUSE,
                 "select filename,category from audit where filename "
                 "LIKE '{}' and display_name LIKE '{}' and deprecated is 0;".format(audit_filename, audit_display_name)]
    else:
        query = ["sqlite3", System.LINUX_AUDIT_WAREHOUSE,
                 "select filename,category from audit where filename "
                 "LIKE '{0}' and deprecated is 0;".format(audit_filename)]
    audit_info = subprocess.check_output(query).decode("utf-8").strip()
    audits = audit_info.split("\n")
    newest_audit = audits[len(audits) - 1].split("|")
    if len(newest_audit) >= 1:
        audit_file = newest_audit[0]
        category = newest_audit[1]
        plugin_id = subprocess.check_output(["sqlite3", System.LINUX_AUDIT_WAREHOUSE,
                                             "select plugin_id from category where id is '{0}';".
                                            format(category)]).decode("utf-8").strip()
        if digit_pattern.match(plugin_id):
            audit_file_id = "{0}_{1}".format(plugin_id, audit_file)
            return audit_file_id
        else:
            pytest.fail("Unable to retrieve the audit file's plugin ID.")
    else:
        pytest.fail("Failed to parse the latest audit file for {}.".format(audit_filename))


def get_nessus_type(api: NessusAPI = None):
    """
    Checks and returns the Server Type.  Useful for determining the Nessus type (Manager, Professional, etc) on the
    scanner.
    """
    if not api:
        api = NessusAPI()

    if nessus_config.NESSUS_VERSION:
        return nessus_config.NESSUS_VERSION

    if NessusConfig.CAT_NESSUS_URL == STRING_NONE.lower():
        return str(None)
    else:
        properties = api.server.properties()
        if properties and "nessus_type" in properties:
            return properties['nessus_type']


def get_nessus_version():
    """
    Checks and returns the Nessus version.  Useful for determining if a particular test can run on the host.
    """
    api = get_stored_nessus_api_instance()

    if not api:
        api = NessusAPI()

    if NessusConfig.CAT_NESSUS_URL == STRING_NONE.lower():
        return str(None)
    elif nessus_config.NESSUS_VERSION_NUMBER:
        return nessus_config.NESSUS_VERSION_NUMBER
    else:
        try:
            properties = api.server.properties()
            if properties and "nessus_ui_version" in properties:
                return properties['nessus_ui_version']
        except (ConnectionRefusedError, requests.exceptions.HTTPError, requests.exceptions.MissingSchema,
                requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout):
            # if URL was fake MissingSchema error will be raised.
            return str(None)


def check_version_less_than(version: str):
    current_version = get_nessus_version()
    if int(current_version.replace(".", "")) < int(version.replace(".", "")):
        return True

    return False


def get_nessus_type_using_api(api: NessusAPI = None) -> str:
    """
    Checks and returns the Nessus type (Manager, Professional, etc).

    :return: nessus type
    :rtype: str
    """
    if not api:
        api = NessusAPI()
    properties = api.server.properties()

    if properties and "nessus_type" in properties:
        if "paid" in properties and properties["paid"] is True:
            return properties["nessus_type"] + " Plus"
        else:
            return properties['nessus_type']


def is_home(api: NessusAPI = None):
    """ Test whether the installed Nessus has a home (Essentials) license """
    _type = get_nessus_type_using_api(api)
    return "Nessus Essentials" in _type or _type == 'Nessus Home'


def is_pro(api: NessusAPI = None):
    """ Test whether the installed Nessus has a pro license """
    return get_nessus_type_using_api(api) == 'Nessus Professional'


def is_expert(api: NessusAPI = None):
    """ Test whether the installed Nessus has an expert license """
    return get_nessus_type_using_api(api) == 'Nessus Expert'


def is_manager(api: NessusAPI = None):
    """ Test whether the installed Nessus has a manager license """
    return get_nessus_type_using_api(api) == 'Nessus Manager'
