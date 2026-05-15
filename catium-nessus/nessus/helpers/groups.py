"""
:copyright: Tenable Network Security, 2017
:date: June 2, 2017
:author: @cdombrowski
"""
import json

from catium.lib.log import create_logger
from catium.lib.util import random_name
from nessus.apiobjects.nessus_api import NessusAPI

log = create_logger()


def get_nessus_group_members_dictionary(api: NessusAPI, group_id: int) -> dict:
    """
    Method to retrieve the members of a group, and their Nessus ID, in a dictionary.
    :param group_id:                Group ID to retrieve members from.
    :param NessusAPI api:           Nessus API instance
    :return group_members_dict:     Dictionary of group members and their Nessus ID.
    """
    group_members_dict = {}
    members = api.groups.list_users(group_id=group_id)['users']
    if members:
        for member in members:
            group_members_dict[member['username']] = member['id']
    else:
        group_members_dict = None
    return group_members_dict


def get_nessus_groups_list(api: NessusAPI) -> dict:
    """
    Method to retrieve a list of groups on the scanner.  Returns dictionary of group names to group ids.
    :param NessusAPI api:          Nessus API instance
    :return groups_dictionary:     Dictionary of groups and their group ID.
    """
    groups_dictionary = {}
    groups = api.groups.get_groups()['groups']
    for group in groups:
        groups_dictionary[group['name']] = group['id']
    return groups_dictionary


def nessus_create_group(api: NessusAPI, group_name: str = None) -> dict:
    """
    Method to create a group in Nessus.  Creates a randomly named group and returns the group_details as a dict.
    :param NessusAPI api:          Nessus API instance
    :param group_name:             Name of group to create.  Uses a random name if group_name is none.
    :return group_details:         Dictionary of group details from the newly created group.
    """
    if not group_name:
        group_name = random_name(prefix='automation-')
    api.groups.create(name=group_name)
    group_details = json.loads(api.http_text)
    return group_details
