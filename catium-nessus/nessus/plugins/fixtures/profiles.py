"""
Fixtures for profiles

:copyright: Tenable Network Security, 2024

"""
from datetime import datetime
from catium.lib.util import random_name
from typing import TYPE_CHECKING
import re

import pytest

from catium.lib.log import create_logger
from nessus.apiobjects.nessus_api import NessusAPI

if TYPE_CHECKING:
    from catium.lib.typechecking import SubRequest

log = create_logger()

@pytest.fixture()
def create_profile_endpoint(request: 'SubRequest', nessus_api_handler: NessusAPI):
    """
    Creates a new agent profile
    @pytest.mark.parametrize('create_profile_endpoint', [(random_name(prefix='agent-profile-'),)],
                             indirect=True)

    # to create multiple groups
    @pytest.mark.parametrize('create_profile_endpoint', [(random_name(prefix='agent-profile-'),
                                                                    random_name(prefix='agent-profile-'))],
                             indirect=True)
    """
    log.debug('fixture init: Create an profile')
    profile = nessus_api_handler.profiles.create(name=request.param["name"],
                                                 description=request.param["description"],
                                                 config=request.param["config"])

    yield profile

    created_uuids = [profile['profile_uuid']]

    try:
        nessus_api_handler.profiles.delete_profiles(uuid_list=created_uuids)
    except Exception:
        log.warning("Unable to delete profile in clean up. profile may have been deleted by test.")

@pytest.fixture()
def create_valid_profile_endpoint(request: 'SubRequest', nessus_api_handler: NessusAPI, version_digits: int):

    versions = nessus_api_handler.settings.agent_versions()
    profile = None
    for key in versions["versions_in_feed"]:
        version = versions["versions_in_feed"][key]
        if "eol" in version:
            eol_date = datetime.fromisoformat(re.sub(r'\..*', '', version["eol"]))
            if eol_date < datetime.now():
                continue
        if "release_date" in version:
            eol_date = datetime.fromisoformat(re.sub(r'\..*', '', version["release_date"]))
            eol_date = eol_date.replace(year=eol_date.year + 2)
            if eol_date < datetime.now():
                continue

        if version_digits == 1 and key.count('.') != 0:
            continue
        if version_digits == 2 and key.count('.') != 1:
            continue
        if version_digits == 3 and key.count('.') != 2:
            continue

        profile = nessus_api_handler.profiles.create(name=random_name(prefix='agent-profile-'),
                                               description="testing version in feed",
                                               config={"version": key})
        break
    if profile == None:
        return None

    yield profile

    created_uuids = [profile['profile_uuid']]

    try:
        nessus_api_handler.profiles.delete_profiles(uuid_list=created_uuids)
    except Exception:
        log.warning("Unable to delete profile in clean up. profile may have been deleted by test.")

@pytest.fixture()
def create_valid_profile_with_agents(request: 'SubRequest', nessus_api_handler: NessusAPI,
                                     create_valid_profile_endpoint,
                                     nessus_create_nessus_agent):

    profile = create_valid_profile_endpoint
    agent_ids = nessus_create_nessus_agent

    nessus_api_handler.profiles.add_profile_members(profile['profile_uuid'], "", agent_ids)

    yield profile
