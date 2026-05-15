"""
Fixtures to set Nessus Agents with New Updated Endpoints

:copyright: Tenable Network Security, 2018
:date: Aug 13, 2018
:author: @jamreliya
"""
from typing import TYPE_CHECKING

import pytest

from catium.lib.log import create_logger
from nessus.apiobjects.nessus_api import NessusAPI

if TYPE_CHECKING:
    from catium.lib.typechecking import SubRequest

log = create_logger()


@pytest.fixture()
def create_agent_group_with_new_endpoint(request: 'SubRequest', nessus_api_handler: NessusAPI):
    """
    Creates a new agent group
    # to create single group
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),)],
                             indirect=True)
                             
    # to create multiple groups                             
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),
                                                                    random_name(prefix='agent-group-'))],
                             indirect=True)
    """
    log.debug('fixture init: Create an agent group with updated end points')
    agent_groups = []
    for group in request.param:
        group_detail = nessus_api_handler.agent_groups.create_agent_group(name=group)
        group_detail.update({'name': group})
        agent_groups.append(group_detail)
    yield agent_groups

    for group in agent_groups:
        try:
            nessus_api_handler.agent_groups.delete_agent_group(group_id=group['id'])
        except Exception:
            log.warning("Unable to delete agent group in clean up. Group may have been deleted by test.")
