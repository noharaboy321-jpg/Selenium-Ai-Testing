"""
    Fixtures for Policies

    :copyright: Tenable Network Security, 2017
    :date: Aug 08 2017
    :author: @ivargas jyerge
"""
from typing import TYPE_CHECKING

import pytest
from requests.exceptions import HTTPError

from catium.lib.log import create_logger
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.policy import create_policy_helper, upload_policy_helper

if TYPE_CHECKING:
    from catium.lib.typechecking import SubRequest

log = create_logger()


@pytest.fixture()
def create_policy(request: 'SubRequest', nessus_api_handler: NessusAPI, get_policy_templates):
    """
    :param request:  parameter values
    :param nessus_api_handler: API object to scanner
    :param get_policy_templates:  template name
    """
    log.debug('fixture init: Creates a new policy')

    policy_type = request.param['template_name'] if hasattr(request, 'param') and 'template_name' in request.param \
        else 'basic'

    policy = create_policy_helper(nessus_api_handler, get_policy_templates, policy_type=policy_type)

    yield policy

    log.debug('fixture teardown: create_policy: Remove policy %s', policy['policy_id'])
    if request.config.getoption('enable_cleanup') and \
            (request.config.getoption('cleanup_on_failure') or not getattr(request.cls, 'has_failed', False)):
        try:
            nessus_api_handler.policies.delete(policy['policy_id'])
        except HTTPError as exc:
            log.warning("Unable to delete policy in clean up. policy may have been deleted by test. Error:%s", exc)
    else:
        log.info('Policy still exists, with ID: %s %s', policy['policy_name'], policy['policy_id'])
        request.instance.cleanup_info = 'Policy ID: %s %s' % (policy['policy_name'], policy['policy_id'])


@pytest.fixture()
def upload_policy(request: "SubRequest", nessus_api_handler: NessusAPI):
    """
    :param request:  parameter values
    :param nessus_api_handler: API object to scanner
    """
    log.debug('fixture init: Uploads a new policy file')

    filepath = request.param['filepath']

    if type(filepath) == list:
        policies = []
        for file in filepath:
            policies.append(upload_policy_helper(filepath=file, api=nessus_api_handler))
        yield policies
    else:
        policy = upload_policy_helper(filepath=filepath, api=nessus_api_handler)
        policies = [policy]
        yield policy

    for policy in policies:
        log.debug('fixture teardown: create_policy: Remove policy %s', policy['id'])
        if request.config.getoption('enable_cleanup') and \
                (request.config.getoption('cleanup_on_failure') or not getattr(request.cls, 'has_failed', False)):
            try:
                nessus_api_handler.policies.delete(policy['id'])
            except HTTPError as exc:
                log.warning("Unable to delete policy in clean up. policy may have been deleted by test. Error:%s", exc)
        else:
            log.info('Policy still exists, with ID: %s %s', policy['name'], policy['id'])
            request.instance.cleanup_info = 'Policy ID: %s %s' % (policy['name'], policy['id'])
