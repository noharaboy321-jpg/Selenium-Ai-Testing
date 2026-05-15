"""
Server Helpers
:copyright: Tenable Network Security, 2017
:date: September 27, 2017
:author: @pellsworth
"""
# pylint: disable=invalid-name

from contextlib import contextmanager
import pytest
from requests import HTTPError
from catium.lib.util import is_ci_environment
from nessus.lib.const.constants import Nessus
from nessus.helpers.system import get_nessus_type

REQUIRED_MSG = '{} is required, {} is being tested against.'


# Decorators

# Skip tests if we're running in CICD mode. These tests usually depend on external resources.
# TODO: Remove this decorator and update tests once resources are available for testing (i.e. accessible from within AWS or resides in AWS)
aws_resource_required = pytest.mark.skipif(is_ci_environment(), reason='Test requires a resource accessible from within AWS')


def is_pro_7(properties) -> bool:
    """
    Determines if a Nessus is a Pro 7

    :param properties: Properties dictionary
    :return: bool
    """
    return 'npv7' in properties and (properties['npv7'] == 'yes' or properties['npv7'] == 1)


@contextmanager
def expect_http_error(code, message: str='', look_for: str=''):
    """
    Fails tests if the expected HTTP status code doesn't match the actual HTTP status code.
    Optionally accepts a look_for string to test for in the returned error.

    :param code: Expected error code
    :param str message: Mesaage to fail the test with
    :param str look_for: String to look for in the error text
    :return:
    """
    passed = False
    code_received = 0
    payload = ''
    error_message = ''

    if not message:
        message = 'Expected a {} return code'.format(str(code))

        if look_for:
            message += ' and "{}" in the error string'.format(str(look_for))

    try:
        yield
    except HTTPError as e:
        code_received = e.response.status_code
        # Setting 'passed' variable as True when response code is as expected
        passed = (code_received == code)

        # If some error text needs to be verified in the API response then updating 'passed' variable accordingly.
        if look_for:
            payload = e.response.json()
            if 'error' in payload:
                error_message = payload['error']
            passed = passed and look_for in error_message
    if not passed:
        pytest.xfail('Received code {}, error "{}" : {}'.format(str(code_received), str(error_message), message))
