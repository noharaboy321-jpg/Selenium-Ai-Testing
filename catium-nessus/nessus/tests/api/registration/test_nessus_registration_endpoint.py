"""
Nessus Registration Endpoint verification
"""
import pytest

from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.server import expect_http_error


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
class TestNessusRegistrationEndpoint:
    """ Tests for Nessus Registration Endpoints """

    cat = None

    @pytest.mark.parametrize('test_data', [
        # errors in firstName (all spaces, empty string, missing)
        {'data': {'firstName': ' ', 'lastName': 'L', 'email': 'foo@example.com'},
         'code': 400, 'error': "Invalid 'firstName' field: bad format"},
        {'data': {'firstName': '', 'lastName': 'L', 'email': 'foo@example.com'},
         'code': 400, 'error': "Invalid 'firstName' field: missing"},
        {'data': {'lastName': 'L', 'email': 'foo@example.com'},
         'code': 400, 'error': "Invalid 'firstName' field: missing"},

        # errors in lastName (all spaces, empty string, missing)
        {'data': {'firstName': 'F', 'lastName': ' ', 'email': 'foo@example.com'},
         'code': 400, 'error': "Invalid 'lastName' field: bad format"},
        {'data': {'firstName': 'F', 'lastName': '', 'email': 'foo@example.com'},
         'code': 400, 'error': "Invalid 'lastName' field: missing"},
        {'data': {'firstName': 'F', 'email': 'foo@example.com'},
         'code': 400, 'error': "Invalid 'lastName' field: missing"},

        # errors in email (various malformations, empty string, missing)
        {'data': {'firstName': 'F', 'lastName': 'L', 'email': 'foo@example'},
         'code': 400, 'error': "Invalid 'email' field: bad format"},
        {'data': {'firstName': 'F', 'lastName': 'L', 'email': 'foo'},
         'code': 400, 'error': "Invalid 'email' field: bad format"},
        {'data': {'firstName': 'F', 'lastName': 'L', 'email': 'foo@example.'},
         'code': 400, 'error': "Invalid 'email' field: bad format"},
        {'data': {'firstName': 'F', 'lastName': 'L', 'email': '@example.com'},
         'code': 400, 'error': "Invalid 'email' field: bad format"},
        {'data': {'firstName': 'F', 'lastName': 'L', 'email': ''},
         'code': 400, 'error': "Invalid 'email' field: missing"},
        {'data': {'firstName': 'F', 'lastName': 'L'},
         'code': 400, 'error': "Invalid 'email' field: missing"}])
    # API_Tested# POST /registration/send-essentials-email
    def test_send_essentials_email(self, test_data):
        """
        Test the validation in our "send an activation email" API.
        We don't actually send the mail so as to avoid filling the production DB / CRM with unused licenses.

        Scenarios tested:
        [x] Validation of each field
        [ ] Triggering of the activation email
        [ ] Reception of the activation email
        """
        api = NessusAPI()

        with expect_http_error(code=test_data['code']):
            api.registration.send_essentials_email(**test_data['data'])

        if test_data['error']:
            assert test_data['error'] in api.http_text
