"""
Unit Test
"""
from http import HTTPStatus
import pytest


@pytest.mark.unittest
@pytest.mark.usefixtures('nessus_api_login')
class TestNessusAPIFixtures:
    """Test Nessus API Fixtures"""

    cat = None

    # API_Tested# GET /server/status
    def test_api_login(self):
        """Test API Login Fixture"""
        self.cat.api.server.status()
        assert self.cat.api.http_status_code == HTTPStatus.OK,\
            'Expected a {} response but got {} instead'.format(HTTPStatus.OK.value, self.cat.api.http_status_code)
