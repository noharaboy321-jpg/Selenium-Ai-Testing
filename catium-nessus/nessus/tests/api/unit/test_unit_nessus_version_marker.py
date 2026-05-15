"""
Unit test of the version marker pytest plugin

:copyright: Tenable Network Security, 2017
:date: Oct 10 2017
:author: @djsmith
"""
import pytest


@pytest.mark.unittest
@pytest.mark.nessus_version(required_version='1.0.0')
@pytest.mark.usefixtures('nessus_class_api_login')
class TestNessusVersionMarker:
    """Unit tests for nessus version marker"""

    @pytest.mark.nessus_version(required_version='6.9.3')
    def test_version(self):
        pass

    @pytest.mark.nessus_version(required_type='Nessus Professional')
    def test_type(self):
        pass

    @pytest.mark.nessus_version(required_version='6.9.1', required_type='Nessus Professional')
    def test_version_and_type(self):
        pass

    @pytest.mark.nessus_version(required_version='6.9.1')
    @pytest.mark.nessus_version(required_type=['Nessus Professional', 'Nessus Manager'])
    def test_version_and_type_list(self):
        pass
