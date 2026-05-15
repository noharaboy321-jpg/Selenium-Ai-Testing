"""
Fixtures for Custom CA

:copyright: Tenable Network Security, 2017
:date: Aug 08 2018
:author: @rdutta
"""

import os
import pytest
from _pytest.fixtures import SubRequest

from catium.helpers.testdata import get_file_path
from catium.lib.api.base_api_object import ResponseObject
from catium.lib.log import create_logger
from nessus.helpers.nessuscli.logchecker import read_from_file

log = create_logger()


@pytest.fixture()
def add_custom_ca(request: SubRequest) -> ResponseObject:
    """
    Fixture to add custom_ca certificate
    example:
        @pytest.mark.parametrize("add_custom_ca", [{'cert_file':
            get_file_path('nessus/tests/ui/ca-cert/test_data/rdp.cer')}] , indirect=True)
    above code will save custom_ca certificate
    """
    log.debug('fixture init: adding custom certificate')
    try:
        ca_file = os.path.abspath(get_file_path(request.param['cert_file']))
        file_data = read_from_file(filename=ca_file)
        response = request.cls.cat.api.server.edit_custom_ca(cert_data=file_data)
        yield response

    finally:
        request.cls.cat.api.server.edit_custom_ca(cert_data="")
