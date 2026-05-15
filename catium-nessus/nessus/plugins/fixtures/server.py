"""
Fixtures for Server

:copyright: Tenable Network Security, 2017
:date: August 10 2018
:author: @rdutta
"""

from http import HTTPStatus

import pytest
from _pytest.fixtures import SubRequest

from catium.lib.api.base_api_object import ResponseObject
from catium.lib.log import create_logger
from catium.lib.ssh.ssh import SSH
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.nessuscli.helper import get_command, get_nessusd_messages, stop_nessus, start_nessus
from nessus.helpers.scanner import wait_for_scanner_to_be_ready
from nessus.lib.const.constants import SSHCommands

log = create_logger()


@pytest.fixture()
def configure_master_password(request: SubRequest) -> ResponseObject:
    """
    Fixture to add or modify master password
    example: 
        @pytest.mark.parametrize('configure_master_password', [{'new_password': 'admin',
                                                                'old_password': 'nessus}], indirect=True)
        
    above code will reset a master password
    """
    log.debug('fixture init: adding or modifying master password')
    try:
        request.cls.cat.api.server.edit_master_password(data=request.param)
        yield request.param.get('new_password')

    finally:
        response = request.cls.cat.api.server.get_master_password()
        if response.get('protected'):
            request.cls.cat.api.server.edit_master_password(data={'old_password': request.param.get('new_password')})
            assert request.cls.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % request.cls.cat.api.http_status_code
        else:
            log.info('Unable to revert set master password in clean up, it may have been reset by test or manually')


@pytest.fixture()
def enable_qa_mode_in_nessus(request: SubRequest):
    """"""
    with SSH() as ssh:
        if not [line for line in ssh.execute("{} {}".format(get_command(
                operation="display_content"), get_nessusd_messages())) if "QA-Mode enabled".lower() in line.lower()]:
            log.info("QA mode is not enabled already. Now trying to enable it.")
            if 'systemd' in ssh.execute("ps -p 1")[-1].lower():
                ssh.execute("sed -i '/\[Service\]/a Environment=NESSUS_QA_MODE=1' "
                            "/usr/lib/systemd/system/nessusd.service")
                ssh.execute("systemctl daemon-reload")
            else:
                ssh.execute("setx NESSUS_QA_MODE 1 /m")
            stop_nessus()
            start_nessus()
            api = NessusAPI()
            wait_for_scanner_to_be_ready(api=api)
            log.info([line for line in ssh.execute("{} {}".format(get_command(
                operation="display_content"), get_nessusd_messages())) if "QA-Mode enabled".lower() in line.lower()])
            log.info("Done with enabling QA mode")
        else:
            log.info("QA mode is already enabled.")
