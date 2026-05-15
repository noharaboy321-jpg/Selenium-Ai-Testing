"""
custom_ca class to verify Certificate Authority

:copyright: Tenable Network Security, 2017
:date: Feb 13, 2018
:last_modified: March 01, 2019
:author: @jamreliya, @rdutta, @kpanchal

Note:
These Environment variables need to be added during the run for CLI Integration.
--> NESSUS_CLI_LOCAL=False
--> CAT_SSH_USERNAME=<machine_username>
--> CAT_SSH_PASSWORD=<machine_password>
"""

import os
import pytest

from catium.helpers.testdata import get_file_path
from catium.lib.const import WAIT_SHORT
from catium.lib.webium.wait import wait
from nessus.helpers.nessuscli.helper import get_nessus_plugin_dir
from nessus.helpers.nessuscli.logchecker import read_from_file, read_from_file_on_remote
from nessus.lib.const import NessusCli
from nessus.lib.message.messages import Messages
from nessus.pageobjects.custom_ca.custom_ca_page import CustomCAPage
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.shared.loading import LoadingCircle

PATH_TO_CERTIFICATE = 'nessus/tests/ui/ca-cert/test_data/rdp.cer'
PATH_TO_CERTIFICATE_WITH_EXTRA_CHAR = 'nessus/tests/ui/ca-cert/test_data/rdp_with_extra_char.cer'


@pytest.mark.nessus_settings_1
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_legacy
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestCustomCA:
    """
    Covers Custom CA related test cases
    # NQA-1087 : Automation tests for Settings - Custom CA
    """

    @pytest.mark.parametrize("add_custom_ca", [{'file_path': get_file_path(PATH_TO_CERTIFICATE)}], indirect=True)
    def test_verify_custom_ca(self, add_custom_ca):
        """
        NQA-1087: Automation tests for Settings - Custom CA.
        NES-8929: Fix about, custom CA and login page related skipped test cases

        1. Navigate to Custom CA and Copy content of attached file to Custom CA.
        2. Click on save. It should save certificate.
        """

        assert Notifications().successes[-1] == Messages.NotificationMessages.custom_ca_updated, \
            'Error in Custom CA certificate, not saved successfully.'

    @pytest.mark.parametrize("add_custom_ca", [{'file_path': get_file_path(PATH_TO_CERTIFICATE)}], indirect=True)
    def test_verify_custom_ca_inc(self, add_custom_ca):
        """
        NQA-1087: Automation tests for Settings - Custom CA.
        NES-8929: Fix about, custom CA and login page related skipped test cases

        3. Navigate to plugin folder and verify content of custom_ca.inc file. It should be same as custom CA.
        """
        inc_file_data = read_from_file_on_remote(filename=os.path.join(get_nessus_plugin_dir(),
                                                                       NessusCli.CUSTOM_CA_INC))

        custom_ca_page = CustomCAPage()
        custom_ca_page.open()
        custom_ca_text = custom_ca_page.certificate_field.text

        assert custom_ca_text == inc_file_data, 'custom_ca.inc file content not same as custom_ca certificate.'

    @pytest.mark.parametrize("add_custom_ca", [{'file_path': get_file_path(PATH_TO_CERTIFICATE)}], indirect=True)
    @pytest.mark.xfail(reason="Refer JIRA ID: NES-18091")
    def test_add_extra_char_custom_ca(self, add_custom_ca):
        """
        NQA-1087: Automation tests for Settings - Custom CA.
        NES-8929: Fix about, custom CA and login page related skipped test cases

        4. Add extra char to custom CA and click save. It should throw error
        5. Verify custom_ca.inc file again and extra char should not be added.
        """

        assert Notifications().successes[-1] == Messages.NotificationMessages.custom_ca_updated, \
            'Error in Custom CA certificate, not saved successfully'

        custom_ca_with_extra_char = read_from_file(filename=get_file_path(PATH_TO_CERTIFICATE_WITH_EXTRA_CHAR))
        custom_ca_page = CustomCAPage()
        custom_ca_page.open()
        LoadingCircle(WAIT_SHORT)
        original_custom_ca = custom_ca_page.certificate_field.text
        LoadingCircle(WAIT_SHORT)
        custom_ca_page.add_custom_ca(ca_value=custom_ca_with_extra_char)

        assert Notifications().errors[-1] == Messages.NotificationMessages.invalid_custom_ca, \
            'Custom CA certificate saved with extra chars'

        inc_file_data = read_from_file_on_remote(filename=os.path.join(get_nessus_plugin_dir(),
                                                                       NessusCli.CUSTOM_CA_INC))

        assert original_custom_ca.rstrip('\n') == inc_file_data, 'custom_ca.inc file content not same as custom_ca ' \
                                                                 'certificate, extra chars might added to inc file'
