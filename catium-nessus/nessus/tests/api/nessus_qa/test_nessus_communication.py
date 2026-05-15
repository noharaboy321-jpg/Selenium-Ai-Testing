"""
:copyright: Tenable Network Security, 2018
:date: June 6, 2017
:last_modified: Nov 13, 2020
:author: @cdombrowski, @kpanchal
"""
import json
import re
from http import HTTPStatus

import pytest
from requests import HTTPError

from catium.helpers.testdata import get_file_path
from catium.lib.config import Config
from catium.lib.const.base_constants import TIME_THIRTY_MINUTES
from catium.lib.const.mailcatcher_constants import Mailcatcher
from catium.lib.log import create_logger
from catium.lib.mailcatcher.retrieve_mail import MailRetriever
from catium.lib.util.util import load_testdata, random_name
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.scan import create_scan_helper
from nessus.helpers.server import aws_resource_required
from nessus.helpers.waiters import wait_scan_state
from nessus.lib.const import API

log = create_logger()


@aws_resource_required
@pytest.mark.nessus_manager
@pytest.mark.smoke
@pytest.mark.usefixtures('nessus_api_login', 'load_test_data')
@pytest.mark.parametrize('test_data_file', ['nessus/tests/api/nessus_qa/test_data/test_nessus_communication.json'])
class TestLDAPServerEndpoints:
    """
    Class will handle testing Nessus ability to communication via LDAP.
    Tests will include logging in with LDAP, searching for LDAP user, creating new LDAP user and more.
    """

    cat = None

    # API_Tested# POST /settings/network/ldap/test
    def test_nessus_ldap_test_invalid_ldap_without_save(self, load_test_data):
        """
        STA-77: Implement test case for /settings/network/ldap, /settings/network/ldap/search, and
        /settings/network/ldap/test

        Tests that an error is returned when testing Invalid LDAP Settings if the settings have not been saved.

        Scenarios tested:
          [x] Successfully return error when testing invalid LDAP settings
        """
        settings = load_test_data["bad_ldap_info"]

        with pytest.raises(HTTPError):
            self.cat.api.settings.test_ldap_settings(settings=settings)

        assert self.cat.api.http_status_code == HTTPStatus.INTERNAL_SERVER_ERROR, \
            'Expected 500 error to return, however %s returned' % self.cat.api.http_status_code

    # API_Tested# GET /settings/network/ldap
    # API_Tested# PUT /settings/network/ldap
    @pytest.mark.parametrize('attribs', (API.Settings.Ldap.Attributes.WITH_ATTRIBUTES,
                                         API.Settings.Ldap.Attributes.WITHOUT_ATTRIBUTES))
    def test_nessus_ldap_save_settings(self, load_test_data, attribs: dict):
        """
        STA-77: Implement test case for /settings/network/ldap, /settings/network/ldap/search, and
        /settings/network/ldap/test

        Tests we are able to save our LDAP settings (with and without advanced settings) via the Nessus API.

        Scenarios tested:
          [x] Successfully set LDAP settings
          [x] Successfully get LDAP settings
        """
        settings_dict = {**load_test_data["ldap_server"], **attribs}
        self.cat.api.settings.set_ldap_settings(settings=settings_dict)
        ldap_details = self.cat.api.settings.get_ldap_settings()

        assert all([self.cat.api.http_status_code == HTTPStatus.OK,
                    settings_dict['ldap_username_attribute'] == ldap_details['ldap_username_attribute']]), \
            'Failed to save LDAP Settings.'

    # API_Tested# POST /settings/network/ldap/test
    @pytest.mark.parametrize('attribs', (API.Settings.Ldap.Attributes.WITH_ATTRIBUTES,
                                         API.Settings.Ldap.Attributes.WITHOUT_ATTRIBUTES))
    def test_nessus_ldap_test_settings(self, load_test_data, attribs: dict):
        """
        STA-77: Implement test case for /settings/network/ldap, /settings/network/ldap/search, and
        /settings/network/ldap/test

        Tests that we are able to test LDAP settings (with and without advanced settings) without saving via the Nessus
        API.

        Scenarios tested:
          [x] Successfully testing valid LDAP settings
        """
        settings_dict = {**load_test_data["ldap_server"], **attribs}
        response = self.cat.api.settings.test_ldap_settings(settings=settings_dict)

        assert response['code'] == 0 and self.cat.api.http_status_code == HTTPStatus.OK, \
            'Failed to test LDAP Settings without saving.'

    # API_Tested# GET /settings/network/ldap
    # API_Tested# PUT /settings/network/ldap
    # API_Tested# POST /settings/network/ldap/test
    @pytest.mark.parametrize('attribs', (API.Settings.Ldap.Attributes.WITH_ATTRIBUTES,
                                         API.Settings.Ldap.Attributes.WITHOUT_ATTRIBUTES))
    def test_nessus_ldap_test_settings_after_saving(self, load_test_data, attribs: dict):
        """
        STA-77: Implement test case for /settings/network/ldap, /settings/network/ldap/search, and
        /settings/network/ldap/test

        Tests that we are able to test LDAP settings (with and without advanced settings) after saving via the Nessus
        API.

        Scenarios tested:
          [x] Successfully set LDAP settings
          [x] Successfully get LDAP settings
          [x] Successfully testing the LDAP settings we just set
        """
        settings_dict = {**load_test_data["ldap_server"], **attribs}
        self.cat.api.settings.set_ldap_settings(settings=settings_dict)

        ldap_details = self.cat.api.settings.get_ldap_settings()
        response = self.cat.api.settings.test_ldap_settings(ldap_details)
        username = load_test_data["ldap_server"]['ldap_username']

        assert response['code'] == 0 and self.cat.api.http_status_code == HTTPStatus.OK and username == response[
            'user'][0]['username'], 'Failed to test LDAP Settings without saving.'

    # API_Tested# GET /users
    # API_Tested# PUT /settings/network/ldap
    @pytest.mark.parametrize('attribs', (API.Settings.Ldap.Attributes.WITH_ATTRIBUTES,
                                         API.Settings.Ldap.Attributes.WITHOUT_ATTRIBUTES))
    @pytest.mark.parametrize('nessus_create_parametrized_ldap_user', [(API.Settings.Ldap.WITH_ATTRIBUTES_USERNAME,
                                                                       API.Permissions.User.BASIC,
                                                                       API.User.Types.LDAP)], indirect=True)
    def test_nessus_ldap_create_user(self, load_test_data, nessus_create_parametrized_ldap_user, attribs: dict):
        """
        STA-77: Implement test case for /settings/network/ldap, /settings/network/ldap/search, and
        /settings/network/ldap/test

        Tests that we are able to create an LDAP user (with and without LDAP advanced settings) via the Nessus
        API.

        Scenarios tested:
          [x] Successfully add LDAP user
        """
        settings_dict = {**load_test_data["ldap_server"], **attribs}
        self.cat.api.settings.set_ldap_settings(settings=settings_dict)

        permissions = self.cat.user_details['permissions']
        user_type = self.cat.api.users.get(nessus_create_parametrized_ldap_user['id'])['type']
        username = self.cat.api.users.get(nessus_create_parametrized_ldap_user['id'])['name']

        assert all([user_type == API.User.Types.LDAP, permissions == API.Permissions.User.BASIC,
                    username == API.Settings.Ldap.WITH_ATTRIBUTES_USERNAME]), \
            'Unable to create LDAP User.'

    # API_Tested# GET /users/{user_id}
    # API_Tested# PUT /settings/network/ldap
    @pytest.mark.parametrize('attribs', (API.Settings.Ldap.Attributes.WITH_ATTRIBUTES,
                                         API.Settings.Ldap.Attributes.WITHOUT_ATTRIBUTES))
    @pytest.mark.parametrize('nessus_create_parametrized_ldap_user', [(API.Settings.Ldap.LDAP_TESTER_USERNAME,
                                                                       API.Permissions.User.BASIC,
                                                                       API.User.Types.LDAP)], indirect=True)
    def test_nessus_ldap_verify_tester_user(self, load_test_data, attribs: dict, nessus_create_parametrized_ldap_user):
        """
        STA-77: Implement test case for /settings/network/ldap, /settings/network/ldap/search, and
        /settings/network/ldap/test

        Tests that we are able to verify all attributes of the LDAP user tester (with and without LDAP advanced
        settings) via the Nessus API.

        Scenarios:
            [x] Test correct attributes of LDAP user testers
        """
        settings_dict = {**load_test_data["ldap_server"], **attribs}
        self.cat.api.settings.set_ldap_settings(settings=settings_dict)
        user_info = self.cat.api.users.get(nessus_create_parametrized_ldap_user['id'])

        assert all([user_info['type'] == API.User.Types.LDAP, user_info['permissions'] == API.Permissions.User.BASIC,
                    user_info['email'] == API.Settings.Ldap.LDAP_TESTER_EMAIL, 'container_id' in user_info,
                    user_info['lockout'] is False, user_info['username'] == API.Settings.Ldap.LDAP_TESTER_USERNAME,
                    user_info['name'] == API.Settings.Ldap.LDAP_TESTER_NAME]), \
            'Unable to verify the LDAP user\'s details.'

    # API_Tested# PUT /settings/network/ldap
    # API_Tested# POST /session
    @pytest.mark.parametrize('nessus_create_parametrized_ldap_user', [(API.Settings.Ldap.LDAP_ADMINISTRATOR_USERNAME,
                                                                       API.Permissions.User.STANDARD,
                                                                       API.User.Types.LDAP)], indirect=True)
    def test_nessus_ldap_verify_administrator_login(self, load_test_data, nessus_create_parametrized_ldap_user):
        """
        STA-77: Implement test case for /settings/network/ldap, /settings/network/ldap/search, and
        /settings/network/ldap/test

        Tests that we are able to log in to Nessus as the LDAP user 'Administrator'.

        Scenarios tested:
          [x] Successfully add a LDAP user and login with the user
        """
        settings_dict = {**load_test_data["ldap_server"], **load_test_data["without_attributes"]}
        self.cat.api.settings.set_ldap_settings(settings=settings_dict)

        api = NessusAPI()
        api.login(username=API.Settings.Ldap.LDAP_ADMINISTRATOR_USERNAME,
                  password=API.Settings.Ldap.LDAP_ADMINISTRATOR_PASSWORD)

        token = json.loads(api.http_text)['token']
        api.logout()

        assert api.http_status_code == HTTPStatus.OK and len(token) == 48, \
            'Unable to log in as the LDAP Administrator user.'

    # API_Tested# POST /settings/network/ldap/search
    # API_Tested# PUT /settings/network/ldap
    @pytest.mark.parametrize('attribs', (API.Settings.Ldap.Attributes.WITH_ATTRIBUTES,
                                         API.Settings.Ldap.Attributes.WITHOUT_ATTRIBUTES))
    def test_nessus_ldap_search_user(self, load_test_data, attribs: dict):
        """
        STA-77: Implement test case for /settings/network/ldap, /settings/network/ldap/search, and
        /settings/network/ldap/test

        Tests that we are able to search for a LDAP user (with and without LDAP advanced settings) via the Nessus
        API.

        Scenarios tested:
          [x] Successfully search and found the LDAP user
        """
        settings_dict = {**load_test_data["ldap_server"], **attribs}
        self.cat.api.settings.set_ldap_settings(settings=settings_dict)
        user_details = self.cat.api.settings.search_ldap(name=API.Settings.Ldap.LDAP_TESTER_USERNAME)

        assert user_details['user'] and user_details['user'][0]['username'] == API.Settings.Ldap.LDAP_TESTER_USERNAME, \
            'Failed to find the specified LDAP user.'


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_manager
@pytest.mark.smoke
@pytest.mark.usefixtures('nessus_api_login', 'load_test_data')
@pytest.mark.parametrize('test_data_file', ['nessus/tests/api/nessus_qa/test_data/test_nessus_communication.json'])
class TestSMTPServerEndpoints:
    """
    Class will handle testing Nessus ability to communication via SMTP.
    Tests will include logging in with SMTP, sending testing e-mail via SMTP and more.
    """

    cat = None

    # API_Tested# POST /settings/network/mail/test
    def test_nessus_smtp_test_invalid_smtp_without_save(self, load_test_data):
        """
        STA-78: Implement test case for /settings/network/mail and /settings/network/mail/test

        Tests that an error is returned when testing Invalid SMTP Settings if the settings have not been saved.
        """
        settings = load_test_data["invalid_smtp_info"]

        with pytest.raises(HTTPError):
            self.cat.api.settings.test_smtp_settings(settings=settings)

        assert self.cat.api.http_status_code == HTTPStatus.INTERNAL_SERVER_ERROR, \
            'Expected 500 error to return, however %s returned' % self.cat.api.http_status_code

    # API_Tested# POST /settings/network/mail/test
    @pytest.mark.incompatible
    def test_nessus_smtp_test_settings(self, load_test_data):
        """
        STA-78: Implement test case for /settings/network/mail and /settings/network/mail/test

        Tests that we are able to test SMTP settings without saving via the Nessus API.

        Scenarios tested:
          [x] Successfully test the SMPT settings are valid
          [ ] Failed the test result when the SMPT settings are invalid
        """
        info_block = "grid_smtp_info" if Config.CAT_USE_GRID else "local_smtp_info"
        settings_dict = load_test_data[info_block]

        response = self.cat.api.settings.test_smtp_settings(settings=settings_dict)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert API.Settings.Smtp.TEST_EMAIL_SUCCESSFUL in response['message'], \
            'Sending test e-mail failed, unable to test SMTP Settings.'

    # API_Tested# GET /settings/network/mail
    # API_Tested# PUT /settings/network/mail
    def test_nessus_smtp_save_settings(self, load_test_data):
        """
        STA-78: Implement test case for /settings/network/mail and /settings/network/mail/test

        Tests that we are able to save the SMTP Settings via the Nessus API.

        Scenarios tested:
          [x] Successfully set the SMTP settings
        """
        info_block = "grid_smtp_info" if Config.CAT_USE_GRID else "local_smtp_info"
        settings_dict = load_test_data[info_block]

        self.cat.api.settings.set_smtp_settings(settings=settings_dict)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        smtp_details = self.cat.api.settings.get_smtp_settings()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert smtp_details.keys() == settings_dict.keys(), 'SMTP Settings failed to save.'

    # API_Tested# GET /settings/network/mail
    # API_Tested# PUT /settings/network/mail
    def test_nessus_smtp_default_settings(self, load_test_data):
        """
        STA-78: Implement test case for /settings/network/mail and /settings/network/mail/test

        Tests that we are able to set the SMTP Settings back to default values.

        Scenarios tested:
          [x] Successfully set the SMPT settings
        """
        settings_dict = load_test_data["default_smtp_settings"]

        self.cat.api.settings.set_smtp_settings(settings=settings_dict)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        smtp_details = self.cat.api.settings.get_smtp_settings()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert smtp_details.keys() == settings_dict.keys(), 'SMTP Settings failed to save.'

    # API_Tested# PUT /settings/network/mail
    # API_Tested# POST /settings/network/mail/test
    @pytest.mark.parametrize('scan_data_file', [
        (get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'), 'advanced')])
    @pytest.mark.parametrize('encryption_type', API.Settings.Smtp.SMTP_ENCRYPTION_TYPE)
    def test_scan_report_not_sent_when_smtp_connection_failed(self, load_test_data, scan_data_file, encryption_type):
        """
        NES-12209: [API] [Negative] Scan report is not sent when SMTP connect failed

        Scenarios tested:
          [x] Scan report is not sent when SMTP connect failed (with all encryption types supported for SMTP settings)
        """
        recipient_mail = '{}{}'.format(random_name(prefix='to-'), Mailcatcher.Server.EMAIL_DOMAIN)

        smtp_settings = load_test_data["invalid_smtp_info"]
        smtp_settings['smtp_enc'] = encryption_type

        self.cat.api.settings.set_smtp_settings(settings=smtp_settings)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        with pytest.raises(HTTPError):
            self.cat.api.settings.test_smtp_settings(settings=smtp_settings)

        assert self.cat.api.http_status_code == HTTPStatus.INTERNAL_SERVER_ERROR, \
            'Expected 500 error to return, however %s returned' % self.cat.api.http_status_code

        scan_details = create_scan_helper(self.cat.api, file_name=scan_data_file[0], template_title=scan_data_file[1])
        scan_id = scan_details[0]['scan']['id']

        payload = load_testdata(scan_data_file[0])
        payload['settings']['emails'] = recipient_mail
        self.cat.api.scans.configure(scan_id, payload)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        self.cat.api.scans.launch(scan_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                               timeout=TIME_THIRTY_MINUTES)

        # Search sent mail from received mails
        found_mail = MailRetriever().search_email(API.Settings.Smtp.SMTP_SENDER_EMAIL, [recipient_mail])
        log.info('Received scan result email :: :: {}'.format(found_mail))

        # Verify that User does not receive scan result email when SMTP connection failed
        assert not found_mail, 'Found the scan results email.'

    # API_Tested# PUT /settings/network/mail
    # API_Tested# POST /settings/network/mail/test
    @pytest.mark.flaky_test
    @pytest.mark.parametrize('scan_data_file', [
        (get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'), 'advanced')])
    def test_user_receives_scan_report_after_scan_gets_completed(self, load_test_data, scan_data_file):
        """
        NES-12261: [API] Verify email notification of scan completion

        Scenarios tested:
          [x] Verify email notification of scan completion
        """
        recipient_mail = '{}{}'.format(random_name(prefix='to-'), Mailcatcher.Server.EMAIL_DOMAIN)
        smtp_settings = load_test_data["grid_smtp_info"]

        self.cat.api.settings.set_smtp_settings(settings=smtp_settings)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        self.cat.api.settings.test_smtp_settings(settings=smtp_settings)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        scan_details = create_scan_helper(self.cat.api, file_name=scan_data_file[0], template_title=scan_data_file[1])
        scan_id = scan_details[0]['scan']['id']

        payload = load_testdata(scan_data_file[0])
        payload['settings']['emails'] = recipient_mail
        self.cat.api.scans.configure(scan_id, payload)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        self.cat.api.scans.launch(scan_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                               timeout=TIME_THIRTY_MINUTES)

        # Search sent mail from received mails
        found_mail = MailRetriever().search_email(API.Settings.Smtp.SMTP_SENDER_EMAIL, [recipient_mail])
        log.info('Received scan result email :: :: {}'.format(found_mail))

        # Verify that User actually receives scan result email successfully
        assert found_mail, 'The mail search did not find the correct email.'

        # Verify sender email id from received scan result email
        assert re.sub('[(){}<>]', '', found_mail[0][Mailcatcher.EmailArrtibutes.SENDER]) == API.Settings.Smtp. \
            SMTP_SENDER_EMAIL, 'Getting incorrect email sender for scan result email.'

        scan_result_email_subject = API.Settings.Smtp.SCAN_RESULT_EMAIL_SUBJECT + scan_details[0]['scan']['name']

        # Verify subject name from received scan result email
        assert found_mail[0][Mailcatcher.EmailArrtibutes.SUBJECT] == scan_result_email_subject, \
            'Getting incorrect email subject for scan result email.'
