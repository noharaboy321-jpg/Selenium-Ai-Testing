"""
Nessus Blackout window (Exclusion) Endpoint verification

Test cases for create and delete blackout window (Exclusion)

:copyright: Tenable Network Security, 2017
:date: Apr 19, 2017
:last_modified: Oct 30, 2020
:author: @jamreliya, @dkothari, @kpanchal
"""
import json
from datetime import datetime, timedelta
from http import HTTPStatus

import pytest
from requests.exceptions import HTTPError

from catium.lib.log.log import create_logger
from catium.lib.util.util import random_name

log = create_logger()


@pytest.mark.nessus_manager
@pytest.mark.smoke
@pytest.mark.usefixtures('nessus_api_login')
class TestNessusBlackoutWindowEndpoint:
    """Tests for Nessus Blackout window (Exclusion) Endpoint"""

    cat = None

    # create blackout window
    # NQA- 623
    # API_Tested# POST /scanners/{scanner_id}/agents/exclusions
    def test_create_exclusion(self, create_exclusion):
        """Verifies exclusion can be created"""

        # call create_exclusion fixture to create blackout window
        created_exclusion_id, scanner_id = create_exclusion[0]['id'], create_exclusion[1]

        # get list of blackout window list
        exclusions = self.cat.api.exclusions.get_exclusions(scanner_id)['exclusions']

        # verify created blackout window is present in the list or not
        assert created_exclusion_id in [exclusion['id'] for exclusion in exclusions], 'Failed to create exclusion'

    # NQA- 624
    # API_Tested# DELETE /scanners/{scanner_id}/agents/exclusions/{exclusion_id}
    def test_delete_exclusion(self, create_exclusion):
        """Verifies exclusion can be deleted"""

        # call create_exclusion fixture to create blackout window
        created_exclusion_id, scanner_id = create_exclusion[0]['id'], create_exclusion[1]

        #  delete exclusion (blackout) window
        self.cat.api.exclusions.delete(created_exclusion_id, scanner_id)

        #  get list of blackout window
        exclusions = self.cat.api.exclusions.get_exclusions(scanner_id)['exclusions']

        assert created_exclusion_id not in [exclusion['id'] for exclusion in exclusions], \
            'Failed to delete exclusion ID #%s' % created_exclusion_id

    # NES-8900
    # API_Tested# GET /scanners/{scanner_id}/agents/exclusions/{exclusion_id:int}
    def test_get_blackout_window_details(self, create_exclusion):
        """
        NES-8900: Create tests for scanners GET /scanners/{scanner_id}/agents/exclusions/{exclusion_id:int}

        Scenarios tested:
            [x] Successfully get the blackout window details
        """
        created_exclusion_id, scanner_id = create_exclusion[0]['id'], create_exclusion[1]
        exclusion_details = self.cat.api.scanners.get_blackout_window_details(scanner_id, created_exclusion_id)

        # get list of blackout window list
        exclusions = self.cat.api.exclusions.get_exclusions(scanner_id)['exclusions']

        assert exclusion_details['id'] in [exclusion['id'] for exclusion in exclusions], 'Failed to get exclusion'

    # NES-8900
    # API_Tested# PUT /scanners/{scanner_id}/agents/exclusions/{exclusion_id:int}
    def test_edit_blackout_window_details(self, create_exclusion):
        """
        NES-8900: Create tests for scanners PUT /scanners/{scanner_id}/agents/exclusions/{exclusion_id:int}

        Scenarios tested:
            [x] Successfully edit the blackout window details
        """
        created_exclusion_id, scanner_id = create_exclusion[0]['id'], create_exclusion[1]
        updated_exclusion_payload = {"name": 'Edited {}'.format(create_exclusion[0]['name']),
                                     "description": "Edited exclusion for {}.".format(create_exclusion[0]['name'])}

        self.cat.api.scanners.edit_blackout_window_details(scanner_id, created_exclusion_id, updated_exclusion_payload)
        exclusion_details = self.cat.api.scanners.get_blackout_window_details(scanner_id, created_exclusion_id)

        assert exclusion_details['name'] == updated_exclusion_payload['name'], \
            'Error while setting name to %s ' % format(updated_exclusion_payload['name'])

        assert exclusion_details['description'] == updated_exclusion_payload['description'], \
            'Error while setting description to %s ' % format(updated_exclusion_payload['description'])

    # API_Tested# GET /scanners/{scanner_id}/agents/exclusions
    def test_get_agent_exclusions_list(self, create_exclusion):
        """
        #STA-8: Add endpoints to agents.py.
        Verifies that exclusion list can be retrieved

        Scenarios tested:
        [X] Get exclusion list

        Note: Verify the data retrieved is expected (e.g. empty list, or null)
        """
        exclusion_name = create_exclusion[0]['name']
        exclusion_list = self.cat.api.agents.exclusions_list()['exclusions']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code

        assert exclusion_name in [exclusion['name'] for exclusion in exclusion_list], \
            'Exclusion list cannot be retrieved'

    # API_Tested# POST /scanners/{scanner_id}/agents/exclusions
    # API_Tested# GET /scanners/{scanner_id}/agents/exclusions
    # API_Tested# DELETE /scanners/{scanner_id}/agents/exclusions/{exclusion_id}
    def test_add_exclusion(self):
        """
        #STA-8: Add endpoints to agents.py.
        Verifies that exclusion can be added

        Scenarios tested:
        [X] Items are added to the exclusion list
        [ ] Add exclusion without name
        [ ] Add exclusion with duplicate name as another exclusion
        """
        data = {"name": random_name('exclusion-'), "description": "", "agent_group_id": None,
                "schedule": {"enabled": True,
                             "rrules": {"freq": "MONTHLY", "interval": 1,
                                        "bysetpos": 4, "byweekday": "2"},
                             "timezone": "America/New_York",
                             "starttime": datetime.now().strftime('%Y-%m-%d %H') + ":00:00",
                             "endtime": datetime.now().strftime('%Y-%m-%d %H') + ":30:00"}}

        created_exclusion = self.cat.api.agents.exclusions_add(data=data)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code

        exclusion_list = self.cat.api.agents.exclusions_list()['exclusions']

        assert created_exclusion['id'] in [exclusion['id'] for exclusion in exclusion_list], \
            'Failed to create exclusion'

        # delete added exclusion
        self.cat.api.agents.remove_exclusion(exclusion_id=created_exclusion['id'])

    # API_Tested# GET /scanners/{scanner_id}/agents/exclusions/{exclusion_id}
    def test_get_exclusion_details(self, create_exclusion):
        """
        #STA-8: Add endpoints to agents.py.
        Verifies that exclusion details can be retrieved

        Scenarios tested:
        [X] Get details of an exclusion item
        [ ] Get details of an exclusion item that does not exist

        """
        exclusion_id = create_exclusion[0]['id']

        exclusion_detail = self.cat.api.agents.get_exclusion(exclusion_id=exclusion_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code

        assert create_exclusion[0] == exclusion_detail, 'Exclusion detail is incorrect or missing'

    # API_Tested# PUT /scanners/{scanner_id}/agents/exclusions/{exclusion_id}
    def test_edit_exclusion(self, create_exclusion):
        """
        #STA-8: Add endpoints to agents.py.
        Verifies that exclusion can be edited

        Scenarios tested:
        [X] Edit the exclusions
        [ ] Edit with invalid values

        """
        exclusion_id = create_exclusion[0]['id']

        data = {"name": random_name('exclusion-'), "description": "", "agent_group_id": None,
                "schedule": {"enabled": True,
                             "rrules": {"freq": "YEARLY", "interval": 1},
                             "timezone": "America/New_York",
                             "starttime": datetime.now().strftime('%Y-%m-%d %H') + ":00:00",
                             "endtime": datetime.now().strftime('%Y-%m-%d %H') + ":30:00"}
                }

        edited_exclusion_detail = self.cat.api.agents.edit_exclusion(exclusion_id=exclusion_id, data=data)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code

        assert edited_exclusion_detail == self.cat.api.agents.get_exclusion(
            exclusion_id=exclusion_id) and create_exclusion[0] != self.cat.api.agents.get_exclusion(
            exclusion_id=exclusion_id), 'Edited exclusion details is incorrect or missing'

    # API_Tested# DELETE /scanners/{scanner_id}/agents/exclusions/{exclusion_id}
    def test_remove_exclusion(self, create_exclusion):
        """
        #STA-8: Add endpoints to agents.py.
        Verifies that exclusion can be deleted/removed

        Scenarios tested:
        [X] Add and delete exclusion
        [ ] Delete non-existent exclusion

        """
        exclusion_id = create_exclusion[0]['id']

        self.cat.api.agents.remove_exclusion(exclusion_id=exclusion_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code

        exclusion_list = self.cat.api.agents.exclusions_list()['exclusions']

        assert exclusion_list is None or exclusion_id not in [exclusion['id'] for exclusion in exclusion_list], \
            'Exclusion is not deleted'

    # API_Tested# POST /scanners/{scanner_id}/agents/exclusions
    # API_Tested# DELETE /scanners/{scanner_id}/agents/exclusions/{exclusion_id}
    def test_duplicate_or_empty_blackout_window_names_not_allowed(self):
        """
        NES-12169: [Negative] Verify duplicate b/w names are not allowed

        Scenarios tested:
            [x] Verify duplicate or empty blackout window names are not allowed.
        """
        blackout_window_name = random_name('blackout_window-')
        created_blackout_window_details = {}

        scanner_id = self.cat.api.scanners.get_list()['scanners'][0]['id']  # get first scanner id
        date = datetime.now().strftime('%Y-%m-%d %H')

        payload = {"name": blackout_window_name, "description": "", "agent_group_id": None,
                   "schedule": {"enabled": True,
                                "rrules": {"freq": "MONTHLY", "interval": 1, "bysetpos": 4, "byweekday": "2"},
                                "timezone": "America/New_York", "starttime": date + ":00:00",
                                "endtime": date + ":30:00"}}
        try:
            if blackout_window_name:
                created_blackout_window_details = self.cat.api.exclusions.create(scanner_id, payload)

                assert self.cat.api.http_status_code == HTTPStatus.OK, \
                    'Expected 200, got %s instead.' % self.cat.api.http_status_code

            with pytest.raises(HTTPError):
                self.cat.api.exclusions.create(scanner_id, payload)

            assert self.cat.api.http_status_code == HTTPStatus.BAD_REQUEST, \
                'Expected 400, got %s instead.' % self.cat.api.http_status_code

            expected_error_msgs = {blackout_window_name: "A freeze window with that name already exists",
                                   '': "The freeze window name can not be empty",
                                   None: "A freeze window name must be provided"}
            error_msg_from_response = json.loads(self.cat.api.http_text)['error']

            assert error_msg_from_response == expected_error_msgs[blackout_window_name], \
                "Expected '{}' error msg, got '{}' instead.".format(expected_error_msgs[blackout_window_name],
                                                                    error_msg_from_response)
        finally:
            if blackout_window_name:
                self.cat.api.exclusions.delete(created_blackout_window_details['id'], scanner_id)

    # API_Tested# PUT /scanners/{scanner_id}/agents/exclusions
    # API_Tested# DELETE /scanners/{scanner_id}/agents/exclusions/{exclusion_id}
    @pytest.mark.parametrize('blackout_window_name', [True, False])
    def test_duplicate_or_empty_blackout_window_names_not_allowed_while_edit(self, create_exclusion,
                                                                             blackout_window_name):
        """
        NES-12169: [Negative] Verify duplicate b/w names are not allowed

        Scenarios tested:
            [x] When user edits existing Blackout window name, and finds duplicate
        """
        existing_blackout_window_details = create_exclusion[0]
        scanner_id = self.cat.api.scanners.get_list()['scanners'][0]['id']  # get first scanner id
        date = datetime.now().strftime('%Y-%m-%d %H')

        payload = {"name": random_name('blackout_window-'), "description": "", "agent_group_id": None,
                   "schedule": {"enabled": True,
                                "rrules": {"freq": "MONTHLY", "interval": 1, "bysetpos": 4, "byweekday": "2"},
                                "timezone": "America/New_York", "starttime": date + ":00:00",
                                "endtime": date + ":30:00"}}

        created_blackout_window_details = self.cat.api.exclusions.create(scanner_id, payload)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        edited_blackout_window_name = existing_blackout_window_details['name'] if blackout_window_name else ''
        payload['name'] = edited_blackout_window_name

        with pytest.raises(HTTPError):
            self.cat.api.agents.edit_exclusion(exclusion_id=created_blackout_window_details['id'], data=payload)

        assert self.cat.api.http_status_code == HTTPStatus.BAD_REQUEST, \
            'Expected 400, got %s instead.' % self.cat.api.http_status_code

        expected_error_msg = "A freeze window with that name already exists" if blackout_window_name else \
            "The freeze window name can not be empty"
        error_msg_from_response = json.loads(self.cat.api.http_text)['error']

        assert error_msg_from_response == expected_error_msg, \
            "Expected '{}' error msg, got '{}' instead.".format(expected_error_msg, error_msg_from_response)

        self.cat.api.exclusions.delete(created_blackout_window_details['id'], scanner_id)

    # API_Tested# POST /scanners/{scanner_id}/agents/exclusions
    @pytest.mark.parametrize('exclusion_fields', ["name", "schedule", "rrules", "timezone", "starttime", "endtime"])
    @pytest.mark.parametrize('exclusion_fields_value', ['', None])
    def test_none_values_not_allowed_while_create_exclusion(self, exclusion_fields, exclusion_fields_value):
        """
        NES-12228: [API] [Negative] Exclusion validations

        Scenarios tested:
            [x] Verify error is thrown if we try to create exclusion rules without "starttime", "endtime", "timezone"
                and "rrules"
        """
        scanner_id = self.cat.api.scanners.get_list()['scanners'][0]['id']  # get first scanner id
        date = datetime.now().strftime('%Y-%m-%d %H')

        payload = {"name": random_name('blackout_window-'), "description": "", "agent_group_id": None,
                   "schedule": {"enabled": True,
                                "rrules": {"freq": "MONTHLY", "interval": 1, "bysetpos": 4, "byweekday": "2"},
                                "timezone": "America/New_York", "starttime": date + ":00:00",
                                "endtime": date + ":30:00"}}

        if exclusion_fields in ["name", "schedule"]:
            payload[exclusion_fields] = exclusion_fields_value
        elif exclusion_fields in ["rrules", "timezone", "starttime", "endtime"]:
            payload["schedule"][exclusion_fields] = exclusion_fields_value

        if (exclusion_fields == "timezone" and exclusion_fields_value is None) or \
                (exclusion_fields == "schedule" and exclusion_fields_value is not None):
            with pytest.raises(HTTPError):
                self.cat.api.exclusions.create(scanner_id, payload)

            assert self.cat.api.http_status_code == HTTPStatus.BAD_REQUEST, \
                'Expected 400, got %s instead.' % self.cat.api.http_status_code

            expected_error_msgs = {"name": ["The blackout window name can not be empty",
                                            "A blackout window name must be provided"],
                                   "rrules": ["malformed schedule.rrules", "schedule.rrules is required"]}

            if exclusion_fields in ["name", "rrules"]:
                expected_error_msg = expected_error_msgs[exclusion_fields][0] if len(exclusion_fields) == 0 else \
                    expected_error_msgs[exclusion_fields][1]
            elif exclusion_fields in ["starttime", "endtime"] and exclusion_fields_value == '':
                expected_error_msg = 'times must be in "YYYY-MM-DD hh:mm:ss" format'
            else:
                exclusion_fields = "starttime" if exclusion_fields == "schedule" and exclusion_fields_value == '' else \
                    exclusion_fields
                expected_error_msg = "schedule.{} is required".format(exclusion_fields)

            error_msg_from_response = json.loads(self.cat.api.http_text)['error']

            assert error_msg_from_response == expected_error_msg, \
                "Expected '{}' error msg, got '{}' instead.".format(expected_error_msg, error_msg_from_response)

    # API_Tested# POST /scanners/{scanner_id}/agents/exclusions
    @pytest.mark.parametrize('rrules_fields', ["freq", "bysecond", "byminute", "byhour", "byweekday", "byweekno",
                                               "byyearday", "bymonthday", "bymonth", "bysetpos"])
    def test_invalid_rrules_value_throws_an_error(self, rrules_fields):
        """
        NES-12228: [API] [Negative] Exclusion validations

        Scenarios tested:
            [x] Verify error is thrown if we try to create exclusion rules with invalid rrules
        """
        scanner_id = self.cat.api.scanners.get_list()['scanners'][0]['id']  # get first scanner id
        date = datetime.now().strftime('%Y-%m-%d %H')

        payload = {"name": random_name('blackout_window-'), "description": "", "agent_group_id": None,
                   "schedule": {"enabled": True,
                                "rrules": {"freq": "MONTHLY", "bysetpos": 4, "byweekday": "2"},
                                "timezone": "America/New_York", "starttime": date + ":00:00",
                                "endtime": date + ":30:00"}}

        if rrules_fields == "freq":
            payload["schedule"]["rrules"][rrules_fields] = None
        elif rrules_fields == "bysetpos":
            payload["schedule"]["rrules"][rrules_fields] = ''
        else:
            payload["schedule"]["rrules"][rrules_fields] = -1

        with pytest.raises(HTTPError):
            self.cat.api.exclusions.create(scanner_id, payload)

        assert self.cat.api.http_status_code == HTTPStatus.BAD_REQUEST, \
            'Expected 400, got %s instead.' % self.cat.api.http_status_code

        expected_error_msg = "malformed schedule.rrules"
        error_msg_from_response = json.loads(self.cat.api.http_text)['error']

        assert error_msg_from_response == expected_error_msg, \
            "Expected '{}' error msg, got '{}' instead.".format(expected_error_msg, error_msg_from_response)

    # API_Tested# POST /scanners/{scanner_id}/agents/exclusions
    def test_end_time_before_start_time_not_allowed_while_create_exclusion(self):
        """
        NES-12228: [API] [Negative] Exclusion validations

        Scenarios tested:
            [x] Verify error is thrown if we try to create exclusion rules when "endtime" is before "starttime"
        """
        scanner_id = self.cat.api.scanners.get_list()['scanners'][0]['id']  # get first scanner id
        start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        end_time = (datetime.now() - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')

        payload = {"name": random_name('blackout_window-'), "description": "", "agent_group_id": None,
                   "schedule": {"enabled": True,
                                "rrules": {"freq": "MONTHLY", "bysetpos": 4, "byweekday": "2"},
                                "timezone": "America/New_York", "starttime": start_time, "endtime": end_time}}

        with pytest.raises(HTTPError):
            self.cat.api.exclusions.create(scanner_id, payload)

        assert self.cat.api.http_status_code == HTTPStatus.BAD_REQUEST, \
            'Expected 400, got %s instead.' % self.cat.api.http_status_code

        expected_error_msg = "schedule starttime must be before endtime"
        error_msg_from_response = json.loads(self.cat.api.http_text)['error']

        assert error_msg_from_response == expected_error_msg, \
            "Expected '{}' error msg, got '{}' instead.".format(expected_error_msg, error_msg_from_response)

    # API_Tested# POST /scanners/{scanner_id}/agents/exclusions
    @pytest.mark.parametrize('invalid_date_format', ["%Y %m %d", "%m %d %Y", "%m %d %y", "%b %d %Y", "%d %b %Y",
                                                     "%B %d %Y", "%d %B %Y"])
    @pytest.mark.parametrize('invalid_time_format', ["%H %M %S", "%H %M %S %f", "%H %M"])
    def test_invalid_date_format_not_allowed_for_start_and_end_time(self, invalid_date_format, invalid_time_format):
        """
        NES-12228: [API] [Negative] Exclusion validations

        Scenarios tested:
            [x] Verify error is thrown if we try to create exclusion rules when times passed are not in format
                "YYYY-MM-DD hh:mm:ss"
        """
        scanner_id = self.cat.api.scanners.get_list()['scanners'][0]['id']  # get first scanner id

        for separator in ['/', ' ', '.', '_', ':']:
            invalid_date_time = '{} {}'.format(invalid_date_format.replace(' ', separator),
                                               invalid_time_format.replace(' ', separator))

            start_time = datetime.now().strftime(invalid_date_time)
            end_time = (datetime.now() + timedelta(hours=1)).strftime(invalid_date_time)
            log.debug("Verified for start-time :: '{}' and end-time :: '{}'".format(start_time, end_time))

            payload = {"name": random_name('blackout_window-'), "description": "", "agent_group_id": None,
                       "schedule": {"enabled": True,
                                    "rrules": {"freq": "MONTHLY", "bysetpos": 4, "byweekday": "2"},
                                    "timezone": "America/New_York", "starttime": start_time, "endtime": end_time}}

            with pytest.raises(HTTPError):
                self.cat.api.exclusions.create(scanner_id, payload)

            assert self.cat.api.http_status_code == HTTPStatus.BAD_REQUEST, \
                'Expected 400, got %s instead.' % self.cat.api.http_status_code

            expected_error_msg = 'times must be in "YYYY-MM-DD hh:mm:ss" format'
            error_msg_from_response = json.loads(self.cat.api.http_text)['error']

            assert error_msg_from_response == expected_error_msg, \
                "Expected '{}' error msg, got '{}' instead.".format(expected_error_msg, error_msg_from_response)
