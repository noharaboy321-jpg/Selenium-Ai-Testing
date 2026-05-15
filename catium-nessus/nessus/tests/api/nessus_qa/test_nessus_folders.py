"""
Nessus scan Folder Endpoints Test

:copyright: Tenable Network Security, 2017
:date: May 31, 2017
:last_modified: June 23, 2022
:author: @cdombrowski, @kpanchal, @krpatel
"""

import json
from http import HTTPStatus
from random import randint

import pytest
from requests import HTTPError

from catium.lib.util import random_name
from catium.lib.util.util import random_string


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_manager
@pytest.mark.smoke
@pytest.mark.usefixtures('nessus_api_login', 'get_folder_dictionary')
class TestFolders:
    """
    Class to handle testing Nessus Folders via the API.
    """

    cat = None

    # API_Tested# GET /folders
    @pytest.mark.nessus_home
    def test_get_nessus_folders(self):
        """
        Tests our ability to retrieve a list of folders from the Nessus API.

        Scenarios tested:
          [x] Successfully get folder list
        """
        folders = self.cat.api.folders.get_folders()

        assert folders and self.cat.api.http_status_code == HTTPStatus.OK and 'folders' in folders, \
            'Unable to retrieve folder list.'

    # API_Tested# PUT /folders/{folder_id}
    @pytest.mark.nessus_home
    @pytest.mark.usefixtures('create_folder')
    def test_nessus_folder_update(self):
        """
        Updates the our randomly created folder to a new name.  This test uses the create_random_folder fixture, which
        handles the creation and deletion of random folders.

        Scenarios tested:
          [x] Successfully modify a folder
          [ ] Attempt to update a folder to use a name that already exists (case insensitive)
        """
        self.cat.api.folders.edit(folder_id=self.cat.folder_id, name=random_name(prefix='updated-'))

        assert self.cat.api.http_status_code == HTTPStatus.OK, 'Unable to edit the folder.'

    # API_Tested# POST /folders
    @pytest.mark.nessus_home
    @pytest.mark.usefixtures('create_folder')
    def test_nessus_folder_creation(self):
        """
        Tests that the folder we create with the create_random_folder fixture is listed
        in the folder list.  If not, we failed to create the folder.

        Scenarios tested:
          [x] Successfully create a folder
          [ ] Attempt to create a folder with a name that already exists (case insensitive)
        """
        assert self.cat.folder_id and self.cat.folders and self.cat.folder_id in self.cat.folders.values(), \
            "Folder creation failed."

    # API_Tested# DELETE /folders/{folder_id}
    @pytest.mark.nessus_home
    def test_nessus_folder_deletion(self):
        """
        Tests that we are able to create a folder, and then delete that folder.  If the folder_id is found in our
        folders after deletion the test fails.

        Scenarios tested:
          [x] Successfully delete a folder
          [ ] Attempt to remove a folder that doesn't exist
        """
        self.cat.api.folders.create(name=random_name(prefix='nessus_'))
        folder_id = json.loads(self.cat.api.http_text)['id']

        self.cat.api.folders.delete(folder_id=folder_id)
        folders = self.cat.api.folders.get_folders()['folders']

        assert not [folder for folder in folders if folder_id == folder['id']], 'Folder deletion failed.'

    # API_Tested# PUT /folders/{folder_id}
    @pytest.mark.nessus_home
    def test_nessus_folder_404(self):
        """
        Tests that we receive a 404 error message when attempting to access a folder that does not exist.

        Scenarios tested:
          [x] Attempt to update a folder that doesn't exist
        """
        with pytest.raises(HTTPError):
            self.cat.api.folders.edit(folder_id=123212, name=random_name(prefix='nessus-'))

    # API_Tested# POST /folders
    # API_Tested# DELETE /folders/{folder_id}
    @pytest.mark.nessus_home
    def test_duplicate_folder_name_not_allowed(self):
        """
        NES-12170: [Negative] Verify duplicate folder names are not allowed

        Scenarios tested:
          [x] Verify duplicate folder names are not allowed.
        """
        folder_name = random_name(prefix='folder-')
        created_folder_details = self.cat.api.folders.create(name=folder_name)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        with pytest.raises(HTTPError):
            self.cat.api.folders.create(name=folder_name)

        assert self.cat.api.http_status_code == HTTPStatus.CONFLICT, \
            'Expected 409, got %s instead.' % self.cat.api.http_status_code

        expected_error_msg = "A folder with the same name already exists"
        error_msg_from_response = json.loads(self.cat.api.http_text)['error']

        assert error_msg_from_response == expected_error_msg, \
            "Expected '{}' error msg, got '{}' instead.".format(expected_error_msg, error_msg_from_response)

        self.cat.api.folders.delete(folder_id=created_folder_details['id'])

    # API_Tested# POST /folders
    @pytest.mark.nessus_home
    @pytest.mark.parametrize('folder_name_length', [-1, 0, 21, 50])
    def test_folder_name_not_allows_0_and_more_than_20_character(self, folder_name_length):
        """
        NES-12170: [Negative] Verify duplicate folder names are not allowed

        Scenarios tested:
          [x] Verify empty and long folder names (more than 20 characters) are also not allowed, and gives 400 error.
        """
        if folder_name_length < 0:
            folder_name = None
        else:
            folder_name = random_string(folder_name_length)

        with pytest.raises(HTTPError):
            self.cat.api.folders.create(name=folder_name)

        assert self.cat.api.http_status_code == HTTPStatus.BAD_REQUEST, \
            'Expected 400, got %s instead.' % self.cat.api.http_status_code

        expected_error_msg = "Invalid 'name' field: missing" if folder_name is None else "Invalid 'name' field: "
        error_msg_from_response = json.loads(self.cat.api.http_text)['error']

        assert error_msg_from_response == expected_error_msg, \
            "Expected '{}' error msg, got '{}' instead.".format(expected_error_msg, error_msg_from_response)

    # API_Tested# POST /folders
    # API_Tested# PUT /folders/{folder_id}
    @pytest.mark.usefixtures('create_folder')
    @pytest.mark.parametrize('folder_name', [True, False])
    def test_duplicate_or_empty_folder_name_not_allowed_while_edit(self, create_folder, folder_name):
        """
        NES-12170: [Negative] Verify duplicate folder names are not allowed

        Scenarios tested:
          [x] Verify gives error when we try to edit the existing folder, and folder with the same name already exists
        """
        created_folder_name = random_name(prefix='folder-')

        created_folder_details = self.cat.api.folders.create(name=created_folder_name)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        edited_folder_name = created_folder_name if folder_name else ''

        with pytest.raises(HTTPError):
            self.cat.api.folders.edit(folder_id=create_folder, name=edited_folder_name)

        expected_status_code = HTTPStatus.CONFLICT if folder_name else HTTPStatus.BAD_REQUEST

        assert self.cat.api.http_status_code == expected_status_code, \
            'Expected %s, got %s instead.' % (expected_status_code, self.cat.api.http_status_code)

        expected_error_msg = "A folder with the same name already exists" if folder_name else "Invalid 'name' field: "
        error_msg_from_response = json.loads(self.cat.api.http_text)['error']

        assert error_msg_from_response == expected_error_msg, \
            "Expected '{}' error msg, got '{}' instead.".format(expected_error_msg, error_msg_from_response)

        self.cat.api.folders.delete(folder_id=created_folder_details['id'])

    # API_Tested# DELETE /folders/{folder_id}
    @pytest.mark.nessus_home
    @pytest.mark.parametrize('invalid_folder_id', [-1, 0, -2])
    def test_invalid_or_non_exist_folder_delete(self, invalid_folder_id):
        """
        NES-12170: [Negative] Verify duplicate folder names are not allowed

        Scenarios tested:
          [x] Verify trying to delete invalid folder (i.e. invalid folder-id) throws error
        """
        if invalid_folder_id < -1:
            invalid_folder_id = randint(100000, 999999)

        with pytest.raises(HTTPError):
            self.cat.api.folders.delete(folder_id=invalid_folder_id)

        assert self.cat.api.http_status_code == HTTPStatus.NOT_FOUND, \
            'Expected 404, got %s instead.' % self.cat.api.http_status_code

    @pytest.mark.parametrize('system_folder_operation', ['edit', 'delete'])
    def test_edit_or_delete_trash_folders_throws_an_error(self, system_folder_operation):
        """
        NES-12170: [Negative] Verify duplicate folder names are not allowed

        Scenarios tested:
          [x] Verify trying to delete System folders (Trash) throws error.
          [x] Verify trying to edit System folders (Trash) throws error.
        """
        trash_folder_id = self.cat.api.folders.get_folders()['folders'][0]['id']
        with pytest.raises(HTTPError):
            if system_folder_operation == 'delete':
                self.cat.api.folders.delete(folder_id=trash_folder_id)
            else:
                self.cat.api.folders.edit(folder_id=trash_folder_id, name=random_name(prefix='folder-'))

        assert self.cat.api.http_status_code == HTTPStatus.FORBIDDEN, \
            f'Expected {HTTPStatus.FORBIDDEN}, got %s instead.' % self.cat.api.http_status_code

        expected_error_msg = "Can not edit system folders"
        error_msg_from_response = json.loads(self.cat.api.http_text)['error']

        assert error_msg_from_response == expected_error_msg, \
            "Expected '{}' error msg, got '{}' instead.".format(expected_error_msg, error_msg_from_response)

    @pytest.mark.parametrize('system_folder_operation', ['edit', 'delete'])
    def test_edit_or_delete_my_scans_folders_throws_an_error(self, system_folder_operation):
        """
        NES-12170: [Negative] Verify duplicate folder names are not allowed

        Scenarios tested:
          [x] Verify trying to delete System folders (My Scans) throws error.
          [x] Verify trying to edit System folders (My Scans) throws error.
        """
        myscan_folder_id = self.cat.api.folders.get_folders()['folders'][1]['id']
        with pytest.raises(HTTPError):
            if system_folder_operation == 'delete':
                self.cat.api.folders.delete(folder_id=myscan_folder_id)
            else:
                self.cat.api.folders.edit(folder_id=myscan_folder_id, name=random_name(prefix='folder-'))

        assert self.cat.api.http_status_code == HTTPStatus.FORBIDDEN, \
            f'Expected {HTTPStatus.FORBIDDEN}, got %s instead.' % self.cat.api.http_status_code

        expected_error_msg = "Can not edit system folders"
        error_msg_from_response = json.loads(self.cat.api.http_text)['error']

        assert error_msg_from_response == expected_error_msg, \
            "Expected '{}' error msg, got '{}' instead.".format(expected_error_msg, error_msg_from_response)
