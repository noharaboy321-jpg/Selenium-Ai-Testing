"""
Test cases for aspects of the HTTP server
"""
import os

import pytest

from catium.helpers.sleep_lib import sleep
from catium.helpers.testdata import get_file_path
from catium.lib.const.base_constants import TIME_FIVE_SECONDS
from catium.lib.util import util
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.cli_command import upload, execute
from nessus.helpers.nessuscli import fix
from nessus.helpers.nessuscli.helper import get_os_name, get_nessus_var_dir
from nessus.helpers.users import create_user
from nessus.lib.const import OperatingSystems


@pytest.mark.nessus_manager
class TestPasswordHashVersion:
    """Test cases for Nessus HTTP Server"""
    cat = None

    @staticmethod
    def verify_user_password_version(username, version):
        remote_hash_file = os.path.join(get_nessus_var_dir(), 'users/', username, "auth/hash")

        if get_os_name() == OperatingSystems.LINUX:
            result = execute(command='cat', args=[remote_hash_file])
        else:
            result = execute(command='type', args=[remote_hash_file.replace('/', '\\')])
        password_hash = result['stdout']
        print('password_hash=' + password_hash)
        return password_hash[-2:] == version

    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.incompatible
    def test_password_hash_version(self):
        """
        Scenarios tested:
        [x] New user, version should be v3
        [x] New user with version v3, after change password should be still v3
        [x] Old user with version v2, when niap_mode != enforcing, after login won't change
        [x] Old user with version v2, when niap_mode = enforcing, after login will change to v3
        [x] Old user with version v2, change password will change to v3
        """
        username = util.random_name('user-')
        user_details = create_user(api=self.cat.api, username=username, password="test")

        assert any(username == user['username'] for user in self.cat.api.users.get_users()['users']), \
            "User does not created"

        try:
            assert self.verify_user_password_version(username=username, version='v3')

            self.cat.api.users.change_password(user_id=user_details['id'], payload={"password": "test1"})

            assert self.verify_user_password_version(username=username, version='v3')

            file_path = get_file_path('nessus/tests/api/auth/test_data/password_hash_v2')
            remote_hash_file = os.path.join(get_nessus_var_dir(), 'users/', username, "auth/hash")
            upload(file_path, remote_hash_file)

            fix.set(key='niap_mode', value='not-enforcing')
            api = NessusAPI()

            assert self.verify_user_password_version(username=username, version='v2')

            api.login(username=username, password='password')

            assert self.verify_user_password_version(username=username, version='v2')

            api.logout()
            fix.set(key='niap_mode', value='enforcing')
            sleep(TIME_FIVE_SECONDS * 4, "wait for 20 seconds so niap_mode is ready ")
            api.login(username=username, password='password')

            assert self.verify_user_password_version(username=username, version='v3')

            upload(file_path, remote_hash_file)
            fix.delete(key='niap_mode')
            self.cat.api.users.change_password(user_id=user_details['id'], payload={"password": "test2"})

            assert self.verify_user_password_version(username=username, version='v3')
        finally:
            self.cat.api.users.delete(user_id=user_details['id'])
