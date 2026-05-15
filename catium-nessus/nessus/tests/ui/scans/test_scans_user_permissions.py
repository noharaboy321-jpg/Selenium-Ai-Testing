"""
Nessus test cases related to Scans user permissions

:copyright: Tenable Network Security, 2018
:date: November 25, 2017
:last_modified: June 24, 2020
:author: @rdutta, @kpanchal
"""

import pytest

from catium.lib.const import WAIT_NORMAL, WAIT_SHORT
from catium.lib.const.base_constants import WAIT_LONG, TIME_THIRTY_SECONDS
from catium.lib.util import random_name
from catium.lib.webium.wait import wait
from nessus.lib.const import Nessus, API
from nessus.lib.message.messages import Messages
from nessus.pageobjects.credentials.host import Password
from nessus.pageobjects.groups.groups_page import GroupsPage, NewGroupPage, GroupList
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.header.user_menu import UserMenu
from nessus.pageobjects.login.login_page import LoginPage
from nessus.pageobjects.scans.scan_basic_settings_page import BasicSetting
from nessus.pageobjects.scans.scan_trash_page import ScansTrashPage
from nessus.pageobjects.scans.scan_view_page import ScanViewPage
from nessus.pageobjects.scans.scans_page import ScansPage, ScanList
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav


@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login', 'delete_all_scans_in_nessus')
class TestScansPermissions:
    """Covers Scans permissions related test cases"""

    test_data = {"user_details": {
        "Basic": {'user_name': random_name(prefix="{} - ".format(API.User.Users.BASIC_USER)),
                  'full_name': 'Basic user', 'email': API.User.Users.TEST_EMAIL,
                  'password': 'Basic_P@ssw0rd', 'role': API.User.Role.BASIC},
        "Standard": {'user_name': random_name(prefix="{} - ".format(API.User.Users.STANDARD_USER)),
                     'full_name': 'Standard user', 'email': API.User.Users.TEST_EMAIL,
                     'password': 'Standard_P@ssw0rd', 'role': API.User.Role.STANDARD},
        "Administrator": {'user_name': random_name(prefix="{} - ".format(API.User.Users.ADMIN_USER)),
                          'full_name': 'Admin user', 'email': API.User.Users.TEST_EMAIL,
                          'password': 'Admin_P@ssw0rd', 'role': API.User.Role.ADMIN},
        "System Administrator": {'user_name': random_name(prefix="{} - ".format(API.User.Users.SYS_ADMIN_USER)),
                                 'password': 'SysAdmin_P@ssw0rd', 'email': API.User.Users.TEST_EMAIL,
                                 'full_name': 'SysAdmin user', 'role': API.User.Role.SYS_ADMIN}
    }, "check_login": False, "unique_username": True}
    test_data_1 = {"user_details": {
        "Basic": {'user_name': random_name(prefix="{} - ".format(API.User.Users.BASIC_USER)),
                  'full_name': 'Basic user', 'email': API.User.Users.TEST_EMAIL,
                  'password': 'Basic_P@ssw0rd', 'role': API.User.Role.BASIC},
        "Standard": {'user_name': random_name(prefix="{} - ".format(API.User.Users.STANDARD_USER)),
                     'full_name': 'Standard user', 'email': API.User.Users.TEST_EMAIL,
                     'password': 'Standard_P@ssw0rd', 'role': API.User.Role.STANDARD}
    }, "check_login": False, "unique_username": True}
    test_data_2 = {"user_details": {
        "Administrator": {'user_name': random_name(prefix="{} - ".format(API.User.Users.ADMIN_USER)),
                          'full_name': 'Admin user', 'email': API.User.Users.TEST_EMAIL,
                          'password': 'Admin_P@ssw0rd', 'role': API.User.Role.ADMIN},
        "System Administrator": {'user_name': random_name(prefix="{} - ".format(API.User.Users.SYS_ADMIN_USER)),
                                 'password': 'SysAdmin_P@ssw0rd', 'email': API.User.Users.TEST_EMAIL,
                                 'full_name': 'SysAdmin user', 'role': API.User.Role.SYS_ADMIN}
    }, "check_login": False, "unique_username": True}

    @pytest.mark.parametrize("create_users", [test_data_1, test_data_2], indirect=True)
    def test_default_user_permissions_in_scans(self, create_users):
        """
        # NQA-361 : UI-Scans-User permissions.
        Sub-part: scan permissions for default user.
        """
        # All type of users has created and user details are returned by fixture
        user_credentials = create_users
        user_scans = {}
        UserMenu().logout()
        login_page = LoginPage()
        wait(lambda: login_page.is_element_present("username_field", timeout=TIME_THIRTY_SECONDS),
             waiting_for="username to become visible")

        scan_list = ScanList()

        # LogIn into every type of users created above
        for user in user_credentials.keys():
            if user_credentials.get(user).get('role') != API.User.Role.BASIC:
                login_page.login_with_credentials(username=user_credentials.get(user).get('user_name'),
                                                  password=user_credentials.get(user).get('password'))

                # Create scans with different permissions
                scan_page = ScansPage()
                for permission in Nessus.Scan.UserPermissions.USER_PERMISSIONS.keys():
                    scan_name = '{} for {} with {}'.format(Nessus.TemplateNames.ADVANCED,
                                                           user_credentials.get(user).get('user_name'), permission)
                    try:
                        user_scans[user].update({permission: scan_name})
                    except KeyError:
                        user_scans.update({user: {permission: scan_name}})

                    LoadingCircle(WAIT_NORMAL)
                    scan_page.create_new_scan(
                        scan_template=Nessus.TemplateNames.ADVANCED, scan_type=Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                        scan_name=scan_name, target_ip=Nessus.Scan.Target.LOCALHOST, add_configuration=True)
                    LoadingCircle(WAIT_SHORT)

                    # Add permission to scan
                    BasicSetting().set_user_permissions_for_scans(
                        user_name=API.User.Users.DEFAULT_USER,
                        permission=Nessus.Scan.UserPermissions.USER_PERMISSIONS.get(permission))

                    Password(host_type=API.Credentials.Host.Types.SSH).fill_password_ssh_form(
                        username=Nessus.USERNAME, password=Nessus.PASSWORD,
                        auth=API.Credentials.Host.SSHAuthTypes.PASSWORD)
                    Password(host_type=API.Credentials.Host.Types.WINDOWS).fill_password_windows_form(
                        username=Nessus.USERNAME, password=Nessus.PASSWORD, domain=Nessus.Scan.Target.LOCALHOST,
                        auth=API.Credentials.Host.WindowsAuthTypes.PASSWORD)
                    scan_page.save_button.click()
                    LoadingCircle(WAIT_LONG)
                    wait(lambda: scan_page.is_element_present('scan_searchbox', timeout=TIME_THIRTY_SECONDS),
                         waiting_for="visibility of search box")

                    # Verify scan has successfully created and saved
                    if permission != Nessus.Scan.UserPermissions.NO_ACCESS:
                        assert 'Shared\n{}'.format(scan_name) in scan_list.get_all_scans(), \
                            'Scan not listed under Scan page.'
                    else:
                        assert scan_name in scan_list.get_all_scans(), 'Scan not listed under Scan page.'

                UserMenu().logout()
                wait(lambda: login_page.is_element_present("username_field", timeout=TIME_THIRTY_SECONDS),
                     waiting_for="username to become visible")

        # LogIn into every type of users created above and verify their permissions is working correctly.
        for user in user_credentials.keys():
            login_page.login_with_credentials(username=user_credentials.get(user).get('user_name'),
                                              password=user_credentials.get(user).get('password'))
            wait(lambda: scan_page.is_element_present('scan_searchbox', timeout=TIME_THIRTY_SECONDS),
                 waiting_for="Visibility of search box")
            if user_credentials.get(user).get('role') != API.User.Role.BASIC:
                assert user_scans.get(user).get(Nessus.Scan.UserPermissions.NO_ACCESS) in \
                       scan_list.get_all_scans(), 'Scan not found.'
                for itr1 in user_scans.keys():
                    if itr1 != user:
                        for permission in Nessus.Scan.UserPermissions.USER_PERMISSIONS:
                            if permission == Nessus.Scan.UserPermissions.NO_ACCESS:
                                assert user_scans.get(itr1).get(Nessus.Scan.UserPermissions.NO_ACCESS) not in \
                                       scan_list.get_all_scans(), 'Scan found.'
                            else:
                                scan_list.click_on_scan('Shared\n{}'.format(user_scans.get(itr1).get(permission)))
                                scan_details_page = ScanViewPage()
                                wait(lambda: scan_details_page.is_element_present("header_element",
                                                                                  timeout=TIME_THIRTY_SECONDS),
                                     waiting_for="scan header to become visible")
                                if permission == Nessus.Scan.UserPermissions.CAN_VIEW:
                                    assert all([(not scan_details_page.is_element_present('launch_button')),
                                                (not scan_details_page.is_element_present('configure_button'))]), \
                                        "'Launch' and 'Configure' button is visible."
                                elif permission == Nessus.Scan.UserPermissions.CAN_CONTROL:
                                    scan_details_page.js_scroll_into_view(scan_details_page.launch_dropdown)
                                    assert all([scan_details_page.is_element_present('launch_button'),
                                                (not scan_details_page.is_element_present('configure_button'))]), \
                                        "Launch button is invisible and Configure button is visible."
                                else:
                                    scan_details_page.js_scroll_into_view(scan_details_page.configure_button)
                                    assert all([scan_details_page.is_element_present('configure_button'),
                                                scan_details_page.is_element_present('launch_button')]), \
                                        "'Configure' and 'Launch' button are invisible."

                                scan_details_page.back_link.click()
                                wait(lambda: scan_page.is_element_present('scan_searchbox',
                                                                          timeout=TIME_THIRTY_SECONDS),
                                     waiting_for="visibility of search box")
                    else:
                        for permissions in Nessus.Scan.UserPermissions.USER_PERMISSIONS:
                            if permissions == Nessus.Scan.UserPermissions.NO_ACCESS:
                                scan_list.click_on_scan(user_scans.get(itr1).get(permissions))
                            else:
                                scan_list.click_on_scan('Shared\n{}'.format(user_scans.get(itr1).get(permissions)))

                            scan_details_page = ScanViewPage()
                            wait(lambda: scan_details_page.is_element_present("header_element",
                                                                              timeout=TIME_THIRTY_SECONDS),
                                 waiting_for="scan header to become visible")
                            scan_details_page.js_scroll_into_view(scan_details_page.launch_dropdown)
                            assert all([scan_details_page.is_element_present('launch_button'),
                                        scan_details_page.is_element_present('configure_button')]), \
                                "'Launch' button and 'Configure' button are invisible."
                            scan_details_page.back_link.click()
                            wait(lambda: scan_page.is_element_present('scan_searchbox', timeout=TIME_THIRTY_SECONDS),
                                 waiting_for="visibility of search box")
            else:
                for permissions in Nessus.Scan.UserPermissions.USER_PERMISSIONS:
                    if permissions != Nessus.Scan.UserPermissions.NO_ACCESS:
                        for other_user in user_scans.keys():
                            scan_list.click_on_scan('Shared\n{}'.format(user_scans.get(other_user).get(permissions)))
                            LoadingCircle(WAIT_NORMAL)
                            scan_details_page = ScanViewPage()
                            assert all([(not scan_details_page.is_element_present('launch_button')),
                                        (not scan_details_page.is_element_present('configure_button'))]), \
                                "'Launch' button and 'Configure' button are visible."
                            scan_details_page.back_link.click()
                            wait(lambda: scan_page.is_element_present('scan_searchbox', timeout=TIME_THIRTY_SECONDS),
                                 waiting_for="visibility of search box")
            UserMenu().logout()
            wait(lambda: login_page.is_element_present("username_field", timeout=TIME_THIRTY_SECONDS),
                 waiting_for="username to become visible")

        login_page.login_with_defaults()
        wait(lambda: UserMenu().is_element_present("user_menu_dropdown", timeout=TIME_THIRTY_SECONDS),
             waiting_for="user menu to become visible")

    @pytest.mark.parametrize("create_users", [test_data], indirect=True)
    def test_other_users_or_groups_permissions_in_scans(self, create_users):
        """
        # NQA-361 : UI-Scans-User permissions.
        Sub-part: scan permissions for other users/groups.
        """
        # All type of users has created and user details are returned by fixture
        user_credentials = create_users
        LoadingCircle(WAIT_NORMAL)
        scan_name = '{} for {} with {}'.format(Nessus.TemplateNames.ADVANCED,
                                               user_credentials.get(API.User.Role.ADMIN).get('user_name'),
                                               Nessus.Scan.UserPermissions.NO_ACCESS)

        # Create a group and add some user (from above created users) into the group
        group_name = random_name(prefix='UserGroup - ')
        group_page = GroupsPage()
        group_page.open()
        wait(lambda: group_page.is_element_present('title_in_header', timeout=TIME_THIRTY_SECONDS),
             waiting_for="waiting for users page to load")
        LoadingCircle(WAIT_NORMAL)
        group_page.create_new_user_group(group_name=group_name)
        wait(lambda: group_page.is_element_present('add_user', timeout=TIME_THIRTY_SECONDS),
             waiting_for="waiting for add_user button to load")
        NewGroupPage().add_user_to_group(user_list=[user_credentials.get(API.User.Role.SYS_ADMIN).get('user_name')])

        # LogOut from current user and LogIn to any of above created user
        UserMenu().logout()
        login_page = LoginPage()
        wait(lambda: login_page.is_element_present('username_field', timeout=TIME_THIRTY_SECONDS),
             waiting_for="username field to become visible")

        login_page.login_with_credentials(username=user_credentials.get(API.User.Role.ADMIN).get('user_name'),
                                          password=user_credentials.get(API.User.Role.ADMIN).get('password'))

        # Create a scan
        scan_page = ScansPage()
        scan_page.create_new_scan(
            scan_template=Nessus.TemplateNames.ADVANCED, scan_type=Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
            scan_name=scan_name, target_ip=Nessus.Scan.Target.LOCALHOST, add_configuration=True)
        LoadingCircle(WAIT_SHORT)

        # Add some permission to other user for this scan (e.g. user-Standard: Can configure)
        basic_setting_page = BasicSetting()
        basic_setting_page.set_user_permissions_for_scans(user_name=user_credentials.get(
            API.User.Role.STANDARD).get('user_name'), permission=Nessus.Scan.UserPermissions.CAN_CONFIGURE)
        basic_setting_page.set_user_permissions_for_scans(user_name=group_name,
                                                          permission=Nessus.Scan.UserPermissions.CAN_CONTROL)

        Password(host_type=API.Credentials.Host.Types.WINDOWS).fill_password_windows_form(
            username=Nessus.USERNAME, password=Nessus.PASSWORD, domain=Nessus.Scan.Target.AWS_LINUX_TARGET_1,
            auth=API.Credentials.Host.WindowsAuthTypes.PASSWORD)
        scan_page.save_button.click()
        LoadingCircle(WAIT_NORMAL)

        # Verify scan has successfully created and saved
        assert 'Shared\n{}'.format(scan_name) in ScanList().get_all_scans(), 'Scan has not been created successfully.'
        LoadingCircle(WAIT_SHORT)
        UserMenu().logout()

        # LogIn into every type of users created above and verify their permissions for the scan is working correctly.
        for user in user_credentials.keys():
            if user_credentials.get(user).get('role') != API.User.Role.BASIC:
                login_page.login_with_credentials(username=user_credentials.get(user).get('user_name'),
                                                  password=user_credentials.get(user).get('password'))
                wait(lambda: ScansPage().is_element_present('scan_searchbox', timeout=TIME_THIRTY_SECONDS),
                     waiting_for="scan search box to become visible")
                scan_list = ScanList()
                scan_list.click_on_scan(scan_name='Shared\n{}'.format(scan_name))
                scan_details_page = ScanViewPage()
                wait(lambda: scan_details_page.is_element_present("header_element", timeout=TIME_THIRTY_SECONDS),
                     waiting_for="header element to become visible")

                scan_details_page.js_scroll_into_view(scan_details_page.launch_dropdown)
                if user_credentials.get(user).get('role') == API.User.Role.STANDARD:
                    assert all([scan_details_page.is_element_present('configure_button'),
                                scan_details_page.is_element_present('launch_button')]), \
                        "'Configure' button and 'Launch' button are invisible."
                elif user_credentials.get(user).get('role') == API.User.Role.SYS_ADMIN:
                    assert all([scan_details_page.is_element_present('launch_button'),
                                (not scan_details_page.is_element_present('configure_button'))]), \
                        "'Launch' button is invisible and 'Configure' button is visible."

                scan_details_page.back_link.click()
                wait(lambda: ScansPage().is_element_present('scan_searchbox', timeout=TIME_THIRTY_SECONDS),
                     waiting_for="scan search box to become visible")
                UserMenu().logout()

        wait(lambda: login_page.is_element_present('username_field', timeout=TIME_THIRTY_SECONDS),
             waiting_for="username field to become visible")

        # LogIn into default user and delete above created group
        login_page.login_with_defaults()
        LoadingCircle(WAIT_NORMAL)
        GroupsPage().open()
        GroupList().delete_group(group_name=group_name)
        LoadingCircle(WAIT_NORMAL)
        assert group_name not in GroupList().get_all_groups_by_name(), "Group exists in group management page."

    @pytest.mark.parametrize("create_users", [test_data], indirect=True)
    def test_default_users_permissions_over_other_users_in_scans(self, create_users):
        """
        # NQA-361 : UI-Scans-User permissions.
        Sub-part: Set default to 'can configure', add a user/group with other permissions.
        """
        # All type of users has created and user details are returned by fixture
        user_credentials = create_users
        LoadingCircle(WAIT_NORMAL)
        scan_name = '{} for {}'.format(Nessus.TemplateNames.ADVANCED,
                                       user_credentials.get(API.User.Role.ADMIN).get('user_name'))

        # Create a group and add some user (from above created users) into the group
        group_name = random_name(prefix='UserGroup - ')
        group_page = GroupsPage()
        group_page.open()
        LoadingCircle(WAIT_NORMAL)
        group_page.create_new_user_group(group_name=group_name)
        LoadingCircle(WAIT_NORMAL)
        NewGroupPage().add_user_to_group(user_list=[user_credentials.get(API.User.Role.SYS_ADMIN).get('user_name'),
                                                    user_credentials.get(API.User.Role.BASIC).get('user_name')])

        # LogOut from current user and LogIn to any of above created user
        UserMenu().logout()
        LoadingCircle(WAIT_SHORT)
        login_page = LoginPage()
        login_page.login_with_credentials(username=user_credentials.get(API.User.Role.ADMIN).get('user_name'),
                                          password=user_credentials.get(API.User.Role.ADMIN).get('password'))

        # Create a scan
        scan_page = ScansPage()
        LoadingCircle(WAIT_NORMAL)
        scan_page.create_new_scan(
            scan_template=Nessus.TemplateNames.ADVANCED, scan_type=Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
            scan_name=scan_name, target_ip=Nessus.Scan.Target.LOCALHOST, add_configuration=True)
        LoadingCircle(WAIT_SHORT)

        # Add some permission to other user for this scan (e.g. user-Standard: Can configure)
        basic_setting_page = BasicSetting()
        basic_setting_page.set_user_permissions_for_scans(user_name=API.User.Users.DEFAULT_USER,
                                                          permission=Nessus.Scan.UserPermissions.CAN_CONFIGURE)
        basic_setting_page.set_user_permissions_for_scans(user_name=user_credentials.get(
            API.User.Role.STANDARD).get('user_name'), permission=Nessus.Scan.UserPermissions.CAN_VIEW)
        basic_setting_page.set_user_permissions_for_scans(user_name=group_name,
                                                          permission=Nessus.Scan.UserPermissions.CAN_CONTROL)
        Password(host_type=API.Credentials.Host.Types.WINDOWS).fill_password_windows_form(
            username=Nessus.USERNAME, password=Nessus.PASSWORD, domain=Nessus.Scan.Target.AWS_LINUX_TARGET_1,
            auth=API.Credentials.Host.WindowsAuthTypes.PASSWORD)
        scan_page.save_button.click()
        LoadingCircle(WAIT_NORMAL)

        # Verify scan has successfully created and saved
        scan_list = ScanList()
        assert 'Shared\n{}'.format(scan_name) in scan_list.get_all_scans(), 'Scan has not been created successfully.'
        LoadingCircle(WAIT_SHORT)
        UserMenu().logout()

        # LogIn into every type of users created above and verify their permissions for the scan is working correctly.
        for user in user_credentials.keys():
            login_page.login_with_credentials(username=user_credentials.get(user).get('user_name'),
                                              password=user_credentials.get(user).get('password'))

            LoadingCircle(WAIT_NORMAL)
            scan_list.click_on_scan(scan_name='Shared\n{}'.format(scan_name))
            scan_details_page = ScanViewPage()
            wait(lambda: scan_details_page.is_element_present("header_element"), timeout_seconds=TIME_THIRTY_SECONDS)

            # As we have set the highest permission to default user, other user/group permissions will
            # functional as (default -> user -> group)
            if user_credentials.get(user).get('role') != API.User.Role.BASIC:
                scan_details_page.js_scroll_into_view(scan_details_page.configure_button)
                assert all([scan_details_page.is_element_present('configure_button'),
                            scan_details_page.is_element_present('launch_button')]), \
                    "'Configure' button and 'Launch' button are invisible."
            else:
                assert all([(not scan_details_page.is_element_present('launch_button')),
                            (not scan_details_page.is_element_present('configure_button'))]), \
                    "'Launch' button and 'Configure' button are visible."

            scan_details_page.back_link.click()
            LoadingCircle(WAIT_SHORT)
            UserMenu().logout()

        # LogIn into default user and delete above created group
        LoadingCircle(WAIT_SHORT)
        login_page.login_with_defaults()
        GroupsPage().open()
        LoadingCircle(WAIT_NORMAL)
        group_list = GroupList()
        group_list.delete_group(group_name=group_name)
        LoadingCircle(WAIT_NORMAL)
        assert group_name not in group_list.get_all_groups_by_name(), 'Group still exists in group management page.'

    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format('NQA-1016 Advanced Scan')), "add_configuration": True,
         "target_ip": Nessus.Scan.Target.LOCALHOST}]}], indirect=True)
    def test_delete_shared_scan(self, create_scans):
        """
        UI - Scans - Delete Shared Scans: NQA-1016
        Verify delete shared scans using more delete option without any error
        """
        BasicSetting().set_user_permissions_for_scans(user_name=API.User.Users.DEFAULT_USER,
                                                      permission=Nessus.Scan.UserPermissions.CAN_VIEW)

        scan_page = ScansPage()
        scan_page.save_button.click()
        LoadingCircle(WAIT_NORMAL)

        scan_list = ScanList()
        shared_scan_name = 'Shared\n{}'.format(create_scans[0])
        assert shared_scan_name in scan_list.get_all_scans(), 'shared scan is not available in scan list'

        scan_page.move_scan_to_selected_folder(scan_list=[shared_scan_name], folder_name=Nessus.Scan.Folder.TRASH)
        assert Notifications().successes[-1] == Messages.NotificationMessages.scan_move_to_trash, \
            'Scan has not been moved to trash successfully.'

        side_nav = SideNav()
        side_nav.get_sidenav_element(element_name=Nessus.Scan.Folder.TRASH).click()
        LoadingCircle(WAIT_NORMAL)
        assert shared_scan_name in scan_list.get_all_scans(), 'shared scan is not available in trash folder.'

        ScansTrashPage().delete_selected_scan(scan_list=[shared_scan_name])
        assert shared_scan_name not in scan_list.get_all_scans(), \
            'shared scan is still available in trash folder or did not deleted permanently.'

        side_nav.get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()
