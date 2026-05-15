"""
Testcases related to Nessus installation steps

:copyright: Tenable Network Security, 2020
:date: May 14th, 2020
:last_modified: July 22, 2020
:author: vsoni.ctr, @kpanchal.ctr
"""
import pytest
from waiting.exceptions import TimeoutExpired

from catium.helpers.sleep_lib import sleep
from catium.lib.activation_code_generator.activation_code_generator import ActivationCodeGenerator
from catium.lib.config.environment_variables import CommonConfig
from catium.lib.const.base_constants import TIME_THIRTY_MINUTES, TIME_THIRTY_SECONDS, TIME_FIVE_SECONDS, \
    TIME_FIVE_MINUTES, TIME_FIFTEEN_MINUTES
from catium.lib.log.log import create_logger
from catium.lib.ssh.ssh import SSH
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.nessuscli import users
from nessus.helpers.nessuscli.helper import get_nessus_cli, stop_nessus, start_nessus
from nessus.helpers.waiters import wait_for_scanner_status
from nessus.lib.const import Nessus
from nessus.lib.const.constants import API, NessusInstallation

log = create_logger()


class TestNessusInstallation:
    """ Test nessus installation, registration and plugin update """

    @pytest.mark.parametrize('nessus_type', [
        pytest.param("Nessus Professional", marks=pytest.mark.install_nessus_pro_windows)])
    def test_nessus_installation_steps_in_windows(self, nessus_type):
        """
        NES-11326 - Add a testcase for windows Nessus installation from Command line

        Scenario Tested:
            [x] Verify Nessus installation and registration steps.

        Steps:
        1. Install Nessus and verify that Nessus service is "running"
        2. Add 'admin' user in Nessus
        3. Register Nessus with activation code and verify the command output
        4. Update Nessus plugins offline and verify command output
        5. Verify Nessus type is as expected
        6. Verify that Nessus version and/or build is not empty
        7. Try to perform api login and verify that it successfully performed.
        """
        with SSH(username=NessusInstallation.ADMINISTRATOR_USER, password=NessusInstallation.ADMINISTRATOR_PASSWORD) \
                as ssh:
            msi_files_list = ssh.execute("dir /b/s *.msi")
            assert len([msi_file for msi_file in msi_files_list if NessusInstallation.NESSUS_MSI == msi_file]) == 1, \
                "Nessus.msi file does not present or Nessus.msi files are more than one."

            nessus_service_status = ssh.execute(command='sc query "Tenable Nessus"')
            assert not any("RUNNING" in output_line for output_line in nessus_service_status), \
                "Nessus service status is 'running' before Nessus installed."

            nessus_quite_installation_output = ssh.execute("msiexec /i Nessus.msi /qn")
            assert len(nessus_quite_installation_output) == 0, "Nessus installation is not successful"

            # Verify that Nessus service status is 'running' after Nessus installation.
            nessus_service_status = ssh.execute(command='sc query "Tenable Nessus"')
            assert any("RUNNING" in output_line for output_line in nessus_service_status), \
                "Nessus service status is not 'running' after Nessus installation"

            # Adding User
            api = NessusAPI()
            wait_for_scanner_status(api=api, status=API.Status.REGISTER, timeout=300,
                                    msg='Waiting for Nessus to be in register state')
            api.users.create(payload=NessusInstallation.ADMIN_USER_PAYLOAD)

            # Nessus registration
            activation_code = ActivationCodeGenerator()
            if nessus_type == "Nessus Essentials":
                code = activation_code.generate_nessus_home()
            else:
                code = activation_code.generate_nessus_manager_code() \
                    if nessus_type == "Nessus Manager" \
                    else activation_code.generate_nessus_professional()

            # Setting auto_update and custom_host fix parameters
            ssh.execute("{} fix --set auto_update=no".format(get_nessus_cli()))
            ssh.execute('{} fix --secure --set custom_host="{}"'.format(get_nessus_cli(),
                                                                        CommonConfig.CAT_PLUGIN_FEED_HOST))

            # Register Nessus and verify that registration is successful.
            registration_output = ssh.execute("{} fetch --register-only {}".format(get_nessus_cli(), code))
            assert any(NessusInstallation.REGISTRATION_SUCCESS == output_line for output_line in registration_output), \
                "Nessus registration is not successful. Registration output is {}".format(registration_output)

            # Offline plugin Update
            stop_nessus()
            plugin_update_output = ssh.execute("{} update --plugins-only".format(get_nessus_cli()))

            # Verify Nessus plugins update output
            assert set(NessusInstallation.PLUGINS_UPDATE_SUCCESS).issubset(plugin_update_output), \
                "Nessus Plugin update was not successful. Plugin update output is {}".format(plugin_update_output)
            start_nessus()

        # Wait till Nessus gets "ready" state
        sleep(20, reason="Waiting for Nessus service to get started")
        wait_for_scanner_status(api=api, status=API.Status.READY, timeout=TIME_FIFTEEN_MINUTES * 3,
                                msg='waiting to for Nessus to be in ready state')

        # Verify Nessus properties after successful installation and registration
        nessus_properties = api.server.properties()
        assert nessus_type == nessus_properties['nessus_type'], \
            "Nessus type is incorrect expected is {} and actual is {}".format(nessus_type,
                                                                              nessus_properties['nessus_type'])
        assert nessus_properties['nessus_ui_version'] and nessus_properties['nessus_ui_build'], \
            "Nessus version and/or build is empty."

        # Try Nessus api login and raise exception if any issues comes up
        try:
            api.login()
        except Exception as e:
            raise Exception("API login is not successful. Exception is : {}".format(e))

        # For Windows-OSs, sometimes it goes to 'loading' state again after the Nessus become ready.
        # Below code-block will make sure Nessus to be in ready state before the smoke tests gets executed.
        try:
            wait_for_scanner_status(api=api, status=API.Status.LOADING, timeout=TIME_THIRTY_SECONDS * 3,
                                    msg='waiting to for Nessus to be in loading state')
        except TimeoutExpired:
            log.info("Nessus does not 'loading' state.")
        finally:
            wait_for_scanner_status(api=api, status=API.Status.READY, timeout=TIME_FIVE_MINUTES,
                                    msg='waiting to for Nessus to be in ready state')

    @pytest.mark.parametrize('nessus_type', [
        pytest.param(ActivationCodeGenerator.NESSUS_PROFESSIONAL, marks=pytest.mark.install_nessus_pro)])
    def test_nessus_installation_steps_for_linux(self, nessus_type):
        """
        NES-11383: Add testcase of Nessus installation steps for Linux using CLI

        Scenario Tested:
            [x] Verify Nessus installation and registration steps.
        """
        installed_nessus_pckgs = []
        nessus_dir = None

        os_commands = {'CentOS': {'search_nessus': 'rpm -qa | grep Nessus', 'remove_nessus': 'rpm -e ',
                                  'install_nessus': 'rpm -ivh '},
                       'Ubuntu': {'remove_nessus': 'dpkg -r ', 'install_nessus': 'dpkg -i '},
                       'Kali': {'remove_nessus': 'dpkg -r ', 'install_nessus': 'dpkg -i '}}

        nessus_service_commands = {'start_nessus': 'supervisorctl start nessusd',
                                   'stop_nessus': 'supervisorctl stop nessusd',
                                   'service_status': 'supervisorctl status nessusd'}

        ssh = SSH()

        log.info('Check installed OS')
        check_installed_os = ssh.execute(command='cat /etc/os-release')
        installed_os = check_installed_os[0].split('=')[1].split()[0].strip('"')
        log.debug("Installed OS :: {}".format(installed_os))

        if installed_os == 'CentOS':
            log.info('Search for installed Nessus package')
            installed_nessus_pckgs = ssh.execute(command=os_commands[installed_os]['search_nessus'],
                                                 timeout=TIME_THIRTY_SECONDS)
            log.debug("Installed Nessus Packages :: {}".format(installed_nessus_pckgs))

        log.info('Stop Nessus service if running')
        stop_nessus_service_output = ssh.execute(command=nessus_service_commands['stop_nessus'],
                                                 timeout=TIME_FIVE_SECONDS)
        log.debug('Stopped Nessus service output :: {}'.format(stop_nessus_service_output))

        # Verifies the nessus service is getting stopped.
        assert 'nessusd: stopped' in stop_nessus_service_output[0], "Failed to stop Nessus service..."

        log.info('Uninstall Nessus')
        installed_nessus_package_name = installed_nessus_pckgs[0] if installed_os == 'CentOS' else 'nessus'
        uninstall_nessus_output = []

        for _ in range(2):
            uninstall_nessus = ssh.execute(
                command=os_commands[installed_os]['remove_nessus'] + installed_nessus_package_name)
            uninstall_nessus_output.append(uninstall_nessus)

        log.debug("Uninstall Nessus output :: {}".format(uninstall_nessus_output))

        # Verifies Nessus is uninstalled successfully
        if installed_os == 'CentOS':
            assert 'error: package {} is not installed'.format(installed_nessus_package_name) in \
                   uninstall_nessus_output[1], 'Failed to uninstall Nessus...'

            log.info('Check Nessus service status after getting uninstalled')
            nessus_service_status = ssh.execute(command=nessus_service_commands['service_status'])

            log.debug("Nessus service status output after uninstallation :: {}".format(nessus_service_status))
            status_command_output = 'STOPPED' if installed_os == 'CentOS' else 'Nessus is not running'

            # Verifies Nessus service is stopped after getting uninstalled
            assert status_command_output in nessus_service_status[0], \
                'Nessus service is still running after getting uninstalled...'
        else:
            assert all([bool(filter(lambda x: 'Removing nessus' in x, uninstall_nessus_output[0])),
                        bool(filter(lambda x: 'Shutting down Nessus' in x, uninstall_nessus_output[0]))]), \
                'Failed to uninstall Nessus...'

        log.info('Remove Nessus directories after getting uninstalled')
        for cmnd in ['rm -rf /opt/nessus', 'rm /opt/nessus']:
            nessus_dir = ssh.execute(command=cmnd)

        log.debug("Remove Nessus directories output :: {}".format(nessus_dir))

        # Verifies Nessus directory is getting removed successfully
        assert "rm: cannot remove" in nessus_dir[0] and "No such file or directory" in nessus_dir[0], \
            'Nessus directory is not getting removed.'

        nessus_pckg_type = 'rpm' if installed_os == 'CentOS' else 'deb'

        log.info('Search latest Nessus build to install')
        find_nessus_pckg = ssh.execute(command='find / -name "*.{}"'.format(nessus_pckg_type))
        log.debug("Nessus package path :: {}".format(find_nessus_pckg))

        log.info('Install latest Nessus package')
        install_nessus_output = ssh.execute(command=os_commands[installed_os]['install_nessus'] + find_nessus_pckg[0],
                                            timeout=TIME_FIVE_MINUTES)
        log.debug("Install Nessus output :: {}".format(install_nessus_output))

        # Verifies Nessus installation output results
        if installed_os == 'CentOS':
            assert all(['Preparing...' in install_nessus_output[0], 'installing...' in install_nessus_output[1],
                        'Unpacking Nessus Core Components...' in install_nessus_output[3],
                        'You can start Nessus by typing /bin/systemctl start nessusd.service' in
                        install_nessus_output[4]]), 'Failed to install Nessus in {}...'.format(installed_os)
        else:
            assert all(['Preparing to unpack' in install_nessus_output[2],
                        'Unpacking nessus' in install_nessus_output[3], 'Setting up nessus' in install_nessus_output[4],
                        'Unpacking Nessus Scanner Core Components...' in install_nessus_output[5]]), \
                'Failed to install Nessus in {}...'.format(installed_os)

        log.info('Start Nessus service after getting installed')
        start_nessus_output = ssh.execute(command=nessus_service_commands['start_nessus'])
        log.debug("Start Nessus output :: {}".format(start_nessus_output))

        # Verifies Nessus service is getting started
        assert 'nessusd: started' in start_nessus_output[0], 'Failed to start Nessus service...'

        log.info('Check Nessus service status')
        nessus_service_status = ssh.execute(command=nessus_service_commands['service_status'])
        log.debug("Nessus service status output :: {}".format(nessus_service_status))

        # Verifies Nessus service status is getting running
        assert 'RUNNING' in nessus_service_status[0], 'Failed to start Nessus service...'

        log.info('Waits for Nessus gets ready to get register')
        nessus_api = NessusAPI()
        wait_for_scanner_status(api=nessus_api, status=API.Status.REGISTER, timeout=TIME_FIVE_MINUTES,
                                msg='Waiting for nessus to get ready for register')

        log.info('Adding user into Nessus')
        add_user_output = users.adduser(username='admin', password='admin', passconfirm='admin', sysadmin=True)
        log.debug('Added user output :: {}'.format(add_user_output))

        # Verifies user is added successfully in Nessus
        assert 'User added' in add_user_output['stdout'], 'Failed to add user in Nessus...'

        log.info("Setting auto_update value to 'no'")
        set_auto_update_output = ssh.execute("{} fix --set auto_update=no".format(get_nessus_cli()))
        log.debug("Set auto_update value output :: {}".format(set_auto_update_output))

        # Verifies auto_update setting value gets updated successfully
        assert all(["Successfully set 'auto_update' to 'no'." in set_auto_update_output[0],
                    "The Nessus web server will be restarted." in set_auto_update_output[1]]), \
            "Failed to set auto_update setting value to 'no'."

        log.info("Set {} as a plugin feed host".format(CommonConfig.CAT_PLUGIN_FEED_HOST))
        set_plugin_feed_output = ssh.execute(command='{} fix --secure --set custom_host="{}"'.format(
            get_nessus_cli(), CommonConfig.CAT_PLUGIN_FEED_HOST))
        log.debug("Plugin feed host output :: {}".format(set_plugin_feed_output))

        # Verifies plugin feed host gets set successfully as a custom host
        assert "Successfully set 'custom_host' to '{}'.".format(CommonConfig.CAT_PLUGIN_FEED_HOST) in \
               set_plugin_feed_output[0], 'Failed to set plugin feed host as a custom host...'

        log.info('Generates activation code for Nessus {}'.format(nessus_type))
        activation_code = ActivationCodeGenerator().generate_code(code_type=nessus_type,
                                                                  expiration_days=Nessus.DEFAULT_EXPIRATION_DAYS)

        log.debug('Activation code for Nessus {} :: {}'.format(nessus_type, activation_code))

        log.info("Register Nessus {}".format(nessus_type))
        register_nessus_output = ssh.execute("{} fetch --register-only {}".format(get_nessus_cli(), activation_code))
        log.debug("Register Nessus output :: {}".format(register_nessus_output))

        # Verifies successful Nessus registration message
        assert any('Your Activation Code has been registered properly - thank you.' in register_output for
                   register_output in register_nessus_output), 'Failed to register Nessus {}'.format(nessus_type)

        log.info('Update Nessus plugins')
        update_plugin_output = ssh.execute("{} update --plugins-only".format(get_nessus_cli()),
                                           timeout=TIME_FIVE_MINUTES)
        log.debug("Update plugin output :: {}".format(update_plugin_output))

        # Verifies Nessus plugins are updated successfully
        assert all(['Nessus Plugins: Complete' in update_plugin_output,
                    bool(filter(lambda x: 'Nessus Plugins are now up-to-date' in x, update_plugin_output))]), \
            'Failed to update Nessus plugins...'

        log.info('Waiting for Nessus to be ready after updating plugins')
        wait_for_scanner_status(api=nessus_api, status=API.Status.READY, timeout=TIME_THIRTY_MINUTES,
                                msg='Waiting for Nessus to be Ready'), 'Nessus is failed to be ready...'

        log.info('Get Nessus details to verify installed Nessus')
        nessus_details = nessus_api.server.properties()
        log.debug('Nessus Details :: {}'.format(nessus_details))

        installed_nessus_type = 'Nessus ' + ('Essentials' if nessus_type == 'home' else nessus_type.capitalize())

        # Verifies installed Nessus type
        assert nessus_details['nessus_type'] == installed_nessus_type, \
            'Invalid Nessus type. Expected Nessus type is :: {}'.format(installed_nessus_type)

        # Verifies installed Nessus version and build
        assert nessus_details['nessus_ui_version'] and nessus_details['nessus_ui_build'], \
            'Failed to get Nessus UI version and build.'

        log.info("===== Installed Nessus Details =====")
        log.info("Nessus Type :: {}".format(nessus_details['nessus_type']))
        log.info("Nessus Version :: {}".format(nessus_details['nessus_ui_version']))
        log.info("Nessus UI Build :: {}".format(nessus_details['nessus_ui_build']))
        log.info("====================================")
