"""
Utilities to help partially automate regression testing. These should be kicked off locally and not run though Jenkins.

:copyright: Tenable Network Security, 2023
:date: June 30, 2023
:author: stellex
"""

import time

from catium.helpers.testdata import get_file_path
from catium.lib.activation_code_generator import ActivationCodeGenerator
from catium.lib.config import CommonConfig
from catium.lib.const import STRING_NO, TIME_THIRTY_MINUTES, TIME_THIRTY_SECONDS, STRING_YES, TIME_NINETY_SECONDS
from catium.lib.log import create_logger
from catium.lib.ssh import SSH
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.nessuscli import users
from nessus.helpers.scan_class import Scan
from nessus.helpers.scanner import wait_for_scanner_status
from nessus.lib.const import Nessus, OperatingSystems
from nessus.lib.const.constants import API


log = create_logger()

"""
    SETUP STEPS
    
    1. Set VERSION to desired version of Nessus
    2. Set LICENSE_TYPE to desired licence level - 'home', 'professional', 'manager', or 'expert'
    3. Set PUBLIC_KEY_PATH to local path to the desired public key for AWS instances
    4. Start/create VMs/AWS instances you wish to test on
    5. Download required Nessus package for each instance and push the file to the ~ directory
    6. Ensure each OS package has a line in the package name builders
    7. Add dict entry for each VM/AWS instance to the IP_LIST. Include the following key/value pairs:
        ip_address - the IP address of the VM/AWS instance
        username - the SSH username used to login
        password - OPTIONAL - REQUIRED ONLY IF THE PASSWORD IS NOT ALREADY 'LabPass1' for SSH, this is the SSH password
        install_file - the package name builder (such as 'AMZN_2_PACKAGE_NAME') for the particular OS
        aws - whether or not the instance is an AWS instance
        home_dir - OPTIONAL - REQUIRED IF THE ADD USER FUNCTION DOES NOT LIKE NON-ROOT USERS - this is the username of
            the ~ directory if it has to be different from the username value, see Known Issues in TestOSSanity
        public_key - OPTIONAL - path to the public key on your local machine if it is different from PUBLIC_KEY_PATH
    
    EXECUTION STEPS - Note this has manual instructions for executing the OS sanity testing that may not apply to what
        you need this utility for
    
    1. Run test_nessus_install. This will loop through each entry in IP_LIST and install Nessus based on the package
        name. The package should be pushed to the ~ directory manually as part of the SETUP STEPS
    2. Run test_register_nessus. This will loop through each entry in IP_LIST and register Nessus with a license defined
        in LICENSE_TYPE, then add a user with username 'admin' and a password of 'admin'. Several advanced settings will
        also be set to facilitate testing, upgrading, and downgrading.
    3. Manually create and run a basic scan for each test instance. This is planned to be automated within this utility
        but is not yet.
    4. Manually downgrade each instance to the Stable version, then upgrade back to the GA version.
    5. Manually upgrade each instance to the EA version, then downgrade back to the GA version.
    6. Run test_uninstall_nessus. This will loop through each entry in IP_LIST and stop the Nessus service, uninstall 
        Nessus, then remove the /opt/nessus/ directory.
"""

VERSION = "10.11.0"
BUILD = "R22280"
NEXUS_URL = f"https://nexus.cloud.aws.tenablesecurity.com/repository/product-release/nessus/{VERSION}/"
LICENSE_TYPE = "professional"
PUBLIC_KEY_PATH = "/Users/stellex/.ssh/stellex-us-east-1.pem"


def package_name_builder(version: str, arch: str, os_key: str, extension: str):
    return f"Nessus-{version}-{os_key}.{arch}.{extension}"


AMZN_2_PACKAGE_NAME = package_name_builder(version=VERSION, arch="x86_64", os_key="amzn2", extension="rpm")
AMZN_2_GRAVITON_PACKAGE_NAME = package_name_builder(version=VERSION, arch="aarch64", os_key="amzn2", extension="rpm")
DEBIAN_32_BIT_PACKAGE_NAME = f"Nessus-{VERSION}-debian10_i386.deb"
DEBIAN_64_BIT_PACKAGE_NAME = f"Nessus-{VERSION}-debian10_amd64.deb"
EL6_PACKAGE_NAME = package_name_builder(version=VERSION, arch="x86_64", os_key="el6", extension="rpm")
EL7_PACKAGE_NAME = package_name_builder(version=VERSION, arch="x86_64", os_key="el7", extension="rpm")
EL7_GRAVITON_PACKAGE_NAME = package_name_builder(version=VERSION, arch="aarch64", os_key="el7", extension="rpm")
EL8_PACKAGE_NAME = package_name_builder(version=VERSION, arch="x86_64", os_key="el8", extension="rpm")
EL8_GRAVITON_PACKAGE_NAME = package_name_builder(version=VERSION, arch="aarch64", os_key="el8", extension="rpm")
EL9_PACKAGE_NAME = package_name_builder(version=VERSION, arch="x86_64", os_key="el9", extension="rpm")
EL9_GRAVITON_PACKAGE_NAME = package_name_builder(version=VERSION, arch="aarch64", os_key="el9", extension="rpm")
FEDORA_PACKAGE_NAME = package_name_builder(version=VERSION, arch="x86_64", os_key="fc38", extension="rpm")
FREEBSD_PACKAGE_NAME = package_name_builder(version=VERSION, arch="x86_64", os_key="fbsd12", extension="rpm")
RASPBERRY_PI_PACKAGE_NAME = f"Nessus-{VERSION}-raspberrypios_armhf.deb"
MACOS_PACKAGE_NAME = f"Nessus-{VERSION}.dmg"
SUSE_12_PACKAGE_NAME = package_name_builder(version=VERSION, arch="x86_64", os_key="suse12", extension="rpm")
SUSE_15_PACKAGE_NAME = package_name_builder(version=VERSION, arch="x86_64", os_key="suse15", extension="rpm")
UBUNTU_PACKAGE_NAME = f"Nessus-{VERSION}-ubuntu1604_amd64.deb"
UBUNTU_32_BIT_PACKAGE_NAME = f"Nessus-{VERSION}-ubuntu1604_i386.deb"
UBUNTU_GRAVITON_PACKAGE_NAME = f"Nessus-{VERSION}-ubuntu1804_aarch64.deb"
WINDOWS_PACKAGE_NAME = f"Nessus-{VERSION}-x64.msi"

IP_LIST = [
    # AWS Hosts
    # Amazon Linux
    {"ip_address": "10.254.170.245", "username": "ec2-user", "install_file": AMZN_2_PACKAGE_NAME, "aws": True, "name": "amazonlinux2"}, # Amazon Linux 2
    {"ip_address": "10.254.171.68", "username": "ec2-user", "install_file": AMZN_2_GRAVITON_PACKAGE_NAME, "aws": True, "name": "amazonlinux2arm"}, # Amazon Linux 2 ARM
    {"ip_address": "10.254.170.106", "username": "ec2-user", "install_file": AMZN_2_PACKAGE_NAME, "aws": True, "name": "amazonlinux2023"}, # Amazon Linux 2023
    {"ip_address": "10.254.170.101", "username": "ec2-user", "install_file": AMZN_2_GRAVITON_PACKAGE_NAME, "aws": True, "name": "amazonlinux2023arm"},  # Amazon Linux 2023 ARM

    # Alma Linux
    {"ip_address": "10.254.170.11", "username": "ec2-user", "install_file": EL9_PACKAGE_NAME, "aws": True, "name": "alma10"},  # AlmaLinux 10

    # CentOS
    {"ip_address": "10.254.170.99", "username": "centos", "install_file": EL8_GRAVITON_PACKAGE_NAME, "aws": True, "name": "centos8arm"},  # CentOS8 ARM
    {"ip_address": "10.254.170.167", "username": "ec2-user", "install_file": EL9_PACKAGE_NAME, "aws": True, "name": "centos9stream"},  # CentOS9 Stream
    {"ip_address": "10.254.170.249", "username": "ec2-user", "install_file": EL9_PACKAGE_NAME, "aws": True, "name": "centos10stream"},  # CentOS10 Stream

    # Debian
    {"ip_address": "10.254.170.6", "username": "admin", "install_file": DEBIAN_64_BIT_PACKAGE_NAME, "aws": True, "name": "debian11"}, # Debian 11
    {"ip_address": "10.254.170.202", "username": "admin", "install_file": DEBIAN_64_BIT_PACKAGE_NAME, "aws": True, "name": "debian12"}, # Debian 12
    {"ip_address": "10.254.170.196", "username": "admin", "install_file": DEBIAN_64_BIT_PACKAGE_NAME, "aws": True, "name": "debian13"}, # Debian 13

    # Miracle Linux
    {"ip_address": "10.254.170.247", "username": "ec2-user", "install_file": EL9_PACKAGE_NAME, "aws": True, "name": "miracle9"},  # Miracle Linux 9

    # RHEL
    {"ip_address": "10.254.170.233", "username": "ec2-user", "install_file": EL9_PACKAGE_NAME, "aws": True, "name": "rhel9"},  # RHEL9
    {"ip_address": "10.254.170.231", "username": "ec2-user", "install_file": EL9_GRAVITON_PACKAGE_NAME, "aws": True, "name": "rhel9arm"},  # RHEL9 ARM
    {"ip_address": "10.254.170.92", "username": "ec2-user", "install_file": EL9_PACKAGE_NAME, "aws": True, "name": "rhel10"},  # RHEL10
    {"ip_address": "10.254.170.207", "username": "ec2-user", "install_file": EL9_GRAVITON_PACKAGE_NAME, "aws": True, "name": "rhel10arm"},  # RHEL10 ARM

    # Rocky Linux
    {"ip_address": "10.254.170.60", "username": "rocky", "install_file": EL9_PACKAGE_NAME, "aws": True, "name": "rocky10"},  # Rocky Linux 10

    # SUSE
    {"ip_address": "10.254.170.197", "username": "ec2-user", "install_file": SUSE_12_PACKAGE_NAME, "aws": True, "name": "suse12"},  # SUSE 12

    # Ubuntu
    {"ip_address": "10.254.170.157", "username": "ubuntu", "install_file": UBUNTU_GRAVITON_PACKAGE_NAME, "aws": True, "name": "ubuntu2204arm"}, # Ubuntu 22.04 ARM

    # Vsphere Hosts
    # CentOS
    {"ip_address": "172.26.103.141", "username": "tenable", "install_file": EL7_PACKAGE_NAME, "aws": False, "name": "centos7"},  # CentOS7

    # Debian
    # {"ip_address": "172.26.103.183", "username": "tenable", "install_file": DEBIAN_64_BIT_PACKAGE_NAME, "aws": False, "name": "debian10"},  # Debian 10

    # Fedora
    # {"ip_address": "172.26.100.138", "username": "root", "install_file": FEDORA_PACKAGE_NAME, "aws": False, "name": "fedora41"},  # Fedora 41
    {"ip_address": "172.26.100.139", "username": "tenable", "install_file": FEDORA_PACKAGE_NAME, "aws": False, "name": "fedora42"},  # Fedora 42

    # Oracle Linux
    {"ip_address": "172.26.103.122", "username": "tenable", "install_file": EL8_PACKAGE_NAME, "aws": False, "name": "oraclelinux8"}, # Oracle Linux 8

    # Raspberry Pi
    # {"ip_address": "dev-pi-001.lab.tenablesecurity.com", "username": "pi", "install_file": RASPBERRY_PI_PACKAGE_NAME, "aws": False, "name": "raspberrypi"},  # Raspberry Pi

    # SUSE 15
    {"ip_address": "172.26.103.245", "username": "root", "install_file": SUSE_15_PACKAGE_NAME, "aws": False, "home_dir": "tenable", "name": "suse15"},

    # TencentOS
    {"ip_address": "172.26.103.117", "username": "tencent", "password": "tencentospassword", "install_file": EL8_PACKAGE_NAME, "aws": False, "name": "tencentos"},  # TencentOS

    # Ubuntu
    {"ip_address": "172.26.103.194", "username": "tenable", "password": "LabPass1", "install_file": UBUNTU_PACKAGE_NAME, "aws": False, "name": "ubuntu1804"},  # Ubuntu 18.04
    {"ip_address": "172.26.103.192", "username": "tenable", "install_file": UBUNTU_32_BIT_PACKAGE_NAME, "aws": False, "home_dir": "tenable", "name": "ubuntu1604_32bit"}, # Ubuntu 16.04 32-bit

    # Windows
    {"ip_address": "172.26.103.230", "username": "Administrator", "password": "LabPass1", "install_file": WINDOWS_PACKAGE_NAME, "aws": False, "name": "windows2019"},  # Windows Server 2019
    {"ip_address": "172.26.103.157", "username": "Administrator", "password": "LabPass1", "install_file": WINDOWS_PACKAGE_NAME, "aws": False, "name": "windows2022"},  # Windows Server 2022

    # MacOS
    # {"ip_address": "172.26.114.84", "username": "Admin", "password": "LabPass1", "install_file": MACOS_PACKAGE_NAME, "aws": False, "name": "macos13"},  # MacOS 13.4
    {"ip_address": "172.26.114.82", "username": "Admin", "password": "LabPass1", "install_file": MACOS_PACKAGE_NAME, "aws": False, "name": "macos14"},  # MacOS 14.7.2
    {"ip_address": "172.26.114.83", "username": "Admin", "password": "LabPass1", "install_file": MACOS_PACKAGE_NAME, "aws": False, "name": "macos15"},  # MacOS 15.0.1
    {"ip_address": "172.26.114.81", "username": "Admin", "password": "LabPass1", "install_file": MACOS_PACKAGE_NAME, "aws": False, "name": "macos26"},  # MacOS 26.0.0
]


class TestOSSanity:
    """
    Functions to help test OS sanity for multiple platforms. Provide a list of pre-spun up instances, either AWS or
    in the lab, to execute against.

    Known issues:
        - Ubuntu versions may have trouble adding a user - add user needs a root user that doesn't always work with
            Ubuntu. If "Failed to add user in Nessus..." displays that host may not work with this utility
        - Certain OS need a root user to use pexpect that is different than the main user. If this is the case, in
            IP_LIST set username to 'root' and home_dir to 'tenable', or whichever user's home directory the package is
            in
    """

    cat = None

    def test_download_nessus_package(self):
        def download_package(download_filepath: str, download_url: str):
            download_command = f"curl -o {download_filepath} {download_url}"
            sudo = False if CAT_PLATFORM == OperatingSystems.WINDOWS else True
            ssh.execute(download_command, sudo=sudo)

        for ip in IP_LIST:
            global CAT_PLATFORM
            CAT_PLATFORM = OperatingSystems.WINDOWS if "windows" in ip["name"] else "darwin" if "macos" in ip["name"] else OperatingSystems.LINUX
            public_key = None
            if ip["aws"]:
                public_key = PUBLIC_KEY_PATH if "public_key" not in ip.keys() else ip["public_key"]
                password = None
            else:
                password = ip["password"] if "password" in ip.keys() else "LabPass1"

            ip_address = ip["ip_address"]
            username = ip["username"]
            install_file = ip["install_file"]
            download_path = f"/home/{username}/{install_file}" if CAT_PLATFORM == OperatingSystems.LINUX else f"/Users/{username}/{install_file}" if CAT_PLATFORM == "darwin" else rf"C:\Users\{username}\{install_file}"
            nexus_url = NEXUS_URL + install_file

            if ip["aws"]:
                with SSH(url_or_ip=ip_address, username=username, public_key_path=public_key) as ssh:
                    download_package(download_filepath=download_path, download_url=nexus_url)
            else:
                with SSH(url_or_ip=ip_address, username=username, password=password) as ssh:
                    download_package(download_filepath=download_path, download_url=nexus_url)

    def test_nessus_install(self):
        def install_nessus(user, file):
            if CAT_PLATFORM == OperatingSystems.LINUX:
                nessuscli_path = "/opt/nessus/sbin/nessuscli"
                launch_command = "systemctl"
                if ".deb" in install_file:
                    install_commands = [f"dpkg --force-all -i /home/{user}/{file}"]
                elif ".rpm" in install_file:
                    install_commands = [f"rpm -ivh --force /home/{user}/{file}"]
            elif CAT_PLATFORM == OperatingSystems.WINDOWS:
                file_path = rf"C:\\Users\\{user}\\{file}"
                nessuscli_path = '"C:/Program Files/Tenable/Nessus/nessuscli"'
                launch_command = ""
                install_commands = [f'msiexec /i {file_path} /qn']
            else:
                nessuscli_path = "/Library/Nessus/run/sbin/nessuscli"
                launch_command = "launchctl"
                install_commands = ["diskutil unmount /Volumes/Nessus\\ Install", f"hdiutil attach ./{file}", "installer -allowUntrusted -pkg /Volumes/Nessus\\ Install/Install\\ Nessus.pkg -target /", "diskutil unmount /Volumes/Nessus\\ Install"]
            sudo = False if CAT_PLATFORM == OperatingSystems.WINDOWS else True
            install_output = []
            for install_command in install_commands:
                output = ssh.execute(install_command, sudo=sudo)
                install_output.extend(output)

            # SCE-4408: Verify FIPS module integrity checks pass during install
            if CAT_PLATFORM == OperatingSystems.LINUX:
                output_text = " ".join(install_output)
                assert "FIPS module Module_Integrity HMAC test FAIL" not in output_text, \
                    f"FIPS Module_Integrity HMAC FAIL in install output for {ip['name']}: {install_output}"
                assert "FIPS module Install_Integrity HMAC test FAIL" not in output_text, \
                    f"FIPS Install_Integrity HMAC FAIL in install output for {ip['name']}: {install_output}"
                log.info(f"FIPS integrity checks passed for {ip['name']}")
            if CAT_PLATFORM != OperatingSystems.WINDOWS:
                launch_output = ssh.execute(f"{launch_command} start nessusd", sudo=sudo)
                if len(launch_output) > 0 and "command not found" in launch_output[0]:
                    ssh.execute("service nessusd start", sudo=sudo)

            time.sleep(10)

            if "release" not in VERSION and "master" not in VERSION:
                version_correct = False
                i = 0
                while i < 300:
                    version_output = ssh.execute(f"{nessuscli_path} -v", sudo=sudo)
                    if version_output[0] == f"nessuscli (Nessus) {VERSION} [build {BUILD}]":
                        version_correct = True
                        break
                    else:
                        f"Expected Nessus build {BUILD} and version {VERSION} did not match actual output: {version_output}, waiting to try again"
                        i += 1
                        time.sleep(1)
                assert version_correct, f"Expected Nessus build {BUILD} and version {VERSION} did not match actual output: {version_output}"

        for ip in IP_LIST:
            public_key = None
            global CAT_PLATFORM
            CAT_PLATFORM = OperatingSystems.WINDOWS if "windows" in ip["name"] else "darwin" if "macos" in ip["name"] else OperatingSystems.LINUX
            if ip["aws"]:
                public_key = PUBLIC_KEY_PATH if "public_key" not in ip.keys() else ip["public_key"]
                password = None
            else:
                password = ip["password"] if "password" in ip.keys() else "LabPass1"
            ip_address = ip["ip_address"]
            username = ip["username"]
            install_file = ip["install_file"]

            if ip["aws"]:
                with SSH(url_or_ip=ip_address, username=username, public_key_path=public_key) as ssh:
                    install_nessus(file=install_file, user=username)
            else:
                with SSH(url_or_ip=ip_address, username=username, password=password) as ssh:
                    install_nessus(file=install_file, user=username)

    def test_register_nessus(self):
        def set_nessus_settings(sudo):
            ssh.execute(f"{nessuscli_path} fix --set fips_mode=enforcing", sudo=sudo)

            settings_details = [{'setting_name': 'auto_update', 'setting_value': STRING_NO, 'secure': False},
                                {'setting_name': 'backend_log_level', 'setting_value': 'verbose', 'secure': False},
                                {'setting_name': 'custom_host', 'setting_value': CommonConfig.CAT_PLUGIN_FEED_HOST_STAGING, 'secure': True},
                                {'setting_name': 'disable_core_updates', 'setting_value': STRING_YES, 'secure': False}]

            for setting in settings_details:
                log.info(f"Setting {setting['setting_name']} value to {setting['setting_value']}")
                if setting["secure"]:
                    setting_output = ssh.execute(f"{nessuscli_path} fix --set --secure {setting['setting_name']}={setting['setting_value']}", sudo=sudo)
                else:
                    setting_output = ssh.execute(f"{nessuscli_path} fix --set {setting['setting_name']}={setting['setting_value']}", sudo=sudo)

                assert f"Successfully set '{setting['setting_name']}' to '{setting['setting_value']}'" in \
                       setting_output[0], f"Updating {setting['setting_name']} setting to {setting['setting_value']} " \
                                          f"wasn't successful"

        def wait_for_status(status, sudo, timeout=TIME_THIRTY_MINUTES,):
            nessus_api = NessusAPI(url=f"https://{ip_address}:8834", login=sudo)

            log.info('restarted nessus and wait for to be ready.')
            wait_for_scanner_status(api=nessus_api, status=status, timeout=timeout,
                                    msg=f'Wait for Nessus to be {status}', sleep_interval=TIME_THIRTY_SECONDS)

        def restart_nessus(status, sudo):
            if CAT_PLATFORM == OperatingSystems.LINUX:
                output = ssh.execute(command="supervisorctl stop nessusd", sudo=sudo)
                if all(['nessusd: stopped' not in op for op in output]):
                    ssh.execute(command='systemctl stop nessusd', sudo=sudo)
                output = ssh.execute(command="supervisorctl start nessusd", sudo=sudo)
                if all(['nessusd: started' not in op for op in output]):
                    ssh.execute(command='service nessusd start', sudo=sudo)
            elif CAT_PLATFORM == OperatingSystems.WINDOWS:
                ssh.execute(command='net start "Tenable Nessus"', sudo=sudo)
            else:
                ssh.execute(command="launchctl start com.tenablesecurity.nessusd", sudo=sudo)
            try:
                wait_for_status(API.Status.READY, sudo=sudo, timeout=TIME_NINETY_SECONDS)
            except:
                wait_for_status(status, sudo=sudo)

        def add_user(au_ssh_args: dict):
            """  """
            log.debug('Adding user into Nessus')
            users.rmuser(username='admin', ssh_args=au_ssh_args, cli_path=nessuscli_path,
                         override_sudo=True, nessus_platform=OperatingSystems.LINUX)
            add_user_output = users.adduser(username='admin', password='admin', passconfirm='admin', sysadmin=True,
                                            ssh_args=au_ssh_args, cli_path=nessuscli_path,
                                            override_sudo=True, nessus_platform=CAT_PLATFORM)

            # Verifies user is added successfully in Nessus
            assert 'User added' in add_user_output['stdout'], 'Failed to add user in Nessus...'

        def register_nessus(expiration_days: float, nessus_type: str, sudo: bool):
            activation_code = ActivationCodeGenerator()

            code = activation_code.generate_nessus_manager_code(expiration_days=expiration_days) \
                if LICENSE_TYPE == ActivationCodeGenerator.NESSUS_MANAGER else activation_code.generate_code(
                code_type=LICENSE_TYPE, expiration_days=expiration_days)

            log.debug(f"Register Nessus {nessus_type}")

            output = ssh.execute(f"{nessuscli_path} fetch --register {code}", sudo=sudo)
            pass

        for ip in IP_LIST:
            global CAT_PLATFORM
            CAT_PLATFORM = OperatingSystems.WINDOWS if "windows" in ip["name"] else "darwin" if "macos" in ip["name"] else OperatingSystems.LINUX
            if CAT_PLATFORM == OperatingSystems.LINUX:
                nessuscli_path = "/opt/nessus/sbin/nessuscli"
                sudo = True
            elif CAT_PLATFORM == OperatingSystems.WINDOWS:
                nessuscli_path = '"C:/Program Files/Tenable/Nessus/nessuscli"'
                sudo = False
            else:
                nessuscli_path = "/Library/Nessus/run/sbin/nessuscli"
                sudo = True
            public_key = None
            if ip["aws"]:
                public_key = PUBLIC_KEY_PATH if "public_key" not in ip.keys() else ip["public_key"]
                password = None
            else:
                password = ip["password"] if "password" in ip.keys() else "LabPass1"
            ip_address = ip["ip_address"]
            username = ip["username"]

            if ip["aws"]:
                ssh_args = {"url_or_ip": ip_address, "username": username, "public_key_path": public_key}
            else:
                ssh_args = {"url_or_ip": ip_address, "username": username, "password": password}

            if "password" in ssh_args.keys():
                with SSH(url_or_ip=ssh_args["url_or_ip"], username=ssh_args["username"], password=ssh_args["password"]) as ssh:
                    wait_for_status(API.Status.REGISTER, sudo=sudo)
                    set_nessus_settings(sudo=sudo)
                    register_nessus(expiration_days=Nessus.DEFAULT_EXPIRATION_DAYS, nessus_type=LICENSE_TYPE, sudo=sudo)
            else:
                with SSH(url_or_ip=ssh_args["url_or_ip"], username=ssh_args["username"],
                         public_key_path=ssh_args["public_key_path"]) as ssh:
                    wait_for_status(status=API.Status.REGISTER, sudo=sudo)
                    set_nessus_settings(sudo=sudo)
                    register_nessus(expiration_days=Nessus.DEFAULT_EXPIRATION_DAYS, nessus_type=LICENSE_TYPE, sudo=sudo)

            add_user(au_ssh_args=ssh_args)
            restart_nessus(API.Status.LOADING, sudo=sudo)

    def test_create_and_execute_scan(self):
        scan_json_path = get_file_path('nessus/tests/utilities/test_data/test_nessus_os_sanity_basic_scan.json')
        scan_type = "basic"
        for ip in IP_LIST:
            nessus_api_handler = NessusAPI(login=True, url=f"https://{ip['ip_address']}:8834")
            nessus_api_handler.login()
            scan = Scan(scan_data_path=scan_json_path, scan_type=scan_type,
                        api_handler=nessus_api_handler)

            scan.create_scan()
            scan_exists = scan.scan_state()

            assert scan_exists, 'Failed to create scan'

            scan.start_scan()

    def test_update_nessus(self):
        # Update channel values: ea, ga, stable
        update_channel = "ga"

        def set_nessus_settings():
            settings_details = [{'setting_name': 'auto_update', 'setting_value': STRING_YES, 'secure': False},
                                {'setting_name': 'disable_core_updates', 'setting_value': STRING_NO, 'secure': False},
                                {'setting_name': 'scanner_update_channel', 'setting_value': update_channel, 'secure': False}]

            for setting in settings_details:
                log.info(f"Setting {setting['setting_name']} value to {setting['setting_value']}")
                if setting["secure"]:
                    setting_output = ssh.execute(f"/opt/nessus/sbin/nessuscli fix --set --secure {setting['setting_name']}={setting['setting_value']}", sudo=True)
                else:
                    setting_output = ssh.execute(f"/opt/nessus/sbin/nessuscli fix --set {setting['setting_name']}={setting['setting_value']}", sudo=True)

        for ip in IP_LIST:
            public_key = None
            if ip["aws"]:
                public_key = PUBLIC_KEY_PATH if "public_key" not in ip.keys() else ip["public_key"]
                password = None
            else:
                password = ip["password"] if "password" in ip.keys() else "LabPass1"
            ip_address = ip["ip_address"]
            username = ip["username"]
            if ip["aws"]:
                with SSH(url_or_ip=ip_address, username=username, public_key_path=public_key) as ssh:
                    set_nessus_settings()
                    update_output = ssh.execute(f"/opt/nessus/sbin/nessuscli update", sudo=True)
            else:
                with SSH(url_or_ip=ip_address, username=username, password=password) as ssh:
                    set_nessus_settings()
                    update_output = ssh.execute(f"/opt/nessus/sbin/nessuscli update", sudo=True)

    def test_nessus_uninstall(self):
        def uninstall():
            install_file = ip["install_file"]
            sudo = True
            if CAT_PLATFORM == OperatingSystems.LINUX:
                if ".deb" in install_file:
                    uninstall_commands = [f"dpkg -r Nessus", "rm -rf /opt/nessus/"]
                elif ".rpm" in install_file:
                    uninstall_commands = [f"rpm -e Nessus-{VERSION}", "rm -rf /opt/nessus/"]
                else:
                    raise ValueError(f"Uninstall commands for file {install_file} not found")
                output = ssh.execute(command="supervisorctl stop nessusd", sudo=sudo)
                if all(['nessusd: stopped' not in op for op in output]):
                    ssh.execute(command='systemctl stop nessusd', sudo=sudo)
            elif CAT_PLATFORM == OperatingSystems.WINDOWS:
                sudo = False
                uninstall_commands = [rf'msiexec.exe /x "C:\Users\{username}\{install_file}" /qn']
            else:
                uninstall_commands = ["launchctl stop nessusd", "rm -rf /Library/Nessus", "rm /Library/LaunchDaemons/com.tenablesecurity.nessus.plist", 'rm -r "/Library/PreferencePanes/Nessus Preferences.prefPane/']

            for uninstall_command in uninstall_commands:
                ssh.execute(uninstall_command, sudo=sudo)

        for ip in IP_LIST:
            global CAT_PLATFORM
            CAT_PLATFORM = OperatingSystems.WINDOWS if "windows" in ip["name"] else "darwin" if "macos" in ip["name"] else OperatingSystems.LINUX
            public_key = None
            if ip["aws"]:
                public_key = PUBLIC_KEY_PATH if "public_key" not in ip.keys() else ip["public_key"]
                password = None
            else:
                password = ip["password"] if "password" in ip.keys() else "LabPass1"
            ip_address = ip["ip_address"]
            username = ip["username"]

            if ip["aws"]:
                with SSH(url_or_ip=ip_address, username=username, public_key_path=public_key) as ssh:
                    uninstall()
            else:
                with SSH(url_or_ip=ip_address, username=username, password=password) as ssh:
                    uninstall()
