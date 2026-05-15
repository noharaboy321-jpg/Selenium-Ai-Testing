"""
Host Credential Mixin

TODO Handle Privilege Escalation
"""
from catium.lib.const import STRING_NO, STRING_YES, Protocols
from nessus.lib.const import API


class HostMixin:
    """
    Mixin class for creating Host credential dictionaries

    .. note:: SSH Host credentials use a 'Elevate privileges with' with an value of 'Nothing', for now.
    .. note:: File uploads require an active API session, this must be passed in if dealing with file uploads.
    """

    class Host:
        """
        Host class for creating host credential dictionaries.
        """

        @staticmethod
        def create_ssh_publickey_credential(api, username: str, private_key: str, key_passphrase: str=None,
                                            port: int=API.Credentials.Host.Ports.SSH,
                                            elevate_privileges: str=API.Credentials.Host.PrivilegeEscalation.NOTHING,
                                            known_hosts: str=None) -> dict:
            """
            Create a SSH Public Key credential dictionary

            :param api: Nessus/TenableCloud API instance
            :param str username: Username
            :param str private_key: Path to private key
            :param str key_passphrase: Private key passphrase
            :param int port: Preferred SSH Port
            :param str elevate_privileges: CyberArk elevate privileges with. Default: Nothing.
            :param str known_hosts: Known Hosts file
            :returns: dict
            """
            filename = api.file.upload(private_key)
            dct = {'auth_method': API.Credentials.Host.SSHAuthTypes.PUBLIC_KEY, 'username': username, 'port': port,
                   'private_key': filename, 'elevate_privileges_with': elevate_privileges}
            if key_passphrase:
                dct['private_key_passphrase'] = key_passphrase
            if known_hosts:
                filename = api.file.upload(known_hosts)
                dct['ssh_known_hosts'] = filename
            return dct

        @staticmethod
        def create_ssh_certificate_credential(api, username: str, certificate: str, private_key: str,
                                              key_passphrase: str=None, port: int=API.Credentials.Host.Ports.SSH,
                                              elevate_privileges: str=API.Credentials.Host.PrivilegeEscalation.NOTHING,
                                              known_hosts: str=None) -> dict:
            """
            Create a SSH Certificate credential dictionary

            :param api: Nessus/TenableCloud API instance
            :param str username: Username
            :param str certificate: Path to certificate
            :param str private_key: Path to private key
            :param str key_passphrase: Private key passphrase
            :param int port: Preferred SSH Port
            :param str elevate_privileges: CyberArk elevate privileges with. Default: Nothing.
            :param str known_hosts: Known Hosts file
            :returns: dict
            """
            cert = api.file.upload(certificate)
            pkey = api.file.upload(private_key)
            dct = {'auth_method': API.Credentials.Host.SSHAuthTypes.CERTIFICATE, 'username': username, 'port': port,
                   'user_cert': cert, 'private_key': pkey, 'elevate_privileges_with': elevate_privileges}
            if key_passphrase:
                dct['private_key_passphrase'] = key_passphrase
            if known_hosts:
                filename = api.file.upload(known_hosts)
                dct['ssh_known_hosts'] = filename
            return dct

        @staticmethod
        def create_ssh_cyberark_credential(username: str, host: str, safe: str, appid: str, folder_id: str,
                                           provider_username: str=None, policyid: str=None, use_ssl: bool=True,
                                           verify_ssl: bool=True, port: int=443,
                                           elevate_privileges: str=API.Credentials.Host.PrivilegeEscalation.NOTHING,
                                           api=None, known_hosts: str=None) -> dict:
            """
            Create a SSH CyberArk credential dictionary

            .. note:: elevate_privileges ONLY supports Nothing and should be left alone, for now.

            :param str username: Username
            :param str host: Central credential provider host
            :param str safe: Vault Safe
            :param str appid: Vault App ID
            :param str folder_id: Vault Folder ID
            :param str provider_username: Central Credential Provider Username
            :param str policyid: Vault Policy ID
            :param bool use_ssl: Use SSL. Default: True.
            :param bool verify_ssl: Verify SSL Certificate. Default: True.
            :param int port: Vault Port. Default: 443.
            :param str elevate_privileges: CyberArk elevate privileges with. Default: Nothing.
            :param api: Nessus/TenableCloud API instance
            :param str known_hosts: Known Hosts file
            :returns: dict
            :raises: AttributeError, if known_hosts is provided without an API instance
            """
            if known_hosts and not api:
                raise AttributeError('Missing required "api" parameter.')
            dct = {'auth_method': API.Credentials.Host.SSHAuthTypes.CYBERARK, 'username': username, 'vault_host': host,
                   'vault_safe': safe, 'vault_app_id': appid, 'vault_folder': folder_id, 'vault_port': port,
                   'vault_elevate_privileges_with': elevate_privileges,
                   'vault_use_ssl': STRING_YES if use_ssl else STRING_NO,
                   'vault_verify_ssl': STRING_YES if verify_ssl else STRING_NO}
            if provider_username:
                dct['vault_username'] = provider_username
            if policyid:
                dct['vault_policy_id'] = policyid
            if known_hosts:
                filename = api.file.upload(known_hosts)
                dct['ssh_known_hosts'] = filename
            return dct

        @staticmethod
        def create_ssh_kerberos_credential(username: str, password: str, kdc: str, realm: str, port: int=88,
                                           transport: str=Protocols.TCP,
                                           elevate_privileges: str=API.Credentials.Host.PrivilegeEscalation.NOTHING,
                                           api=None, known_hosts: str=None) -> dict:
            """
            Create a Kerberos credential dictionary

            :param str username: Username
            :param str password: Password
            :param str kdc: Key Distribution Center (KDC)
            :param str realm: Realm
            :param int port: KDC Port
            :param str transport: KDC Transport. Default: tcp. Supported Options: tcp and udp.
            :param str elevate_privileges: Elevate privileges with. Default: Nothing.
            :param api: Nessus/TenableCloud API instance
            :param str known_hosts: Known Hosts file
            :raises: AttributeError, if known_hosts is provided without an API instance
            :returns: dict
            """
            if known_hosts and not api:
                raise AttributeError('Missing required "api" parameter.')
            dct = {'auth_method': API.Credentials.Host.SSHAuthTypes.KERBEROS, 'username': username,
                   'password': password, 'kdc': kdc, 'realm': realm, 'kdc_port': port, 'kdc_transport': transport,
                   'elevate_privileges_with': elevate_privileges}
            if known_hosts:
                filename = api.file.upload(known_hosts)
                dct['ssh_known_hosts'] = filename
            return dct

        @staticmethod
        def create_windows_kerberos_credential(username: str, password: str, kdc: str, domain: str, port: int=88,
                                               transport: str=Protocols.TCP) -> dict:
            """
            Create a Kerberos credential dictionary for Windows auth

            :param str username: Username
            :param str password: Password
            :param str kdc: Key Distribution Center (KDC)
            :param str domain: Domain
            :param int port: KDC Port
            :param str transport: KDC Transport. Default: tcp. Supported Options: tcp and udp.
            :returns: dict
            """
            return {'auth_method': API.Credentials.Host.WindowsAuthTypes.KERBEROS, 'username': username,
                    'password': password, 'kdc': kdc, 'domain': domain, 'kdc_port': port, 'kdc_transport': transport}

        @staticmethod
        def create_ssh_password_credential(username: str, password: str,
                                           elevate_privileges: str=API.Credentials.Host.PrivilegeEscalation.NOTHING,
                                           escalation_account: str=None, escalation_password: str=None,
                                           api=None, known_hosts: str=None) -> dict:
            """
            Create a SSH Password credential dictionary

            :param str username: Username
            :param str password: Password
            :param str elevate_privileges: Elevate privileges with. Default: Nothing.
            :param api: Nessus/TenableCloud API instance
            :param str known_hosts: Known Hosts file
            :raises: AttributeError, if known_hosts is provided without an API instance
            :returns: dict
            """
            if known_hosts and not api:
                raise AttributeError('Missing required "api" parameter.')
            dct = {'auth_method': API.Credentials.Host.SSHAuthTypes.PASSWORD, 'username': username,
                   'password': password, 'elevate_privileges_with': elevate_privileges,
                   'escalation_account': escalation_account, 'escalation_password': escalation_password}
            if known_hosts:
                filename = api.file.upload(known_hosts)
                dct['ssh_known_hosts'] = filename
            return dct

        @staticmethod
        def create_ssh_thycotic_credential(username: str, name: str, url: str, login: str, password: str,
                                           organization: str=None, domain: str=None, verify_ssl: bool=True,
                                           known_hosts: str=None, api=None, private_key: bool=False) -> dict:
            """
            Create a SSH Thycotic credential dictionary

            :param str username: Username
            :param str name: Thycotic Secret Name
            :param str url: Thycotic Secret Server URL
            :param bool private_key:  Use Private Key
            :param str login: Thycotic Login Name
            :param str password: Thycotic Password
            :param str organization: Thycotic Organization
            :param str domain: Thycotic Domain
            :param bool verify_ssl: Verify SSL Certificate. Default: True.
            :param api: Nessus/TenableCloud API
            :param str known_hosts: Known Hosts file
            :raises: AttributeError, if known_hosts is provided without an API instance
            :returns: dict
            """
            if known_hosts and not api:
                raise AttributeError('Missing required "api" parameter.')
            dct = {'auth_method': API.Credentials.Host.SSHAuthTypes.THYCOTIC, 'username': username,
                   'thycotic_secret_name': name, 'thycotic_url': url, 'thycotic_username': login,
                   'thycotic_password': password, 'thycotic_private_key': STRING_YES if private_key else STRING_NO,
                   'thycotic_ssl_verify': STRING_YES if verify_ssl else STRING_NO}
            if organization:
                dct['thycotic_organization'] = organization
            if domain:
                dct['thycotic_domain'] = domain
            if known_hosts:
                filename = api.file.upload(known_hosts)
                dct['ssh_known_hosts'] = filename
            return dct

        @staticmethod
        def create_ssh_lieberman_credential(host: str, port: int, ssl: bool, ssl_verify: bool,
                pam_user: str, pam_password: str, username: str) -> dict:
            """
            Create a SSH Lieberman credential dictionary

            :param str target: Server for which we will be looking up credentials
            :param str host: The Lieberman server to pull creds from
            :param int port: The Lieberman server port
            :param bool ssl: Use SSL?
            :param bool ssl_verift: Check the server's ssl cert is signed
            :param str pam_user: Lieberman user
            :param str api_key: Lieberman password
            :param str username: the account name on `host` to use
            :returns: dict
            """
            dct = {
                    'auth_method': API.Credentials.Host.SSHAuthTypes.LIEBERMAN,
                    'username': username,
                    'lieberman_host': host,
                    'lieberman_port': port,
                    'lieberman_pam_user': pam_user,
                    'lieberman_pam_password': pam_password,
                    'lieberman_use_ssl': STRING_YES if ssl else STRING_NO,
                    'lieberman_verify_ssl': STRING_YES if ssl_verify else STRING_NO,
                }
            return dct

        @staticmethod
        def create_windows_lieberman_credential(host: str, port: int, ssl: bool, ssl_verify: bool,
                pam_user: str, pam_password: str, username: str, domain: str) -> dict:
            """
            Create a Windows Lieberman credential dictionary

            :param str target: Server for which we will be looking up credentials
            :param str host: The Lieberman server to pull creds from
            :param int port: The Lieberman server port
            :param bool ssl: Use SSL?
            :param bool ssl_verift: Check the server's ssl cert is signed
            :param str pam_user: Lieberman user
            :param str api_key: Lieberman password
            :param str username: the account name on `host` to use
            :param str domain: the domain name on `host` to use
            :returns: dict
            """
            dct = {
                    'auth_method': API.Credentials.Host.SSHAuthTypes.LIEBERMAN,
                    'username': username,
                    'domain': domain,
                    'lieberman_host': host,
                    'lieberman_port': port,
                    'lieberman_pam_user': pam_user,
                    'lieberman_pam_password': pam_password,
                    'lieberman_use_ssl': STRING_YES if ssl else STRING_NO,
                    'lieberman_verify_ssl': STRING_YES if ssl_verify else STRING_NO,
                }
            return dct

        @staticmethod
        def create_ssh_beyondtrust_credential(host: str, port: int, ssl: bool, ssl_verify: bool,
                api_key: str, username: str, duration_minutes: int, try_private_key: bool,
                try_escalation: bool) -> dict:
            """
            Create a SSH BeyondTrust credential dictionary

            :param str target: Server for which we will be looking up credentials
            :param str host: The BT PasswordSafe server to pull creds from
            :param int port: The BT PasswordSafe server port
            :param bool ssl: Use SSL?
            :param bool ssl_verift: Check the server's ssl cert is signed
            :param str api_key: BT PasswordSafe API Key
            :param str username: the account name on `host` to use
            :param int duration_minutes: the amount of time (in minutes) to keep the BT creds
                                         checked out for
            :param bool try_private_key: Use public key auth before falling back to password
            :param bool try_excalation: Try to use the configured escalation command
            :returns: dict
            """
            dct = {
                    'auth_method': API.Credentials.Host.SSHAuthTypes.BEYOND_TRUST,
                    'username': username,
                    'beyondtrust_host': host,
                    'beyondtrust_port': port,
                    'beyondtrust_api_key': api_key,
                    'beyondtrust_duration': duration_minutes,
                    'beyondtrust_use_ssl': STRING_YES if ssl else STRING_NO,
                    'beyondtrust_verify_ssl': STRING_YES if ssl_verify else STRING_NO,
                    'beyondtrust_use_private_key': STRING_YES if try_private_key else STRING_NO,
                    'beyondtrust_use_escalation': STRING_YES if try_escalation else STRING_NO,
                }
            return dct

        @staticmethod
        def create_windows_beyondtrust_credential(host: str, port: int, ssl: bool, ssl_verify: bool,
                api_key: str, username: str, duration_minutes: int) -> dict:
            """
            Create a SSH BeyondTrust credential dictionary

            :param str target: Server for which we will be looking up credentials
            :param str host: The BT PasswordSafe server to pull creds from
            :param int port: The BT PasswordSafe server port
            :param bool ssl: Use SSL?
            :param bool ssl_verift: Check the server's ssl cert is signed
            :param str api_key: BT PasswordSafe API Key
            :param str username: the account name on `host` to use
            :param int duration_minutes: the amount of time (in minutes) to keep the BT creds
                                         checked out for
            :param bool try_private_key: Use public key auth before falling back to password
            :param bool try_excalation: Try to use the configured escalation command
            :returns: dict
            """
            dct = {
                    'auth_method': API.Credentials.Host.WindowsAuthTypes.BEYOND_TRUST,
                    'username': username,
                    'beyondtrust_host': host,
                    'beyondtrust_port': port,
                    'beyondtrust_api_key': api_key,
                    'beyondtrust_duration': duration_minutes,
                    'beyondtrust_use_ssl': STRING_YES if ssl else STRING_NO,
                    'beyondtrust_verify_ssl': STRING_YES if ssl_verify else STRING_NO,
                }
            return dct

        @staticmethod
        def create_windows_cyberark_credential(
                username: str, host: str, safe: str, appid: str, folder_id: str, domain: str=None,
                provider_username: str=None, policyid: str=None, use_ssl: bool=True, verify_ssl: bool=True,
                port: int=443, elevate_privileges: str=API.Credentials.Host.PrivilegeEscalation.NOTHING) -> dict:
            """
            Create a Windows CyberArk credential dictionary

            .. note:: elevate_privileges ONLY supports Nothing and should be left alone, for now.

            :param str username: Username
            :param str host: Central credential provider host
            :param str safe: Vault Safe
            :param str appid: Vault App ID
            :param str folder_id: Vault Folder ID
            :param str domain: Domain (if using domain credentials)
            :param str provider_username: Central Credential Provider Username
            :param str policyid: Vault Policy ID
            :param bool use_ssl: Use SSL. Default: True.
            :param bool verify_ssl: Verify SSL Certificate. Default: True.
            :param int port: Vault Port. Default: 443.
            :param str elevate_privileges: CyberArk elevate privileges with. Default: Nothing.
            :returns: dict
            """
            dct = {'auth_method': API.Credentials.Host.WindowsAuthTypes.CYBERARK, 'username': username,
                   'vault_host': host, 'vault_safe': safe, 'vault_app_id': appid, 'vault_folder': folder_id,
                   'vault_port': port, 'vault_elevate_privileges_with': elevate_privileges,
                   'vault_use_ssl': STRING_YES if use_ssl else STRING_NO,
                   'vault_verify_ssl': STRING_YES if verify_ssl else STRING_NO}
            if provider_username:
                dct['vault_username'] = provider_username
            if domain:
                dct['domain'] = domain
            if policyid:
                dct['vault_policy_id'] = policyid
            return dct

        @staticmethod
        def create_windows_thycotic_credential(username: str, name: str, url: str, login: str, password: str,
                                               domain: str=None, organization: str=None, thycotic_domain: str=None,
                                               verify_ssl: bool=True) -> dict:
            """
            Create a Windows Thycotic credential dictionary

            TODO: Refactor with kwargs

            :param str username: Username
            :param str name: Thycotic Secret Name
            :param str domain: Windows Domain
            :param str url: Thycotic Secret Server URL
            :param str login: Thycotic Login Name
            :param str password: Thycotic Password
            :param str organization: Thycotic Organization
            :param str thycotic_domain: Thycotic Domain
            :param bool verify_ssl: Verify SSL Certificate. Default: True.
            :returns: dict
            """
            dct = {'auth_method': API.Credentials.Host.WindowsAuthTypes.THYCOTIC, 'username': username,
                   'domain': domain, 'thycotic_secret_name': name, 'thycotic_url': url, 'thycotic_username': login,
                   'thycotic_password': password, 'thycotic_ssl_verify': STRING_YES if verify_ssl else STRING_NO}
            if organization:
                dct['thycotic_organization'] = organization
            if domain:
                dct['thycotic_domain'] = thycotic_domain
            return dct

        @staticmethod
        def create_win_password_credential(username: str, password: str, domain: str) -> dict:
            """
            Create a Windows Password credential dictionary

            :param str username: Windows Username
            :param str password: Windows Password
            :param str domain: Windows Domain

            :returns: dict
            """
            dct = {'auth_method': API.Credentials.Host.WindowsAuthTypes.PASSWORD, 'username': username,
                   'password': password}
            if domain:
                dct['domain'] = domain
            return dct
