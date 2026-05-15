"""
Miscellaneous Credential Mixin

TODO Incomplete
"""
from catium.lib.const import STRING_NO, STRING_YES
from nessus.lib.const import API


class MiscellaneousMixin:
    """Mixin class for creating Miscellaneous credential dictionaries"""

    class Miscellaneous:
        """
        Miscellaneous class for creating various credential dictionaries.
        """

        @staticmethod
        def create_asdi_credential(domain_controller: str, domain: str, domain_admin: str, domain_pwd: str) -> dict:
            """
            Create an ADSI credential dictionary

            :param str domain_controller: Domain Controller
            :param str domain: Fully Qualified Domain Name
            :param str domain_admin: Domain user with administrator privileges.
            :param str domain_pwd: The domain administrator's password
            :returns: dict
            """
            return {'auth_method': API.Credentials.Miscellaneous.ADSI, 'domain_controller': domain_controller,
                    'domain': domain, 'domain_admin': domain_admin, 'password': domain_pwd}

        @staticmethod
        def create_ibm_series_credential():
            """ TODO  """
            raise NotImplementedError

        @staticmethod
        def create_openstack_credential():
            """ TODO  """
            raise NotImplementedError

        @staticmethod
        def create_palo_alto_credential(username: str, password: str, port: int, https: str, verify_ssl: str):
            """
            Create a Palo Alto PAN-OS Credential Dictionary

            :param str username:      PAN-OS Username
            :param str password:      Pan-OS Password
            :param str port:          Port to connect to.
            :param bool https:        If enabled, use https.
            :param bool verify_ssl:   If enabled, verify SSL.
            :return:
            """
            return {'auth_method': API.Credentials.Miscellaneous.PALO_ALTO, 'username': username, 'password': password,
                    'port': port, 'https': STRING_YES if https else STRING_NO,
                    'verify_ssl': STRING_YES if verify_ssl else STRING_NO}

        @staticmethod
        def create_rhev_credential():
            """ TODO  """
            raise NotImplementedError

        @staticmethod
        def create_vmware_esx_credential(username: str, password: str, dont_verify_ssl: bool) -> dict:
            """
            Create a VMWare ESX Credential Dictionary

            :param str username: ESX Username
            :param str password: ESX Password
            :param bool dont_verify_ssl: If enabled, don't verify SSL.
            :return: dict
            """
            return {'auth_method': API.Credentials.Miscellaneous.VMWARE_ESX, 'username': username,
                    'password': password, 'dont_verify_ssl': STRING_YES if dont_verify_ssl else STRING_NO}

        @staticmethod
        def create_vmware_vcenter_credential(host: str, port: int, username: str, password: str, https: bool,
                                             verify_ssl: bool) -> dict:
            """
            Create a VMWare vCenter Credential Dictionary
            :param str host: vCenter IP/Hostname
            :param int port: vCenter Server Port
            :param str username: vCenter Username
            :param str password: vCenter Password
            :param bool https: Use https
            :param bool verify_ssl: Verify SSL cert
            :return: dict
            """
            return {'auth_method': API.Credentials.Miscellaneous.VMWARE_VCENTER, 'host': host,
                    'port': port, 'username': username, 'password': password,
                    'https': STRING_YES if https else STRING_NO, 'verify_ssl': STRING_YES if verify_ssl else STRING_NO}

        @staticmethod
        def create_x509_credential(api, client_cer: str, client_key: str, key_pwd: str, ca_cer: str) -> dict:
            """
            :param str client_cer: Client Certificate
            :param str client_key: Client Private Key
            :param str key_pwd: Passphrase for Client Private Key
            :param str ca_cer: CA Certificate
            """
            client_cer_file = api.file.upload(client_cer)
            client_key_file = api.file.upload(client_key)
            ca_cer_file = api.file.upload(ca_cer)

            return {'auth_method': API.Credentials.Miscellaneous.X509, 'client_cert': client_cer_file,
                    'client_key': client_key_file, 'key_pwd': key_pwd, 'ca_cert': ca_cer_file}
