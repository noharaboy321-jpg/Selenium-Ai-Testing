"""
Patch Management Credential Mixin
"""
from catium.lib.const import STRING_YES, STRING_NO
from nessus.lib.const import API


class PatchManagementMixin:
    """Mixin class for creating Patch Management credential dictionaries"""

    class PatchManagement:
        """Patch Management Helpers"""

        @staticmethod
        def create_microsoft_sccm_credential(server: str, domain: int, username: str, password: str) -> dict:
            """
            Create an SCCM credential dictionary

            :param str server: SCCM server
            :param int domain: SCCM domain
            :param str username: SCCM Username
            :param str password: SCCM Password
            :returns: dict
            """
            return {'auth_method': API.Credentials.PatchManagement.Types.MICROSOFT_SCCM, 'server': server,
                    'domain': domain, 'username': username, 'password': password}

        @staticmethod
        def create_microsoft_wsus_credential(server: str, port: int, username: str, password: str, https: bool,
                                             verify_ssl: bool) -> dict:
            """
            Create an WSUS credential dictionary

            TODO: refactor for kwargs

            :param str server: WSUS server
            :param int port: WSUS port
            :param str username: WSUS Username
            :param str password: WSUS Password
            :param bool https: Use https
            :param bool verify_ssl: Verify SSL cert
            :returns: dict
            """
            return {'auth_method': API.Credentials.PatchManagement.Types.MICROSOFT_WSUS, 'server': server, 'port': port,
                    'username': username, 'password': password, 'https': https, 'verify_ssl': verify_ssl}

        @staticmethod
        def create_dell_kace_credential(server: str, port: int, username: str, password: str, org_db_name: str) -> dict:
            """
            Create an Dell Kace credential dictionary

            :param str server: Dell KACE K1000 server
            :param int port: Dell KACE K1000 port
            :param str username: Dell KACE K1000 Username
            :param str password: Dell KACE K1000 Password
            :param str org_db_name: Dell KACE K1000 Org DB
            :returns: dict
            """
            return {'auth_method': API.Credentials.PatchManagement.Types.DELL_KACE, 'server': server,
                    'port': port, 'username': username, 'password': password, 'org_db_name': org_db_name}

        @staticmethod
        def create_ibm_bigfix_credential(server: str, port: int, username: str, password: str, https: bool,
                                         verify_ssl: bool) -> dict:
            """
            Create an IBM BigFix credential dictionary

            :param str server: IBM BigFix server
            :param int port: IBM BigFix port
            :param str username: IBM BigFix Username
            :param str password: IBM BigFix Password
            :param bool https: Use https
            :param bool verify_ssl: Verify SSL cert
            :returns: dict
            """
            return {'auth_method': API.Credentials.PatchManagement.Types.IBM_BIGFIX, 'server': server,
                    'port': port, 'username': username, 'password': password,
                    'https': STRING_YES if https else STRING_NO, 'verify_ssl': STRING_YES if verify_ssl else STRING_NO}

        @staticmethod
        def create_redhat_satellite5_credential(server: str, port: int, username: str, password: str,
                                                verify_ssl: bool) -> dict:
            """
            Create a Red Hat Satellite 5 credential dictionary

            :param str server: Red Hat Satellite 5 server
            :param int port: Red Hat Satellite 5 port
            :param str username: Red Hat Satellite 5 Username
            :param str password: Red Hat Satellite 5 Password
            :param bool verify_ssl: Verify SSL cert
            :returns: dict
            """
            return {'auth_method': API.Credentials.PatchManagement.Types.REDHAT_SATELLITE5, 'server': server,
                    'port': port, 'username': username, 'password': password,
                    'verify_ssl': STRING_YES if verify_ssl else STRING_NO}

        @staticmethod
        def create_redhat_satellite6_credential(server: str, port: int, username: str, password: str, https: bool,
                                                verify_ssl: bool) -> dict:
            """
            Create a Red Hat Satellite 6 credential dictionary

            :param str server: Red Hat Satellite 6 server
            :param int port: Red Hat Satellite 6 port
            :param str username: Red Hat Satellite 6 Username
            :param str password: Red Hat Satellite 6 Password
            :param bool https: Use https
            :param bool verify_ssl: Verify SSL cert
            :returns: dict
            """
            return {'auth_method': API.Credentials.PatchManagement.Types.REDHAT_SATELLITE6, 'server': server,
                    'port': port, 'username': username, 'password': password,
                    'https': STRING_YES if https else STRING_NO, 'verify_ssl': STRING_YES if verify_ssl else STRING_NO}

        @staticmethod
        def create_symantec_altiris_credential(server: str, port: int, username: str, password: str,
                                               db_name: str, use_windows_auth: bool) -> dict:
            """
            Create a Symantec Altiris credential dictionary

            :param str server: Symantec Altiris server
            :param int port: Symantec Altiris port
            :param str username: Symantec Altiris Username
            :param str password: Symantec Altiris Password
            :param str db_name: Symantec Altiris DB Name
            :param bool use_windows_auth: Use Windows Authentication
            :returns: dict
            """
            return {'auth_method': API.Credentials.PatchManagement.Types.SYMANTEC_ALTIRIS, 'server': server,
                    'port': port, 'username': username, 'password': password, 'db_name': db_name,
                    'use_windows_auth': STRING_YES if use_windows_auth else STRING_NO}
