"""
Plaintext Authentication Credential Mixin

TODO Incomplete
"""


class PlaintextAuthenticationMixin:
    """Mixin class for creating Plaintext Authentication credential dictionaries"""

    class PlaintextAuthentication:

        @staticmethod
        def create_ftp_credential(username: str, password: str) -> dict:
            """
            Add FTP credential

            :param str username: FTP Username
            :param str password: FTP Password
            :returns: dict
            """
            return {'username': username, 'password': password}

        @staticmethod
        def create_http_credential():
            raise NotImplementedError

        @staticmethod
        def create_imap_credential():
            raise NotImplementedError

        @staticmethod
        def create_ipmi_credential():
            raise NotImplementedError

        @staticmethod
        def create_nntp_credential():
            raise NotImplementedError

        @staticmethod
        def create_pop2_credential():
            raise NotImplementedError

        @staticmethod
        def create_pop3_credential():
            raise NotImplementedError

        @staticmethod
        def create_snmpv12_credential():
            raise NotImplementedError

        @staticmethod
        def create_telnet_rsh_rexec_credential():
            raise NotImplementedError
