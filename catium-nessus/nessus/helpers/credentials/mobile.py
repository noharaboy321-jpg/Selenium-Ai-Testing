"""
Mobile Credential Mixin

"""
from catium.lib.const import STRING_YES, STRING_NO
from nessus.lib.const import API


class MobileMixin:
    """Mixin class for creating Mobile credential dictionaries"""

    class Mobile:
        """Class for defining mobile credential helper functions"""

        @staticmethod
        def create_airwatch_credential(api_url: str, port: int, username: str, password: str, api_key: str,
                                       https: bool=True, verify_ssl: bool=True) -> dict:
            """
            Create an airwatch credential dictionary

            :param str api_url: Airwatch Environment API URL
            :param int port: Port
            :param str username: Airwatch Username
            :param str password: Airwatch Password
            :param str api_key: API Key
            :param bool https: Use HTTPS
            :param bool verify_ssl: Verify SSL certificate
            :returns: dict
            """
            return {'auth_method': API.Credentials.Mobile.AIRWATCH, 'api_url': api_url, 'port': port,
                    'username': username, 'password': password, 'api_key': api_key,
                    'https': STRING_YES if https else STRING_NO,
                    'verify_ssl': STRING_YES if verify_ssl else STRING_NO}

        @staticmethod
        def create_mobile_iron_credential(portal_url: str, port: int, username: str, password: str, https: bool,
                                          verify_ssl: bool) -> dict:
            """Create MobileIron credential dictionary

            :param str portal_url: VSP Admin Portal URL
            :param int port: Port
            :param str username: MobileIron Username
            :param str password: MobileIron Password
            :param bool https: Use HTTPS
            :param bool verify_ssl: Verify SSL certificate
            :returns: dict
            """

            return {'auth_method': API.Credentials.Mobile.MOBILEIRON, 'portal_url': portal_url, 'port': port,
                    'username': username, 'password': password, 'https': https, 'verify_ssl': verify_ssl}

        @staticmethod
        def create_good_mdm_credential(server: str, port: int, domain: str, username: str, password: str, https: bool,
                                       verify_ssl: bool) -> dict:
            """Create Good MDM credential dictionary

            TODO: refactor to use kwargs

            :param str server: Good MDM server
            :param int port: Port
            :param str domain: Good MDM domain
            :param str username: Good MDM Username
            :param str password: Good MDM Password
            :param bool https: Use HTTPS
            :param bool verify_ssl: Verify SSL certificate
            :returns: dict
            """
            return {'auth_method': API.Credentials.Mobile.GOODMDM, 'server': server, 'port': port, 'domain': domain,
                    'username': username, 'password': password, 'https': https, 'verify_ssl': verify_ssl}

        @staticmethod
        def create_apple_profile_manager_credential(server: str, port: int, username: str, password: str,
                                                    https: bool=True, verify_ssl: bool=True) -> dict:
            """
            Create Apple Profile Manager dictionary

            :param str server: Apple Profile Manager IP
            :param int port: Port
            :param str username: Apple Profile Manager Username
            :param str password: Apple Profile Manager Password
            :param bool https: Use HTTPS
            :param bool verify_ssl: Verify SSL cert
            :returns: dict
            """

            return {'auth_method': API.Credentials.Mobile.APM, 'server': server, 'port': port, 'username': username,
                    'password': password, 'https': STRING_YES if https else STRING_NO,
                    'verify_ssl': STRING_YES if verify_ssl else STRING_NO}

        @staticmethod
        def create_maas360_credential(root_url: str, platform_id: int, billing_id: int, app_id: str, app_version: float,
                                      app_access_key: str, username: str, password: str) -> dict:
            """
            Create MaaS360 dictionary

            :param str root_url: MaaS360 Root Url
            :param int platform_id: MaaS360 Platform ID
            :param int billing_id: MaaS360 Billing ID
            :param str app_id: MaaS360 App ID
            :param float app_version: MaaS360 App Version
            :param str app_access_key: MaaS360 App Access Key
            :param str username: Maas360 Username
            :param str password: Maas360 Password
            :returns: dict
            """
            return {'auth_method': API.Credentials.Mobile.MAAS360, 'root_url': root_url, 'platform_id': platform_id,
                    'billing_id': billing_id, 'app_id': app_id, 'app_version': app_version,
                    'app_access_key': app_access_key, 'username': username, 'password': password}
