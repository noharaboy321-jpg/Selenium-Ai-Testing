"""
Database Credential Mixin
"""
from nessus.lib.const import API
from catium.lib.const import STRING_NO, STRING_YES

class DatabaseMixin:
    """Mixin class for creating Database credential dictionaries"""

    class Database:
        """Database Helpers"""

        @staticmethod
        def create_sql_server_credential(username: str, password: str=None,
                                         port: int=API.Credentials.Database.Ports.SQL_SERVER,
                                         sql_server_auth_type=API.Credentials.Database.SQLServer.AUTH_TYPE_WINDOWS,
                                         instance_name: str=None, auth_type: str=None) -> dict:
            """
            Create a SQL Server Database credential dictionary

            :param str username: Username
            :param str password: Password
            :param int port: Port
            :param str sql_server_auth_type: Authentication Type. Default: SQL_SERVER_AUTH_TYPE_WINDOWS
                Supported Options: SQL_SERVER_AUTH_TYPE_WINDOWS and SQL_SERVER_AUTH_TYPE_SQL
            :param str instance_name: Instance name
            :param str auth_type: Authentication type
            :returns: dict
            """
            dct = {'type': API.Credentials.Database.Types.SQL_SERVER, 'username': username, 'port': port,
                   'sql_server_auth_type': sql_server_auth_type}

            if password:
                dct['password'] = password

            if instance_name:
                dct['db_sid'] = instance_name

            if auth_type:
                dct['authtype'] = auth_type

            return dct

        @staticmethod
        def create_mysql_credential(username: str, password: str=None,
                                    port: int=API.Credentials.Database.Ports.MYSQL, auth_type: str=None) -> dict:
            """
            Create a MySQL Database credential dictionary

            :param str username: Username
            :param str password: Password
            :param int port: Port
            :param str auth_type: Authentication type
            :returns: dict
            """
            dct = {'type': API.Credentials.Database.Types.MYSQL, 'username': username, 'port': port}

            if password:
                dct['password'] = password

            if auth_type:
                dct['authtype'] = auth_type

            return dct

        @staticmethod
        def create_db2_credential(username: str, database_name: str, password: str=None,
                                  port: int=API.Credentials.Database.Ports.DB2, auth_type: str=None) -> dict:
            """
            Create a DB2 Database credential dictionary

            :param str username: Username
            :param str database_name: Database name
            :param str password: Password
            :param int port: Port
            :param str auth_type: Authentication type
            :returns: dict
            """
            dct = {'type': API.Credentials.Database.Types.DB2, 'username': username, 'port': port,
                   'db_sid': database_name}

            if password:
                dct['password'] = password

            if auth_type:
                dct['authtype'] = auth_type

            return dct

        @staticmethod
        def create_postgresql_credential(username: str, password: str=None,
                                         port: int=API.Credentials.Database.Ports.POSTGRESQL,
                                         database_name: str=None, auth_type: str=None) -> dict:
            """
            Create a PostgreSQL Database credential dictionary

            :param str username:
            :param str password:
            :param int port:
            :param str database_name:
            :param str auth_type: Authentication type
            :returns: dict
            """
            dct = {'username': username, 'port': port,
                   'type': API.Credentials.Database.Types.POSTGRESQL}

            if database_name:
                dct['db_sid'] = database_name

            if password:
                dct['password'] = password

            if auth_type:
                dct['authtype'] = auth_type

            return dct

        @staticmethod
        def create_oracle_credential(username: str, service: str, password: str=None,
                                     port: int=API.Credentials.Database.Ports.ORACLE,
                                     oracle_auth_type=API.Credentials.Database.Oracle.AUTH_TYPE_SYSDBA,
                                     service_type=API.Credentials.Database.Oracle.SVC_TYPE_SID,
                                     auth_type: str = None) -> dict:
            """
            Create an Oracle Database credential dictionary

            :param str username: Username
            :param str service: Service
            :param str password: Password
            :param str port: Port
            :param str oracle_auth_type: Oracle Authentication Type
            :param str service_type: Service Type
            :param str auth_type: Authentication type
            :returns: dict
            """
            dct = {'type': API.Credentials.Database.Types.ORACLE, 'username': username,
                   'oracle_auth_type': oracle_auth_type, 'oracle_service_type': service_type, 'port': port}

            if service:
                dct['oracle_sid'] = service

            if password:
                dct['password'] = password

            if auth_type:
                dct['authtype'] = auth_type

            return dct

        @staticmethod
        def create_mongodb_credential(username: str, password: str=None, database: str=None,
                                      port: int=API.Credentials.Database.Ports.MONGODB) -> dict:
            """
            Create a MongoDB Database credential dictionary

            :param str username: Username
            :param str password: Password
            :param str database: Database
            :param int port: Port
            :returns: dict
            """
            dct = {'username': username, 'port': port}

            if database:
                dct['database'] = database

            if password:
                dct['password'] = password

            return dct

        @staticmethod
        def create_lieberman_credential(host: str, pam_port: int, ssl: bool, ssl_verify: bool,
                pam_user: str, pam_password: str, system_name: str=None, database: str=None, port: int=None) -> dict:
            """
            # TODO
            """
            dct = {
                    'lieberman_host': host,
                    'lieberman_port': pam_port,
                    'lieberman_pam_user': pam_user,
                    'lieberman_pam_password': pam_password,
                    'lieberman_use_ssl': STRING_YES if ssl else STRING_NO,
                    'lieberman_verify_ssl': STRING_YES if ssl_verify else STRING_NO,
                    'authtype': "Lieberman"
                }
            
            if system_name:
                dct['lieberman_system_name'] = system_name

            return dct

