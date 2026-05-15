"""
Nessus Plugin database authentication
"""
import pytest

from nessus.helpers.credentials.credential import CredentialHelper
from nessus.models.scan import ScanModel
from nessus.helpers.scan import launch_scan
from nessus.lib.const import API


@pytest.mark.scanning
@pytest.mark.plugins
@pytest.mark.usefixtures('nessus_api_login')
@pytest.mark.usefixtures('load_test_data')
@pytest.mark.parametrize('test_data_file', ['nessus/tests/api/plugins/test_data/test_database_auth_multiple.json'])
class TestDatabaseAuth:
    """
    Test class for Nessus Plugin Database authentication.
    """
    cat = None

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_successful_mysql_login(self, load_test_data):
        """
        Verify MySQL Authentication is possible via username/pass.
        """
        scan_model = ScanModel.create_model()
        scan_model.add_database_credential(CredentialHelper.Database.create_mysql_credential(
            username=load_test_data['mysql']['username'], password=load_test_data['mysql']['password'],
            port=load_test_data['mysql']['port'], auth_type=load_test_data['mysql']['auth_type']))
        plugin_ids = load_test_data['mysql']['plugins_to_enable']
        plugin_id_report = load_test_data['mysql']['mysql_login_plugin']
        scan_model.plugins = plugin_ids
        target = load_test_data['mysql']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id_report)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'Credentialed checks have been enabled for MySQL server on port' in outputs[0]['plugin_output']

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_failed_mysql_login(self, load_test_data):
        """
        Verify MySQL Authentication fails with provided username/pass.
        """
        scan_model = ScanModel.create_model()
        scan_model.add_database_credential(CredentialHelper.Database.create_mysql_credential(
            username=load_test_data['mysql']['bad_username'], password=load_test_data['mysql']['bad_password'],
            port=load_test_data['mysql']['port'], auth_type=load_test_data['mysql']['auth_type']))
        plugin_ids = load_test_data['mysql']['plugins_to_enable']
        plugin_id_report = load_test_data['mysql']['db_fail_plugin']
        scan_model.plugins = plugin_ids
        target = load_test_data['mysql']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id_report)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'Nessus was unable to log into the following database systems' in outputs[0]['plugin_output']

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_successful_db2_login(self, load_test_data):
        """
        Verify IBM DB2 Authentication is possible via username/pass.
        """
        scan_model = ScanModel.create_model()
        scan_model.add_database_credential(CredentialHelper.Database.create_db2_credential(
            username=load_test_data['db2']['username'], password=load_test_data['db2']['password'],
            database_name=load_test_data['db2']['db_name'], auth_type=load_test_data['db2']['auth_type']))
        plugin_ids = load_test_data['db2']['plugins_to_enable']
        plugin_id_report = load_test_data['db2']['db2_login_plugin']
        scan_model.plugins = plugin_ids
        target = load_test_data['db2']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id_report)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'Credentialed checks have been enabled for DB2 server on port' in outputs[0]['plugin_output']

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_failed_db2_login(self, load_test_data):
        """
        Verify IBM DB2 Authentication fails with provided username/pass.
        """
        scan_model = ScanModel.create_model()
        scan_model.add_database_credential(CredentialHelper.Database.create_db2_credential(
            username=load_test_data['db2']['bad_username'], password=load_test_data['db2']['bad_password'],
            database_name=load_test_data['db2']['db_name'], auth_type=load_test_data['db2']['auth_type']))
        plugin_ids = load_test_data['db2']['plugins_to_enable']
        plugin_id_report = load_test_data['db2']['db_fail_plugin']
        scan_model.plugins = plugin_ids
        target = load_test_data['db2']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id_report)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'Nessus was unable to log into the following database systems' in outputs[0]['plugin_output']

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_successful_oracle_login(self, load_test_data):
        """
        Verify Oracle DB Authentication is possible via username/pass.
        """
        scan_model = ScanModel.create_model()
        scan_model.add_database_credential(CredentialHelper.Database.create_oracle_credential(
            username=load_test_data['oracle']['username'], password=load_test_data['oracle']['password'],
            service=load_test_data['oracle']['service'], auth_type=load_test_data['oracle']['auth_type']))
        plugin_ids = load_test_data['oracle']['plugins_to_enable']
        plugin_id_report = load_test_data['oracle']['oracle_login_plugin']
        scan_model.plugins = plugin_ids
        target = load_test_data['oracle']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id_report)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'Credentialed checks have been enabled for Oracle' in outputs[0]['plugin_output']

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_failed_oracle_login(self, load_test_data):
        """
        Verify Oracle Authentication fails with provided username/pass.
        """
        scan_model = ScanModel.create_model()
        scan_model.add_database_credential(CredentialHelper.Database.create_oracle_credential(
            username=load_test_data['oracle']['bad_username'], password=load_test_data['oracle']['bad_password'],
            service=load_test_data['oracle']['service'], auth_type=load_test_data['oracle']['auth_type']))
        plugin_ids = load_test_data['oracle']['plugins_to_enable']
        plugin_id_report = load_test_data['oracle']['db_fail_plugin']
        scan_model.plugins = plugin_ids
        target = load_test_data['oracle']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id_report)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'Nessus was unable to log into the following database systems' in outputs[0]['plugin_output']

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_successful_mssql_login(self, load_test_data):
        """
        Verify MS SQL Authentication is possible via username/pass.
        """
        scan_model = ScanModel.create_model()
        scan_model.add_database_credential(CredentialHelper.Database.create_sql_server_credential(
            username=load_test_data['mssql']['username'], password=load_test_data['mssql']['password'],
            instance_name=load_test_data['mssql']['instance_name'], auth_type=load_test_data['mssql']['auth_type']))
        plugin_ids = load_test_data['mssql']['plugins_to_enable']
        plugin_id_report = load_test_data['mssql']['mssql_login_plugin']
        scan_model.plugins = plugin_ids
        target = load_test_data['mssql']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id_report)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'Credentialed checks have been enabled for MSSQL' in outputs[0]['plugin_output']

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_failed_mssql_login(self, load_test_data):
        """
        Verify MS SQL Authentication fails with provided username/pass.
        """
        scan_model = ScanModel.create_model()
        scan_model.add_database_credential(CredentialHelper.Database.create_sql_server_credential(
            username=load_test_data['mssql']['bad_username'], password=load_test_data['mssql']['bad_password'],
            instance_name=load_test_data['mssql']['instance_name'], auth_type=load_test_data['mssql']['auth_type']))
        plugin_ids = load_test_data['mssql']['plugins_to_enable']
        plugin_id_report = load_test_data['mssql']['db_fail_plugin']
        scan_model.plugins = plugin_ids
        target = load_test_data['mssql']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id_report)
        outputs = json_out['outputs']
        if json_out['outputs'] is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'Nessus was unable to log into the following database systems' in outputs[0]['plugin_output']

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_successful_postgres_login(self, load_test_data):
        """
        Verify PostgreSQL Authentication works w/ username/pass.
        """
        scan_model = ScanModel.create_model()
        scan_model.add_database_credential(
            CredentialHelper.Database.create_postgresql_credential(
                username=load_test_data['postgresql']['username'], password=load_test_data['postgresql']['password'],
                database_name=load_test_data['postgresql']['database_name'],
                auth_type=load_test_data['postgresql']['auth_type']))
        plugin_ids = load_test_data['postgresql']['plugins_to_enable']
        plugin_id_report = load_test_data['postgresql']['postgresql_login_plugin']
        scan_model.plugins = plugin_ids
        target = load_test_data['postgresql']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id_report)
        outputs = json_out['outputs']
        if json_out['outputs'] is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'Credentialed checks have been enabled for PostgreSQL server on port 5432' in outputs[0]['plugin_output']

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_failed_postgres_login(self, load_test_data):
        """
        Verify PostgreSQL Authentication fails with provided username/pass.
        """
        scan_model = ScanModel.create_model()
        scan_model.add_database_credential(
            CredentialHelper.Database.create_postgresql_credential(
                username=load_test_data['postgresql']['bad_user'], password=load_test_data['postgresql']['bad_pass'],
                database_name=load_test_data['postgresql']['database_name'],
                auth_type=load_test_data['postgresql']['auth_type']))
        plugin_ids = load_test_data['postgresql']['plugins_to_enable']
        plugin_id_report = load_test_data['postgresql']['db_fail_plugin']
        scan_model.plugins = plugin_ids
        target = load_test_data['postgresql']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id_report)
        outputs = json_out['outputs']
        if json_out['outputs'] is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'Nessus was unable to log into the following database systems' in outputs[0]['plugin_output']

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_successful_mongodb_detection(self, load_test_data):
        """
        Verify MongoDB detection works.
        """
        scan_model = ScanModel.create_model()
        scan_model.add_mongodb_credential(CredentialHelper.Database.create_mongodb_credential(
            username=load_test_data['mongodb']['username'], password=load_test_data['mongodb']['password'],
            database=load_test_data['mongodb']['database'], port=load_test_data['mongodb']['port']))
        plugin_ids = load_test_data['mongodb']['plugins_to_enable']
        plugin_id_report = load_test_data['mongodb']['mongodb_login_plugin']
        scan_model.plugins = plugin_ids
        target = load_test_data['mongodb']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id_report)
        outputs = json_out['outputs']
        if json_out['outputs'] is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'Version' in outputs[0]['plugin_output']


    def test_successful_mysql_lieberman_login(self, load_test_data):
        """
        Verify MySQL Authentication is possible via lieberman.
        """
        creds = CredentialHelper.Database.create_mysql_credential(
                username=load_test_data['lieberman']['mysql']['username'],)
        creds.update(CredentialHelper.Database.create_lieberman_credential(
                host=load_test_data['lieberman']['host'],
                pam_port=load_test_data['lieberman']['port'],
                ssl=load_test_data['lieberman']['ssl'],
                ssl_verify=load_test_data['lieberman']['ssl_verify'],
                pam_user=load_test_data['lieberman']['pam_user'],
                pam_password=load_test_data['lieberman']['pam_password'],
                system_name=load_test_data['lieberman']['mysql']['system_name']))

        scan_model = ScanModel.create_model()
        scan_model.add_database_credential(creds)

        plugin_ids = load_test_data['lieberman']['mysql']['plugins_to_enable']
        plugin_id_report = load_test_data['lieberman']['mysql']['mysql_login_plugin']
        scan_model.plugins = plugin_ids
        target = load_test_data['lieberman']['mysql']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id_report)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'Credentialed checks have been enabled for MySQL' in outputs[0]['plugin_output']
    


    def test_successful_oracle_lieberman_login(self, load_test_data):
        """
        Verify Oracle DB Authentication is possible via lieberman.
        """
        creds = CredentialHelper.Database.create_oracle_credential(
                username=load_test_data['lieberman']['oracle']['username'],
                service=load_test_data['lieberman']['oracle']['service'],)
        creds.update(CredentialHelper.Database.create_lieberman_credential(
                host=load_test_data['lieberman']['host'],
                pam_port=load_test_data['lieberman']['port'],
                ssl=load_test_data['lieberman']['ssl'],
                ssl_verify=load_test_data['lieberman']['ssl_verify'],
                pam_user=load_test_data['lieberman']['pam_user'],
                pam_password=load_test_data['lieberman']['pam_password'],
                system_name=load_test_data['lieberman']['oracle']['system_name']))

        scan_model = ScanModel.create_model()
        scan_model.add_database_credential(creds)

        plugin_ids = load_test_data['lieberman']['oracle']['plugins_to_enable']
        plugin_id_report = load_test_data['lieberman']['oracle']['oracle_login_plugin']
        scan_model.plugins = plugin_ids
        target = load_test_data['lieberman']['oracle']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id_report)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'Credentialed checks have been enabled for Oracle' in outputs[0]['plugin_output']


    def test_successful_mssql_lieberman_login(self, load_test_data):
        """
        Verify MS SQL Authentication is possible via lieberman.
        """
        creds = CredentialHelper.Database.create_sql_server_credential(
                username=load_test_data['lieberman']['mssql']['username'],
                instance_name=load_test_data['lieberman']['mssql']['instance_name'],
                sql_server_auth_type=API.Credentials.Database.SQLServer.AUTH_TYPE_SQL,)
        creds.update(CredentialHelper.Database.create_lieberman_credential(
                host=load_test_data['lieberman']['host'],
                pam_port=load_test_data['lieberman']['port'],
                ssl=load_test_data['lieberman']['ssl'],
                ssl_verify=load_test_data['lieberman']['ssl_verify'],
                pam_user=load_test_data['lieberman']['pam_user'],
                pam_password=load_test_data['lieberman']['pam_password'],
                system_name=load_test_data['lieberman']['mssql']['system_name']))

        scan_model = ScanModel.create_model()
        scan_model.add_database_credential(creds)

        plugin_ids = load_test_data['lieberman']['mssql']['plugins_to_enable']
        plugin_id_report = load_test_data['lieberman']['mssql']['mssql_login_plugin']
        scan_model.plugins = plugin_ids
        target = load_test_data['lieberman']['mssql']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id_report)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'Credentialed checks have been enabled for MSSQL' in outputs[0]['plugin_output']

    def test_successful_postgres_lieberman_login(self, load_test_data):
        """
        Verify PostgreSQL Authentication is possible via lieberman.
        """
        creds = CredentialHelper.Database.create_postgresql_credential(
                username=load_test_data['lieberman']['postgres']['username'],
                database_name=load_test_data['lieberman']['postgres']['database_name'])
        creds.update(CredentialHelper.Database.create_lieberman_credential(
                host=load_test_data['lieberman']['host'],
                pam_port=load_test_data['lieberman']['port'],
                ssl=load_test_data['lieberman']['ssl'],
                ssl_verify=load_test_data['lieberman']['ssl_verify'],
                pam_user=load_test_data['lieberman']['pam_user'],
                pam_password=load_test_data['lieberman']['pam_password'],
                system_name=load_test_data['lieberman']['postgres']['system_name']))

        scan_model = ScanModel.create_model()
        scan_model.add_database_credential(creds)
        plugin_ids = load_test_data['lieberman']['postgres']['plugins_to_enable']
        plugin_id_report = load_test_data['lieberman']['postgres']['postgresql_login_plugin']
        scan_model.plugins = plugin_ids
        target = load_test_data['lieberman']['postgres']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id_report)
        outputs = json_out['outputs']
        if json_out['outputs'] is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'Credentialed checks have been enabled for PostgreSQL server on port 5432' in outputs[0]['plugin_output']


