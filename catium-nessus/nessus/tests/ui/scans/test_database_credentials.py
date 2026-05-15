"""
Nessus Credentials tab under Policy/Scan form related test cases For Database

:copyright: Tenable Network Security, 2017
:date: April 26, 2018
:last_modified: Mar 07, 2019
:author: @mameta, @ntarwani, @jchavda
"""
import os

import pytest

from catium.helpers.testdata import get_file_path
from catium.lib.const import WAIT_SHORT
from nessus.helpers.scan import save_and_configure_scan
from nessus.lib.const import API, Nessus
from nessus.pageobjects.credentials.database import Database, MongoDB, CyberArkDatabase, Lieberman
from nessus.pageobjects.scans.scans_page import ScansPage
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav


@pytest.mark.usefixtures('login')
class TestDatabaseCredentialsForm:
    """ Advanced scan creating and editing with Credentials -> Database related test cases"""

    @pytest.mark.nessus_home
    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_mongodb_database_credentials(self, create_scan):
        """
        NQA-1114: Verify Advanced scan is saved with Database > MongoDB
        1. Navigate to New Scan > Advanced Scan
        2. Enter scan details
        3. Go to credentials tab and select Database > MongoDB
        4. Fill input fields for the sub categories
        5. Save the scan
        6. Open the saved scan
        5. Verify the data saved is retained.
        """
        mongo_db_data_form = {'username': 'root', 'database': 'mongoDB', 'port': '27018', 'password': 'root'}
        scan_name = create_scan
        mongo_db = MongoDB(host_type=API.Credentials.Database.Types.MONGODB)
        LoadingCircle(WAIT_SHORT)
        mongo_db.fill_monogodb_database_form(**mongo_db_data_form)
        save_and_configure_scan(class_object=mongo_db, scan_name=scan_name)

        assert len(mongo_db.active_credentials) == 1, 'More than 1 credentials are available'
        mongo_db.open_saved_credentials_component(form_name=API.Credentials.Database.Types.MONGODB)
        mongo_db_data_form.update({'password': '********'})
        assert mongo_db.get_mongodb_form_values() == mongo_db_data_form, \
            'Data saved is incorrect or missing'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.nessus_home
    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('sql_server_form_data',
                             ({'database_type': 'SQL Server', 'port': '1433', 'db_auth_type': 'SQL',
                               'instance_name': 'nessus'},
                              {'database_type': 'SQL Server', 'port': '1433',
                               'db_auth_type': 'Windows', 'instance_name': 'nessus'}))
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_sql_server_database_credentials(self, create_scan, sql_server_form_data):
        """
        NQA-1120: Verify Advanced Scan is saved with Database > Database, auth type>
                    Password and Database Type> SQL Server > Windows
        NQA-1121: Verify Advanced Scan is saved with Database > Database, auth type>
                    Password and Database Type> SQL Server > SQL
        
        1. Navigate to New Scan > Advanced Scan
        2. Enter scan details
        3. Go to credentials tab and select Database > Database, auth type > Password, 
            Database Type> SQL Server > Windows/SQL
        4. Fill input fields
        5. Save the scan
        6. Open the saved scan
        5. Verify the data saved is retained.
        """
        password_form_data = {'authentication_type': 'Password', 'username': 'root', 'password': 'admin'}

        scan_name = create_scan
        database = Database(host_type=API.Credentials.Types.CATEGORY_DATABASE)
        LoadingCircle(WAIT_SHORT)
        database.fill_sql_server_form(**sql_server_form_data)
        database.fill_password_database_form(**password_form_data)

        save_and_configure_scan(class_object=database, scan_name=scan_name)

        assert len(database.active_credentials) == 1, 'More than 1 credentials are available'
        database.open_saved_credentials_component(form_name=API.Credentials.Types.CATEGORY_DATABASE)
        password_form_data.update({'password': '********'})
        assert database.get_password_database_form() == password_form_data and database. \
            get_sql_server_database_form_values() == sql_server_form_data, 'Data saved is incorrect or missing'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.nessus_home
    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("oracle_form_data, element_to_validate", [({'database_type': 'Oracle', 'port': '1522',
                                                                         'db_auth_type': 'SYSDBA',
                                                                         'service_type': 'SID',
                                                                         'service_name': 'database'},
                                                                        'get_database_username_element'),
                                                                       ({'database_type': 'Oracle', 'port': '1522',
                                                                         'db_auth_type': 'SYSOPER',
                                                                         'service_type': 'SERVICE_NAME',
                                                                         'service_name': 'database'}, 'oracle_sid'),
                                                                       ({'database_type': 'Oracle', 'port': '1522',
                                                                         'db_auth_type': 'NORMAL',
                                                                         'service_type': 'SERVICE_NAME',
                                                                         'service_name': 'database'}, 'oracle_sid')])
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_oracle_database_credentials(self, create_scan, oracle_form_data, element_to_validate):
        """
        NQA-1122: Verify Advanced Scan is saved with Database > Database, auth type> Password and
                    Database Type>Oracle >SYSDBA>SID
        NQA-1123: Verify Advanced Scan is saved with Database > Database, auth type> Password and
                    Database Type>Oracle >SYSOPER>Service Name
        NQA-1124: Verify Advanced Scan is saved with Database > Database, auth type> Password and
                    Database Type>Oracle >NORMAL>Service Name
        
        1. Navigate to New Scan > Advanced Scan
        2. Enter scan details
        3. Go to credentials tab and select Database > Database, auth type > Password, Database Type>Oracle >SYSDBA>SID
        4. Fill input fields
        5. Save the scan
        6. Open the saved scan
        5. Verify the data saved is retained.
        6. Repeat steps with Database Type>Oracle >SYSOPER>Service Name and Database Type>Oracle >NORMAL>Service Name

        NQA-1281: Verify mandatory field validation while edit for Advanced scan with credentials -> Database
        Auth Type: Password and Database Type: Oracle
        1. Repeat steps 1 to 6 from NQA-1122, NQA-1123, NQA-1124
        2. Under password remove data of username field
        3. Hit 'Save' and verify Validation message should appear "Error: Username is required."
        4. Again try to remove data of service field from Database Type>Oracle and auth_type > SYSOPER
        5. Hit 'Save' and verify validation message should appear for Service Name Field "Error: Service is required."
        """
        password_form_data = {'authentication_type': 'Password', 'username': 'root', 'password': 'admin'}

        scan_name = create_scan

        database = Database(host_type=API.Credentials.Types.CATEGORY_DATABASE)
        LoadingCircle(WAIT_SHORT)
        database.fill_password_database_form(**password_form_data)
        database.fill_oracle_database_type_form(**oracle_form_data)
        save_and_configure_scan(class_object=database, scan_name=scan_name)
        assert len(database.active_credentials) == 1, 'More than 1 credentials are available'

        database.open_saved_credentials_component(form_name=API.Credentials.Types.CATEGORY_DATABASE)
        password_form_data.update({'password': '********'})
        assert database.get_password_database_form() == password_form_data and \
               database.get_oracle_database_form_values() == oracle_form_data, 'Data saved is incorrect or missing'

        LoadingCircle(WAIT_SHORT)
        if element_to_validate == 'get_database_username_element':
            assert database.check_required_field_validation(class_instance=database, element=element_to_validate,
                                                            error_message='username',
                                                            element_args={'data_group': 'Password'}), \
                'Error notification for blank {} is missing.'.format(element_to_validate)
        else:
            assert database.check_required_field_validation(class_instance=database, element=element_to_validate), \
                'Error notification for blank {} is missing.'.format(element_to_validate)

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.parametrize("database_form_data, element_to_validate, notification", [
        ({'database_type': 'PostgreSQL', 'port': '5432', 'database_name': 'database'},
         'get_cyberark_element', 'app_id'),
        ({'database_type': 'DB2', 'port': '5432', 'database_name': 'database'}, 'get_element_for_given_form',
         'database_name'),
        ({'port': '5432', "database_type": "MySQL"}, 'get_cyberark_element', 'app_id')])
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_cyberark_database_credentials(self, create_scan, database_form_data, element_to_validate, notification):
        """
        NQA-1125: Verify Advanced Scan is saved with Database > Database, auth type> CyberArk and
                    Database Type> PostgreSQL
        NQA-1126: Verify Advanced Scan is saved with Database > Database, auth type> CyberArk and
                    Database Type> DB2
        NQA-1127: Verify Advanced Scan is saved with Database > Database, auth type> CyberArk and
                    Database Type> MySQL
        NES-8892: Some database credentialed tests are failing.
        Notes: database credentials tests are failing due to UI changes. Database type combobox has been moved on Top.

        1. Navigate to New Scan > Advanced Scan
        2. Enter scan details
        3. Go to credentials tab and select Database > Database, auth type > CyberArk,
            Database Type> PostgreSQL
        4. Fill input fields
        5. Save the scan
        6. Open the saved scan
        5. Verify the data saved is retained.
        6. Repeat steps with Database Type> MySQL and Database Type> DB2

        NQA-1281: Verify mandatory field validation while edit for Advanced scan with credentials -> Database
        Auth Type: CyberArk and Database Type: DB2
        1. Repeat steps 1 to 6 from NQA-1125, NQA-1126, NQA-1127
        2. Under CyberArk remove data of CyberArk Account Details Name field
        3. Hit 'Save' and verify Validation message should appear "Error: CyberArk Account Details Name is required."
        4. Again try to remove data of database Name field from Database Type>DB2
        5. Hit 'Save' and verify validation message should appear for database Name Field "Error: Database Name
        is required."
        """
        scan_name = create_scan

        key_path = os.path.abspath(get_file_path('nessus/tests/api/plugins/test_data/api_pub_key_target_priv_key'))

        cyberark_form_data = {'authentication_type': 'CyberArk', 'username': 'root', 'cred_host': '172.26.22.204',
                              'safe': 'Unix Accounts', 'appid': 'Nessus', 'use_ssl': False, 'verify_ssl': False}

        cyberark = CyberArkDatabase(host_type=API.Credentials.Types.CATEGORY_DATABASE)
        LoadingCircle(WAIT_SHORT)

        cyberark.fill_db2_or_postgresql_or_mysql_form(**database_form_data)
        cyberark.fill_cyberark_database_form(
            **cyberark_form_data, client_cert_filepath=key_path, private_key_filepath=key_path,
            database_type=database_form_data['database_type'], db_name=database_form_data['database_name'] if
            'database_name' in database_form_data else "", db_port=database_form_data['port'])
        save_and_configure_scan(class_object=cyberark, scan_name=scan_name)

        assert len(cyberark.active_credentials) == 1, 'More than 1 credentials are available'

        cyberark.open_saved_credentials_component(form_name=API.Credentials.Types.CATEGORY_DATABASE)

        database_form_data_PostgreSQL = {'database_type': 'PostgreSQL', 'port': '5432', 'database_name': ''}
        database_form_data_DB2 = {'database_type': 'DB2', 'port': '5432', 'database_name': 'database'}
        database_form_data_SQL = {'database_type': 'MySQL', 'port': '5432'}
        if database_form_data['database_type'] == 'DB2':
            assert cyberark.get_cyberark_database_form_values() == cyberark_form_data and cyberark. \
                get_db2_or_postgresql_or_mysql_form() == database_form_data_DB2, 'Data saved is incorrect or missing'
        elif database_form_data['database_type'] == 'PostgreSQL':
            assert cyberark.get_cyberark_database_form_values() == cyberark_form_data and cyberark. \
                get_db2_or_postgresql_or_mysql_form() == database_form_data_PostgreSQL, 'Data saved is incorrect or missing'
        else:
            assert cyberark.get_cyberark_database_form_values() == cyberark_form_data and cyberark. \
                get_db2_or_postgresql_or_mysql_form() == database_form_data_SQL, 'Data saved is incorrect or missing'

        assert "api_pub_key_target_priv_key" in \
               cyberark.get_cyberark_element_for_verification(database_type=database_form_data['database_type'],
                                                              data_input_id='pam_private_key').get_attribute(
                   'data-value') and "api_pub_key_target_priv_key" in \
               cyberark.get_cyberark_element_for_verification(database_type=database_form_data['database_type'],
                                                              data_input_id='pam_client_cert').get_attribute(
                   'data-value'), 'uploaded file is not available'

        LoadingCircle(WAIT_SHORT)
        if database_form_data['database_type'] == 'DB2':
            assert cyberark.check_required_field_validation(
                class_instance=cyberark, element=element_to_validate, error_message=notification,
                element_args={'db_type': database_form_data['database_type'], 'auth_type': "CyberArk",
                              'element_name': 'Database Name'}), \
                'Error notification for blank {} is missing.'.format(element_to_validate)
        else:
            assert cyberark.check_required_field_validation(
                class_instance=cyberark, element=element_to_validate, error_message=notification,
                element_args={'database_type': database_form_data['database_type'], 'data_input_id': 'pam_app_id'}), \
                'Error notification for blank {} is missing.'.format(element_to_validate)

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.parametrize("sql_server_form_data, element_to_validate, notification", [
        ({'database_type': 'SQL Server', 'port': '1433', 'db_auth_type': 'SQL',
          'instance_name': 'MSSQLSERVER'}, 'get_lieberman_host', 'lieberman_host'),
        ({'database_type': 'SQL Server', 'port': '1433',
          'db_auth_type': 'Windows', 'instance_name': 'MSSQLSERVER'}, 'get_lieberman_host', 'lieberman_host')])
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_lieberman_database_credentials(self, create_scan, sql_server_form_data, element_to_validate, notification):
        """
        NQA-1264: Verify Advanced scan is saved with Database > Database > Lieberman and database type >
            SQL Server > Windows
        NQA-1263: Verify Advanced Scan is saved with Database > Database, auth type> Lieberman and Database Type >
            SQL Server > SQL
        NES-8892: Some database credentialed tests are failing.
        Notes: database credentials tests are failing due to UI changes. Database type combobox has been moved on Top.

        1. Navigate to New Scan > Advanced Scan
        2. Enter Scan details
        3. Go to credentials tab and select Database > Database, auth type > Password,
            Database Type> SQL Server > Windows/SQL
        4. Fill input fields
        5. Save the scan
        6. Open the saved scan
        5. Verify the data saved is retained.

        NQA-1281: Verify mandatory field validation while edit for Advanced scan with credentials -> Database
        Auth Type : Lieberman
        1. Repeat steps 1 to 5 from NQA-1264, NQA-1263
        2. Under lieberman remove data of Lieberman host field
        3. Hit 'Save' and verify validation message should appear for Lieberman host field "Error: Lieberman host
        is required."
        """
        lieberman_form_data = {'username': 'admin', 'port': '80', 'host': '172.26.26.186', 'user': 'sys_admin',
                               'system_name': 'MSSQL.SANDERSON.RPI', 'use_ssl': True, 'verify_ssl': True,
                               'auth_type': 'Lieberman', 'password': 'admin'}

        scan_name = create_scan
        scan_page = ScansPage()

        lieberman = Lieberman(host_type=API.Credentials.Types.CATEGORY_DATABASE)
        LoadingCircle(WAIT_SHORT)
        lieberman.fill_sql_server_form(**sql_server_form_data)
        lieberman.fill_lieberman_form(**lieberman_form_data, database_type=sql_server_form_data['database_type'],
                                      instance_name=sql_server_form_data['instance_name'],
                                      db_auth_type=sql_server_form_data['db_auth_type'])
        lieberman.js_scroll_into_view(scan_page.save_button)

        save_and_configure_scan(class_object=lieberman, scan_name=scan_name)
        assert len(lieberman.active_credentials) == 1, 'More than 1 credentials are available'

        lieberman.open_saved_credentials_component(form_name=API.Credentials.Types.CATEGORY_DATABASE)
        lieberman_form_data.update({'password': '********'})
        assert lieberman.get_lieberman_form() == lieberman_form_data and lieberman. \
            get_sql_server_database_form_values_for_lieberman() == sql_server_form_data, \
            'Data saved is incorrect or missing'

        LoadingCircle(WAIT_SHORT)
        assert lieberman.check_required_field_validation(class_instance=lieberman, element=element_to_validate,
                                                         error_message=notification,
                                                         element_args={'database_type': sql_server_form_data[
                                                             'database_type']}), \
            'Error notification for blank {} is missing.'.format(element_to_validate)

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)
