"""
Nessus Credentials tab under Policy/Scan form related test cases For Database

:copyright: Tenable Network Security, 2017
:last modified: Mar 05, 2019
:author: @ntarwani, @jchavda
"""

import os

import pytest

from catium.helpers.testdata import get_file_path
from catium.lib.const import WAIT_SHORT, TIME_FIVE_SECONDS
from catium.lib.webium.wait import wait
from nessus.lib.const import API, Nessus
from nessus.pageobjects.credentials.database import Database, MongoDB, CyberArkDatabase, Lieberman
from nessus.pageobjects.policies.new_policy_form import NewPolicyForm
from nessus.pageobjects.policies.policies_page import PolicyList
from nessus.pageobjects.shared.loading import LoadingCircle


@pytest.mark.policies_pipeline_1
@pytest.mark.usefixtures('login')
class TestDatabaseCredentialsForm:
    """NQA-1246: Automation tests for New Policy > 'advanced scan' under 'Scanner' tab is saved successfully with values
        given under credentials ->Category 'Database' """

    @pytest.mark.nessus_home
    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED,
                                                Nessus.Scan.ScanTemplateTabs.SCANNER_TAB)], indirect=True)
    def test_mongodb_database_credentials(self, create_policy):
        """
        NQA-1247: Verify Advanced scan is saved with Database > MongoDB
        1. Navigate to Polices > New Policy
        2. Enter Policy details
        3. Go to credentials tab and select Database > MongoDB
        4. Fill input fields for the sub categories
        5. Save the policy
        6. Open the saved policy
        5. Verify the data saved is retained.
        """
        mongo_db_data_form = {'username': 'root', 'database': 'mongoDB', 'port': '27018', 'password': 'root'}
        policy_name = create_policy
        policy_form = NewPolicyForm()

        mongo_db = MongoDB(host_type=API.Credentials.Database.Types.MONGODB)
        LoadingCircle(WAIT_SHORT)
        mongo_db.fill_monogodb_database_form(**mongo_db_data_form)
        policy_form.save_button.click()

        PolicyList().click_on_policy(policy_name=policy_name)
        policy_form.credentials.click()
        assert len(mongo_db.active_credentials) == 1, 'More than 1 credentials are available'

        mongo_db.open_saved_credentials_component(form_name=API.Credentials.Database.Types.MONGODB)
        mongo_db_data_form.update({'password': '********'})
        assert mongo_db.get_mongodb_form_values() == mongo_db_data_form, 'Data saved is incorrect or missing'

        policy_form.back_to_policies.click()
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.nessus_home
    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('sql_server_form_data', ({'database_type': 'SQL Server', 'port': '1433',
                                                       'db_auth_type': 'SQL', 'instance_name': 'nessus'},
                                                      {'database_type': 'SQL Server', 'port': '1433',
                                                       'db_auth_type': 'Windows', 'instance_name': 'nessus'}))
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED,
                                                Nessus.Scan.ScanTemplateTabs.SCANNER_TAB)], indirect=True)
    def test_sql_server_password_credentials(self, create_policy, sql_server_form_data):
        """
        NQA-1248: Verify Advanced Scan is saved with Database > Database, auth type>
                    Password and Database Type> SQL Server > Windows
        NQA-1429: Verify Advanced Scan is saved with Database > Database, auth type>
                    Password and Database Type> SQL Server > SQL

        1. Navigate to Polices > New Policy
        2. Enter Policy details
        3. Go to credentials tab and select Database > Database, auth type > Password,
            Database Type> SQL Server > Windows/SQL
        4. Fill input fields
        5. Save the policy
        6. Open the saved policy
        5. Verify the data saved is retained.
        """
        policy_name = create_policy
        policy_form = NewPolicyForm()

        password_form_data = {'authentication_type': 'Password', 'username': 'root', 'password': 'admin'}

        database = Database(host_type=API.Credentials.Types.CATEGORY_DATABASE)
        LoadingCircle(WAIT_SHORT)
        database.fill_sql_server_form(**sql_server_form_data)
        database.fill_password_database_form(**password_form_data)

        policy_form.save_button.click()

        PolicyList().click_on_policy(policy_name=policy_name)
        policy_form.credentials.click()
        assert len(database.active_credentials) == 1, 'More than 1 credentials are available'

        database.open_saved_credentials_component(form_name=API.Credentials.Types.CATEGORY_DATABASE)
        password_form_data.update({'password': '********'})

        assert database.get_password_database_form() == password_form_data and \
               database.get_sql_server_database_form_values() == sql_server_form_data, \
            'Data saved is incorrect or missing'

        policy_form.back_to_policies.click()
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.nessus_home
    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('oracle_form_data', ({'database_type': 'Oracle', 'port': '1522',
                                                   'db_auth_type': 'SYSDBA', 'service_type': 'SID',
                                                   'service_name': 'database'},
                                                  {'database_type': 'Oracle', 'port': '1522', 'db_auth_type': 'SYSOPER',
                                                   'service_type': 'SERVICE_NAME', 'service_name': 'database'},
                                                  {'database_type': 'Oracle', 'port': '1522', 'db_auth_type': 'NORMAL',
                                                   'service_type': 'SERVICE_NAME', 'service_name': 'database'}))
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED,
                                                Nessus.Scan.ScanTemplateTabs.SCANNER_TAB)], indirect=True)
    def test_oracle_database_credentials(self, create_policy, oracle_form_data):
        """
        NQA-1250: Verify Advanced Scan is saved with Database > Database, auth type> Password and
                    Database Type>Oracle >SYSDBA>SID
        NQA-1251: Verify Advanced Scan is saved with Database > Database, auth type> Password and
                    Database Type>Oracle >SYSOPER>Service Name
        NQA-1252: Verify Advanced Scan is saved with Database > Database, auth type> Password and
                    Database Type>Oracle >NORMAL>Service Name

        1. Navigate to Polices > New Policy
        2. Enter Policy details
        3. Go to credentials tab and select Database > Database, auth type > Password, Database Type>Oracle >SYSDBA>SID
        4. Fill input fields
        5. Save the policy
        6. Open the saved policy
        5. Verify the data saved is retained.
        6. Repeat steps with Database Type>Oracle >SYSOPER>Service Name and Database Type>Oracle >NORMAL>Service Name
        """
        policy_name = create_policy
        policy_form = NewPolicyForm()

        password_form_data = {'authentication_type': 'Password', 'username': 'root', 'password': 'admin'}

        database = Database(host_type=API.Credentials.Types.CATEGORY_DATABASE)
        LoadingCircle(WAIT_SHORT)
        database.fill_oracle_database_type_form(**oracle_form_data)
        database.fill_password_database_form(**password_form_data)

        policy_form.save_button.click()

        PolicyList().click_on_policy(policy_name=policy_name)
        policy_form.credentials.click()
        assert len(database.active_credentials) == 1, 'More than 1 credentials are available'

        database.open_saved_credentials_component(form_name=API.Credentials.Types.CATEGORY_DATABASE)
        password_form_data.update({'password': '********'})
        assert database.get_password_database_form() == password_form_data and \
               database.get_oracle_database_form_values() == oracle_form_data, 'Data saved is incorrect or missing'

        policy_form.back_to_policies.click()
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.parametrize('database_form_data', (
            {'database_type': 'PostgreSQL', 'port': '5432', 'database_name': ''},
            {'database_type': 'DB2', 'port': '5432', 'database_name': '1'},
            {'database_type': 'MySQL', 'port': '5432'}))
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED,
                                                Nessus.Scan.ScanTemplateTabs.SCANNER_TAB)], indirect=True)
    def test_cyberark_database_credentials(self, create_policy, database_form_data):
        """
        NQA-1253: Verify Advanced Scan is saved with Database > Database, auth type> CyberArk and
                    Database Type> PostgreSQL
        NQA-1254: Verify Advanced Scan is saved with Database > Database, auth type> CyberArk and
                    Database Type> DB2
        NQA-1255: Verify Advanced Scan is saved with Database > Database, auth type> CyberArk and
                    Database Type> MySQL
        NES-8892: Some database credentialed tests are failing.
        Notes: database credentials tests are failing due to UI changes. Database type combobox has been moved on Top.

        1. Navigate to Polices > New Policy
        2. Enter Policy details
        3. Go to credentials tab and select Database > Database, auth type > CyberArk,
            Database Type> PostgreSQL
        4. Fill input fields
        5. Save the policy
        6. Open the saved policy
        5. Verify the data saved is retained.
        6. Repeat steps with Database Type> MySQL and Database Type> DB2
        """
        key_path = os.path.abspath(get_file_path('nessus/tests/api/plugins/test_data/api_pub_key_target_priv_key'))

        cyberark_form_data = {'authentication_type': 'CyberArk', 'username': 'root', 'cred_host': '172.26.22.204',
                              'safe': 'Unix Accounts', 'appid': 'Nessus', 'use_ssl': False, 'verify_ssl': False}

        policy_name = create_policy
        policy_form = NewPolicyForm()

        cyberark = CyberArkDatabase(host_type=API.Credentials.Types.CATEGORY_DATABASE)
        LoadingCircle(WAIT_SHORT)
        cyberark.fill_db2_or_postgresql_or_mysql_form(**database_form_data)
        cyberark.fill_cyberark_database_form(
            **cyberark_form_data, client_cert_filepath=key_path, private_key_filepath=key_path,
            database_type=database_form_data['database_type'], db_name=database_form_data[
                'database_name'] if 'database_name' in database_form_data else "", db_port=database_form_data['port'])
        if database_form_data['database_type'] == 'PostgreSQL':
            policy_form.save_button.click()
        elif database_form_data['database_type'] == 'DB2':
            wait(lambda: policy_form.is_element_present('database_area'), timeout_seconds=TIME_FIVE_SECONDS)
            policy_form.database_area.send_keys("")
            policy_form.save_button.click()
        else:
            policy_form.save_button.click()

        policy_list = PolicyList()
        policy_list.loaded()
        policy_list.click_on_policy(policy_name=policy_name)
        policy_form.credentials.click()

        assert len(cyberark.active_credentials) == 1, 'More than 1 credentials are available'

        cyberark.open_saved_credentials_component(form_name=API.Credentials.Types.CATEGORY_DATABASE)

        assert cyberark.get_cyberark_database_form_values() == cyberark_form_data and cyberark. \
            get_db2_or_postgresql_or_mysql_form() == database_form_data, 'Data saved is incorrect or missing'

        assert "api_pub_key_target_priv_key" in \
               cyberark.get_cyberark_key_element(database_type=database_form_data['database_type'],
                                                 data_input_id='pam_private_key').get_attribute(
                   'data-value') and "api_pub_key_target_priv_key" in \
               cyberark.get_cyberark_element(database_type=database_form_data['database_type'],
                                             data_input_id='pam_client_cert').get_attribute(
                   'data-value'), 'uploaded file is not available'

        policy_form.back_to_policies.click()
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.parametrize('sql_server_form_data',
                             ({'database_type': 'SQL Server', 'port': '1433', 'db_auth_type': 'SQL',
                               'instance_name': 'MSSQLSERVER'},
                              {'database_type': 'SQL Server', 'port': '1433',
                               'db_auth_type': 'Windows', 'instance_name': 'MSSQLSERVER'}))
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED,
                                                Nessus.Scan.ScanTemplateTabs.SCANNER_TAB)], indirect=True)
    def test_lieberman_database_credentials(self, create_policy, sql_server_form_data):
        """
        NQA-1261: Verify Advanced scan is saved with Database > Database > Lieberman and database type >
            SQL Server > Windows
        NQA-1262: Verify Advanced Scan is saved with Database > Database, auth type> Lieberman and Database Type >
            SQL Server > SQL
        NES-8892: Some database credentialed tests are failing.
        Notes: database credentials tests are failing due to UI changes. Database type combobox has been moved on Top.

        1. Navigate to Polices > New Policy
        2. Enter Policy details
        3. Go to credentials tab and select Database > Database, auth type > Password,
            Database Type> SQL Server > Windows/SQL
        4. Fill input fields
        5. Save the policy
        6. Open the saved policy
        5. Verify the data saved is retained.
        """
        lieberman_form_data = {'username': 'admin', 'port': '80', 'host': '172.26.26.186', 'user': 'asd',
                               'system_name': 'MSSQL.SANDERSON.RPI', 'use_ssl': True, 'verify_ssl': True,
                               'auth_type': 'Lieberman', 'password': 'admin'}

        policy_name = create_policy
        policy_form = NewPolicyForm()

        lieberman = Lieberman(host_type=API.Credentials.Types.CATEGORY_DATABASE)
        LoadingCircle(WAIT_SHORT)
        lieberman.fill_sql_server_form(**sql_server_form_data)
        lieberman.fill_lieberman_form(**lieberman_form_data, database_type=sql_server_form_data['database_type'],
                                      instance_name=sql_server_form_data['instance_name'],
                                      db_auth_type=sql_server_form_data['db_auth_type'])

        lieberman.js_scroll_into_view(policy_form.save_button)

        policy_form.save_button.click()

        policy_list = PolicyList()
        policy_list.loaded()
        PolicyList().click_on_policy(policy_name=policy_name)
        policy_form.credentials.click()
        assert len(lieberman.active_credentials) == 1, 'More than 1 credentials are available'

        lieberman.open_saved_credentials_component(form_name=API.Credentials.Types.CATEGORY_DATABASE)
        lieberman_form_data.update({'password': '********'})

        assert lieberman.get_lieberman_form() == lieberman_form_data and \
               lieberman.get_sql_server_database_form_values_for_lieberman() == sql_server_form_data, \
            'Data saved is incorrect or missing'

        policy_form.back_to_policies.click()
