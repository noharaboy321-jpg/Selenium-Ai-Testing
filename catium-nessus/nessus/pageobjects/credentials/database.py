"""
Nessus page classes for Database under credentials tab in new scan page

:copyright: Tenable Network Security, 2017
:date: April 26, 2018
:last_modified: June 17, 2018
:author: @mameta, @ntarwani, @jchavda, @kpanchal
"""

from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement

from catium.lib.webium import Find
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.text_field import TextField
from nessus.lib.const import API
from nessus.pageobjects.credentials.credentials_page import Credentials
from nessus.pageobjects.scans.scans_page import ScansPage


class Database(Credentials):
    """Page class for Database field under category dropdown in Nessus scan credentials."""

    oracle_database_service_type = Find(Select2Dropdown, by=By.CSS_SELECTOR,
                                        value='li[class*=opened][data-name="Database"] '
                                              '>div>div>div:not([style*="display:none"]) '
                                              'select[data-input-id="oracle_service_type"]')
    oracle_sid = Find(TextField, by=By.CSS_SELECTOR,
                      value='li[class*=opened][data-name="Database"] input[data-input-id="oracle_sid"]')

    auth_type = Find(Select2Dropdown, by=By.CSS_SELECTOR,
                     value='div[data-group="Oracle"] div[class="form-group"] > select[data-name="Auth Type"]')

    database_type = Find(Select2Dropdown, by=By.CSS_SELECTOR,
                         value='li[class*=opened][data-name="Database"] select[data-input-id="type"]')

    def __init__(self, **kwargs):
        super().__init__()
        self.click_credentials_type(category_name=API.Credentials.Types.CATEGORY_DATABASE,
                                    credentials_type=kwargs.get('host_type'))

    def get_auth_type_element(self) -> Find:
        """
        Returns Auth type element

        :return: auth type element for database
        :rtype: WebElement
        """
        db_type = self.database_type.get_value_selected()

        return Find(Select2Dropdown, by=By.CSS_SELECTOR, value='div[data-group="{}"] div[class="form-group"] > select['
                                                               'data-name="Auth Type"]'.format(db_type), context=self)

    def get_database_username_element(self, data_group: str) -> Find:
        """
        Returns username element

        :param str data_group: data group name
        :return: username element for database
        :rtype: WebElement
        """
        db_type = self.database_type.get_value_selected()

        return Find(by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="Database"] div[data-group="{}"] '
                                              'div[data-group="{}"] input[data-input-id="username"]'.
                    format(db_type, data_group), context=self)

    def get_password_element(self, data_group: str) -> Find:
        """
        Returns password element

        :param str data_group: data group name
        :return: password element for database
        :rtype: WebElement
        """
        db_type = self.database_type.get_value_selected()

        return Find(by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="Database"] div[data-group="{}"] '
                                              'div[data-group="{}"] input[data-input-id="password"]'.
                    format(db_type, data_group), context=self)

    def get_database_port(self, database_type: str) -> WebElement:
        """
        get database port field
        :param str database_type: database type
        :return: port element for database
        :rtype: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="Database"] '
                                              'div[data-group="{}"] [data-input-id="port"]'
                    .format(database_type), context=self)

    def get_database_auth_type(self, auth_type: str) -> WebElement:
        """
        get database authentication type
        :param str auth_type: sql_server_auth_type or oracle_auth_type
        :return: database auth type
        :rtype: WebElement
        """
        return Find(Select2Dropdown, by=By.CSS_SELECTOR, value='li[class*=opened][data-name="Database"] '
                                                               '>div>div>div:not([style*="display:none"]) '
                                                               'select[data-input-id*="{}"]'.format(auth_type),
                    context=self)

    def database_or_instance_name(self, database_type: str) -> WebElement:
        """
        Get database or instance name

        :param str database_type: database type
        :return: database name or instance name element
        :rtype: WebElement
        """
        return Find(Select2Dropdown, by=By.CSS_SELECTOR, value='li[class*=opened][data-name="Database"] '
                                                               'div[data-group="{}"] input[data-input-id="db_sid"]'
                    .format(database_type), context=self)

    def get_cyberark_host_element(self, database_type: str, data_input_id: str) -> WebElement:
        """
        Get elements of CyberArk and Lieberman Auth Type

        :param str database_type: Select database type eq. DB2 and Oracle etc
        :param str data_input_id: Textfield name eq. Host, Port etc
        :return: Elements of CyberArk and Lieberman
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*=opened][data-name="Database"] '
                                                         'div[data-group="{}"] '
                                                         'input[data-input-id="{}"][data-name="CyberArk Host"]'.format(
            database_type,
            data_input_id),
                    context=self)

    def get_cyberark_key_element(self, database_type: str, data_input_id: str) -> WebElement:
        """
        Get elements of CyberArk and Lieberman Auth Type

        :param str database_type: Select database type eq. DB2 and Oracle etc
        :param str data_input_id: Textfield name eq. Host, Port etc
        :return: Elements of CyberArk and Lieberman
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*=opened][data-name="Database"] '
                                                         'div[data-group="{}"] '
                                                         'input[data-input-id="{}"][data-name="Client Certificate Private Key"]'.format(
            database_type,
            data_input_id),
                    context=self)

    def get_cyberark_safe_element(self, database_type: str, data_input_id: str) -> WebElement:
        """
        Get elements of CyberArk and Lieberman Auth Type

        :param str database_type: Select database type eq. DB2 and Oracle etc
        :param str data_input_id: Textfield name eq. Host, Port etc
        :return: Elements of CyberArk and Lieberman
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*=opened][data-name="Database"] '
                                                         'div[data-group="{}"] div[data-group="Username"] '
                                                         'input[data-input-id="{}"]'.format(database_type,
                                                                                            data_input_id),
                    context=self)

    def get_cyberark_element(self, database_type: str, data_input_id: str) -> WebElement:
        """
        Get elements of CyberArk and Lieberman Auth Type

        :param str database_type: Select database type eq. DB2 and Oracle etc
        :param str data_input_id: Textfield name eq. Host, Port etc
        :return: Elements of CyberArk and Lieberman
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*=opened][data-name="Database"] '
                                                         'div[data-group="{}"] '
                                                         'input[data-input-id="{}"]'.format(database_type,
                                                                                            data_input_id),
                    context=self)

    def get_cyberark_element_for_verification(self, database_type: str, data_input_id: str) -> WebElement:
        """
        Get elements of CyberArk and Lieberman Auth Type

        :param str database_type: Select database type eq. DB2 and Oracle etc
        :param str data_input_id: Textfield name eq. Host, Port etc
        :return: Elements of CyberArk and Lieberman
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*=opened][data-name="Database"] '
                                                         'div[data-group="{}"] '
                                                         'input[data-input-id="{}"][data-name*="Client Certificate"]'.format(
            database_type,
            data_input_id),
                    context=self)

    def fill_password_database_form(self, **kwargs) -> None:
        """
        fill password form under database
        :return: None
        """
        username = kwargs.get('username', '')
        password = kwargs.get('password', '')
        authentication_type = kwargs.get('authentication_type', '')

        self.get_auth_type_element().select_by_visible_text(authentication_type)
        self.get_database_username_element('Password').send_keys(username)
        self.get_password_element('Password').send_keys(password)

    def get_password_database_form(self) -> dict:
        """
        Returns password form under Database category
        :return: dictionary containing password form values
        :rtype: dict
        """
        auth_type = self.get_auth_type_element().get_value_selected()

        return {'authentication_type': auth_type,
                'username': self.get_database_username_element(auth_type).get_attribute('value'),
                'password': self.get_password_element(auth_type).get_attribute('value')}

    def fill_oracle_database_type_form(self, **kwargs) -> None:
        """
        fill oracle database type under database-> database type
        :return: None
        """
        database_type = kwargs.get('database_type', '')
        port = kwargs.get('port', '')
        db_auth_type = kwargs.get('db_auth_type', '')
        service_type = kwargs.get('service_type', '')
        service_name = kwargs.get('service_name', '')

        self.database_type.select_by_visible_text(database_type)
        self.get_database_port(database_type).clear()
        self.get_database_port(database_type).send_keys(port)
        self.get_database_auth_type(auth_type="oracle_auth_type").select_by_visible_text(db_auth_type)
        self.oracle_database_service_type.select_by_visible_text(service_type)
        self.oracle_sid.value = service_name

    def get_oracle_database_form_values(self) -> dict:
        """
        returns filled values of oracle database form
        :return: dictionary containing oracle form values
        :rtype:dict
        """
        return {'database_type': self.database_type.text,
                'port': self.get_database_port("Oracle").get_attribute('value'),
                'db_auth_type': self.get_database_auth_type(auth_type="oracle_auth_type").text,
                'service_type': self.oracle_database_service_type.text,
                'service_name': self.oracle_sid.get_attribute('value')}

    def fill_sql_server_form(self, **kwargs) -> None:
        """
        fill sql server type under database-> database type
        :return: None
        """
        database_type = kwargs.get('database_type', '')
        port = kwargs.get('port', '')
        db_auth_type = kwargs.get('db_auth_type', '')
        instance_name = kwargs.get('instance_name', '')

        self.database_type.select_by_visible_text(database_type)
        self.get_database_port(database_type).clear()
        self.get_database_port(database_type).send_keys(port)
        self.get_database_auth_type(auth_type="sql_server_auth_type").select_by_visible_text(db_auth_type)
        self.database_or_instance_name(database_type).send_keys(instance_name)

    def get_sql_server_database_form_values(self) -> dict:
        """
        returns filled values of sql server form
        :return dictionary containing values of sql server form
        :rtype:dict
        """
        return {'database_type': self.database_type.text,
                'db_auth_type': self.get_database_auth_type(auth_type="sql_server_auth_type").text,
                'instance_name': self.database_or_instance_name('SQL Server').get_attribute('value'),
                'port': self.get_database_port("SQL Server").get_attribute('value')}

    def fill_db2_or_postgresql_or_mysql_form(self, **kwargs) -> None:
        """
        fill postgresql or db2 or mysql database form under database type
        :return: None
        """
        database_type = kwargs.get('database_type', '')
        database_name = kwargs.get('database_name', '')
        port = kwargs.get('port', '')

        self.database_type.select_by_visible_text(database_type)
        self.get_database_port(database_type).clear()
        self.get_database_port(database_type).send_keys(port)

        if database_type in ['DB2', 'PostgreSQL']:
            self.database_or_instance_name(database_type).send_keys(database_name)

    def get_db2_or_postgresql_or_mysql_form(self) -> dict:
        """
        Returns form for DB2 or PostgreSQL form
        :return: dictionary containing values for DB2 or PostgreSQL form
        :rtype: dict
        """
        database_type = self.database_type.text
        data = {'database_type': database_type, 'port': self.get_database_port(database_type).get_attribute('value')}

        if database_type == 'PostgreSQL':
            data.update({'database_name': self.database_or_instance_name(database_type).get_attribute('value')})
        elif database_type == 'DB2':
            data.update({'database_name': self.get_element_for_given_form(db_type=database_type, auth_type="CyberArk",
                                                                          element_name="Database Name").value})

        if database_type in ["MySQL", "DB2"]:
            data.update({'port': self.get_element_for_given_form(db_type=database_type, auth_type="CyberArk",
                                                                 element_name="Database Port").value})

        return data

    def get_element_for_given_form(self, db_type: str, auth_type: str, element_name: str,
                                   element_type: str = "text") -> WebElement:
        """
        This function returns web-element for given specifications (db_type/auth_type)
        :param str db_type: Type of Database
        :param str auth_type:  Auth Type
        :param str element_name: Name of element
        :param element_type: Type of element (text or drop down)
        :return: Web-element for given specification
        :rtype: WebElement
        """
        type = Select2Dropdown if element_type == "drop_down" else TextField
        return Find(type, by=By.XPATH, value='//li[contains(@class, "opened")]//div[contains(@class, '
                                             '"component-inputs")]//div[@data-group="{}"]//div[@data-group="{}"]'
                                             '//*[@data-name="{}"]'.format(db_type, auth_type, element_name),
                    context=self)


class CyberArkDatabase(Database):
    """
    Page object for CyberArk under Database
    """

    def get_private_key_passphrase_element(self, database_type: str) -> WebElement:
        """
        Get private key passphrase element

        :param str database_type: Database type eq.DB2 Or Oracle Or MySQL
        :return: Private key passphrase element for cyberArk in Database
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*=opened] div[data-group="{}"] '
                                                         'div[data-group="CyberArk"] '
                                                         'input[data-input-id="vault_cyberark_private_key_passphrase"]'
                    .format(database_type), context=self)

    def get_use_ssl_element(self, database_type: str) -> WebElement:
        """
        Get Use SSL

        :param str database_type: Database type eq.DB2 Or Oracle Or MySQL
        :return: Use SSL element for cyberArk in Database
        :rtype: WebElement
        """
        return Find(CheckboxDiv, by=By.CSS_SELECTOR,
                    value='li[class*="opened"][data-name="Database"] div[data-group="{}"] div[data-group="CyberArk"] div['
                          'data-input-id="pam_use_ssl"]'.format(database_type), context=self)

    def db_or_instance_name(self, database_type: str) -> WebElement:
        """
        Get database name associated with cyberark form
        :param database_type: Type of Database
        :return: WebElement for database name in cyberark form.
        :rtype: WebElement
        """
        return self.get_element_for_given_form(db_type=database_type, auth_type="CyberArk",
                                               element_name="Database Name")

    def get_verify_ssl_element(self, database_type: str) -> WebElement:
        """
        Get Verify SSL Certificate element

        :param str database_type: Database type eq.DB2 Or Oracle Or MySQL
        :return: Verify ssl checkbox element for cyberArk in Database
        :rtype: WebElement
        """
        return Find(CheckboxDiv, by=By.CSS_SELECTOR,
                    value='li[class*="opened"][data-name="Database"] div[data-group="{}"] div[data-group="CyberArk"] div['
                          'data-input-id="pam_verify_ssl"]'.format(database_type), context=self)

    def fill_cyberark_legacy_database_form(self, **kwargs) -> None:
        """
        fill form for CyberArk under database
        :return: None
        """
        authentication_type = kwargs.get('authentication_type')
        use_ssl = kwargs.get('use_ssl', True)
        verify_ssl = kwargs.get('verify_ssl', True)
        database_type = kwargs.get('database_type', '')

        self.get_auth_type_element().select_by_visible_text('CyberArk')
        self.get_database_username_element(authentication_type).send_keys(kwargs.get('username'))
        self.get_cyberark_element(database_type=database_type, data_input_id='vault_host').send_keys(kwargs.get
                                                                                                     ('cred_host'))
        self.get_cyberark_element(database_type=database_type, data_input_id='vault_port').send_keys(kwargs.get
                                                                                                     ('cred_port'))
        self.get_cyberark_element(database_type=database_type, data_input_id='vault_cyberark_url').send_keys(
            kwargs.get('cyberark_url'))
        self.get_cyberark_element(database_type=database_type, data_input_id='vault_username').send_keys(
            kwargs.get('cred_username'))
        self.get_cyberark_element(database_type=database_type, data_input_id='vault_password').send_keys(
            kwargs.get('cred_password'))
        self.get_cyberark_element(database_type=database_type, data_input_id='vault_safe').send_keys(kwargs.get('safe'))
        self.get_cyberark_element(database_type=database_type, data_input_id='vault_cyberark_client_cert').send_keys(
            kwargs.get('client_cert_filepath'))
        self.get_cyberark_element(database_type=database_type, data_input_id='vault_cyberark_private_key').send_keys(
            kwargs.get('private_key_filepath'))
        self.get_private_key_passphrase_element(database_type=database_type).send_keys(kwargs.get('passphrase'))
        self.js_scroll_into_view(element=ScansPage().save_button)
        self.get_cyberark_element(database_type=database_type, data_input_id='vault_app_id').send_keys(
            kwargs.get('appid'))
        self.get_cyberark_element(database_type=database_type, data_input_id='vault_folder').send_keys(
            kwargs.get('folder'))
        self.get_cyberark_element(database_type=database_type, data_input_id='vault_policy_id').send_keys(
            kwargs.get('policy_id'))
        self.get_cyberark_element(database_type=database_type, data_input_id='vault_account_name').send_keys(
            kwargs.get('account_name'))
        self.get_use_ssl_element(database_type=database_type).set_checked(use_ssl)
        self.get_verify_ssl_element(database_type=database_type).set_checked(verify_ssl)
        if database_type == "DB2":
            self.get_element_for_given_form(db_type=database_type, auth_type="CyberArk",
                                            element_name="Database Name").send_keys(kwargs.get('db_name'))
        if database_type in ["MySQL", "DB2"]:
            db_port = self.get_element_for_given_form(db_type=database_type, auth_type="CyberArk",
                                                      element_name="Database Port")
            db_port.clear()
            db_port.send_keys(kwargs.get('db_port'))

    def fill_cyberark_database_form(self, **kwargs) -> None:
        """
        fill form for CyberArk under database
        :return: None
        """
        authentication_type = kwargs.get('authentication_type')
        use_ssl = kwargs.get('use_ssl', True)
        verify_ssl = kwargs.get('verify_ssl', True)
        database_type = kwargs.get('database_type', '')

        self.get_auth_type_element().select_by_visible_text('CyberArk')
        self.get_database_username_element(authentication_type).send_keys(kwargs.get('username'))
        self.get_cyberark_host_element(database_type=database_type, data_input_id='pam_host').send_keys(kwargs.get(
            'cred_host'))
        self.get_cyberark_element(database_type=database_type, data_input_id='pam_app_id').send_keys(
            kwargs.get('appid'))

        self.get_cyberark_element(database_type=database_type, data_input_id='pam_client_cert').send_keys(
            kwargs.get('client_cert_filepath'))
        self.get_cyberark_key_element(database_type=database_type, data_input_id='pam_private_key').send_keys(
            kwargs.get('private_key_filepath'))
        self.js_scroll_into_view(element=ScansPage().save_button)
        self.get_cyberark_safe_element(database_type=database_type, data_input_id='pam_safe').send_keys(
            kwargs.get('safe'))
        self.get_use_ssl_element(database_type=database_type).set_checked(use_ssl)
        self.get_verify_ssl_element(database_type=database_type).set_checked(verify_ssl)

        if database_type == "DB2":
            self.get_element_for_given_form(db_type=database_type, auth_type="CyberArk",
                                            element_name="Database Name").send_keys(kwargs.get('db_name'))

        if database_type in ["MySQL", "DB2"]:
            db_port = self.get_element_for_given_form(db_type=database_type, auth_type="CyberArk",
                                                      element_name="Database Port")
            db_port.clear()
            db_port.send_keys(kwargs.get('db_port'))

    def get_cyberark_legacy_database_form_values(self) -> dict:
        """
        returns cyberark database filled form values
        :return: dictionary containing CyberArk form values
        :rtype:dict
        """
        auth_type = self.get_auth_type_element().get_value_selected()
        database_type = self.database_type.text

        cyberark_data = {'authentication_type': auth_type,
                         'username': self.get_database_username_element(auth_type).get_attribute('value'),
                         'cred_host': self.get_cyberark_element(database_type, 'vault_host').get_attribute('value'),
                         'cred_port': self.get_cyberark_element(database_type, 'vault_port').get_attribute('value'),
                         'cyberark_url': self.get_cyberark_element(database_type, 'vault_cyberark_url').get_attribute
                         ('value'),
                         'cred_username': self.get_cyberark_element(database_type, 'vault_username').get_attribute
                         ('value'),
                         'cred_password': self.get_cyberark_element(database_type, 'vault_password').get_attribute
                         ('value'),
                         'safe': self.get_cyberark_element(database_type, 'vault_safe').get_attribute('value'),
                         'passphrase': self.get_private_key_passphrase_element(database_type).get_attribute('value'),
                         'appid': self.get_cyberark_element(database_type, 'vault_app_id').get_attribute('value'),
                         'folder': self.get_cyberark_element(database_type, 'vault_folder').get_attribute('value'),
                         'policy_id': self.get_cyberark_element(database_type, 'vault_policy_id').get_attribute
                         ('value'),
                         'account_name': self.get_cyberark_element(database_type, 'vault_account_name').get_attribute
                         ('value'),
                         'use_ssl': self.get_use_ssl_element(database_type).is_selected(),
                         'verify_ssl': self.get_verify_ssl_element(database_type).is_selected(),
                         }
        return cyberark_data

    def get_cyberark_database_form_values(self) -> dict:
        """
        returns cyberark database filled form values
        :return: dictionary containing CyberArk form values
        :rtype:dict
        """
        selected_auth_type = self.get_auth_type_element().get_value_selected()
        auth_type = selected_auth_type.split(' (')[0] if ' (' in selected_auth_type else selected_auth_type
        database_type = self.database_type.text

        cyberark_data = {'authentication_type': auth_type,
                         'username': self.get_database_username_element(auth_type).get_attribute('value'),
                         'cred_host': self.get_cyberark_host_element(database_type, 'pam_host').get_attribute('value'),
                         'safe': self.get_cyberark_element(database_type, 'pam_safe').get_attribute('value'),
                         'appid': self.get_cyberark_element(database_type, 'pam_app_id').get_attribute('value'),
                         'use_ssl': self.get_use_ssl_element(database_type).is_selected(),
                         'verify_ssl': self.get_verify_ssl_element(database_type).is_selected()}
        return cyberark_data


class Lieberman(Database):
    """
    Page Object for Lieberman database
    """

    def get_lieberman_user(self, database_type: str) -> WebElement:
        """
        Get Lieberman user

        :param str database_type: Database type eq.DB2 Or Oracle Or MySQL
        :return: Lieberman user element for Lieberman in Database
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*=opened][data-name="Database"] '
                                                         'div[data-group="{}"] '
                                                         'input[data-input-id="lieberman_pam_user"]'.
                    format(database_type), context=self)

    def get_lieberman_host(self, database_type: str) -> WebElement:
        """
        Get Lieberman host

        :param str database_type: Database type eq.DB2 Or Oracle Or MySQL
        :return: Lieberman host element for Lieberman in Database
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*=opened][data-name="Database"] '
                                                         'div[data-group="{}"] '
                                                         'input[data-input-id="lieberman_host"]'.
                    format(database_type), context=self)

    def get_use_ssl_element(self, database_type: str) -> WebElement:
        """
        Get Use SSL

        :param str database_type: Database type eq.DB2 Or Oracle Or MySQL
        :return: Use SSL element for Lieberman in Database
        :rtype: WebElement
        """
        return Find(CheckboxDiv, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="Database"] '
                                                           'div[data-group="{}"] '
                                                           'div[data-input-id="lieberman_use_ssl"]'.
                    format(database_type), context=self)

    def get_verify_ssl_element(self, database_type: str) -> WebElement:
        """
        Get Verify SSL Certificate element

        :param str database_type: Database type eq.DB2 Or Oracle Or MySQL
        :return: verify SSL element for Lieberman in Database
        :rtype: WebElement
        """

        return Find(CheckboxDiv, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="Database"] '
                                                           'div[data-group="{}"] '
                                                           'div[data-input-id="lieberman_verify_ssl"]'.
                    format(database_type), context=self)

    def fill_lieberman_form(self, **kwargs) -> None:
        """
        Method to fill Lieberman form under Database category

        :return: None
        """
        self.get_auth_type_element().select_by_visible_text(kwargs.get('auth_type'))
        database_type = kwargs.get('database_type', '')
        self.get_database_username_element(data_group='Lieberman').send_keys(kwargs.get('username'))
        self.get_cyberark_element(database_type=database_type, data_input_id='lieberman_host').send_keys(
            kwargs.get('host'))
        self.get_cyberark_element(database_type=database_type, data_input_id='lieberman_port').send_keys(
            kwargs.get('port'))
        self.get_lieberman_user(database_type=database_type).send_keys(kwargs.get('user'))
        self.get_cyberark_element(database_type=database_type, data_input_id='lieberman_pam_password').send_keys(
            kwargs.get('password'))
        self.get_cyberark_element(database_type=database_type, data_input_id='lieberman_system_name').send_keys(
            kwargs.get('system_name'))
        self.get_use_ssl_element(database_type=database_type).set_checked(kwargs.get('use_ssl'))
        self.get_verify_ssl_element(database_type=database_type).set_checked(kwargs.get('verify_ssl'))
        self.get_element_for_given_form(db_type=database_type, auth_type="Lieberman",
                                        element_name="Instance name").send_keys(kwargs.get('instance_name'))
        self.get_element_for_given_form(db_type=database_type, auth_type="Lieberman", element_name="Auth type",
                                        element_type="drop_down").select_by_visible_text(kwargs.get('db_auth_type'))

    def get_lieberman_form(self) -> dict:
        """
        Returns form data for Lieberman under Database category

        :return: Dictionary containing form data for Lieberman
        :rtype: dict
        """
        auth_type = self.get_auth_type_element().get_value_selected()
        database_type = self.database_type.text

        return {'username': self.get_database_username_element(auth_type).get_attribute('value'),
                'port': self.get_cyberark_element(database_type, 'lieberman_port').get_attribute('value'),
                'host': self.get_cyberark_element(database_type, 'lieberman_host').get_attribute('value'),
                'user': self.get_lieberman_user(database_type).get_attribute('value'),
                'password': self.get_cyberark_element(database_type, 'lieberman_pam_password').get_attribute('value'),
                'system_name': self.get_cyberark_element(database_type, 'lieberman_system_name').get_attribute('value'),
                'use_ssl': self.get_use_ssl_element(database_type).is_selected(),
                'verify_ssl': self.get_verify_ssl_element(database_type).is_selected(),
                'auth_type': self.get_auth_type_element().get_value_selected()
                }

    def get_sql_server_database_form_values_for_lieberman(self) -> dict:
        """
        returns filled values of sql server form for lieberman
        :return dictionary containing values of sql server form
        :rtype:dict
        """
        return {'database_type': self.database_type.text,
                'db_auth_type': self.get_element_for_given_form(db_type=self.database_type.text,
                                                                auth_type="Lieberman", element_name="Auth type",
                                                                element_type="drop_down").value,
                'instance_name': self.get_element_for_given_form(db_type=self.database_type.text, auth_type="Lieberman",
                                                                 element_name="Instance name").value,
                'port': self.get_database_port("SQL Server").get_attribute('value')}


class MongoDB(Credentials):
    """
    Page Object for MongoDB database
    """
    username = Find(TextField, by=By.CSS_SELECTOR, value='li[class*=opened] input[data-input-id="username"]')
    password = Find(TextField, by=By.CSS_SELECTOR, value='li[class*=opened] input[data-input-id="password"]')
    port = Find(TextField, by=By.CSS_SELECTOR, value='li[class*=opened] input[data-input-id="port"]')
    database = Find(TextField, by=By.CSS_SELECTOR, value='li[class*=opened] input[data-input-id="database"]')

    def __init__(self, **kwargs):
        super().__init__()
        self.click_credentials_type(category_name=API.Credentials.Types.CATEGORY_DATABASE,
                                    credentials_type=kwargs.get('host_type'))

    def fill_monogodb_database_form(self, **kwargs) -> None:
        """
        fill form for mongoDB database
        :return: None
        """
        self.username.value = kwargs.get('username')
        self.password.value = kwargs.get('password')
        self.database.value = kwargs.get('database')
        self.port.value = kwargs.get('port')

    def get_mongodb_form_values(self) -> dict:
        """
        returns filled mongoDB database form values
        :return: dictionary containing MongoDB database form values
        :rtype:dict
        """
        return {'username': self.username.value, 'password': self.password.value, 'database': self.database.value,
                'port': self.port.value}
