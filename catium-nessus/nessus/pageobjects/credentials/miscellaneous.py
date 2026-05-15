""""
Nessus page classes for miscellaneous under credentials tab in new scan page

:copyright: Tenable Network Security, 2018
:date: May 10, 2018
:author: @kpanchal
"""

from selenium.webdriver.common.by import By

from catium.lib.webium import Find
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.controls.toggleswitch import ToggleSwitch
from nessus.lib.const import API
from nessus.pageobjects.credentials.credentials_page import Credentials


class Miscellaneous(Credentials):
    """
    NQA-1166 : Page class for `Miscellaneous` category in Nessus scan credentials.
    """
    username = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"] input[data-name="Username"]')
    password = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"] input[data-name="Password"]')
    port = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"] input[data-name="Port"]')
    http_toggle_button = Find(ToggleSwitch, by=By.CSS_SELECTOR, value='li[class*="opened"] div[data-name="HTTPS"]')
    verify_ssl_cert = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='li[class*="opened"] '
                                                                  'div[data-name="Verify SSL Certificate"]')

    def __init__(self, **kwargs):
        super().__init__()
        self.click_credentials_type(category_name=API.Credentials.Types.CATEGORY_MISCELLANEOUS,
                                    credentials_type=kwargs.get('misc_type'))

    def fill_form(self, *args, **kwargs) -> None:
        """
        Set the value of form with kwargs as a dictionary.
        """
        raise NotImplementedError

    def get_form_values(self) -> dict:
        """
        Returns the value of filled form as a dictionary.
        """
        raise NotImplementedError

    @staticmethod
    def get_misc_inst(misc_id: str) -> object:
        """
        Returns the object of subclass of Miscellaneous.
        :param string misc_id: miscellaneous type as a String.
        :rtype: object
        """
        for _cls in Miscellaneous.__subclasses__():
            if _cls._id == misc_id:
                return _cls(misc_type=_cls.misc_type)
        raise AssertionError("Invalid Subclass")


class ADSICredentialsConfig(Miscellaneous):
    """
    Page class for ADSI credentials under Miscellaneous category in New Scan Creation Page in Nessus.
    """
    domain_controller = Find(TextField, by=By.CSS_SELECTOR,
                             value='li[class*="opened"] input[data-name="Domain Controller"]')
    domain = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"] input[data-name="Domain"]')
    domain_admin = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"] input[data-name="Domain Admin"]')
    domain_pass = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"] input[data-name="Domain Password"]')
    adsi_value = Find(by=By.CSS_SELECTOR, value='.lozenge')

    _id = API.Credentials.Miscellaneous.ADSI
    misc_type = API.Credentials.Miscellaneous.ADSI

    def fill_form(self, **kwargs) -> None:
        """
        Set the details of adsi credentials for Miscellaneous type.
        :param kwargs: Get domain_controller, domain, domain_admin and domain_pass as a kwargs.
        :rtype: none
        """
        self.domain_controller.value = kwargs.get('domain_controller')
        self.domain.value = kwargs.get('domain')
        self.domain_admin.value = kwargs.get('domain_admin')
        self.domain_pass.value = kwargs.get('domain_pass')

    def get_form_values(self) -> dict:
        """
        Returns filled ADSI form data values.
        :rtype: dict
        """
        return {'domain_controller': self.domain_controller.value, 'domain': self.domain.value,
                'domain_admin': self.domain_admin.value, 'domain_pass': self.domain_pass.value}


class F5CredentialsConfig(Miscellaneous):
    """
    Page class for F5 credentials under Miscellaneous category in New Scan Creation Page in Nessus.
    """

    _id = API.Credentials.Miscellaneous.F5
    misc_type = API.Credentials.Miscellaneous.F5

    def fill_form(self, **kwargs) -> None:
        """
        Set the details of F5 credentials for Miscellaneous type.
        :param kwargs: Get user_name, password, port, https and ssl_cert as a kwargs.
        :rtype: none
        """
        self.username.value = kwargs.get('user_name')
        self.password.value = kwargs.get('password')
        self.port.value = kwargs.get('port')
        https = kwargs.get('https')
        ssl = kwargs.get('ssl_cert')

        self.http_toggle_button.set_toggle(https)

        if self.verify_ssl_cert.is_displayed():
            self.verify_ssl_cert.set_checked(ssl)

    def get_form_values(self) -> dict:
        """
        Returns filled F5 form data values.
        :rtype: dict
        """
        adsi_dict = {'user_name': self.username.value, 'port': int(self.port.value), 'password': self.password.value,
                     'https': self.http_toggle_button.is_selected()}

        if self.verify_ssl_cert.is_displayed():
            adsi_dict.update({'ssl_cert': self.verify_ssl_cert.is_selected()})

        return adsi_dict


class IBMCredentialsConfig(Miscellaneous):
    """
    Page class for IBM iSeries credentials under Miscellaneous category in New Scan Creation Page in Nessus.
    """

    _id = API.Credentials.Miscellaneous.IBM_SERIES
    misc_type = API.Credentials.Miscellaneous.IBM_SERIES

    def fill_form(self, **kwargs) -> None:
        """
        Set the details of IBM iSeries credentials for Miscellaneous type.
        :param kwargs: Get user_name and password as a kwargs.
        :rtype: none
        """
        self.username.value = kwargs.get('user_name')
        self.password.value = kwargs.get('password')

    def get_form_values(self) -> dict:
        """
        Returns filled IBM iSeries form data values.
        :rtype: dict
        """
        return {'user_name': self.username.value, 'password': self.password.value}


class OpenStackCredentialsConfig(Miscellaneous):
    """
    Page class for Open Stack credentials under Miscellaneous category in New Scan Creation Page in Nessus.
    """
    tenant_name = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"] '
                                                            'input[data-name="Tenant Name for Authentication"]')

    _id = API.Credentials.Miscellaneous.OPEN_STACK
    misc_type = API.Credentials.Miscellaneous.OPEN_STACK

    def fill_form(self, **kwargs) -> None:
        """
        Set the details of Open Stack credentials for Miscellaneous type.
        :param kwargs: Get user_name, password, tenant_name, port, https and ssl_cert as a kwargs.
        :rtype: none
        """
        self.username.value = kwargs.get('user_name')
        self.password.value = kwargs.get('password')
        self.tenant_name.value = kwargs.get('tenant_name')
        self.port.value = kwargs.get('port')
        https = kwargs.get('https')
        ssl = kwargs.get('ssl_cert')

        self.http_toggle_button.set_toggle(https)

        if self.verify_ssl_cert.is_displayed():
            self.verify_ssl_cert.set_checked(ssl)

    def get_form_values(self) -> dict:
        """
        Returns filled Open Stack form data values.
        :rtype: dict
        """
        open_stack_dict = {'user_name': self.username.value, 'password': self.password.value,
                           'tenant_name': self.tenant_name.value, 'port': int(self.port.value),
                           'https': self.http_toggle_button.is_selected()}

        if self.verify_ssl_cert.is_displayed():
            open_stack_dict.update({'ssl_cert': self.verify_ssl_cert.is_selected()})

        return open_stack_dict


class PaloAltoNetworkCredentialsConfig(Miscellaneous):
    """
    Page class for Palo Alto Network PAN-OS credentials under Miscellaneous category in New Scan Creation Page in Nessus
    """

    _id = API.Credentials.Miscellaneous.PALO_ALTO
    misc_type = API.Credentials.Miscellaneous.PALO_ALTO

    def fill_form(self, **kwargs) -> None:
        """
        Set the details of Palo Alto Network PAN-OS credentials for Miscellaneous type.
        :param kwargs: Get user_name, password, port, https and ssl_cert as a kwargs.
        :rtype: none
        """
        self.username.value = kwargs.get('user_name')
        self.password.value = kwargs.get('password')
        self.port.value = kwargs.get('port')
        https = kwargs.get('https')
        ssl = kwargs.get('ssl_cert')

        self.http_toggle_button.set_toggle(https)

        if self.verify_ssl_cert.is_displayed():
            self.verify_ssl_cert.set_checked(ssl)

    def get_form_values(self) -> dict:
        """
        Returns filled Palo Alto Network PAN-OS form data values.
        :rtype: dict
        """
        palo_alto_dict = {'user_name': self.username.value, 'password': self.password.value,
                          'port': int(self.port.value), 'https': self.http_toggle_button.is_selected()}

        if self.verify_ssl_cert.is_displayed():
            palo_alto_dict.update({'ssl_cert': self.verify_ssl_cert.is_selected()})

        return palo_alto_dict


class RHEVCredentialsConfig(Miscellaneous):
    """
    Page class for RHEV credentials under Miscellaneous category in New Scan Creation Page in Nessus.
    """

    _id = API.Credentials.Miscellaneous.RHEV
    misc_type = API.Credentials.Miscellaneous.RHEV

    def fill_form(self, **kwargs) -> None:
        """
        Set the details of RHEV credentials for Miscellaneous type.
        :param kwargs: Get user_name, password, port and ssl_cert as a kwargs.
        :rtype: none
        """
        self.username.value = kwargs.get('user_name')
        self.password.value = kwargs.get('password')
        self.port.value = kwargs.get('port')
        ssl = kwargs.get('ssl_cert')

        self.verify_ssl_cert.set_checked(ssl)

    def get_form_values(self) -> dict:
        """
        Returns filled RHEV form data values.
        :rtype: dict
        """
        return {'user_name': self.username.value, 'password': self.password.value, 'port': int(self.port.value),
                'ssl_cert': self.verify_ssl_cert.is_selected()}


class VMwareESXCredentialsConfig(Miscellaneous):
    """
    Page class for VMware ESX SOAP API credentials under Miscellaneous category in New Scan Creation Page in Nessus.
    """
    do_not_verify_ssl_cert = Find(CheckboxDiv, by=By.CSS_SELECTOR,
                                  value='li[class*="opened"] div[data-name="Do not verify SSL Certificate"]')

    _id = API.Credentials.Miscellaneous.VMWARE_ESX
    misc_type = API.Credentials.Miscellaneous.VMWARE_ESX

    def fill_form(self, **kwargs) -> None:
        """
        Set the details of VMware ESX SOAP API credentials for Miscellaneous type.
        :param kwargs: Get user_name, password and ssl_cert as a kwargs.
        :rtype: none
        """
        self.username.value = kwargs.get('user_name')
        self.password.value = kwargs.get('password')
        ssl = kwargs.get('ssl_cert')

        self.do_not_verify_ssl_cert.set_checked(ssl)

    def get_form_values(self) -> dict:
        """
        Returns filled VMware ESX SOAP API form data values.
        :rtype: dict
        """
        return {'user_name': self.username.value, 'password': self.password.value,
                'ssl_cert': self.do_not_verify_ssl_cert.is_selected()}


class VMwarevCenterCredentialsConfig(Miscellaneous):
    """
    Page class for VMware vCenter SOAP API credentials under Miscellaneous category in New Scan Creation Page in Nessus.
    """
    vcenter_host = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"] input[data-name="vCenter Host"]')
    vcenter_port = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"] input[data-name="vCenter Port"]')

    _id = API.Credentials.Miscellaneous.VMWARE_VCENTER
    misc_type = API.Credentials.Miscellaneous.VMWARE_VCENTER

    def fill_form(self, **kwargs) -> None:
        """
        Set the details of VMware vCenter SOAP API credentials for Miscellaneous type.
        :param kwargs: Get vcenter_host, vcenter_port, user_name, password, https and ssl_cert as a kwargs.
        :rtype: none
        """
        self.vcenter_host.value = kwargs.get('vcenter_host')
        self.vcenter_port.value = kwargs.get('vcenter_port')
        self.username.value = kwargs.get('user_name')
        self.password.value = kwargs.get('password')
        https = kwargs.get('https')
        ssl = kwargs.get('ssl_cert')

        self.http_toggle_button.set_toggle(https)

        if self.verify_ssl_cert.is_displayed():
            self.verify_ssl_cert.set_checked(ssl)

    def get_form_values(self) -> dict:
        """
        Returns filled VMware vCenter SOAP API form data values.
        :rtype: dict
        """
        vmware_vcenter_dict = {'vcenter_host': self.vcenter_host.value, 'vcenter_port': int(self.vcenter_port.value),
                               'user_name': self.username.value, 'password': self.password.value,
                               'https': self.http_toggle_button.is_selected()}

        if self.verify_ssl_cert.is_displayed():
            vmware_vcenter_dict.update({'ssl_cert': self.verify_ssl_cert.is_selected()})

        return vmware_vcenter_dict


class X509CredentialsConfig(Miscellaneous):
    """
    Page class for X.509 credentials under Miscellaneous category in New Scan Creation Page in Nessus.
    """
    client_cert = Find(by=By.CSS_SELECTOR, value='li[class*="opened"] input[data-name="Client certificate"]')
    client_key = Find(by=By.CSS_SELECTOR, value='li[class*="opened"] input[data-name="Client key"]')
    pass_for_key = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"] input[data-name="Password for key"]')
    ca_cert_to_trust = Find(by=By.CSS_SELECTOR, value='li[class*="opened"] input[data-name="CA certificate to trust"]')

    _id = API.Credentials.Miscellaneous.X509
    misc_type = API.Credentials.Miscellaneous.X509

    def fill_form(self, **kwargs) -> None:
        """
        Set the details of X.509 credentials for Miscellaneous type.
        :param kwargs: Get client_cert, client_key, pass_key and ca_cert_path as a kwargs.
        :rtype: none
        """
        self.client_cert.send_keys(kwargs.get('client_cert'))
        self.client_key.send_keys(kwargs.get('client_key'))
        self.pass_for_key.value = kwargs.get('pass_key')
        self.ca_cert_to_trust.send_keys(kwargs.get('ca_cert_path'))
