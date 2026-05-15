"""
Nessus page classes for Compliance tab under Advanced Scan for Scans/Policies
:copyright: Tenable Network Security, 2017
:date: June 04, 2018
:last_modified: March 29, 2024
:author: @mameta, @kpanchal, @krpatel
"""
from selenium.webdriver.common.by import By

from catium.lib.webium import Find
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.controls.upload_field import UploadField
from nessus.lib.const.compliance_constants import ComplianceConst
from nessus.pageobjects.compliances.compliance_page import Compliance


class UploadACustomAdtranAOSAuditFile(Compliance):
    """ page object for Upload a custom Adtran AOS audit file compliance under Adtran AOS compliance """
    audit_file = Find(UploadField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Adtran AOS"] '
                                                             'input[data-name="Audit file"]')
    config_file = Find(UploadField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Adtran AOS"] '
                                                              'input[data-name*="config file(s)"]')
    _compliance_type = "Upload a custom Adtran AOS audit file"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.ADTRAN_AOS,
                                   compliance_type=self._compliance_type)


class TNSAlcatelTiMOSBestPracticeAudit(Compliance):
    """Page object for TNS Alcatel-Lucent TiMOS/Nokia SR-OS Best Practice Audit
            compliance under Alcatel TiMOS compliance """
    login_prompt_text = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Alcatel TiMOS"] '
                                                                  'input[data-name="Login prompt text"]')
    primary_rsyslog_server = Find(TextField, by=By.CSS_SELECTOR,
                                  value='li[class*="opened"][data-parent="Alcatel TiMOS"] '
                                        'input[data-name="Primary rsyslog server"]')
    sros_log_target_index = Find(TextField, by=By.CSS_SELECTOR,
                                 value='li[class*="opened"][data-parent="Alcatel TiMOS"] '
                                       'input[data-name="SROS Log Target Index"]')
    primary_remote_authentication_server = Find(TextField, by=By.CSS_SELECTOR,
                                                value='li[class*="opened"][data-parent="Alcatel TiMOS"] '
                                                      'input[data-name="Primary remote authentication server"]')
    secondary_remote_authentication_server = Find(TextField, by=By.CSS_SELECTOR,
                                                  value='li[class*="opened"][data-parent="Alcatel TiMOS"] '
                                                        'input[data-name="Secondary remote authentication server"]')
    primary_ntp_server = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Alcatel TiMOS"] '
                                                                   'input[data-name="Primary NTP server"]')
    secondary_ntp_server = Find(TextField, by=By.CSS_SELECTOR,
                                value='li[class*="opened"][data-parent="Alcatel TiMOS"] '
                                      'input[data-name="Secondary NTP server"]')
    primary_dns_server = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Alcatel TiMOS"] '
                                                                   'input[data-name="Primary DNS server"]')
    secondary_dns_server = Find(TextField, by=By.CSS_SELECTOR,
                                value='li[class*="opened"][data-parent="Alcatel TiMOS"] '
                                      'input[data-name="Secondary DNS server"]')
    # file upload
    config_file = Find(UploadField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Alcatel TiMOS"] '
                                                              'input[data-name*="config file(s)"]')

    _compliance_type = "TNS Alcatel-Lucent TiMOS/Nokia SR-OS Best Practice Audit"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.ALCATEL_TIMOS,
                                   compliance_type=self._compliance_type)


class CISAmazonWebServicesFoundationsL1(Compliance):
    """Page object for CIS Amazon Web Services Foundations L1 compliance under Amazon AWS compliance """
    days_without_account_activity = Find(TextField, by=By.CSS_SELECTOR,
                                         value='li[class*="opened"][data-parent="Amazon AWS"] '
                                               'input[data-name="Days without Account activity"]')

    _compliance_type = "CIS Amazon Web Services Foundations v5.0.0 L1"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.AMAZON_AWS,
                                   compliance_type=self._compliance_type)


class TenableAWSBestPracticeAudit(Compliance):
    """Page object for Tenable AWS Best Practice Audit  compliance under Amazon AWS compliance"""
    days_without_account_activity = Find(TextField, by=By.CSS_SELECTOR,
                                         value='li[class*="opened"][data-parent="Amazon AWS"] '
                                               'input[data-name="Days without Account activity"]')

    _compliance_type = "Tenable AWS Best Practice Audit"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.AMAZON_AWS,
                                   compliance_type=self._compliance_type)


class DISASTIGAristaSeriesNDM(Compliance):
    """Page object for DISA STIG Arista MLS DCS-7000 Series NDM V1R2 compliance under Arista EOS compliance"""
    ntp_server_one = Find(TextField, by=By.CSS_SELECTOR,
                          value='li[class*="opened"][data-parent="Arista EOS"] input[data-name="NTP Server 1"]')
    ntp_server_two = Find(TextField, by=By.CSS_SELECTOR,
                          value='li[class*="opened"][data-parent="Arista EOS"] input[data-name="NTP Server 2"]')
    banner_login = Find(TextField, by=By.CSS_SELECTOR,
                        value='li[class*="opened"][data-parent="Arista EOS"] input[data-name="Banner login"]')
    # file upload
    config_file = Find(UploadField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Arista EOS"] '
                                                              'input[data-name*="config file(s)"]')
    _compliance_type = "DISA STIG Arista MLS DCS-7000 Series NDM V1R2"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.ARISTA_EOS,
                                   compliance_type=self._compliance_type)


class DISASTIGAristaSeriesL2S(Compliance):
    """Page object for DISA STIG Arista MLS DCS-7000 Series L2S v1r3 under Arista EOS compliance"""
    # file upload
    config_file = Find(UploadField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Arista EOS"] '
                                                              'input[data-name*="config file(s)"]')
    _compliance_type = "DISA STIG Arista MLS DCS-7000 Series L2S v1r3"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.ARISTA_EOS,
                                   compliance_type=self._compliance_type)


class TNSBlueCoatProxySGBenchmark(Compliance):
    """Page object for TNS BlueCoat ProxySG Benchmark compliance under BlueCoat ProxySG compliance """
    primary_gateway = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="BlueCoat ProxySG"] '
                                                                'input[data-name="Primary Gateway"]')
    primary_dns_server = Find(TextField, by=By.CSS_SELECTOR,
                              value='li[class*="opened"][data-parent="BlueCoat ProxySG"] '
                                    'input[data-name="Primary DNS Server"]')
    alternate_dns_server = Find(TextField, by=By.CSS_SELECTOR,
                                value='li[class*="opened"][data-parent="BlueCoat ProxySG"] '
                                      'input[data-name="Alternate DNS Server"]')
    adn_primary_manager = Find(TextField, by=By.CSS_SELECTOR,
                               value='li[class*="opened"][data-parent="BlueCoat ProxySG"] '
                                     'input[data-name="ADN Primary Manager"]')
    syslog_server = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="BlueCoat ProxySG"] '
                                                              'input[data-name="Syslog Server"]')
    internal_networks = Find(TextField, by=By.CSS_SELECTOR,
                             value='li[class*="opened"][data-parent="BlueCoat ProxySG"] '
                                   'input[data-name="Internal Networks')
    snmp_community = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="BlueCoat ProxySG"] '
                                                               'input[data-name="SNMP Community"]')
    # file upload
    config_file = Find(UploadField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="BlueCoat ProxySG"] '
                                                              'input[data-name*="config file(s)"]')
    _compliance_type = "TNS BlueCoat ProxySG Benchmark"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.BLUECOAT_PROXYSG,
                                   compliance_type=self._compliance_type)


class TNSBrocadeFabricOSBestPractices(Compliance):
    """Page object for Tenable Best Practices Brocade FabricOS compliance under Brocade FabricOS compliance"""
    syslog_server_ip = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Brocade FabricOS"] '
                                                                 'input[data-name="SYSLOG server IP"]')
    ntp_server_ip = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Brocade FabricOS"] '
                                                              'input[data-name="NTP server IP"]')
    scp_server_ip = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Brocade FabricOS"] '
                                                              'input[data-name="SCP server IP"]')
    snmpv3_trap_target = Find(TextField, by=By.CSS_SELECTOR,
                              value='li[class*="opened"][data-parent="Brocade FabricOS"] '
                                    'input[data-name="SNMPv3 trap target"]')
    # file upload
    config_file = Find(UploadField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Brocade FabricOS"] '
                                                              'input[data-name*="Fabric OS config file(s)"]')
    _compliance_type = "Tenable Best Practices Brocade FabricOS"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.BROCADE_FABRICOS,
                                   compliance_type=self._compliance_type)


class CisCiscoFirewallAsa8(Compliance):
    """Page object for CIS Cisco Firewall v8.x L1 v4.2.0 compliance under Cisco IOS compliance category"""
    aaa_login_group = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Cisco IOS"] '
                                                                'input[data-name="AAA Login Group"]')
    https_admin_address = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Cisco IOS"] '
                                                                    'input[data-name="HTTPS Admin Address"]')
    https_admin_interface = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Cisco IOS"] '
                                                                      'input[data-name="HTTPS Admin Interface"]')
    ssh_admin_address = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Cisco IOS"] '
                                                                  'input[data-name="SSH Admin Address"]')
    ssh_admin_interface = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Cisco IOS"] '
                                                                    'input[data-name="SSH Admin Interface"]')
    syslog_serve_address = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Cisco IOS"] '
                                                                     'input[data-name="Syslog server address"]')
    ntp_server = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Cisco IOS"] '
                                                           'input[data-name="NTP Server"]')

    # dropdown
    config_to_audit = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Cisco IOS"] '
                                                                      'select[data-input-id="cisco_config_to_audit"]')

    # file upload
    config_file = Find(UploadField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Cisco IOS"] '
                                                              'input[data-name="IOS config file(s)"]')
    _compliance_type = "CIS Cisco Firewall v8.x L1 v4.2.0"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.CISCO_IOS,
                                   compliance_type=self._compliance_type)


class CISMySqlL2(Compliance):
    """Page object for CIS MySQL 5.6 Enterprise Database L2 v2.0.0 compliance under Database compliance category"""
    mysql_admin_user = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Database"] '
                                                                 'input[data-name="MySQL Admin User"]')

    _compliance_type = "CIS MySQL 5.6 Enterprise Database L2 v2.0.0"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.DATABASE,
                                   compliance_type=self._compliance_type)

# TODO: Fix releated test cases and then remove following class
# class TNSDellForce10(Compliance):
#     """Page object for TNS Dell Force10 Best Practice Audit compliance under Dell Force10 FTOS compliance category"""
#     logging_server = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Dell Force10 FTOS"] '
#                                                                'input[data-name="Logging Server"]')
#     snmp_host = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Dell Force10 FTOS"] '
#                                                           'input[data-name="SNMP Host"]')
#     ntp_server = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Dell Force10 FTOS"] '
#                                                            'input[data-name="NTP Server"]')
#     motd_banner = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Dell Force10 FTOS"] '
#                                                             'input[data-name="MOTD Banner"]')
#     exec_banner = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Dell Force10 FTOS"] '
#                                                             'input[data-name="EXEC Banner"]')
#     login_banner = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Dell Force10 FTOS"] '
#                                                              'input[data-name="Login Banner"]')
# 
#     # file upload
#     config_file = Find(UploadField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Dell Force10 FTOS"] '
#                                                               'input[data-name="FTOS config file(s)"]')
#     _compliance_type = "TNS Dell Force10 Best Practice Audit"
# 
#     def __init__(self):
#         super().__init__()
#         self.click_compliance_type(category_name=ComplianceConst.DELL_FORCE10_FTOS,
#                                    compliance_type=self._compliance_type)


class TNSExtremeExtremeXOS(Compliance):
    """Page object for TNS Extreme ExtremeXOS Best Practice Audit compliance under
    Extreme ExtremeXOS compliance category"""
    snmp_host = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Extreme ExtremeXOS"] '
                                                          'input[data-name="SNMP Host"]')
    logging_server = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Extreme ExtremeXOS"] '
                                                               'input[data-name="Logging Server"]')

    # file upload
    config_file = Find(UploadField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Extreme ExtremeXOS"] '
                                                              'input[data-name="ExtremeOS config file(s)"]')
    _compliance_type = "TNS Extreme ExtremeXOS Best Practice Audit"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.EXTREME_EXTREMEXOS,
                                   compliance_type=self._compliance_type)


class DISAF5LocalTrafficManager(Compliance):
    """Page object for DISA F5 BIG-IP Local Traffic Manager STIG v2r4 compliance under F5 compliance category"""
    virtual_server_connection_limit = Find(TextField, by=By.CSS_SELECTOR,
                                           value='li[class*="opened"][data-parent="F5"] '
                                                 'input[data-name="Virtual Server Connection Limit"]')
    virtual_server_connection_rate_limit = Find(TextField, by=By.CSS_SELECTOR,
                                                value='li[class*="opened"][data-parent="F5"] '
                                                      'input[data-name="Virtual Server Connection Rate Limit"]')
    _compliance_type = "DISA F5 BIG-IP Local Traffic Manager STIG v2r4"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.F_FIVE,
                                   compliance_type=self._compliance_type)


class TNSFireEye(Compliance):
    """Page object for TNS FireEye compliance under FireEye compliance Category"""
    dns_server_ip_address = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="FireEye"] '
                                                                      'input[data-name="DNS server IP address"]')
    configuration_changes_audited = Find(TextField, by=By.CSS_SELECTOR,
                                         value='li[class*="opened"][data-parent="FireEye"] '
                                               'input[data-name="Configuration changes audited"]')

    # file upload
    config_file = Find(UploadField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="FireEye"] '
                                                              'input[data-name="FireEye config file(s)"]')
    _compliance_type = "TNS FireEye"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.FIREEYE,
                                   compliance_type=self._compliance_type)


class TNSFortigateFortiOS(Compliance):
    """Page object for TNS Fortigate FortiOS Best Practices compliance under Fortigate FortiOS compliance Category"""

    # file upload
    config_file = Find(UploadField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Fortigate FortiOS"] '
                                                              'input[data-name="Fortigate FortiOS config file(s)"]')
    _compliance_type = "TNS Fortigate FortiOS Best Practices"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.FORTIGATE_FORTIOS,
                                   compliance_type=self._compliance_type)


class TNSHPProCurveBestPractices(Compliance):
    """Page object for TNS HP ProCurve compliance under HP ProCurve compliance """

    # text boxes
    management_network = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="HP ProCurve"] '
                                                                   'input[data-input-id="MANAGEMENT_NETWORK"]')
    management_network_access = Find(TextField, by=By.CSS_SELECTOR,
                                     value='li[class*="opened"][data-parent="HP ProCurve"] '
                                           'input[data-input-id="MANAGEMENT_NETWORK_ACCESS"]')
    radius_auth_interfaces = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="HP ProCurve"] '
                                                                       'input[data-input-id="RADIUS_AUTH_INTERFACES"]')
    radius_auth_level = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="HP ProCurve"] '
                                                                  'input[data-input-id="RADIUS_AUTH_LEVEL"]')
    tacacs_auth_interfaces = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="HP ProCurve"] '
                                                                       'input[data-input-id="TACACS_AUTH_INTERFACES"]')
    tacacs_auth_level = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="HP ProCurve"] '
                                                                  'input[data-input-id="TACACS_AUTH_LEVEL"]')
    aaa_auth_attempts = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="HP ProCurve"] '
                                                                  'input[data-input-id="AAA_AUTH_ATTEMPTS"]')
    # dropdown
    config_to_audit = Find(Select2Dropdown, by=By.CSS_SELECTOR,
                           value='li[class*="opened"][data-parent="HP ProCurve"] '
                                 'select[data-input-id="procurve_config_to_audit"]')
    # file upload
    config_file = Find(UploadField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="HP ProCurve"] '
                                                              'input[data-name="ProCurve config file(s)"]')
    _compliance_type = "TNS HP ProCurve"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.HP_PROCURVE,
                                   compliance_type=self._compliance_type)


class TNSHuaweiVRP(Compliance):
    """Page object for TNS Huawei VRP Best Practice Audit compliance under Huawei VRP compliance category"""
    first_line_of_text_in_login_header = Find(TextField, by=By.CSS_SELECTOR,
                                              value='li[class*="opened"][data-parent="Huawei VRP"] '
                                                    'input[data-name="First line of text in login header"]')
    first_line_of_text_in_shell_header = Find(TextField, by=By.CSS_SELECTOR,
                                              value='li[class*="opened"][data-parent="Huawei VRP"] '
                                                    'input[data-name="First line of text in shell header"]')
    ip_address_of_ntp_server = Find(TextField, by=By.CSS_SELECTOR,
                                    value='li[class*="opened"][data-parent="Huawei VRP"] '
                                          'input[data-name="IP address of NTP server."]')
    ip_address_of_syslog_server = Find(TextField, by=By.CSS_SELECTOR,
                                       value='li[class*="opened"][data-parent="Huawei VRP"] '
                                             'input[data-name="IP address of syslog server."]')
    snmp_trap_host_ip = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Huawei VRP"] '
                                                                  'input[data-name="SNMP trap host ip."]')
    snmp_v3_group_name = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Huawei VRP"] '
                                                                   'input[data-name="SNMP V3 group name"]')

    # file upload
    config_file = Find(UploadField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Huawei VRP"] '
                                                              'input[data-name="Huawei VRP config file(s)"]')
    _compliance_type = "TNS Huawei VRP Best Practice Audit"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.HUAWEI_VRP,
                                   compliance_type=self._compliance_type)


class IBMSystemSecurityReferenceforV7R2(Compliance):
    """Page object for IBM System i Security Reference for V7R2 compliance under IBM iSeries compliance category"""
    use_adopted_authority = Find(TextField, by=By.CSS_SELECTOR,
                                 value='li[class*="opened"][data-parent="IBM iSeries"] '
                                       'input[data-name="Use Adopted Authority (QUSEADPAUT)"]')
    ssl_cipher_spec_list = Find(TextField, by=By.CSS_SELECTOR,
                                value='li[class*="opened"][data-parent="IBM iSeries"] '
                                      'input[data-name="SSL Cipher spec list"]')
    _compliance_type = "IBM System i Security Reference for V7R2"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.IBM_ISERIES,
                                   compliance_type=self._compliance_type)


class CISJuniperJunosBenchmarkL1(Compliance):
    """Page object for CIS Juniper Junos Benchmark v1.0.1 L1 compliance under Juniper JUNOS compliance category"""
    untrusted_interface = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Juniper Junos"] '
                                                                    'input[data-name="Untrusted IPv4 interface"]')
    login_message_text = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Juniper Junos"] '
                                                                   'input[data-name="Login message text"]')

    # file upload
    config_file = Find(UploadField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Juniper Junos"] '
                                                              'input[data-name="Junos config file(s)"]')
    _compliance_type = "CIS Juniper OS Benchmark v2.1.0 L1"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.JUNIPER_JUNOS,
                                   compliance_type=self._compliance_type)


class CISMicrosoftAzureFoundations(Compliance):
    """Page object for CIS Microsoft 365 Foundations v5.0.0 L2 E5 compliance under Microsoft Azure compliance"""

    anti_phishing_policy = Find(TextField, by=By.CSS_SELECTOR,
                                value='li[class*="opened"][data-parent="Microsoft Azure"] '
                                      'input[data-name="Anti-Phishing Policy Name"]')
    sharepoint_domain = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Microsoft Azure"] '
                                                                  'input[data-name="SharePoint Allowed Domain List"]')
    _compliance_type = "CIS Microsoft 365 Foundations v5.0.0 L2 E5"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.MICROSOFT_AZURE,
                                   compliance_type=self._compliance_type)


class AppleProfileManagerTNS(Compliance):
    """ Page object for Apple Profile Manager - TNS Best Practices Audit v1.1.0 compliance under
    Mobile Device Manager compliance category"""

    device_application_whitelist = Find(TextField, by=By.CSS_SELECTOR,
                                        value='li[class*="opened"][data-parent="Mobile Device Manager"] '
                                              'input[data-name="Device Application Whitelist"]')
    device_application_blacklist = Find(TextField, by=By.CSS_SELECTOR,
                                        value='li[class*="opened"][data-parent="Mobile Device Manager"] '
                                              'input[data-name="Device Application Blacklist"]')

    _compliance_type = "MobileIron - DISA Samsung Android 7 with Knox 2.x v1r1"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.MOBILE_DEVICE_MANAGER,
                                   compliance_type=self._compliance_type)


class TNSNetAppDataONTAP(Compliance):
    """ Page object for TNS NetApp Data ONTAP 7G compliance under NetApp Data ONTAP compliance category"""
    ssh_allowed_network = Find(TextField, by=By.CSS_SELECTOR,
                               value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                     'input[data-name="SSH allowed network"]')
    audit_log_max_size = Find(TextField, by=By.CSS_SELECTOR,
                              value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                    'input[data-name="Audit log max size"]')
    interfaces_blocking_cifs = Find(TextField, by=By.CSS_SELECTOR,
                                    value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                          'input[data-name="Interfaces blocking CIFS"]')
    interfaces_blocking_ftp = Find(TextField, by=By.CSS_SELECTOR,
                                   value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                         'input[data-name="Interfaces blocking FTP"]')
    interfaces_blocking_iscsi = Find(TextField, by=By.CSS_SELECTOR,
                                     value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                           'input[data-name="Interfaces blocking ISCSI"]')
    interfaces_blocking_nfs = Find(TextField, by=By.CSS_SELECTOR,
                                   value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                         'input[data-name="Interfaces blocking NFS"]')
    interfaces_blocking_snapmirror = Find(TextField, by=By.CSS_SELECTOR,
                                          value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                                'input[data-name="Interfaces blocking SnapMirror"]')
    interfaces_blocking_ndmp = Find(TextField, by=By.CSS_SELECTOR,
                                    value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                          'input[data-name="Interfaces blocking NDMP"]')
    rsh_allowed_network = Find(TextField, by=By.CSS_SELECTOR,
                               value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                     'input[data-name="RSH allowed network"]')
    telnet_allowed_network = Find(TextField, by=By.CSS_SELECTOR,
                                  value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                        'input[data-name="Telnet allowed network"]')
    snmp_allowed_network = Find(TextField, by=By.CSS_SELECTOR,
                                value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                      'input[data-name="SNMP allowed network"]')
    http_allowed_network = Find(TextField, by=By.CSS_SELECTOR,
                                value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                      'input[data-name="HTTP allowed network"]')
    snapmirror_allowed_network = Find(TextField, by=By.CSS_SELECTOR,
                                      value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                            'input[data-name="SnapMirror allowed network"]')
    snapmirror_incoming_repl_limit = Find(TextField, by=By.CSS_SELECTOR,
                                          value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                                'input[data-name="SnapMirror incoming repl limit"]')
    snapmirror_outgoing_repl_limit = Find(TextField, by=By.CSS_SELECTOR,
                                          value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                                'input[data-name="SnapMirror outgoing repl limit"]')
    snapvault_allowed_network = Find(TextField, by=By.CSS_SELECTOR,
                                     value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                           'input[data-name="SnapVault allowed network"]')
    snapvault_dr_backup_snapshot = Find(TextField, by=By.CSS_SELECTOR,
                                        value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                              'input[data-name="SnapVault DR backup snapshot"]')
    dns_domain_name = Find(TextField, by=By.CSS_SELECTOR,
                           value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                 'input[data-name="DNS domain name"]')
    ntp_servers = Find(TextField, by=By.CSS_SELECTOR,
                       value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                             'input[data-name="NTP servers"]')
    cifs_log_autosave_size = Find(TextField, by=By.CSS_SELECTOR,
                                  value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                        'input[data-name="CIFS log autosave size"]')
    cifs_log_autosave_interval = Find(TextField, by=By.CSS_SELECTOR,
                                      value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                            'input[data-name="CIFS log autosave interval"]')
    cifs_log_extension = Find(TextField, by=By.CSS_SELECTOR,
                              value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                    'input[data-name="CIFS log extension"]')
    cifs_max_simultaneous_logs = Find(TextField, by=By.CSS_SELECTOR,
                                      value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                            'input[data-name="CIFS max simultaneous logs"]')
    cifs_handle_timeout = Find(TextField, by=By.CSS_SELECTOR,
                               value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                     'input[data-name="CIFS handle timeout"]')
    nfs_domain_name = Find(TextField, by=By.CSS_SELECTOR,
                           value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                 'input[data-name="NFS domain name"]')
    nfs_principal_kerberos_server = Find(TextField, by=By.CSS_SELECTOR,
                                         value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                               'input[data-name="NFS principal Kerberos server"]')
    nfs_kerberos_realm = Find(TextField, by=By.CSS_SELECTOR,
                              value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                    'input[data-name="NFS Kerberos realm"]')
    nfs_simultaneous_security_contexts = Find(TextField, by=By.CSS_SELECTOR,
                                              value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                                    'input[data-name="NFS simultaneous security contexts"]')
    nfs_idle_context_timeout = Find(TextField, by=By.CSS_SELECTOR,
                                    value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                          'input[data-name="NFS idle context timeout"]')
    nfs_default_security_style = Find(TextField, by=By.CSS_SELECTOR,
                                      value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                            'input[data-name="NFS default security style"]')
    nfs_default_unix_user = Find(TextField, by=By.CSS_SELECTOR,
                                 value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                       'input[data-name="NFS default unix user"]')
    nfs_default_windows_user = Find(TextField, by=By.CSS_SELECTOR,
                                    value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                          'input[data-name="NFS default Windows user"]')
    nfs_user_mapping_expiration = Find(TextField, by=By.CSS_SELECTOR,
                                       value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                             'input[data-name="NFS user mapping expiration"]')

    # file upload
    config_file = Find(UploadField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="NetApp Data ONTAP"] '
                                                              'input[data-name="Data ONTAP config file(s)"]')
    _compliance_type = "TNS NetApp Data ONTAP 7G"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.NETAPP_DATA_ONTAP,
                                   compliance_type=self._compliance_type)


class TNSBestPracticeOpenStack(Compliance):
    """ Page object for Tenable Best Practices OpenStack v2.0.0 compliance under Openstack compliance category"""
    server_owner_user_id = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="OpenStack"] '
                                                                      'input[data-name="Server Owner User ID"]')
    the_last_nessus_scan = Find(TextField, by=By.CSS_SELECTOR,
                                value='li[class*="opened"][data-parent="OpenStack"] '
                                      'input[data-name="Days Since the last Nessus Scan"]')
    _compliance_type = "Tenable Best Practices OpenStack v2.0.0"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.OPENSTACK,
                                   compliance_type=self._compliance_type)


class CISPaloAltoFirewallBenchmarkL1(Compliance):
    """ Page object for CIS Palo Alto Firewall 7 Benchmark L1 v1.0.0 compliance under
    Palo Alto Networks PAN-OS compliance category"""
    authentication_profile_failed_attempts = Find(TextField, by=By.CSS_SELECTOR,
                                                  value='li[class*="opened"][data-parent="Palo Alto Networks PAN-OS"] '
                                                        'input[data-name="Authentication Profile Failed Attempts"]')
    authentication_profile_lockout_time = Find(TextField, by=By.CSS_SELECTOR,
                                               value='li[class*="opened"][data-parent="Palo Alto Networks PAN-OS"] '
                                                     'input[data-name="Authentication Profile Lockout Time"]')
    tcp_syn_cookies_alert_rate = Find(TextField, by=By.CSS_SELECTOR,
                                      value='li[class*="opened"][data-parent="Palo Alto Networks PAN-OS"] '
                                            'input[data-name="TCP SYN Cookies Alert Rate"]')
    tcp_syn_cookies_activate_rate = Find(TextField, by=By.CSS_SELECTOR,
                                         value='li[class*="opened"][data-parent="Palo Alto Networks PAN-OS"] '
                                               'input[data-name="TCP SYN Cookies Activate Rate"]')
    tcp_syn_cookies_maximal_rate = Find(TextField, by=By.CSS_SELECTOR,
                                        value='li[class*="opened"][data-parent="Palo Alto Networks PAN-OS"] '
                                              'input[data-name="TCP SYN Cookies Maximal Rate"]')
    _compliance_type = "CIS Palo Alto Firewall 7 Benchmark L1 v1.0.0"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.PALO_ALTO_NETWORKS_PAN_OS,
                                   compliance_type=self._compliance_type)


class TNSBestPracticeRackSpace(Compliance):
    """ Page object for Tenable Best Practices RackSpace v2.0.0 compliance under Rackspace compliance category"""
    # server_owner_user_id = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Rackspace"] '
                                                                      # 'input[data-name="Server Owner Username"]')
    # lb_algorithm = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Rackspace"] '
                                                             # 'input[data-name="LB Algorithm"]')
    role_name_for_user_list = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Rackspace"] '
                                                                        'input[data-name="Role Name for User List"]')
    days_since_the_last_nessus_scan = Find(TextField, by=By.CSS_SELECTOR,
                                           value='li[class*="opened"][data-parent="Rackspace"] '
                                                 'input[data-name="Days since the last Nessus scan"]')
    max_user_connections = Find(TextField, by=By.CSS_SELECTOR,
                                value='li[class*="opened"][data-parent="Rackspace"] '
                                      'input[data-name="DBC Var - max_user_connections"]')
    max_connections = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Rackspace"] '
                                                                'input[data-name="DBC Var - max_connections"]')
    max_allowed_packet = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Rackspace"] '
                                                                   'input[data-name="DBC Var - max_allowed_packet"]')
    max_connect_errors = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Rackspace"] '
                                                                   'input[data-name="DBC Var - max_connect_errors"]')
    wait_timeout = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Rackspace"] '
                                                             'input[data-name="DBC Var - wait_timeout"]')
    sql_mode = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Rackspace"] '
                                                         'input[data-name="DBC Var - sql_mode"]')
    _compliance_type = "Tenable Best Practices RackSpace v2.0.0"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.RACKSPACE,
                                   compliance_type=self._compliance_type)


class TNSSalesforceBestPracticesAudit(Compliance):
    """ Page object for TNS Salesforce Best Practices Audit v1.2.0 compliance under
        Salesforce.com compliance category"""
    start_ip = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Salesforce.com"] '
                                                         'input[data-name="Start IP"]')
    end_ip = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Salesforce.com"] '
                                                       'input[data-name="End IP"]')
    dm_ipad = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Salesforce.com"] '
                                                        'input[data-name="DM iPad"]')
    nessus_scan_interval = Find(TextField, by=By.CSS_SELECTOR,
                                value='li[class*="opened"][data-parent="Salesforce.com"] '
                                      'input[data-name="Nessus Scan Interval"]')
    known_administrators = Find(TextField, by=By.CSS_SELECTOR,
                                value='li[class*="opened"][data-parent="Salesforce.com"] '
                                      'input[data-name="Known Administrators"]')
    pw_change_interval = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Salesforce.com"] '
                                                                   'input[data-name="PW Change Interval"]')
    _compliance_type = "TNS Salesforce Best Practices Audit v1.2.0"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.SALESFORCE_COM,
                                   compliance_type=self._compliance_type)


class TnsSonicWALL(Compliance):
    """ Page object for TNS SonicWALL v5.9 compliance under SonicWALL SonicOS compliance category"""

    # file upload
    config_file = Find(UploadField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="SonicWALL SonicOS"] '
                                                              'input[data-name="SonicOS config file(s)"]')
    _compliance_type = "TNS SonicWALL v5.9"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.SONICWALL_SONICOS,
                                   compliance_type=self._compliance_type)


class CisAixL1(Compliance):
    """ Page object for CIS AIX 5.3/6.1 L1 v1.1.0 compliance under UNIX Category """
    cde_login_greeting_one = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Unix"] '
                                                                       'input[data-name="CDE Login Greeting 1"]')
    cde_login_greeting_two = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Unix"] '
                                                                       'input[data-name="CDE Login Greeting 2"]')
    hosts_allow_entry = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Unix"] '
                                                                  'input[data-name="hosts.allow Entry"]')
    banner = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Unix"] '
                                                       'input[data-name="Banner Text"]')
    var_adm_cron_at_allow_user = Find(TextField, by=By.CSS_SELECTOR,
                                      value='li[class*="opened"][data-parent="Unix"] '
                                            'input[data-name="/var/adm/cron/at.allow User"]')
    var_adm_cron_cron_allow_user = Find(TextField, by=By.CSS_SELECTOR,
                                        value='li[class*="opened"][data-parent="Unix"] '
                                              'input[data-name="/var/adm/cron/cron.allow User"]')
    _compliance_type = "CIS AIX 5.3/6.1 L1 v1.1.0"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.UNIX,
                                   compliance_type=self._compliance_type)


class TNSFileAnalysisAdultMediaContent(Compliance):
    """ Page object for TNS File Analysis - Adult Media Content compliance under
    UNIX  File Contents compliance Category"""
    include_devices_mounted_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR,
                                            value='li[class*="opened"][data-parent="Unix File Contents"] '
                                                  'div[data-name="Include devices mounted in sub-directories of '
                                                  'scan path (not recommended)"]')
    include_path = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Unix File Contents"] '
                                                             'input[data-name="Include path(s)"]')
    exclude_path = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Unix File Contents"] '
                                                             'input[data-name="Exclude path(s)"]')
    file_extension = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Unix File Contents"] '
                                                               'input[data-name="File extension(s)"]')
    max_size_per_file = Find(TextField, by=By.CSS_SELECTOR,
                             value='li[class*="opened"][data-parent="Unix File Contents"] '
                                   'input[data-name="Max size per file"]')
    max_cumulative_size = Find(TextField, by=By.CSS_SELECTOR,
                               value='li[class*="opened"][data-parent="Unix File Contents"] '
                                     'input[data-name="Max cumulative size"]')
    max_depth = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Unix File Contents"] '
                                                          'input[data-name="Max depth"]')

    _compliance_type = "TNS File Analysis - Adult Media Content"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.UNIX_FILE_CONTENTS,
                                   compliance_type=self._compliance_type)


class CisVmwareESXi(Compliance):
    """ Page object for CIS VMware ESXi 5.1 v1.0.1 Level 1 compliance under VMware vCenter/vSphere compliance """
    ntp_server_address = Find(TextField, by=By.CSS_SELECTOR,
                              value='li[class*="opened"][data-parent="VMware vCenter/vSphere"] '
                                    'input[data-name="NTP server address"]')
    remote_syslog_ip = Find(TextField, by=By.CSS_SELECTOR,
                            value='li[class*="opened"][data-parent="VMware vCenter/vSphere"] '
                                  'input[data-name="Remote syslog IP"]')
    dcui_access_users = Find(TextField, by=By.CSS_SELECTOR,
                             value='li[class*="opened"][data-parent="VMware vCenter/vSphere"] '
                                   '[data-name="DCUI Access Users"]')
    vmsafe_agent_addr = Find(TextField, by=By.CSS_SELECTOR,
                             value='li[class*="opened"][data-parent="VMware vCenter/vSphere"] '
                                   'input[data-name="VMSafe agent addr"]')
    agent_port_num = Find(TextField, by=By.CSS_SELECTOR,
                          value='li[class*="opened"][data-parent="VMware vCenter/vSphere"] '
                                'input[data-name="Agent Port Num"]')
    system_log_dir = Find(TextField, by=By.CSS_SELECTOR,
                          value='li[class*="opened"][data-parent="VMware vCenter/vSphere"] '
                                'input[data-name="System log dir"]')
    ssh_session_timeout = Find(TextField, by=By.CSS_SELECTOR,
                               value='li[class*="opened"][data-parent="VMware vCenter/vSphere"] '
                                     'input[data-name="SSH session timeout"]')
    the_cpu_share_level = Find(TextField, by=By.CSS_SELECTOR,
                               value='li[class*="opened"][data-parent="VMware vCenter/vSphere"] '
                                     'input[data-name="The CPU Share Level"]')
    num_memory_shares = Find(TextField, by=By.CSS_SELECTOR,
                             value='li[class*="opened"][data-parent="VMware vCenter/vSphere"] '
                                   'input[data-name="Num Memory Shares"]')
    mem_share_level = Find(TextField, by=By.CSS_SELECTOR,
                           value='li[class*="opened"][data-parent="VMware vCenter/vSphere"] '
                                 'input[data-name="Mem Share Level"]')

    _compliance_type = "CIS VMware ESXi 5.1 v1.0.1 Level 1"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.VMWARE_VCENTER_VSPHERE,
                                   compliance_type=self._compliance_type)


class TNSBestPracticeWatchGuardAudit(Compliance):
    """Page object for TNS Best Practice WatchGuard Audit 1.0.0 compliance under WatchGuard Category"""
    user_auth_timeout = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="WatchGuard"] '
                                                                  'input[data-name="User Auth Timeout"]')
    user_session_timeout = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="WatchGuard"] '
                                                                     'input[data-name="User Session Tiemout"]')
    mgmt_user_auth_timeout = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="WatchGuard"] '
                                                                       'input[data-name="MGMT User Auth Timeout"]')
    mgmt_user_session_timeout = Find(TextField, by=By.CSS_SELECTOR,
                                     value='li[class*="opened"][data-parent="WatchGuard"] '
                                           'input[data-name="MGMT User Session Timeout"]')
    single_sign_on = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="WatchGuard"] '
                                                               'input[data-name="Single Sign-On"]')
    ntp_server_ip_addresses = Find(TextField, by=By.CSS_SELECTOR,
                                   value='li[class*="opened"][data-parent="WatchGuard"] '
                                         'input[data-name="NTP Server IP addresses"]')
    dns_server_ip_addresses = Find(TextField, by=By.CSS_SELECTOR,
                                   value='li[class*="opened"][data-parent="WatchGuard"] '
                                         'input[data-name="DNS Server IP addresses"]')
    wins_server_ip_addresses = Find(TextField, by=By.CSS_SELECTOR,
                                    value='li[class*="opened"][data-parent="WatchGuard"] '
                                          'input[data-name="WINS Server IP addresses"]')
    ldap_server_name = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="WatchGuard"] '
                                                                 'input[data-name="LDAP Server Name"]')
    ldap_server_port = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="WatchGuard"] '
                                                                 'input[data-name="LDAP Server Port"]')
    ddos_server_conns_per_second = Find(TextField, by=By.CSS_SELECTOR,
                                        value='li[class*="opened"][data-parent="WatchGuard"] '
                                              'input[data-name="DDoS Server - Conns Per Second"]')
    ddos_client_conns_per_second = Find(TextField, by=By.CSS_SELECTOR,
                                        value='li[class*="opened"][data-parent="WatchGuard"] '
                                              'input[data-name="DDoS Client - Conns Per Second"]')
    icmp_error_handling_pmtu = Find(TextField, by=By.CSS_SELECTOR,
                                    value='li[class*="opened"][data-parent="WatchGuard"] '
                                          'input[data-name="ICMP Error Handling PMTU"]')
    icmp_error_handling_time_exceeded = Find(TextField, by=By.CSS_SELECTOR,
                                             value='li[class*="opened"][data-parent="WatchGuard"] '
                                                   'input[data-name="ICMP Error Handling Time Exceeded"]')
    icmp_error_handling_nw_unreachable = Find(TextField, by=By.CSS_SELECTOR,
                                              value='li[class*="opened"][data-parent="WatchGuard"] '
                                                    'input[data-name="ICMP Error Handling NW Unreachable"]')
    icmp_err_handling_host_unreachable = Find(TextField, by=By.CSS_SELECTOR,
                                              value='li[class*="opened"][data-parent="WatchGuard"] '
                                                    'input[data-name="ICMP Err. Handling Host Unreachable"]')
    icmp_port_unreachable = Find(TextField, by=By.CSS_SELECTOR,
                                 value='li[class*="opened"][data-parent="WatchGuard"] '
                                       'input[data-name="ICMP - Port Unreachable"]')
    icmp_protocol_unreachable = Find(TextField, by=By.CSS_SELECTOR,
                                     value='li[class*="opened"][data-parent="WatchGuard"] '
                                           'input[data-name="ICMP - Protocol Unreachable"]')
    remote_log_server_address = Find(TextField, by=By.CSS_SELECTOR,
                                     value='li[class*="opened"][data-parent="WatchGuard"] '
                                           'input[data-name="Remote Log Server Address"]')
    # file upload
    config_file = Find(UploadField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="WatchGuard"] '
                                                              'input[data-name="WatchGuard config file(s)"]')
    _compliance_type = "TNS Best Practice WatchGuard Audit 1.0.0"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.WATCHGUARD,
                                   compliance_type=self._compliance_type)


class CisIbmBenchmarkLevelOneWindows(Compliance):
    """Page object for CIS IBM DB2 9 Benchmark v3.0.1 Level 1 OS Windows compliance under WINDOWS Category"""
    database_being_audited = Find(TextField, by=By.CSS_SELECTOR,
                                  value='li[class*="opened"][data-parent="Windows"] '
                                        'input[data-name="Name of the database being audited."]')
    path_to_sqllib = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Windows"] '
                                                               'input[data-name="DB2 Path to SQLLIB"]')
    Default_drive = Find(TextField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Windows"] '
                                                              'input[data-name="Default drive for new databases."]')
    tablespace_container_path = Find(TextField, by=By.CSS_SELECTOR,
                                     value='li[class*="opened"][data-parent="Windows"] '
                                           'input[data-name="DB2 Tablespace Container path"]')
    path_for_primary_archive_logs = Find(TextField, by=By.CSS_SELECTOR,
                                         value='li[class*="opened"][data-parent="Windows"] '
                                               'input[data-name="Full path to the location for primary archive logs."]')
    path_for_secondary_archive_logs = Find(TextField, by=By.CSS_SELECTOR,
                                           value='li[class*="opened"][data-parent="Windows"] '
                                                 'input[data-name="Full path to the location for '
                                                 'secondary archive logs."]')
    path_for_failed_archives = Find(TextField, by=By.CSS_SELECTOR,
                                    value='li[class*="opened"][data-parent="Windows"] '
                                          'input[data-name="Full path to the location for failed archives."]')
    path_for_mirror_logs = Find(TextField, by=By.CSS_SELECTOR,
                                value='li[class*="opened"][data-parent="Windows"] '
                                      'input[data-name="Full path to the location for mirror logs."]')

    _compliance_type = "CIS IBM DB2 9 Benchmark v3.0.1 Level 1 OS Windows"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.WINDOWS,
                                   compliance_type=self._compliance_type)


class CISCiscoCisIosL1(Compliance):
    """Page object for CIS Cisco IOS 15 L1 v4.1.1 compliance under CIS Cisco Category"""
    # file upload
    config_file = Find(UploadField, by=By.CSS_SELECTOR, value='li[class*="opened"][data-parent="Cisco IOS"] '
                                                              'input[data-name="IOS config file(s)"]')
    _compliance_type = "CIS Cisco IOS 15 L1 v4.1.1"

    def __init__(self):
        super().__init__()
        self.click_compliance_type(category_name=ComplianceConst.CISCO_IOS, compliance_type=self._compliance_type)
