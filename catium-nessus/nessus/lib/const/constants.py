"""
Nessus Constants

:copyright: Tenable Network Security, 2017
:date: Mar 2, 2017

:last_modified: July 25, 2024
:author: @jyerge, @rdutta, @yshah, @vsoni, @kpanchal, @krpatel, @mdabra
"""

import random
# pylint: disable=R0903
from datetime import datetime
from enum import Enum

from catium.lib.const import STRING_NONE
from catium.lib.util import random_name


# TODO Remove unused constants


class API:
    """Common API"""
    AUTOMATION_SECRET = 'siQExNN83EjLt2BweRgYXn85E5GnpbvBuSqvtjNA9FYR6rhV44wu4a3' \
                        'NyespzTAiuJsS6HQYyEzPe2NM2vnzhBu2qpH9vHzuJgZ2ySHd2p7yQiZK4adPG7FW4PcUSbLi'

    class Audits:
        """Audits related"""
        CISCO_AUDIT_FILE_NAME = 'Custom Cisco IOS'

        class Type(Enum):
            """Audit Types"""
            Feed = 'feed'
            Custom = 'custom'

    class Agents:
        """Constants related to Agents"""

        class ExportFormats:
            """Constants for Agent export formats"""

            FORMAT_CSV = 'csv'

    class Credentials:
        """Credential related"""

        class Types:
            """Credential types"""
            CATEGORY_CLOUD_SERVICES = 'Cloud Services'
            CATEGORY_DATABASE = 'Database'
            CATEGORY_HOST = 'Host'
            CATEGORY_MISCELLANEOUS = 'Miscellaneous'
            CATEGORY_PLAINTEXT_AUTHENTICATION = 'Plaintext Authentication'
            CATEGORY_MOBILE = 'Mobile'
            CATEGORY_PATCH_MANAGEMENT = 'Patch Management'

        class CloudServices:
            """Cloud Services Credentials"""

            class Types:
                """Types of Cloud Services"""
                RACKSPACE = "Rackspace"
                MICROSOFT_AZURE = "Microsoft Azure"
                AMAZON_AWS = "Amazon AWS"
                SALESFORCE = "Salesforce.com"
                OFFICE365 = "Office 365"

        class Database:
            """Database credential"""

            class Types:
                """Types"""
                ORACLE = 'Oracle'
                POSTGRESQL = 'PostgreSQL'
                DB2 = 'DB2'
                MYSQL = 'MySQL'
                SQL_SERVER = 'SQL Server'
                MONGODB = 'MongoDB'

            class Ports:
                """Ports"""
                DB2 = 50000
                POSTGRESQL = 5432
                MYSQL = 3306
                MONGODB = 27017
                ORACLE = 1521
                SQL_SERVER = 1433

            class Oracle:
                """Oracle Database"""
                AUTH_TYPE_SYSDBA = 'SYSDBA'
                AUTH_TYPE_SYSOPER = 'SYSOPER'
                AUTH_TYPE_NORMAL = 'NORMAL'
                SVC_TYPE_SID = 'SID'
                SVC_TYPE_SERVICE_NAME = 'SERVICE_NAME'

            class SQLServer:
                """SQLServer Database"""
                AUTH_TYPE_WINDOWS = 'Windows'
                AUTH_TYPE_SQL = 'SQL'

        class Host:
            """Host credential"""

            class Ports:
                """Ports"""
                SNMP = 161
                SSH = 22
                KDC = 88

            class PrivilegeEscalation:
                """Privilege escalation"""
                NOTHING = 'Nothing'
                K5LOGIN = '.k5login'
                CISCO_ENABLE = "Cisco 'enable'"
                DZDO = 'dzdo'
                PBRUN = 'pbrun'
                SU = 'su'
                SU_SUDO = 'su+sudo'
                SUDO = 'sudo'

            class SSHAuthTypes:
                """SSH authentication types"""
                PUBLIC_KEY = 'public key'
                CYBERARK = 'CyberArk'
                CERTIFICATE = 'certificate'
                KERBEROS = 'Kerberos'
                PASSWORD = 'password'
                THYCOTIC = 'Thycotic Secret Server'
                BEYOND_TRUST = 'BeyondTrust'
                LIEBERMAN = 'Lieberman'

            class WindowsAuthTypes:
                """Windows authentication types"""
                PASSWORD = 'Password'
                CYBERARK = 'CyberArk'
                THYCOTIC = 'Thycotic Secret Server'
                KERBEROS = 'Kerberos'
                BEYOND_TRUST = 'BeyondTrust'
                LIEBERMAN = 'Lieberman'

            class Types:
                """Types"""
                SNMPV3 = 'SNMPv3'
                SSH = 'SSH'
                WINDOWS = 'Windows'
                AWS = "Amazon AWS"
                HOST_LIST = [SNMPV3, SSH, WINDOWS]

            class HostNames:
                """Hostnames"""
                MOBILE_REPORTING = 'Mobile Reporting'
                ESX_MACHINE = '172.26.48.110'

        class Miscellaneous:
            """Miscellaneous credential"""
            # Types
            ADSI = 'ADSI'
            F5 = 'F5'
            IBM_SERIES = 'IBM iSeries'
            OPEN_STACK = 'OpenStack'
            PALO_ALTO = 'Palo Alto Networks PAN-OS'
            RHEV = 'RHEV'
            VMWARE_ESX = 'VMware ESX SOAP API'
            VMWARE_VCENTER = 'VMware vCenter SOAP API'
            X509 = 'X.509'

        class Mobile:
            """ Mobile credential """
            AIRWATCH = 'AirWatch'
            MOBILEIRON = 'MobileIron'
            BLACKBERRY = 'Blackberry UEM'
            GOODMDM = 'Good MDM'
            INTUNE = 'Intune'
            APM = "Apple Profile Manager"
            MAAS360 = "MaaS360"
            WORKSPACEONE = "Workspace ONE"
            MOBILE_LIST = [AIRWATCH, APM, BLACKBERRY, GOODMDM, INTUNE, MAAS360, MOBILEIRON, WORKSPACEONE]

            class Ports:
                """ Ports """
                PORT = 443
                GOODMDM_PORT = 19005

        class PatchManagement:
            """Patch Management credential"""

            class Types:
                """Types of forms under PatchManagement Credentials Category"""
                MICROSOFT_SCCM = 'Microsoft SCCM'
                MICROSOFT_WSUS = 'Microsoft WSUS'
                DELL_KACE = 'Dell KACE K1000'
                IBM_BIGFIX = 'IBM Tivoli Endpoint Manager (BigFix)'
                REDHAT_SATELLITE5 = 'Red Hat Satellite Server'
                REDHAT_SATELLITE5_FORM_NAME = 'Red Hat Satellite 5 Server'
                REDHAT_SATELLITE6 = 'Red Hat Satellite 6 Server'
                SYMANTEC_ALTIRIS = 'Symantec Altiris'

        class PlaintextAuthentication:
            """Types of forms under Plaintext authentication credential category"""
            FTP = 'FTP'
            HTTP = 'HTTP'
            IMAP = 'IMAP'
            IPMI = 'IPMI'
            NNTP = 'NNTP'
            POP2 = 'POP2'
            POP3 = 'POP3'
            SNMPV12 = 'SNMPv1/v2c'
            TELNET_RSH_REXEC = 'telnet/rsh/rexec'

            class HTTPAuthTypes:
                """HTTP authentication types"""
                AUTOMATIC = 'Automatic authentication'
                BASIC = 'Basic/Digest authentication'
                HTTP_LOGIN = 'HTTP login form'
                HTTP_COOKIES = 'HTTP cookies import'

    class ClusterGroup:
        """Constants related to cluster group"""

        DEFAULT_CLUSTER_GROUP_NAME = "Default Cluster Group"
        DEFAULT_CLUSTER_GROUP_ID = 1

        class ErrorMessages:
            """Constants for error messages by API request with incorrect pre-condition."""
            SET_GROUP_AS_DEFAULT_ERROR = '{"error":"Cannot set the cluster group as default because ' \
                                         'the cluster group does not have any assigned nodes. Assign ' \
                                         'at least one node to the cluster group and try again."}'
            LAST_NODE_DELETE_ERROR = "Cannot delete the last node in a cluster group that still has agents assigned " \
                                     "to it. Move the agents to another cluster group and try again."
            AGENT_ASSIGN_ERROR = '{"error":"Cannot assign agents to a cluster group that does not have any assigned ' \
                                 'nodes. Assign a node to the cluster group and try again."}'
            NODE_REMOVE_ERROR = "Cannot remove the node from the cluster group because it has linked agents and " \
                                "there are no other nodes in the cluster group. Add another node to the cluster " \
                                "group or move the linked agents to another cluster group."

    class PoliciesSettings:
        """Policies Settings tab related"""

        class SettingsTypes:
            """policy setting tab options"""
            BASIC = "BASIC"
            DISCOVERY = "DISCOVERY"
            ASSESSMENT = "ASSESSMENT"
            REPORT = "REPORT"
            ADVANCED = "ADVANCED"

            class Assessment:
                """Assessment setting options"""
                GENERAL = "General"
                WINDOWS = "Windows"
                MALWARE = "Malware"
                WEB_APPLICATIONS = "Web Applications"

    class Scap:
        """Scap related"""

        class Types:
            """Scap and OVAL types"""
            LINUX_OVAL = "Linux (OVAL)"
            LINUX_SCAP = "Linux (SCAP)"
            WINDOWS_OVAL = "Windows (OVAL)"
            WINDOWS_SCAP = "Windows (SCAP)"
            VALID_TYPES = [LINUX_OVAL, LINUX_SCAP, WINDOWS_OVAL, WINDOWS_SCAP]

        SCAP_AND_OVAL_INFORMATION = [
            {'count_of_forms': 1, 'form_type': Types.WINDOWS_SCAP, 'form_details': [
                {'version': '1.2', 'benchmark_id': 'Windows_7_STIG', 'profile_id': 'Windows - 1_Classified',
                 'stream_id': '1234567', 'result_type': 'Full results w/o system characteristics',
                 'definition_file_name': 'U_Windows_7_V1R27_STIG_SCAP_1-1_Benchmark.zip',
                 'definition_file_path': 'nessus/tests/ui/scan/test_data/'}]},
            {'count_of_forms': 1, 'form_type': Types.WINDOWS_OVAL, 'form_details': [
                {'definition_file_name': 'U_Windows_7_V1R27_STIG_OVAL.zip',
                 'definition_file_path': 'nessus/tests/ui/scan/test_data/'}]},
            {'count_of_forms': 1, 'form_type': Types.LINUX_SCAP, 'form_details': [
                {'version': '1.2', 'stream_id': '1234567', 'benchmark_id': 'RHEL_6_STIG',
                 'profile_id': 'MAC - 1_Classified',
                 'result_type': 'Full results w/ system characteristics',
                 'definition_file_name': 'U_RedHat_6_V1R9_STIG_SCAP_1-1_Benchmark.zip',
                 'definition_file_path': 'nessus/tests/ui/scan/test_data/'}]},
            {'count_of_forms': 1, 'form_type': Types.LINUX_OVAL, 'form_details': [
                {'definition_file_name': 'U_RedHat_6_V1R9_STIG_OVAL.zip',
                 'definition_file_path': 'nessus/tests/ui/scan/test_data/'}]}]

    class Permissions:
        """Roles for TenableCloud & Nessus"""

        class Agent:
            """Agent Roles"""
            NO_ACCESS = 0
            CAN_USE = 16

        class AgentGroup:
            """Agent Group Permissions"""
            NO_ACCESS = 0
            CAN_USE = 16

        class AssetList:
            """
            Asset List Roles
            .. note:: Only available for TenableCloud
            """
            NO_ACCESS = 0
            CAN_VIEW = 32
            CAN_SCAN = 64

        class CiscoIse:
            """
            Cisco-Ise Roles
            .. note:: Only available in Nessus Manager
            """
            CAN_VIEW = 16
            CAN_QUARANTINE = 32

        class Policy:
            """
            Policy Roles
            .. note:: Only available in Nessus Manager
            """
            NO_ACCESS = 0
            CAN_USE = 16
            CAN_EDIT = 32

        class Scanner:
            """Scanner Roles"""
            NO_ACCESS = 0
            CAN_USE = 16
            CAN_MANAGE = 64

        class Scan:
            """
            Scan Roles
            .. note:: Only available in Nessus Manager
            """
            NO_ACCESS = 0
            CAN_VIEW = 16
            CAN_CONTROL = 32
            CAN_CONFIGURE = 64

        class User:
            """User Roles"""
            DISABLED = 0
            BASIC = 16
            STANDARD = 32
            ADMINISTRATOR = 64

            # Doesn't appear in TenableCloud API documentation so may only be applicable to Nessus
            SYSTEM_ADMINISTRATOR = 128
            VALID_PERMISSIONS = [0, 16, 32, 64, 128]

        class Types:
            """Permission object types"""
            AGENT_GROUP = 'agent-group'
            ASSET_LIST = 'asset-list'
            CONNECTOR = 'connector'
            DEFAULT = 'default'
            GROUP = 'group'
            POLICY = 'policy'
            USER = 'user'
            SCAN = 'scan'
            SCANNER = 'scanner'
            AGENT = 'agent'
            SCANNER_POOL = 'scanner-pool'
            USER_DEFINED = 'policies'
            VALID_TYPES = [AGENT_GROUP, ASSET_LIST, CONNECTOR, DEFAULT, GROUP, POLICY, USER, SCAN, SCANNER,
                           SCANNER_POOL]

    class Policies:
        """Policy related"""
        POLICY_TEMPLATE_PAGE_HEADER = "Policy Templates"

        class Uuids:
            """Policy UUIDS"""
            CUSTOM_SCAN = 'ab4bacd2-05f6-425c-9d79-3ba3940ad1c24e51e1f403febe40'

    class Scan:
        """Scan related"""

        class Actions:
            """Scan control actions"""
            LAUNCH = 'launch'
            PAUSE = 'pause'
            RESUME = 'resume'
            STOP = 'stop'

        class Chapters:
            """Scan chapters"""
            VALID_CHAPTERS = ['vuln_hosts_summary', 'vuln_by_host', 'compliance_exec', 'remediations', 'vuln_by_plugin',
                              'compliance', 'custom', 'vulnerabilities', 'exploitable_vulns', 'top10', 'hosts_vulns',
                              'known_accounts', 'oses_found', 'unsupported_software', 'year_old_vulns']

        class ExportFormats:
            """Scan export formats"""
            FORMAT_NESSUS = 'nessus'
            FORMAT_HTML = 'html'
            FORMAT_PDF = 'pdf'
            FORMAT_CSV = 'csv'
            FORMAT_DB = 'db'
            FORMAT_POLICY = 'policy'
            FORMAT_TIMING_DATA = 'timing'
            VALID_FORMATS = [FORMAT_NESSUS, FORMAT_HTML, FORMAT_PDF, FORMAT_CSV, FORMAT_DB]
            VALID_IMPORT_FORMATS = [FORMAT_NESSUS, FORMAT_DB]

        class UIExportFormats:
            """Scan export formats from UI"""
            FORMAT_NESSUS = 'Nessus'
            FORMAT_HTML = 'HTML'
            FORMAT_PDF = 'PDF'
            FORMAT_CSV = 'CSV'
            FORMAT_DB = 'Nessus DB'
            VALID_FORMATS = [FORMAT_NESSUS, FORMAT_HTML, FORMAT_PDF, FORMAT_CSV, FORMAT_DB]
            HIDE_SYSTEM_TEMPLATES = "Hide system templates"
            TEMPLATE_DESCRIPTION_LABEL = "Template Description:"
            FILTER_APPLIED_LABEL = "Filters Applied:"
            FORMATTING_OPTIONS_LABEL = "Formatting Options:"

        class ReportTypes:
            """Export report types"""
            EXPLOITABLE_VULNERABILITIES = "Summary of Exploitable Vulnerabilities"
            TOP_10_VULNERABILITIES = "Top 10 Vulnerabilities"
            HOSTS_WITH_VULNERABILITIES = "Summary of Hosts with Vulnerabilities"
            DEFAULT_OR_KNOWN_ACCOUNTS = "Summary of Known/Default Accounts"
            OS_DETECTIONS = "Summary of Operating Systems"
            UNSUPPORTED_SOFTWARE = "Summary of Unsupported Software"
            VULNERABILITIES_LESS_THAN_1_YEAR_OLD = "Summary of Vulnerabilities Older Than One Year"
            CUSTOM = "Custom"

            PRO_REPORT_TEMPLATES = [EXPLOITABLE_VULNERABILITIES, TOP_10_VULNERABILITIES, HOSTS_WITH_VULNERABILITIES,
                                    DEFAULT_OR_KNOWN_ACCOUNTS, OS_DETECTIONS, UNSUPPORTED_SOFTWARE,
                                    VULNERABILITIES_LESS_THAN_1_YEAR_OLD]

            class ReportContent:
                """ Export report content constants """
                PREVALENT_VULNERABILITIES_SECTION_TITLE = 'Top 10 Most Prevalent Vulnerabilities'
                PREVALENT_VULNERABILITIES_TABLE_TITLE = 'Top 10 Most Prevalent Vulnerabilities: '
                PREVALENT_VULNERABILITIES_TABLE_DESCRIPTION = 'Top 10 most prevalent (medium, high, critical) ' \
                                                              'vulnerabilities'

        class VulnerabilityGroup:
            """ Export report vulnerability group options """
            HOST = "Host"
            PLUGIN = "Plugin"

        class VulnerabilitiesDetails:
            """ Export report vulnerabilities details link """
            SELECT_ALL = "Select All"
            CLEAR = "Clear"
            PLUGIN_FILE_DATA = ['####sysconfig####\n[VERSION]\nVERSION=73\nMODEL=RV320\nSSL=0\nIPSEC=0\nPPTP=0\n'
                                'PLATFORMCODE=RV0XX\n[...]\n[SYSTEM]\nHOSTNAME=router\nDOMAINNAME=example.com\n'
                                'DOMAINCHANGE=1\nUSERNAME=cisco\nPASSWD=066bae9070a9a95b3e03019db131cd40\n[...]']
            PLUGIN_FILE_DATA_TYPE_TEXT = ['[2019-04-17 13:22:24] [session 0] session.set_debug: Debugging enabled at '
                                          'level DEBUG3\n[2019-04-17 13:22:24] [session 0] ssh_client_state.set: ** '
                                          'Entering STATE SOC_CLOSED **\n[2019-04-17 13:22:24] [session 0] '
                                          'session.set_error: No user-supplied SSH credential sets were found.\n'
                                          '[2019-04-17 13:22:24] [session 0] Login via sshlib::try_ssh_kb_settings_'
                                          'login has failed.\n[2019-04-17 13:22:24] [session 0] session.close_'
                                          'connection: Socket is already closed.']
            Vulnerability_selected_in_basic_network_scan = ["SSL Self-Signed Certificate",
                                                            "SSH Weak Algorithms Supported"]
            Host_selected_in_basic_network_scan = ["172.26.48.10", "172.26.48.25"]
            # Any grouped vuln list in the scan will work for this
            Grouped_vulnerability_ids = [55883, 79638, 82828, 90510, 90510]
            Vulnerability_id_in_basic_network_scan = [11219]
            # Pick a group that exists in two hosts, and drill into one host, get only expected result
            Grouped_vulnerability_one_host = '172.26.48.25'
            Grouped_vulnerability_one_host_results = [94437, 94437, 42873, 51192, 51192, 51192, 57582, 70544, 70544,
                                                      70544, 21643, 21643, 21643, 10863, 10863, 42981, 62563]

        class RemediationsDetails:
            """Remediations list on scan result page"""
            REMEDIATIONS = ['OpenSSL AES-NI Padding Oracle MitM Information Disclosure: '
                            'Upgrade to OpenSSL version 1.0.1t / 1.0.2h or later.\n16 2',
                            'Tenable Nessus 6.x < 6.8 Multiple Vulnerabilities: '
                            'Upgrade to Tenable Nessus version 6.8 or later.\n3 1']

        class LaunchTypes:
            """Scan launch types"""
            ON_DEMAND = 'ON_DEMAND'
            DAILY = 'DAILY'
            WEEKLY = 'WEEKLY'
            MONTHLY = 'MONTHLY'
            YEARLY = 'YEARLY'
            VALID_LAUNCH_TYPES = [ON_DEMAND, DAILY, WEEKLY, MONTHLY, YEARLY]

        class Status:
            """Scan status"""

            ABORTED = 'aborted'
            CANCELING = 'canceling'
            CANCELED = 'canceled'
            COMPLETED = 'completed'
            IMPORTED = 'imported'
            PAUSED = 'paused'
            PAUSING = 'pausing'
            PENDING = 'pending'
            PROCESSING = 'processing'
            RESUMING = 'resuming'
            RUNNING = 'running'
            STOPPED = 'stopped'
            STOPPING = 'stopping'
            EMPTY = 'empty'
            INITIALIZING = 'initializing'

    class Scanners:
        """Scanners related"""

        class ScannerPage:
            """Scanner page"""
            IDLE_STATUS = "This scanner is currently idle."
            LABELS = ['Activation Code',
                      'Connection',
                      'Expiration',
                      'Last Connection',
                      'Last Updated',
                      'Linked On',
                      'Nessus Scanner',
                      'Platform',
                      'Plugin Set',
                      'Plugins',
                      'Software',
                      'Status',
                      'Version']
            PERMISSION_OPTION = ['No access', 'Can use', 'Can manage']

        class LinkStatus:
            """Link statuses"""
            UNLINKED = 0
            LINKED = 1

        class Directive:
            """Scanner Directive"""

            class Status:
                """Directive Status"""
                ABORTED = 'aborted'
                CANCELING = 'canceling'
                CANCELED = 'canceled'
                COMPLETED = 'completed'
                IMPORTED = 'imported'
                PAUSED = 'paused'
                PAUSING = 'pausing'
                PENDING = 'pending'
                PROCESSING = 'processing'
                RESUMING = 'resuming'
                RUNNING = 'running'
                STOPPED = 'stopped'
                STOPPING = 'stopping'
                EMPTY = 'empty'

    class Schedule:
        """Schedule related"""

        class Frequencies:
            """Frequencies"""
            FREQ_ONCE = 'ONCE'
            FREQ_DAILY = 'DAILY'
            FREQ_WEEKLY = 'WEEKLY'
            FREQ_MONTHLY = 'MONTHLY'
            FREQ_YEARLY = 'YEARLY'
            VALID_FREQUENCIES = [FREQ_ONCE, FREQ_DAILY, FREQ_WEEKLY, FREQ_MONTHLY, FREQ_YEARLY]

        class Uuids:
            """Schedule UUID"""
            UUID = '731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65'

        class TimeZone:
            """Scheduled timezone"""
            ZULU_ZONE = 'Zulu'
            AMERICA_ZONE = 'America/New_York'

        class ByDays:
            """By Days"""
            BYDAY_SUNDAY = 'SU'
            BYDAY_MONDAY = 'MO'
            BYDAY_TUESDAY = 'TU'
            BYDAY_WEDNESDAY = 'WE'
            BYDAY_THURSDAY = 'TH'
            BYDAY_FRIDAY = 'FR'
            BYDAY_SATURDAY = 'SA'
            VALID_BYDAYS = [BYDAY_SUNDAY, BYDAY_MONDAY, BYDAY_TUESDAY, BYDAY_WEDNESDAY, BYDAY_THURSDAY, BYDAY_FRIDAY,
                            BYDAY_SATURDAY]

    class ScannerGroup:
        """Scanner Group related"""

        class Types:
            """Types"""
            LOAD_BALANCING = 'load_balancing'

    class ScannerHealth:
        """ Scanner Health related constant """
        SYSTEM_SPEC = 'system-specs'
        ALERT_MESSAGE = 'Minimum CPU requirements not met.'
        SYS_RAM_WARN_MSG = 'Your system does not meet the minimum recommended number of cores'
        SYS_RAM_RECOMMEND_MSG = 'Amount recommended:'
        CURRENT_SYS_RAM = 'Your system has:'
        NUMBER_RECOMMEND_MSG = 'Number recommended:'

    class Settings:
        """Settings related"""

        class AdvancedSettings:
            """Advanced Settings related constants"""
            RESTART_NOT_REQUIRED = ["agent_auto_unlink", "agent_auto_unlink_expiration", "agent_software_update",
                                    "allow_post_scan_editing", "auto_update_ui", "disable_ntp", "stop_scan_on_hang",
                                    "xmlrpc_idle_session_timeout"]

        class Ldap:
            """Ldap related strings"""
            WITH_ATTRIBUTES_USERNAME = "SharePoint"
            LDAP_TESTER_USERNAME = "tester1"
            LDAP_TESTER_EMAIL = "jcinquegrani@tenable.com"
            LDAP_TESTER_NAME = "tester1 tester1"
            LDAP_ADMINISTRATOR_USERNAME = "Administrator"
            LDAP_ADMINISTRATOR_EMAIL = "nessus_user@tenable.com"
            LDAP_ADMINISTRATOR_NAME = "Administrator"
            LDAP_ADMINISTRATOR_PASSWORD = "amethyst"
            LDAP_HOST = '172.26.48.10'
            LDAP_PORT = '636'
            LDAP_BASE_DN = 'CN=Users,DC=target,DC=tenablesecurity,DC=com'

            class Attributes:
                """LDAP Attribute Related"""
                WITH_ATTRIBUTES = {
                    "ldap_username_attribute": "sAMAccountName",
                    "ldap_email_attribute": "mail",
                    "ldap_name_attribute": "CN",
                    "ldap_ca": "AbCd1235%"

                }

                WITHOUT_ATTRIBUTES = {
                    "ldap_username_attribute": "",
                    "ldap_email_attribute": "",
                    "ldap_name_attribute": "",
                    "ldap_ca": ""
                }

        class Smtp:
            """SMTP Related Strings"""
            TEST_EMAIL_SUCCESSFUL = "SMTP Email successfully sent"
            SMTP_HOST = "tf-mailcatcher-lb-d212eb4b775ff714.elb.us-east-1.amazonaws.com"
            SMTP_PORT = "8025"
            SMTP_SENDER_EMAIL = "test@tenablesecurity.com"
            SMTP_HOST_NAME = "localhost:8834"
            SMTP_NONE = 'NONE'
            SMTP_PLAIN = 'PLAIN'
            SMTP_LOGIN = 'LOGIN'
            SMTP_NTLM = 'NTLM'
            SMTP_CRAM = 'CRAM-MD5'
            SMTP_AUTH_TYPE = [SMTP_NONE, SMTP_PLAIN, SMTP_LOGIN, SMTP_NTLM, SMTP_CRAM]
            SMTP_NO_ENCRYPT = 'No Encryption'
            SMTP_FORCE_SSL = 'Force SSL'
            SMTP_FORCE_TLS = 'Force TLS'
            SMTP_USE_TLS = 'Use TLS if available'
            SMTP_ENCRYPTION_TYPE = [SMTP_NO_ENCRYPT, SMTP_FORCE_SSL, SMTP_FORCE_TLS, SMTP_USE_TLS]
            SMTP_TEST_EMAIL_SUBJECT = 'Nessus SMTP Configuration Test'
            SCAN_RESULT_EMAIL_SUBJECT = 'Nessus Scan Results: '

        class ProxyServer:
            """Proxy Server related strings"""
            PROXY_HOST = '172.26.27.22'
            PROXY_PORT = '3128'
            PROXY_USERNAME = 'nesadmin'
            PROXY_PASSWORD = 'LabPass1'
            PROXY_USER_AGENT = 'Test Connection'
            PROXY_AUTO_DETECT = 'AUTO DETECT'
            PROXY_NONE = 'NONE'
            PROXY_BASIC = 'BASIC'
            PROXY_DIGEST = 'DIGEST'
            PROXY_NTLM = 'NTLM'
            PROXY_AUTH_METHODS = [PROXY_AUTO_DETECT, PROXY_NONE, PROXY_BASIC, PROXY_DIGEST, PROXY_NTLM]

        class SensorProxy:
            """ Sensor proxy related constants """
            QA_DEVELOP_SITE = 'qa-develop.cloud.aws.tenablesecurity.com'
            QA_STAGING_SITE = 'qa-staging.cloud.aws.tenablesecurity.com'
            QA_MILESTONE_SITE = 'qa-milestone.cloud.aws.tenablesecurity.com'
            TIO_SITE = QA_STAGING_SITE
            SENSOR_PROXY_LINKED = 'Linked successfully to {}'.format(TIO_SITE)
            SENSOR_PROXY_UNLINKED = 'Unlinked successfully from url https://{}/remote/sensor-proxy'.format(TIO_SITE)
            SENSOR_PROXY_RELINKED = 'Relink successful with {}'.format(TIO_SITE)
            UNLINKED_MESSAGE = 'Successfully unlinked'
            SCANNER_LINK_SUCCESS = 'Scanner link successful with {}'.format(TIO_SITE)
            AGENT_LINK_SUCCESS = 'Agent link successful with {}'.format(TIO_SITE)
            SP_TIO_LINKING_ERROR = 'Unable to link with url https://{}/remote/sensor-proxy'.format(TIO_SITE)
            SENSORS_TO_SP_LINKING_ERROR = 'Response code from linking: '
            SP_DOWN_UNLINK_ERROR = 'Unlink from controller failed: Connection to '
            SP_DOWN_LINK_ERROR = 'Link fail: Connection to '
            SP_SSL_ERROR = 'SSL error encountered when negotiating with '
            ACCESS_LOG_FILE = 'nginx/logs/access.log'
            SIDECAR_LOG_FILE = 'logs/sidecar.log'
            SIDECAR_PID_FILE = 'run/sidecar.pid'
            SIDECAR_JSON_FILE = 'config/sidecar.json'
            SCANNER = 'scanner'
            AGENT = 'agent'
            WIN_PLATFORM = 'WINDOWS'
            WIN_DISTRO = 'win-x86-64'
            LINUX_PLATFORM = 'LINUX'
            LINUX_DISTRO = 'es7-x86-64'
            MISS = 'MISS'
            HIT = 'HIT'
            PLUGINS = 'plugins'
            CORE_UPDATE = 'core update'
            UPDATE = 'update'
            TENABLE_IO = 'Tenable.io'
            SENSOR_PROXY = 'Sensor Proxy'
            STALE = 'STALE'

    class Status:
        """Status related"""
        LOADING = 'loading'
        ENABLED = 'enabled'
        ENABLE = 'enable'
        DISABLED = 'Disabled'
        DISABLE = 'disable'
        MIXED = 'mixed'
        READY = 'ready'
        REGISTER = 'register'
        LOCKED = 'locked'
        FEED_EXPIRED = 'feed-expired'

    class Types:
        """Object types"""
        POLICY = 'policy'
        SCAN = 'scan'

    class User:
        """User related"""
        API_KEYS_LENGTH = 64

        class Types:
            """Types"""
            LOCAL = 'local'
            LDAP = 'ldap'
            VALID_TYPES = [LOCAL, LDAP]

        class Users:
            """Different user accounts used for testing"""
            ADMIN_USER = "user-Admin"
            BASIC_USER = "user-Basic"
            DEFAULT_USER = "default"
            RANDOM_USER = "random_user"
            STANDARD_USER = "user-Standard"
            SYS_ADMIN_USER = "user-SysAdmin"
            TEST_EMAIL = "test@tenable.com"
            USERS_DATA = {BASIC_USER: BASIC_USER, STANDARD_USER: STANDARD_USER,
                          ADMIN_USER: ADMIN_USER, SYS_ADMIN_USER: SYS_ADMIN_USER}

        class Role:
            """Different Roles of user"""
            ADMIN = 'Administrator'
            BASIC = 'Basic'
            DISABLED = 'Disabled'
            STANDARD = 'Standard'
            SYS_ADMIN = 'System Administrator'
            ROLE_LIST_MANAGER = [BASIC, STANDARD, ADMIN, SYS_ADMIN]
            ROLE_LIST_PROFESSIONAL = [STANDARD, SYS_ADMIN]

    class Severity:
        """different level of severity"""
        INFO = 'recast_info'  # 0
        LOW = 'recast_low'  # 1
        MEDIUM = 'recast_medium'
        HIGH = 'recast_high'  # 2
        CRITICAL = 'recast_critical'  # 4


class Scanner:
    """Strings related to the Scanner object."""
    NESSUS_DB_DIRECTORY = "output/"
    NESSUS_DB_DOWNLOAD = False
    NESSUS_DB_PASSWORD = 'sapphire'
    # Example: 2017-03-30_0912
    NESSUS_DB_TIMESTAMP = str("{0:%Y-%m-%d_%H%M}".format(datetime.now()))
    NESSUS_DB_FILENAME = None
    NESSUS_SCAN_NAME = random_name(prefix='scan-')

    NESSUS_MANAGER_LINKING_KEY = STRING_NONE

    class Strings:
        """Common strings for miscellaneous scanning actions."""
        AVAILABILITY_OF_SCANNER = 'Availability of Nessus scanner'
        SCAN_TO_START = 'Scan to start.'
        SCANNER_LOGIN_SUCCEED = 'Waiting for scanner login to succeed'
        EXPORT_STATUS_OK = 'Waiting for scan export to complete.'


class Nessus:
    """Nessus Framework Constants"""
    BAD_USERNAMES = [".", "<>?</", "  "]
    DEFAULT_PORT = 8834
    DEFAULT_PASSWORD = 'sapphire'
    PRODUCT_NAME = "NESSUS"
    USER_ROLES = [API.Permissions.User.STANDARD, API.Permissions.User.SYSTEM_ADMINISTRATOR]
    ENDPOINT_FOR_OFFLINE_LINKING = "https://plugins-internal-prod.cloud.aws.tenablesecurity.com/v2/offline.php"
    USERNAME = 'admin'
    ROOT = 'root'
    LABPASS = 'LabPass1'
    PASSWORD = 'admin'
    DEFAULT_EXPIRATION_DAYS = 365
    SCANS = "Scans"
    SENSORS = "Sensors"
    SETTINGS = "Settings"
    DEFAULT_HEADER_MENU = [SCANS, SETTINGS]

    class UI:
        """Nessus UI related constants"""
        DEFAULT_SIDENAV_WIDTH = 191
        MIN_SIDENAV_WIDTH = 201
        MAX_SIDENAV_WIDTH = 501
        COLLAPSED_SIDENAV_WIDTH = 51

    class About:
        """Nessus about page related constants."""
        NESSUS_MANAGER_LABELS = ['Nessus Manager', 'Version', 'Licensed Hosts', 'Licensed Scanners', 'Licensed Agents']
        NESSUS_PROFESSIONAL_LABELS = ['Nessus Professional (original)', 'Version']
        NESSUS_PROFESSIONAL_10_LABELS = ['Nessus Professional Version 10', 'Version']
        NESSUS_EXPERT_10_LABELS = ['Licensed Domains', 'Licensed URLs', 'Nessus Expert Version 10', 'Version']
        PLUGINS_LABELS = ['Plugins', 'Last Updated', 'License Expiration', 'Plugin Set', 'Policy Template Version',
                          'Activation Code']
        FEED_STATUS = 'Feed Status'
        UPDATE_TO_PRO8_LICENSE_AGREEMENT_URL = "https://docs.tenable.com/other/Tenable_Master_Agreement.pdf"
        REGISTRATION_OPTIONS = ['Nessus (Essentials, Professional, Expert or Manager)', 'Offline']
        OFFLINE = 'Offline'
        POLICY_TEMPLATE_VERSION = "Policy Template Version"
        LICENSE_EXPIRING_SOON = 'License Expiring Soon'
        LICENSE_EXPIRED = 'License Expired'
        DEF_ASD_DOMAINS = 1000
        RENEW_NESSUS = 'Renew Nessus'
        RENEW_NESSUS_LICENSE = 'Renew Nessus License'
        NON_ADMIN_USER_NM_LABLES = ['Nessus Manager', 'Version']
        NON_ADMIN_USER_PLUGINS_LABELS = ['Plugins', 'Last Updated', 'Plugin Set', 'Policy Template Version']

        class SoftwareUpdateChannel:
            UPDATE_GA_OPTION = "ga"
            UPDATE_EA_OPTION = "ea"
            STABLE_VERSION_OPTION = "stable"
            UPDATE_GA_LABEL = "Update to the latest GA release. (Default)"
            UPDATE_EA_LABEL = "Opt in to Early Access releases."
            STABLE_VERSION_LABEL = "Delay updates, staying on an older release."
            UPDATE_CHOICE_DICT = {UPDATE_EA_OPTION: UPDATE_EA_LABEL, STABLE_VERSION_OPTION: STABLE_VERSION_LABEL}
            VERSION_UPDATE_WARNING_TITLE = "Version Update Warning"
            VERSION_UPDATE_WARNING_MESSAGE = "When you save changes to your Nessus Update Plan, Nessus may " \
                                             "immediately update to align with the version represented by your " \
                                             "selected plan. Nessus may either upgrade or downgrade versions and " \
                                             "restart. Do you want to continue?"
            SOFTWARE_UPDATE_SETTING_SAVED_NOTIFICATION = "Software Update settings saved successfully."
            BUILD_UPDATE_FILES_LIST = ['nessus-es7-x86-64.tar.gz', 'nessus.manifest']

        class TenableStore:
            """Constants related to tenable store page"""
            TENABLE_STORE_LINKS = ["https://www.cleverbridge.com", "https://store.tenable.com/"]
            BUY_NOW_MESSAGE = "Buy Nessus Professional now"
            PURCHASE_NP = "Purchase Nessus Professional"

        class PluginsetUpdate:
            """ Constants related to plugin set update """

            ABORTED = 'Aborted'
            NASL_NOT_LOADED = 'nasl could not be loaded'
            UNABLE_TO_COMPILE = 'Unable to compile'
            UNWANTED_LOGS = [ABORTED, NASL_NOT_LOADED, UNABLE_TO_COMPILE]

        class SoftwareUpdate:
            """ Constants related to software update tab """
            DAILY = 'Daily'
            WEEKLY = 'Weekly'
            MONTHLY = 'Monthly'
            UPDATE_FREQUENCY_OPTIONS = [DAILY, WEEKLY, MONTHLY]

        class PluginLocales:
            """Constants related to Plugin locales tab"""
            PLUGIN_LOCALES = 'Plugin Detail Locales'
            DEFAULT_PLUGIN_LOCALES = 'Default Plugin Detail Locale'
            LOCALES_HINT = 'Enable this option to download plugin detail language packs and configure the Default Plugin Detail Locale.'
            CHECKBOX_DESCRIPTION = 'Enable Plugin Locales'
            TAB_HEADER = [PLUGIN_LOCALES, DEFAULT_PLUGIN_LOCALES]
            TAB_NAME = 'Plugin Detail Locale'
            CHINESE_SIMPLIFIED = 'Chinese Simplified'
            CHINESE_TRADITIONAL = 'Chinese Traditional'
            JAPANESE = 'Japanese'
            AVAILABLE_LOCALES = [CHINESE_SIMPLIFIED, JAPANESE, CHINESE_TRADITIONAL]
            DEFAULT_LOCALE = 'en'
            MODAL_TITLE = 'Locale Update Warning'
            MODAL_TEXT = 'A change was made to the locales selection. Do you want to continue?'
            MODAL_TEXT1 = 'When you save changes to Plugin Locales default, Nessus plugin metadata (Name, Description, etc) will appear in the chosen language. Do you want to continue?'

    class NotificationPage:
        """Constants related to notification page"""
        critical_notifications = ["This notification is present on all platforms",
                                  "This notification is present on Linux",
                                  "This notification is present on Windows",
                                  "This notification exists to be acknowledged.",
                                  "This notification exists to be acknowledged and duration is 30 seconds.",
                                  "This notification exists to be acknowledged and duration is 40 seconds.",
                                  "This notification is not yet expired."]

    class AdvancedSettings:
        """Advanced Settings for Nessus"""
        MDM_DISABLE_INACTIVE_DEVICE_FILTERING = "mdm_disable_inactive_device_filtering"
        XMLRPC_LISTEN_PORT = "xmlrpc_listen_port"
        LOGIN_BANNER = "login_banner"
        SCAN_VULNERABILITY_GROUPS = "scan_vulnerability_groups"
        SCAN_VULNERABILITY_GROUPS_MIXED = "scan_vulnerability_groups_mixed"
        NON_DEFAULT_PORT_VALUE = "8000"

        USER_INTERFACE_TAB = "UI"
        SCANNING_TAB = "Scanning"
        LOGGING_TAB = "Logging"
        PERFORMANCE_TAB = "Performance"
        SECURITY_TAB = "Security"
        MISCELLANEOUS_TAB = "Misc"
        CUSTOM_TAB = "Custom"
        AGENTS_AND_SCANNERS_TAB = "Agents_and_MS"
        CLUSTER_TAB = "Clustering"
        ALLOW_POST_SCAN_EDITING = 'allow_post_scan_editing'
        DISABLE_NESSUS_WEB_SERVER = 'disable_xmlrpc'
        DISABLE_UI = 'disable_ui'
        MAXIMUM_CONCURRENT_WEB_USERS = 'global.max_web_users'
        NESSUS_WEB_SERVER_IP = 'listen_address'
        NESSUS_WEB_SERVER_PORT = 'xmlrpc_listen_port'
        USE_MIXED_VULNERABILITY_GROUPS = 'scan_vulnerability_groups_mixed'
        USE_VULNERABILITY = 'scan_vulnerability_groups'

        AUDIT_TRAIL_VERBOSITY = 'audit_trail'
        AUTO_ENABLE_PLUGIN_DEPENDENCIES = 'auto_enable_dependencies'
        CGI_PATHS_WEB_SCAN = 'cgi_path'
        ENGINE_THREAD_IDLE_TIME = 'engine.idle_wait'
        MAX_PLUGIN_OUTPUT_SIZE = 'plugin_output_max_size_kb'
        MAXIMUM_PORTS_IN_SCAN_REPORTS = 'report.max_ports'
        MAXIMUM_SIZE_EMAIL_REPORT = 'attached_report_maximum_size'
        NESSUS_RULE_FILE_LOCATION = 'rules'
        NON_SIMULTANEOUS_PORTS = 'non_simult_ports'
        PAUSED_SCAN_TIMEOUT = 'paused_scan_timeout'
        PCAP_SNAPSHOT_LENGTH = 'pcap.snaplen'
        PORT_RANGE = 'port_range'
        REVERSE_DNS_LOOKUPS = 'reverse_lookup'
        SAFE_CHECKS = 'safe_checks'
        SILENT_PLUGIN_DEPENDENCIES = 'silent_dependencies'
        SLICE_NETWORK_ADDRESSES = 'slice_network_addresses'

        LOG_ADDITIONAL_SCAN_DETAILS_NAME = 'Log Additional Scan Details'
        LOG_ADDITIONAL_SCAN_DETAILS = 'log_details'
        SCAN_HISTORY_EXPIRATION_DAYS_NAME = 'User Scan Result Deletion Threshold'
        SCAN_HISTORY_EXPIRATION_DAYS_ID = 'scan_history_expiration_days'
        LOG_VERBOSE_SCAN_DETAILS = 'log_whole_attack'
        NESSUS_DUMP_FILE_LOCATION = 'dumpfile'
        NESSUS_DUMP_FILE_LOG_LEVEL = 'nasl_log_type'
        NESSUS_LOG_LEVEL = 'backend_log_level'
        NESSUS_SCANNER_LOG_LOCATION = 'logfile'
        SCANNER_METRIC_LOGGING = 'scanner.metrics'
        USE_MILLISECONDS_IN_LOGS = 'logfile_msec'

        ENGINE_THREAD_POOL_SIZE = 'thread_pool_size'
        GLOBAL_MAX_HOST_CONCURRENTLY_SCANNED = 'global.max_hosts'
        GLOBAL_MAX_TCP_SESSIONS = 'global.max_simult_tcp_sessions'
        MAX_CONCURRENT_CHECKS_PER_HOST = 'max_checks'
        MAX_CONCURRENT_HOST_PER_SCAN = 'max_hosts'
        MAX_CONCURRENT_SCANS = 'global.max_scans'
        MAX_ENGINE_THREADS = 'engine.max'
        MAX_HOSTS_PER_ENGINE_THREAD = 'engine.max_hosts'
        MAX_TCP_SESSIONS_PER_HOST = 'host.max_simult_tcp_sessions'
        MAX_TCP_SESSIONS_PER_SCAN = 'max_simult_tcp_sessions'
        MINIMUM_ENGINE_THREADS = 'engine.min'
        OPTIMIZE_TESTS = 'optimize_test'
        OPTIONAL_HOSTS_PER_ENGINE_THREAD = 'engine.optimal_hosts'
        PLUGIN_CHECK_OPTIMIZATION_LEVEL = 'optimization_level'
        PLUGINS_TIMEOUT = 'plugins_timeout'
        QDB_MEMORY_USAGE = 'qdb_mem_usage'
        REDUCE_TCP_SESSIONS_ON_NETWORK = 'reduce_connections_on_congestion'
        SCAN_CHECK_READ_TIMEOUT = 'checks_read_timeout'
        STOP_SCAN_ON_HOST_DISCONNECT = 'stop_scan_on_disconnect'
        WEBSERVER_THREAD_POOL_SIZE = 'www_thread_pool_size'

        CIPHER_FILES_ON_DISK = 'cipher_files_on_disk'
        FORCE_PUBLIC_KEY_AUTHENTICATION = 'force_pubkey_auth'
        MAX_CONCURRENT_SESSION_PER_USER = 'max_sessions_per_user'
        SSL_CIPHER_LIST = 'ssl_cipher_list'
        SSL_MODE = 'ssl_mode'

        AUTOMATIC_UPDATE_DELAY = 'auto_update_delay'
        INITIAL_SLEEP_TIME = 'ms_agent_sleep'
        MAX_HTTP_CLIENT_REQUESTS = 'max_http_client_requests'
        NESSUS_DEBUG_PORT = 'dbg_port'
        NESSUS_PREFERENCES_DATABASES = 'config_file'
        NON_USER_SCAN_RESULT_CLEANUP_THRESHOLD = 'report_cleanup_threshold_days'
        PATH_TO_JAVA = 'path_to_java'
        REMOTE_SCANNER_PORT = 'remote_listen_port'
        REPORT_CRASHES_TO_TENABLE = 'report_crashes'
        SCAN_SOURCE_IP = 'source_ip'
        USER_SCAN_RESULT_DELETION_THRESHOLD = 'scan_history_expiration_days'
        SEND_TELEMETRY = 'send_telemetry'
        DISABLE_GUIDES = 'disable_guides'
        DISABLE_USER_GUIDES = 'Disable User Guides'

        AGENTS_PROGRESS = "agents_progress_viewable"
        AUTOMATIC_HOSTNAME_UPDATE = "update_hostname"
        CONCURRENT_AGENT_SOFTWARE_UPDATES = "cloud.manage.download_max"
        TRACK_UNIQUE_AGENTS = "track_unique_agents"
        AUTO_UPDATE = 'auto_update'

        SEVERITY_BASIS = 'System Default Severity Basis'
        CVSS_V4 = 'CVSS v4.0'
        CVSS_V3 = 'CVSS v3.0'
        CVSS_V2 = 'CVSS v2.0'
        UI_THEME = "ui_theme"
        DARK_MODE = "Dark"
        LIGHT_MODE = "Light"
        SYNC_WITH_OS = "Sync with OS setting"

        INFO = 'info'
        VERBOSE = 'verbose'
        DEBUG = 'debug'
        NORMAL = 'normal'

        SETTING_TABS = ["UI", "Scanning", "Logging", "Performance", "Security", "Misc", "Custom"]
        NESSUS_FILES = ["nessusd.dump", "nessusd.messages", "nessusd.rules"]
        BACKEND_LOG_LEVELS = [DEBUG, VERBOSE, NORMAL]

        class UIThemeColors:
            """ Color palette related constants """
            DARK_MODE = "Dark"
            LIGHT_MODE = "Light"
            WHITE_FONT_COLOR = "#FFFFFF"
            BLACK_FONT_COLOR = "#000000"

            class DarkTheme:
                """ Dark theme related color code """
                SIDE_NAV_SECTION_COLOR = "#373D47"
                LAYOUT_SECTION_COLOR = "#242D3B"
                HEADER_SECTION_COLOR = "#454D56"
                LINK_COLOR = "#1DD2E3"
                BLUE_BUTTON_COLOR = "#137281"
                GREY_BUTTON_COLOR = "#5A5D65"
                TEXT_COLOR = "#FFFFFF"
                BORDER_COLOR = "#484C56"
                CRITICAL = "#CC1246"
                HIGH = "#FF5959"
                MEDIUM = "#FFA15E"
                LOW = "#FFDC61"
                INFO = "#4D95CA"

            class LightTheme:
                """ Light theme related color code """
                SIDE_NAV_SECTION_COLOR = "#F5F5F5"
                LAYOUT_SECTION_COLOR = "#FFFFFF"
                HEADER_SECTION_COLOR = "#263746"
                LINK_COLOR = "#0071B9"
                BLUE_BUTTON_COLOR = "#0071B9"
                GREY_BUTTON_COLOR = "#EEEEEE"
                WHITE_BUTTON_COLOR = "#FFFFFF"
                TEXT_COLOR = "#333333"
                BORDER_COLOR = "#DDDDDD"
                CRITICAL = "#91243E"
                HIGH = "#DD4B50"
                MEDIUM = "#F18C43"
                LOW = "#F8C851"
                INFO = "#67ACE1"

            ELEMENT_COLOR_DICT = {DARK_MODE: [DarkTheme.LINK_COLOR, DarkTheme.GREY_BUTTON_COLOR,
                                              DarkTheme.BLUE_BUTTON_COLOR],
                                  LIGHT_MODE: [LightTheme.LINK_COLOR, LightTheme.GREY_BUTTON_COLOR,
                                               LightTheme.BLUE_BUTTON_COLOR]}

    class AgentsFilter:
        """Agents Filter Related Constants"""
        IP_ADDRESS = 'IP Address'
        NAME = 'Name'
        PLATFORM = 'Platform'
        VERSION = 'Version'
        LAST_CONNECTION = 'Last Connection'
        LAST_PLUGIN_UPDATE = 'Last Plugin Update'
        LAST_SCANNED = 'Last Scanned'
        KEY = 'key'
        VALUE = 'value'
        OPERATOR = 'operator'
        FILTER_VALUE_DATEPICKER = [LAST_CONNECTION, LAST_PLUGIN_UPDATE, LAST_SCANNED]
        FILTER_VALUE_TEXT_FIELD = [IP_ADDRESS, NAME, PLATFORM, VERSION,
                                   LAST_CONNECTION, LAST_PLUGIN_UPDATE, LAST_SCANNED]

    class DummyCredentials:
        """Dummy constants for policy credentials"""
        USERNAME = random_name("Nessus_user-")
        PASSWORD = random_name("NessusPass@")
        DOMAIN_IP = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
        EXPORT_SECURITY_PASSWORD = 'password'

    class Manager:
        """Nessus Manager Constants"""
        NESSUS_EXPERT = "Nessus Expert"
        NESSUS_MANAGER = "Nessus Manager"
        PRODUCT_NAME = "NESSUS_MANAGER"
        USER_ROLES = [API.Permissions.User.BASIC, API.Permissions.User.STANDARD, API.Permissions.User.ADMINISTRATOR,
                      API.Permissions.User.SYSTEM_ADMINISTRATOR]

    class Professional:
        """Nessus Professional Constants"""
        PRODUCT_NAME = "NESSUS_PROFESSIONAL"
        NESSUS_PROFESSIONAL = "Nessus Professional"
        NESSUS_PROFESSIONAL_8 = "Nessus Professional 8"

    class Essentials:
        """"Nessus Essentials constants"""
        NESSUS_ESSENTIALS = "Nessus Essentials"
        UPGRADE_TO_PROFESSIONAL = 'Upgrade to Nessus Professional'
        NO_HOST_USED = "No licensed hosts have been used."

    class TemplateNames:
        """Nessus default templates names."""
        THREAT_LANDSCAPE_RETROSPECTIVE = "{} Threat Landscape Report (TLR)".format(datetime.now().year - 2)
        ADVANCED = "Advanced Scan"
        ADVANCED_NAME = "AdvancedScan(172.26/28.90)"
        ATTACK_SURFACE_DISCOVERY = "Attack Surface Discovery"
        ADVANCED_AGENT = "Advanced Agent Scan"
        ADVANCED_DYNAMIC = "Advanced Dynamic Scan"
        FIND_AI = 'Find AI'
        PRE_DEFINED_ADVANCED_DYNAMIC = "Advanced Pre-Defined Dynamic Scan"
        AUDIT_CLOUD = "Audit Cloud Infrastructure"
        AUDIT_PATCH = "Credentialed Patch Audit"
        BASIC_AGENT = "Basic Agent Scan"
        ATTACK_PATH_ANALYSIS = "Attack Path Analysis"
        BASIC_NETWORK = "Basic Network Scan"
        COMPLIANCE_AUDIT = "Policy Compliance Auditing"
        HOST_DISCOVERY = "Host Discovery"
        INTEL_AMT = "Intel AMT Security Bypass"
        INTERNAL_PCI = "Internal PCI Network Scan"
        MALWARE = "Malware Scan"
        MDM_AUDIT = "MDM Config Audit"
        MOBILE_DEVICE = "Mobile Device Scan"
        OFFLINE_AUDIT = "Offline Config Audit"
        PCI_EXTERNAL = "PCI Quarterly External Scan"
        SCAP_OVAL = "SCAP and OVAL Auditing"
        SCAP_OVAL_AGENT = "SCAP and OVAL Agent Auditing"
        SOLORIGATE = "Solorigate"
        SPECTRE_MELTDOWN = "Spectre and Meltdown"
        WANNACRY = "WannaCry Ransomware"
        RIPPLE_20_REMOTE_SCAN = 'Ripple20 Remote Scan'
        ZEROLOGON_REMOTE_SCAN = 'Zerologon Remote Scan'
        WEB_APP = "Web Application Tests"
        ENHANCED_ASSET_DISCOVERY = 'Enhanced Asset Discovery'
        PROXYLOGON_MS_EXCHANGE = 'ProxyLogon : MS Exchange'
        PRINT_NIGHTMARE = 'PrintNightmare'
        ACTIVE_DIRECTORY_STARTER = 'Active Directory Starter Scan'
        LOG_4_SHELL = "Log4Shell"
        LOG4SHELL_REMOTE_CHECKS = "Log4Shell Remote Checks"
        LOG4SHELL_VULNERABILITY_ECOSYSTEM = "Log4Shell Vulnerability Ecosystem"
        AGENT_LOG4SHELL = "Agent Log4Shell"
        CISA_ALERTS = "CISA Alerts AA22-011A and AA22-047A"
        CONTILEAKS = "ContiLeaks"
        RANSOMWARE = 'Ransomware Ecosystem'
        CREDENTIAL_VALIDATION = 'Credential Validation'
        PING_ONLY_DISCOVERY = 'Ping-Only Discovery'
        REMOTE_MONITORING_MANAGE = 'Remote Monitoring and Management'
        AGENT_RESET = 'Nessus 10.8.0 / 10.8.1 Agent Reset'
        SCAN_TEMPLATE_LIST = [ADVANCED_DYNAMIC, CREDENTIAL_VALIDATION, ADVANCED, AUDIT_CLOUD, BASIC_NETWORK,
                              MOBILE_DEVICE, AUDIT_PATCH, HOST_DISCOVERY, INTERNAL_PCI, MALWARE, MDM_AUDIT,
                              OFFLINE_AUDIT, PCI_EXTERNAL, COMPLIANCE_AUDIT, SCAP_OVAL, WEB_APP,
                              ACTIVE_DIRECTORY_STARTER, FIND_AI, PING_ONLY_DISCOVERY,
                              AGENT_RESET]
        SCAN_TEMPLATE_LIST_HOME = [ADVANCED_DYNAMIC, CREDENTIAL_VALIDATION, ADVANCED, AUDIT_CLOUD, BASIC_NETWORK,
                              MOBILE_DEVICE, AUDIT_PATCH, HOST_DISCOVERY, INTERNAL_PCI, MALWARE, MDM_AUDIT,
                              OFFLINE_AUDIT, PCI_EXTERNAL, COMPLIANCE_AUDIT, SCAP_OVAL, WEB_APP,
                              ACTIVE_DIRECTORY_STARTER, FIND_AI, PING_ONLY_DISCOVERY,
                              AGENT_RESET]
        SCAN_TEMPLATE_LIST_EXPERT = [ADVANCED_DYNAMIC, CREDENTIAL_VALIDATION, ADVANCED, AUDIT_CLOUD,
                                     BASIC_NETWORK, AUDIT_PATCH, HOST_DISCOVERY, INTERNAL_PCI, MALWARE, MDM_AUDIT,
                                     MOBILE_DEVICE, OFFLINE_AUDIT, PCI_EXTERNAL, COMPLIANCE_AUDIT, SCAP_OVAL, WEB_APP,
                                     ACTIVE_DIRECTORY_STARTER, ATTACK_SURFACE_DISCOVERY, FIND_AI, PING_ONLY_DISCOVERY,
                                     AGENT_RESET]
        AGENT_TEMPLATE_LIST = [AGENT_LOG4SHELL, ADVANCED_AGENT, BASIC_AGENT, MALWARE,
                               COMPLIANCE_AUDIT, SCAP_OVAL_AGENT]
        SCAN_VULNERABILITIES_TEMPLATE_LIST_HOME = [BASIC_NETWORK, CREDENTIAL_VALIDATION, ADVANCED, ADVANCED_DYNAMIC, FIND_AI,
                                              MALWARE, MOBILE_DEVICE, WEB_APP, AUDIT_PATCH, ACTIVE_DIRECTORY_STARTER,
                                              AGENT_RESET]
        SCAN_VULNERABILITIES_TEMPLATE_LIST = [BASIC_NETWORK, CREDENTIAL_VALIDATION, ADVANCED, ADVANCED_DYNAMIC, FIND_AI,
                                              MALWARE, MOBILE_DEVICE, WEB_APP, AUDIT_PATCH, ACTIVE_DIRECTORY_STARTER,
                                              AGENT_RESET]

        SCAN_DISCOVERY_TEMPLATE_LIST = [HOST_DISCOVERY, PING_ONLY_DISCOVERY]
        SCAN_DISCOVERY_TEMPLATE_LIST_EXPERT = [HOST_DISCOVERY, ATTACK_SURFACE_DISCOVERY, PING_ONLY_DISCOVERY]
        SCAN_COMPLIANCE_TEMPLATE_LIST = [AUDIT_CLOUD, INTERNAL_PCI, MDM_AUDIT, OFFLINE_AUDIT, PCI_EXTERNAL,
                                         COMPLIANCE_AUDIT, SCAP_OVAL]

        AGENT_VULNERABILITIES_TEMPLATE_LIST = [AGENT_LOG4SHELL, BASIC_AGENT, ADVANCED_AGENT, MALWARE]
        AGENT_COMPLIANCE_TEMPLATE_LIST = [COMPLIANCE_AUDIT, SCAP_OVAL_AGENT]
        AGENT_DISCOVERY_TEMPLATE_LIST = [ATTACK_PATH_ANALYSIS]

        SCAN_TEMPLATES_REQUIRED_HOST = [ADVANCED, ADVANCED_DYNAMIC, BASIC_NETWORK, AUDIT_PATCH, HOST_DISCOVERY,
                                        INTERNAL_PCI, MALWARE, PCI_EXTERNAL, COMPLIANCE_AUDIT, SCAP_OVAL,
                                        WEB_APP]

        SCAN_TEMPLATE_ORDER = [HOST_DISCOVERY, PING_ONLY_DISCOVERY, BASIC_NETWORK]
        SCAN_TEMPLATE_ORDER_EXPERT = [ATTACK_SURFACE_DISCOVERY, HOST_DISCOVERY, PING_ONLY_DISCOVERY]

    class TemplateCategories:
        VULNERABILITIES = "Vulnerabilities"
        COMPLIANCE = "Compliance"
        DISCOVERY = "Discovery"

        SCAN_TEMPLATE_CATEGORIES_LIST = [VULNERABILITIES, COMPLIANCE, DISCOVERY]
        AGENT_TEMPLATE_CATEGORIES_LIST = [VULNERABILITIES, COMPLIANCE]

    class Filter:
        """Constants related to filter in nessus"""
        KEY = 'key'
        VALUE = 'value'
        OPERATOR = 'operator'
        FILTER = 'filter'
        QUALITY = 'quality'
        INDEX = 'filter_index'
        MATCH_TYPE = 'match_type'
        CVSSV4_FILTER_OPTION = ['CVSS v4.0 Base Score', 'CVSS v4.0 Base+Threat Score', 'CVSS v4.0 Supplemental Vector',
                                'CVSS v4.0 Threat Vector', 'CVSS v4.0 Vector']

        class FilterMatch:
            """Filter match type constants"""
            ANY = 'Any'
            ALL = 'All'
            FILTER_MATCH_OPTIONS = [ALL, ANY]

        class FilterOperators:
            """Constants related to filter operators in nessus"""
            EQUAL_TO = 'is equal to'
            NOT_EQUAL_TO = 'is not equal to'
            CONTAINS = 'contains'
            NOT_CONTAINS = 'does not contain'
            EARLIER_THAN = 'earlier than'
            LATER_THAN = 'later than'
            ON_DATE = 'on'
            NOT_ON_DATE = 'not on'
            IS_MORE_THAN = 'is more than'
            IS_LESS_THAN = 'is less than'
            OPERATOR_MAPPING = {'eq': EQUAL_TO, 'match': CONTAINS, 'gt': IS_MORE_THAN, 'date-gt': LATER_THAN}

        class FilterRecordTypes:
            """Constants related to filter Record Type in nessus"""
            CNAME = 'CNAME'
            NS = 'NS'
            PTR = 'PTR'
            A = 'A'
            AAAA = 'AAAA'
            SOA = 'SOA'
            MX = 'MX'

        class FilterKeys:
            """Constants related to filter keys in scan results page"""
            CANVAS_EXPLOIT_FRAMEWORK = 'CANVAS Exploit Framework'
            CANVAS_PACKAGE = 'CANVAS Package'
            CORE_EXPLOIT_FRAMEWORK = 'CORE Exploit Framework'
            DEFAULT_KNOWN_ACCOUNTS = 'Default/Known Accounts'
            ELLIOT_EXPLOIT_FRAMEWORK = 'Elliot Exploit Framework'
            EXPLOIT_AVAILABLE = 'Exploit Available'
            EXPLOITABILITY_AVAILABLE = 'Exploitability Ease'
            HOSTNAME = 'Hostname'
            IP_ADDRESS = 'IP Address'
            PLUGIN_DESCRIPTION = 'Plugin Description'
            PLUGIN_FAMILY = 'Plugin Family'
            PLUGIN_ID = 'Plugin ID'
            PLUGIN_MODIFICATION_DATE = 'Plugin Modification Date'
            PLUGIN_NAME = 'Plugin Name'
            PLUGIN_PUBLICATION_DATE = 'Plugin Publication Date'
            PLUGIN_TYPE = 'Plugin Type'
            PORT = 'Port'
            PROTOCOL = 'Protocol'
            RECORD_TYPE = "Record Type"
            SEVERITY = 'Severity'
            TARGET_HOSTNAME = 'Target Hostname'
            UNSUPPORTED_BY_VENDOR = 'Unsupported By Vendor'

            VALUE_DROPDOWN = [CANVAS_EXPLOIT_FRAMEWORK, CANVAS_PACKAGE, CORE_EXPLOIT_FRAMEWORK, DEFAULT_KNOWN_ACCOUNTS,
                              ELLIOT_EXPLOIT_FRAMEWORK, EXPLOIT_AVAILABLE, EXPLOITABILITY_AVAILABLE, PLUGIN_FAMILY,
                              PLUGIN_TYPE, PROTOCOL, RECORD_TYPE, SEVERITY, UNSUPPORTED_BY_VENDOR]
            VALUE_DATEPICKER = [PLUGIN_MODIFICATION_DATE, PLUGIN_PUBLICATION_DATE]

    class Scanner:
        "Nessus Scanner related Constants"

        SCANNER_SETUP_DESCRIPTION = "Remote scanners can be linked to Nessus using the provided key. Once linked, " \
                                    "they can be managed locally and selected when configuring scans. From this page " \
                                    "you can view the current status of your scanners and drill down to control all " \
                                    "running scans."

    class Scan:
        """Nessus Scan Related Constants"""
        COPY_SCAN = "copy"
        MODAL_TITLE_FOR_SCAN_COPY = "Copy Scan to Folder"
        MODAL_TITLE_FOR_SCAN_MOVE = "Move Scan to Folder"
        MOVE_SCAN = "move"
        SCAN_TEMPLATE_PAGE_HEADER = "Scan Templates"
        DEFAULT_SCAN_NAMES_CREATED_VIA_WIZARD = ["My Basic Network Scan", "My Host Discovery Scan"]

        class ScanDescriptions:
            """E.G. HD Wizard Description"""
            HD_WIZARD_DESC = "To get started, launch a host discovery scan to " \
                             "identify what hosts on your network are available to" \
                             " scan. Hosts that are discovered through a discovery" \
                             " scan do not count towards the 16 host limit on your" \
                             " license." \
                             "\n\nEnter targets as hostnames, IPv4 addresses, or" \
                             " IPv6 addresses. For IP addresses, you can use CIDR" \
                             " notation (e.g., 192.168.0.0/24), a range" \
                             " (e.g., 192.168.0.1-192.168.0.255), or a " \
                             "comma-separated list (e.g., 192.168.0.0, 192.168.0.1)."

        class ScanFeatureTabs:
            """Nessus Scan feature tabs"""
            CREDENTIALS = "credentials"
            COMPLIANCE = "compliance"
            PLUGINS = "plugins"

        class ScanTemplateTabs:
            """scan template tabs"""
            SCANNER_TAB = 'Scanner'
            AGENT_TAB = 'Agent'
            WAS_TAB = 'WAS'
            USER_DEFINED_TAB = 'User Defined'

        class ResultTypes:
            """Scan result types"""
            DEFAULT = 'default'
            MOBILE = 'mobile'
            ADSI = 'adsi'
            PATCHMANAGEMENT = 'patch management'
            MISCELLANEOUS = 'miscellaneous'

        class Target:
            """scan targets for scanning on the controller"""
            PRODUCTION_FEED_SERVER_HOST = "plugins-internal-prod.cloud.aws.tenablesecurity.com"
            OLD_PRODUCTION_FEED_SERVER_HOST = "10.0.16.51"
            OLD_STAGING_FEED_SERVER_HOST = "10.0.17.100"
            STAGING_FEED_SERVER_HOST = "plugins-internal-staging.cloud.aws.tenablesecurity.com"
            AWS_LINUX_TARGET_1 = "10.254.130.10"
            AWS_LINUX_TARGET_2 = "10.254.130.239"
            LINUX_TARGET = "172.26.48.53"
            LINUX_TARGET_1 = "172.26.48.50"
            LINUX_TARGET_2 = "172.26.17.90"
            LOCALHOST = "127.0.0.1"
            WINDOWS_TARGET = "172.26.48.75"
            # Don't use PUB_TARGET_1 for Nessus home related testcases as unique host is needed for testing (NES-9865)
            PUB_TARGET_1 = "target1.pubtarg.tenablesecurity.com"
            PUB_TARGET_2 = "target2.pubtarg.tenablesecurity.com"
            PUB_TARGET_3 = "target3.pubtarg.tenablesecurity.com"
            PUB_TARGET_4 = "target4.pubtarg.tenablesecurity.com"
            MAX_DISCOVERY_TARGET = '10.254.130.0/24'
            MAX_DISCOVERY_TARGET_LOCAL = '172.26.48.0-172.26.48.100'
            NO_SCAN_RESULT_TARGET = '172.26.48.11'
            INFO_LEVEL_TARGET = '172.26.48.15'
            MULTIPLE_TARGETS = "target4.pubtarg.tenablesecurity.com, target3.pubtarg.tenablesecurity.com"

        class Folder:
            """folder name for scanning on the controller"""
            ALL_SCANS = "All Scans"
            FOLDER_CREATION_WINDOW_TITLE = "New Folder"
            MY_SCANS = "My Scans (S)"
            TRASH = "Trash"
            DEFAULT_FOLDERS = [ALL_SCANS, MY_SCANS, TRASH]

        class TemplateNames:
            """Template Names"""
            SCANNER_ADVANCED = 'Advanced Scan'
            MALWARE = 'malware'
            PATCH_AUDIT = 'patch_audit'
            MDM = 'mdm'
            MOBILE = 'mobile'
            COMPLIANCE = 'compliance'
            OFFLINE = 'offline'
            SCAP = 'scap'
            AGENT_BASIC = 'agent_basic'
            AGENT_ADVANCE = 'agent_advanced'
            AGENT_MALWARE = 'agent_malware'
            AGENT_SCAP = 'agent_scap'
            AGENT_COMPLIANCE = 'agent_compliance'
            CLOUD_AUDIT = 'cloud_audit'
            DISCOVERY = 'discovery'
            ADVANCED = 'advanced'
            BASIC = 'basic'
            ASD = 'domain_discovery_scan'
            WAS_SCAN = 'was_scan'

        class SettingsTypes:
            """Scan setting tab options under Agent Tab"""
            BASIC = "BASIC"
            DISCOVERY = "DISCOVERY"
            ASSESSMENT = "ASSESSMENT"
            REPORT = "REPORT"
            ADVANCED = "ADVANCED"

        class SettingsBasicSubMenu:
            """Sub menu links under basic settings in Scan configuration."""
            GENERAL = 'General'
            NOTIFICATIONS = 'Notifications'
            PERMISSIONS = 'Permissions'
            SCHEDULE = 'Schedule'

        class SettingsAdvancedSubMenu:
            """ Sub menu under Advanced settings in Scan configuration """
            TARGET_TO_CAPTURE_HINT_MSG = "Provide one target to capture network scan traffic on next scan launch. " \
                                         "Note: cannot use localhost/127.0.0.1"
            DEFAULT_CAPTURE_PORT_RANGE = "1-65535"
            PORTS_TO_CAPTURE_HINT_MSG = "Provide ports or port ranges to capture"

        class UserPermissions:
            """User permissions in Scan."""
            CAN_CONFIGURE = 'Can configure'
            CAN_CONTROL = 'Can control'
            CAN_VIEW = 'Can view'
            NO_ACCESS = 'No access'
            CAN_EDIT = 'Can edit'
            USER_PERMISSIONS = {NO_ACCESS: NO_ACCESS, CAN_VIEW: CAN_VIEW,
                                CAN_CONTROL: CAN_CONTROL, CAN_CONFIGURE: CAN_CONFIGURE}

        class Vulnerability:
            """scan results vulnerabilities"""
            PING_THE_REMOTE_HOST = "Ping the remote host"
            NESSUS_SCAN_INFO = "Nessus Scan Information"
            DEBUGGING_LOG_REPORT = "Debugging Log Report"
            PLUGIN_OUTPUT_PORT = "Port"
            PLUGIN_OUTPUT_HOSTS = "Hosts"
            CVSSV4_VULN = "TEST PLUGIN FOR CVSSv4"

        class ComplianceAuthentication:
            """Scan compliance authentication levels"""
            NEW_WITH_AUTH = "new_auth"
            NEW_WITHOUT_AUTH = "new_no_auth"
            WITH_AUTH = "auth"
            WITHOUT_AUTH = "no_auth"
            VALID_AUTH_LEVELS = [WITH_AUTH, WITHOUT_AUTH, NEW_WITH_AUTH, NEW_WITHOUT_AUTH]

        class Severity:
            """scan results severity"""
            CRITICAL = "Critical"
            DEFAULT = "Hide this result"
            HIDE = "Hide this result"
            HIGH = "High"
            INFO = "Info"
            LOW = "Low"
            MEDIUM = "Medium"
            MIXED = "Mixed"
            NONE = "None"
            SEVERITY_LEVELS = [CRITICAL, HIGH, INFO, LOW, MEDIUM]

        class Snoozing:
            """Constants related to snoozing"""
            ONE_DAY = "1 Day"
            ONE_WEEK = "1 Week"
            ONE_MONTH = "1 Month"
            CUSTOM = "Custom"
            DURATION_LIST = ['1 Day', '1 Week', '1 Month', 'Custom']
            SHOW_SNOOZED = "Show Snoozed"
            HIDE_SNOOZED = "Hide Snoozed"
            ENABLE_GROUPS = "Enable Groups"
            DISABLE_GROUPS = "Disable Groups"
            VULN_SETTING_POP_UP_MENU = [SHOW_SNOOZED, HIDE_SNOOZED, ENABLE_GROUPS, DISABLE_GROUPS]

        class Results:
            """Constants related to scan results page"""
            CURRENT_TAG = 'Current'
            CUSTOM_TAG = 'Custom'
            DELETE = "Delete"
            CREATE_SCAN = "Create Scan"
            ENABLE = "Enable"
            ENABLE_DASHBOARD = "Enable Dashboard"
            ENABLE_DASHBOARD_MESSAGE = "Dashboards are disabled for this scan.\nClick here to enable."

            class Tabs:
                """Tab's name constants in scan results page"""
                DASHBOARD_TAB = 'Dashboard'
                HISTORY_TAB = 'History'
                HOSTS_TAB = 'Hosts'
                NOTES_TAB = 'Notes'
                REMEDIATION_TAB = 'Remediations'
                VULNERABILITIES_TAB = 'Vulnerabilities'
                SCAN_SUMMARY_TAB = "Scan Summary"

            class LaunchTypes:
                """Constants related to scan launch types"""
                CUSTOM = 'Custom'
                DEFAULT = 'Default'
                SELECTED = 'Selected'

            class RightColumnHeader:
                """Headers in right column of scan result page"""
                SCAN_DETAILS = 'Scan Details'
                PLUGIN_DETAILS = 'Plugin Details'
                VULNERABILITIES = 'Vulnerabilities'
                AGENT_DETAILS = 'Agent Details'

            class ScanDetailsLevels:
                """Constants related to scan details in scan results page"""
                SCAN_ELAPSED_TIME = 'Elapsed'
                SCAN_END_TIME = 'End'
                SCAN_POLICY = 'Policy'
                SCAN_SCANNER = 'Scanner'
                SCAN_START_TIME = 'Start'
                SCAN_STATUS = 'Status'

                DEFAULT_LEVELS = [SCAN_STATUS, SCAN_POLICY, SCAN_START_TIME, SCAN_END_TIME]

            class HostDetailsLevels:
                """Constants related to host details in scan results page"""
                HOST_DNS = 'DNS'
                HOST_IP = 'IP'
                HOST_OS = 'OS'
                HOST_KB = 'KB'
                SCAN_ELAPSED_TIME = 'Elapsed'
                SCAN_END_TIME = 'End'
                SCAN_START_TIME = 'Start'

                DEFAULT_LEVELS = [HOST_IP, HOST_DNS, SCAN_START_TIME, SCAN_END_TIME, SCAN_ELAPSED_TIME, HOST_KB]

            class PlugInDetailsLevels:
                """Constants related to plugin details in scan results page"""
                PLUGIN_FAMILY = 'Family'
                PLUGIN_ID = 'ID'
                PLUGIN_MODIFIED_DATE = 'Modified'
                PLUGIN_PUBLISHED_DATE = 'Published'
                PLUGIN_SEVERITY = 'Severity'
                PLUGIN_TYPE = 'Type'
                PLUGIN_VERSION = 'Version'
                CVSSV4_RISK_INFO = 'Risk Factor: Medium\n' \
                                   'CVSS v4.0 Base Score:   1.8\n' \
                                   'CVSS v4.0 Vector:   ' \
                                   'CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:A/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N\n' \
                                   'CVSS v4.0 Threat Vector:   CVSS:4.0/E:U\n' \
                                   'CVSS v3.0 Base Score:   5.5\n' \
                                   'CVSS v3.0 Vector:   CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H\n' \
                                   'CVSS v3.0 Temporal Vector:   CVSS:3.0/E:U/RL:O/RC:C\n' \
                                   'CVSS v3.0 Temporal Score:   4.8\n' \
                                   'CVSS v2.0 Base Score: 4.3\n' \
                                   'CVSS v2.0 Vector: CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P\n' \
                                   'CVSS v2.0 Temporal Vector: CVSS2#E:U/RL:OF/RC:C\n' \
                                   'CVSS v2.0 Temporal Score: 3.2'
                CVSSV4_PLUGIN_INFO = 'ID: 260733\n' \
                                     'Version: 1.5\n' \
                                     'Type: local\n' \
                                     'Published: September 3, 2025\n' \
                                     'Modified: September 29, 2025'
                CVSSV4_SYNOPSIS = 'The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be patched.'
                CVSSV4_SOLUTION = 'There is no known solution at this time.'
                CVSSV4_SEE_ALSO = 'https://access.redhat.com/security/cve/cve-2025-54080\n' \
                                  'https://security-tracker.debian.org/tracker/CVE-2025-54080\n' \
                                  'https://ubuntu.com/security/CVE-2025-54080'


                DEFAULT_LEVELS = [PLUGIN_FAMILY, PLUGIN_ID, PLUGIN_SEVERITY]

            class AgentDetailsLevels:
                """ Constants related to agent details in scan results page """
                AGENT_GROUPS = 'Groups'
                AGENT_CLUSTER = 'Cluster'
                REPORTED = 'Reported'

                DEFAULT_LEVELS = [AGENT_GROUPS, AGENT_CLUSTER, REPORTED]

            class Export:
                """Constants related to export pop-up"""
                EXPORT_FORMATTING_TEXT = "Include page breaks between vulnerability results"
                VULNERABILITY_DETAILS = "Vulnerabilities Details"
                GROUP_VULNERABILITY_BY = "Group Vulnerabilities By"
                EXPORT_CSV_MODAL_TITLE = 'Generate CSV Report'
                PLUGIN_INFORMATION = "Plugin Information"
                EXPLOITABLE_WITH = "Exploitable With"
                METASPLOIT = "Metasploit"
                CORE_IMPACT = "Core Impact"
                CANVAS = "CANVAS"
                REFERENCES = "References"
                BID = "BID"
                XREF = "XREF"
                MSKB = "MSKB"
                EXPLOITABLE_WITH_COLUMNS = [METASPLOIT, CORE_IMPACT, CANVAS]
                REFERENCES_COLUMNS = [BID, XREF, MSKB]

            class HostDiscoveryTable:
                """Constants related to Host Discovery Table columns"""
                HOST = 'Host'
                FQDN = "FQDN"
                OPERATING_SYSTEM = "Operating System"
                PORTS = "Ports"

            class ClusterGroupTable:
                """Constants related to Cluster group Table columns"""
                NAME = 'Name'
                NODES = 'Nodes'
                AGENTS = 'Agents'
                USAGE = 'Current Usage'
                SCANS = 'Scans'
                LAST_MODIFIED = 'Last Modified'
                COLUMN_NAMES = [NAME, NODES, AGENTS, USAGE, SCANS, LAST_MODIFIED]

            class ThreatLevelTab:
                """Constants related to threat level tab"""
                ASSESSED_THREAT = "Assessed Threat Level"
                THREAT_LEVEL_DESCRIPTION = "The following vulnerabilities are ranked by Tenable\'s patented " \
                                           "Vulnerability Priority Rating (VPR) system. The findings listed below " \
                                           "detail the top ten vulnerabilities, providing a prioritized view " \
                                           "to help guide remediation to effectively reduce risk.\nClick on each " \
                                           "finding to show further details along with the impacted hosts.\nTo learn " \
                                           "more about Tenable\'s VPR scoring system, see Predictive Prioritization."
                VPR_SEVERITY = "VPR Severity"
                NAME = "Name"
                REASONS = "Reasons"
                VPR_SCORE = "VPR Score"
                HOSTS = "Hosts"
                SYNOPSIS = "Synopsis"
                VULNERABILITY_PRIORITY_RATING = "Vulnerability Priority Rating"
                AFFECTED_HOSTS = "Affected Hosts"
                DESCRIPTION = "Description"
                SOLUTION = "Solution"
                SEE_ALSO = "See Also"
                PLUGIN_INFORMATION = "Plugin Information"
                RISK_INFORMATION = "Risk Information"
                VULNERABILITY_INFORMATION = "Vulnerability Information"
                PLUGIN_DETAILS_CONTENT_LABELS = [SYNOPSIS, VULNERABILITY_PRIORITY_RATING, AFFECTED_HOSTS, DESCRIPTION,
                                                 SOLUTION, SEE_ALSO, PLUGIN_INFORMATION, RISK_INFORMATION,
                                                 VULNERABILITY_INFORMATION]
                COLUMN_LIST = [VPR_SEVERITY, NAME, REASONS, VPR_SCORE, HOSTS]
                PREDICTIVE_PRIORITIZATION_LINK_URL = "https://www.tenable.com/predictive-prioritization"

            class ScanSummaryTab:
                """ Constants related to scan summary tab """
                SCAN_DURATION_SECTION_LABEL = "Scan Durations"
                SCAN_DURATION_TIME_LABEL = "SCAN DURATION"
                MEDIAN_SCAN_TIME_LABEL = "MEDIAN SCAN TIME PER HOST"
                MAX_SCAN_TIME_LABEL = "MAX SCAN TIME"
                BASIC_OVERVIEW = "Basic Overview"
                REPORT_OVERVIEW = "Report Overview"
                CREDENTIAL_SETTINGS_OVERVIEW = "Credential Settings Overview"
                FRAGILE_DEVICES = "Fragile Devices"
                ASSESSMENT_OVERVIEW = "Assessment Overview"
                ADVANCED_OVERVIEW = "Advanced Overview"
                PORT_SCANNER_OVERVIEW = "Port Scanner Overview"
                POLICY_DETAILS_SECTION_LABEL = [BASIC_OVERVIEW, REPORT_OVERVIEW, CREDENTIAL_SETTINGS_OVERVIEW,
                                                FRAGILE_DEVICES, ASSESSMENT_OVERVIEW, ADVANCED_OVERVIEW,
                                                PORT_SCANNER_OVERVIEW]
                OS_DISTRIBUTION_SECTION_TITLE = "Top 5 Operating Systems Detected During Scan"
                PLUGIN_FAMILY_SECTION_TITLE = "Plugin Families Enabled/Disabled"
                PLUGIN_FAMILY_SEARCH_FIELD_PLACEHOLDER = "Search Plugin Families"
                RESULTS_PER_PAGE_LABEL = "Results per page"
                AUTHENTICATION_CREDENTIALS_INFO_SECTION_LABEL = "Authentication / Credential Info (Hosts)"
                SUCCEEDED_HOST_LABEL = "SUCCEEDED"
                FAILED_HOST_LABEL = "FAILED"
                SCAN_NOTES_SECTION_LABEL = "Scan Notes"
                PLUGIN_RULES_APPLIED_SECTION_LABEL = "Plugin Rules Applied"
                PLUGIN_RULES_SEARCH_FIELD_PLACEHOLDER = "Search Plugin Rules"

    class Agents:
        """Agents Related Constants"""
        EMPTY_AGENT_LIST_MESSAGE = 'No agents have been added.'
        UNLINK_AGENTS = 'Unlink Agents'
        UNLINK_AGENT = 'Unlink Agent'
        DELETE_AGENTS = 'Delete Agents'
        DELETE_AGENT = 'Delete Agent'
        REMOVE_AGENTS = 'Remove Agents'
        ADD_TO_GROUP = 'Add to Group(s)'
        UNLINK_AGENTS_WARNING = 'Are you sure you want to unlink these agents?'
        UNLINK_AGENT_WARNING = 'Are you sure you want to unlink this agent?'
        REMOVE_AGENTS_WARNING = 'Are you sure you want to remove these agents?'
        DELETE_AGENTS_WARNING = 'Are you sure you want to delete these agents?'
        DELETE_AGENT_WARNING = 'Are you sure you want to delete this agent?'
        LINK_AGENT_DESCRIPTION = "Agents can be linked to Nessus using the following setup instructions. Once linked," \
                                 " they will automatically download all necessary plugins. This process takes " \
                                 "several minutes and is required before an agent will return results. " \
                                 "A full list of agents can be exported to CSV."
        AGENT_SETUP_INSTRUCTION = 'Agent Setup Instructions'
        NO_AGENTS_LINKED = 'No agents have been linked.'
        AGENT_TABLE_COLUMNS = {'Last Scanned', 'Status', 'Platform', 'Groups', 'Last Plugin Update', 'Version',
                               'IP Address', 'Name'}

        class Filter:
            """Agents Filter related Constants"""
            IP_ADDRESS = 'IP Address'
            NAME = 'Name'
            PLATFORM = 'Platform'
            VERSION = 'Version'
            LAST_CONNECTION = 'Last Connection'
            LAST_PLUGIN_UPDATE = 'Last Plugin Update'
            LAST_SCANNED = 'Last Scanned'
            MEMBER_OF_GROUP = 'Member of Group'
            PROFILE_NAME = 'Profile Name'
            PROFILE_UUID = 'Profile UUID'
            STATUS = 'Status'
            ANY = 'Any'
            ALL = 'All'
            MATCH_TYPE = 'match_type'
            NUMBER_OF_FILTER = 'number_of_filter'
            NONE = 'None'
            KEY = 'key'
            VALUE = 'value'
            OPERATOR = 'operator'
            IS_EQUAL_TO = 'is equal to'
            IS_NOT_EQUAL_TO = 'is not equal to'
            CONTAINS = 'contains'
            NA = 'N/A'
            AGENTS = 'Agents'
            PLUGIN_SET = 'Plugin Set'
            GENERAL = 'General'
            SOFTWARE = 'Software'
            CONNECTION = 'Connection'
            PLUGINS = 'Plugins'
            FILTER_VALUE_DATEPICKER = [LAST_CONNECTION, LAST_PLUGIN_UPDATE, LAST_SCANNED]
            FILTER_VALUE_TEXT_FIELD = [IP_ADDRESS, NAME, PLATFORM, VERSION,
                                       LAST_CONNECTION, LAST_PLUGIN_UPDATE, LAST_SCANNED]
            FILTER_VALUE_DROPDOWN = [MEMBER_OF_GROUP, STATUS]
            GENERAL_SOFTWARE_LABELS = [GENERAL, STATUS, IP_ADDRESS, AGENTS, SOFTWARE, PLATFORM, VERSION]
            CONNECTION_PLUGINS_LABELS = [CONNECTION, LAST_CONNECTION, PLUGINS, PLUGIN_SET]

        class AgentStatus:
            """Agent status related constants"""
            UNLINKED = 'Unlinked'
            ONLINE = 'online'
            LINK_SUCCESSFUL = 'Link successful'
            SUCCESSFULLY_UNLINKED = 'Successfully unlinked'
            CONNECTION_WITH_CONTROLLER = 'Last successful connection with controller:'
            LINK_FAILED = "Linking failed"
            LINK_STATUS_CONNECTED_TO_NM = 'Link status: Connected to {}:{}'
            LINK_STATUS_LINKED_TO = 'Linked to: {}:{}'

        class Cluster:
            """ Agents cluster related constants """
            NEAR_MAX_AGENTS = '(Near Max Agents)'
            MAX_AGENTS = '(Max Agents)'
            MAX_AGENTS_EXCEEDED = '(Max Agents Exceeded)'
            ENABLE = 'Enable'
            DISABLE = 'Disable'
            SCANNING = 'Scanning'
            ENABLE_CLUSTER_WARNING = 'Are you sure you want to enable clustering? PLEASE NOTE: This setting can not ' \
                                     'be reversed, and will cause the Nessus backend to reload.'
            CREATE_NEW_OPTION = "Create new ..."

        class Settings:
            """Constants related to Agent settings"""
            PREVENT_SCAN = 'Prevent agent scans'
            PREVENT_CORE_UPDATES = 'Prevent core updates'
            PREVENT_PLUGIN_UPDATES = 'Prevent plugin updates'
            PERMANENT_BLACKOUT_WINDOW = 'Enforce permanent blackout window'

        class AgentLogMessages:
            """Agent log file messages related constants"""
            FAILED_WITH_STATUS_401 = 'failed with status 401'
            ASKED_TO_RELINK_BY_PARENT_NODE = 'Asked to relink; attempting an immediate relink'
            RECEIVED_401_FROM_MANAGER = 'Received unlinking code 410|Bad agent|from manager'
            NOT_LINKED_TO_MANAGER = 'Link status: Not linked to a manager'
            STAGGERED_START_CALCULATION = 'Staggered start calculation'
            DUPLICATE_AGENT_FOUND = "Duplicate agent found"

        class InstallAgentOnAWS:
            BUILD_PATH = {
                'CentOS8': "/install/NessusAgent-*-es8.x86_64.rpm",
            }
            PREFERENCE_RETRIEVE_FAILURES = ["Preferences do not exist yet", "Could not retrieve value for"]
            OS_COMMANDS = {
                'CentOS8': {'search_agent': 'rpm -qa | grep NessusAgent',
                            'remove_agent': 'rpm -e ', 'install_agent': 'rpm -ivh ',
                            'upgrade_agent': 'rpm -Uvh', "download": "curl",
                            'set_download_path': '--output'}
            }

        class AgentsUpdates:
            """  """
            AGENT_UPDATES_DESCRIPTION = "Configure the Agent Update plan for the Agents linked to this Nessus Manager."
            AGENT_UPDATE_TAB = "Agent Updates"
            AGENT_UPDATES_ROUTE = "/#/sensors/agent-updates"
            TOOLTIP_FOR_EA = "Update to the newest Nessus Agent version as soon as it is released for Early Access, " \
                             "typically a few weeks before general availability."
            TOOLTIP_FOR_GA = "Update to the latest Nessus Agent release as soon as it is made generally available."
            TOOLTIP_FOR_STABLE = "Remain on an earlier version of Nessus Agent, " \
                                 "at least one release older than the current GA version."
            GA_FEED_BOX_LABEL = "General Availability:"
            EA_FEED_BOX_LABEL = "Early Access:"
            STABLE_FEED_BOX_LABEL = "Stable:"
            LAST_CHECKED_FEED_BOX_LABEL = "Last checked available versions:"
            DOWNLOADED_VERSION_FEED_BOX_LABEL = "Currently downloaded version:"
            UPDATED_FEED_BOX_LABEL = "Last updated:"
            ENABLE_AGENT_UPDATE_TEXT = "Enable Agent Updates"
            DEFAULT_FEED_VALUE = True
            EXPECTED_LABELS = ['General Availability:',
                               'Early Access:',
                               'Stable:',
                               'Last checked available versions:',
                               'Currently downloaded version:',
                               'Last updated:']

        class AgentsProfiles:
            """  Agent Profiles tab under Sensor tab of Nessus Manager"""
            AGENT_PROFILE_DESCRIPTION = ("You can use agent profiles to apply a specific version to your linked agents."
                                         " This can be helpful for testing; for example, you may want to schedule a"
                                         " testing period on a subset of your agents before upgrading all your agents"
                                         " to a new version. An agent profile allows you to apply a newer version to"
                                         " a subset of your agents for a limited time, and more broadly, allows you to"
                                         " upgrade and downgrade agents to different versions easily. You can only"
                                         " assign an agent to one profile.")

            AGENT_PROFILES_TAB = "Agent Profiles"
            AGENT_PROFILES_ROUTE = "/#/sensors/agent-profiles"

    class AgentGroups:
        """Constants related to agent groups"""
        NEW_AGENT_GROUP = 'New Agent Group'
        AGENT_GROUP_HEADER = 'Agent Groups'
        EDIT_AGENT_GROUP = 'Edit Agent Group'
        WATERMARK_FOR_EMPTY_AGENT = 'No agents have been added.'

    class SideNavResources:
        """Nessus resources in side navigation bar."""
        AGENTS = "Agents"
        PLUGIN_RULES = "Plugin Rules"
        POLICIES = "Policies (P)"
        SCANNERS = "Scanners"
        CUSTOMIZED_REPORTS = "Customized Reports"
        LINKED_AGENTS = "Linked Agents"
        GROUPS = "Groups"
        CLUSTER_MIGRATION = "Cluster Migration"
        FREEZE_WINDOWS = "Freeze Windows"
        ACTIVITY = "Agent Activity"
        AGENT_CLUSTERING = "Agent Clustering"
        COMMUNITY = "Community"
        RESEARCH = "Research"
        AGENT_GROUPS = "Agent Groups"
        MY_SCANS = "My Scans (S)"
        ALL_SCANS = "All Scans"
        TRASH = "Trash"
        ALL_RESOURCES = [AGENTS, PLUGIN_RULES, CUSTOMIZED_REPORTS, POLICIES, SCANNERS]
        SENSOR_LINK_TABS = [SCANNERS, LINKED_AGENTS, GROUPS, CLUSTER_MIGRATION, FREEZE_WINDOWS, ACTIVITY]

        SCANS_SUB_MENU = {MY_SCANS: "#/scans/folders/my-scans", ALL_SCANS: "#/scans/folders/all-scans",
                          TRASH: "#/scans/folders/trash", POLICIES: "#/scans/policies",
                          PLUGIN_RULES: "#/scans/plugin-rules", CUSTOMIZED_REPORTS: "#/scans/custom-reports"}

        SENSORS_SUB_MENU = {LINKED_AGENTS: "#/sensors/agents", AGENT_GROUPS: "#/sensors/agent-groups",
                            AGENT_CLUSTERING: "#/sensors/agent-cluster-migration",
                            FREEZE_WINDOWS: "#/sensors/agent-freeze-windows", SCANNERS: "#/sensors/scanners"}

    class SideNavAccounts:
        """Nessus accounts in side navigation bar."""
        GROUPS = "Groups (G)"
        MY_ACCOUNT = "My Account (M)"
        USERS = "Users (U)"
        ALL_ACCOUNTS = [GROUPS, MY_ACCOUNT, USERS]

        class Users:
            """ Constants related to Users """
            TRANSFER_USER_DATA = 'Transfer User Data'
            TRANSFER_USER_DATA_WARNING = 'Warning: Transferring user data transfers ownership of all policies, ' \
                                         'scans, scan results, and plugin rules to you. This action cannot be undone.'
            DELETE_SINGLE_USER = 'Delete User'
            DELETE_SINGLE_USER_WARNING = 'Warning: Deleting a user results in the deletion of all the user\'s ' \
                                         'policies, scans and scan results. This action cannot be undone. Are you ' \
                                         'sure you want to delete this user?'
            DELETE_MULTIPLE_USER = 'Delete Users'
            DELETE_MULTIPLE_USER_WARNING = 'Warning: Deleting users results in the deletion of selected users ' \
                                           'policies, scans and scan results. This action cannot be undone. Are you ' \
                                           'sure you want to delete these users?'
            TRANSFER_OWNERSHIP_MESSAGE = 'Transfer ownership of user owned scans, policies, and plugin rules to you ' \
                                         'instead of deleting.'

        class Groups:
            """ Constants related to Groups """
            DELETE_SINGLE_GROUP = 'Delete Group'
            DELETE_MULTIPLE_GROUP = 'Delete Groups'
            DELETE_SINGLE_GROUP_WARNING = 'Are you sure you want to delete this group?'
            DELETE_MULTIPLE_GROUP_WARNING = 'Are you sure you want to delete these groups?'
            REMOVE_USER = 'Remove User'
            REMOVE_USER_WARNING = 'Are you sure you want to remove this user from the group?'

    class SideNavSettings:
        """Nessus settings in side navigation bar."""
        ABOUT = "About (C)"
        ADVANCED = "Advanced"
        CUSTOM_CA = "Custom CA"
        LDAP_SERVER = "LDAP Server"
        PASSWORD_MGMT = "Password Management"
        PROXY_SERVER = "Proxy Server"
        SMTP_SERVER = "SMTP Server"
        SCANNER_HEALTH = "Scanner Health"
        REMOTE_LINK = "Remote Link"
        DEBUG_LOGS = "Debug Logs"
        UPGRADE_ASSISTANT = "Upgrade Assistant"
        NOTIFICATIONS = "Notification Logs"

        SETTINGS_SUB_MENU = {
            ABOUT: "#/settings/about", ADVANCED: "#/settings/advanced", PROXY_SERVER: "#/settings/proxy-server",
            SMTP_SERVER: "#/settings/smtp-server", CUSTOM_CA: "#/settings/custom-ca",
            UPGRADE_ASSISTANT: "#/settings/migrate", PASSWORD_MGMT: "#/settings/password-management",
            SCANNER_HEALTH: "#/settings/scanner-health", NOTIFICATIONS: "#/settings/notifications"}

    class DebugLogs:
        """ Constants related to Debug Logs Page """
        EMPTY_LOGS_MESSAGE = "No logs have been created."
        DEBUG_LOGS_TABLE_COLUMNS = ['Filename', 'Start Time', 'End Time', 'Last Modified']
        DELETE_LOG = "Delete Log"
        DELETE_LOG_WARNING = "Are you sure you want to delete this log?"
        DELETE_LOGS = "Delete Logs"
        DELETE_LOGS_WARNING = "Are you sure you want to delete these logs?"
        NO_RECORDS_FOUND_MSG = "No records found."

    class Accounts:
        """Nessus accounts in side navigation bar."""
        MY_ACCOUNT = "My Account (M)"
        USERS = "Users (U)"
        GROUPS = "Groups (G)"
        MY_ACCOUNT_TITLE = "My Account"

    class ScannerHealth:
        """ Constants related to scanner health page. """
        SCANNER_HEALTH = "Scanner Health"
        OVERVIEW = "Overview"
        NETWORK = "Network"
        ALERTS = "Alerts"
        OVERVIEW_SUBHEADERS_LIST = ["CURRENT HEALTH", "SCANNER ALERTS", "SYSTEM MEMORY", "NESSUS DATA DISK SPACE",
                                    "MEMORY USAGE HISTORY", "CPU USAGE HISTORY", "SCANNING HISTORY"]
        CURRENT_HEALTH_COUNT_LABELS = ["NESSUS MEMORY USED", "CPU LOAD", "HOSTS BEING SCANNED"]
        NETWORK_SUBHEADERS_LIST = ["SCANNING HISTORY", "NETWORK CONNECTIONS", "NETWORK TRAFFIC",
                                   "NUMBER OF DNS LOOKUPS", "DNS LOOKUP TIME"]
        TIME_RANGE_OPTIONS = ["Past hour", "Past 3 hours", "Past 6 hours", "Past 12 hours", "Past 24 hours",
                              "Past 2 days", "Past week"]
        PAST_24_HOURS = "Past 24 hours"

        class OverviewTab:
            """ Constants related to Overview tab under scanner health page """
            OTHER = 'Other'
            NESSUS = 'Nessus'
            USED = 'Used'
            FREE = 'Free'
            MEMORY_USAGE_HISTORY = 'MEMORY USAGE HISTORY'
            CPU_USAGE_HISTORY = 'CPU USAGE HISTORY'

        class NetworkTab:
            """ Constants related to Network tab under scanner health page """
            SCANNING_HISTORY = 'SCANNING HISTORY'
            NETWORK_CONNECTIONS = 'NETWORK CONNECTIONS'
            NETWORK_TRAFFIC = 'NETWORK TRAFFIC'
            NUMBER_OF_DNS_LOOKUPS = 'NUMBER OF DNS LOOKUPS'
            DNS_LOOKUP_TIME = 'DNS LOOKUP TIME'

    class RegistrationPage:
        """ Constants related to Registration page. """
        WELCOME_HEADER = "Welcome to Nessus"
        SCANNERS_TYPE = ["Nessus Expert Trial", "Nessus Professional Trial", "Nessus Expert", "Nessus Professional",
                         "Nessus Manager", "Nessus Essentials", "Managed Scanner"]
        NESSUS_TYPE = ["Set up a purchased instance of Nessus", "Start a trial of Nessus Expert",
                       "Start a trial of Nessus Professional", "Register for Nessus Essentials",
                       "Link Nessus to another Tenable product"]
        ACTIVATION_CODE_HEADER = 'Get an activation code'
        ACTIVATION_CODE = 'Activation Code'
        LICENSE_INFORMATION = 'License Information'
        GET_STARTED = 'Get Started'
        EMAIL = 'nessus@tenable.com'

    class SystemReportTemplates:
        """
        Constants related to system templates for report generation.
        """
        DETAILED_VULNS_BY_HOST_WITH_COMP_REMEDIATION = 'Detailed Vulnerabilities By Host with Compliance/Remediations'
        DETIALED_VULNS_BY_HOST = 'Detailed Vulnerabilities By Host'
        DETAILED_VULNS_BY_PLUGINS_WITH_COMP_REMEDIATION = \
            'Detailed Vulnerabilities By Plugin with Compliance/Remediations'
        DETIALED_VULNS_BY_PLUGINS = 'Detailed Vulnerabilities By Plugin'
        SUMMARY_OF_OS = 'Summary of Operating Systems'
        COMPLETE_LIST_OF_VULNS_BY_HOST = 'Complete List of Vulnerabilities by Host'
        SUMMARY_OF_UNSUPPORTED_SOFTWARE = 'Summary of Unsupported Software'
        SUMMARY_OF_HOSTS_WITH_VULNS = 'Summary of Hosts with Vulnerabilities'
        SUMMARY_OF_VULNS_OLDER_THAN_ONE_YEAR = 'Summary of Vulnerabilities Older Than One Year'
        SUMMARY_OF_KNOWN_DEFAULT_ACCOUNTS = 'Summary of Known/Default Accounts'
        TOP_10_VULNS = 'Top 10 Vulnerabilities'
        SUMMARY_OF_EXPLOITABLE_VULNS = 'Summary of Exploitable Vulnerabilities'
        COMPLIANCE = 'Compliance'
        VULNS_OPTIONS = 'Vulnerability Operations'
        REMEDIATIONS = 'Remediations'

        PRO_SYSTEM_TEMPLATES = {DETAILED_VULNS_BY_HOST_WITH_COMP_REMEDIATION, DETIALED_VULNS_BY_HOST,
                                DETAILED_VULNS_BY_PLUGINS_WITH_COMP_REMEDIATION, DETIALED_VULNS_BY_PLUGINS,
                                SUMMARY_OF_OS, COMPLETE_LIST_OF_VULNS_BY_HOST, SUMMARY_OF_UNSUPPORTED_SOFTWARE,
                                SUMMARY_OF_HOSTS_WITH_VULNS, SUMMARY_OF_VULNS_OLDER_THAN_ONE_YEAR,
                                SUMMARY_OF_KNOWN_DEFAULT_ACCOUNTS, TOP_10_VULNS, SUMMARY_OF_EXPLOITABLE_VULNS,
                                COMPLIANCE, VULNS_OPTIONS, REMEDIATIONS}
        MANAGER_SYSTEM_TEMPLATES = {DETAILED_VULNS_BY_HOST_WITH_COMP_REMEDIATION, DETIALED_VULNS_BY_HOST,
                                    DETAILED_VULNS_BY_PLUGINS_WITH_COMP_REMEDIATION, DETIALED_VULNS_BY_PLUGINS,
                                    COMPLETE_LIST_OF_VULNS_BY_HOST, COMPLIANCE, VULNS_OPTIONS, REMEDIATIONS}
        HOME_SYSTEM_TEMPLATES = {COMPLETE_LIST_OF_VULNS_BY_HOST, DETIALED_VULNS_BY_HOST,
                                 DETIALED_VULNS_BY_PLUGINS, VULNS_OPTIONS}

        class TemplatesTable:
            """ Constants related to Templates Table. """
            TEMPLATE_NAME_COLUMN = "Template Name"
            TEMPLATE_TYPE_COLUMN = "Type"
            LAST_MODIFIED_COLUMN = "Last Modified"
            ALL_COLUMNS = [TEMPLATE_NAME_COLUMN, TEMPLATE_TYPE_COLUMN, LAST_MODIFIED_COLUMN]

        class TemplateType:
            """ Constants related to Templates Types. """
            SYSTEM = "System"
            CUSTOM = "Custom"

    class PluginDownloadFailedPage:
        """ Constants related to Plugin download failed page. """
        DOWNLOAD_FAILED = "Download Failed"
        INSTALLATION_EXPIRED = 'Installation Expired'

    class AcknowledgementModal:
        """ Constants related to Acknowledgement modal """
        ACKNOWLEDGEMENT_MODAL_TEXT_LIST = ["This notification is present on all platforms",
                                           "This notification is present on Linux",
                                           "This notification is present on MacOS",
                                           "This notification is present on Windows",
                                           "This notification is present on FreeBSD",
                                           "This is never shown because the platform never matches.",
                                           "This notification exists to be acknowledged.",
                                           "This notification exists to be acknowledged and duration is 30 seconds.",
                                           "This notification exists to be acknowledged and duration is 40 seconds.",
                                           "This notification exists to be acknowledged for test history.",
                                           "This notification exists to be acknowledged.",
                                           "This notification exists to be acknowledged and duration is 6 seconds.",
                                           "This notification was already expired.",
                                           "This notification is not yet active.",
                                           "This notification is not yet expired.",
                                           "This notification is not yet expired.",
                                           "This notification is not yet expired.", "Modal Medium.", "Modal Low.",
                                           "Modal High.", "Banner Medium.", "Banner Low", "Banner High.",
                                           "Banner Permanent.", "Login Medium.", "Login Low.", "Login High."]

    class PluginRules:
        """ Constants related to Plugin rules page """
        SINGLE_DELETE_MODAL_HEADER = "Delete Rule"
        BULK_DELETE_MODAL_HEADER = "Delete Rules"
        SINGLE_DELETE_MODAL_CONTENT = "Are you sure you want to delete this rule?"
        BULK_DELETE_MODAL_CONTENT = "Are you sure you want to delete these rules?"

    class UpgradeAssistant:
        """ Constants related to Upgrade Assistant page """
        SIGN_UP_URL = "https://www.tenable.com/products/tenable-io/evaluate"
        ACCESS_KEY = "Access Key"
        SECRET_KEY = "Secret Key"
        TENABLE_IO_DOMAIN = "Tenable.io domain"
        NESSUS_IDENTIFIER = "Nessus instance"
        ACCESS_KEY_TOOLTIP = "An access key can be generated from your administrator user account in Tenable Vulnerability Management"
        SECRET_KEY_TOOLTIP = "A secret key can be generated from your administrator user account in Tenable Vulnerability Management"
        TENABLE_IO_DOMAIN_TOOLTIP = "Tenable Vulnerability Management domain to use when migrating users"
        NESSUS_IDENTIFIER_TOOLTIP = "Specify a unique identifier for this Nessus instance"
        CONFIRM_UPGRADE = "Confirm Upgrade"
        CONFIRM_UPGRADE_MODAL_CONTENT = "Are you sure you want to upgrade this scanner to Tenable.io? All scans will " \
                                        "be disabled and enabled in Tenable.io upon successful migration."
        CONFIRM_UPGRADE_WARNING = "NOTICE: This process can not be reversed."
        UPGRADE_ASSISTANT_DESCRIPTION = "This tool will migrate your Nessus data to Tenable Vulnerability Management. " \
                                        "After the initial migration is complete, any linked scanners and agents will" \
                                        " be upgraded to the latest version available, if necessary, and will" \
                                        " automatically be relinked to Tenable Vulnerability Management. " \
                                        "You will also be able to setup a scan history migration. You will need a " \
                                        "Tenable Vulnerability Management account to begin the process. " \
                                        "Please choose an option below to get started."
        UPGRADDDE_NOW_DESCRIPTION = 'I have a Tenable.io account'
        SIGN_UP_FIRST_DESCRIPTION = 'I need a Tenable.io account'

    class RemoteLink:
        """ Constants related to Remote Link page """
        LINK_TO = 'Link to'
        SCANNER_NAME = 'Scanner Name'
        MANAGER_HOST = 'Manager Host'
        MANAGER_PORT = 'Manager Port'
        LINKING_KEY = 'Linking Key'
        USE_PROXY = 'Use Proxy'
        NESSUS_MANAGER = 'Nessus Manager'
        TENABLE_IO = 'Tenable.io'
        LINK_TO_OPTIONS = [TENABLE_IO, NESSUS_MANAGER]

    class TopTenVulnerabilitiesReport:
        """Constants related to top ten vulnerabilities report"""

        TOP_TEN_VULNS_TITLE = 'Advanced Scan for Top 10 vulns'
        TABLE_OF_CONTENTS = 'TABLE OF CONTENTS'
        OVERVIEW = 'Overview'
        VULN_INSTANCES = 'Vulnerability Instances: all and exploitable, by severity'
        TOP_TEN_CRITICAL_VULN = 'Top 10 Critical Vulnerabilities'
        TOP_TEN_CRITICAL_VPR = 'Top 10 Critical Vulnerabilities: (VPR)'
        TOP_TEN_CRITICAL_EPSS = 'Top 10 Critical Vulnerabilities: (EPSS)'
        TOP_TEN_CRITICAL_CVSS_V3 = 'Top 10 Critical Vulnerabilities: (CVSS v3.0)'
        TOP_TEN_HIGH_VULN = 'Top 10 High Vulnerabilities'
        TOP_TEN_HIGH_VPR = 'Top 10 High Vulnerabilities: (VPR)'
        TOP_TEN_HIGH_EPSS = 'Top 10 High Vulnerabilities: (EPSS)'
        TOP_TEN_HIGH_CVSS_V3 = 'Top 10 High Vulnerabilities: (CVSS v3.0)'
        TOP_TEN_HIGH_CVSS_V4 = 'Top 10 High Vulnerabilities: (CVSS v4.0)'
        TOP_TEN_MOST_PREVALENT_VULN = 'Top 10 Most Prevalent Vulnerabilities'
        TOP_TEN_MOST_PREVALENT_VPR = 'Top 10 Most Prevalent Vulnerabilities: (VPR)'
        TOP_TEN_MOST_PREVALENT_EPSS = 'Top 10 Most Prevalent Vulnerabilities: (EPSS)'
        TOP_TEN_MOST_PREVALENT_CVSS_V3 = 'Top 10 Most Prevalent Vulnerabilities: (CVSS v3.0)'
        TOP_TEN_CRITICAL_CVSS_V2 = 'Top 10 Critical Vulnerabilities: (CVSS v2.0)'
        TOP_TEN_HIGH_CVSS_V2 = 'Top 10 High Vulnerabilities: (CVSS v2.0)'
        TOP_TEN_MOST_PREVALENT_CVSS_V2 = 'Top 10 Most Prevalent Vulnerabilities: (CVSS v2.0)'
        TABLE_OF_CONTENTS_LIST_CVSS_V3 = [TABLE_OF_CONTENTS, OVERVIEW, VULN_INSTANCES, TOP_TEN_CRITICAL_VULN,
                                          TOP_TEN_CRITICAL_VPR, TOP_TEN_CRITICAL_EPSS, TOP_TEN_CRITICAL_CVSS_V3,
                                          TOP_TEN_HIGH_VULN,
                                          TOP_TEN_HIGH_VPR, TOP_TEN_HIGH_EPSS, TOP_TEN_HIGH_CVSS_V3,
                                          TOP_TEN_MOST_PREVALENT_VULN,
                                          TOP_TEN_MOST_PREVALENT_VPR, TOP_TEN_MOST_PREVALENT_EPSS,
                                          TOP_TEN_MOST_PREVALENT_CVSS_V3]
        TABLE_OF_CONTENTS_LIST_CVSS_V2 = [TABLE_OF_CONTENTS, OVERVIEW, VULN_INSTANCES, TOP_TEN_CRITICAL_VULN,
                                          TOP_TEN_CRITICAL_VPR, TOP_TEN_CRITICAL_EPSS, TOP_TEN_CRITICAL_CVSS_V2,
                                          TOP_TEN_HIGH_VULN,
                                          TOP_TEN_HIGH_VPR, TOP_TEN_HIGH_EPSS, TOP_TEN_HIGH_CVSS_V2,
                                          TOP_TEN_MOST_PREVALENT_VULN,
                                          TOP_TEN_MOST_PREVALENT_VPR, TOP_TEN_MOST_PREVALENT_EPSS,
                                          TOP_TEN_MOST_PREVALENT_CVSS_V2]
        VPR = "VPR"
        CVSS_V3 = "CVSS v3.0"
        CVSS_V2 = "CVSS v2.0"

    class FreezeWindows:
        """ Constants related to freeze window """
        FREEZE_WINDOW_DESCRIPTION = "Freeze Windows allow you to prevent any combination of agent software updates, " \
                                    "plug-in updates and scans from being installed or executed, " \
                                    "based on a given schedule. Rules that impact Freeze Windows can be configured " \
                                    "in the Agent Settings tab. Freeze Windows apply to all linked agents. " \
                                    "From this page you can view, create, edit or delete Freeze Windows."
        FREEZE_WINDOW_TITLE = "Freeze Windows"
        NEW_FREEZE_WINDOW_TITLE = "New Freeze Window"
        CREATE_FREEZE_WINDOW = "Create a new freeze window"
        FREEZE_WINDOW_TAB = "Freeze Windows"
        AGENT_FREEZE_WINDOW = "agent-freeze-windows"
        NEW_FREEZE_WINDOW = "agent-freeze-windows/new"
        DELETE_FW_POP_UP_TITLE = 'Delete Freeze Window'
        DELETE_FW_POP_UP_TEXT = 'Are you sure you want to delete this freeze window?'
        FREEZE_WINDOW = "Freeze Window"
        FREEZE_WINDOW_SETTING_OPTIONS = [
            'When checked, a permanent freeze window schedule is enforced and rules configured below are applied.',
            'When checked, agents do not receive software updates during scheduled freeze windows.',
            'When checked, agents do not receive plugin updates during scheduled freeze windows.',
            'When checked, the system does not run agent scans during scheduled freeze windows.']

    class CustomizedReports:
        """ Constants related to Customized Reports Page """
        LIST_OF_VULNS_BY_HOST = "Complete List of Vulnerabilities by Host"
        COMPLIANCE = "Compliance"
        DETAILED_VULNS_BY_HOST = "Detailed Vulnerabilities By Host"
        DETAILED_VULNS_BY_HOST_WITH_COMPLIANCE = "Detailed Vulnerabilities By Host with Compliance/Remediations"
        DETAILED_VULNS_BY_PLUGINS = "Detailed Vulnerabilities By Plugin"
        DETAILED_VULNS_BY_PLUGINS_WITH_COMPLIANCE = "Detailed Vulnerabilities By Plugin with " \
                                                    "Compliance/Remediations"
        KNOWN_ACCOUNTS_DETAILS = "Known/Default Account Details"
        REMEDIATIONS = "Remediations"
        EXPLOITABLE_VULNS = "Summary of Exploitable Vulnerabilities"
        HOSTS_WITH_VULNS = "Summary of Hosts with Vulnerabilities"
        VULNS_OLDER_THAN_YEAR = "Summary of Vulnerabilities Older Than One Year"
        YEAR_OLD_VULNS = "Summary of Hosts with Vulnerabilities > 1 Year Old"
        KNOWN_DEFAULT_ACCOUNTS_SUMMARY = "Summary of Known/Default Accounts"
        OS_SYSTEM = "Summary of Operating Systems"
        UNSUPPORTED_SOFTWARE = "Summary of Unsupported Software"
        VULN_HOSTS_SUMMARY = "Summary of Vulnerabilities by Host"
        TOP_10_VULNS = "Top 10 Vulnerabilities"
        TOP_X_VULNS = "Top X Vulnerabilities"
        VULN_OPERATION = "Vulnerability Operations"
        GROUP2_REPORT_OPTIONS = ['STIG Severity', 'CVSS v4.0 Base Score', 'CVSS v4.0 Base+Threat Score',
                                 'CVSS v3.0 Base Score',
                                 'CVSS v2.0 Temporal Score', 'CVSS v3.0 Temporal Score', 'VPR Score', 'EPSS Score',
                                 'Risk Factor',
                                 'References', 'Plugin Information', 'Exploitable With']

        class ReportChapters:
            """ Constants related to Report Chapters """
            UP_ARROW = "Up"
            DOWN_ARROW = "Down"
            MOVE_CHAPTER_UP = "Move chapter up"
            MOVE_CHAPTER_DOWN = "Move chapter down"
            DELETE_CHAPTER = "Delete chapter"

            COMPLIANCE_DESCRIPTION = "Performs a compliance check on the scan results."
            VULN_BY_HOST_DESCRIPTION = "List all vulnerabilities by host"
            VULN_BY_PLUGIN_DESCRIPTION = "List all vulnerabilities by plugin"
            KNOWN_ACCOUNT_DETAILS_DESCRIPTION = "Reports actionable details on the most prevalent known and default " \
                                                "accounts detected during the scan."
            REMEDIATIONS_DESCRIPTION = "Presents remediation recommendations based on the scan results."
            EXPLOITABLE_VULNS_DESCRIPTION = "Reports on the top vulnerabilities found in the scan for which there " \
                                            "are known exploits."
            HOSTS_VULNS_DESCRIPTION = "Reports on the most vulnerable hosts detected during the scan."
            YEAR_OLD_VULNS_DESCRIPTION = "Reports on hosts with vulnerabilities older than one year."
            KNOWN_ACCOUNT_DESCRIPTION = "Reports on the known/default accounts detected during the scan."
            OS_SYSTEM_DESCRIPTION = "Reports on Operating Systems detected during the scan."
            UNSUPPORTED_SOFTWARE_DESCRIPTION = "Reports on unsupported software detections from the scan."
            VULN_HOSTS_SUMMARY_DESCRIPTION = "Provides a per-host list of vulnerabilities."
            TOP_X_VULNS_DESCRIPTION = "Reports on the most prevalent vulnerabilities detected during the scan."

            EMPTY_CHAPTER_MESSAGE = 'No chapters have been added. Click the "Add a Chapter" button to add chapters.'
            ADD_CHAPTER_MODAL_TITLE = "Add a Report Chapter"
            DELETE_CHAPTER_MODAL_TITLE = "Delete Chapter"
            DELETE_CHAPTER_WARNING = "Are you sure to delete this chapter?"

        class ReportTemplates:
            """ Constants related to Report Templates """
            LIST_OF_VULNS_BY_HOST_DESCRIPTION = "This report provides a summary list of vulnerabilities for each " \
                                                "host detected in the scan."
            COMPLIANCE_DESCRIPTION = "This report provides compliance violations found in the scan."
            VULNS_BY_HOST_DESCRIPTION = "This report presents detailed vulnerabilities by host."
            VULNS_BY_HOST_WITH_COMPLIANCE_DESCRIPTION = "This report presents detailed vulnerabilities by host, " \
                                                        "including the compliance and remediations checks."
            VULNS_BY_PLUGINS_DESCRIPTION = "This report presents detailed vulnerabilities by plugin."
            VULNS_BY_PLUGINS_WITH_COMPLIANCE_DESCRIPTION = "This report presents detailed vulnerabilities by plugin, " \
                                                           "including the compliance and remediations checks."
            REMEDIATIONS_DESCRIPTION = "This report provides remediation recommendations for the scan."
            EXPLOITABLE_VULNS_DESCRIPTION = "This report provides a summary of the most prevalent exploitable " \
                                            "vulnerabilities."
            HOSTS_VULNS_DESCRIPTION = "This report provides a summary of the most prevalent vulnerabilities, by host."
            VULNS_OLDER_THAN_YEAR_DESCRIPTION = "This report provides a summary of the most prevalent " \
                                                "vulnerabilities published more than a year ago."
            KNOWN_DEFAULT_ACCOUNTS_SUMMARY = "This report provides a summary of the most prevalent detections of " \
                                             "known and default accounts, along with actionable details for the " \
                                             "worst offenders."
            OS_SYSTEM_DESCRIPTION = "This report provides a summary of the most prevalent operating systems " \
                                    "detected on the network during the scan."
            UNSUPPORTED_SOFTWARE_DESCRIPTION = "This report provides system administrators with a summary of the " \
                                               "software that is no longer supported and puts the organization at " \
                                               "the most risk."
            TOP_10_VULNS_DESCRIPTION = "This report breaks down vulnerabilities by scoring system, presenting " \
                                       "results by rollup-count and severity scoring."
            VULN_OPERATION_DESCRIPTION = "This report lists host and vulnerability details for each host detected " \
                                         "in the scan."
            NO_CUSTOM_TEMPLATES_MESSAGE = "No custom templates created."
            BACK_TO_REPORT_TEMPLATE_LINK = "Back to Report Templates"

        CHAPTER_LIST = [COMPLIANCE, DETAILED_VULNS_BY_HOST, DETAILED_VULNS_BY_PLUGINS, KNOWN_ACCOUNTS_DETAILS,
                        REMEDIATIONS, EXPLOITABLE_VULNS, HOSTS_WITH_VULNS, YEAR_OLD_VULNS,
                        KNOWN_DEFAULT_ACCOUNTS_SUMMARY, OS_SYSTEM, UNSUPPORTED_SOFTWARE, VULN_HOSTS_SUMMARY,
                        TOP_X_VULNS]

        CHAPTERS_DICT = {
            COMPLIANCE: 'compliance', DETAILED_VULNS_BY_HOST: 'vuln_by_host', REMEDIATIONS: 'remediations',
            DETAILED_VULNS_BY_PLUGINS: 'vuln_by_plugin', HOSTS_WITH_VULNS: 'hosts_vulns', TOP_X_VULNS: 'top10',
            KNOWN_ACCOUNTS_DETAILS: 'known_accounts_details', EXPLOITABLE_VULNS: 'exploitable_vulns',
            OS_SYSTEM: 'oses_found', YEAR_OLD_VULNS: 'year_old_vulns', KNOWN_DEFAULT_ACCOUNTS_SUMMARY: 'known_accounts',
            UNSUPPORTED_SOFTWARE: 'unsupported_software', VULN_HOSTS_SUMMARY: 'vuln_hosts_summary'}

        CHAPTER_DESCRIPTION_DICT = {
            COMPLIANCE: ReportChapters.COMPLIANCE_DESCRIPTION,
            DETAILED_VULNS_BY_HOST: ReportChapters.VULN_BY_HOST_DESCRIPTION,
            DETAILED_VULNS_BY_PLUGINS: ReportChapters.VULN_BY_PLUGIN_DESCRIPTION,
            KNOWN_ACCOUNTS_DETAILS: ReportChapters.KNOWN_ACCOUNT_DETAILS_DESCRIPTION,
            REMEDIATIONS: ReportChapters.REMEDIATIONS_DESCRIPTION,
            EXPLOITABLE_VULNS: ReportChapters.EXPLOITABLE_VULNS_DESCRIPTION,
            HOSTS_WITH_VULNS: ReportChapters.HOSTS_VULNS_DESCRIPTION,
            YEAR_OLD_VULNS: ReportChapters.YEAR_OLD_VULNS_DESCRIPTION,
            KNOWN_DEFAULT_ACCOUNTS_SUMMARY: ReportChapters.KNOWN_ACCOUNT_DESCRIPTION,
            OS_SYSTEM: ReportChapters.OS_SYSTEM_DESCRIPTION,
            UNSUPPORTED_SOFTWARE: ReportChapters.UNSUPPORTED_SOFTWARE_DESCRIPTION,
            TOP_X_VULNS: ReportChapters.TOP_X_VULNS_DESCRIPTION,
            VULN_HOSTS_SUMMARY: ReportChapters.VULN_HOSTS_SUMMARY_DESCRIPTION}

        VULNS_DETAILS_OPTIONS = ['Synopsis', 'Description', 'See Also', 'Solution', 'Risk Factor',
                                 'CVSS v3.0 Base Score', 'CVSS v3.0 Temporal Score', 'CVSS v2.0 Base Score',
                                 'CVSS v2.0 Temporal Score', 'STIG Severity', 'References', 'Exploitable With',
                                 'Plugin Information', 'Plugin Output']

        DEFAULT_TEMPLATES = [LIST_OF_VULNS_BY_HOST, COMPLIANCE, DETAILED_VULNS_BY_HOST, VULN_OPERATION, REMEDIATIONS,
                             DETAILED_VULNS_BY_HOST_WITH_COMPLIANCE, DETAILED_VULNS_BY_PLUGINS,
                             DETAILED_VULNS_BY_PLUGINS_WITH_COMPLIANCE]

        PRO_REPORT_TEMPLATES = [EXPLOITABLE_VULNS, TOP_10_VULNS, HOSTS_WITH_VULNS, UNSUPPORTED_SOFTWARE, OS_SYSTEM,
                                KNOWN_DEFAULT_ACCOUNTS_SUMMARY, VULNS_OLDER_THAN_YEAR]

        TEMPLATE_DESCRIPTION_DICT = {
            LIST_OF_VULNS_BY_HOST: ReportTemplates.LIST_OF_VULNS_BY_HOST_DESCRIPTION,
            COMPLIANCE: ReportTemplates.COMPLIANCE_DESCRIPTION,
            DETAILED_VULNS_BY_HOST: ReportTemplates.VULNS_BY_HOST_DESCRIPTION,
            DETAILED_VULNS_BY_HOST_WITH_COMPLIANCE: ReportTemplates.VULNS_BY_HOST_WITH_COMPLIANCE_DESCRIPTION,
            DETAILED_VULNS_BY_PLUGINS: ReportTemplates.VULNS_BY_PLUGINS_DESCRIPTION,
            DETAILED_VULNS_BY_PLUGINS_WITH_COMPLIANCE: ReportTemplates.VULNS_BY_PLUGINS_WITH_COMPLIANCE_DESCRIPTION,
            REMEDIATIONS: ReportTemplates.REMEDIATIONS_DESCRIPTION,
            EXPLOITABLE_VULNS: ReportTemplates.EXPLOITABLE_VULNS_DESCRIPTION,
            HOSTS_WITH_VULNS: ReportTemplates.HOSTS_VULNS_DESCRIPTION,
            KNOWN_DEFAULT_ACCOUNTS_SUMMARY: ReportTemplates.KNOWN_DEFAULT_ACCOUNTS_SUMMARY,
            OS_SYSTEM: ReportTemplates.OS_SYSTEM_DESCRIPTION,
            UNSUPPORTED_SOFTWARE: ReportTemplates.UNSUPPORTED_SOFTWARE_DESCRIPTION,
            VULNS_OLDER_THAN_YEAR: ReportTemplates.VULNS_OLDER_THAN_YEAR_DESCRIPTION,
            TOP_10_VULNS: ReportTemplates.TOP_10_VULNS_DESCRIPTION,
            VULN_OPERATION: ReportTemplates.VULN_OPERATION_DESCRIPTION}


class Prefixes:
    """Prefixes used in randomly generated test objects"""
    USER = 'auto-'
    CONTAINER = 'automation-'
    GROUP = 'group-'
    AGENT_GROUP = 'AgentGroup-'


class ReportParanoiaTypes(Enum):
    """Report Paranoia constants"""
    AVOID_POTENTIAL_FALSE_ALARMS = 'Avoid false alarms'
    SHOW_POTENTIAL_FALSE_ALARMS = 'Paranoid (more false alarms)'


class System:
    """Strings related to System level commands."""
    LINUX_AUDIT_WAREHOUSE = '/opt/nessus/var/nessus/audits/audit_warehouse.audit'


class OperatingSystems:
    """different flavour of os"""
    BSD = 'bsd'
    FREEBSD = 'freebsd'
    LINUX = 'linux'
    MAC = 'osx'
    MAC_OS = 'mac'
    OTHER = 'other'
    WINDOWS = 'windows'


class SortOrder:
    """Types of sorting order."""
    ASCENDING = "asc"
    DESCENDING = "desc"
    VALID_ORDERS = [ASCENDING, DESCENDING]


class NessusCli:
    """constant for Nessus CLI"""
    LINUX_TIMESTAMP_DMYHMS = '%d/%b/%Y %H:%M:%S'
    WINDOWS_TIMESTAMP_DMYHMS = "{dd/MMM/yyyy HH:mm:ss}"
    BACKEND_LOG = 'backend.log'
    CUSTOM_CA_INC = 'custom_CA.inc'
    PASSWORD_SET = 'New password is set'
    FOP_JAR_FILE_VERSION = "2.6"
    NESSUSCLI_LOG = "nessuscli.log"

    class BugReportGenerator:
        """Constants related to bug report generator command"""
        CA_CERT = "cacert.pem"
        SERVER_CERT = "servercert.pem"
        LICENSE_INFO = "license_info.txt"
        CERT_CHECK = "cert_check.txt"
        AUTO_CONFIGURE = ".autoconfigure.json"
        PRODUCT_SUMMARY = "product_summary.txt"
        TAR_FILE_NAME = "nessus-bug-report-archive.tar.gz"
        ZIP_FILE_NAME = "nessus-bug-report-archive.zip"
        BUG_REPORT_CERT_FILES = [CA_CERT, SERVER_CERT]
        BUG_REPORT_ADDITIONAL_FILES = [CERT_CHECK, AUTO_CONFIGURE, PRODUCT_SUMMARY]
        BUG_REPORT_FILES_DIR = "bug_report"
        CERT_CHECK_LOGS = {'[debug] Custom handler called for certCheck', '[debug] Completed custom handler.'}
        AUTO_CONFIGURE_JSON = '{"user":{},"preferences":{},"link":{"host":"sensor.cloud.tenable.com","port":443}}'
        PRODUCT_SUMMARY_TAGS_MANAGER = ['Engine', 'Product', 'Package', 'Name', 'Type', 'IPs', 'WAS FQDNs', 'WAS Image ID',
                                        'ASD Domains', 'ASD Sub-Domains', 'Scanners', 'Agents',
                                        'Expiration Date', 'Features', 'remote_scanners', 'agent_activity',
                                        'agent_update_channel', 'policies', 'cluster_groups', 'scan_summary', 'report',
                                        'cluster', 'agent_groups', 'users', 'ldap', 'agents', 'agent_settings', 'offline', 'vpr',
                                        'plugin_rules', 'migration', 'scan_api', 'folders', 'api', 'local_scanner',
                                        'scanner_update_channel', 'logs', 'agent_freeze_windows', 'custom_reports',
                                        'epss',
                                        'groups', 'remote_settings', 'agent_profiles', 'software_update', 'smtp',
                                        'dashboards']

        PRODUCT_SUMMARY_TAGS_PRO = ['Engine', 'Product', 'Package', 'Name', 'Type', 'IPs', 'WAS FQDNs', 'WAS Image ID', 'ASD Domains',
                                    'ASD Sub-Domains', 'Scanners', 'Agents', 'Expiration Date', 'Features', 'policies', 'scan_summary', 'report', 'remote_link', 'cluster',
                                    'live_results', 'plugin_locale', 'users', 'offline', 'vpr', 'plugin_rules', 'migration',
                                    'scan_api', 'api', 'folders', 'local_scanner', 'scanner_update_channel',
                                    'email_reports', 'custom_reports', 'logs', 'epss', 'tools_was', 'software_update',
                                    'smtp']

    class ServerCertAndCaCert:
        """Constants related to servercert and cacert"""
        CERT_CONFIRMED = "The server cert {}/CA/servercert.pem is confirmed against CA cert {}/CA/cacert.pem"
        CERT_NOT_MATCH = "[info] The server cert {}/CA/servercert.pem does not match against CA cert {}/CA/cacert.pem"

    class BWPreferences:
        """Nessus Preferences related to Blackout window"""

        PERMANENT_BLACKOUT = 'bw_permanent_blackout_window'
        CORE_UPDATES = 'bw_prevent_core_updates'
        PLUGIN_UPDATES = 'bw_prevent_plugin_updates'
        AGENT_SCANS = 'bw_prevent_agent_scans'

    class BackupAndRestore:
        """Constants related to 'nessuscli backup' command"""

        BACKUP_COMMAND = "backup --create"
        RESTORE_COMMAND = "backup --restore"
        BACKUP_FILE_NAME = "nessus_backup.tar.gz"
        RESTORE_FAILURE = 'Please shut down the Nessus service before running backup --restore'
        DB_VERSION_CHECK_PASSED = "DB version check passed; continuing with restore operation."

    class ImportCerts:
        """Constants related to 'nessuscli import-certs' command"""
        IMPORT_CERT_COMMAND = "import-certs"
        IMPORT_CERTS_HELP_COMMAND = 'import-certs --help'
        IMPORT_CERTS_HELP = {'Description:', 'Commands:',
                             'Validates and imports the server key and server and CA certificates',
                             '(the key and certs must be provided; the server chain is optional).',
                             '--serverkey=<server key path>', '--cacert=<CA certificate path>',
                             '--servercert=<server certificate path>',
                             '[--serverchain=<server chain pem path>]',
                             'import-certs --serverkey=<KEYFILE> --servercert=<CERTFILE> --cacert=<CAFILE> [--serverchain=<CHAINFILE>]'}
        SERVER_CERT_PEM = "CA/servercert.pem"
        SERVER_KEY_PEM = "CA/serverkey.pem"
        CA_CERT_PEM = "CA/cacert.pem"
        CA_DIR_PATH = "CA"
        CORRECT_SERVER_CERT_PEM = "/tmp/servercert_correct.pem"
        CORRECT_SERVER_KEY_PEM = "/tmp/serverkey_correct.pem"
        INCORRECT_SERVER_CERT_PEM = "/tmp/servercert_incorrect.pem"
        INCORRECT_SERVER_KEY_PEM = "/tmp/serverkey_incorrect.pem"
        CORRECT_CA_CERT_PEM = "/tmp/cacert_correct.pem"
        INCORRECT_CA_CERT_PEM = "/tmp/cacert_incorrect.pem"
        INCORRECT_CERT_PEM_FILE_PATH = "/tmp/abc.pem"
        SUCCESSFUL_SERVER_CERT = ['New server certificate is valid; saving a copy of the old one and '
                                  'importing the new one.', 'Confirming that the certificates still match.',
                                  'Successfully imported certificate(s).']
        SUCCESSFUL_CA_CERT = ['New CA certificate is valid; saving a copy of the old one and importing the new one.',
                              'Confirming that the certificates still match.', 'Successfully imported certificate(s).']
        SUCCESSFUL_BOTH_CERTS = ['Saving a copy of the old key and certs and importing the new ones.',
                                 'Confirming imported key and certs.', 'Successfully imported key and certificates.']
        UNSUCCESSFUL_SERVER_CERT = 'Error: new server certificate could not be validated with the new CA certificate.'
        UNSUCCESSFUL_SERVER_KEY = 'Error: server key could not be validated against server cert.'
        PROVIDE_NECESSARY_INPUTS = ['You must provide the new server key, server certificate, and CA certificate, '
                                    'as a set.']
        UNSUCCESSFUL_CA_CERT = 'Error: CA certificate is invalid.'
        UNSUCCESSFUL_SERVER_CA_CERT = 'Error: CA certificate is invalid.'
        INCORRECT_PATH_ERROR = {'servercert': 'Error: Server certificate path not found.',
                                'cacert': 'Error: CA certificate path not found.',
                                'serverkey': 'Error: Server key path not found.'}
        MISSING_PATH_FOR_CERT = 'Please provide either a new CA certificate or new server certificate, or both.'

    class NessuscliHelp:
        """Constants related to 'nessuscli --help' command"""

        BUG_REPORT_CMD = 'Bug Reporting Commands:'
        USER_CMD = 'User Commands:'
        DUMP_CMD = 'Dump Commands:'
        MANAGER_CMD = 'Manager Commands:'
        FETCH_CMD = 'Fetch Commands:'
        NODE_CMD = 'Node Commands:'
        FIX_CMD = 'Fix Commands:'
        CERT_CMD = 'Certificate Commands:'
        BACK_UP_TOOL_CMD = 'Backup Tool:'
        ANALYZE_CMD = 'Analyze Commands:'
        SOFTWARE_UPDATE_CMD = 'Software Update Commands:'

        CMD_HEADERS_LIST = [BUG_REPORT_CMD, USER_CMD, DUMP_CMD, MANAGER_CMD, FETCH_CMD, FIX_CMD, CERT_CMD,
                            BACK_UP_TOOL_CMD, SOFTWARE_UPDATE_CMD]
        CMD_HEADERS_LIST_WO = [BUG_REPORT_CMD, USER_CMD, DUMP_CMD, FETCH_CMD, FIX_CMD, CERT_CMD,
                            BACK_UP_TOOL_CMD, SOFTWARE_UPDATE_CMD]
        HELP_CMD_VALIDATIONS = {"bug-report-generator": ['   bug-report-generator',
                                                         '   bug-report-generator --quiet [--full] [--scrub]'],
                                "user": ['   rmuser [username]', '   chpasswd [username]', '   adduser [username]',
                                         '   lsuser'],
                                "update": ['   update', '   update --all', '   update --plugins-only',
                                           '   update <plugin archive> [WAS plugin archive signature file] [--agent-version]'],
                                "analyze": ['   analyze scan <uuid>'],
                                "backup": ['   backup --create <backup filename> [--targz] [--include-backups]',
                                           '   backup --restore <backup file path>'],
                                "mkcert": ['   mkcert-client', '   mkcert [-q]'],
                                "fix": ['   fix [--secure] --list', '   fix [--secure] --set <name=value>',
                                        '   fix [--secure] --get <name>', '   fix [--secure] --delete <name>',
                                        '   fix --show', '   fix --show <name>', '   fix --list-interfaces',
                                        '   fix --reset'],
                                "node": ['   node link --key=<key> --host=<host> --port=<port>', '   node unlink',
                                         '   node status'],
                                "manager": ['   manager download-core', '   manager generate-plugins [--force]'],
                                "dump": ['   dump --plugins'],
                                "fetch": ['   fetch --register <serial>',
                                          '   fetch --register-offline <license.file>', '   fetch --check',
                                          '   fetch --code-in-use', '   fetch --challenge',
                                          '   fetch --security-center', '   fetch --scanner-health-stats']}


class NessusFilePath:
    """ File paths of Nessus """

    class Windows:
        """File paths for 'Windows' instance"""
        NESSUS_CLI = r'"C:/Program Files/Tenable/Nessus/nessuscli.exe"'
        NESSUSD = r'"C:/Program Files/Tenable/Nessus/nessusd.exe"'
        NESSUS_SBIN = r'"C:\Program Files\Tenable\Nessus"'
        NESSUS_VAR = r'C:\ProgramData\Tenable\Nessus\nessus'
        NESSUS_PLUGIN_DIR = r'C:/ProgramData/Tenable/Nessus/nessus/plugins'
        NESSUSD_DUMP = r'C:\ProgramData\Tenable\Nessus\nessus\logs\nessusd.dump'
        NESSUS_TOOLS_DIR = r'C:/ProgramData/Tenable/Nessus/nessus/tools'
        NESSUSD_MESSAGES = r'C:\ProgramData\Tenable\Nessus\nessus\logs\nessusd.messages'
        NESSUS_BACKEND_LOGS = r'C:\ProgramData\Tenable\Nessus\nessus\logs\backend.log'
        NESSUS_LOGS_DIR = r'C:\ProgramData\Tenable\Nessus\nessus\logs'
        NESSUS_SERVER_LOG = r'C:\ProgramData\Tenable\Nessus\nessus\logs\www_server.log'
        REPORT_ENGINE_DIR = r'C:\ProgramData\Tenable\Nessus\nessus\report-engine'
        NESSUS_TEMPLATE_DIR = r'C:\ProgramData\Tenable\Nessus\var\nessus\templates'
        NESSUS_COM_DIR = r'C:\ProgramData\Tenable\Nessus\com\nessus'
        NESSUS_CONF = r'C:\ProgramData\Tenable\Nessus\conf'
        NESSUS_BIN = r'C:\Program Files\Tenable\Nessus'
        NESSUS_LIB = r'C:\ProgramData\Tenable\Nessus\nessus'

    class Linux:
        """File paths for 'Linux' instance"""
        NESSUS_CLI = "/opt/nessus/sbin/nessuscli"
        NESSUSD = "/opt/nessus/sbin/nessusd"
        NESSUS_VAR = "/opt/nessus/var/nessus"
        NESSUS_SBIN = "/opt/nessus/sbin/"
        NESSUS_PLUGIN_DIR = '/opt/nessus/lib/nessus/plugins'
        NESSUSD_DUMP = "/opt/nessus/var/nessus/logs/nessusd.dump"
        NESSUS_TOOLS_DIR = '/opt/nessus/var/nessus/tools/'
        NESSUS_BACKEND_LOGS = "/opt/nessus/var/nessus/logs/backend.log"
        NESSUS_PLUGIN_FEED_INFO_DIR = '/opt/nessus/var/nessus/plugin_feed_info.inc'
        NESSUSD_MESSAGES = "/opt/nessus/var/nessus/logs/nessusd.messages"
        NESSUS_LOGS_DIR = "/opt/nessus/var/nessus/logs/"
        NESSUS_SERVER_LOG = "/opt/nessus/var/nessus/logs/www_server.log"
        NESSUS_PLUGIN_MD5_DIR = "/opt/nessus/lib/nessus/plugins/MD5"
        NESSUS_METADATA_JSON = "/opt/nessus/var/nessus/templates/metadata.json"
        REPORT_ENGINE_DIR = "/opt/nessus/var/nessus/report-engine"
        NESSUS_TEMPLATE_DIR = '/opt/nessus/var/nessus/templates'
        NESSUS_COM_DIR = "/opt/nessus/com/nessus"
        NESSUS_CONF = "/opt/nessus/etc/nessus/"
        NESSUS_BIN = "/opt/nessus/bin"
        NESSUS_LIB = "/opt/nessus/lib/nessus"

    class FreeBSD:
        """File paths for 'Linux' instance"""
        NESSUS_CLI = "/usr/local/nessus/sbin/nessuscli"
        NESSUSD = "/usr/local/nessus/sbin/nessusd"
        NESSUS_VAR = "/usr/local/nessus/var/nessus"
        NESSUS_SBIN = "/usr/local/nessus/sbin/"
        NESSUS_PLUGIN_DIR = '/usr/local/nessus/lib/nessus/plugins'
        NESSUSD_DUMP = "/usr/local/nessus/var/nessus/logs/nessusd.dump"
        NESSUS_TOOLS_DIR = '/usr/local/nessus/var/nessus/tools/'
        NESSUSD_MESSAGES = "/usr/local/nessus/var/nessus/logs/nessusd.messages"
        NESSUS_BACKEND_LOGS = "/usr/local/nessus/var/nessus/logs/backend.log"
        NESSUS_LOGS_DIR = "/usr/local/nessus/var/nessus/logs/"
        NESSUS_SERVER_LOG = "/usr/local/nessus/var/nessus/logs/www_server.log"
        REPORT_ENGINE_DIR = "/usr/local/nessus/var/nessus/report-engine"
        NESSUS_TEMPLATE_DIR = '/usr/local/nessus/var/nessus/templates'
        NESSUS_COM_DIR = "/usr/local/nessus/com/nessus"
        NESSUS_CONF = "/usr/local/nessus/etc/nessus"
        NESSUS_BIN = "/usr/local/nessus/bin"
        NESSUS_LIB = "/usr/local/nessus/lib/nessus"

    class MacOS:
        """"""
        NESSUS_CLI = "/Library/Nessus/run/sbin/nessuscli"
        NESSUSD = "/Library/Nessus/run/sbin/nessusd"
        NESSUS_VAR = "/Library/Nessus/run/var/nessus/"
        NESSUS_SBIN = "/Library/Nessus/run/sbin/"
        NESSUS_PLUGIN_DIR = '/Library/Nessus/run/lib/nessus/plugins'
        NESSUSD_DUMP = "/Library/Nessus/run/var/nessus/logs/nessusd.dump"
        NESSUS_TOOLS_DIR = '/Library/Nessus/run/var/nessus/tools/'
        NESSUS_TEMPLATE_DIR = '/Library/Nessus/run/var/nessus/templates'
        NESSUSD_MESSAGES = "/Library/Nessus/run/var/nessus/logs/nessusd.messages"
        NESSUS_BACKEND_LOGS = "/Library/Nessus/run/var/nessus/logs/backend.log"
        NESSUS_LOGS_DIR = "/Library/Nessus/run/var/nessus/logs/"
        NESSUS_COM_DIR = "/Library/Nessus/run/com/nessus/"
        NESSUS_SERVER_LOG = "/Library/Nessus/run/var/nessus/logs/www_server.log"
        NESSUS_CONF = "/Library/Nessus/run/var/nessus/conf/"
        NESSUS_BIN = "/Library/Nessus/run/bin"
        NESSUS_LIB = "/Library/Nessus/run/lib/nessus"


class NessusAgentFilePath:
    """File paths of Nessus"""
    NESSUS_AGENT_BACKEND_LOGS = "/opt/nessus_agent/var/nessus/logs/backend.log"


class SSHCommands:
    class Windows:
        """"""
        COMMAND = {"move_file": "move", "copy_file": "copy {} {}", "remove_file": "rm -rf", "display_content": "cat",
                   "display_directory_content": "dir", "get_file_size": "for %I in ({}) do @echo %~zI",
                   "last_modified": "for %A in ({}) do @echo=%~tA", "create_file": "type nul > {}",
                   "rename_file": "mv {} {}", "create_directory": "mkdir {}", "append_to_file": "echo -n '{}' >> {}",
                   "stop_docker": "net stop docker", "start_docker": "net start docker",
                   "docker_container_exists": "docker ps |grep was-scanner",
                   "docker_image_exists": "docker image ls |grep was-scanner"}

    class Linux:
        """"""
        COMMAND = {"move_file": "mv", "copy_file": "cp {} {}", "remove_file": "rm -rf", "display_content": "cat",
                   "display_directory_content": "ls", "extract_tar_files": "tar -xzvf", "unzip_files": "unzip -o",
                   "get_file_size": "stat --format='%s' {}", "last_modified": "stat -c '%y' {}",
                   "file_created_date": "stat -c '%w' {}", "create_file": "touch {}", "rename_file": "mv {} {}",
                   "create_directory": "mkdir -p {}", "append_to_file": """bash -c \"echo -n '{}' >> {}\"""",
                   "stop_docker": "systemctl stop docker", "start_docker": "systemctl start docker",
                   "docker_container_exists": "docker ps |grep was-scanner",
                   "docker_image_exists": "docker image ls |grep was-scanner"}

    class MacOS:
        """"""
        COMMAND = {"move_file": "mv", "copy_file": "cp {} {}", "remove_file": "rm -rf", "display_content": "cat",
                   "display_directory_content": "ls", "extract_tar_files": "tar -xzvf", "unzip_files": "unzip -o",
                   "get_file_size": "find . -type f -exec ls -l {} \;", "last_modified": "stat -c '%y' {}",
                   "file_created_date": "stat -f '%SB' {}", "create_file": "touch {}", "rename_file": "mv {} {}",
                   "create_directory": "mkdir -p {}", "append_to_file": "echo '{}' >> {}",
                   "docker_container_exists": "docker ps |grep was-scanner",
                   "docker_image_exists": "docker image ls |grep was-scanner"}


class NessusInstallation:
    """Constants for Nessus installation"""
    ADMINISTRATOR_USER = "Administrator"
    ADMINISTRATOR_PASSWORD = "Automation!"
    REGISTRATION_SUCCESS = "Your Activation Code has been registered properly - thank you."
    PLUGINS_UPDATE_SUCCESS = ["Nessus Plugins: Complete",
                              " * Nessus Plugins are now up-to-date and the changes will be "
                              "automatically processed by Nessus."]
    ADMIN_USER_PAYLOAD = {'username': Nessus.USERNAME, 'permissions': API.Permissions.User.SYSTEM_ADMINISTRATOR,
                          'password': Nessus.PASSWORD}
    NESSUS_MSI = "C:\\Users\\Administrator\\Nessus.msi"
    BUILD_PATH = {'CentOS': '/install/Nessus-*-es7.x86_64.rpm'}
    OS_RELEASE_FILE_PATH = "/etc/os-release"
    NESSUS_DIR_PATH = "/opt/nessus"
    OS_COMMANDS = {'CentOS': {'force_upgrade': 'rpm -Uvh --force'}}


