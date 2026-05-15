"""
Nessus compliance Constants
:copyright: Tenable Network Security, 2017
:date: June 04, 2018
:last_modified: June 19, 2022
:author: @mameta, @kpanchal, @krpatel
"""


class ComplianceConst:
    """Nessus compliance categories and sub categories under scans and policies"""

    # all categories of compliance
    ADTRAN_AOS = "Adtran AOS"
    ALCATEL_TIMOS = "Alcatel TiMOS"
    AMAZON_AWS = "Amazon AWS"
    ARISTA_EOS = "Arista EOS"
    BLUECOAT_PROXYSG = "BlueCoat ProxySG"
    BROCADE_FABRICOS = "Brocade FabricOS"
    CHECK_POINT_GAIA = "Check Point GAiA"
    CISCO_IOS = "Cisco IOS"
    DATABASE = "Database"
    EXTREME_EXTREMEXOS = "Extreme ExtremeXOS"
    F_FIVE = "F5"
    FIREEYE = "FireEye"
    FORTIGATE_FORTIOS = "Fortigate FortiOS"
    HP_PROCURVE = "HP ProCurve"
    HUAWEI_VRP = "Huawei VRP"
    IBM_ISERIES = "IBM iSeries"
    JUNIPER_JUNOS = "Juniper Junos"
    JUNIPER_OS = "Juniper OS"
    MICROSOFT_AZURE = "Microsoft Azure"
    MOBILE_DEVICE_MANAGER = "Mobile Device Manager"
    MONGODB = "MongoDB"
    NETAPP_DATA_ONTAP = "NetApp Data ONTAP"
    OPENSTACK = "OpenStack"
    PALO_ALTO_NETWORKS_PAN_OS = "Palo Alto Networks PAN-OS"
    RACKSPACE = "Rackspace"
    RHEV = "RHEV"
    SALESFORCE_COM = "Salesforce.com"
    SONICWALL_SONICOS = "SonicWALL SonicOS"
    UNIX = "Unix"
    UNIX_FILE_CONTENTS = "Unix File Contents"
    VMWARE_VCENTER_VSPHERE = "VMware vCenter/vSphere"
    WATCHGUARD = "WatchGuard"
    WINDOWS = "Windows"
    WINDOWS_FILE_CONTENTS = "Windows File Contents"
    SPLUNK = 'Splunk'
    IBM_DB2_DB = 'IBM DB2 DB'
    ORACLE_DB = 'Oracle DB'
    MYSQL_DB = 'MySQL DB'
    MICROSOFT_SQL_SERVER_DB = 'Microsoft SQL Server DB'
    SYBASE_DB = 'Sybase DB'
    OPENSHIFT = 'OpenShift'
    POSTGRESQL_DB = 'PostgreSQL DB'

    # constants for specific term of compliance
    ALCATEL = "Alcatel"
    AMAZON = "Amazon"
    ARISTA = "Arista"
    CISCO = "Cisco"
    DELL = "Dell"
    IBM = "IBM"
    APPLE_PROFILE_MANAGER = "Apple Profile Manager"
    PALO_ALTO = "Palo Alto"
    CIS_AIX = "CIS AIX"
    AUDIT_MEDIA_CONTENT = "Adult Media Content"
    SONICWALL = "SonicWALL"
    MYSQL = "MySQL"
    RACK_SPACE = "RackSpace"
    SALESFORCE = "Salesforce"
    VMWARE = "VMware"
    TENABLE_AWS = "Tenable"
    MOBILEIRON = 'MobileIron'

    # compliance list for various templates
    POLICY_COMPLIANCE_LIST = ['All', 'Adtran AOS', 'Alcatel TiMOS', 'Arista EOS', 'BlueCoat ProxySG',
                              'Brocade FabricOS', 'Check Point GAiA', 'Cisco ACI', 'Cisco Firepower', 'Cisco IOS',
                              'Cisco Viptela', 'Database', 'Extreme ExtremeXOS', 'Splunk', 'IBM DB2 DB', 'Oracle DB',
                              'MySQL DB', 'Microsoft SQL Server DB', 'Sybase DB', 'OpenShift', 'PostgreSQL DB',
                              'F5', 'FireEye', 'Fortigate FortiOS', 'Generic SSH', 'HP ProCurve', 'Huawei VRP',
                              'IBM iSeries', 'Juniper Junos', 'MongoDB', 'NetApp API', 'NetApp Data ONTAP', 'OpenStack',
                              'Palo Alto Networks PAN-OS', 'RHEV', 'SonicWALL SonicOS', 'Unix', 'Unix File Contents',
                              'VMware vCenter/vSphere', 'WatchGuard', 'Windows', 'Windows File Contents', 'ZTE ROSNG',
                              'ArubaOS', 'Citrix Application Delivery']
    POLICY_COMPLIANCE_LIST_PRO = ['Brocade FabricOS', 'BlueCoat ProxySG', 'Adtran AOS', 'ArubaOS', 'Check Point GAiA',
                                  'Arista EOS', 'All', 'Alcatel TiMOS']
    ACI_COMPLIANCE_LIST_PRO = ['All', 'Amazon AWS', 'Microsoft Azure']
    ACI_COMPLIANCE_LIST = ['All', 'Amazon AWS', 'Google Cloud Platform', 'Microsoft Azure', 'Rackspace',
                           'Salesforce.com', 'Snowflake', 'Zoom']
