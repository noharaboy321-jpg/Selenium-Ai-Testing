"""
API Audit Helpers
"""


def create_compliance_list(compliance_data: list):
    """
    Takes the passed in compliance results and creates a list of the compliance checks present in the scan results.
    :param list compliance_data: Compliance results from scan.
    :return: list
    """
    compliance_list = []
    for check in compliance_data:
        compliance_list.append(check["plugin_name"])
    return compliance_list


def get_compliance_id(compliance_data: list, compliance_check: str):
    """
    Takes the passed in compliance results and attempts to map the expected compliance check with its plugin ID.
    :param list compliance_data: Compliance results from scan.
    :param str compliance_check: Expected compliance check.
    :return: str
    """
    compliance_id = None
    for check in compliance_data:
        if check['plugin_name'] == compliance_check:
            compliance_id = check['plugin_id']
    return compliance_id


def create_cisco_ios_15_level_1_audit(audit_id: str, vty_acl: int, vty_auth_ip: str, snmp_acl: str,
                                      snmp_trap_host: str, logging_host_ip: str, ntp_server: str,
                                      cisco_config_to_audit: str) -> dict:
    """
    Create an Cisco IOS Compliance dictionary

    :param str audit_id:                ID of built in Cisco IOS Audit File.
    :param int vty_acl:                 VTY ACL ID
    :param str vty_auth_ip:             VTY authorized IP
    :param str snmp_acl:                SNMP ACL - ACL ID
    :param str snmp_trap_host:          SNMP Trap Server
    :param str logging_host_ip:         Logging Server
    :param str ntp_server:              NTP Server
    :param str cisco_config_to_audit:   Config to audit
    :returns: dict
    """
    return {'id': audit_id, 'variables': {'VTY_ACL': vty_acl, 'VTY_AUTH_IP': vty_auth_ip, 'SNMP_ACL': snmp_acl,
                                          'SNMP_TRAP_HOST': snmp_trap_host, 'LOGGING_HOST_IP': logging_host_ip,
                                          'NTP_SERVER': ntp_server,
                                          'cisco_config_to_audit': cisco_config_to_audit}}


def create_pan_os_tns_best_practices_audit(audit_id: str, pri_dns_server: str, sec_dns_server: str,
                                           pri_ntp_server: str, sec_ntp_server: str, update_server: str,
                                           config_timestamp: str, time_zone: str) -> dict:
    """
    Create an Palo Alto PAN-OS Compliance dictionary

    :param str audit_id:           ID of built in Palo Alto PAN-OS Audit File.
    :param str pri_dns_server:     Primary DNS Server
    :param str sec_dns_server:     Secondary DNS Server
    :param str pri_ntp_server:     Primary NTP Server
    :param str sec_ntp_server:     Secondary NTP Server
    :param str update_server:      Software Update Server
    :param str config_timestamp:   Firewall Config Timestamp
    :param str time_zone:          Timezone to use when reporting time / correlating logs.
    :returns: dict
    """
    return {'id': audit_id, 'variables': {'PRI_DNS_SERVER': pri_dns_server, 'SEC_DNS_SERVER': sec_dns_server,
                                          'PRI_NTP_SERVER': pri_ntp_server, 'SEC_NTP_SERVER': sec_ntp_server,
                                          'UPDATE_SERVER': update_server, 'TIMESTAMP': config_timestamp,
                                          'TIMEZONE': time_zone}}

def create_CIS_Microsoft_Server_2008_Domain_Controller_Level_1_audit(audit_id: str, firewall_domain_log: str, firewall_private_log: str,
                                           firewall_public_log: str, logon_caption: str, logon_text: str) -> dict:
    """
    Create an Windows 2008 domain controller Compliance dictionary

    :param str audit_id:            ID of built in Windows 2008 DC Audit File.
    :param str firewall_domain_log: Path and name of the domain firewall log file
    :param str firewall_private_log:Path and name of the private firewall log file
    :param str firewall_public_log: Path and name of the public firewall log file
    :param str logon_caption:       Caption text of the logon warning a user recieves when logging onto the system
    :param str logon_text:          Body text of the logon warning a user recieves when logging onto the system
    :returns: dict
    """
    return {'id': audit_id, 'variables': {'FIREWALL_DOMAIN_LOG': firewall_domain_log, 'FIREWALL_PRIVATE_LOG': firewall_private_log,
                                          'FIREWALL_PUBLIC_LOG': firewall_public_log, 'LOGON_CAPTION': logon_caption,
                                          'LOGON_TEXT': logon_text}}


def create_CIS_Microsoft_Windows_10_Enterprise_Level_1_audit(audit_id: str, firewall_domain_log: str, firewall_private_log: str,
                                            firewall_public_log: str, logon_caption: str, logon_text: str) -> dict:

    """
    Create an Windows 10 Compliance dictionary

    :param str audit_id:            ID of built in Windows 10 Audit File.
    :param str firewall_domain_log: Path and name of the domain firewall log file
    :param str firewall_private_log:Path and name of the private firewall log file
    :param str firewall_public_log: Path and name of the public firewall log file
    :param str logon_caption:       Caption text of the logon warning a user recieves when logging onto the system
    :param str logon_text:          Body text of the logon warning a user recieves when logging onto the system
    :param str audit_id:           ID of built in Windows 2008 DC Audit File.
    :returns: dict
    """
    return {'id': audit_id, 'variables': {'FIREWALL_DOMAIN_LOG': firewall_domain_log, 'FIREWALL_PRIVATE_LOG': firewall_private_log,
                                          'FIREWALL_PUBLIC_LOG': firewall_public_log, 'LOGON_CAPTION': logon_caption,
                                          'LOGON_TEXT': logon_text}}



def create_cis_vmware_esxi_5_1_level_1_audit(audit_id: str, ntp_server: str, log_host: str, dcui_access: str,
                                             agent_address: str, agent_port: int, log_dir: str,
                                             shell_session_timeout: int, cpu_share_level: str, num_mem_shares: int,
                                             mem_share_level: str):
    """
    Create a VMWare ESXi CIS Compliance dictionary

    :param str audit_id:                 ID of built in VMWare ESXi CIS Compliance File
    :param str ntp_server:               Name or IP address of the NTP Server
    :param str log_host:                 IP Address of the centralized syslog server
    :param str dcui_access:              List of trusted users that can override lockdown mode
    :param str agent_address:            VMSafe Address
    :param inrt agent_port:              VMSafe Port
    :param str log_dir:                  Path to system log directory
    :param int shell_session_timeout:    Number of minutes before an idle SSH Session is disconnected
    :param str cpu_share_level:          CPU Share Level
    :param int num_mem_shares:           Number of memory shares
    :param str mem_share_level:          Memory share level
    :returns: dict
    """
    return {'id': audit_id, 'variables': {'NTP_SERVER': ntp_server, 'LOG_HOST': log_host,
                                          'DCUI_ACCESS': dcui_access, 'AGENT_ADDRESS': agent_address,
                                          'AGENT_PORT': agent_port, 'LOG_DIR': log_dir,
                                          'SHELL_SESSION_TIMEOUT': shell_session_timeout,
                                          'CPU_SHARE_LEVEL': cpu_share_level, 'NUM_MEM_SHARES': num_mem_shares,
                                          'MEM_SHARE_LEVEL': mem_share_level}}


def create_vmware_vcenter_best_practices(audit_id: str):
    """
    Create a VMWare vCenter DISA STIG Compliance dictionary

    :param str audit_id:                 ID of built in VMWare vCenter DISA STIG v1r7 Audit File.
    :returns: dict
    """
    return {'id': audit_id, 'variables': {}}
