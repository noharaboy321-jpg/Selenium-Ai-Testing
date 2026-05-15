# API Audit Helpers

This helper has various functions that return dictionaries that can be added to a ScanModel object for running compliance scans.

- Supported Audits
    - Cisco
    - Palo Alto PAN-OS
    - VMWare ESXi
    - VMWare vCenter

More audit types will be added in the future.

Sample code for creating a Cisco IOS15 Level 1 audit dictionary

from nessus.helpers.audits.audit import create_cisco_ios_15_level_1_audit

create_cisco_ios_15_level_1_audit('46689_CIS_Cisco_IOS_15_v4.0.0_Level_1.audit',
                                  '20','192\\.168\\.1\\.0 0\\.0\\.0\\.255','1',
                                  '192\\.168\\.0\\.2','192\\.168\\.2\\.1',
                                  '192\\.168\\.3\\.1','Saved/(show config)')

Returns:
{
  'variables': {
    'NTP_SERVER': '192\\.168\\.3\\.1',
    'LOGGING_HOST_IP': '192\\.168\\.2\\.1',
    'VTY_AUTH_IP': '192\\.168\\.1\\.0 0\\.0\\.0\\.255',
    'cisco_config_to_audit': 'Saved/(show config)',
    'SNMP_ACL': '1',
    'SNMP_TRAP_HOST': '192\\.168\\.0\\.2',
    'VTY_ACL': '20'
    },
    'id': '46689_CIS_Cisco_IOS_15_v4.0.0_Level_1.audit'
  }