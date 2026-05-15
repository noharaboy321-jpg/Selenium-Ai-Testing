"""
Nessus Compliance Check Authentication
"""
import pytest

from nessus.helpers.audits.audit import create_cisco_ios_15_level_1_audit, create_pan_os_tns_best_practices_audit, \
    create_CIS_Microsoft_Server_2008_Domain_Controller_Level_1_audit, \
    create_CIS_Microsoft_Windows_10_Enterprise_Level_1_audit, \
    create_cis_vmware_esxi_5_1_level_1_audit, create_vmware_vcenter_best_practices
from nessus.helpers.credentials.credential import CredentialHelper
from nessus.models.scan import ScanModel
from nessus.helpers.scan import launch_compliance_scan
from nessus.helpers.system import get_audit_id
from nessus.lib import const
from catium.lib.const import STRING_FEED, STRING_CUSTOM


@pytest.mark.scanning
@pytest.mark.plugins
@pytest.mark.usefixtures('nessus_api_login')
@pytest.mark.usefixtures('load_test_data')
@pytest.mark.parametrize('test_data_file', ['nessus/tests/api/plugins/test_data/test_compliance_checks.json'])
class TestComplianceChecks:
    """
    Test class for Nessus Compliance Check Authentication
    """
    cat = None

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/compliance/{plugin_id}
    def test_cisco_ios_15_level_1_audit(self, load_test_data):
        """
        Verify Compliance checks are successful on Cisco devices.
        """
        scan_model = ScanModel.create_model()
        scan_model.add_ssh_credential(
            CredentialHelper.Host.create_ssh_password_credential(username=load_test_data['cisco_ios']['username'],
                                                                 password=load_test_data['cisco_ios']['password']))
        scan_model.uuid = load_test_data['cisco_ios']['uuid']
        audit_id = get_audit_id(load_test_data['cisco_ios']['audit_id'])
        audit_data = create_cisco_ios_15_level_1_audit(audit_id=audit_id,
                                                       vty_acl=load_test_data['cisco_ios']['vty_acl'],
                                                       vty_auth_ip=load_test_data['cisco_ios']['vty_auth_ip'],
                                                       snmp_acl=load_test_data['cisco_ios']['snmp_acl'],
                                                       snmp_trap_host=load_test_data['cisco_ios']['snmp_trap_host'],
                                                       logging_host_ip=load_test_data['cisco_ios']['logging_host_ip'],
                                                       ntp_server=load_test_data['cisco_ios']['ntp_server'],
                                                       cisco_config_to_audit=load_test_data['cisco_ios']
                                                       ['cisco_config_to_audit'])

        audit_type = None
        if load_test_data['cisco_ios']['audit_type'] == STRING_FEED:
            audit_type = const.API.Audits.Type.Feed
        elif load_test_data['cisco_ios']['audit_type'] == STRING_CUSTOM:
            audit_type = const.API.Audits.Type.Custom
        scan_model.add_audit_file(audit_type, audit_data)
        target = load_test_data['cisco_ios']['target']
        compliance_check = load_test_data['cisco_ios']['compliance_check']
        compliance_out = launch_compliance_scan(self.cat.api, scan_model, target, compliance_check)
        assert "The following configuration line is set" in compliance_out['outputs'][0]['plugin_output'], \
            "{0} check failed.".format(compliance_check)

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/compliance/{plugin_id}
    def test_palo_alto_pan_os_tns_best_practices_audit(self, load_test_data):
        """
        Verify Compliance checks are successful on Palo Alto PAN-OS devices.
        """
        scan_model = ScanModel.create_model()
        scan_model.add_palo_alto_pan_os_credential(
            CredentialHelper.Miscellaneous.create_palo_alto_credential(username=load_test_data['pan_os']['username'],
                                                                       password=load_test_data['pan_os']['password'],
                                                                       port=load_test_data['pan_os']['port'],
                                                                       https=load_test_data['pan_os']['https'],
                                                                       verify_ssl=
                                                                       load_test_data['pan_os']['verify_ssl']))
        scan_model.uuid = load_test_data['pan_os']['uuid']
        audit_id = get_audit_id(load_test_data['pan_os']['audit_id'])
        audit_data = create_pan_os_tns_best_practices_audit(audit_id=audit_id,
                                                            pri_dns_server=
                                                            load_test_data['pan_os']['pri_dns_server'],
                                                            sec_dns_server=
                                                            load_test_data['pan_os']['sec_dns_server'],
                                                            pri_ntp_server=
                                                            load_test_data['pan_os']['pri_ntp_server'],
                                                            sec_ntp_server=
                                                            load_test_data['pan_os']['sec_ntp_server'],
                                                            update_server=
                                                            load_test_data['pan_os']['update_server'],
                                                            config_timestamp=
                                                            load_test_data['pan_os']['config_timestamp'],
                                                            time_zone=
                                                            load_test_data['pan_os']['timezone'])
        audit_type = None
        if load_test_data['pan_os']['audit_type'] == STRING_FEED:
            audit_type = const.API.Audits.Type.Feed
        elif load_test_data['pan_os']['audit_type'] == STRING_CUSTOM:
            audit_type = const.API.Audits.Type.Custom
        scan_model.add_audit_file(audit_type, audit_data)
        target = load_test_data['pan_os']['target']
        compliance_check = load_test_data['pan_os']['compliance_check']
        compliance_out = launch_compliance_scan(self.cat.api, scan_model, target, compliance_check)
        assert 'outputs' in compliance_out and \
               "research" in compliance_out['outputs'][0]['plugin_output'], "{0} check failed.".format(compliance_check)

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/compliance/{plugin_id}
    def test_CIS_Microsoft_Server_2008_Domain_Controller_Level_1(self, load_test_data):
        """
        Verify Compliance checks for server 2008 DC
        """
        scan_model = ScanModel.create_model()
        scan_model.add_windows_credential(
            CredentialHelper.Host.create_win_password_credential(username=load_test_data['2008_dc']['username'],
                                                                 password=load_test_data['2008_dc']['password'],
                                                                 domain=load_test_data['2008_dc']['domain']))
        scan_model.uuid = load_test_data['2008_dc']['uuid']
        audit_id = get_audit_id(load_test_data['2008_dc']['audit_id'])
        audit_data = create_CIS_Microsoft_Server_2008_Domain_Controller_Level_1_audit(audit_id=audit_id,
                                                                                      firewall_domain_log=
                                                                                      load_test_data['2008_dc'][
                                                                                          'fw_domain_log'],
                                                                                      firewall_private_log=
                                                                                      load_test_data['2008_dc'][
                                                                                          'fw_private_log'],
                                                                                      firewall_public_log=
                                                                                      load_test_data['2008_dc'][
                                                                                          'fw_public_log'],
                                                                                      logon_caption=
                                                                                      load_test_data['2008_dc'][
                                                                                          'logon_caption'],
                                                                                      logon_text=
                                                                                      load_test_data['2008_dc'][
                                                                                          'logon_text'])

        audit_type = None
        if load_test_data['2008_dc']['audit_type'] == STRING_FEED:
            audit_type = const.API.Audits.Type.Feed
        elif load_test_data['2008_dc']['audit_type'] == STRING_CUSTOM:
            audit_type = const.API.Audits.Type.Custom
        scan_model.add_audit_file(audit_type, audit_data)
        target = load_test_data['2008_dc']['target']
        compliance_check = load_test_data['2008_dc']['compliance_check']
        compliance_out = launch_compliance_scan(self.cat.api, scan_model, target, compliance_check)
        assert 'outputs' in compliance_out and 'PASSED' in compliance_out['outputs'][0]['ports'], \
            "{0} check failed.".format(compliance_check)

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/compliance/{plugin_id}
    def test_CIS_Microsoft_Windows_10_Enterprise_Level_1(self, load_test_data):
        """
        Verify Compliance checks for Windows 10
        """
        scan_model = ScanModel.create_model()
        scan_model.add_windows_credential(
            CredentialHelper.Host.create_win_password_credential(
                username=load_test_data['win10_audit']['username'],
                password=load_test_data['win10_audit']['password'],
                domain=load_test_data['win10_audit']['domain']))
        scan_model.uuid = load_test_data['win10_audit']['uuid']
        audit_id = get_audit_id(load_test_data['win10_audit']['audit_id'],
                                load_test_data['win10_audit']['audit_display_name'])
        audit_data = create_CIS_Microsoft_Windows_10_Enterprise_Level_1_audit(audit_id=audit_id,
                                                                              firewall_domain_log=
                                                                              load_test_data['win10_audit'][
                                                                                  'fw_domain_log'],
                                                                              firewall_private_log=
                                                                              load_test_data['win10_audit'][
                                                                                  'fw_private_log'],
                                                                              firewall_public_log=
                                                                              load_test_data['win10_audit'][
                                                                                  'fw_public_log'],
                                                                              logon_caption=
                                                                              load_test_data['win10_audit'][
                                                                                  'logon_caption'],
                                                                              logon_text=
                                                                              load_test_data['win10_audit'][
                                                                                  'logon_text'])

        audit_type = None
        if load_test_data['win10_audit']['audit_type'] == STRING_FEED:
            audit_type = const.API.Audits.Type.Feed
        elif load_test_data['win10_audit']['audit_type'] == STRING_CUSTOM:
            audit_type = const.API.Audits.Type.Custom
        scan_model.add_audit_file(audit_type, audit_data)
        target = load_test_data['win10_audit']['target']
        compliance_check = load_test_data['win10_audit']['compliance_check']
        compliance_out = launch_compliance_scan(self.cat.api, scan_model, target, compliance_check)
        assert 'outputs' in compliance_out and \
               "'success'" in compliance_out['outputs'][0]['plugin_output'], \
            "{0} check failed.".format(compliance_check)

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/compliance/{plugin_id}
    def test_vmware_esxi_cis_level_1_audit(self, load_test_data):
        """
        Verify Compliance checks are successful on VMWare ESXi.
        """
        scan_model = ScanModel.create_model()
        scan_model.add_vmware_esx_credential(
            CredentialHelper.Miscellaneous.create_vmware_esx_credential(username=
                                                                        load_test_data['vmware_esx']['username'],
                                                                        password=
                                                                        load_test_data['vmware_esx']['password'],
                                                                        dont_verify_ssl=
                                                                        load_test_data['vmware_esx']['dont_verify_ssl'])
        )
        scan_model.uuid = load_test_data['vmware_esx']['uuid']
        audit_id = get_audit_id(load_test_data['vmware_esx']['audit_id'])
        audit_data = create_cis_vmware_esxi_5_1_level_1_audit(audit_id=audit_id,
                                                              ntp_server=
                                                              load_test_data['vmware_esx']['ntp_server'],
                                                              log_host=
                                                              load_test_data['vmware_esx']['log_host'],
                                                              dcui_access=
                                                              load_test_data['vmware_esx']['dcui_access'],
                                                              agent_address=
                                                              load_test_data['vmware_esx']['agent_address'],
                                                              agent_port=
                                                              load_test_data['vmware_esx']['agent_port'],
                                                              log_dir=
                                                              load_test_data['vmware_esx']['log_dir'],
                                                              shell_session_timeout=
                                                              load_test_data['vmware_esx']['shell_session_timeout'],
                                                              cpu_share_level=
                                                              load_test_data['vmware_esx']['cpu_share_level'],
                                                              num_mem_shares=
                                                              load_test_data['vmware_esx']['num_mem_shares'],
                                                              mem_share_level=
                                                              load_test_data['vmware_esx']['mem_share_level'])
        audit_type = None
        if load_test_data['vmware_esx']['audit_type'] == STRING_FEED:
            audit_type = const.API.Audits.Type.Feed
        elif load_test_data['vmware_esx']['audit_type'] == STRING_CUSTOM:
            audit_type = const.API.Audits.Type.Custom
        scan_model.add_audit_file(audit_type, audit_data)
        target = load_test_data['vmware_esx']['target']
        compliance_check = load_test_data['vmware_esx']['compliance_check']
        compliance_out = launch_compliance_scan(self.cat.api, scan_model, target, compliance_check)
        assert 'outputs' in compliance_out and "running = true" in compliance_out['outputs'][0]['plugin_output'], \
            "{0} check failed.".format(compliance_check)

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/compliance/{plugin_id}
    def test_vmware_vcenter5_best_practices(self, load_test_data):
        """
        Verify Compliance checks are successful on VMWare vCenter.
        """
        scan_model = ScanModel.create_model()
        scan_model.add_vmware_vcenter_credential(
            CredentialHelper.Miscellaneous.create_vmware_vcenter_credential(username=
                                                                            load_test_data['vmware_vcenter5']
                                                                            ['username'],
                                                                            password=load_test_data['vmware_vcenter5']
                                                                            ['password'],
                                                                            host=load_test_data['vmware_vcenter5']
                                                                            ['vcenter_server'],
                                                                            port=load_test_data['vmware_vcenter5']
                                                                            ['port'],
                                                                            https=load_test_data['vmware_vcenter5']
                                                                            ['https'],
                                                                            verify_ssl=load_test_data['vmware_vcenter5']
                                                                            ['verify_ssl'])
        )
        scan_model.uuid = load_test_data['vmware_vcenter5']['uuid']
        audit_id = get_audit_id(load_test_data['vmware_vcenter5']['audit_id'])
        audit_data = create_vmware_vcenter_best_practices(audit_id=audit_id)
        audit_type = None
        if load_test_data['vmware_vcenter5']['audit_type'] == STRING_FEED:
            audit_type = const.API.Audits.Type.Feed
        elif load_test_data['vmware_vcenter5']['audit_type'] == STRING_CUSTOM:
            audit_type = const.API.Audits.Type.Custom
        scan_model.add_audit_file(audit_type, audit_data)
        target = load_test_data['vmware_vcenter5']['target']
        compliance_check = load_test_data['vmware_vcenter5']['compliance_check']
        compliance_out = launch_compliance_scan(self.cat.api, scan_model, target, compliance_check)
        assert 'outputs' in compliance_out and "config.nfc.useSSL : true" in \
               compliance_out['outputs'][0]['plugin_output'], \
            "{0} check failed.".format(compliance_check)

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/compliance/{plugin_id}
    def test_vmware_vcenter6_best_practices(self, load_test_data):
        """
        Verify Compliance checks are successful on VMWare vCenter.
        """
        scan_model = ScanModel.create_model()
        scan_model.add_vmware_vcenter_credential(
            CredentialHelper.Miscellaneous.create_vmware_vcenter_credential(username=
                                                                            load_test_data['vmware_vcenter6']
                                                                            ['username'],
                                                                            password=load_test_data['vmware_vcenter6']
                                                                            ['password'],
                                                                            host=load_test_data['vmware_vcenter6']
                                                                            ['vcenter_server'],
                                                                            port=load_test_data['vmware_vcenter6']
                                                                            ['port'],
                                                                            https=load_test_data['vmware_vcenter6']
                                                                            ['https'],
                                                                            verify_ssl=load_test_data['vmware_vcenter6']
                                                                            ['verify_ssl'])
        )
        scan_model.uuid = load_test_data['vmware_vcenter6']['uuid']
        audit_id = get_audit_id(load_test_data['vmware_vcenter6']['audit_id'])
        audit_data = create_vmware_vcenter_best_practices(audit_id=audit_id)
        audit_type = None
        if load_test_data['vmware_vcenter6']['audit_type'] == STRING_FEED:
            audit_type = const.API.Audits.Type.Feed
        elif load_test_data['vmware_vcenter6']['audit_type'] == STRING_CUSTOM:
            audit_type = const.API.Audits.Type.Custom
        scan_model.add_audit_file(audit_type, audit_data)
        target = load_test_data['vmware_vcenter6']['target']
        compliance_check = load_test_data['vmware_vcenter6']['compliance_check']
        compliance_out = launch_compliance_scan(self.cat.api, scan_model, target, compliance_check)
        assert 'outputs' in compliance_out and "Network adapter 1 : Connected at Boot = true" in \
               compliance_out['outputs'][0]['plugin_output'], \
            "{0} check failed.".format(compliance_check)
