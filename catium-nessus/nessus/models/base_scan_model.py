"""
Base Scan Model

The following is true.
    The default model is based off of the Advanced Scan / Advanced Network Scan templates
    The models attributes represent scan settings and are used when creating a request model for an API request
    You may use the provided helper methods to enable one or more plugins and add credentials
    Specifying no plugins to enable, uses the plugin settings from the Advanced Scan template
    a Subset of scan settings are supported via kwargs, others may be set via object setters (e.g. model.ssh_port = 22)

Product: Nessus, TenableCloud
"""
from collections import defaultdict

from catium.lib import const
from catium.lib.errors import CatiumModelError
from nessus.lib.config import NessusConfig
from nessus.lib.const import API
from nessus.lib.const import ReportParanoiaTypes


class BaseScanModel(object):
    """
    Base Scan Model

    Defines the parameters needed to create a new scan

    rrules:
        Expects a semi-colon delimited string comprised of three values. The frequency (FREQ=ONCE or DAILY or WEEKLY or
        MONTHLY or YEARLY), the interval (INTERVAL=1 or 2 or 3 ... x), and the days of the week (BYDAY=SU,MO,TU,WE,TH,
        FR,SA).

        To create a scan that runs every three weeks on Monday Wednesday and Friday the string would be
        'FREQ=WEEKLY;INTERVAL=3;BYDAY=MO,WE,FR'


    .. note:: If autogen is True then the Advanced scan template will be used to create the scan
    .. note:: Scan Targets are NOT auto-generated and must be provided
    .. note:: If no plugins are specified then ALL plugins will be enabled

    Kwargs:
        uuid (str): UUID for the editor template to use to create the scan
        name (str): The desired name of the scan
        description (str): The description of the scan
        policy_id (int): The ID of the policy to use to create the scan
        folder_id (int): The ID of the destination folder for the scan
        scanner_id (int): The ID of the scanner to use to run the scan
        enabled (bool): If True, the schedule for the scan is enabled
        launch (str): When to launch the scan (Accepts: ON_DEMAND, DAILY, WEEKLY, MONTHLY, YEARLY)
        starttime (str): The starting time and date for the scan (Format: YYYYMMDDTHHMMSS)
        rrules (str): Scan schedule
        timezone (str): The timezone for the scan schedule
        text_targets (str): The list of targets to scan
        file_targets (str): The name of a file containing the list of targets to scan
        emails (str): A comma separated list of accounts who will receive the scan summary report
        acls (list): A list containing permissions to apply to the scan
        use_dashboard (bool): If True, the dashboard will enabled for the scan
        plugins (list): A valid list of plugin IDs to enable
        autogen (bool): Automatically generate scan parameters, ignores parameters passed
        apm_force_updates (str): If yes, enables apple profile manager force update for devices.

    :raises: CatiumModelError
    """

    def __init__(self, **kwargs):
        super().__init__()

        kwargs.setdefault('uuid', None)
        kwargs.setdefault('name', None)
        kwargs.setdefault('description', None)
        kwargs.setdefault('policy_id', None)
        kwargs.setdefault('folder_id', None)
        kwargs.setdefault('scanner_id', None)
        kwargs.setdefault('enabled', False)
        kwargs.setdefault('launch', None)
        kwargs.setdefault('starttime', None)
        kwargs.setdefault('rrules', None)
        kwargs.setdefault('timezone', None)
        kwargs.setdefault('text_targets', None)
        kwargs.setdefault('file_targets', None)
        kwargs.setdefault('emails', None)
        kwargs.setdefault('acls', None)
        kwargs.setdefault('use_dashboard', False)
        kwargs.setdefault('plugins', [])
        kwargs.setdefault('families', None)
        kwargs.setdefault('autogen', False)
        kwargs.setdefault('apm_force_updates', None)
        kwargs.setdefault('enable_plugin_debugging', None)
        kwargs.setdefault('log_whole_attack', None)
        kwargs.setdefault('network_capture_enabled', None)
        kwargs.setdefault('network_capture_hosts', None)

        # Default template placeholder
        self.default_template = ''

        # Scan object attributes supported via kwargs
        self.uuid = kwargs.get('uuid')
        self.name = kwargs.get('name')
        self.log_whole_attack = kwargs.get('log_whole_attack')
        self.description = kwargs.get('description')
        self.policy_id = kwargs.get('policy_id')
        self.folder_id = kwargs.get('folder_id')
        self.scanner_id = kwargs.get('scanner_id')
        self.enabled = kwargs.get('enabled')
        self.launch = kwargs.get('launch')
        self.starttime = kwargs.get('starttime')
        self.rrules = kwargs.get('rrules')
        self.timezone = kwargs.get('timezone')
        self.text_targets = kwargs.get('text_targets')
        self.file_targets = kwargs.get('file_targets')
        self.emails = kwargs.get('emails')
        self.acls = kwargs.get('acls')
        self.plugins = kwargs.get('plugins')
        self.families = kwargs.get('families')
        self.use_dashboard = kwargs.get('use_dashboard')
        self.network_capture_enabled = kwargs.get('network_capture_enabled')
        self.network_capture_hosts = kwargs.get('network_capture_hosts')

        # Scan object attributes not supported via kwargs
        self.filters = []
        self.filter_type = ''
        self.ping_the_remote_host = const.STRING_YES
        self.test_local_nessus_host = const.STRING_YES
        self.fast_network_discovery = const.STRING_NO
        self.arp_ping = const.STRING_YES
        self.tcp_ping = const.STRING_YES
        self.tcp_ping_dest_ports = 'built-in'
        self.icmp_ping = const.STRING_YES
        self.icmp_unreach_means_host_down = const.STRING_NO
        self.icmp_ping_retries = '2'
        self.udp_ping = const.STRING_NO
        self.scan_network_printers = const.STRING_NO
        self.scan_netware_hosts = const.STRING_NO
        self.wol_mac_addresses = ''
        self.wol_wait_time = '5'
        self.network_type = 'Mixed (use RFC 1918)'
        self.unscanned_closed = const.STRING_NO
        self.portscan_range = 'default'
        self.ssh_netstat_scanner = const.STRING_YES
        self.wmi_netstat_scanner = const.STRING_YES
        self.snmp_scanner = const.STRING_YES
        self.only_portscan_if_enum_failed = const.STRING_YES
        self.verify_open_ports = const.STRING_NO
        self.tcp_scanner = const.STRING_NO
        self.syn_scanner = const.STRING_YES
        self.syn_firewall_detection = 'Automatic (normal)'
        self.udp_scanner = const.STRING_NO
        self.svc_detection_on_all_ports = const.STRING_YES
        self.detect_ssl = const.STRING_YES
        self.ssl_prob_ports = 'Known SSL ports'
        self.cert_expiry_warning_days = '60'
        self.enumerate_all_ciphers = const.STRING_YES
        self.check_crl = const.STRING_NO
        self.report_paranoia = 'Normal'
        self.thorough_tests = const.STRING_NO
        self.av_grace_period = '0'
        self.smtp_domain = 'example.com'
        self.smtp_from = 'nobody@example.com'
        self.smtp_to = 'postmaster@[AUTO_REPLACED_IP]'
        self.provided_creds_only = const.STRING_YES
        self.test_default_oracle_accounts = const.STRING_NO
        self.modbus_start_reg = '0'
        self.modbus_end_reg = '16'
        self.start_cotp_tsap = '8'
        self.stop_cotp_tsap = '8'
        self.scan_webapps = const.STRING_NO
        self.request_windows_domain_info = const.STRING_YES
        self.enum_domain_users_start_uid = '1000'
        self.enum_domain_users_end_uid = '1200'
        self.enum_local_users_start_uid = '1000'
        self.enum_local_users_end_uid = '1200'
        self.disable_dns_resolution = const.STRING_NO
        self.win_known_bad_hashes = ''
        self.win_known_good_hashes = ''
        self.host_whitelist = ''
        self.enable_file_scanning = const.STRING_NO
        self.report_verbosity = 'Normal'
        self.report_superseded_patches = const.STRING_YES
        self.silent_dependencies = const.STRING_YES
        self.allow_post_scan_editing = const.STRING_YES
        self.reverse_lookup = const.STRING_NO
        self.log_live_hosts = const.STRING_NO
        self.display_unreachable_hosts = const.STRING_NO
        self.safe_checks = const.STRING_YES
        self.stop_scan_on_disconnect = const.STRING_NO
        self.slice_network_addresses = const.STRING_NO
        self.reduce_connections_on_congestion = const.STRING_NO
        self.use_kernel_congestion_detection = const.STRING_NO
        self.network_receive_timeout = '5'
        self.max_checks_per_host = '5'
        self.max_hosts_per_scan = '100'
        self.max_simult_tcp_sessions_per_host = ''
        self.max_simult_tcp_sessions_per_scan = ''
        self.enable_plugin_debugging = kwargs.get('enable_plugin_debugging')
        self.aws_ui_region_type = 'Rest of the World'
        self.aws_us_east_1 = const.STRING_NO
        self.aws_us_west_1 = const.STRING_NO
        self.aws_us_west_2 = const.STRING_NO
        self.aws_eu_west_1 = const.STRING_NO
        self.aws_eu_central_1 = const.STRING_NO
        self.aws_ap_northeast_1 = const.STRING_NO
        self.aws_ap_southeast_1 = const.STRING_NO
        self.aws_ap_southeast_2 = const.STRING_NO
        self.aws_sa_east_1 = const.STRING_NO
        self.aws_us_gov_west_1 = const.STRING_NO
        self.aws_use_https = const.STRING_YES
        self.aws_verify_ssl = const.STRING_YES
        self.region_dfw_pref_name = const.STRING_YES
        self.region_ord_pref_name = const.STRING_YES
        self.region_iad_pref_name = const.STRING_YES
        self.region_lon_pref_name = const.STRING_YES
        self.region_syd_pref_name = const.STRING_YES
        self.region_hkg_pref_name = const.STRING_YES
        self.ssh_known_hosts = ''
        self.ssh_port = API.Credentials.Host.Ports.SSH
        self.ssh_client_banner = 'OpenSSH_5.0'
        self.never_send_win_creds_in_the_clear = const.STRING_YES
        self.dont_use_ntlmv1 = const.STRING_YES
        self.start_remote_registry = const.STRING_NO
        self.enable_admin_shares = const.STRING_NO
        self.apm_force_updates = kwargs.get('apm_force_updates')
        self.apm_update_timeout = '5'
        self.http_login_method = 'POST'
        self.http_reauth_delay = '0'
        self.http_login_max_redir = '0'
        self.http_login_invert_auth_regex = const.STRING_NO
        self.http_login_auth_regex_on_headers = const.STRING_NO
        self.http_login_auth_regex_nocase = const.STRING_NO
        self.snmp_port = '161'
        self.additional_snmp_port1 = '161'
        self.additional_snmp_port2 = '161'
        self.additional_snmp_port3 = '161'
        self.patch_audit_over_telnet = const.STRING_NO
        self.patch_audit_over_rsh = const.STRING_NO
        self.patch_audit_over_rexec = const.STRING_NO
        self.adtran_aos_offline_configs = ''
        self.bluecoat_proxysg_offline_configs = ''
        self.brocade_offline_configs = ''
        self.checkpoint_gaia_offline_configs = ''
        self.cisco_config_to_audit = 'Saved/(show config)'
        self.cisco_offline_configs = ''
        self.dell_f10_offline_configs = ''
        self.extremeos_offline_configs = ''
        self.fireeye_offline_configs = ''
        self.fortios_offline_configs = ''
        self.procurve_config_to_audit = 'Saved/(show config)'
        self.procurve_offline_configs = ''
        self.huawei_offline_configs = ''
        self.junos_offline_configs = ''
        self.netapp_offline_configs = ''
        self.sonicos_offline_configs = ''
        self.watchguard_offline_configs = ''
        self.agent_group_id = ''
        self.staggered_start_mins = '0'

        # Private object attributes
        self.__audits = defaultdict(lambda: defaultdict(list))
        self.__credentials = {'add': {}, 'edit': {}, 'delete': {}}
        self.__scap = {'add': {}, 'edit': {}, 'delete': {}}

        if kwargs['autogen']:
            self.name = NessusConfig.CAT_NESSUS_SCAN_NAME
            self.description = 'Created automatically by Automation'
            self.text_targets = '127.0.0.1'
            self.enabled = False

    def add_mongodb_credential(self, credential: dict):
        """
        Add MongoDB credential to model

        :param dict credential: Credential Dictionary
        """
        self._add_credential(API.Credentials.Types.CATEGORY_DATABASE,
                             API.Credentials.Database.Types.MONGODB, credential)

    def add_database_credential(self, credential: dict):
        """
        Add Database credential to model

        :param dict credential: Credential Dictionary
        """
        self._add_credential(API.Credentials.Types.CATEGORY_DATABASE,
                             API.Credentials.Types.CATEGORY_DATABASE, credential)

    # Override ssh_port if specified credential port differs then the default
    def add_ssh_credential(self, credential: dict):
        """
        Add SSH credential to model

        :param dict credential: Credential Dictionary
        """
        self._add_credential(API.Credentials.Types.CATEGORY_HOST, API.Credentials.Host.Types.SSH,
                             credential)

    def add_windows_credential(self, credential: dict):
        """
        Add Windows credential to model

        :param dict credential: Credential Dictionary
        """
        self._add_credential(API.Credentials.Types.CATEGORY_HOST, API.Credentials.Host.Types.WINDOWS,
                             credential)

    def add_aws_credential(self, credential: dict):
        """
        Add AWS credential to model

        :param dict credential: Credential Dictionary
        """
        self._add_credential(API.Credentials.Types.CATEGORY_CLOUD_SERVICES, API.Credentials.Host.Types.AWS,
                             credential)

    def add_airwatch_credential(self, credential: dict):
        """
        Add AirWatch credential to model

        :param dict credential: Credential Dictionary
        """
        self._add_credential(API.Credentials.Types.CATEGORY_MOBILE, API.Credentials.Mobile.AIRWATCH,
                             credential)

    def add_good_mdm_credential(self, credential: dict):
        """
        Add Good MDM credential to model

        :param dict credential: Credential Dictionary
        """
        self._add_credential(API.Credentials.Types.CATEGORY_MOBILE, API.Credentials.Mobile.GOODMDM,
                             credential)

    def add_microsoft_sccm_credential(self, credential: dict):
        """
        Add Microsoft SCCM credential to model

        :param dict credential: Credential Dictionary
        """
        self._add_credential(API.Credentials.Types.CATEGORY_PATCH_MANAGEMENT,
                             API.Credentials.PatchManagement.Types.MICROSOFT_SCCM, credential)

    def add_microsoft_wsus_credential(self, credential: dict):
        """
        Add Microsoft WSUS credential to model

        :param dict credential: Credential Dictionary
        """
        self._add_credential(API.Credentials.Types.CATEGORY_PATCH_MANAGEMENT,
                             API.Credentials.PatchManagement.Types.MICROSOFT_WSUS, credential)

    def add_mobile_iron_credential(self, credential: dict):
        """
        Add MobileIron credential to model

        :param dict credential: credential Dictionary
        """
        self._add_credential(API.Credentials.Types.CATEGORY_MOBILE,
                             API.Credentials.Mobile.MOBILEIRON, credential)

    def add_adsi_credential(self, credential: dict):
        """
        Add ADSI credential to model

        :param dict credential: credential Dictionary
        """
        self._add_credential(API.Credentials.Types.CATEGORY_MISCELLANEOUS,
                             API.Credentials.Miscellaneous.ADSI, credential)

    def add_apple_profile_manager_credential(self, credential: dict):
        """
        Add Apple Profile Manager credential to model

        :param dict credential: Credential Dictionary
        """
        self._add_credential(API.Credentials.Types.CATEGORY_MOBILE,
                             API.Credentials.Mobile.APM, credential)

    def add_maas360_credential(self, credential: dict):
        """
        Add MaaS360 credential to model

        :param dict credential: Credential Dictionary
        """
        self._add_credential(API.Credentials.Types.CATEGORY_MOBILE,
                             API.Credentials.Mobile.MAAS360, credential)

    def add_dell_kace_credential(self, credential: dict):
        """
        Add Dell Kace credential to model

        :param dict credential: Credential Dictionary
        """
        self._add_credential(API.Credentials.Types.CATEGORY_PATCH_MANAGEMENT,
                             API.Credentials.PatchManagement.Types.DELL_KACE, credential)

    def add_ibm_bigfix_credential(self, credential: dict):
        """
        Add IBM BigFix credential to model

        :param dict credential: Credential Dictionary
        """
        self._add_credential(API.Credentials.Types.CATEGORY_PATCH_MANAGEMENT,
                             API.Credentials.PatchManagement.Types.IBM_BIGFIX, credential)

    def add_palo_alto_pan_os_credential(self, credential: dict):
        """
        Add Palo Alto PAN-OS credential to model

        :param dict credential: Credential Dictionary
        """
        self._add_credential(API.Credentials.Types.CATEGORY_MISCELLANEOUS,
                             API.Credentials.Miscellaneous.PALO_ALTO, credential)

    def add_redhat_satellite5_credential(self, credential: dict):
        """
        Add Red Hat Satellite 5 credential to model

        :param dict credential: Credential Dictionary
        """
        self._add_credential(API.Credentials.Types.CATEGORY_PATCH_MANAGEMENT,
                             API.Credentials.PatchManagement.Types.REDHAT_SATELLITE5, credential)

    def add_redhat_satellite6_credential(self, credential: dict):
        """
        Add Red Hat Satellite 6 credential to model

        :param dict credential: Credential Dictionary
        """
        self._add_credential(API.Credentials.Types.CATEGORY_PATCH_MANAGEMENT,
                             API.Credentials.PatchManagement.Types.REDHAT_SATELLITE6, credential)

    def add_symantec_altiris_credential(self, credential: dict):
        """
        Add Symantec Altiris credential to model

        :param dict credential: Credential Dictionary
        """
        self._add_credential(API.Credentials.Types.CATEGORY_PATCH_MANAGEMENT,
                             API.Credentials.PatchManagement.Types.SYMANTEC_ALTIRIS, credential)

    def add_vmware_esx_credential(self, credential: dict):
        """
        Add VMWare ESX credential to model

        :param dict credential: Credential Dictionary
        """
        self._add_credential(API.Credentials.Types.CATEGORY_MISCELLANEOUS,
                             API.Credentials.Miscellaneous.VMWARE_ESX, credential)

    def add_vmware_vcenter_credential(self, credential: dict):
        """
        Add VMWare vCenter credential to model

        :param dict credential: Credential Dictionary
        """
        self._add_credential(API.Credentials.Types.CATEGORY_MISCELLANEOUS,
                             API.Credentials.Miscellaneous.VMWARE_VCENTER, credential)

    def add_x509_credential(self, credential: dict):
        """
        Add X.509 credential to model

        :param dict credential: Credential Dictionary
        """
        self._add_credential(API.Credentials.Types.CATEGORY_MISCELLANEOUS,
                             API.Credentials.Miscellaneous.X509, credential)

    def add_audit_file(self, audit_type: API.Audits.Type, audit: dict):
        """
        Add audit file to model

        :param dict audit: Audit Dictionary
        :param str audit_type: Audit Type (Feed, Custom)
        """
        if not isinstance(audit_type, API.Audits.Type):
            raise AttributeError('Audit type must be {0} or {1}.'.format(API.Audits.Type.Feed.value,
                                                                         API.Audits.Type.Custom.value))
        self._add_audit(audit_type.value, audit)

    def enable_report_paranoia(self, paranoia_level: ReportParanoiaTypes) -> None:
        """
        Enable Report Paranoia (i.e. Accuracy)

        :param ReportParanoiaTypes paranoia_level: Paranoia level
        :return: None
        :raises: AttributeError, if paranoia_level is not an instance ReportParanoiaTypes
        """
        if not isinstance(paranoia_level, ReportParanoiaTypes):
            raise AttributeError('Paranoia Level must be {0} or {1}'.format(
                ReportParanoiaTypes.AVOID_POTENTIAL_FALSE_ALARMS, ReportParanoiaTypes.SHOW_POTENTIAL_FALSE_ALARMS))
        self.report_paranoia = paranoia_level

    def create_payload(self) -> dict:
        """Returns a dictionary for use as a request model to API endpoints"""
        dct = {
            'credentials': {} if all([not self.__credentials['add'], not self.__credentials['edit'],
                                      not self.__credentials['delete']]) else self.__credentials,
            'plugins': self.plugins,
            'uuid': self.uuid,
            'audits': {} if not self.__audits else self.__audits,
            'settings': {},
            'scap': {} if all([not self.__scap['add'], not self.__scap['edit'],
                               not self.__scap['delete']]) else self.__scap,
        }

        attrs = self.__dict__.copy()
        settings = {}
        for key in attrs:
            if key.startswith('_BaseScanModel__'):
                continue
            if key == 'uuid':
                continue
            settings[key] = attrs[key]
        dct['settings'].update(settings)

        return dct

    def enable_plugins(self, plugin_list: list):
        """
        Enable one or more plugins

        :param list plugin_list: A list of plugins
        """
        self.plugins = plugin_list

    def _add_credential(self, category: str, credtype: str, credential: dict):
        _infinite_cred_types = [API.Credentials.Types.CATEGORY_DATABASE, API.Credentials.Host.Types.SNMPV3,
                                API.Credentials.Host.Types.SSH, API.Credentials.Host.Types.WINDOWS,
                                API.Credentials.Miscellaneous.ADSI]
        if category in self.__credentials['add'].keys():
            if credtype in self.__credentials['add'][category] and credtype not in _infinite_cred_types:
                if len(self.__credentials['add'][category][credtype]) > 1:
                    raise CatiumModelError('Multiple credentials of type "%s" are not supported.' % category)

        if category not in self.__credentials['add'].keys():
            self.__credentials['add'][category] = {}

        if credtype not in self.__credentials['add'][category].keys():
            self.__credentials['add'][category][credtype] = [credential]
        else:
            self.__credentials['add'][category][credtype].append(credential)

    def _add_audit(self, audit_type: str, audit: dict):
        self.__audits[audit_type]['add'].append(audit)

    def add_scap_credential(self, credential: dict):
        """
        Add scap credential to model

        :param dict credential: Credential Dictionary
        """
        self._add_scap_credential(API.Credentials.Host.Types.WINDOWS, "", credential)

    def _add_scap_credential(self, category: str, scaptype: str, credential: dict):
        _infinite_cred_types = [API.Credentials.Types.CATEGORY_DATABASE, API.Credentials.Host.Types.SNMPV3,
                                API.Credentials.Host.Types.SSH, API.Credentials.Host.Types.WINDOWS,
                                API.Credentials.Miscellaneous.ADSI]

        if category in self.__scap['add'].keys():
            if scaptype in self.__scap['add'][category] and scaptype not in _infinite_cred_types:
                if len(self.__scap['add'][category][scaptype]) > 1:
                    raise CatiumModelError('Multiple credentials of type "%s" are not supported.' % category)

        if category not in self.__scap['add'].keys():
            self.__scap['add'][category] = {}

        if scaptype not in self.__scap['add'][category].keys():
            self.__scap['add'][category] = [credential]
        else:
            self.__scap['add'][category].append(credential)
