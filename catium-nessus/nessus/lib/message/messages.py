"""
Nessus Messages and notifications

:copyright: Tenable Network Security, 2017
:date: July 25, 2017
:last_modified: April 18, 2023
:author: @rdutta, @mameta, @ntarwani, @kpanchal, @krpatel
"""


class Messages:
    """String Messages for Nessus"""

    class NotificationMessages:
        """ common Notification Messages """
        continue_without_password = "Error: Password can not be empty."
        continue_button_code = "Error: Please correct all form errors to continue."
        invalid_time_integer = "Error: Please enter a valid integer between 1 and 365."
        enabled_success = "Freeze window enabled successfully."
        freeze_window_create_success = 'Freeze window created successfully.'
        freeze_window_edit_success = 'Freeze window edited successfully.'
        freeze_window_delete_success = 'Freeze window deleted successfully.'
        edit_success = "Freeze window edited successfully."
        invalid_end_time = "Error: End time is before start time."
        duplicate_name = "Error: A freeze window with that name already exists"
        save_scan = "Scan saved successfully."
        scan_move_to_trash = "Scan moved to trash successfully."
        delete_scan = "Scan deleted successfully."
        invalid_udp_port = "Error: UDP port is invalid."
        invalid_max_crawl = "Error: Maximum pages to crawl is invalid."
        import_scan_success = "File imported successfully."
        invalid_email = "Error: Please enter a valid email address to continue."
        invalid_current_password = "Error: Current password is invalid"
        new_password_blank = "Error: New password can not be empty."
        save_change_password = "Account settings updated successfully."
        ldap_connection_error = 'Error: Failed to connect to the LDAP server: LDAP server not specified.'
        saved_smtp_settings = 'SMTP settings updated successfully.'
        smtp_email_sent = 'SMTP Email successfully sent to: '
        custom_ca_updated = 'Custom CA updated successfully.'
        invalid_custom_ca = 'Error: Invalid CA data'
        update_to_pro = 'Successfully upgraded to Nessus Pro 7'
        downgrade_to_professional_legacy = 'Successfully downgraded from Nessus Pro 7'
        target_required_error = 'Error: Targets is required.'
        no_plugins_found_error = 'Error: No plugins were found.'
        save_settings = "Settings saved successfully."
        export_csv_error = "Error: No columns selected for CSV export."
        scan_restriction_error = 'Error: Scan saving is restricted due to modification of the license ' \
                                 'restrictions file.'
        policy_restriction_error = 'Error: Policy saving is restricted due to modification of the license ' \
                                   'restrictions file.'
        select_host_on_scan_wizard_error = 'Error: Please select some hosts to scan for vulnerabilities.'
        missing_user_details = "Error: Missing First Name. Missing Last Name. Missing Email."
        missing_first_name = 'Error: Missing First Name.'
        missing_last_name = "Error: Missing Last Name."
        missing_email = "Error: Missing Email."
        blank_email = "Email address cannot be blank"
        blank_last_name = "Last Name cannot be blank"
        blank_first_name = "First Name cannot be blank"
        missing_activation_code = 'Error: Missing Activation Code.'
        missing_linking_key = "Error: Missing key."
        missing_host_and_key = 'Error: Missing host. Missing key.'
        missing_host_port_and_key = 'Error: Missing host. Missing port. Missing key.'
        missing_username_password = 'Error: Missing Username. Missing Password.'
        missing_password = 'Error: Missing Password.'
        missing_username = 'Error: Missing Username.'
        missing_offline_keys = 'Error: Missing Offline Nessus License.'
        update_server_error = 'Error: Update Server must be a hostname or IP address, with or without a valid port.'
        failed_to_login = 'Error: Failed login attempt occurred'
        new_and_current_password_mismatch = "Error: New password can not match the current password"
        tenable_io_linking_error = 'Error: [401] This scanner, agent, or API key token does not appear to be related ' \
                                   'to any active containers on any sites and has been blacklisted.'
        target_to_capture_error = "Error: Target to capture is required."
        ports_to_capture_error = "Error: Ports to capture is required."
        single_log_delete_success = "Log deleted successfully."
        multiple_logs_delete_success = "Logs deleted successfully."
        offline_mode_route_error = "Error: Route not available because the scanner is configured in offline mode"

        class PluginLocales:
            """Notification messages related to Agents page in Nessus."""
            locales_saved_successfully = 'Locale settings saved successfully.'

        class Agents:
            """Notification messages related to Agents page in Nessus."""
            unlink_agents = 'Agents unlinked successfully.'
            delete_agents = 'Agents deleted successfully.'
            delete_agent = 'Agent deleted successfully.'
            unlink_agent = 'Agent unlinked successfully.'
            key_changed_success = 'Linking key changed successfully; Nessus will restart shortly.'

            class AgentGroups:
                """Notification messages related to Agent Groups page under Agents tab in Nessus."""
                group_added = 'Group added successfully.'
                agents_added_to_groups = 'Agents added to group(s) successfully.'
                agent_added_to_groups = 'Agent added to group(s) successfully.'
                delete_agent_group = 'Agent group deleted successfully.'
                edit_agent_group = 'Agent group edited successfully.'
                remove_agent = 'Agent removed successfully.'
                remove_agents = 'Agents removed successfully.'

            class AgentCluster:
                """ Notification messages related to Agent Cluster under Agents tab in Nessus. """
                nessus_backend_restart = 'The Nessus backend will restart shortly.'
                node_updated = 'Agent node updated successfully.'
                node_enabled = 'Agent node enabled successfully.'
                node_disabled = 'Agent node disabled successfully.'
                rebalance_node = 'Agent rebalance started successfully.'
                rebalancing_node_status_pending = 'NOTICE: Agents are currently rebalancing across your ' \
                                                  'nodes: status pending.'
                delete_cluster_group = 'Cluster Group deleted successfully.'
                add_node_to_group = 'Cluster Node added to group successfully.'
                add_agent_to_group = 'Agent added to group successfully.'
                move_node_to_group = 'Node successfully moved to new cluster group.'
                move_agent_to_group = 'Agent successfully moved to new cluster group.'
                unable_to_delete_cluster_group = "Error: Cannot delete cluster group that has nodes assigned to it. " \
                                                 "Move the nodes to another cluster group and try again."
                unable_to_assign_agents_to_group = "Error: Cannot assign agents to a cluster group that does not " \
                                                   "have any assigned nodes. Assign a node to the cluster group " \
                                                   "and try again."
                unable_to_delete_node_from_group = "Error: Cannot delete the last node in a cluster group that still " \
                                                   "has agents assigned to it. Move the agents to another cluster " \
                                                   "group and try again."
                change_cluster_group = 'Cluster group changed successfully'
                empty_cluster_group_name = 'Error: The cluster group name is empty.'
                create_cluster_group_error = 'Error: Please correct all form errors to continue.'
                save_agent_node_setting = 'Agent node settings updated successfully.'
                max_scan_cutoff_value_error = "Error: Please enter a valid integer less than or equal to 2147483647"
                min_scan_cutoff_value_error = "Error: Please enter a valid integer greater than or equal to 300"
                max_global_agent_node_error = "Error: Please enter a valid integer between 0 and 20000 (inclusive)."

            class AgentSettings:
                """ Notification messages related to Agent Settings """
                edit_agent_setting = 'Agent settings edited successfully.'

        class PlugInRules:
            """Notification messages related to PlugIn rules page in Nessus."""
            delete_rule = "Rule deleted successfully."
            bulk_delete_rules = "Rules deleted successfully."
            add_rule = "Rule added successfully."
            update_rule = "Rule updated successfully."

        class ProxyServer:
            """Notification messages related to Proxy server page in Nessus."""
            proxy_server_saved = "Proxy settings updated successfully. Nessus will restart for the settings to take " \
                                 "effect."
            proxy_successfully_connected = "Proxy successfully connected to 'plugins.nessus.org:443'" \
                                           " using authentication method"
            proxy_server_connection_error = "Error: Connection to proxy {}:{} failed"

        class SMTPServer:
            recepient_error = "Error: It was not possible to email this scan:\nCan't open a socket on port 8025"

        class About:
            """Notification messages related to About page in Nessus."""
            update_plugins = "Software update scheduled successfully."
            settings_saved = "Software Update settings saved successfully."
            logs_requested = "Logs requested."
            master_password_saved_successfully = "Encryption Password updated successfully."
            purchase_np_message = 'Please complete your purchase of Nessus Professional in the new browser window' \
                                  ' that was just opened. Once finished, simply click on the "Purchase Completed" ' \
                                  'button below and Nessus will restart to refresh your license. If the transaction ' \
                                  'did not complete or you are not ready to purchase please click on "Cancel."'

        class Scans:
            """Messages and Notifications related to Scans page in Nessus."""
            empty_scan_list = "This folder is empty."
            invalid_import_format = "Error: Upload Failed. Unsupported file format."
            scan_copied = "Scan copied successfully."
            scans_copied = "Scans copied successfully."
            scan_moved = "Scan moved successfully."
            scans_moved = "Scans moved successfully."
            scans_deleted = "Scans deleted successfully."
            required_scan_name = "Error: Name is required."
            required_agent_group = "Error: Agent Groups is required."
            invalid_scheduled_time = "Error: The scheduled start time is in the past."
            invalid_target = "there are no valid targets"
            unresolved_target = 'Target "{}" was not scanned because IP address resolution failed using flags 6.'
            empty_scan_page_message = "This folder is empty. Create a new scan."
            empty_trash = "Your trash is empty."

        class ScanResults:
            """Messages and Notifications related to Scan_Results page in Nessus."""
            vulnerability_modified = "Vulnerability modified successfully."
            vulnerabilities_modified = "Vulnerabilities modified successfully."
            host_deleted = "Host deleted successfully."
            hosts_deleted = "Hosts deleted successfully."
            history_deleted = "Results deleted successfully."
            vulnerability_snoozed = "Vulnerability snoozed successfully."
            vulnerabilities_snoozed = "Vulnerabilities snoozed successfully."
            vulnerability_awoken = 'Vulnerability awoken successfully.'
            vulnerabilities_awoken = "Vulnerabilities awoken successfully."
            vulnerabilities_snooze_pop_up_message_one_day = \
                "Are you sure you want to snooze this vulnerability for 1 day?"
            vulnerability_wake_popup_message = 'Are you sure you want to wake this vulnerability?'
            vulnerabilities_wake_popup_message = "Are you sure you want to wake these vulnerabilities?"
            max_schedule_scan_popup_title = "Confirm Scan Schedule Save"
            max_schedule_scan_popup_content = "WARNING: Saving will disable schedules for 1 other scan."
            enable_dashboard_popup_content = "Are you sure you want to enable the dashboard for this scan?"
            empty_custom_date_error = "Error: Custom date can not be empty."

        class Policies:
            """Messages and Notifications related to Policies page in Nessus."""
            empty_policy_list = "No policies have been created."
            invalid_import_format = "Error: Invalid file name."
            policy_imported = "File uploaded successfully."
            policy_import_initiated = "Policy upload has initiated."
            policy_saved = "Policy saved successfully."
            policy_copied = "Policy copied successfully."
            policies_copied = "Policies copied successfully."
            policy_deleted = "Policy deleted successfully."
            policies_deleted = "Policies deleted successfully."
            audit_policy_validation = "Error: At least one audit must be added to this policy in the 'Compliance' " \
                                      "section."
            cred_patch_audit_validation = "Error: One of the following credentials must be added to this policy: " \
                                          "SNMPv1/v2c, Windows, SSH, SNMPv3, IBM DataPower Gateway, HCL BigFix, " \
                                          "Symantec Altiris, Red Hat Satellite 6 Server, Microsoft SCCM, " \
                                          "Red Hat Satellite Server, Dell KACE K1000, IBM Tivoli Endpoint Manager " \
                                          "(BigFix), Microsoft WSUS, VMware vCenter API, Palo Alto Networks PAN-OS, " \
                                          "VMware vCenter SOAP API, VMware ESX SOAP API, ADSI, MongoDB, Database"
            malware_credential_validation = "Error: One of the following credentials must be added to this policy: " \
                                            "Windows, SSH, IBM DataPower Gateway"
            mobile_device_validation = "Error: One of the following credentials must be added to this policy: " \
                                       "Workspace ONE, MobileIron, MaaS360, AirWatch, Intune, Good MDM, Blackberry UEM, Apple " \
                                       "Profile Manager, ADSI"

        class SideNavFolders:
            """Messages and Notifications related to SideNav Folders in Nessus."""
            folder_added = "Folder added successfully."
            delete_folder = "Folder deleted successfully."
            folder_updated = "Folder updated successfully."
            duplicate_folder_error = "Error: A folder with the same name already exists"
            invalid_name_error = "Error: Invalid 'name' field: "

        class Groups:
            """Messages and Notifications, related to Groups page in Nessus."""
            empty_group_list = 'No groups have been created.'
            duplicate_group_name = 'Error: A group with that name already exists'
            edit_group_name = 'Group edited successfully.'
            delete_bulk_groups = 'Groups deleted successfully.'
            remove_user = 'User removed successfully.'

        class Users:
            """Notification messages related to Users page in Nessus"""
            success_sign_out = "Signed out successfully. Goodbye, admin."
            invalid_credentials = "Error: Invalid Credentials"
            invalid_username = "Error: Invalid 'username' field"
            session_expired = "Error: Session expired"
            unauthorized_user = "Error: You are not authorized to perform this request."
            duplicate_username = 'Error: Duplicate username'
            user_updated = 'User updated successfully.'
            create_user = 'User created successfully.'
            no_record_found = 'No records found.'
            api_keys_generation = 'Keys generated successfully.'
            empty_user_list = 'No users have been added to this group.'
            user_group_page_name = 'Groups / '
            error_message = 'Error: No users available.'
            delete_user = "User deleted successfully."
            delete_bulk_user = "Users deleted successfully."
            invalid_master_password = "Error: Current encryption password is invalid"
            sessions_limit_violated = "Error: Too many active sessions."
            success_transfer_data = 'User data transferred successfully.'

        class Agent:
            """Notification messages related to agent page in Nessus"""
            required_name = "Error: Name is required."
            invalid_content = "Error: SCAP content must be added to this policy."
            required_scap_file = "Error: SCAP File (zip) is required."

        class PasswordManagement:
            """Notification messages related to Password Management page in Nessus"""
            max_login_attempts_error = 'Error: Account is locked out'
            settings_updated = 'Password settings updated successfully.'
            min_passwd_length_error = 'Error: New password failed to meet password rules. ' \
                                      'Password is too short (must be at least {} chars long)'
            min_passwd_length_error_with_complexity = 'Error: When complexity is enabled ' \
                                                      'minimum password length must be 8 or greater.'
            passwd_complexity_error = 'Error: New password failed to meet password rules. ' \
                                      'TIP: Add special character(s).'
            password_req_title = 'Password requirements'
            password_req_description = "Minimum number of characters to 8, and at least three of the following: at " \
                                       "least one upper case letter, at least one lower case letter, at least one " \
                                       "special character, at least one number."

        class Scap:
            """Notification messages related to SCAP and OVAL Auditing page in Nessus"""
            scap_content_error = 'Error: SCAP content must be added to this policy.'
            data_stream_error = 'Error: SCAP Data Stream ID is required.'
            benchmark_id_error = 'Error: SCAP Benchmark ID is required.'
            scap_file_error = 'Error: SCAP File (zip) is required.'
            oval_file_error = 'Error: OVAL definitions file is required.'
            scap_ssh_credential_error = 'Error: Linux SCAP requires SSH credentials.'
            scap_window_credential_error = 'Error: Windows SCAP requires Windows credentials.'
            scap_oval_ssh_credential_error = 'Error: Linux (OVAL) SCAP requires SSH credentials.'
            scap_oval_window_credential_error = 'Error: Windows (OVAL) SCAP requires Windows credentials.'

        class Credentials:
            """Notification messages related to Credentials in Nessus."""
            app_id = "Error: AppId is required."
            credential_host = 'Error: CyberArk Host is required.'
            credential_port = 'Error: Central Credential Provider Port is required.'
            key_dis_center_element = 'Error: Key Distribution Center (KDC) is required.'
            escalation_password_element = 'Error: SSH user password is required.'
            su_user_element = 'Error: su user is required.'
            server_url_element = 'Error: Thycotic Secret Server URL is required.'
            private_key = 'Error: Private key is required.'
            escalation_account_element = 'Error: Escalation account is required.'
            username = 'Error: Username is required.'
            checkout_duration_element = 'Error: Checkout duration is required.'
            authentication_password_element = 'Error: Authentication password is required.'
            privacy_password = 'Error: Privacy password is required.'
            secret_name_element = 'Error: Thycotic Secret Name is required.'
            hash_element = 'Error: Hash is required.'
            beyond_trust_api_key_element = 'Error: BeyondTrust API key is required.'
            api_url = 'Error: AirWatch Environment API URL is required.'
            password = 'Error: Password is required.'
            server = 'Error: Server is required.'
            app_access_key = 'Error: App access key is required.'
            portal_url = 'Error: VSP Admin Portal URL is required.'
            login_page = 'Error: Login page is required.'
            required_cookies_file = 'Error: Cookies file is required.'
            oracle_sid = 'Error: Service is required.'
            database_name = 'Error: Database Name is required.'
            cyberark_element = 'Error: CyberArk Account Details Name is required.'
            lieberman_host = 'Error: Lieberman host is required.'
            lieberman_user = 'Error: Lieberman user is required.'
            domain = 'Error: Domain is required.'
            satellite_server = 'Error: Satellite server is required.'
            domain_controller = 'Error: Domain Controller is required.'
            client_certificate = 'Error: Client certificate is required.'
            vcenter_host = 'Error: vCenter Host is required.'
            web_reports_server = 'Error: Web Reports Server is required.'
            client_id = 'Error: Client Id is required.'
            application_id_for_key = application_id_for_password = 'Error: Application ID is required.'
            access_key = 'Error: AWS Access Key ID is required.'
            client_secret = 'Error: Client Secret is required.'
            password_or_api_key_error = 'Error: Password or API Key is required.'

        class AdvancedSettings:
            server_restart_message = "NOTICE: The Nessus web server must restart before some settings will take " \
                                     "effect. Restart now."
            no_record_found = 'No records found.'

        class UpgradeAssistant:
            invalid_access_key = "Error: Access Key is required."
            invalid_secret_key = "Error: Secret Key is required."
            invalid_domain = "Error: Tenable Vulnerability Management domain is required."
            invalid_all_field = "Error: Please fill in all the required fields."

        class CustomizedReports:
            REPORT_TEMPLATE_SAVED = "Report template saved successfully."
            EMPTY_CHAPTERS_ERROR = 'Error: You must have at least one chapter.'
            EMPTY_TEMPLATE_NAME_ERROR = "Error: Name is required."

    class NessusCli:
        """Messages for Nessus CLI"""
        PLUGIN_UPDATE_STARTED = 'Nessus Plugins Update: Started'
        PLUGIN_UPDATE_FINISHED = 'Nessus Plugins Update: Finished'
        PLUGIN_NOUPDATE = 'Nessus Plugins Update: No Update'
        PLUGIN_REGISTERED = 'Successfully registered plugin feed'
        UI_UPTODATE = 'Remote Core: UI up to date'
        PLUGIN_UPDATE_SUCCESSFUL = 'Update successful.  The changes will be automatically processed by Nessus.'
        DB_TREE_READ_DATA_ERROR = "db_tree_read_data: invalid qdb data entry"
        NESSUS_CORE_UPDATE_STARTED = 'Nessus Core Components Update: Started'
        GLOBAL_DB_UPGRADE_COMPLETE = '[info] [globaldb] Upgrade complete.'
        ACCOUNT_EXPIRED = "Account expired"

    class ToolTip:
        """Tool tip messages for Nessus"""
        expert_title = "The industry leading vulnerability assessment solution for the modern attack surface"
        professional_title = "Trial the de-facto industry standard vulnerability assessment solution for security practitioners."
        plugin_tab_eye_icon_tool_tip = 'Plugins are read only in this template. ' \
                                       'To customize, create an "Advanced Scan."'
        snooze_icon = "Snooze"
        snoozed_for_one_day = "Snoozing for a day... Click to wake."
        snoozed_for_one_week = "Snoozing for 7 days... Click to wake."
        snoozed_for_one_month = "Snoozing for a month... Click to wake."
        system_link_tool_tip = "Reset to System Default"
        references = 'BID/XREF/MSKB'
        plugin_information = 'Plugin Publication Date/Plugin Modification Date'
        exploitable_with = 'Metasploit/Core Impact/CANVAS'
        nessus_essentials = "The free version of Nessus for educators, students, and hobbyists."
        nessus_manager = "The enterprise solution for managing Nessus Agents at scale."
        nessus_professional = "The de-facto industry standard vulnerability assessment solution for security" \
                              " practitioners."
        managed_scanner = "Link your scanner to another Tenable solution such as Tenable Vulnerability Management or Tenable Security Center."
        top_radiobutton_tip = "Activate your Nessus Expert, Nessus Professional or Nessus Manager"

    class Home:
        """Messages related to nessus home"""
        max_schedule_scan_limit = "NOTE: Only one schedule can be enabled. Any other scheduled scans will be disabled" \
                                  ". Upgrade to Nessus Professional"

    class ExpiredLicense:
        """Messages related to nessus home"""
        scan_launch_disabled = "Error: Scans are disabled due to license expiration."
        schedule_scan_warning = "NOTE: Scan schedules are disabled due to license expiration."
        license_expired = "Error: Your plugin feed subscription expired 1 day(s) ago."
        warning_for_expired_license = 'Your license expired on {} ({} days ago)'
        warning_message_today = 'Your license has expired today, {}'
        warning_message_for_future = 'Your license will expire in {} days, on {}'

    class NessusAgent:
        """Nessus agent backend.log verification messages"""
        SCAN_DISABLED_IN_FREEZE = "Scans disabled due to an active freeze window"
        PLUGINS_BLOCKED = "Plugin updates disabled due to an active permanent freeze window"
        CORE_UPDATES_BLOCKED = "Core updates disabled due to an active permanent freeze window"
