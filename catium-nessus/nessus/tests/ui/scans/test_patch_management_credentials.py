"""
Nessus Credentials tab under Policy/Scan form related test cases For Host -> Patch Management
:copyright: Tenable Network Security, 2017
:date: May 9, 2018
:last_modified: July 13, 2018
:author: @ntarwani, @mameta
"""

import pytest

from nessus.helpers.scan import save_and_configure_scan
from nessus.lib.const import API, Nessus
from nessus.pageobjects.credentials.patch_management import MicrosoftSCCM, DellKaceK1000, PatchManagement, \
    SymantecAltiris
from nessus.pageobjects.sidenav.sidenav import SideNav


@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestUICredentialsPatchManagementForm:
    """
     NQA-1145- Advanced Scan > Credentials > Patch Management related Test cases
     NQA-1286- Verify mandatory field validation while edit for Advanced scan with credentials -> Patch Management
    """

    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_microsoft_sccm_credentials(self, create_scan):
        """
        NQA-1149- Fill form for Advanced Scan > Credentials > Patch Management > Microsoft SCCM
        1. Navigate to 'Advanced scan' template from scanner tab
        2. Give valid name and target
        3. Go to Credentials tab and select Patch Management > Microsoft SCCM
        4. Fill the form
        5. Save the scan
        6. Click on created scan
        7. Verify the values saved are retained

        NQA-1286- Verify mandatory field validation while edit for Advanced scan with credentials -> Patch Management
        - Repeat steps 1 to 7 from NQA-1149
        - Under Microsoft SCCM remove 'Domain' and hit ‘Save’
        - Validation message should appear
        """
        scan_name = create_scan
        microsoft_form_data = {'server': '10.10.13.11', 'username': 'admin', 'password': 'admin', 'domain': 'tenable'}

        microsoft_sccm = MicrosoftSCCM(patch_type=API.Credentials.PatchManagement.Types.MICROSOFT_SCCM)
        assert microsoft_sccm.opened_form_value == API.Credentials.PatchManagement.Types.MICROSOFT_SCCM, \
            'Microsoft SCCM form is not open'

        microsoft_sccm.fill_microsoft_sccm_form(**microsoft_form_data)
        save_and_configure_scan(class_object=microsoft_sccm, scan_name=scan_name)

        assert len(microsoft_sccm.active_credentials) == 1, "More than 1 credentials are available"

        microsoft_sccm.open_saved_credentials_component(form_name=API.Credentials.PatchManagement.Types.MICROSOFT_SCCM)
        microsoft_form_data.update({'password': '********'})
        assert microsoft_sccm.get_microsoft_sccm_data() == microsoft_form_data, "Data saved is missing or incorrect"

        assert microsoft_sccm.check_required_field_validation(class_instance=microsoft_sccm, element="domain"), \
            'Error notification for blank required "Domain" field is missing.'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)

    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_dell_kace_credentials(self, create_scan):
        """
        NQA-1146- Fill form for Advanced Scan > Credentials > Patch Management > Dell Kace K1000
        1. Navigate to 'Advanced scan' template from scanner tab
        2. Give valid name and target
        3. Go to Credentials tab and select Patch Management > Dell Kace K1000
        4. Fill the form
        5. Save the scan
        6. Click on created scan
        7. Verify the values saved are retained

        NQA-1286- Verify mandatory field validation while edit for Advanced scan with credentials -> Patch Management
        - Repeat steps 1 to 7 from -NQA-1146
        - Under Dell KACE K1000 remove 'Server' and hit ‘Save’
        - Validation message should appear
        """
        scan_name = create_scan
        dell_kace = {'server': '10.10.13.11', 'username': 'admin', 'password': 'admin', 'port': '3301',
                     'org_db_name': 'ORG 1'}

        dell_kace_cred = DellKaceK1000(patch_type=API.Credentials.PatchManagement.Types.DELL_KACE)
        assert dell_kace_cred.opened_form_value == API.Credentials.PatchManagement.Types.DELL_KACE, \
            "Dell Kace K1000 form is not opened"

        dell_kace_cred.fill_dell_kace_form(**dell_kace)
        save_and_configure_scan(class_object=dell_kace_cred, scan_name=scan_name)

        assert len(dell_kace_cred.active_credentials) == 1, "More than 1 credentials are available"

        dell_kace_cred.open_saved_credentials_component(form_name=API.Credentials.PatchManagement.Types.DELL_KACE)
        dell_kace.update({'password': '********'})
        assert dell_kace_cred.get_dell_kace_form() == dell_kace, "Data saved is missing or incorrect"

        assert dell_kace_cred.check_required_field_validation(class_instance=dell_kace_cred, element="server"), \
            'Error notification for blank required "server" field is missing.'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)

    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    @pytest.mark.parametrize("form_data, element_to_validate",
                             [({'form_name': API.Credentials.PatchManagement.Types.REDHAT_SATELLITE6,
                                'username': 'admin', 'password': 'admin', 'port': '443', 'server': '172.26.25.16'},
                               'username'),
                              ({'form_name': API.Credentials.PatchManagement.Types.IBM_BIGFIX, 'username': 'admin',
                                'password': 'admin', 'port': '443', 'server': '172.26.22.35'},
                               'server'),
                              ({'form_name': API.Credentials.PatchManagement.Types.MICROSOFT_WSUS, 'username': 'admin',
                                'password': 'admin', 'port': '8530', 'server': '172.26.22.35'}, 'username')])
    @pytest.mark.parametrize("https_toggle, verify_ssl", [(True, True), (True, False), (False, None)])
    def test_red_hat_6_microsoft_wsus_ibm_credentials(self, create_scan, form_data, element_to_validate, https_toggle,
                                                      verify_ssl):
        """
        NQA-1147- Fill form for Advanced Scan > Credentials > Patch Management > IBM Tivoli Endpoint Manager(BigFix)
        NQA-1150- Fill form for Advanced Scan > Credentials > Patch Management > Microsoft WSUS
        NQA-1151- Fill form for Advanced Scan > Credentials > Patch Management > Red Hat Satellite 6 server
        1. Navigate to 'Advanced scan' template from scanner tab
        2. Give valid name and target
        3. Go to Credentials tab and select Patch Management > IBM Tivoli Endpoint Manager(BigFix).
        4. Fill the form
        5. Save the scan
        6. Click on created scan
        7. Verify the values saved are retained
        8. Repeat case for Microsoft WSUS and Red Hat Satellite 6 server

        NQA-1286- Verify mandatory field validation while edit for Advanced scan with credentials -> Patch Management
        - Repeat steps 1 to 7 from above test cases
        - Under above test case remove required field and hit ‘Save’
        - Validation message should appear
        """
        scan_name = create_scan
        patch_type = form_data['form_name']

        form_data.update({'https_toggle': https_toggle})
        if verify_ssl is not None:
            form_data.update({'verify_ssl': verify_ssl})
        else:
            try:
                del form_data['verify_ssl']
            except KeyError:
                pass

        patch_mgmt = PatchManagement(patch_type=patch_type)
        patch_mgmt.fill_red_hat_microsoft_and_ibm_form(**form_data)
        save_and_configure_scan(class_object=patch_mgmt, scan_name=scan_name)
        assert len(patch_mgmt.active_credentials) == 1, "More than one credentials is present"

        patch_mgmt.open_saved_credentials_component(form_name=patch_type)
        form_data.update({'password': '********'})
        assert patch_mgmt.get_red_hat_microsoft_and_ibm_data(form_name=patch_type) == form_data, \
            "Data saved is missing or incorrect"
        if form_data['form_name'] == API.Credentials.PatchManagement.Types.IBM_BIGFIX:
            assert patch_mgmt.check_required_field_validation(class_instance=patch_mgmt, element='server',
                                                              error_message='web_reports_server'), \
                'Error notification for blank required "Web Reports Server" field is missing.'
        else:
            assert patch_mgmt.check_required_field_validation(class_instance=patch_mgmt, element=element_to_validate), \
                'Error notification for blank required {} field is missing.'.format(element_to_validate)

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)

    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    @pytest.mark.parametrize("verify_ssl", [False, True])
    def test_red_hat_5_credentials(self, create_scan, verify_ssl):
        """
        NQA-1152- Fill form for Advanced Scan > Credentials > Patch Management > Red Hat Satellite 5 Server
        1. Navigate to 'Advanced scan' template from scanner tab
        2. Give valid name and target
        3. Go to Credentials tab and select Patch Management > Red Hat Satellite 5 Server
        4. Fill the form
        5. Save the scan
        6. Click on created scan
        7. Verify the values saved are retained

        NQA-1286- Verify mandatory field validation while edit for Advanced scan with credentials -> Patch Management
        - Repeat steps 1 to 7 from NQA-1152
        - Under Red Hat Satellite 5 Server remove 'Satellite server' and hit ‘Save’
        - Validation message should appear
        """
        scan_name = create_scan
        form_data = {'form_name': 'Red Hat Satellite Server', 'username': 'admin', 'password': 'admin', 'port': '443',
                     'server': '172.26.25.16', 'verify_ssl': verify_ssl}

        red_hat5 = PatchManagement(patch_type=API.Credentials.PatchManagement.Types.REDHAT_SATELLITE5)
        assert red_hat5.opened_form_value == API.Credentials.PatchManagement.Types.REDHAT_SATELLITE5, \
            'Red hat Satellite 5 Server form is not open'

        red_hat5.fill_red_hat_microsoft_and_ibm_form(**form_data)
        save_and_configure_scan(class_object=red_hat5, scan_name=scan_name)
        assert len(red_hat5.active_credentials) == 1, "More than one credentials is present"

        red_hat5.open_saved_credentials_component(
            form_name=API.Credentials.PatchManagement.Types.REDHAT_SATELLITE5_FORM_NAME)
        form_data.update({'password': '********'})
        assert red_hat5.get_red_hat_microsoft_and_ibm_data(
            form_name=API.Credentials.PatchManagement.Types.REDHAT_SATELLITE5) == form_data, \
            "Data saved is missing or incorrect"

        assert red_hat5.check_required_field_validation(class_instance=red_hat5, element='server',
                                                        error_message='satellite_server'), \
            'Error notification for blank required "Satellite Server" field is missing.'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)

    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_symantec_altiris_credentials(self, create_scan):
        """
       NQA-1153- Fill form for Advanced Scan > Credentials > Patch Management > Symantec Altiris
       1. Navigate to 'Advanced scan' template from scanner tab
       2. Give valid name and target
       3. Go to Credentials tab and select Patch Management > Symantec Altiris
       4. Fill the form
       5. Save the scan
       6. Click on created scan
       7. Verify the values saved are retained

       NQA-1286- Verify mandatory field validation while edit for Advanced scan with credentials -> Patch Management
        - Repeat steps 1 to 7 from NQA-1153
        - Under Symantec Altiris remove 'Server' and hit ‘Save’
        - Validation message should appear
       """
        scan_name = create_scan
        symantec_form_data = {'username': 'admin', 'port': '5690', 'db_name': 'Symantec_CMDB',
                              'password': 'admin', 'server': '172.26.25.16', 'use_win_auth': True}

        symantec = SymantecAltiris(patch_type=API.Credentials.PatchManagement.Types.SYMANTEC_ALTIRIS)
        assert symantec.opened_form_value == API.Credentials.PatchManagement.Types.SYMANTEC_ALTIRIS, \
            'Symantec Altiris form is not open'

        symantec.fill_symantec_altiris_form(**symantec_form_data)
        save_and_configure_scan(class_object=symantec, scan_name=scan_name)
        assert len(symantec.active_credentials) == 1, "More than one credentials is present"

        symantec.open_saved_credentials_component(form_name=API.Credentials.PatchManagement.Types.SYMANTEC_ALTIRIS)
        symantec_form_data.update({'password': '********'})
        assert symantec.get_symantec_form_data() == symantec_form_data, "Data saved is missing or incorrect"

        assert symantec.check_required_field_validation(class_instance=symantec, element='server'), \
            'Error notification for blank required "server" field is missing.'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
