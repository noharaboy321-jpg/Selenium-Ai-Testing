"""
Nessus credential tab under scan form related test case For Mobile -> AirWatch

:Copyright: Tenable Network Security, 2018
:Date: May 03, 2018
:last_modified: July 06, 2018
:Author: @jchavda, @kpanchal
"""
import pytest

from catium.lib.const import WAIT_SHORT
from nessus.helpers.scan import save_and_configure_scan
from nessus.lib.const import API, Nessus
from nessus.pageobjects.credentials.mobile_credential import AirWatch, AppleProfileManager, GoodMDM, MaaS360, MobileIron
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav


@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestMobileCredentialForm:
    """NQA-1130 : Credentials -> Category 'Mobile' -> AirWatch form related Test cases"""

    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    @pytest.mark.parametrize("http_toggle, ssl, element_to_validate",
                             [(True, True, 'api_url'), (True, False, None), (False, None, None)])
    def test_airwatch_form(self, create_scan, http_toggle, ssl, element_to_validate):
        """
        NQA-1131 : Verify 'advanced scan' under 'Scanner' tab is saved with credentials -> 'Mobile' -> 'AirWatch'
        1. Navigate Advanced scan template
        2. Give name and target
        3. Go to Credential --> Mobile --> AirWatch
        4. Fill the form
        5. Save scan
        6. Click on created scan
        7. Verify saved values are retained

        NQA-1282: Verify mandatory field validation while edit for Advanced scan with credentials -> Mobile
        1. Repeat steps 1 to 7 from NQA-1131
        2. Under AirWatch, remove AirWatch Environment API URL and save the scan.
        3. Validation message should appear.
        """
        form_data = {'api_url': 'as705.awmdm.com/airwatchservices/0/',
                     'port': API.Credentials.Mobile.Ports.PORT,
                     'username': 'apiuser',
                     'api_key': '1UQH4IQQAAG6A45QAUAA',
                     'http_switch': http_toggle}

        if ssl is not None:
            form_data.update({'ssl': ssl})
        else:
            try:
                del form_data['ssl']
            except KeyError:
                pass

        scan_name = create_scan
        mobile_page = AirWatch(mobile_credential_type=API.Credentials.Mobile.AIRWATCH)
        assert mobile_page.get_credentials_types(category_name='Mobile') == API.Credentials.Mobile.MOBILE_LIST, \
            'Category Type is missing'
        assert mobile_page.opened_form_value == API.Credentials.Mobile.AIRWATCH, 'Mobile form is not open'

        mobile_page.fill_airwatch_form(**form_data, password='Sapphire123!@#')
        save_and_configure_scan(class_object=mobile_page, scan_name=scan_name)
        assert len(mobile_page.active_credentials) == 1, "More than 1 credentials are available"

        mobile_page.open_saved_credentials_component(form_name=API.Credentials.Mobile.AIRWATCH)
        assert mobile_page.get_airwatch_form_data() == form_data, 'Data saved is incorrect or missing'

        if element_to_validate:
            assert mobile_page.check_required_field_validation(
                class_instance=mobile_page, element=element_to_validate), \
                'Error notification for blank {} is missing.'.format(element_to_validate)

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    @pytest.mark.parametrize("http_toggle, ssl, element_to_validate",
                             [(True, True, 'password'), (True, False, None), (False, None, None)])
    def test_apple_profile_manager_form(self, create_scan, http_toggle, ssl, element_to_validate):
        """
        NQA-1148 : Verify 'advanced scan' under 'Scanner' tab is saved with credentials -> 'Mobile' -> 'Apple Profile
        Manager'
        1. Navigate Advanced scan template
        2. Give name and target
        3. Go to Credential --> Mobile --> Apple Profile Manager
        4. Fill the form
        5. Save scan
        6. Click on created scan
        7. Verify saved values are retained

        NQA-1282: Verify mandatory field validation while edit for Advanced scan with credentials -> Mobile
        1. Repeat steps 1 to 7 from NQA-1148
        2. Under Apple Profile Manager, remove Password and save the scan.
        3. Validation message should appear.
        """
        form_data = {'server': '172.26.16.75',
                     'port': API.Credentials.Mobile.Ports.PORT,
                     'username': 'tenable',
                     'http_switch': http_toggle,
                     'force_device': True,
                     'device_update_timeout': '10'}

        if ssl is not None:
            form_data.update({'ssl': ssl})
        else:
            try:
                del form_data['ssl']
            except KeyError:
                pass

        scan_name = create_scan
        mobile_page = AppleProfileManager(mobile_credential_type=API.Credentials.Mobile.APM)
        assert mobile_page.get_credentials_types(category_name='Mobile') == API.Credentials.Mobile.MOBILE_LIST, \
            'Category Type is missing'
        assert mobile_page.opened_form_value == API.Credentials.Mobile.APM, 'Mobile form is not open'

        mobile_page.fill_apple_profile_manager_form(**form_data, password='sapphire')
        save_and_configure_scan(class_object=mobile_page, scan_name=scan_name)
        assert len(mobile_page.active_credentials) == 1, "More than 1 credentials are available"

        mobile_page.open_saved_credentials_component(form_name=API.Credentials.Mobile.APM)
        assert mobile_page.get_apple_profile_manager_form_data() == form_data, 'Data saved is incorrect or missing'

        if element_to_validate is not None:
            assert mobile_page.check_required_field_validation(
                class_instance=mobile_page, element=element_to_validate), \
                'Error notification for blank {} is missing.'.format(element_to_validate)

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    @pytest.mark.parametrize("http_toggle, ssl, element_to_validate",
                             [(True, True, 'server'), (True, False, None), (False, None, None)])
    def test_good_mdm_form(self, create_scan, http_toggle, ssl, element_to_validate):
        """
        NQA-1164 : Verify 'advanced scan' under 'Scanner' tab is saved with credentials -> 'Mobile' -> Good MDM
        1. Navigate Advanced scan template
        2. Give name and target
        3. Go to Credential --> Mobile --> Good MDM
        4. Fill the form
        5. Save scan
        6. Click on created scan
        7. Verify saved values are retained

        NQA-1282: Verify mandatory field validation while edit for Advanced scan with credentials -> Mobile
        1. Repeat steps 1 to 7 from NQA-1164
        2. Under Good MDM, remove Server and save the scan.
        3. Validation message should appear.
        """
        form_data = {'server': '172.26.22.186',
                     'port': API.Credentials.Mobile.Ports.GOODMDM_PORT,
                     'domain': 'tenableregmdm.com',
                     'username': 'tenable',
                     'http_switch': http_toggle}

        if ssl is not None:
            form_data.update({'ssl': ssl})
        else:
            try:
                del form_data['ssl']
            except KeyError:
                pass

        scan_name = create_scan
        mobile_page = GoodMDM(mobile_credential_type=API.Credentials.Mobile.GOODMDM)
        assert mobile_page.get_credentials_types(category_name='Mobile') == API.Credentials.Mobile.MOBILE_LIST, \
            'Category Type is missing'
        assert mobile_page.opened_form_value == API.Credentials.Mobile.GOODMDM, 'Mobile form is not open'

        mobile_page.fill_good_mdm_form(**form_data, password='sapphire')
        save_and_configure_scan(class_object=mobile_page, scan_name=scan_name)
        assert len(mobile_page.active_credentials) == 1, "More than 1 credentials are available"

        mobile_page.open_saved_credentials_component(form_name=API.Credentials.Mobile.GOODMDM)
        assert mobile_page.get_good_mdm_form_data() == form_data, 'Data saved is incorrect or missing'

        if element_to_validate:
            assert mobile_page.check_required_field_validation(
                class_instance=mobile_page, element=element_to_validate), \
                'Error notification for blank {} is missing.'.format(element_to_validate)

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_maas_mobile_form(self, create_scan):
        """
        NQA-1165 : Verify 'advanced scan' under 'Scanner' tab is saved with credentials -> 'Mobile' -> MaaS360
        1. Navigate Advanced scan template
        2. Give name and target
        3. Go to Credential --> Mobile --> MaaS360
        4. Fill the form
        5. Save scan
        6. Click on created scan
        7. Verify saved values are retained

        NQA-1282: Verify mandatory field validation while edit for Advanced scan with credentials -> Mobile
        1. Repeat steps 1 to 7 from NQA-1165
        2. Under MaaS360, remove App access key and save the scan.
        3. Validation message should appear.
        """
        form_data = {'username': 'tenable_qa',
                     'root_url': 'https://services.m3.maas360.com',
                     'platform_id': '3',
                     'billing_id': '30011910',
                     'app_id': 'com.30011910.api',
                     'app_version': '1.0',
                     'app_access_key': 'QWqFnNsSps'}

        scan_name = create_scan
        mobile_page = MaaS360(mobile_credential_type=API.Credentials.Mobile.MAAS360)
        assert mobile_page.get_credentials_types(category_name='Mobile') == API.Credentials.Mobile.MOBILE_LIST, \
            'Category Type is missing'
        assert mobile_page.opened_form_value == API.Credentials.Mobile.MAAS360, 'Mobile form is not open'

        mobile_page.fill_maas_mobile_form(**form_data, password='Vv6j#NTV')
        save_and_configure_scan(class_object=mobile_page, scan_name=scan_name)
        assert len(mobile_page.active_credentials) == 1, "More than 1 credentials are available"

        mobile_page.open_saved_credentials_component(form_name=API.Credentials.Mobile.MAAS360)
        assert mobile_page.get_maas_mobile_form_data() == form_data, 'Data saved is incorrect or missing'

        assert mobile_page.check_required_field_validation(class_instance=mobile_page, element='app_access_key'), \
            "Error notification for blank 'App access key' is missing."

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    @pytest.mark.parametrize("http_toggle, ssl, element_to_validate",
                             [(True, True, 'portal_url'), (True, False, None), (False, None, None)])
    def test_mobileiron_form(self, create_scan, http_toggle, ssl, element_to_validate):
        """
        NQA-1170 : Verify 'advanced scan' under 'Scanner' tab is saved with credentials -> 'Mobile' -> MobileIron
        1. Navigate Advanced scan template
        2. Give name and target
        3. Go to Credential --> Mobile --> MobileIron
        4. Fill the form
        5. Save scan
        6. Click on created scan
        7. Verify saved values are retained

        NQA-1282: Verify mandatory field validation while edit for Advanced scan with credentials -> Mobile
        1. Repeat steps 1 to 7 from NQA-1170
        2. Under MobileIron, remove VSP Admin Portal URL and save the scan.
        3. Validation message should appear.
        """
        form_data = {'portal_url': 'https://172.26.22.37/mifs/login.jsp',
                     'port': API.Credentials.Mobile.Ports.PORT,
                     'username': 'admin',
                     'http_switch': http_toggle}

        if ssl is not None:
            form_data.update({'ssl': ssl})
        else:
            try:
                del form_data['ssl']
            except KeyError:
                pass

        scan_name = create_scan
        mobile_page = MobileIron(mobile_credential_type=API.Credentials.Mobile.MOBILEIRON)
        assert mobile_page.get_credentials_types(category_name='Mobile') == API.Credentials.Mobile.MOBILE_LIST, \
            'Category Type is missing'
        assert mobile_page.opened_form_value == API.Credentials.Mobile.MOBILEIRON, 'Mobile form is not open'

        mobile_page.fill_mobileiron_form(**form_data, password='trel123!@#')
        save_and_configure_scan(class_object=mobile_page, scan_name=scan_name)
        assert len(mobile_page.active_credentials) == 1, "More than 1 credentials are available"

        mobile_page.open_saved_credentials_component(form_name=API.Credentials.Mobile.MOBILEIRON)
        assert mobile_page.get_mobileiron_form_data() == form_data, 'Data saved is incorrect or missing'

        if element_to_validate:
            assert mobile_page.check_required_field_validation(
                class_instance=mobile_page, element=element_to_validate), \
                'Error notification for blank {} is missing.'.format(element_to_validate)

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)
