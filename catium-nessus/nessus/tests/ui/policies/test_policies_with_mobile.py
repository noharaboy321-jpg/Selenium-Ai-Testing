"""
Nessus Credentials tab under Policy form related test cases for Mobile category.

:copyright: Tenable Network Security, 2018
:date: May 24, 2018
:last_modified: May 29, 2018
:author: @kpanchal
"""

import pytest

from catium.lib.util.util import random_name
from nessus.lib.const import API, Nessus
from nessus.pageobjects.credentials.mobile_credential import AirWatch, AppleProfileManager, GoodMDM, MaaS360, MobileIron
from nessus.pageobjects.policies.new_policy_form import NewPolicyForm
from nessus.pageobjects.policies.policies_page import PolicyList


@pytest.mark.policies_pipeline_2
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestMobileCredentialsForm:
    """
    This class covers Mobile credential form related test under new policies.
    """

    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix="Policy of {} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    @pytest.mark.parametrize("http_toggle, ssl", [(True, True), (True, False), (False, None)])
    def test_air_watch_credential_form(self, create_policies, http_toggle, ssl):
        """
        NQA-1216 : Verify Advanced scan is saved with Mobile > AirWatch

        1. Navigate to 'Advanced scan' template from scanner tab under New Policy
        2. Give valid name and target
        3. Go to Credentials tab and select Mobile > AirWatch
        4. Verify following input fields:
        - AirWatch Environment API URL
        - Port
        - Username
        - Password
        - API Key
        - HTTPS
        - Verify SSL certificate
        5. Save the policy
        6. Click on created policy
        7. Verify the values saved are retained
        """
        air_watch_form_data = {'api_url': 'as705.awmdm.com/airwatchservices/0/',
                               'port': API.Credentials.Mobile.Ports.PORT, 'username': 'admin',
                               'api_key': '1UQH4IQQAAG6A45QAUAA', 'http_switch': http_toggle}

        if ssl is not None:
            air_watch_form_data.update({'ssl': ssl})
        else:
            try:
                del air_watch_form_data['ssl']
            except KeyError:
                pass

        policy_name = create_policies[0]
        policy_form = NewPolicyForm()
        air_watch_form = AirWatch(mobile_credential_type=API.Credentials.Mobile.AIRWATCH)

        assert air_watch_form.get_credentials_types(category_name=API.Credentials.Types.CATEGORY_MOBILE) == API.\
            Credentials.Mobile.MOBILE_LIST, 'Any of the credential type under Mobile category is missing or mismatched.'

        assert air_watch_form.opened_form_value == API.Credentials.Mobile.AIRWATCH, \
            'AirWatch credential form is not opened.'

        air_watch_form.fill_airwatch_form(**air_watch_form_data, password='Admin@123')
        policy_form.save_button.click()

        PolicyList().click_on_policy(policy_name=policy_name)
        policy_form.credentials.click()

        assert len(air_watch_form.active_credentials) == 1, 'More than 1 credentials are available.'

        air_watch_form.open_saved_credentials_component(form_name=API.Credentials.Mobile.AIRWATCH)

        assert air_watch_form.get_airwatch_form_data() == air_watch_form_data, \
            'Entered data and saved data is different.'

    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix="Policy of {} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    @pytest.mark.parametrize("http_toggle, ssl", [(True, True), (True, False), (False, None)])
    def test_apple_profile_manager_credential_form(self, create_policies, http_toggle, ssl):
        """
        NQA-1217 : Verify Advanced scan is saved with Mobile > Apple Profile Manager

        1. Navigate to 'Advanced scan' template from scanner tab
        2. Give valid name and target
        3. Go to Credentials tab and select Mobile > Apple Profile Manager
        4. Verify following input fields:
        - Server
        - Port
        - Username
        - Password
        - API Key
        - HTTPS
        - Verify SSL certificate
        - Global credential settings
        5. Save the policy
        6. Click on created policy
        7. Verify the values saved are retained
        """
        apm_form_data = {'server': '172.26.16.75', 'port': API.Credentials.Mobile.Ports.PORT, 'username': 'tenable',
                         'http_switch': http_toggle, 'force_device': True, 'device_update_timeout': '10'}

        if ssl is not None:
            apm_form_data.update({'ssl': ssl})
        else:
            try:
                del apm_form_data['ssl']
            except KeyError:
                pass

        policy_name = create_policies[0]
        policy_form = NewPolicyForm()
        apm_form = AppleProfileManager(mobile_credential_type=API.Credentials.Mobile.APM)

        assert apm_form.get_credentials_types(category_name=API.Credentials.Types.CATEGORY_MOBILE) == API.\
            Credentials.Mobile.MOBILE_LIST, 'Any of the credential type under Mobile category is missing or mismatched.'

        assert apm_form.opened_form_value == API.Credentials.Mobile.APM, \
            'Apple Profile Manager credential form is not opened.'

        apm_form.fill_apple_profile_manager_form(**apm_form_data, password='Admin@123')
        apm_form.js_scroll_into_view(policy_form.save_button)
        policy_form.save_button.click()

        PolicyList().click_on_policy(policy_name=policy_name)
        policy_form.credentials.click()

        assert len(apm_form.active_credentials) == 1, 'More than 1 credentials are available.'

        apm_form.open_saved_credentials_component(form_name=API.Credentials.Mobile.APM)

        assert apm_form.get_apple_profile_manager_form_data() == apm_form_data, \
            'Entered data and saved data is different.'

    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix="Policy of {} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    @pytest.mark.parametrize("http_toggle, ssl", [(True, True), (True, False), (False, None)])
    def test_good_mdm_credential_form(self, create_policies, http_toggle, ssl):
        """
        NQA-1218 : Verify Advanced scan is saved with Mobile > Good MDM

        1. Navigate to 'Advanced scan' template from scanner tab
        2. Give valid name and target
        3. Go to Credentials tab and select Mobile > Good MDM
        4. Verify following input fields:
        - Server
        - Port
        - Domain
        - Username
        - Password
        - HTTPS
        - Verify SSL certificate
        5. Save the policy
        6. Click on created policy
        7. Verify the values saved are retained
        """
        good_mdm_form_data = {'server': '172.26.22.186', 'port': API.Credentials.Mobile.Ports.GOODMDM_PORT,
                              'domain': 'tenableregmdm.com', 'username': 'tenable', 'http_switch': http_toggle}

        if ssl is not None:
            good_mdm_form_data.update({'ssl': ssl})
        else:
            try:
                del good_mdm_form_data['ssl']
            except KeyError:
                pass

        policy_name = create_policies[0]
        policy_form = NewPolicyForm()
        good_mdm_form = GoodMDM(mobile_credential_type=API.Credentials.Mobile.GOODMDM)

        assert good_mdm_form.get_credentials_types(category_name=API.Credentials.Types.CATEGORY_MOBILE) == API. \
            Credentials.Mobile.MOBILE_LIST, 'Any of the credential type under Mobile category is missing or mismatched.'

        assert good_mdm_form.opened_form_value == API.Credentials.Mobile.GOODMDM, \
            'Good MDM credential form is not opened.'

        good_mdm_form.fill_good_mdm_form(**good_mdm_form_data, password='Admin@123')
        policy_form.save_button.click()

        PolicyList().click_on_policy(policy_name=policy_name)
        policy_form.credentials.click()

        assert len(good_mdm_form.active_credentials) == 1, 'More than 1 credentials are available.'

        good_mdm_form.open_saved_credentials_component(form_name=API.Credentials.Mobile.GOODMDM)

        assert good_mdm_form.get_good_mdm_form_data() == good_mdm_form_data, \
            'Entered data and saved data is different.'

    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix="Policy of {} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    def test_mass360_credential_form(self, create_policies):
        """
        NQA-1219 : Verify Advanced scan is saved with Mobile > MaaS360

        1. Navigate to 'Advanced scan' template from scanner tab
        2. Give valid name and target
        3. Go to Credentials tab and select Mobile > MaaS360
        4. Verify following input fields:
        - Username
        - Password
        - Root URL
        - Platform Id
        - Billing Id
        - App Id
        - App Version
        - App access key
        5. Save the policy
        6. Click on created policy
        7. Verify the values saved are retained
        """
        maas360_form_data = {'username': 'tenable_qa', 'root_url': 'https://services.m3.maas360.com',
                             'platform_id': '3', 'billing_id': '30011910', 'app_id': 'com.30011910.api',
                             'app_version': '1.0', 'app_access_key': 'QWqFnNsSps'}

        policy_name = create_policies[0]
        policy_form = NewPolicyForm()
        maas360_form = MaaS360(mobile_credential_type=API.Credentials.Mobile.MAAS360)

        assert maas360_form.get_credentials_types(category_name=API.Credentials.Types.CATEGORY_MOBILE) == API. \
            Credentials.Mobile.MOBILE_LIST, 'Any of the credential type under Mobile category is missing or mismatched.'

        assert maas360_form.opened_form_value == API.Credentials.Mobile.MAAS360, \
            'MaaS360 credential form is not opened.'

        maas360_form.fill_maas_mobile_form(**maas360_form_data, password='Admin@123')
        policy_form.save_button.click()

        PolicyList().click_on_policy(policy_name=policy_name)
        policy_form.credentials.click()

        assert len(maas360_form.active_credentials) == 1, 'More than 1 credentials are available.'

        maas360_form.open_saved_credentials_component(form_name=API.Credentials.Mobile.MAAS360)

        assert maas360_form.get_maas_mobile_form_data() == maas360_form_data, \
            'Entered data and saved data is different.'

    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix="Policy of {} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    @pytest.mark.parametrize("http_toggle, ssl", [(True, True), (True, False), (False, None)])
    def test_mobile_iron_credential_form(self, create_policies, http_toggle, ssl):
        """
        NQA-1220 : Verify Advanced scan is saved with Mobile > MobileIron

        1. Navigate to 'Advanced scan' template from scanner tab
        2. Give valid name and target
        3. Go to Credentials tab and select Mobile > MobileIron
        4. Verify following input fields:
        - VSP admin portal URL
        - Port
        - Username
        - Password
        - Https
        - Verify SSL Certificate
        5. Save the policy
        6. Click on created policy
        7. Verify the values saved are retained
        """
        mobile_iron_form_data = {'portal_url': 'https://172.26.22.37/mifs/login.jsp',
                                 'port': API.Credentials.Mobile.Ports.PORT, 'username': 'admin',
                                 'http_switch': http_toggle}

        if ssl is not None:
            mobile_iron_form_data.update({'ssl': ssl})
        else:
            try:
                del mobile_iron_form_data['ssl']
            except KeyError:
                pass

        policy_name = create_policies[0]
        policy_form = NewPolicyForm()
        mobile_iron_form = MobileIron(mobile_credential_type=API.Credentials.Mobile.MOBILEIRON)

        assert mobile_iron_form.get_credentials_types(category_name=API.Credentials.Types.CATEGORY_MOBILE) == API. \
            Credentials.Mobile.MOBILE_LIST, 'Any of the credential type under Mobile category is missing or mismatched.'

        assert mobile_iron_form.opened_form_value == API.Credentials.Mobile.MOBILEIRON, \
            'MobileIron credential form is not opened.'

        mobile_iron_form.fill_mobileiron_form(**mobile_iron_form_data, password='Admin@123')
        policy_form.save_button.click()

        PolicyList().click_on_policy(policy_name=policy_name)
        policy_form.credentials.click()

        assert len(mobile_iron_form.active_credentials) == 1, 'More than 1 credentials are available.'

        mobile_iron_form.open_saved_credentials_component(form_name=API.Credentials.Mobile.MOBILEIRON)

        assert mobile_iron_form.get_mobileiron_form_data() == mobile_iron_form_data, \
            'Entered data and saved data is different.'
