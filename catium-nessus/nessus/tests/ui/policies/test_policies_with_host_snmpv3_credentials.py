"""
Nessus test cases related to Policies with Host -> SNMPv3 Credentials

:copyright: Tenable Network Security, 2017
:date: May 16, 2018
:last_modified: May 17, 2018
:author: @rdutta, @krpatel
"""

import pytest
from selenium.webdriver import ChromeOptions

from catium.lib.const import WAIT_SHORT
from catium.lib.const.base_constants import WAIT_NORMAL
from catium.lib.util.util import random_name
from nessus.lib.const import API, Nessus
from nessus.lib.message.messages import Messages
from nessus.pageobjects.credentials.host import SNMPv3
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.policies.new_policy_form import NewPolicyForm
from nessus.pageobjects.policies.policies_page import PolicyList
from nessus.pageobjects.shared.loading import LoadingCircle


@pytest.fixture()
def chrome_options():
    """Set chrome options."""
    options = ChromeOptions()

    prefs = {"profile.password_manager_leak_detection": False}
    options.add_experimental_option('prefs', prefs)
    return options

@pytest.mark.policies_pipeline_3
@pytest.mark.nessus_home
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('login')
class TestPoliciesWithHostSNMPv3Credentials:
    """Test class for Policies with host SNMPv3 credentials related test cases."""
    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix="Policy of {} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    @pytest.mark.parametrize("test_data", [
        {'username': Nessus.USERNAME, 'port': API.Credentials.Host.Ports.SNMP,
         'security_level': 'No authentication and no privacy'},
        {'username': Nessus.USERNAME, 'security_level': 'Authentication without privacy',
         'port': API.Credentials.Host.Ports.SNMP, 'authentication_algo': 'SHA1', 'auth_password': Nessus.PASSWORD},
        {'username': Nessus.USERNAME, 'security_level': 'Authentication without privacy',
         'port': API.Credentials.Host.Ports.SNMP, 'authentication_algo': 'MD5', 'auth_password': Nessus.PASSWORD},
        {'username': Nessus.USERNAME, 'port': API.Credentials.Host.Ports.SNMP,
         'security_level': 'Authentication and privacy', 'authentication_algo': 'SHA1',
         'auth_password': Nessus.PASSWORD, 'privacy_algo': 'AES', 'privacy_password': Nessus.PASSWORD},
        {'username': Nessus.USERNAME, 'port': API.Credentials.Host.Ports.SNMP,
         'security_level': 'Authentication and privacy', 'authentication_algo': 'SHA1',
         'auth_password': Nessus.PASSWORD, 'privacy_algo': 'DES', 'privacy_password': Nessus.PASSWORD},
        {'username': Nessus.USERNAME, 'port': API.Credentials.Host.Ports.SNMP,
         'security_level': 'Authentication and privacy', 'authentication_algo': 'MD5', 'auth_password': Nessus.PASSWORD,
         'privacy_algo': 'AES', 'privacy_password': Nessus.PASSWORD},
        {'username': Nessus.USERNAME, 'port': API.Credentials.Host.Ports.SNMP,
         'security_level': 'Authentication and privacy', 'authentication_algo': 'MD5', 'auth_password': Nessus.PASSWORD,
         'privacy_algo': 'DES', 'privacy_password': Nessus.PASSWORD}])
    def test_policies_with_host_snmpv3_credentials(self, create_policies, test_data):
        """
        #NQA-1187 : Automation tests for 'advanced scan' under New Policy > 'Scanner' tab is saved successfully
        with values given under credentials -> Category as 'Host' -> 'SNMPv3
        1.Navigate to 'Advanced scan' template from scanner tab under Policies
        2. Give valid name and description
        3. Go to Credentials tab and select Host > SNMPv3
            Verify following input fields: as per security level its optional
                Username* : administrator
                Port: input data
                Security Level: Authentication and privacy
                Authentication algorithm : SHA1 / MD5
                Authentication password* : input data
                Privacy algorithm : AES / DES
                Privacy password : input data
        4. Save the scan
        5. Click on created scan.
        6. Verify above saved values were retained.
        """
        policy_name = create_policies[0]
        policy_form = NewPolicyForm()
        snmpv3_form = SNMPv3(host_type=API.Credentials.Host.Types.SNMPV3)
        LoadingCircle(WAIT_SHORT)
        assert snmpv3_form.get_credentials_types(category_name='Host') == API.Credentials.Host.Types.HOST_LIST, \
            'Any of the credentials form under "Host" category is missing or mismatched'

        LoadingCircle(WAIT_SHORT)
        assert snmpv3_form.opened_form_value == API.Credentials.Host.Types.SNMPV3, 'SNMPv3 form is not opened up.'

        snmpv3_form.fill_snmpv3_form(**test_data)
        policy_form.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.Policies.policy_saved, \
            "Success notifications for policy save is mismatched or missing."

        PolicyList().click_on_policy(policy_name=policy_name)
        LoadingCircle(WAIT_NORMAL)
        policy_form.credentials.click()
        LoadingCircle(WAIT_SHORT)
        assert len(snmpv3_form.active_credentials) == 1, "More than 1 credentials are available"

        snmpv3_form.open_saved_credentials_component(form_name=API.Credentials.Host.Types.SNMPV3)
        saved_data = dict(filter(lambda i: i[0] not in ('auth_password', 'privacy_password'), test_data.items()))
        assert snmpv3_form.get_snmpv3_form_data() == saved_data, 'Saved data not retained.'

        policy_form.back_to_policies.click()
        LoadingCircle(WAIT_SHORT)
