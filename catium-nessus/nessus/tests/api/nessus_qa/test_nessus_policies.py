"""
:copyright: Tenable Network Security, 2017
:date: June 26, 2017
:author: @cdombrowski
"""
from nessus.helpers.system import get_nessus_version
from nessus.lib.const.constants import API
import pytest


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_manager
@pytest.mark.smoke
@pytest.mark.usefixtures('nessus_api_login', 'get_policy_templates')
class TestNessusPolicies:
    """
    Class to handle Nessus Policy tests.  This includes tests such as creating a policy, editing a policy, and
    verifying the policy returns the expected output.
    """

    cat = None

    # TODO: Refactor the skip check using the version marker once it is implemented (CAT-1561).
    @pytest.mark.skipif(get_nessus_version() != "6.12.0",
                        reason="This test requires version 2 of the Nessus API.")
    # API_Tested# GET /editor/policy/templates/{template_uuid}
    def test_nessus_policy_plugins_available(self, get_policy_templates):
        """
        Tests that policies return their enabled plugin families when using version 2 of the Nessus API.
        """
        self.cat.api.add_header({'X-API-Version': "2"})
        policy_templates = get_policy_templates
        for policy in policy_templates:
            if policy['uuid'] == API.Policies.Uuids.CUSTOM_SCAN:
                pass
            else:
                assert 'plugins' in self.cat.api.editor.details(template_type=API.Types.POLICY,
                                                                template_uuid=policy['uuid']), \
                    "{0} policy did not return plugins.".format(policy['name'])
