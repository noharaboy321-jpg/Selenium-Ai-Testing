"""
Nessus API Policy Helpers
"""
from catium.helpers.testdata import get_file_path
from catium.lib.api.base_api_object import ResponseObject
from catium.lib.log import create_logger
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.models.policy import PolicyModel

AWS_CREDENTIAL = {"add": {"Cloud Services": {"Amazon AWS": [{"access_key_id": "asasasaaaa ",
                                                             "secret_key": "asadsfsfsfsfssf "}]}}}
TENABLE_AWS_AUDIT = {"feed": {"add": [{"id": "72426_AWS_Security_Best_Practices.audit", "variables": {
    "ADMIN_GROUP": "Admins", "CHANGE_DAYS_WINDOW": "90", "INACTIVE_ACCOUNT_DAYS": "30"}}]}}
HOST_CREDENTIALS = {'add': {'Host': {'Windows': [{'auth_method': "Password", 'username': "asdf", 'password': "adsf"}]}}}
AUDITS = {'feed': {'add': [{'id': "81914_CIS_Apple_iOS_8_Level_1_v1.0.0-AirWatch.audit", 'variables': {}}]}}
OFFLINE_AUDITS = {'custom': {'add': [{'category': 'Cisco IOS', 'file': ''}]}}
MOBILE_CREDENTIALS = {'add': {'Mobile': {'AirWatch': [{'api_url': "as705.awmdm.com/airwatchservices/0/", 'port': "443",
                                                       'username': "apiuser", 'password': "Sapphire00!",
                                                       'api_key': "1UQH4IQQAAG6A45QAUAA", 'https': "yes",
                                                       'verify_ssl': "yes"}]}}}
CISCO_IOS_AUDIT_FILE = 'nessus/tests/api/policy/test_data/CIS_Cisco_v2.2_Level_11.audit'
CISCO_IOS_CONFIG_FILE = 'nessus/tests/api/policy/test_data/CiscoIOSOffline_PolicyTestFile.txt'
WINDOWS_SCAP_FILE = 'nessus/tests/api/scan/test_data/U_Windows_7_V1R27_STIG_SCAP_1-11_Benchmark.zip'
SCAP = {'add': {'Windows': [{'file': '', 'version': '1.1', 'benchmark_id': 'Windows_7_STIG',
                             'profile_id': 'MAC-1_Classified',
                             'oval_result_type': 'Full results w/ system characteristics'}]}}

log = create_logger()


def upload_policy_helper(filepath: str, api: NessusAPI = None) -> ResponseObject:
    """
    Uploads a Policy

    .. note:: This method handles uploading via the file:upload endpoint and the importing via the policies:import
        endpoint

    :param str filepath: relative path to policy file
    :param NessusAPI api: NessusAPI instance
    :returns: dict, policy
    """
    response_filename = api.file.upload(filepath)
    return api.policies.import_policy(file=response_filename)


def configure_policy(policy_id: int, settings: dict, api: NessusAPI = None) -> ResponseObject:
    return api.policies.configure(policy_id=policy_id, payload=settings)


def create_policy_helper(api_handler: NessusAPI, template_list: list, **kwargs):
    """

    :param api_handler: api handler
    :param kwargs: to access variable arguments
    :param template_list: policy template
    :return: none
    """
    policy_uuid = None
    policy_type = kwargs.get('policy_type', 'basic')

    for template in template_list:
        uuid = template['uuid']
        name = template['name']

        if policy_type in name:
            policy_uuid = uuid
            break

    # get policy name from the kwargs, if not generate random name
    policy_name = kwargs.get('policy_name')

    if policy_name is not None:
        policy_model = PolicyModel(settings={'name': policy_name})
    else:
        policy_model = PolicyModel(autogen=True)

    policy_settings = policy_model.settings

    if policy_type == 'cloud_audit':
        policy_credentials = AWS_CREDENTIAL
        audits = TENABLE_AWS_AUDIT
        payload = {'audits': audits, 'uuid': policy_uuid, 'settings': policy_settings,
                   'credentials': policy_credentials}

    elif policy_type == 'malware' or policy_type == 'patch_audit':
        policy_credentials = HOST_CREDENTIALS
        payload = {'uuid': policy_uuid, 'settings': policy_settings, 'credentials': policy_credentials}

    elif policy_type == 'mdm' or policy_type == 'mobile' or policy_type == 'compliance':
        audits = AUDITS
        policy_credentials = MOBILE_CREDENTIALS
        payload = {'audits': audits, 'uuid': policy_uuid, 'settings': policy_settings,
                   'credentials': policy_credentials}

    elif policy_type == 'offline':
        # Supported : Cisco IOS(Upload Custom Cisco IOS audit file)

        audit_file = get_file_path(kwargs.get('cisco_ios_audit_file', CISCO_IOS_AUDIT_FILE))

        config_file = get_file_path(kwargs.get('cisco_ios_config_file', CISCO_IOS_CONFIG_FILE))

        OFFLINE_AUDITS['custom']['add'][0]['file'] = api_handler.file.upload(file=audit_file)
        audits = OFFLINE_AUDITS
        policy_settings['cisco_offline_configs'] = api_handler.file.upload(file=config_file)
        payload = {'audits': audits, 'uuid': policy_uuid, 'settings': policy_settings}

    elif policy_type in ('scap', 'agent_scap'):
        # Supported : Windows(SCAP)
        scap_file = get_file_path(kwargs.get('windows_scap_file', WINDOWS_SCAP_FILE))
        SCAP['add']['Windows'][0]['file'] = api_handler.file.upload(file=scap_file)
        scap = SCAP
        policy_credentials = HOST_CREDENTIALS if policy_type == 'scap' else {}
        payload = {'scap': scap, 'uuid': policy_uuid, 'settings': policy_settings,
                   'credentials': policy_credentials}

    else:
        policy_credentials = policy_model.credentials
        payload = {'uuid': policy_uuid, 'settings': policy_settings, 'credentials': policy_credentials}

    return api_handler.policies.create(payload)
