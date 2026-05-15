"""
Fixtures deploys Nessus into a Kubernetes cluster, based on the configuration provided by the
kube_deploy_nessus_config fixture.

This fixture is intended to be used in a chained fixture scenario, where you log into the API using a
fixture that sets the test class object property, cat.api. When deploying an Agent, a linking key is required.
The linking key is retrieved from the API. This should be used in conjunction with Nessus and tenable.io, where
agents can link.

In order for automatic linking to work, a test should call an API login fixture that sets the cat.api class attribute.
The cat.api API instance is used to retrieve the linking key and instruct the scanner to link using that key.
The scanner links to whatever hostname CAT_URL is set to on port 443.

- Nessus Agents are linked automatically
- Docker images are stored in catium/lib/const/deployment.py as constants, for easy referencing


Configuration:

A dict comprised of configuration key/value pairs.
{"image": "",
 "link": ""}

"image" (str) - Docker image URL
"link"  (str) - Link deployment to a Nessus or tenableio instance (see docs for more information)

:copyright: Tenable Network Security, 2017
:date: Jul 17, 2017
:author: @jyerge
"""
# fixture wrapper parameters cause pylint to give redefined-outer-name warnings
# pylint: disable=redefined-outer-name
import json
from typing import TYPE_CHECKING

import pytest
from requests.exceptions import RequestException

from catium.helpers.kube.deployment import create_kube_deployment
from catium.helpers.sleep_lib import sleep
from catium.lib.activation_code_generator import ActivationCodeGenerator, CatiumActivationCodeGeneratorError
from catium.lib.aws.ec2client import EC2Client
from catium.lib.config import Config as config
from catium.lib.const import AWS, AWSEC2, TIME_FIFTEEN_MINUTES, TIME_TWO_MINUTES
from catium.lib.const.deployment import DEPLOYMENT_TYPE_AWS_MANAGED, DEPLOYMENT_TYPE_NESSUS_MANAGED,\
    DEPLOYMENT_TYPE_NESSUS_MANAGER, DEPLOYMENT_TYPE_NESSUS_REMOTE, SCANNER_NAME, SCANNER_PASSWORD, SCANNER_USERNAME
from catium.lib.errors import CatiumDeploymentError
from catium.lib.kubectl import Kubectl
from catium.lib.log import create_logger
from catium.lib.url import Url
from catium.lib.util import load_testdata, random_name
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.metadata.scanner import get_id as get_scanner_id
from nessus.helpers.waiters import wait_for_plugins, wait_for_scanner_login, wait_for_scanner_registration, \
    wait_for_scanner_status
from nessus.lib.config import NessusConfig
from nessus.lib.const import API

if TYPE_CHECKING:
    from catium.lib.typechecking import SubRequest

log = create_logger()


def _activate_scanner(scanner_type: str, host: str, port: int, fresh_install: bool=False):
    if scanner_type not in [DEPLOYMENT_TYPE_NESSUS_REMOTE, DEPLOYMENT_TYPE_NESSUS_MANAGED,
                            DEPLOYMENT_TYPE_NESSUS_MANAGER]:
        raise ValueError('Invalid value for "scanner_type".')

    if fresh_install is True:
        log.debug('Scanner setup in a fresh install state: no activation or plugin updates will occur')
        return

    log.debug('Scanner will be activated and plugins updated as requested')

    try:
        if scanner_type == DEPLOYMENT_TYPE_NESSUS_MANAGER:
            activation_code = ActivationCodeGenerator.generate_nessus_manager_code(ips=1024, scanners=1024, agents=1024)
        else:
            activation_code = ActivationCodeGenerator.generate_code(ActivationCodeGenerator.NESSUS_PROFESSIONAL)
        nessus_api = NessusAPI()
        nessus_api.session_url = 'https://{host}:{port}'.format(host=host, port=port)
        wait_for_scanner_status(api=nessus_api,
                                status=API.Status.READY,
                                timeout=TIME_FIFTEEN_MINUTES,
                                msg='Availability of Nessus scanner')
        wait_for_scanner_login(api=nessus_api,
                               username=SCANNER_USERNAME,
                               password=SCANNER_PASSWORD,
                               timeout=TIME_FIFTEEN_MINUTES,
                               msg='Waiting for scanner login to succeed')
        wait_for_scanner_registration(api=nessus_api,
                                      code=activation_code,
                                      timeout=TIME_FIFTEEN_MINUTES,
                                      msg='Waiting for scanner registration to succeed')
        wait_for_scanner_status(api=nessus_api,
                                status=API.Status.READY,
                                timeout=TIME_FIFTEEN_MINUTES,
                                msg='Scanner registration to complete')
        wait_for_scanner_status(api=nessus_api,
                                status=API.Status.READY,
                                timeout=TIME_FIFTEEN_MINUTES,
                                msg='Availability of Nessus scanner')
        wait_for_scanner_login(api=nessus_api,
                               username=SCANNER_USERNAME,
                               password=SCANNER_PASSWORD,
                               timeout=TIME_FIFTEEN_MINUTES,
                               msg='Waiting for scanner login to succeed')
        wait_for_scanner_status(api=nessus_api,
                                status=API.Status.READY,
                                timeout=TIME_FIFTEEN_MINUTES,
                                msg='Availability of Nessus scanner')
        scanner_id = get_scanner_id(nessus_api.scanners.get_list(), SCANNER_NAME)
        nessus_api.scanners.force_plugin_update(scanner_id=scanner_id)
        wait_for_scanner_status(api=nessus_api,
                                status=API.Status.READY,
                                timeout=TIME_FIFTEEN_MINUTES,
                                msg='Scanner registration to complete')
        wait_for_plugins(api=nessus_api, timeout=TIME_FIFTEEN_MINUTES)
        wait_for_scanner_status(api=nessus_api,
                                status=API.Status.READY,
                                timeout=TIME_FIFTEEN_MINUTES,
                                msg='Availability of Nessus scanner')
        try:
            nessus_api.logout()
        except RequestException:
            pass
    except RequestException as exc:
        raise CatiumDeploymentError('Nessus API failure: {msg}'.format(msg=exc))
    except CatiumActivationCodeGeneratorError as exc:
        raise CatiumDeploymentError('Nessus activation failed: {msg}'.format(msg=exc))


def _cleanup(deployment):
    if deployment.get('deployment_name'):
        deployment_name = deployment.get('deployment_name')
        log.debug('Starting kube cleanup process ...')
        kube = Kubectl()
        try:
            kube.delete_deployment_set(deployment_name=deployment_name, replica=1)
            log.debug('Deleted deployment set "%s" successfully', deployment_name)
        except Exception:
            log.exception('Failed to delete deployment for "%s"', deployment_name)


# region Deployment Fixtures (func scoped)
@pytest.fixture()
def kube_standalone_deploy(request: 'SubRequest'):
    """
    Informs deployment that this is a standalone deployment (i.e. no linking)

    .. note:: Requires the cat.deployment attribute exists

    :param SubRequest request: SubRequest
    :raises: AttributeError, if cat.deployment is not present
    """
    if not hasattr(request.cls.cat, 'deployment'):
        raise AttributeError('Missing required "deployment" attribute for request object.')
    url = 'https://{host}:{port}'.format(host=request.cls.cat.deployment['IP'], port=request.cls.cat.deployment['Port'])
    setattr(NessusConfig, 'CAT_NESSUS_URL', url)


@pytest.fixture()
def kube_deploy_nessus_config(request):
    """Nessus Kube Deployment Configuration"""
    param = getattr(request, 'param', None)
    log.debug('fixture init: kube_deploy_nessus_config: configuration: %s', param)
    return param


@pytest.fixture()
def kube_deploy_nessus_remote_scanner(request: 'SubRequest', kube_deploy_nessus_config: dict) -> dict:
    """
    Deploys a Nessus Remote (Professional) scanner

    :param SubRequest request: SubRequest
    :param dict kube_deploy_nessus_config: Deployment configuration
    :return: dict
    :raises: CatiumDeploymentError
    """
    log.debug('fixture init: kube_deploy_nessus_remote_scanner')
    deployment = {}
    try:
        kube_deploy_nessus_config['type'] = DEPLOYMENT_TYPE_NESSUS_REMOTE
        deployment = create_kube_deployment(config=kube_deploy_nessus_config, api=request.cls.cat.api,
                                            product_url=NessusConfig.CAT_NESSUS_URL)
        # wait for nessus remote scanner to be link with controller
        sleep(sleep_time=TIME_TWO_MINUTES, reason="waiting for scanner to linked with controller")
        _activate_scanner(scanner_type=DEPLOYMENT_TYPE_NESSUS_REMOTE,
                          host=deployment['IP'],
                          port=deployment['Port'],
                          fresh_install=kube_deploy_nessus_config.get('freshInstall') or False)
        request.cls.cat.deployment = deployment
        yield deployment
    finally:
        log.debug('fixture teardown: kube_deploy_nessus_remote_scanner')
        _cleanup(deployment)


@pytest.fixture()
def kube_deploy_nessus_managed_scanner(request: 'SubRequest', kube_deploy_nessus_config: dict) -> dict:
    """
    Deploys a Nessus Managed (Professional) scanner

    :param SubRequest request: SubRequest
    :param dict kube_deploy_nessus_config: Deployment configuration
    :return: dict
    :raises: CatiumDeploymentError
    """
    log.debug('fixture init: kube_deploy_nessus_managed_scanner: configuration: %s', kube_deploy_nessus_config)
    deployment = {}
    try:
        kube_deploy_nessus_config['type'] = DEPLOYMENT_TYPE_NESSUS_MANAGED
        deployment = create_kube_deployment(config=kube_deploy_nessus_config, api=request.cls.cat.api,
                                            product_url=NessusConfig.CAT_NESSUS_URL)
        _activate_scanner(scanner_type=DEPLOYMENT_TYPE_NESSUS_MANAGED,
                          host=deployment['IP'],
                          port=deployment['Port'],
                          fresh_install=kube_deploy_nessus_config.get('freshInstall') or False)
        request.cls.cat.deployment = deployment
        yield deployment
    finally:
        log.debug('fixture teardown: kube_deploy_nessus_managed_scanner')
        _cleanup(deployment)


@pytest.fixture()
def kube_deploy_nessus_manager(request: 'SubRequest', kube_deploy_nessus_config: dict) -> dict:
    """
    Deploys a Nessus Manager

    :param SubRequest request: SubRequest
    :param dict kube_deploy_nessus_config: Deployment configuration
    :return: dict
    :raises: CatiumDeploymentError
    """
    log.debug('fixture init: kube_deploy_nessus_manager: configuration: %s', kube_deploy_nessus_config)
    deployment = {}
    try:
        kube_deploy_nessus_config['type'] = DEPLOYMENT_TYPE_NESSUS_MANAGER
        deployment = create_kube_deployment(config=kube_deploy_nessus_config, api=request.cls.cat.api,
                                            product_url=NessusConfig.CAT_NESSUS_URL)
        _activate_scanner(scanner_type=DEPLOYMENT_TYPE_NESSUS_MANAGER,
                          host=deployment['IP'],
                          port=deployment['Port'],
                          fresh_install=kube_deploy_nessus_config.get('freshInstall') or False)
        request.cls.cat.deployment = deployment
        yield deployment
    finally:
        log.debug('fixture teardown: kube_deploy_nessus_manager')
        _cleanup(deployment)


@pytest.fixture()
def deploy_nessus_aws(request: 'SubRequest') -> dict:
    """
    Deploys a Nessus AWS managed scanner to a tenable.io instance based on the configuration

    .. note:: The AWS instance is linked to container owned by the API session user (i.e. cat.api)
    .. note:: This fixture relies on the request.cls.cat.api attribute

    :param SubRequest request: SubRequest
    :returns: dict, deployment dict
    :raises: CatiumDeploymentError
    """
    log.debug('fixture init: deploy_nessus_aws')
    settings = load_testdata('nessus/plugins/deployment/aws_nessus_instance_config.json')
    instance = None
    try:
        name = random_name('automation-aws-')
        linking_key = request.cls.cat.api.scanners.get_linking_key().get('key')
        ec2client = EC2Client(region=AWS.Regions.USEast1,
                              access_key_id=config.CAT_ACCESS_KEY,
                              secret_key=config.CAT_SECRET_ACCESS_KEY)
        user_data = json.dumps({'name': name,
                                'manager_host': Url(NessusConfig.CAT_NESSUS_URL).hostname,
                                'manager_port': '443',
                                'key': linking_key,
                                'iam_role': settings['iamrole']})
        log.debug('AWS instance user data is: %s', user_data)
        instance = ec2client.create_instance(image=settings['image'],
                                             instance_type=AWSEC2.InstanceTypes.t2medium.value,
                                             snapshot=settings['snapshot'],
                                             subnet=settings['subnet'],
                                             groups=settings['groups'],
                                             arn=settings['arn'],
                                             tag=name,
                                             userdata=user_data,
                                             zone=AWS.AvailabilityZones.USEast1A,
                                             assign_public_ip=True)
        log.debug('Creating AWS EC2 instance')
        instance.wait_until_exists()
        log.debug('Instance "%s" created successfully', instance.id)
        log.debug('Waiting for instance "%s" to become available', instance.id)
        instance.wait_until_running()
        log.debug('Instance "%s" is ready', instance.id)
        yield {'name': name, 'type': DEPLOYMENT_TYPE_AWS_MANAGED}
    finally:
        log.debug('fixture teardown: deploy_nessus_aws')
        try:
            if instance:
                instance.terminate()
        except Exception:
            log.exception('Terminating instance "%s" failed', instance.id)
# endregion


# region Deployment Fixtures (class scoped)
@pytest.fixture(scope='class')
def tns_risky_kube_standalone_deploy(request: 'SubRequest'):
    """
    Informs deployment that this is a standalone deployment (i.e. no linking)

    .. note:: Requires the cat.deployment attribute exists

    :param SubRequest request: SubRequest
    :raises: AttributeError, if cat.deployment is not present
    """
    if not hasattr(request.cls.cat, 'deployment'):
        raise AttributeError('Missing required "deployment" attribute for request object.')
    url = 'https://{host}:{port}'.format(host=request.cls.cat.deployment['IP'], port=request.cls.cat.deployment['Port'])
    setattr(NessusConfig, 'CAT_NESSUS_URL', url)


@pytest.fixture(scope='class')
def tns_risky_kube_deploy_nessus_config(request):
    """Nessus Kube Deployment Configuration"""
    param = getattr(request, 'param', None)
    log.debug('fixture init: kube_deploy_nessus_config: configuration: %s', param)
    return param


@pytest.fixture(scope='class')
def tns_risky_kube_deploy_nessus_remote_scanner(request: 'SubRequest', tns_risky_kube_deploy_nessus_config: dict) -> dict:
    """
    Deploys a Nessus Remote (Professional) scanner

    :param SubRequest request: SubRequest
    :param dict tns_risky_kube_deploy_nessus_config: Deployment configuration
    :return: dict
    :raises: CatiumDeploymentError
    """
    log.debug('fixture init: kube_deploy_nessus_remote_scanner: configuration: %s', tns_risky_kube_deploy_nessus_config)
    deployment = {}
    try:
        tns_risky_kube_deploy_nessus_config['type'] = DEPLOYMENT_TYPE_NESSUS_REMOTE
        deployment = create_kube_deployment(config=tns_risky_kube_deploy_nessus_config, api=request.cls.cat.api,
                                            product_url=NessusConfig.CAT_NESSUS_URL)
        _activate_scanner(scanner_type=DEPLOYMENT_TYPE_NESSUS_REMOTE,
                          host=deployment['IP'],
                          port=deployment['Port'],
                          fresh_install=tns_risky_kube_deploy_nessus_config.get('freshInstall') or False)
        request.cls.cat.deployment = deployment
        yield deployment
    finally:
        log.debug('fixture teardown: kube_deploy_nessus_remote_scanner')
        _cleanup(deployment)


@pytest.fixture(scope='class')
def tns_risky_kube_deploy_nessus_managed_scanner(request: 'SubRequest', tns_risky_kube_deploy_nessus_config: dict) -> \
        dict:
    """
    Deploys a Nessus Managed (Professional) scanner

    :param SubRequest request: SubRequest
    :param dict tns_risky_kube_deploy_nessus_config: Deployment configuration
    :return: dict
    :raises: CatiumDeploymentError
    """
    log.debug('fixture init: kube_deploy_nessus_managed_scanner: configuration: %s',
              tns_risky_kube_deploy_nessus_config)
    deployment = {}
    try:
        tns_risky_kube_deploy_nessus_config['type'] = DEPLOYMENT_TYPE_NESSUS_MANAGED
        deployment = create_kube_deployment(config=tns_risky_kube_deploy_nessus_config, api=request.cls.cat.api,
                                            product_url=NessusConfig.CAT_NESSUS_URL)
        _activate_scanner(scanner_type=DEPLOYMENT_TYPE_NESSUS_MANAGED,
                          host=deployment['IP'],
                          port=deployment['Port'],
                          fresh_install=tns_risky_kube_deploy_nessus_config.get('freshInstall') or False)
        request.cls.cat.deployment = deployment
        yield deployment
    finally:
        log.debug('fixture teardown: kube_deploy_nessus_managed_scanner')
        _cleanup(deployment)


@pytest.fixture(scope='class')
def tns_risky_kube_deploy_nessus_manager(request: 'SubRequest', tns_risky_kube_deploy_nessus_config: dict) -> dict:
    """
    Deploys a Nessus Manager

    :param SubRequest request: SubRequest
    :param dict tns_risky_kube_deploy_nessus_config: Deployment configuration
    :return: dict
    :raises: CatiumDeploymentError
    """
    log.debug('fixture init: kube_deploy_nessus_manager: configuration: %s', tns_risky_kube_deploy_nessus_config)
    deployment = {}
    try:
        tns_risky_kube_deploy_nessus_config['type'] = DEPLOYMENT_TYPE_NESSUS_MANAGER
        deployment = create_kube_deployment(config=tns_risky_kube_deploy_nessus_config, api=request.cls.cat.api,
                                            product_url=NessusConfig.CAT_NESSUS_URL)
        _activate_scanner(scanner_type=DEPLOYMENT_TYPE_NESSUS_MANAGER,
                          host=deployment['IP'],
                          port=deployment['Port'],
                          fresh_install=tns_risky_kube_deploy_nessus_config.get('freshInstall') or False)
        request.cls.cat.deployment = deployment
        yield deployment
    finally:
        log.debug('fixture teardown: kube_deploy_nessus_manager')
        _cleanup(deployment)


@pytest.fixture(scope='class')
def tns_risky_deploy_nessus_aws(request: 'SubRequest') -> dict:
    """
    Deploys a Nessus AWS managed scanner to a tenable.io instance based on the configuration

    .. note:: The AWS instance is linked to container owned by the API session user (i.e. cat.api)
    .. note:: This fixture relies on the request.cls.cat.api attribute

    :param SubRequest request: SubRequest
    :returns: dict, deployment dict
    :raises: CatiumDeploymentError
    """
    log.debug('fixture init: deploy_nessus_aws')
    settings = load_testdata('nessus/plugins/deployment/aws_nessus_instance_config.json')
    instance = None
    try:
        name = random_name('automation-aws-')
        linking_key = request.cls.cat.api.scanners.get_linking_key().get('key')
        ec2client = EC2Client(region=AWS.Regions.USEast1,
                              access_key_id=config.CAT_ACCESS_KEY,
                              secret_key=config.CAT_SECRET_ACCESS_KEY)
        user_data = json.dumps({'name': name,
                                'manager_host': Url(NessusConfig.CAT_NESSUS_URL).hostname,
                                'manager_port': '443',
                                'key': linking_key,
                                'iam_role': settings['iamrole']})
        log.debug('AWS instance user data is: %s', user_data)
        instance = ec2client.create_instance(image=settings['image'],
                                             instance_type=AWSEC2.InstanceTypes.t2medium.value,
                                             snapshot=settings['snapshot'],
                                             subnet=settings['subnet'],
                                             groups=settings['groups'],
                                             arn=settings['arn'],
                                             tag=name,
                                             userdata=user_data,
                                             zone=AWS.AvailabilityZones.USEast1A,
                                             assign_public_ip=True)
        log.debug('Creating AWS EC2 instance')
        instance.wait_until_exists()
        log.debug('Instance "%s" created successfully', instance.id)
        log.debug('Waiting for instance "%s" to become available', instance.id)
        instance.wait_until_running()
        log.debug('Instance "%s" is ready', instance.id)
        yield {'name': name, 'type': DEPLOYMENT_TYPE_AWS_MANAGED}
    finally:
        log.debug('fixture teardown: deploy_nessus_aws')
        try:
            if instance:
                instance.terminate()
        except Exception:
            log.exception('Terminating instance "%s" failed', instance.id)
# endregion
