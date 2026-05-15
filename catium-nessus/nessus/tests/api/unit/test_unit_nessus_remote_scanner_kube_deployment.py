"""
Unit test for deploying a Nessus Remote scanner

:copyright: Tenable Network Security, 2017
:date: Jul 06, 2017
:author: @jyerge
"""
import pytest
from http import HTTPStatus
from requests.exceptions import RequestException

from catium.lib.const import TIME_FIFTEEN_MINUTES, STRING_NO, TIME_ONE_HOUR
from catium.lib.const.deployment import DOCKER_IMAGES, SCANNER_USERNAME, SCANNER_PASSWORD
from catium.lib.ssh import SSH
from nessus.lib.const import API
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.waiters import wait_for_scanner_login, wait_for_scanner_status


@pytest.mark.unittest
class TestNessusRemoteScannerKubeDeployment:
    """Ensures that a Remote Nessus scanner can be deployed into the Automation Kubernetes cluster"""

    cat = None

    @pytest.mark.usefixtures("kube_deploy_nessus_remote_scanner")
    @pytest.mark.parametrize("kube_deploy_nessus_config", [{
        "link": STRING_NO, "image": DOCKER_IMAGES['nessus']['es7']['release']}],
                             indirect=True)
    def test_nessus_remote_scanner_kube_deploy(self, kube_deploy_nessus_config):
        """Test Remote Nessus scanner deployment"""
        nessus_api = None
        try:
            nessus_api = NessusAPI()
            nessus_api.session_url = 'https://{host}:{port}'.format(host=self.cat.deployment['IP'],
                                                                    port=self.cat.deployment['Port'])
            wait_for_scanner_status(api=nessus_api,
                                    status=API.Status.READY,
                                    timeout=TIME_ONE_HOUR,
                                    msg='Availability of Nessus scanner')
            wait_for_scanner_login(api=nessus_api,
                                   username=SCANNER_USERNAME,
                                   password=SCANNER_PASSWORD,
                                   timeout=TIME_FIFTEEN_MINUTES,
                                   msg='Waiting for scanner login to succeed')
            nessus_api.session.get()
            response_code = nessus_api.http_status_code
            nessus_api.logout()
            nessus_api = None
            assert response_code == HTTPStatus.OK, 'Expected HTTP 200, got {} instead'.format(response_code)
        finally:
            if nessus_api:
                try:
                    nessus_api.logout()
                except RequestException:
                    pass

    @pytest.mark.usefixtures("kube_deploy_nessus_remote_scanner")
    @pytest.mark.parametrize("kube_deploy_nessus_config", [{
        "link": STRING_NO, "image": DOCKER_IMAGES['nessus']['es6']['release'], "ssh": True}],
                             indirect=True)
    def test_nessus_remote_scanner_kube_deploy_with_ssh_for_es6(self, kube_deploy_nessus_config):
        """Test Remote Nessus scanner deployment with SSH enabled for ES6"""
        assert 'SSHPort' in self.cat.deployment,\
            'Expected the field "SSHPort" to be present in returned deployment dictionary'
        ssh = SSH(url_or_ip=self.cat.deployment['IP'],
                  port=self.cat.deployment['SSHPort'],
                  username='root',
                  password='LabPass1')
        result = ssh.execute(command='id')
        assert 'uid=0(root)' in result[0],\
            'Expected substring "uid=0(root)" to be present in response "{}"'.format(result[0])

    @pytest.mark.usefixtures("kube_deploy_nessus_remote_scanner")
    @pytest.mark.parametrize("kube_deploy_nessus_config", [{
        "link": STRING_NO, "image": DOCKER_IMAGES['nessus']['es7']['release'], "ssh": True}],
                             indirect=True)
    def test_nessus_remote_scanner_kube_deploy_with_ssh_for_es7(self, kube_deploy_nessus_config):
        """Test Remote Nessus scanner deployment with SSH enabled for ES7"""
        assert 'SSHPort' in self.cat.deployment,\
            'Expected the field "SSHPort" to be present in returned deployment dictionary'
        ssh = SSH(url_or_ip=self.cat.deployment['IP'],
                  port=self.cat.deployment['SSHPort'],
                  username='root',
                  password='LabPass1')
        result = ssh.execute(command='id')
        assert 'uid=0(root)' in result[0],\
            'Expected substring "uid=0(root)" to be present in response "{}"'.format(result[0])

    # Tests a standalone deployment, i.e. links to nothing but can be used for testing
    @pytest.mark.usefixtures("kube_deploy_nessus_remote_scanner", "kube_standalone_deploy")
    @pytest.mark.parametrize("kube_deploy_nessus_config", [{
        "link": STRING_NO, "image": DOCKER_IMAGES['nessus']['es7']['release']}],
                             indirect=True)
    def test_nessus_remote_scanner_kube_deploy_standalone(self, kube_deploy_nessus_config):
        """Test Remote Nessus standalone scanner deployment"""
        nessus_api = NessusAPI()
        wait_for_scanner_status(api=nessus_api,
                                status=API.Status.READY,
                                timeout=TIME_ONE_HOUR,
                                msg='Availability of Nessus scanner')
        wait_for_scanner_login(api=nessus_api,
                               username=SCANNER_USERNAME,
                               password=SCANNER_PASSWORD,
                               timeout=TIME_FIFTEEN_MINUTES,
                               msg='Waiting for scanner login to succeed')
        nessus_api.session.get()
        response_code = nessus_api.http_status_code
        nessus_api.logout()
        assert response_code == HTTPStatus.OK, 'Expected HTTP 200, got {} instead'.format(response_code)

    # Tests a standalone deployment without activation, i.e. links to nothing but can be used for testing
    @pytest.mark.usefixtures("kube_deploy_nessus_remote_scanner", "kube_standalone_deploy")
    @pytest.mark.parametrize("kube_deploy_nessus_config", [{
        "link": STRING_NO, "image": DOCKER_IMAGES['nessus']['es7']['release'], "freshInstall": True}],
                             indirect=True)
    def test_nessus_remote_scanner_kube_deploy_standalone_freshinstall(self, kube_deploy_nessus_config):
        """Test a fresh install of a Remote Nessus standalone scanner deployment"""
        nessus_api = NessusAPI()
        wait_for_scanner_status(api=nessus_api,
                                status=API.Status.REGISTER,
                                timeout=TIME_ONE_HOUR,
                                msg='Availability of Nessus scanner')
        assert nessus_api.http_status_code == HTTPStatus.OK,\
            'Expected HTTP {0}, got {1} instead'.format(HTTPStatus.OK, nessus_api.http_status_code)


@pytest.mark.unittest
@pytest.mark.serial
@pytest.mark.usefixtures("tns_risky_kube_deploy_nessus_remote_scanner",
                         "tns_risky_kube_standalone_deploy",
                         "nessus_class_api_login")
@pytest.mark.parametrize("tns_risky_kube_deploy_nessus_config", [{
    "link": STRING_NO, "image": DOCKER_IMAGES['nessus']['es7']['release']}],
                         indirect=True, scope='class')
class TestTNSRiskyNessusRemoteScannerKubeDeployment:
    """
    Ensures that a Remote Nessus scanner can be deployed into the Automation Kubernetes cluster using the risky
    deployment fixtures
    """

    cat = None

    # API_Tested# GET /server/status
    def test_get_scanner_status(self, tns_risky_kube_deploy_nessus_config):
        """Verify scanner status can be retrieved"""
        self.cat.api.server.status()
        assert self.cat.api.http_status_code == HTTPStatus.OK,\
            'Expected HTTP {0}, got {1} instead'.format(HTTPStatus.OK, self.cat.api.http_status_code)

    # API_Tested# GET /session
    def test_get_session(self, tns_risky_kube_deploy_nessus_config):
        """
        Verify session can be retrieved
        
            Scenarios:
            [x] Test successful session retrieval
        """
        self.cat.api.session.get()
        assert self.cat.api.http_status_code == HTTPStatus.OK,\
            'Expected HTTP {0}, got {1} instead'.format(HTTPStatus.OK, self.cat.api.http_status_code)

    # API_Tested# GET /users
    def test_get_users(self, tns_risky_kube_deploy_nessus_config):
        """
        Verify users can be retrieved
        
         Scenarios:
         [x] Test that user information can be retrieved
        """
        self.cat.api.users.get_users()
        assert self.cat.api.http_status_code == HTTPStatus.OK,\
            'Expected HTTP {0}, got {1} instead'.format(HTTPStatus.OK, self.cat.api.http_status_code)
