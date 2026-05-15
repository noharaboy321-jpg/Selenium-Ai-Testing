"""
Unittests for Scanner deployment fixture.

:copyright: Tenable Network Security, 2017
:date: Sept 27th 2017
:author: @jmcneil
"""

import pytest


@pytest.mark.unittest
class TestNessusProDeployment:
    """Test ability to start a Nessus Professional scanner using the Docker fixture."""

    cat = None
    nessus_mode = "pro"
    wait_for_plugin_loading = True

    @pytest.mark.usefixtures("docker_scanner")
    def test_scanner_deployment(self, docker_scanner):
        """Test deploying a Nessus Professional scanner using Docker."""
        assert docker_scanner.cid, "Nessus Professional failed to start correctly on Docker host."


@pytest.mark.unittest
class TestNessusManagerDeployment:
    """Test ability to start a Nessus Manager using the Docker fixture, without waiting for plugin loading."""

    cat = None
    nessus_mode = "manager"
    wait_for_plugin_loading = False

    @pytest.mark.usefixtures("docker_scanner")
    def test_manager_deployment(self, docker_scanner):
        """Test deploying a Nessus Manager using Docker."""
        assert docker_scanner.cid, "Nessus Manager failed to start correctly on Docker host."


@pytest.mark.unittest
class TestScanningDeployment:
    """Test ability to start a Nessus Professional scanner using the Docker scanning fixture."""

    cat = None

    @pytest.mark.usefixtures("docker_scanning")
    def test_scanning_deployment(self, docker_scanning):
        """Test deploying a Nessus Professional scanner scan testing using Docker."""
        assert docker_scanning.cid, "Nessus Professional failed to start correctly on " \
                                    "Docker host and is unavilable for scanning."
