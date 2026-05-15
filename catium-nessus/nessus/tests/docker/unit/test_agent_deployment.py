"""
Unittest for Agent deployment fixture.

:copyright: Tenable Network Security, 2017
:date: Sept 27th 2017
:author: @jmcneil
"""

import pytest


@pytest.mark.unittest
@pytest.mark.usefixtures("docker_agent")
class TestAgentDeployment:
    """Test ability to start a Nessus Agent using the docker agent fixture."""

    cat = None
    fetch_key = False
    linked = False
    use_proxy = False

    def test_agent_deployment(self, docker_agent):
        """Test deploying Nessus Agents using Docker."""
        assert docker_agent.cid, "The Agent failed to start correctly."
