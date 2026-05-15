# -*- coding: utf-8 -*-

"""
Python bindings for working / interacting with Docker Nessus and Docker Nessus Agent images (or any docker image).
Supports a large portion of the features offered by the docker run, images and logs commands.

Examples :

.. code-block:: python

   from nessus.helpers.dockernessus import docker_nessus

   agent_cid = docker_nessus.start_agent(full_image_name="nessus-centos6-agent:6.11.0", fetch_key=True)
   scanner_cid = docker_nessus.start_scanner(full_image_name="nessus-centos6:6.11.0", type="pro")
   managed_cid = docker_nessus.start_managed_scanner(full_image_name="nessus-centos6:6.11.0", key="<linking_key>")
"""

from nessus.helpers.dockernessus.lib.container import Container
from nessus.helpers.dockernessus.lib.image import Image
from .dockernessus import DockerNessus
from nessus.lib.config import docker_config

__version__ = "0.1.0"
__last_modification__ = "2017.08.30"
__title__ = 'dockernessus'

image = Image(version=docker_config.DOCKER_API_VERSION, base_url=docker_config.DOCKER_SCANNER_HOST)
container = Container(version=docker_config.DOCKER_API_VERSION, base_url=docker_config.DOCKER_SCANNER_HOST)
docker_nessus = DockerNessus(version=docker_config.DOCKER_API_VERSION, base_url=docker_config.DOCKER_SCANNER_HOST)
docker_agent_hosts = []

for host in docker_config.DOCKER_AGENT_HOSTS:
    docker_agent_hosts.append(DockerNessus(version=docker_config.DOCKER_API_VERSION, base_url=host))

if docker_config.DOCKER_REGISTRY_USERNAME:
    docker_nessus.login(registry=docker_config.LAB_DOCKER_REGISTRY,
                        username=docker_config.DOCKER_REGISTRY_USERNAME,
                        password=docker_config.DOCKER_REGISTRY_PASSWORD,
                        email=docker_config.DOCKER_REGISTRY_EMAIL)
    container.login(registry=docker_config.LAB_DOCKER_REGISTRY,
                    username=docker_config.DOCKER_REGISTRY_USERNAME,
                    password=docker_config.DOCKER_REGISTRY_PASSWORD,
                    email=docker_config.DOCKER_REGISTRY_EMAIL)

    image.login(registry=docker_config.LAB_DOCKER_REGISTRY,
                username=docker_config.DOCKER_REGISTRY_USERNAME,
                password=docker_config.DOCKER_REGISTRY_PASSWORD,
                email=docker_config.DOCKER_REGISTRY_EMAIL)

    for dah in docker_agent_hosts:
        dah.login(registry=docker_config.LAB_DOCKER_REGISTRY,
                  username=docker_config.DOCKER_REGISTRY_USERNAME,
                  password=docker_config.DOCKER_REGISTRY_PASSWORD,
                  email=docker_config.DOCKER_REGISTRY_EMAIL)
