"""
Helper functions for Docker images.

The code examples in the docstrings assume the module has been imported like so:

.. code-block:: python

    import dockernessus
    docker_nessus = dockernessus.DockerNessus()

:copyright: Tenable Network Security, 2017
:date: Aug 30 2017
:author: @jmcneil
"""


from .session import Session


class Image(Session):

    """Class provides image related Docker methods."""

    def build(self, image_name, dockerfile_path=None, nocache=True, show_output=True, remove=True):
        """
        Build a Docker image from a Dockerfile. If no dockerfile_path is specified, it will assume the Dockerfile is
        in the current working directory.

        :param str image_name: The name/tag for the image.
        :param str dockerfile_path: Location of the Dockerfile. Supports /local/, https://domain/Dockerfile or repo.git.
        :param bool nocache: Flag to enable/disable cache usage during image build. Default: True
        :param bool show_output: Flag to hide build output.
        :param bool remove: Flag to remove intermediate containers during the build. Default: True
        :returns: Output of the build.
        :rtype: Generator

        .. code-block:: python

            docker_nessus.build("my_appname:0.0.1", "/opt/my_appname/")
        """
        if not dockerfile_path:
            dockerfile_path = "."

        build_output = self.api_client.build(path=dockerfile_path, tag=image_name,
                                             nocache=nocache, rm=remove, decode=True)

        if show_output and build_output:
            for line in build_output:
                self.logger.info(str(line))

        return build_output

    def history(self, image_name):
        """
        Show the history of the Docker image.

        :param str image_name: Image ID to pull history information from.
        :return: A list of Docker history, None if failed.
        :rtype: List

        .. code-block:: python

            history = docker_nessus.history("nginx")
            for line in history:
                print("{0} | {1}".format(line["Id"], line["CreatedBy"]))
        """
        return self.api_client.history(image_name)

    def inspect_image(self, image):
        """
        Inspect a Docker image and return the info.

        :param str image: Image name or ID to inspect.
        :return: docker inspect output, None if failed.
        :rtype: Dictionary

        .. code-block:: python

            image_info = docker_nessus.inspect(image="nginx")
            print(image_info["Config"])
        """
        return self.api_client.inspect_image(image)

    def import_image(self, tarball, repo, tag):
        """
        Import a docker image from a tarball.

        :param str tarball: name of the tarball to import. Full path if not local.
        :param str repo: Image name up to the :. Typically the registry name. Ex:
                docker-registry.lab.tenablesecurity.com/services/nessus-centos7
        :param str tag: Tag for the image, usually aversion. Ex: 6.5.0
        :returns: docker inspect output, False if failed.
        :rtype: String

        .. code-block:: python

            docker_nessus.import_image("/tmp/image.tar",
                                       "dockerregistry.lab.tenablesecurity.com/services/nessus-custom",
                                       "6.11.0")
        """
        return self.api_client.import_image(src=tarball, repository=repo, tag=tag)

    def list(self):
        """
        List all available Docker images.

        :return: A list of Docker images, None if failed.
        :rtype: List

        .. code-block:: python

            image_list = docker_nessus.list()
            for line in image_list:
                print(line["RepoTags"][0])
        """
        return self.api_client.images()

    def prune_images(self):
        """
        Prune unused images from the Docker host.

        :returns: A dict containing a list of deleted image IDs and the amount of disk space reclaimed in bytes.
        :rtype: Dictionary

        .. code-block:: python

            docker_nessus.prune()
        """
        return self.client.images.prune()

    def pull(self, tag, image_name=None, image_dict=None, image_list=None, insecure_registry=True):
        """
        Pull a Docker image from the registry. Similar to docker pull, but accepts a dict|list containing
        multiple images.

        :param str tag: the image tag. Ex 6.11.0
        :param str image_name: The name of a single image to pull.
        :param dict image_dict: A Dictionary containing <general name>: <docker_image_name>.
        :param list image_list: a list containing [<docker_image_name>, <docker_image_name>].
        :param bool insecure_registry: Flag to disable/enable insecure registry setting.
        :returns: True if pulled
        :rtype: Boolean

        .. code-block:: python

            image_name = "docker-registry.lab.tenablesecurity.com/services/nessus-centos6"
            docker_nessus.pull(tag="6.11.0", image_name=image_name)
            docker_nessus.pull(tag="latest", image_list=["ubuntu", "nginx"])
            docker_nessus.pull(tag="6.11.0", image_dict={"Docker Nessus": image_name})
        """
        if image_name:
            res = self.api_client.pull(image_name, tag=tag)
            print (res)
            return True
        if image_dict:
            for name, dict_image_name in image_dict.items():
                self.api_client.pull(dict_image_name, tag=tag)
            return True
        elif image_list:
            for list_image_name in image_list:
                self.api_client.pull(list_image_name, tag=tag)
            return True

        self.logger.debug("There was an issue pulling images from the docker registry.")
        return False

    def push(self, repo, tag):
        """
        Push an image to a Docker Registry.

        :param str repo: Repository to push to.
        :param str tag: Tag of the image to push.
        :returns: True if pushed, False if failed.
        :rtype: Boolean

        .. code-block:: python

            docker_nessus.push(repository="docker-registry.lab.tenablesecurity.com/services/myservice", tag="0.1.1")
        """
        pushed = self.api_client.push(repository=repo, tag=tag)
        return True if pushed else False

    def remove_image(self, image):
        """
        Remove a Docker image.

        :param str image: Image ID to remove.
        :returns: True if removed, False if failed.
        :rtype: Boolean

        .. code-block:: python

            image_removed = docker_nessus.remove("test:latest")
        """
        self.api_client.remove_image(image)
        return True

    def tag(self, image, new_image_name, tag, force=False):
        """
        Tag a Docker image with a new name. Similar to docker tag command.

        :param str image: Name or Id of the existing image to tag.
        :param str new_image_name: Image name up to the colon (:). Typically the registry name. Ex:
                docker-registry.lab.tenablesecurity.com/services/nessus-centos7
        :param str tag: Tag for the image, usually a version. Ex: 6.6.0
        :param bool force: Force the image to be tagged, regardless if it is tagged in multiple repo's etc.
        :returns: True if tagged, False if failed.
        :rtype: Boolean

        .. code-block:: python

            docker_nessus.tag("ubuntu:14.04", "ubuntu", tag="devtest")
        """
        tagged = self.api_client.tag(image, repository=new_image_name, tag=tag, force=force)
        return True if tagged else False
