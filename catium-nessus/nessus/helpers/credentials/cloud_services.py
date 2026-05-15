"""
Cloud Services Credential Mixin

TODO Incomplete
"""


class CloudServicesMixin:
    """Mixin class for creating Cloud Services credential dictionaries"""

    class CloudServices:
        @staticmethod
        def create_amazon_aws_credential():
            raise NotImplementedError

        @staticmethod
        def create_rackspace_credential():
            raise NotImplementedError

        @staticmethod
        def create_microsoft_azure_credential():
            raise NotImplementedError

        @staticmethod
        def create_salesforce_credential():
            raise NotImplementedError
