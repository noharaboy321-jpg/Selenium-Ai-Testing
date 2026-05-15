"""
Base helper class for credentials
"""
from nessus.helpers.credentials.cloud_services import CloudServicesMixin
from nessus.helpers.credentials.database import DatabaseMixin
from nessus.helpers.credentials.miscellaneous import MiscellaneousMixin
from nessus.helpers.credentials.plaintext_authentication import PlaintextAuthenticationMixin
from nessus.helpers.credentials.host import HostMixin
from nessus.helpers.credentials.mobile import MobileMixin
from nessus.helpers.credentials.patch_management import PatchManagementMixin


class CredentialBaseHelper:
    """Base class for the CredentialHelper class"""


class CredentialHelper(CloudServicesMixin, DatabaseMixin, HostMixin, MiscellaneousMixin, PlaintextAuthenticationMixin,
                       MobileMixin, PatchManagementMixin, CredentialBaseHelper):
    """
    Helper class for Credentials

    .. note:: This class mixes in several mix-in classes, the CredentialBaseHelper should ALWAYS be mixed in last. This
        is recommended by API.
    """
