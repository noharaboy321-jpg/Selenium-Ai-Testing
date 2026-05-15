"""
Policy Model
"""
from catium.lib.util import random_name


class PolicyModel(object):
    """
    Defines the parameters needed to create a new policy in Nessus

    :param str uuid: UUID of policy template
    :param basically_a_json_object settings: Settings for the policy
    :param basically_a_json_object credentials: Credentials for the policy
    :param boolean autogen: Automatically generate policy parameters, ignores parameters passed
    :raises: ModelError
    """
    uuid = None

    def __init__(self, uuid: str=None, settings: dict=None, credentials: dict=None, name: str=None, autogen=False):

        super().__init__()

        if autogen:
            self.settings = {
                'name': random_name(prefix='policy-')
            }
            self.credentials = {}
        else:
            self.settings = settings
            self.credentials = credentials

    @staticmethod
    def create_model():
        """Method to auto-generate a default PolicyModel with required parameters"""
        return PolicyModel(autogen=True)

    def configure_settings(self, settings: dict):
        """
        Configure settings for policy

        Settings Tuples:
            settings = [(API.Policies.Settings, True)]
            Tuple is ({setting}, {bool}) where True enables settings and False disables setting

        :param dict settings: Dictionary of setting tuples
        :raises: TypeError
        """
        if not settings:
            return
        policy_settings = {
            'name': random_name(prefix='policy-')
        }
        for item in settings:
            if not isinstance(item, tuple):
                raise TypeError('Invalid setting "%s", expected type to be tuple.' % str(item))

            setting = item[0]
            state = item[1]

            if not isinstance(state, bool):
                msg = 'Invalid state for setting "%s", expected type to be bool but got "%s".' % (setting, type(state))
                raise TypeError(msg)

            policy_settings[setting.value] = state
        self.settings = policy_settings

    def configure_credentials(self):
        """
        Configure policy credentials

        .. note:: This sets the credentials for the policy

        """
        self.credentials = {}

    def create_payload(self) -> dict:
        """Returns a dictionary for use as a request model to API endpoints"""
        return {'uuid': self.uuid, 'settings': self.settings, 'credentials': self.credentials}
