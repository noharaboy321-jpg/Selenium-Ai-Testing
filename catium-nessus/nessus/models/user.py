"""
Nessus User Model
"""
from nessus.models.base_user_model import BaseUserModel


class UserModel(BaseUserModel):
    """Nessus User Model"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @staticmethod
    def create_model():
        """Method to auto-generate a default UserModel with required parameters"""
        return UserModel(autogen=True)
