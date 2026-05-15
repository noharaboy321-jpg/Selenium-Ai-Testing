"""
Nessus Users Endpoint
"""
from catium.lib import const
from catium.lib.api.base_api_object import ResponseObject
from catium.lib.log import create_logger
from nessus.apiobjects import routes
from nessus.models.user import UserModel

log = create_logger()


class UsersEndpoint(object):
    """ Users API Endpoint """

    def __init__(self, cls):
        self._cls = cls

    def create(self, model: UserModel = None, payload: dict = None, stream: bool = False) -> ResponseObject:
        """
        Create a user

        :param object model: A UserModel object
        :param dict payload: Raw payload
        :param bool stream: True if need to get response text else False
        :return: ResponseObject
        """
        self._cls.check_model_and_payload(model, payload)

        if model:
            payload = model.create_payload()

        response = self._cls.request(const.HTTPMethods.POST, routes.USERS, json=payload, stream=stream)
        response = ResponseObject(response)
        log.debug('Created User ID #%s using model', response['id'])
        return response

    def delete(self, user_id: int) -> None:
        """
        Delete a user

        :param int user_id: User ID
        :return: None
        """
        self._cls.request(const.HTTPMethods.DELETE, routes.USERS + '/' + str(user_id))
        log.debug('Deleted user ID "%s"', user_id)

    def delete_users(self, user_ids: list, transfer: bool = False) -> ResponseObject:
        """
        Delete multiple (bulk) users

        :param list user_ids: User IDs to delete
        :param transfer: Transfer the user data to 'admin' user or not
        :return: ResponseObject
        """
        payload = {'ids': user_ids, 'transfer': True} if transfer else {'ids': user_ids, 'transfer': False}
        response = self._cls.request(const.HTTPMethods.DELETE, routes.USERS, json=payload)
        log.debug('Deleted user IDs "%s"', user_ids)
        return ResponseObject(response)

    def get(self, user_id: int) -> ResponseObject:
        """
        Gets a user's details

        :param int user_id: User ID
        :return: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.USERS + '/' + str(user_id))
        log.debug('Got user details for user ID "%s"', user_id)
        return ResponseObject(response)

    def edit(self, user_id: int, model: UserModel) -> ResponseObject:
        """
        Edit user

        :param int user_id: User ID
        :param object model: A UserModel object
        :return: ResponseObject
        """
        payload = model.create_payload()
        resource = '%s/%s' % (routes.USERS, user_id)
        response = self._cls.request(const.HTTPMethods.PUT, resource, json=payload)
        response = ResponseObject(response)
        log.debug('Edited User ID #%s using model', response['id'])
        return response

    def change_password(self, user_id: int, payload: dict) -> ResponseObject:
        """
        Change user password
        :param int user_id: User ID
        :param dict payload: payload which consist new password for user
        :return: ResponseObject
        """
        resource = '%s/%s/chpasswd' % (routes.USERS, user_id)
        response = self._cls.request(const.HTTPMethods.PUT, resource, json=payload)
        response = ResponseObject(response)
        return response

    def get_users(self) -> ResponseObject:
        """
        Get a list of users

        :return: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.USERS)
        return ResponseObject(response)

    def password(self, user_id: int, current_password: str, password: str) -> ResponseObject:
        """
        Changes the password for the given user

        :param int user_id: User ID
        :param str current_password: Current password for user
        :param str password: New password for user
        :return: ResponseObject
        """
        resource = '%s/%s/chpasswd' % (routes.USERS, user_id)
        response = self._cls.request(const.HTTPMethods.PUT, resource,
                                     json={'current_password': current_password, 'password': password})
        return ResponseObject(response)

    def generate_keys(self, user_id: int) -> ResponseObject:
        """
        Generates the API Keys for the given user

        :param int user_id: User ID
        :return: ResponseObject
        """
        resource = '%s/%s/keys' % (routes.USERS, user_id)
        response = self._cls.request(const.HTTPMethods.PUT, resource)
        return ResponseObject(response)

    def transfer_user_data(self, user_id: int) -> ResponseObject:
        """
        Transfer the data for given user to 'admin' user.

        :param int user_id: User ID
        :return: ResponseObject
        """
        payload = {"ids": [str(user_id)]}
        resource = '%s/transfer' % routes.USERS
        response = self._cls.request(const.HTTPMethods.POST, resource, json=payload)
        return ResponseObject(response)
