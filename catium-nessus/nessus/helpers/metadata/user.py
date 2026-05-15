"""
Helper methods to retrieving metadata from an API User Object
"""
from catium.lib.errors import CatiumAPIResponseError, CatiumAPIObjectNotFoundError


def get_id(resp, username: str) -> str:
    """
    Iterates through a list of users and attempts to return the ID for the supplied username (or contact)

    :param resp: API Response Object
    :param str username: Username
    :returns: User ID
    :raises: CatiumAPIResponseError, CatiumAPIObjectNotFoundError
    """
    if 'users' not in resp:
        raise CatiumAPIResponseError('API response is malformed, expected "users" field.')
    results = [user['id'] for user in resp['users'] if user['username'].lower() == username.lower()]
    if not results:
        raise CatiumAPIObjectNotFoundError('User "%s" not found.' % username)
    return results[0]
