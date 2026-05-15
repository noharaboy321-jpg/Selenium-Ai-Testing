"""
Helper methods to retrieving metadata from an API Policy object
"""
from catium.lib.errors import CatiumAPIResponseError, CatiumAPIObjectNotFoundError


def get_template_uuid(resp, name: str) -> str:
    """
    Iterates through a list of policies and attempts to return the Template UUID for the supplied name

    :param resp: API Response Object
    :param str name: Policy name
    :returns: str, template UUID
    :raises: CatiumAPIResponseError, CatiumAPIObjectNotFoundError
    """
    if 'policies' not in resp:
        raise CatiumAPIResponseError('API response is malformed, expected "policies" field.')
    results = [policy['template_uuid'] for policy in resp['policies'] if policy['title'].lower() == name.lower()]
    if not results or len(results) == 0:
        raise CatiumAPIObjectNotFoundError('Policy "%s" not found.' % name)
    return results[0]


def get_id(resp, name: str) -> str:
    """
    Iterates through a list of policies and attempts to return the ID for the supplied name

    :param resp: API Response Object
    :param str name: Policy name
    :returns: str, ID
    :raises: CatiumAPIResponseError, CatiumAPIObjectNotFoundError
    """
    if 'policies' not in resp:
        raise CatiumAPIResponseError('API response is malformed, expected "policies" field.')
    results = [policy['id'] for policy in resp['policies'] if policy['title'].lower() == name.lower()]
    if not results or len(results) == 0:
        raise CatiumAPIObjectNotFoundError('Policy "%s" not found.' % name)
    return results[0]


def get_user_permissions(resp, name: str) -> int:
    """
    Iterates through a list of policies and attempts to return the user permissions for the supplied name

    :param resp: API Response Object
    :param str name: Policy name
    :returns: int, permissions
    :raises: CatiumAPIResponseError, CatiumAPIObjectNotFoundError
    """
    if 'policies' not in resp:
        raise CatiumAPIResponseError('API response is malformed, expected "policies" field.')
    results = [policy['user_permissions'] for policy in resp['policies'] if policy['title'].lower() == name.lower()]
    if not results or len(results) == 0:
        raise CatiumAPIObjectNotFoundError('Policy "%s" not found.' % name)
    return int(results[0])
