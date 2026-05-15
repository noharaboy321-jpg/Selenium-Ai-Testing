"""
Helper methods to retrieving metadata from an API Scanner object
"""
from catium.lib.errors import CatiumAPIObjectNotFoundError


def get_id(resp, name: str) -> str:
    """
    Iterates through a list of scanners and attempts to return the ID for the supplied name

    :param resp: API Response Object
    :param str name: Scanner name
    :returns: Scanner ID
    :raises: CatiumAPIObjectNotFoundError
    """
    for scanner in resp['scanners']:
        if scanner['name'].lower() == name.lower():
            return scanner['id']
    raise CatiumAPIObjectNotFoundError('Scanner "%s" not found.' % name)


def get_uuid(resp, name: str) -> str:
    """
    Iterates through a list of scanners and attempts to return the ID for the supplied name

    :param resp: API Response Object
    :param str name: Scanner name
    :returns: Scanner ID
    :raises: CatiumAPIObjectNotFoundError
    """
    for scanner in resp['scanners']:
        if scanner['name'].lower() == name.lower():
            return scanner['uuid']
    raise CatiumAPIObjectNotFoundError('Scanner "%s" not found.' % name)


def get_record(resp, name: str) -> dict:
    """
    Iterates through a list of scanners and attempts to return the record for the supplied name

    :param resp: API Response Object
    :param str name: Scanner name
    :returns: dict
    :raises: CatiumAPIObjectNotFoundError
    """
    for scanner in resp['scanners']:
        if scanner['name'].lower() == name.lower():
            return scanner
    raise CatiumAPIObjectNotFoundError('Scanner "%s" not found.' % name)
