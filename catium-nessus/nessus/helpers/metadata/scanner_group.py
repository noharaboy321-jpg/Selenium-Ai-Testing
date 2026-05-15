"""
Helper methods to retrieving metadata from an API Scanner Group object
"""
from catium.lib.errors import CatiumAPIObjectNotFoundError


def get_id(resp, name: str) -> str:
    """
    Iterates through a list of scanner groups and returns the ScannerGroupID for the supplied scanner group name

    :param resp: API Response Object of GET /scanner-groups API
    :param str name: Scanner Group name
    :return: ID of Scanner Group
    :raises: CatiumAPIObjectNotFoundError
    """
    results = [scanner_group['id']
               for scanner_group in resp['scanner_pools'] if scanner_group['name'].lower() == name.lower()]
    if not results:
        raise CatiumAPIObjectNotFoundError('Scanner Group "%s" not found.' % name)
    return results[0]


def get_scanner_id(resp, name: str) -> str:
    """
    Iterates through a list of scanner groups and returns the ScannerID for the supplied scanner group name.

    :param resp: API Response Object of GET /scanner-groups API
    :param str name: Scanner Group name
    :returns: ScannerID of Scanner Group
    :raises: CatiumAPIObjectNotFoundError
    """
    results = [scanner_group['scanner_id']
               for scanner_group in resp['scanner_pools'] if scanner_group['name'].lower() == name.lower()]
    if not results:
        raise CatiumAPIObjectNotFoundError('Scanner Group "%s" not found.' % name)
    return results[0]
