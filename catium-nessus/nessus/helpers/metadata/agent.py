"""
Helper methods to retrieving metadata from an API Agent object
"""
from catium.lib.errors import CatiumAPIObjectNotFoundError


def get_agent_id(resp, name: str) -> str:
    """
    Iterates through a list of scanners and attempts to return the ID for the supplied name

    :param resp: API Response Object
    :param str name: Agent name
    :returns: Agent ID
    :raises: CatiumAPIObjectNotFoundError
    """
    results = [agent['id'] for agent in resp['agents'] if agent['name'].lower() == name.lower()]
    if not results:
        raise CatiumAPIObjectNotFoundError('Agent "%s" not found.' % name)
    return results[0]

