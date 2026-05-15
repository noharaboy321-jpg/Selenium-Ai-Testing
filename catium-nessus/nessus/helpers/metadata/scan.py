"""
Helper methods to retrieving metadata from an API Scan object
"""
from catium.lib.api.base_api_object import ResponseObject
from catium.lib.errors import CatiumAPIResponseError, CatiumAPIObjectNotFoundError
from catium.lib.log import create_logger

log = create_logger()


def _get_template_uuid(resp: ResponseObject, field: str, string: str) -> str:
    if 'templates' not in resp:
        raise CatiumAPIResponseError('API response is malformed, expected "templates" field. Response: {0}'.
                                     format(resp))
    results = [template['uuid'] for template in resp['templates'] if string.lower() in template[field].lower()]

    if not results:
        raise CatiumAPIObjectNotFoundError('Template "{0}" not found.'.format(string))

    return results[0]


def get_template_uuid(resp: ResponseObject, title: str) -> str:
    """
    Iterates through a list of templates and attempts to return the UUID for the supplied title or name.

    .. note:: This method compares both template titles and names

    :param ResponseObject resp: API Response Object
    :param str title: Template title or name.
    :returns: Template UUID
    :raises: CatiumAPIResponseError, CatiumAPIObjectNotFoundError
    """
    try:
        return _get_template_uuid(resp=resp, field='name', string=title)
    except CatiumAPIObjectNotFoundError as exc:
        log.debug("Unable to find template {0} by name, "
                  "attempting to find it using template title. Reason: {1}".format(str(title), str(exc)))
        return _get_template_uuid(resp=resp, field='title', string=title)


def get_template_uuid_by_name(resp: ResponseObject, name: str) -> str:
    """
    Iterates through a list of templates and attempts to return the UUID for the supplied title

    .. note:: This method compares the passed ``name`` arg to the template name, not the title. A template title is
        something like 'Advanced Scan' where a name is something like 'avdscan' (not the exact, just a sample)

    :param ResponseObject resp: API Response Object
    :param str name: Template name (not title)
    :returns: Template UUID
    :raises: CatiumAPIResponseError, CatiumAPIObjectNotFoundError
    """
    return _get_template_uuid(resp=resp, field='name', string=name)


def get_template_name(resp: ResponseObject, uuid: str) -> str:
    """
    Iterates through a list of templates and attempts to return the name for the supplied UUID

    :param ResponseObject resp: API Response Object
    :param str uuid: Template uuid
    :returns: Template name
    :raises: CatiumAPIResponseError, CatiumAPIObjectNotFoundError
    """
    if 'templates' not in resp:
        raise CatiumAPIResponseError('API response is malformed, expected "templates" field. Response: {0}'.
                                     format(resp))
    results = [template['name'] for template in resp['templates'] if template['uuid'].lower() == uuid.lower()]
    if not results:
        raise CatiumAPIObjectNotFoundError('Template "%s" not found.' % uuid)
    return results[0]


def get_scan_details_by_name(resp: ResponseObject, name: str) -> int:
    """
    Iterates through a list of scans and attempts to return the scan job ID for the supplied scan job name

    :param resp: API Response Object
    :param str name: Scan job name
    :returns: Scan job details
    :rtype: int
    :raises: CatiumAPIObjectNotFoundError
    """
    if 'scans' not in resp:
        raise CatiumAPIResponseError('API response is malformed, expected "scans" field. Response: {0}'.format(resp))
    for scan in resp['scans']:
        if scan.get('name') == name:
            return scan
    raise CatiumAPIObjectNotFoundError('Scan "%s" not found.' % name)
