"""
Marker to indicate Nessus version requirements

:copyright: Tenable Network Security, 2017
:date: Oct 10 2017
:author: @djsmith
"""
from typing import TYPE_CHECKING

from catium.lib.log import create_logger
from nessus.helpers.system import get_nessus_version, get_nessus_type
from packaging.version import Version

if TYPE_CHECKING:
    from catium.lib.typechecking import Config

log = create_logger()


def pytest_collection_modifyitems(config: 'Config', items: list):
    """Remove tests from the collection that do not meet the following version requirements:
    current version >= required version, if required version specified
    current version <= max version, if max version specified
    current type is in the set of supported types, provided as a string or list of strings
    """
    nessus_version = get_nessus_version()
    nessus_version = nessus_version if nessus_version is None else '0'
    nessus_type = get_nessus_type()
    remaining = list()
    deselected = list()

    while items:
        test_object = items.pop(0)
        max_version = None
        required_version = None
        required_type = None
        # TODO: this picks the highest required version, but should it use a hierarchy? ie. function > class > module?

        for info in test_object.iter_markers(name='nessus_version'):
                info_version = info.kwargs.get('required_version', None)
                info_type = info.kwargs.get('required_type', None)
                info_max_version = info.kwargs.get('max_version', None)
                if required_version is None:
                    required_version = info.kwargs.get('required_version')
                if info_version is not None:
                    if Version(info_version) > Version(required_version):
                        required_version = info_version
                if required_type is None and info_type is not None:
                    required_type = info_type
                if info_max_version is not None:
                    max_version = info_max_version

        if is_allowed_version_and_type(nessus_version, nessus_type, required_version, max_version, required_type):
            remaining.append(test_object)
        else:
            print('{} requirements do not match the current nessus type and version: (type={}, version={})'.format(
                test_object.name, nessus_type, nessus_version))
            print('Required type: version={}, type={} max_version={}'.format(required_version, required_type,
                                                                             max_version))
            deselected.append(test_object)
    items[:] = remaining
    config.hook.pytest_deselected(items=deselected)


def is_allowed_version_and_type(nessus_version, nessus_type, required_version=None, max_version=None,
                                required_type=None) -> bool:
    """
    Checks whether or not the Nessus test target meets the specified version requirements
    :param nessus_version: the current Nessus version
    :param nessus_type: the current Nessus type (ie. Nessus Professional, Nessus Manager)
    :param required_version: the minimum required Nessus version
    :param max_version: the maximum supported Nessus version
    :param required_type: one or more Nessus types (Nessus Professional, Nessus Manager)
    :return:
    """
    if required_version:
        if Version(required_version) > Version(nessus_version):
            return False

    if max_version:
        if Version(nessus_version) > Version(max_version):
            return False

    if isinstance(required_type, str):
        if nessus_type != required_type:
            return False

    if isinstance(required_type, list):
        if nessus_type not in required_type:
            return False

    return True


