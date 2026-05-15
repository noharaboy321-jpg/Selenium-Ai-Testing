"""
Nessus API Settings Helpers
"""
import time

from catium.lib.log import create_logger
from catium.lib.ssh.ssh import SSH
from nessus.apiobjects.nessus_api import NessusAPI

log = create_logger()


def handle_connection_popup(timeout_to_appear: int, timeout_to_disappear: int) -> None:
    # log.debug("Waiting for the connection pop up to appear")
    # nas = NoticeAdvancedSettings()
    # wait(lambda: not nas.connection_popup, sleep_seconds=TIME_FIVE_SECONDS, timeout_seconds=timeout_to_appear,
    #      waiting_for="Waiting to re-connect")
    # log.debug("Connection pop up is visible")
    #
    # try:
    #     log.debug("Waiting for the connection pop up to disappear")
    #     wait(lambda: _re_connect(), sleep_seconds=TIME_FIVE_SECONDS, timeout_seconds=timeout_to_disappear,
    #          waiting_for="Waiting to re-connect")
    #     log.debug("Connection pop up is not visible")
    # except TimeoutExpired:
    #     log.debug('Connection popup still remains after 30 mins. A Refresh may resolve that.')
    time.sleep(.5)


def get_current_advanced_settings(api: NessusAPI) -> list:
    """
    Method to return the names of current advanced settings of a Nessus scanner.

    :param NessusAPI api: Nessus API instance
    :returns: Names of current advanced settings configured
    :rtype: list
    """
    advanced_settings = api.settings.get_list()['preferences']
    return [setting['name'] for setting in advanced_settings]


def _construct_advanced_settings_payload(current_settings: list, settings_to_action: list, action: str = 'edit') \
        -> dict:
    """
    Method to construct the payload used to add/edit/remove advanced settings for a Nessus scanner.

    .. note:: Following actions will take place, based on action, as follows:
              - action='edit': payload is constructed only with settings from 'current_settings' in 'edit' mode
              - action='add': payload is constructed with settings from 'current_settings' in 'edit' mode plus the
                              settings from 'settings_to_action' in 'add' mode
              - action='remove': payload is constructed with settings from 'current_settings' in 'edit' mode that
                                 are not specified in 'settings_to action' plus the settings from 'settings_to_action'
                                 in 'remove' mode

    :param list current_settings: List of dictionaries with actual advanced settings configured for Nessus scanner
    :param list settings_to_action: List of dictionaries with settings to action (add/edit/remove)
    :param str action: Action to manipulate (add/edit/remove) advanced settings; Default value: edit
    :returns: Payload used to manipulate (add/edit/remove) advanced settings of a Nessus scanner
    :rtype: dict

    Example #1 (edit settings):
    >> _construct_advanced_settings_payload(settings_to_action=[{'name': 'max_scans', 'value': '1'}],
                                            current_settings=[{'name': 'max_scans', 'value': '10'},
                                                              {'name': 'max_hosts', 'value': '100'}],
                                            action='edit')
    {
        'setting.0.action': 'edit',
        'setting.0.name': 'max_scans',
        'setting.0.value': '10',
        'setting.1.action': 'edit',
        'setting.1.name': 'max_hosts',
        'setting.1.value': '100'
    }

    Example #2 (add new setting(s)):
    >> _construct_advanced_settings_payload(settings_to_action=[{'name': 'max_taks', 'value': '5'}],
                                            current_settings=[{'name': 'max_scans', 'value': '10'},
                                                              {'name': 'max_hosts', 'value': '100'}],
                                            action='add')
    {
        'setting.0.action': 'edit',
        'setting.0.name': 'max_scans',
        'setting.0.value': '10',
        'setting.1.action': 'edit',
        'setting.1.name': 'max_hosts',
        'setting.1.value': '100',
        'setting.2.action': 'add',
        'setting.2.name': 'max_tasks',
        'setting.2.value': '5',
    }

    Example #3 (remove setting(s)):
    >> _construct_advanced_settings_payload(settings_to_action=[{'name': 'max_taks', 'value': '5'}],
                                            current_settings=[{'name': 'max_scans', 'value': '10'},
                                                              {'name': 'max_hosts', 'value': '100'},
                                                              {'name': 'max_tasks', 'value': '5'}],
                                            action='remove')
    {
        'setting.0.action': 'edit',
        'setting.0.name': 'max_scans',
        'setting.0.value': '10',
        'setting.1.action': 'edit',
        'setting.1.name': 'max_hosts',
        'setting.1.value': '100',
        'setting.2.action': 'remove',
        'setting.2.name': 'max_tasks',
        'setting.2.value': '5',
    }
    """
    supported_actions = ['edit', 'add', 'remove']
    if action not in supported_actions:
        raise ValueError('Invalid action: "%s"; supported actions: "%s"' % action, ', '.join(supported_actions))
    payload = {}
    for index, setting in enumerate(current_settings):
        prefix = 'setting.' + str(index) + '.'
        payload[prefix + 'action'] = 'remove' \
            if setting['name'] in [attr['name'] for attr in settings_to_action] else 'edit'
        for key in list(setting.keys()):
            attr = prefix + key
            payload[attr] = setting[key]
    if action != 'add':
        return payload
    for index, setting in enumerate(settings_to_action):
        prefix = 'setting.' + str(len(current_settings) + index) + '.'
        payload[prefix + 'action'] = action
        for key in list(setting.keys()):
            attr = prefix + key
            payload[attr] = setting[key]
    return payload


def add_advanced_settings(settings: list, api: NessusAPI = None) -> None:
    """
    Method to add additional advanced settings to a Nessus scanner.

    Settings Example:
        [{'name': 'allow_post_scan_editing', 'value': 'yes'}, {'name': 'auto_enable_dependencies', 'value': 'yes'}]

    Usage:
        add_advanced_settings([{'name': 'my_setting_one', 'value': 'AAAATEST'}], api_inst)

    :param list settings: A list of dictionaries specifying the settings to add
    :param NessusAPI api: Nessus API instance
    :returns: None
    :rtype: None
    :raises: ValueError, in case of invalid 'action'
    """
    advanced_settings = api.settings.get_list()['preferences']
    advanced_settings_payload = _construct_advanced_settings_payload(current_settings=advanced_settings,
                                                                     settings_to_action=settings, action='add')
    api.settings.update(advanced_settings_payload)


def update_advanced_settings(settings: list, api: NessusAPI = None) -> None:
    """
    Method to update the advanced settings specified by 'settings' list

    Settings Example:
        We receive a response back as
        {'preferences': [
            {'id': '82269162c33cc8edd712dcd203857cf3', 'name': 'allow_post_scan_editing', 'value': 'yes'},
            {'id': 'cf0f93549b1bbfa0654ae39e7043624d', 'name': 'auto_enable_dependencies', 'value': 'yes'}]}

        The ``settings`` list is iterated and looks for matching setting names, if found that dictionary is updated
        with the new value.

    Usage:
        update_advanced_settings([{'name': 'allow_post_scan_editing', 'value': 'AAAATEST'}], api_inst)

    :param list settings: A list of dictionaries specifying the settings to edit
    :param NessusAPI api: Nessus API instance
    :returns: None
    :rtype: None
    :raises: ValueError, in case of invalid 'action'
    """
    advanced_settings = api.settings.get_list()['preferences']

    for setting in settings:
        for advanced_setting in advanced_settings:
            if setting['name'] == advanced_setting['name']:
                advanced_setting['value'] = setting['value']
    advanced_settings_payload = _construct_advanced_settings_payload(current_settings=advanced_settings,
                                                                     settings_to_action=[], action='edit')
    api.settings.update(advanced_settings_payload)


def delete_advanced_settings(settings: list, api: NessusAPI = None) -> None:
    """
    Method to delete the advanced settings specified by 'settings' list

    Settings Example:
        [{'name': 'allow_post_scan_editing', 'value': 'yes'}, {'name': 'auto_enable_dependencies', 'value': 'yes'}]

    Usage:
        delete_advanced_settings([{'name': 'my_setting_one', 'value': 'AAAATEST'}], api_inst)

    :param list settings: A list of dictionaries specifying the settings to edit
    :param NessusAPI api: Nessus API instance
    :returns: None
    :rtype: None
    :raises: ValueError, in case of invalid 'action'
    """
    advanced_settings = api.settings.get_list()['preferences']
    advanced_settings_payload = _construct_advanced_settings_payload(current_settings=advanced_settings,
                                                                     settings_to_action=settings, action='remove')
    api.settings.update(advanced_settings_payload)


def get_remote_file_size(file_path: str) -> int:
    """
    Returns size of specific remote file

    :param str file_path: File name
    :return: file size
    :rtype: int
    """
    with SSH() as ssh:
        return int(ssh.execute(command='ls -lS {}'.format(file_path))[0].split(' ')[4])


def get_setting_id(api: NessusAPI, setting):
    """
    Use the full list of settings (returned by API v3) to find
    the unique id for the setting that we want to edit.
    """
    settings = api.settings.get_list(version=3)
    for family in settings['settings']:
        for s in settings['settings'][family]['settings']:
            if 'setting' in s and s['setting'] == setting:
                return s['id']
    assert False, "Couldn't find setting '%s' in advanced settings" % setting


def get_current_advanced_setting_value(api: NessusAPI, setting_name: str, api_version: int = None,
                                       setting_tab: str = None) -> str:
    """
    Method to return the value of current advanced setting of Nessus.

    :param NessusAPI api: Nessus API instance
    :param str setting_name: Setting name
    :param int api_version: Nessus API version (e.g: 2 or 3)
    :param str setting_tab: Setting tab name
    :returns: Value of current advanced setting configured
    :rtype: str
    """
    advanced_settings = api.settings.get_list(version=api_version)

    setting_list = advanced_settings["settings"][setting_tab]["settings"] if api_version else \
        advanced_settings['preferences']

    setting_properties = ['default', 'setting'] if api_version else ['value', 'name']

    return [setting[setting_properties[0]] for setting in setting_list if setting[setting_properties[1]] ==
            setting_name][0]
