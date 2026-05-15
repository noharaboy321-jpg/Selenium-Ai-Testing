"""
Helper functions for updating templates
"""

import json
import os
from json import JSONDecodeError

from catium.lib.log import create_logger
from nessus.helpers.cli_command import execute, upload
from nessus.helpers.nessuscli.helper import get_nessus_plugin_dir, get_nessus_template_dir
from nessus.helpers.nessuscli.helper import stop_nessus, start_nessus
from nessus.lib.config.environment_variables import NESSUS_PLATFORM
from nessus.lib.const import OperatingSystems

NESSUS_TEMPLATES_DIR = get_nessus_template_dir()
NESSUS_TMP_TEMPLATES_DIR = os.path.join(get_nessus_template_dir(), "tmp")
NESSUS_PLUGINS_DIR = get_nessus_plugin_dir()
TEMPLATES_COPY_DIR = '/tmp/templates-copy'
TEMPLATES_ORIG_DIR = '/tmp/templates-orig'

log = create_logger()


def create_templates_backup():
    """Make a safe copy of the templates before we modify them"""
    execute('rm', ['-rf', TEMPLATES_ORIG_DIR])
    execute('cp', ['-a', NESSUS_TEMPLATES_DIR, TEMPLATES_ORIG_DIR])


def restore_templates_backup():
    """Restore the safe copy of the templates after we modify them"""
    files = execute('ls', [TEMPLATES_ORIG_DIR])['stdout'].split('\n')
    files = filter(lambda f: f.endswith('.json'), files)
    for file in files:
        execute('cp', ['%s/%s' % (TEMPLATES_ORIG_DIR, file), NESSUS_TEMPLATES_DIR])


def prep_templates_update(metadata: dict = None, mask_files: list = []):
    """Set up a template updates, updating version etc as necessary"""
    execute('rm', ['-rf', TEMPLATES_COPY_DIR])
    execute('cp', ['-a', TEMPLATES_ORIG_DIR, TEMPLATES_COPY_DIR])

    for file in mask_files:
        execute('rm', ['-f', '%s/%s' % (TEMPLATES_COPY_DIR, file)])

    if metadata:
        with open('/tmp/metadata.json.rewrite', 'wt') as file:
            file.write(json.dumps(metadata))

        template_dir = TEMPLATES_COPY_DIR + "/" if NESSUS_PLATFORM not in [OperatingSystems.MAC,
                                                                           OperatingSystems.MAC_OS] else ""

        upload('/tmp/metadata.json.rewrite', template_dir + 'metadata.json')

        if NESSUS_PLATFORM == OperatingSystems.MAC_OS:
            execute('cp', ["metadata.json", TEMPLATES_COPY_DIR + '/metadata.json'])


def fill_tmp_templates_dir():
    """Put an identical copy of templates in templates/tmp to test overwrite scenarios"""
    files = execute('ls', [NESSUS_TEMPLATES_DIR])['stdout'].split('\n')
    files = filter(lambda f: f.endswith('.json'), files)
    for file in files:
        execute('cp', ['%s/%s' % (NESSUS_TEMPLATES_DIR, file), NESSUS_TMP_TEMPLATES_DIR])


def update_templates():
    """Put the prepped files into the plugins feed and trigger an update"""
    files = execute('ls', [TEMPLATES_COPY_DIR])['stdout'].split('\n')
    files = filter(lambda f: f.endswith('.json'), files)

    for file in files:
        execute('cp', ['%s/%s' % (TEMPLATES_COPY_DIR, file), '%s/%s.new' % (NESSUS_PLUGINS_DIR, file)])

    stop_nessus()
    start_nessus()


def get_template_metadata():
    metadata = execute('cat', [NESSUS_TEMPLATES_DIR + '/metadata.json'])['stdout']
    try:
        return json.loads(metadata)
    except JSONDecodeError:
        log.debug('Tried to decode content: %s', metadata)
        raise


def get_tmp_template_metadata():
    metadata = execute('cat', [NESSUS_TMP_TEMPLATES_DIR + '/metadata.json'])['stdout']
    return json.loads(metadata)
