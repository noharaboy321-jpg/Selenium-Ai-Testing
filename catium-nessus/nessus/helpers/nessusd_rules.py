"""
Nessus rules file related helper functions

:copyright: Tenable Network Security, 2022
:date: September 6, 2022
:modified: September 6, 2022
:author: @stellex
"""
from catium.lib.log.log import create_logger
from catium.lib.ssh import SSH

from nessus.helpers.nessuscli.helper import get_command, get_nessus_conf_dir, path_join

log = create_logger()
conf_dir = get_nessus_conf_dir()


def create_nessusd_rules_file():
    create_directory = get_command(operation='create_directory')
    create_file = get_command(operation='create_file')
    with SSH() as ssh:
        conf_dir_output = ssh.execute(create_directory.format(conf_dir))
        log.info("Create conf directory output: " + str(conf_dir_output))
        rules_file_output = ssh.execute(create_file.format(path_join([conf_dir, 'nessusd.rules'])))
        log.info("Create rules file output: " + str(rules_file_output))
        chmod_output = ssh.execute(f"chmod 755 " + path_join([conf_dir, 'nessusd.rules']), sudo=True)
        log.info("Chmod output: " + str(chmod_output))


def remove_nessusd_rules_file():
    remove_file = get_command(operation='remove_file')
    with SSH() as ssh:
        remove_file_output = ssh.execute(f"""{remove_file} {path_join(path_dir_list=[conf_dir, "nessusd.rules"])}""")
        log.info("Remove file output: " + str(remove_file_output))


def replace_nessusd_rules_file(content):
    remove_nessusd_rules_file()
    create_nessusd_rules_file()
    update_nessusd_rules_file(content=content)


def update_nessusd_rules_file(content):
    append_to_file = get_command(operation='append_to_file')
    rules_file_path = path_join(path_dir_list=[conf_dir, "nessusd.rules"])
    with SSH() as ssh:
        append_to_file_output = ssh.execute(append_to_file.format(content, rules_file_path), sudo=True)
        log.info("Append to file output: " + str(append_to_file_output))
