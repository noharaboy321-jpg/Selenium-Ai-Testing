"""
Functions related to using custom plugins, and dynamically creating new ones

:copyright: Tenable Network Security, 2023
:date: August 17, 2023
:author: @stellex
"""

from catium.lib.log.log import create_logger
from catium.lib.ssh import SSH
from nessus.helpers.nessuscli.helper import get_nessus_plugin_dir, get_command, path_join, stop_nessus, start_nessus

log = create_logger()


class Plugin:
    def __init__(self, filename, name: str, script_id: int, plugin_family: str = None,
                 plugin_directory: str = None, script_version: str = None,
                 summary: str = None, synopsis: str = None, description: str = None,
                 see_also: str = None, solution: str = None, cvss_vector: str = None,
                 publication_date: str = None, modification_date: str = None, plugin_type: str = None,
                 agent: str = None, category: str = None, plugin_copyright: str = None, url_or_ip=None):
        if ".nasl" not in filename:
            raise ValueError("Filename value must end in .nasl to be compiled into a plugin")
        self.filename = filename
        self.name = name
        self.plugin_family = plugin_family if plugin_family is not None else "Fake Plugins"
        self.plugin_directory = plugin_directory if plugin_directory is not None else get_nessus_plugin_dir()
        self.script_id = script_id
        self.script_version = script_version if script_version is not None else "1.0"
        self.summary = summary if summary is not None else "Plugin summary"
        self.synopsis = synopsis if synopsis is not None else "Plugin synopsis"
        self.description = description if description is not None else "Plugin description"
        self.see_also = see_also if see_also is not None else "Plugin see_also"
        self.solution = solution if solution is not None else "Plugin solution"
        self.cvss_vector = cvss_vector if cvss_vector is not None else "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
        self.publication_date = publication_date if publication_date is not None else "2022/02/20"
        self.modification_date = modification_date if modification_date is not None else "2022/02/20"
        self.plugin_type = plugin_type
        self.agent = agent
        self.category = category if category is not None else "ACT_GATHER_INFO"
        self.plugin_copyright = plugin_copyright if plugin_copyright is not None else "This script is a test plugin used by automation"
        self.url_or_ip = url_or_ip

        self.filepath = path_join(path_dir_list=[self.plugin_directory, self.filename])
        self.create_raw_plugin_file(url_or_ip=self.url_or_ip)
        self.add_line_output = []

    def create_raw_plugin_file(self, url_or_ip=None):
        with SSH(url_or_ip=self.url_or_ip) as ssh:
            create_file_command = get_command("create_file").format(self.filepath)
            ssh.execute(command=create_file_command, sudo=True)
            default_plugin_file = [
                "if (description)",
                "{",
                f"script_id({self.script_id});",
                f'script_version(\\"{self.script_version}\\");',
                f'script_name(english:\\"{self.name}\\");',
                f'script_summary(english:\\"{self.summary}\\");',
                f'script_set_attribute(attribute:\\"synopsis\\", value: \\"{self.synopsis}\\");',
                f'script_set_attribute(attribute:\\"description\\", value: \\"{self.description}\\");',
                f'script_set_attribute(attribute:\\"see_also\\", value: \\"{self.see_also}\\");',
                f'script_set_attribute(attribute:\\"solution\\", value: \\"{self.solution}\\");',
                f'script_set_attribute(attribute:\\"cvss_vector\\", value: \\"{self.cvss_vector}\\");',
                f'script_set_attribute(attribute:\\"plugin_publication_date\\", value: \\"{self.publication_date}\\");',
                f'script_set_attribute(attribute:\\"plugin_modification_date\\", value: \\"{self.modification_date}\\");'
            ]

            if self.plugin_type is not None:
                default_plugin_file.append(f'script_set_attribute(attribute:\\"plugin_type\\", value: \\"{self.plugin_type}\\");')
            if self.agent is not None:
                default_plugin_file.append(f'script_set_attribute(attribute:\\"agent\\", value: \\"{self.agent}\\");')

            default_plugin_file.extend(
                [
                f'script_end_attributes();',
                f'script_category({self.category});',
                f'script_family(english:\\"{self.plugin_family}\\");',
                f'script_copyright(english:\\"{self.plugin_copyright}\\");',
                'exit(0);',
                "}"
                ]
            )

            self.add_lines_to_plugin_file(lines=default_plugin_file)
            ssh.disconnect()

    def add_lines_to_plugin_file(self, lines: list):
        self.add_line_output = []
        with SSH(url_or_ip=self.url_or_ip) as ssh:
            append_to_file_command = get_command("append_to_file")
            for line in lines:
                self.add_line_output.append(ssh.execute(command=append_to_file_command.format(line, path_join([self.plugin_directory, self.filename])), sudo=True))
            ssh.disconnect()

    def compile_plugin(self):
        remove_file = get_command(operation='remove_file')
        with SSH(url_or_ip=self.url_or_ip) as ssh:
            compile_output = ssh.execute(f"""{remove_file} {path_join(path_dir_list=[self.plugin_directory, "plugin_feed_info.inc"])}""", sudo=True)
            ssh.disconnect()

        stop_nessus()
        start_nessus()
