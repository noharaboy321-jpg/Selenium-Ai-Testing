"""
Nessus helpers for DB functions
:copyright: Tenable Network Security, 2022
:date: July 29, 2022
:last_modified: July 29, 2022
:author: @stellex
"""
import platform
import sqlite3

from nessus.helpers.cli_command import execute
from nessus.helpers.nessuscli.helper import get_nessus_var_dir, path_join
from nessus.lib.config import NessusConfig

system_os = platform.system()


class ScanDB:
    def __init__(self, db_path, decrypt: bool = True, connect: bool = True):
        self.db_path = db_path
        if decrypt:
            self.decrypt_db()
        if connect:
            self.connect_db()
        else:
            self.db_connection = None
            self.cursor = None
        self.loaded_query = None
        self.result = None

    def connect_db(self):
        self.db_connection = sqlite3.connect(database=self.db_path)
        self.cursor = self.db_connection.cursor()

    def decrypt_db(self, output_file_path: str = None, decrypt_file_path: str = "./scripts/db/", key: str = 'sapphire',
                   master_key: bool = False, execute_locally: bool = True):
        """
        Decrypts a Nessus db. Generally used in conjunction with the export/download APIs
        :param decrypt_file_path: Location of the decrypt file on the system doing the decrypting
        :param key: Value of the key used to decrypt the db. Overridden if master_key is set to True
        :param master_key: Boolean to indicate whether to use the Nessus master key instead of a specified key
        :param output_file_path: String path of the output file, including the output directory
        :param execute_locally: Boolean to determine whether execute this locally on the machine running the test, or
        remotely on the machine running Nessus
        :return: Does not return anything, the file will be output at the location by the command.
        """

        if output_file_path is None:
            if self.db_path[-3:] == ".db":
                output_file_path = self.db_path[:-3]
            else:
                output_file_path = self.db_path
            output_file_path += ".plain.db"

        if "nessusdbDecrypt" not in decrypt_file_path:
            if execute_locally:
                platform = system_os.lower()
            else:
                platform = NessusConfig.CAT_NESSUS_PLATFORM
            decrypt_file_path = path_join([decrypt_file_path, f"nessusdbDecrypt_{platform}_amd64"])
        if system_os == 'Windows':
            decrypt_file_path += '.exe'

        directory = execute(command="pwd", args=[], execute_locally=execute_locally)
        output = execute(command="chmod", args=['0755', decrypt_file_path], execute_locally=execute_locally, sudo=True)
        if master_key:
            var_directory = get_nessus_var_dir()
            args = ['-masterkey', path_join([var_directory, "master.key"])]
        else:
            args = ['-key', key]

        args.extend(['-o', output_file_path, self.db_path])
        output = execute(command=decrypt_file_path, args=args, execute_locally=execute_locally, sudo=True)

        self.db_path = output_file_path

    def execute_query(self):
        self.result = []
        for row in self.cursor.execute(self.loaded_query):
            self.result.append(row)

    def load_scan_result_by_plugin_query(self, plugin_id):
        self.loaded_query = f"""select Host.hostname, Ports.port, Ports.protocol, Plugins.id, Plugins.plugin_name,
            PluginOutput.plugin_output from ScanResults
            join Host on Host.id = ScanResults.host_id
            join Ports on Ports.id = ScanResults.port_id
            join Plugins on Plugins.id = ScanResults.plugin_id
            join PluginOutput on PluginOutput.id = ScanResults.output_id
            where Plugins.id=={plugin_id}"""

    def load_scan_errors(self):
        self.loaded_query = f"""select * from ScanErrors"""

    def load_custom_query(self, query):
        self.loaded_query = query
        
