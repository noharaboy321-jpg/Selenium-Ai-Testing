"""
    Fixtures for interacting with the file system

    :copyright: Tenable Network Security, 2017
    :date: Aug 10 2022
    :author: @stellex
"""
import os
import shutil
from typing import TYPE_CHECKING

import pytest

from catium.helpers.testdata import get_file_path
from catium.lib.log import create_logger
from catium.lib.ssh import SSH
from nessus.helpers.cli_command import execute

from nessus.helpers.scanner import restart_scanner

from nessus.helpers.nessuscli.helper import get_nessus_plugin_dir, path_join, get_command, stop_nessus, start_nessus, \
    get_os_name
from nessus.lib.const import OperatingSystems

if TYPE_CHECKING:
    from catium.lib.typechecking import SubRequest

log = create_logger()


FOLDER_MAPPING = {
    "test_files": "test_files",
    "pluginsets/custom": "pluginsets_custom",
}


def _get_local_test_file_path(file_name: str, source_folder: str) -> str:
    """
    Get the absolute path to a test file stored in the repository.

    :param file_name: Name of the file
    :param source_folder: Source folder name (will be mapped to local folder)
    :return: Absolute path to the local test file
    :raises FileNotFoundError: If the test file does not exist at the expected path
    """
    local_folder = FOLDER_MAPPING.get(source_folder, "test_files")
    relative_path = os.path.join(
        "nessus/tests", "plugins/test_data", local_folder, file_name
    )
    absolute_path = get_file_path(relative_path)

    if not os.path.exists(absolute_path):
        raise FileNotFoundError(
            f"Test file not found: {absolute_path}. "
            f"Ensure the file '{file_name}' exists in the repository under "
            f"nessus/tests/plugins/test_data/{local_folder}/"
        )

    return absolute_path


@pytest.fixture()
def add_test_file(request: 'SubRequest'):
    """
    Adds a test file to a given location. Files are stored in the repository under
    {LocalTestFiles.BASE_PATH}/{LocalTestFiles.PLUGINS_TEST_DATA}/ and copied to the 
    target system at runtime.
    
    Optionally cleans up the file after running. Provide a dict in the request with:
    - file_path: Target path where file should be placed
    - file_name: Name of the file to copy
    - cleanup_file: Boolean indicating whether to clean up after test (default: True)
    - source_folder: Source folder name (default: 'test_files')
    - execute_locally: If True, copy to local filesystem; if False, copy to remote via SSH (default: False)
    """
    file_data = request.param if type(request.param) is list else [request.param]

    downloaded_file_path = []

    for file in file_data:
        file_path = file['file_path']
        file_name = file["file_name"]
        cleanup_file = file.get('cleanup_file', True)
        source_folder = file.get('source_folder', "test_files")
        execute_locally = file.get('execute_locally', False)

        # Handle file_name as either a string or a list of strings
        file_names = file_name if isinstance(file_name, list) else [file_name]

        for name in file_names:
            current_download_file_path = path_join(path_dir_list=[file_path, name])

            # Get local source file path from repository
            local_source_path = _get_local_test_file_path(name, source_folder)
            log.debug(f"Source file path: {local_source_path}")
            log.debug(f"Target file path: {current_download_file_path}")

            if execute_locally:
                # Copy file locally
                os.makedirs(os.path.dirname(current_download_file_path), exist_ok=True)
                shutil.copy2(local_source_path, current_download_file_path)
                os.chmod(current_download_file_path, 0o755)
                log.debug(f"Copied {local_source_path} to {current_download_file_path}")
                downloaded_file_path.append(current_download_file_path)
            else:
                # Copy file to remote system via SSH
                with SSH() as ssh:
                    # Ensure target directory exists on remote
                    ssh.execute(f"mkdir -p {file_path}")
                    # Transfer file from local repo to remote system
                    ssh.send_file(local_source_path, remote_file_path=current_download_file_path)
                    chmod_output = ssh.execute(f"chmod 755 {current_download_file_path}")
                    log.debug(chmod_output)
                downloaded_file_path.append(current_download_file_path)

    yield downloaded_file_path if len(downloaded_file_path) > 1 else downloaded_file_path[0]

    if cleanup_file:
        remove_file = get_command('remove_file')

        with SSH() as ssh:
            for file in downloaded_file_path:
                output = ssh.execute(f"{remove_file} {file}")
                log.debug(output)


@pytest.fixture()
def copy_file(request: 'SubRequest'):
    """
    Copies a given file on the remote system. Can optionally clean up the file by deleting the original and renaming the
    copied file.
    """
    file_path = request.param['file_path']
    copied_file_name = request.param['copy_name'] if 'copy_name' in request.param.keys() else file_path + ".bak"
    cleanup_file = request.param['cleanup_file'] if 'cleanup_file' in request.param.keys() else False

    with SSH() as ssh:
        copy_command = get_command("copy_file").format(file_path, copied_file_name)
        ssh.execute(command=copy_command)

    yield {"copied_file_name": copied_file_name, "original_file_name": file_path}

    if cleanup_file:
        remove_command = get_command("remove_file") + " " + file_path
        ssh.execute(remove_command)
        rename_command = get_command("rename_file").format(copied_file_name, file_path)
        ssh.execute(rename_command)
        remove_command = get_command("remove_file") + " " + copied_file_name
        ssh.execute(remove_command)


@pytest.fixture()
def rename_file(request: 'SubRequest'):
    """
    Renames a given file on the remote system. Can optionally clean up the file by renaming it back to the original name.
    Provide a dict to the request with the file pat h as file_path, the old file name as old_file, the new file name as
    new_file, and a boolean indicating whether to clean up the file or notas cleanup_file.
    """
    file_path = request.param['file_path']
    old_file = path_join([file_path, request.param['old_file_name']])
    old_file = old_file if get_os_name() != OperatingSystems.WINDOWS else old_file.replace("\\", "\\\\")
    new_file = path_join([file_path, request.param['new_file_name']])
    new_file = new_file if get_os_name() != OperatingSystems.WINDOWS else new_file.replace("\\", "\\\\")
    cleanup_file = request.param['cleanup_file']
    restart = request.param['restart'] if 'restart' in request.param.keys() else False

    with SSH() as ssh:
        rename_command = get_command('rename_file').format(old_file, new_file)
        sudo = False if get_os_name() in [OperatingSystems.WINDOWS, OperatingSystems.FREEBSD] else True
        output = ssh.execute(command=rename_command, sudo=sudo)
        log.info(output)

    yield

    if cleanup_file:
        with SSH() as ssh:
            rename_command = get_command('rename_file').format(new_file, old_file)
            ssh.execute(command=rename_command, sudo=sudo)

        if restart:
            stop_nessus()
            start_nessus()
