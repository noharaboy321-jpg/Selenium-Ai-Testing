"""
Test cases to verify nessusd commands

:copyright: Tenable Network Security, 2021
:date: Feb 09, 2021
:last_modified: Feb 09, 2021
:author: @kpanchal
"""
import os
import re

import pytest

from catium.lib.log.log import create_logger
from catium.lib.ssh.ssh import SSH
from nessus.helpers.nessuscli.encryption_pwd import set_or_remove_encryption_password
from nessus.helpers.nessuscli.helper import (
    get_nessusd,
    get_nessus_plugin_dir,
    get_command,
    start_nessus,
    stop_nessus,
)
from nessus.lib.const.constants import NessusCli, Nessus

log = create_logger()

TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), 'test_data')
INVALID_NASL_CONTENT = "THIS IS NOT VALID NASL CONTENT"


def _parse_recompile_summary(output_lines):
    """Parse the summary line from nessusd -R/-Rt output.

    Extracts plugin/library counts from output like:
        285125 plugins (279528 compiled, 1 failed to compile) loaded (273sec)
        285125 plugins and 320 independent libraries loaded (17sec)
        285126 plugins (1 compiled) and 322 independent libraries (2 compiled) loaded (14sec)

    :param list output_lines: Raw output lines from ssh.execute()
    :returns: dict with plugin_count, plugin_compiled, plugin_failed,
              lib_count, lib_compiled, lib_failed, time_sec — or None if not found
    """
    text = ' '.join(output_lines)
    match = re.search(
        r'(\d+) plugins\s*'
        r'(?:\(([^)]*)\)\s*)?'
        r'(?:and (\d+) independent libraries\s*(?:\(([^)]*)\)\s*)?)?'
        r'loaded \((\d+)sec\)',
        text
    )
    if not match:
        return None

    result = {
        'plugin_count': int(match.group(1)),
        'lib_count': int(match.group(3)) if match.group(3) else 0,
        'time_sec': int(match.group(5)),
    }

    for prefix, group_idx in [('plugin', 2), ('lib', 4)]:
        details = match.group(group_idx) or ''
        compiled = re.search(r'(\d+) compiled', details)
        failed = re.search(r'(\d+) failed to compile', details)
        result['{}_compiled'.format(prefix)] = int(compiled.group(1)) if compiled else 0
        result['{}_failed'.format(prefix)] = int(failed.group(1)) if failed else 0

    return result


@pytest.mark.parametrize('license_type', [pytest.param("Nessus Manager", marks=pytest.mark.nessus_manager),
                                          pytest.param("Nessus Professional", marks=pytest.mark.nessus_pro),
                                          pytest.param("Nessus Essential", marks=pytest.mark.nessus_home)])
class TestNessusdCommands:
    """Test cases related to 'Nessusd --help' command"""

    def test_nessusd_help_command_shows_encryption_password(self, license_type):
        """
        NES-12558: [Automation] Test case for NES-12547

        Scenario Tested:
        [x] Verify that "nessusd --help" command output is showing "--set-encryption-passwd" instead of 
            "--set-master-passwd".
        """
        with SSH() as ssh:
            nessusd_help_cmnd_output = ssh.execute(command="{} --help".format(get_nessusd()))
        log.debug("Help command output is : {}".format(nessusd_help_cmnd_output))

        command, command_description = nessusd_help_cmnd_output[11], nessusd_help_cmnd_output[12]

        for cmnd in [command, command_description]:
            assert all(["master" not in cmnd, "encryption" in cmnd]), \
                "'master' is not replaced with 'encryption' yet either in command or description."

    @pytest.mark.parametrize('keyword', ['master', 'encryption'])
    def test_set_encryption_or_master_password(self, license_type, keyword):
        """
        NES-12558: [Automation] Test case for NES-12547

        Scenario Tested:
        [x] Verify that "nessusd --help" command output is showing "--set-encryption-passwd" instead of 
            "--set-master-passwd".
        """
        random_pwd = Nessus.PASSWORD
        log.debug("Encryption/Master password that was set :: {}".format(random_pwd))

        try:
            set_result = set_or_remove_encryption_password(key_word=keyword, new_password=random_pwd,
                                                           confirm_new_pwd=random_pwd)

            assert set_result['stdout'].split('\r')[1].lstrip('\n') == NessusCli.PASSWORD_SET, \
                "Failed to set encryption/master password."
        finally:
            remove_result = set_or_remove_encryption_password(key_word=keyword, old_password=random_pwd)

            assert remove_result['stdout'].split('\r')[1].lstrip('\n') == NessusCli.PASSWORD_SET, \
                "Failed to remove encryption/master password."


@pytest.mark.nessus_cli
@pytest.mark.nessus_engine
@pytest.mark.long_running
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
class TestNessusdPluginRecompileOutput:
    """
    SCE-4405: Verify nessusd -R and -Rt output plugin compilation and error info to stdout

    Tests the full and incremental plugin recompilation commands, verifying that
    compilation counts and error information are reported correctly to stdout.
    """

    @pytest.mark.xray(test_key='SCE-4405')
    @pytest.mark.parametrize('install_custom_plugin', [{
        'filenames': ['main_with_2_libs.nasl', 'lib1.inc', 'lib2.inc'],
        'test_data_dir': 'nessus/tests/nessuscli/test_data',
        'cleanup_file': True,
        'restart': False,
    }], indirect=True)
    def test_nessusd_recompile_plugin_error_output(self, install_custom_plugin):
        """
        SCE-4405: Verify nessusd -R/-Rt outputs plugin compilation and error info

        Scenario Tested:
        [x] nessusd -R reports compiling a large number of plugins
        [x] nessusd -Rt reports no changes when no plugins are modified
        [x] nessusd -Rt reports correct count when plugins are modified
        [x] nessusd -Rt reports compilation errors for invalid plugins and libraries
        [x] nessusd -R full recompile reports errors for invalid plugins
        """
        remote_plugin_path, remote_lib1_path, remote_lib2_path = install_custom_plugin

        nessusd = get_nessusd()
        plugin_dir = get_nessus_plugin_dir()
        remove_file = get_command(operation='remove_file')
        append_to_file = get_command(operation='append_to_file')

        # --- Step 1: Stop the Nessus service ---
        stop_nessus()

        try:
            # --- Step 2: nessusd -R (full recompile) ---
            with SSH() as ssh:
                full_recompile_output = ssh.execute(
                    command=f"{nessusd} -R", sudo=True
                )
            log.info(f"nessusd -R output: {full_recompile_output}")

            summary = _parse_recompile_summary(full_recompile_output)
            assert summary is not None, \
                f"Failed to parse nessusd -R summary line. Got: {full_recompile_output}"
            assert summary['plugin_compiled'] > 1000, \
                f"nessusd -R should compile a large number of plugins. Got: {summary['plugin_compiled']} compiled"
            assert summary['plugin_failed'] == 0, \
                f"nessusd -R should have no compilation failures on clean run. Got: {summary['plugin_failed']} failed"

            # --- Step 3: nessusd -Rt (incremental, no changes) ---
            with SSH() as ssh:
                baseline_output = ssh.execute(
                    command=f"{nessusd} -Rt", sudo=True
                )
            log.info(f"nessusd -Rt baseline output: {baseline_output}")

            summary = _parse_recompile_summary(baseline_output)
            assert summary is not None, \
                f"Failed to parse nessusd -Rt summary line. Got: {baseline_output}"
            assert summary['plugin_compiled'] == 0, \
                f"nessusd -Rt baseline should compile no plugins. Got: {summary['plugin_compiled']} compiled"
            assert summary['plugin_failed'] == 0, \
                f"nessusd -Rt baseline should have no failures. Got: {summary['plugin_failed']} failed"
            assert summary['lib_compiled'] == 0, \
                f"nessusd -Rt baseline should compile no libraries. Got: {summary['lib_compiled']} compiled"

            # --- Steps 4-5: Modify one .nasl, run -Rt, verify one plugin compiled ---
            with SSH() as ssh:
                # Use find instead of glob to avoid 'Argument list too long' with 285k+ files
                nasl_files = ssh.execute(
                    command=f"find {plugin_dir} -maxdepth 1 -name '*.nasl' -type f | head -1",
                    sudo=True
                )
                assert nasl_files, \
                    f"No .nasl files found in plugin directory: {plugin_dir}"
                first_nasl = nasl_files[0].strip()
                assert first_nasl.endswith('.nasl'), \
                    f"Failed to find a .nasl file in plugin directory. Got: {nasl_files}"
                log.info(f"Modifying plugin file: {first_nasl}")

                ssh.execute(
                    command=append_to_file.format(' ', first_nasl), sudo=True
                )

            with SSH() as ssh:
                one_plugin_output = ssh.execute(
                    command=f"{nessusd} -Rt", sudo=True
                )
            log.info(f"nessusd -Rt after 1 modified plugin: {one_plugin_output}")

            summary = _parse_recompile_summary(one_plugin_output)
            assert summary is not None, \
                f"Failed to parse nessusd -Rt summary line. Got: {one_plugin_output}"
            assert summary['plugin_compiled'] >= 1, \
                "nessusd -Rt should report at least 1 plugin compiled after modification. " \
                f"Got: {summary['plugin_compiled']} compiled"

            # --- Steps 6-7: Modify two .nasl files, run -Rt, verify two plugins compiled ---
            with SSH() as ssh:
                nasl_files = ssh.execute(
                    command=f"find {plugin_dir} -maxdepth 1 -name '*.nasl' -type f | head -2",
                    sudo=True
                )
                valid_nasl_files = [f.strip() for f in nasl_files if f.strip().endswith('.nasl')]
                assert len(valid_nasl_files) >= 2, \
                    f"Failed to find 2 .nasl files in plugin directory. Got: {nasl_files}"
                for nasl_file in valid_nasl_files:
                    log.info(f"Modifying plugin file: {nasl_file}")
                    ssh.execute(
                        command=append_to_file.format(' ', nasl_file), sudo=True
                    )

            with SSH() as ssh:
                two_plugins_output = ssh.execute(
                    command=f"{nessusd} -Rt", sudo=True
                )
            log.info(f"nessusd -Rt after 2 modified plugins: {two_plugins_output}")

            summary = _parse_recompile_summary(two_plugins_output)
            assert summary is not None, \
                f"Failed to parse nessusd -Rt summary line. Got: {two_plugins_output}"
            assert summary['plugin_compiled'] >= 2, \
                "nessusd -Rt should report at least 2 plugins compiled. " \
                f"Got: {summary['plugin_compiled']} compiled"

            # --- Steps 8-9: Touch test plugin so -Rt detects a change ---
            with SSH() as ssh:
                ssh.execute(
                    command=append_to_file.format(' ', remote_plugin_path), sudo=True
                )

            with SSH() as ssh:
                custom_plugin_output = ssh.execute(
                    command=f"{nessusd} -Rt", sudo=True
                )
            log.info(f"nessusd -Rt after adding custom plugin+libs: {custom_plugin_output}")

            summary = _parse_recompile_summary(custom_plugin_output)
            assert summary is not None, \
                f"Failed to parse nessusd -Rt summary line. Got: {custom_plugin_output}"
            assert summary['plugin_compiled'] >= 1, \
                "nessusd -Rt should compile at least 1 plugin after adding test plugin. " \
                f"Got: {summary['plugin_compiled']} compiled"

            # --- Steps 10-11: Corrupt lib1.inc, run -Rt, verify error reported ---
            with SSH() as ssh:
                ssh.execute(
                    command=append_to_file.format(INVALID_NASL_CONTENT, remote_lib1_path),
                    sudo=True
                )
                log.info("Corrupted lib1.inc with invalid content")

            with SSH() as ssh:
                lib1_error_output = ssh.execute(
                    command=f"{nessusd} -Rt", sudo=True
                )
            log.info(f"nessusd -Rt after corrupting lib1.inc: {lib1_error_output}")

            summary = _parse_recompile_summary(lib1_error_output)
            assert summary is not None, \
                f"Failed to parse nessusd -Rt summary line. Got: {lib1_error_output}"
            assert summary['plugin_failed'] >= 1, \
                "nessusd -Rt should report at least 1 plugin failed to compile. " \
                f"Got: {summary['plugin_failed']} failed"
            assert summary['lib_failed'] >= 1, \
                "nessusd -Rt should report at least 1 library failed to compile. " \
                f"Got: {summary['lib_failed']} failed"

            # --- Steps 12-13: Fix lib1.inc, modify lib2.inc, run -Rt ---
            with SSH() as ssh:
                local_lib1_path = os.path.join(TEST_DATA_DIR, 'lib1.inc')
                ssh.send_file(local_lib1_path, remote_file_path=remote_lib1_path)
                log.info("Restored lib1.inc")

                ssh.execute(
                    command=append_to_file.format(' ', remote_lib2_path), sudo=True
                )
                log.info("Modified lib2.inc with whitespace")

            with SSH() as ssh:
                fix_lib1_output = ssh.execute(
                    command=f"{nessusd} -Rt", sudo=True
                )
            log.info(f"nessusd -Rt after fixing lib1, modifying lib2: {fix_lib1_output}")

            summary = _parse_recompile_summary(fix_lib1_output)
            assert summary is not None, \
                f"Failed to parse nessusd -Rt summary line. Got: {fix_lib1_output}"
            assert summary['plugin_compiled'] >= 1, \
                "nessusd -Rt should compile at least 1 plugin after lib changes. " \
                f"Got: {summary['plugin_compiled']} compiled"
            assert summary['lib_compiled'] >= 1, \
                "nessusd -Rt should compile at least 1 library after fix/modify. " \
                f"Got: {summary['lib_compiled']} compiled"

            # --- Steps 14-15: Corrupt main_with_2_libs.nasl, run -Rt ---
            with SSH() as ssh:
                ssh.execute(
                    command=append_to_file.format(INVALID_NASL_CONTENT, remote_plugin_path),
                    sudo=True
                )
                log.info("Corrupted main_with_2_libs.nasl with invalid content")

            with SSH() as ssh:
                plugin_error_output = ssh.execute(
                    command=f"{nessusd} -Rt", sudo=True
                )
            log.info(f"nessusd -Rt after corrupting plugin: {plugin_error_output}")

            summary = _parse_recompile_summary(plugin_error_output)
            assert summary is not None, \
                f"Failed to parse nessusd -Rt summary line. Got: {plugin_error_output}"
            assert summary['plugin_failed'] >= 1, \
                "nessusd -Rt should report at least 1 plugin failed to compile. " \
                f"Got: {summary['plugin_failed']} failed"

            # --- Steps 16-17: Fix main_with_2_libs.nasl, run -Rt ---
            with SSH() as ssh:
                local_plugin_path = os.path.join(TEST_DATA_DIR, 'main_with_2_libs.nasl')
                ssh.send_file(local_plugin_path, remote_file_path=remote_plugin_path)
                log.info("Restored main_with_2_libs.nasl")

            with SSH() as ssh:
                fix_plugin_output = ssh.execute(
                    command=f"{nessusd} -Rt", sudo=True
                )
            log.info(f"nessusd -Rt after fixing plugin: {fix_plugin_output}")

            summary = _parse_recompile_summary(fix_plugin_output)
            assert summary is not None, \
                f"Failed to parse nessusd -Rt summary line. Got: {fix_plugin_output}"
            assert summary['plugin_compiled'] >= 1, \
                "nessusd -Rt should compile at least 1 plugin after fix. " \
                f"Got: {summary['plugin_compiled']} compiled"

            # --- Steps 18-19: Corrupt lib1, modify lib2, remove plugin, run -Rt ---
            with SSH() as ssh:
                ssh.execute(
                    command=append_to_file.format(INVALID_NASL_CONTENT, remote_lib1_path),
                    sudo=True
                )
                ssh.execute(
                    command=append_to_file.format(' ', remote_lib2_path), sudo=True
                )
                ssh.execute(
                    command=f"{remove_file} {remote_plugin_path}", sudo=True
                )
                log.info("Corrupted lib1, modified lib2, removed main plugin")

            with SSH() as ssh:
                mixed_output = ssh.execute(
                    command=f"{nessusd} -Rt", sudo=True
                )
            log.info(f"nessusd -Rt after mixed changes: {mixed_output}")

            summary = _parse_recompile_summary(mixed_output)
            assert summary is not None, \
                f"Failed to parse nessusd -Rt summary line. Got: {mixed_output}"
            assert summary['lib_compiled'] >= 1, \
                "nessusd -Rt should report at least 1 library compiled. " \
                f"Got: {summary['lib_compiled']} compiled"
            assert summary['lib_failed'] >= 1, \
                "nessusd -Rt should report at least 1 library failed to compile. " \
                f"Got: {summary['lib_failed']} failed"

            # --- Steps 20-21: Restore invalid plugin, run nessusd -R (full) ---
            with SSH() as ssh:
                local_plugin_path = os.path.join(TEST_DATA_DIR, 'main_with_2_libs.nasl')
                ssh.send_file(local_plugin_path, remote_file_path=remote_plugin_path)
                ssh.execute(
                    command=append_to_file.format(INVALID_NASL_CONTENT, remote_plugin_path),
                    sudo=True
                )
                log.info("Restored main_with_2_libs.nasl with invalid content appended")

            with SSH() as ssh:
                full_recompile_error_output = ssh.execute(
                    command=f"{nessusd} -R", sudo=True
                )
            log.info(f"nessusd -R with invalid plugin: {full_recompile_error_output}")

            summary = _parse_recompile_summary(full_recompile_error_output)
            assert summary is not None, \
                f"Failed to parse nessusd -R summary line. Got: {full_recompile_error_output}"
            assert summary['plugin_compiled'] > 1000, \
                "nessusd -R should compile a large number of plugins. " \
                f"Got: {summary['plugin_compiled']} compiled"
            assert summary['plugin_failed'] >= 1, \
                "nessusd -R should report at least 1 plugin failed to compile. " \
                f"Got: {summary['plugin_failed']} failed"

        finally:
            # Restart the Nessus service that was stopped in Step 1
            # (fixture handles cleanup of test files)
            try:
                start_nessus()
                log.info("Restarted Nessus service")
            except Exception as e:
                log.warning(f"Failed to restart Nessus service during cleanup: {e}")
