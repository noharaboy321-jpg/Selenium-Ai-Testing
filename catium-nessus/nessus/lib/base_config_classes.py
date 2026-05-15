"""
    :copyright: Tenable Network Security, 2019
    :date: Oct 19, 2019
    :author: @mjuuti
"""
from nessus.helpers.dockernessus.lib.general import build_target_list
from nessus.lib.config import docker_config


class BaseDockerConfig(object):
    """Base configuration for Docker related tests and fixtures."""

    # Agent specific
    agent_db = docker_config.AGENT_DB
    agent_group = docker_config.AGENT_CONFIG["groups"]
    controller_host = docker_config.CONTROLLER_CONFIG["host"]
    controller_port = docker_config.CONTROLLER_CONFIG["port"]
    controller_url = docker_config.CONTROLLER_URL
    controller_api = None
    container_details = None
    override_user = None
    override_pass = None

    # Docker settings
    docker_host = docker_config.DOCKER_HOST
    expose_port = docker_config.AGENT_CONFIG["expose_port"]
    tag = docker_config.DOCKER_TAG
    full_image_name = None
    image_name = None
    test_name = None
    cid = None

    # Inspected during test:
    controller_type = "manager"
    fetch_key = False
    linked = False
    linking_key = None
    log_whole_attack = docker_config.LOG_WHOLE_ATTACK
    nessus_mode = "scanner"
    wait_for_plugin_loading = False
    use_proxy = False

    # General
    debug = docker_config.DEBUG
    nessus_username = docker_config.SCANNER_CONFIG["admin_user"]
    nessus_password = docker_config.SCANNER_CONFIG["admin_pass"]


class ScannerBaseConfig(BaseDockerConfig):
    """Settings specific to Docker Scanners."""
    nessus_mode = "scanner"
    upgrade_build = docker_config.SCANNER_CONFIG["upgrade_build"]

    # Scanner info
    nessus_ui_build = None
    nessus_ui_version = None
    platform = None
    scanner_boottime = None
    scanner_api = None
    scanner_url = docker_config.SCANNER_URL
    server_build = None
    server_version = None
    scanner_name = None
    linking_details = None

    # Scanner prefs
    auto_update = docker_config.AUTO_UPDATE
    no_user_mode = docker_config.NO_USER
    update_plugins = docker_config.UPDATE_PLUGINS

    no_root_mode = docker_config.NO_ROOT
    nessus_user = docker_config.NESSUS_USER
    nessus_group = docker_config.NESSUS_GROUP

    # Plugin prefs
    plugin_dev_branch = docker_config.PLUGIN_DEV_BRANCH
    plugin_set = None
    plugin_server = docker_config.PRODUCTION_PLUGIN_SERVER
    plugin_server_api = docker_config.PRODUCTION_PLUGIN_SERVER_API

    # Targets
    qa_bot_linux_targets = build_target_list(docker_config.QA_BOT_LINUX_TARGETS)
    qa_bot_windows_targets = build_target_list(docker_config.QA_BOT_WINDOWS_TARGETS)
    aix_targets = build_target_list(docker_config.AIX_TARGETS)
    cisco_targets = build_target_list(docker_config.CISCO_TARGETS)
    hpux_targets = build_target_list(docker_config.HPUX_TARGETS)
    juniper_targets = build_target_list(docker_config.JUNIPER_TARGETS)
    solaris_targets = build_target_list(docker_config.SOLARIS_TARGETS)
