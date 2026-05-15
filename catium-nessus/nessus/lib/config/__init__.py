"""
    :date: Apr 26, 2017
    :author: @cdombrowski
"""
# Modified from the catium -> lib -> config -> __init__.py file created by @mjuuti.
# pylint: disable=unused-wildcard-import, wildcard-import

from catium.lib.config import Config
from .environment_variables import NessusEnvironmentConfig


class NessusConfig(Config, NessusEnvironmentConfig):
    """Nessus configuration values holder"""
    pass
