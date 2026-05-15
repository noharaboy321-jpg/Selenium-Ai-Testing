"""
:copyright: Tenable Network Security, 2017
:date: September 12, 2017
:author: @pellsworth
"""

from nessus.helpers.cli_command import execute
from nessus.helpers.nessuscli.helper import get_nessus_cli


def generate_quiet() -> dict:
    return execute(get_nessus_cli(), ['bug-report-generator', '--quiet', '--full', '--scrub'])
