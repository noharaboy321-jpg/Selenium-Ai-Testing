"""
:copyright: Tenable Network Security, 2017
:date: September 7, 2017
:author:
"""

from nessus.helpers.cli_command import execute
from nessus.helpers.nessuscli.helper import get_nessus_cli


def list() -> dict:
    """ Run 'nessuscli scan list' command """
    return execute(get_nessus_cli(), ['scans', 'list'])


def launch(scan_id: int) -> dict:
    """ Run 'nessuscli scan launch [scan_id]' command """
    args = ['scans', 'launch', str(scan_id)]
    return execute(command=get_nessus_cli(), args=args)


def export(scan_id: int) -> dict:
    """ Run 'nessuscli scan export [scan_id] --format=csv' command """
    args = ['scans', 'export', str(scan_id), '--format=csv']
    return execute(command=get_nessus_cli(), args=args)
