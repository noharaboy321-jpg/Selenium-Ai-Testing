"""
Nessus recast severity Helpers

Copyright: Tenable Network Security, 2017
Creation Date: Nov 20, 2017
:author jamreliya
"""


def plugin_rule_to_recast_mapper(severity: str) -> int:
    """
    Maps a plugin rule severity to the corresponding integer value.
    """
    mapper = {
        'recast_info': 0,
        'recast_low': 1,
        'recast_medium': 2,
        'recast_high': 3,
        'recast_critical': 4}
    return mapper.get(severity, -1)
