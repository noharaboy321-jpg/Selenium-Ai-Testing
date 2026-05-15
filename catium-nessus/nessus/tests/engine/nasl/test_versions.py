"""
Nasl dump versions

:copyright: Tenable Network Security, 2017
:date: September 7th, 2017
:author: @mkeeler
"""
import pytest
from nessus.helpers.cli_command import execute
from nessus.lib.config import environment_variables as nessus_config


@pytest.mark.nessus_nasl
class TestNaslVersions:
    """ Test nasl -m commands """

    @pytest.mark.skipif(not nessus_config.NESSUS_DEBUG_TESTS,
                        reason='nasl version test requires the NESSUS_DEBUG_TESTS env var to be set')
    def test_nasl_versions(self):
        find_str = '\n'.join(('----------------------------------------------------------------------',
                              '',
                              'Library Versions:',
                              '----------------------------------------------------------------------',
                              'expat: expat_2.1.1',
                              'libBZIP2: 1.0.6, 6-Sept-2010',
                              'libJPEG: 8d  15-Jan-2012',
                              'libPCAP: 2.4',
                              'libPCRE: 7.8',
                              'libXML2: 2.9.4',
                              'libXMLSEC: 1.2.18',
                              'libXSLT: 1.1.27',
                              'OpenSSL: OpenSSL 1.0.2k  26 Jan 2017',
                              'SQLite (with ZIPVFS and SEE): 3.8.10.1',
                              'ZLib: 1.2.8',
                              'Snappy (modified for Nessus): 1.1.2', ''))

        output = execute(nessus_config.NASL_EXE, ['-m'])
        assert output['rc'] == 0
        assert not output['stderr']

        out = output['stdout']
        assert output['stdout'].endswith(find_str)
