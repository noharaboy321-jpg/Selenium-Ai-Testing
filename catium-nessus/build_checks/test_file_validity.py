"""
The buildcheck from automation-configuration repo have been moved to a python package(catium-buildchecks).
Since the files in the buildchecks package cannot be executed as pytest, this module acts as a proxy and imports the file to the catium project so that the buildchecks could be executed.
"""
from buildchecks.test_file_validity import *