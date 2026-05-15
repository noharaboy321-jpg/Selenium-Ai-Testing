@Library('tenable.common')
import com.tenable.jenkins.*
import com.tenable.jenkins.builds.*
import com.tenable.jenkins.Constants
import com.tenable.jenkins.common.Common

def runNessusSmoke (String targetOS, String nessusBuildBranch, String catiumBranch, String markers = "None", String nessusPackage = "None") {

    Common common = new Common(this)

    List ignoredItems = ["nessus/tests/api/zzz_nessusd/test_verify_nessusd_dump.py", "nessus/tests/nessuscli/test_verify_nessusd_dump.py"]
    List testFolder = ['nessuscli', 'ui', 'api']
    boolean nessusHome = true
    boolean nessusPro = true
    boolean nessusManager = true
    boolean nessusExpert = true
    Integer instanceCount = 3
    String markersString = "not real_agent"
    if (markers != "None") {
        markers = markers + " and " + markersString
    }

    def nessusTests

    node(Constants.DOCKERNODE) {
        BuildsCommon buildsCommon = new BuildsCommon(this)
        buildsCommon.cleanup()
        checkout scm
        def rootDir = pwd()
        echo "Root directory is: ${rootDir}"
        nessusTests = load "${rootDir}/pipelines/runTests.groovy"
    }

    nessusTests.runTests(targetOS, nessusBuildBranch, catiumBranch, testFolder, nessusHome, nessusPro, nessusManager, nessusExpert, instanceCount, markers, ignoredItems, nessusPackage)
}

return this
