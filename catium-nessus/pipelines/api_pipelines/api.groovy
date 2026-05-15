@Library('tenable.common')
import com.tenable.jenkins.*
import com.tenable.jenkins.builds.*
import com.tenable.jenkins.Constants
import com.tenable.jenkins.common.Common

def runApi(String targetOS, String nessusBuildBranch, String catiumBranch, String markers = "None", String nessusPackage = "None") {

    Common common = new Common(this)

    List testFolder = ['api']
    boolean nessusHome = true
    boolean nessusPro = true
    boolean nessusManager = true
    boolean nessusExpert = true
    Integer instanceCount = 4
    String markersString = "not license_change, not flaky_test, not docker, not skip_pro_scan_api_disabled, not skip_nessustc"
    if (markers != "None") {
        markersString = markers + " and " + markersString
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

    nessusTests.runTests(targetOS, nessusBuildBranch, catiumBranch, testFolder, nessusHome, nessusPro, nessusManager, nessusExpert, instanceCount, markersString, [], nessusPackage)
}

return this