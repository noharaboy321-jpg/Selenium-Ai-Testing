@Library('tenable.common')
import com.tenable.jenkins.*
import com.tenable.jenkins.builds.*
import com.tenable.jenkins.Constants
import com.tenable.jenkins.common.Common

def runUISettings (String targetOS, String nessusBuildBranch, String catiumBranch, String markers = "None") {

    Common common = new Common(this)

    List testFolder = ['ui']

    boolean nessusHome = true
    boolean nessusPro = true
    boolean nessusManager = true
    boolean nessusExpert = true
    Integer instanceCount = 3
    String markersString = "not standalone and not update and not license_change and not browser_file_download"
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

    nessusTests.runTests(targetOS, nessusBuildBranch, catiumBranch, testFolder, nessusHome, nessusPro, nessusManager, nessusExpert, instanceCount, markersString)
}

return this
