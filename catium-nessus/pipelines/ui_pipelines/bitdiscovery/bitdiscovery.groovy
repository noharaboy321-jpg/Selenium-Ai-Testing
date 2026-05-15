@Library('tenable.common')
import com.tenable.jenkins.*
import com.tenable.jenkins.builds.*
import com.tenable.jenkins.Constants
import com.tenable.jenkins.common.Common

def runUIBitdiscovery (String targetOS, String nessusBuildBranch, String catiumBranch) {

    Common common = new Common(this)

    List testFolder = ['ui/expert', 'ui/scans/test_asd_scans.py']
    boolean nessusHome = false
    boolean nessusPro = false
    boolean nessusManager = false
    boolean nessusExpert = true
    Integer instanceCount = 3
    String markers = "no_markers"

    def nessusTests

    node(Constants.DOCKERNODE) {
        BuildsCommon buildsCommon = new BuildsCommon(this)
        buildsCommon.cleanup()
        checkout scm
        def rootDir = pwd()
        echo "Root directory is: ${rootDir}"
        nessusTests = load "${rootDir}/pipelines/runTests.groovy"
    }

    nessusTests.runTests(targetOS, nessusBuildBranch, catiumBranch, testFolder, nessusHome, nessusPro, nessusManager, nessusExpert, instanceCount, markers)
}

return this
