@Library('tenable.common')
import com.tenable.jenkins.*
import com.tenable.jenkins.builds.*
import com.tenable.jenkins.Constants
import com.tenable.jenkins.common.Common

def runUIAgents (String targetOS, String nessusBuildBranch, String catiumBranch) {

    Common common = new Common(this)

    List testFolder = ['ui/agents', 'ui/cluster']
    boolean nessusHome = false
    boolean nessusPro = false
    boolean nessusManager = true
    boolean nessusExpert = false
    Integer instanceCount = 3
    String markers = "not real_agent and not standalone and not update and not license_change and not browser_file_download"

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
