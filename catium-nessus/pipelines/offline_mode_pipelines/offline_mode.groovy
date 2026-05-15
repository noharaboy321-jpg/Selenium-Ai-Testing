@Library('tenable.common')
import com.tenable.jenkins.*
import com.tenable.jenkins.builds.*
import com.tenable.jenkins.Constants
import com.tenable.jenkins.common.Common

def runOfflineMode (String targetOS, String nessusBuildBranch, String catiumBranch, String markers = "None", String nessusPackage = "None", String nessusDebugInfo = "None") {

    Common common = new Common(this)

    List testFolder = ['ui/offline_mode']
    boolean nessusHome = false
    boolean nessusPro = true
    boolean nessusManager = true
    boolean nessusExpert = true
    boolean offlineMode = true
    String leakCheckLevel = "Off"
    Integer instanceCount = 3
    String markersString = "not real_agent"
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

    nessusTests.runTests(targetOS, nessusBuildBranch, catiumBranch, testFolder, nessusHome, nessusPro, nessusManager, nessusExpert, instanceCount, markersString, [], nessusPackage, nessusDebugInfo, leakCheckLevel, false, offlineMode)
}

return this
