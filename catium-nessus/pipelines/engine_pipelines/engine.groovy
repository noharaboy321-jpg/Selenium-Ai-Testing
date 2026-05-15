@Library('tenable.common')
import com.tenable.jenkins.*
import com.tenable.jenkins.builds.*
import com.tenable.jenkins.Constants
import com.tenable.jenkins.common.Common

def runEngine (String targetOS, String nessusBuildBranch, String catiumBranch, String leakCheckLevel = "Off", Boolean disableCompilationLeakCheck = false, String markers = "None", String nessusPackage = "None", String nessusDebugInfo = "None") {

    Common common = new Common(this)

    List testFolder = ['advanced_settings', 'install', 'logs', 'nasl', 'plugins', 'scan', 'upgrade']
    boolean nessusHome = true
    boolean nessusPro = true
    boolean nessusManager = true
    boolean nessusExpert = true
    Integer instanceCount = 3
    String markersString = "nessus_engine and not real_agent"
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

    nessusTests.runTests(targetOS, nessusBuildBranch, catiumBranch, testFolder, nessusHome, nessusPro, nessusManager, nessusExpert, instanceCount, markersString, [], nessusPackage, nessusDebugInfo, leakCheckLevel, disableCompilationLeakCheck, false)
}

return this
