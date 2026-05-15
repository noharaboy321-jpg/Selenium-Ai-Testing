@Library('tenable.common')
import com.tenable.jenkins.*
import com.tenable.jenkins.builds.*
import com.tenable.jenkins.Constants
import com.tenable.jenkins.common.Common
import com.tenable.jenkins.common.Logger
import groovy.transform.Field

@Field Logger logger = new Logger(this, 'runTests', Constants.LOG_LEVEL_DEBUG)

// Load leak exemptions from the file while this is being loaded, not while the function runs:
@Field def leakExemptions = []
try {
    leakExemptions = load("${pwd()}/pipelines/nessus_leak_exemptions.groovy")
} catch (Exception e) {
    // Not available when called from agent repo
}

def runTests(Map args) {
    // ===========================================
    // PARAMETER EXTRACTION
    // ===========================================

    // Agent Package Source
    String agentPackageSourceType = args.agentPackageSourceType ?: 'Direct URL'
    String agentPackageUrl = args.agentPackageUrl ?: null
    String agentJenkinsBranch = args.agentJenkinsBranch ?: null
    String agentJenkinsBuildNumber = args.agentJenkinsBuildNumber ?: 'latest'
    String agentVersion = args.agentVersion ?: null

    // Nessus Package Source
    String nessusPackageSourceType = args.nessusPackageSourceType ?: 'Direct URL'
    String nessusPackageUrl = args.nessusPackageUrl ?: null
    String nessusJenkinsBranch = args.nessusJenkinsBranch ?: null
    String nessusJenkinsBuildNumber = args.nessusJenkinsBuildNumber ?: 'latest'
    String nessusBuildBranch = args.nessusBuildBranch
    String nessusVersion = args.nessusVersion
    String nexusPath = args.nexusPath ?: nessusVersion
    String filesLabBuildNumber = args.filesLabBuildNumber ?: null
    String fetchPackageAwsRole = args.fetchPackageAwsRole ?: Constants.ARN_BUILD_ARTEFACTS
    String debugInfoUrl = args.debugInfoUrl ?: 'None'

    // Test Environment Configuration
    List targetOS = args.targetOS
    Boolean preconfiguredAmi = args.preconfiguredAmi ?: false
    String nessusPluginsetId = args.nessusPluginsetId ?: null
    String pluginServer = args.pluginServer ?: 'plugins-internal-staging.cloud.aws.tenablesecurity.com'
    Integer instanceCount = args.instanceCount
    String instanceType = args.instanceType ?: 'default'

    // AWS Configuration
    String awsRole = args.awsRole ?: Constants.IAM_ROLE_ARN_AUTOMATION
    String awsRegion = args.awsRegion ?: 'us-east-1'
    String awsAlternateVpcId = args.awsAlternateVpcId ?: 'vpc-0165441395292999e'
    String awsSecurityGroup = args.awsSecurityGroup ?: ''

    // License Configuration
    Boolean nessusEssentialsPlus = args.nessusEssentialsPlus
    Boolean nessusEssentials = args.nessusEssentials
    Boolean nessusPro = args.nessusPro
    Boolean nessusExpert = args.nessusExpert
    Boolean nessusManager = args.nessusManager

    // Test Execution Configuration
    String catiumBranch = args.catiumBranch
    List testFolder = args.testFolder
    String markers = args.markers
    List ignoredItems = args.ignoredItems ?: []
    Boolean offlineMode = args.offlineMode ?: false
    String retries = args.retries ?: "0"

    // Leak Check Configuration
    String leakCheckLevel = args.leakCheckLevel ?: 'Off'
    Boolean disableCompilationLeakCheck = args.disableCompilationLeakCheck ?: false

    // Plugin Update Configuration
    String initialPluginsetId = args.initialPluginsetId ?: null
    String updatedPluginsetId = args.updatedPluginsetId ?: null

    // Windows Target IPs (legacy)
    String windows10Ip = args.windows10Ip ?: null
    String windows11Ip = args.windows11Ip ?: null
    String windowsServer2022Ip = args.windowsServer2022Ip ?: null
    String windowsServer2019Ip = args.windowsServer2019Ip ?: null

    // Notification Configuration
    Boolean sendPerTestNotifications = args.sendPerTestNotifications != null ? args.sendPerTestNotifications : true

    // Other Configuration
    String sensorOrchBranch = args.sensorOrchBranch ?: null
    String awsPrivateKey = args.awsPrivateKey ?: null

    // Product Mode
    String product = args.product ?: 'nessus'
    Boolean isAgentMode = (product == 'agent')

    // General parameters (shared across products)
    String logLevelConsole = args.logLevelConsole ?: 'INFO'
    String logLevel = args.logLevel ?: 'DEBUG'

    // Agent-specific Configuration
    List agentTargetOS = args.targetOS ?: []
    String nessusTargetOS = args.nessusTargetOS ?: null
    String tvmUrl = args.tvmUrl ?: 'qa-develop.cloud.aws.tenablesecurity.com'
    String tvmUsername = args.tvmUsername ?: 'shared-engine@tenable.dev'
    String tvmPassword = args.tvmPassword ?: 'Tenable@12345'
    Integer pluginsetLookback = args.pluginsetLookback ?: 5

    // Normalize "None" sentinel values to null
    if (agentPackageUrl == "None") agentPackageUrl = null
    if (nessusPackageUrl == "None") nessusPackageUrl = null

    // ===========================================
    // PRODUCT-DEPENDENT CONSTANTS
    // ===========================================
    String packagePrefix = isAgentMode ? 'NessusAgent' : 'Nessus'
    String testPathPrefix = isAgentMode ? 'nessusagent/tests/' : 'nessus/tests/'
    String buildTag = isAgentMode ? 'nessusagent' : 'nessus'
    String productName = isAgentMode ? 'Nessus Agent' : 'Nessus'
    String teamName = isAgentMode ? 'QE-NessusAgent' : 'QE-Nessus'
    String gitRepoUrl = isAgentMode
        ? 'git@github.com:tenb-Product/catium-nessusagent.git'
        : 'git@github.com:tenb-Product/catium-nessus.git'
    String slackChannel = isAgentMode
        ? '#agent_automated_test_results'
        : '#nessus_automated_test_results'
    String ddGitBranch = isAgentMode ? 'release' : 'master'
    String ddTagPrefix = isAgentMode ? 'NessusAgentVersion' : 'NessusVersion'
    String ddTeamName = isAgentMode ? 'NessusAgent' : 'Nessus'

    // ===========================================
    // INITIALIZATION
    // ===========================================
    Common common = new Common(this)
    Integer passedTests = 0
    Integer failedTests = 0
    Map testResultsMap = [:]

    // ===========================================
    // STAGE: RESOLVE PACKAGE SOURCE
    // ===========================================
    String sanitizedVersion
    String sanitizedNessusVersion = ''

    stage("Resolve Package Source") {
        node(Constants.M42XL_AE_PROD_TESTING) {
            if (isAgentMode) {
                // Resolve agent package
                String agentSourceType = agentPackageUrl ? 'Direct URL' : agentPackageSourceType
                Map agentResolution = resolvePackageVersion(
                    agentSourceType, agentPackageUrl, agentJenkinsBranch, agentJenkinsBuildNumber,
                    agentVersion, packagePrefix, fetchPackageAwsRole, awsRegion, filesLabBuildNumber
                )
                sanitizedVersion = agentResolution.sanitizedVersion
                agentJenkinsBuildNumber = agentResolution.resolvedBuildNumber ?: agentJenkinsBuildNumber
                filesLabBuildNumber = agentResolution.filesLabBuildNumber ?: filesLabBuildNumber

                // Also resolve Nessus manager package if needed
                if (nessusManager) {
                    String managerSourceType = nessusPackageUrl ? 'Direct URL' : nessusPackageSourceType
                    Map nessusResolution = resolvePackageVersion(
                        managerSourceType, nessusPackageUrl, nessusJenkinsBranch, nessusJenkinsBuildNumber,
                        nessusBuildBranch, 'Nessus', fetchPackageAwsRole, awsRegion, filesLabBuildNumber
                    )
                    sanitizedNessusVersion = nessusResolution.sanitizedVersion
                    nessusBuildBranch = nessusResolution.resolvedBranch
                    nessusJenkinsBuildNumber = nessusResolution.resolvedBuildNumber ?: nessusJenkinsBuildNumber
                    filesLabBuildNumber = nessusResolution.filesLabBuildNumber ?: filesLabBuildNumber
                }
            } else {
                // Resolve Nessus package
                Map nessusResolution = resolvePackageVersion(
                    nessusPackageSourceType, nessusPackageUrl, nessusJenkinsBranch, nessusJenkinsBuildNumber,
                    nessusBuildBranch, packagePrefix, fetchPackageAwsRole, awsRegion, filesLabBuildNumber
                )
                sanitizedNessusVersion = nessusResolution.sanitizedVersion
                sanitizedVersion = sanitizedNessusVersion
                nessusBuildBranch = nessusResolution.resolvedBranch
                nessusJenkinsBuildNumber = nessusResolution.resolvedBuildNumber
                filesLabBuildNumber = nessusResolution.filesLabBuildNumber ?: filesLabBuildNumber
            }
        }
    }

    // ===========================================
    // STAGE: CONFIGURE BUILD DISPLAY
    // ===========================================
    String folderString = ""
    testFolder.each { String folder ->
        if (folderString == "") {
            folderString = folder
        } else {
            folderString = folderString + "_${folder}"
        }
    }

    String displayNameSuffix
    if (isAgentMode) {
        List displayOS = agentTargetOS.size() == 1 ? agentTargetOS : ['multiple_agent_os']
        if (nessusManager) {
            displayNameSuffix = "@ nessus_os_${nessusTargetOS}_agent_os_${displayOS[0]}_${sanitizedVersion}_${folderString}_tests"
        } else {
            displayNameSuffix = "@ agent_${sanitizedVersion}_${displayOS[0]}_${folderString}_tests"
        }
    } else {
        displayNameSuffix = "@ ${targetOS}_${sanitizedVersion}_${folderString}_tests"
    }
    if (!currentBuild.displayName.contains(displayNameSuffix)) {
        currentBuild.displayName += displayNameSuffix
    }
    List buildDescription = ["<h5> ${sanitizedVersion} </h5>"]
    this.currentBuild.description = common.getCauseDescriptions()
    this.currentBuild.description += '\n' + buildDescription.join('\n')

    // ===========================================
    // STAGE: BUILD TEST CONFIGURATION
    // ===========================================
    // Default test parameters
    BuildParams defaultParams = new BuildParams(this)
    defaultParams.pytestCreateHtmlReport = false
    defaultParams.alsoPublishAttentionMsgsToChannels = slackChannel
    if (sendPerTestNotifications) {
        defaultParams.alsoPublishNotificationMsgsToChannels = slackChannel
    }

    String ignoredItemsString = ""
    if (!isAgentMode) {
        ignoredItemsString = "--ignore=nessus/tests/api/scanner_health/test_scanner_health_endpoints.py"
    }
    ignoredItems.each { String item ->
        ignoredItemsString += " --ignore=${item}"
    }

    defaultParams.pytestOptions = "-p catium.plugins.xdist_variables --reruns=${retries} --reruns-delay=0 --capabilities '{\"idleTimeout\": 15, \"maxDuration\": 45, \"buildTags \":[\"${buildTag}\"]}' ${ignoredItemsString}"

    List testPaths = []
    testFolder.each { String folder ->
        testPaths.add("${testPathPrefix}${folder}")
    }

    defaultParams.retryCount = 0
    defaultParams.timeout = 900
    defaultParams.productName = productName
    defaultParams.teamName = teamName
    defaultParams.testCategory = "REGR"
    defaultParams.suiteType = "ENGINE"
    defaultParams.platform = isAgentMode ? "${agentTargetOS}" : "${targetOS}"

    // ===========================================
    // STAGE: BUILD LICENSE CONFIGURATIONS (Nessus mode only)
    // ===========================================
    List nessusLicenses = []

    if (!isAgentMode) {
        if (nessusEssentials) {
            nessusLicenses.add([type: "home", licenseMarker: "nessus_home"])
            nessusLicenses.add([type: "essentials", licenseMarker: "nessus_essentials"])
        }
        if (nessusEssentialsPlus) {
            nessusLicenses.add([type: "essentials_plus", licenseMarker: "nessus_essentials_plus"])
        }
        if (nessusPro) {
            nessusLicenses.add([type: "pro", licenseMarker: "nessus_pro"])
        }
        if (nessusManager) {
            nessusLicenses.add([type: "manager", licenseMarker: "nessus_manager"])
        }
        if (nessusExpert) {
            nessusLicenses.add([type: "expert", licenseMarker: "nessus_expert"])
        }
        logger.info("Configured licenses: ${nessusLicenses.collect { it.type }}")
    }

    // ===========================================
    // STAGE: BUILD TEST INSTANCES
    // ===========================================
    String conan_id_query = 'os=Linux AND build_type=Release'
    Map conan_id_rh_compiler_queries = [
        '6': ' AND compiler.version=9',
        '7': ' AND compiler.version=10'
    ]

    String debugInfoFilename
    List testInstances = []

    // Generate manager package filename for agent+manager mode
    String managerDownloadFilename = null
    if (isAgentMode && nessusManager && nessusTargetOS) {
        Map managerPkg = buildPackageFilename('Nessus', sanitizedNessusVersion, nessusTargetOS, nessusTargetOS.contains('arm'))
        managerDownloadFilename = managerPkg.downloadFilename
    }

    stage("Build Test Matrix") {
        List osList = isAgentMode ? agentTargetOS : targetOS
        logger.info("Building test matrix for OS: ${osList}")

        // Validate OS entries
        List validOS = ["amazonlinux", "amazonlinux2023", "amazonlinux2023arm", "amazonlinuxarm", "centos7", "centos9stream", "debian12", "fedora38", "miraclelinux9", "oraclelinux8", "oraclelinux9", "rhel8-arm", "rhel9-arm", "suse15", "ubuntu20", "ubuntu22", "ubuntu22arm", "ubuntu24", "ubuntu24arm", "windows2019"]
        List invalidOS = osList.findAll { !validOS.contains(it) }
        if (invalidOS) {
            logger.warn("Unrecognized OS entries (may cause setup failures): ${invalidOS}")
        }

        String baseConanQuery = conan_id_query
        osList.each { String currentOS ->
            Map pkg = buildPackageFilename(packagePrefix, sanitizedVersion, currentOS, currentOS.contains('arm'))
            Boolean arm = pkg.arm
            String osMarkers = pkg.osMarkers

            if (!isAgentMode && !preconfiguredAmi) {
                // Nessus-specific: build per-OS conan query and debug info
                String elVersion = pkg.elVersion
                conan_id_query = baseConanQuery
                if (pkg.conanQueryAddition) {
                    conan_id_query += pkg.conanQueryAddition
                }
                if (conan_id_rh_compiler_queries[elVersion]) {
                    conan_id_query += conan_id_rh_compiler_queries[elVersion]
                }
                String baseDebugInfoFilename = pkg.baseDebugInfoFilename ?: "Nessus_"
                if (baseDebugInfoFilename == "all_") {
                    debugInfoFilename = baseDebugInfoFilename + "debuginfo" + pkg.packageOS.replace(".", "-") + pkg.architecture + "-" + sanitizedVersion + ".tar.xz"
                } else {
                    debugInfoFilename = baseDebugInfoFilename + "debuginfo-" + sanitizedVersion + pkg.packageOS + pkg.architecture + pkg.packageExtension
                }
            }

            // Build marker string
            String markerString = buildMarkerString(markers, osMarkers, arm, offlineMode)

            if (isAgentMode) {
                // Agent mode: one instance per OS
                String agentType = nessusManager ? 'nessus_manager' : 'non_nessus_manager'
                String fullMarkers = markerString ? "'${markerString}'" : ""
                Map instance = [
                    "os": currentOS.toLowerCase(),
                    "type": agentType,
                    "arm": arm,
                    "preconfiguredAmi": false,
                    "markers": fullMarkers,
                    "downloadFilename": pkg.downloadFilename,
                    "debugInfoFile": null
                ]
                testInstances.add(instance)
                logger.debug("Added agent test instance: ${instance}")
            } else {
                // Nessus mode: one instance per OS × license
                nessusLicenses.each { config ->
                    String fullMarkers
                    if (markerString) {
                        fullMarkers = "'${config.licenseMarker} and ${markerString}'"
                    } else {
                        fullMarkers = "'${config.licenseMarker}'"
                    }
                    logger.info("Markers for ${config.type} on ${currentOS}: ${fullMarkers}")
                    Map instance = [
                        "os": currentOS.toLowerCase(),
                        "type": config.type,
                        "arm": arm,
                        "preconfiguredAmi": preconfiguredAmi,
                        "markers": fullMarkers,
                        "downloadFilename": pkg.downloadFilename,
                        "debugInfoFile": debugInfoFilename
                    ]
                    testInstances.add(instance)
                    logger.debug("Added test instance: ${instance}")
                }
            }
        }

        logger.info("Total test instances configured: ${testInstances.size()}")
    }

    // ===========================================
    // STAGE: CONFIGURE LEAK CHECKING
    // ===========================================
    String customJemallocConanId = ''
    String customJemallocOpts = ''
    String jemallocConanBranch = 'jemalloc/5.2.1@shared-components/tenable-jenkins-profiling-5.2.1'

    if (leakCheckLevel != 'Off') {
        logger.info("Configuring leak checking: ${leakCheckLevel}")
        customJemallocOpts = 'prof:true,prof_final:true,prof_prefix:/opt/nessus/var/nessus/logs/jeprof'
        if (leakCheckLevel == 'High') {
            customJemallocOpts += ',lg_prof_sample:0'
        } else if (leakCheckLevel == 'Medium') {
            customJemallocOpts += ',lg_prof_sample:10'
        } else if (leakCheckLevel ==~ /SampleLog:[0-9]*/) {
            customJemallocOpts += ',lg_prof_sample:' + (leakCheckLevel =~ /^SampleLog:([0-9]*)$/)[0][1]
        }
        // For 'Low' (or unrecognized options), leave lg_prof_sample at the default of 19
    }

    // ===========================================
    // STAGE: EXECUTE TESTS
    // ===========================================
    Exception parallelException = null
    Map testers = [:]
    String testersString
    logger.info("Test paths: ${testPaths}")

    stage("Execute Tests") {
        testPaths.each { String testPath ->
            testInstances.each { Map config ->
                if (config.downloadFilename && config.downloadFilename.contains('.invalid')) {
                    throw new Exception("${config.os} is not configured in the pipeline")
                }
                logger.debug("Processing test instance: ${config}")

                if (nessusPluginsetId == null) {
                    testersString = "${testPath}_${config.type}_${config.os}"
                } else {
                    testersString = "${nessusPluginsetId}_${testPath}_${config.type}_${config.os}"
                }

                logger.debug("Evaluating OS type: ${config.os}")
                if (config.os.contains("windows")) {
                    // Windows tests not yet implemented
                } else {
                    testers[testersString] = {
                        node(Constants.M42XL_AE_PROD_TESTING) {
                            BuildsCommon buildsCommon = new BuildsCommon(this)
                            buildsCommon.cleanup()

                            // Determine EC2 instance type
                            String ec2InstanceType = determineInstanceType(instanceType, config.arm, isAgentMode)

                            // Configure AWS subnet
                            Map awsConfig = configureAwsNetwork(args.awsSubnetId, awsSecurityGroup, awsRole, awsRegion, awsAlternateVpcId)
                            String awsSubnetId = awsConfig.subnetId
                            String awsInstanceSecurityGroup = awsConfig.securityGroup

                            // Build package URL
                            String currentPackageUrl
                            Boolean shouldPassAwsRole = false
                            if (isAgentMode) {
                                String agentSourceType = agentPackageUrl ? 'Direct URL' : agentPackageSourceType
                                Map agentPkgConfig = buildPackageUrl(
                                    agentSourceType, agentPackageUrl, agentJenkinsBranch, agentJenkinsBuildNumber,
                                    filesLabBuildNumber, sanitizedVersion, config, fetchPackageAwsRole, awsRegion
                                )
                                currentPackageUrl = agentPkgConfig.url
                                shouldPassAwsRole = agentPkgConfig.requiresAwsRole
                                logger.info("Using agent package URL: ${currentPackageUrl}")
                            } else {
                                Map packageConfig = buildPackageUrl(
                                    nessusPackageSourceType, nessusPackageUrl, nessusJenkinsBranch, nessusJenkinsBuildNumber,
                                    filesLabBuildNumber, sanitizedNessusVersion, config, fetchPackageAwsRole, awsRegion
                                )
                                currentPackageUrl = packageConfig.url
                                shouldPassAwsRole = packageConfig.requiresAwsRole
                            }

                            // Configure debug info URL
                            String finalDebugInfoUrl = configureDebugInfoUrl(debugInfoUrl, customJemallocOpts, nexusPath, debugInfoFilename)

                            // Install leak checking dependencies if needed
                            if (leakCheckLevel != 'Off') {
                                sh "sudo apt-get -y update && sudo apt-get -y install python3-pip && sudo pip install 'conan<2.0'"
                            }

                            // Get jemalloc conan ID if leak checking enabled
                            if ((leakCheckLevel != 'Off') && (customJemallocConanId == '')) {
                                withConan(name: 'tenable') {
                                    String conan_out = sh(returnStdout: true, script: "conan search -r tenable -q '${conan_id_query}' ${jemallocConanBranch}")
                                    def package_id_matches = conan_out =~ /Package_ID: *([0-9A-Fa-f]*)/
                                    if (package_id_matches) {
                                        customJemallocConanId = jemallocConanBranch + ':' + (conan_out =~ /Package_ID: *([0-9A-Fa-f]*)/)[0][1]
                                    }
                                }
                            }

                            // Configure DataDog
                            String DD_TAG = "${ddTagPrefix}:${config.type},team:'${ddTeamName}',OS:${config.os}"
                            String ddSite = 'datadoghq.com'
                            String ddAgentHost = 'http://datadog-agent.service.build.aws.tenablesecurity.com:8126'

                            // Build withOnDemandTestEnv arguments
                            Map withOdeArgs = [
                                OS: config.os,
                                awsInstanceType: ec2InstanceType,
                                instanceCount: instanceCount,
                                diskSize: 80,
                                playbookExtraVars: ['user_data_wait': '45', 'plugin_server_host': pluginServer, 'plugin_server_api': "https://${pluginServer}/keygen/json.generate.php"],
                                awsSubnetId: awsSubnetId,
                                verbose: args.verbose ?: false
                            ]

                            if (awsPrivateKey) {
                                withOdeArgs.awsPrivateKey = awsPrivateKey
                            }

                            if (isAgentMode) {
                                // Agent mode ODE args
                                withOdeArgs.skipConfiguration = true
                                if (nessusManager) {
                                    String managerSourceType = nessusPackageUrl ? 'Direct URL' : nessusPackageSourceType
                                    Map managerUrlConfig = [downloadFilename: managerDownloadFilename, preconfiguredAmi: false]
                                    Map managerPkgResult = buildPackageUrl(
                                        managerSourceType, nessusPackageUrl, nessusJenkinsBranch,
                                        nessusJenkinsBuildNumber, filesLabBuildNumber, sanitizedNessusVersion,
                                        managerUrlConfig, fetchPackageAwsRole, awsRegion
                                    )
                                    String managerPackageUrl = managerPkgResult.url
                                    shouldPassAwsRole = shouldPassAwsRole || managerPkgResult.requiresAwsRole
                                    String managerInstanceType = determineInstanceType('default', nessusTargetOS.contains('arm'), false)
                                    withOdeArgs.clusterConfig = [
                                        manager: [
                                            product: 'nessus',
                                            OS: nessusTargetOS,
                                            awsInstanceType: managerInstanceType,
                                            packageUrl: managerPackageUrl,
                                            nessusType: 'manager',
                                            skipConfiguration: false,
                                        ],
                                        agents: [
                                            product: 'agent',
                                            packageUrl: currentPackageUrl,
                                            dependencyGroup: 'manager',
                                            connectGroup: 'manager',
                                            skipConfiguration: true,
                                        ],
                                    ]
                                    withOdeArgs.packageUrl = "None"
                                    withOdeArgs.product = "None"
                                } else {
                                    withOdeArgs.packageUrl = currentPackageUrl
                                    withOdeArgs.product = 'agent'
                                }
                            } else {
                                // Nessus mode ODE args
                                withOdeArgs.nessusType = config.type
                                withOdeArgs.nessusUpdatePlugins = args.updatePlugins ?: 'yes'
                                withOdeArgs.packageUrl = currentPackageUrl
                                withOdeArgs.debugInfoUrl = finalDebugInfoUrl
                                withOdeArgs.product = 'nessus'
                                withOdeArgs.customJemallocConanId = customJemallocConanId
                                withOdeArgs.customJemallocOpts = customJemallocOpts
                                withOdeArgs.leakExemptions = leakExemptions
                                withOdeArgs.disableCompilationLeakCheck = disableCompilationLeakCheck
                                withOdeArgs.preconfiguredAmi = config.preconfiguredAmi
                                withOdeArgs.productVersion = sanitizedNessusVersion
                                withOdeArgs.pluginsetTagId = nessusPluginsetId
                            }

                            if (shouldPassAwsRole) {
                                withOdeArgs["fetchPackageAwsRole"] = fetchPackageAwsRole
                            }
                            if (awsInstanceSecurityGroup) {
                                withOdeArgs["awsInstanceSecurityGroup"] = awsInstanceSecurityGroup
                            }
                            if (sensorOrchBranch) {
                                withOdeArgs["sensorOrchBranch"] = sensorOrchBranch
                            }

                            logger.info("Starting On-Demand test environment")
                            logger.debug("withODE parameters: ${withOdeArgs}")

                            withOnDemandTestEnv(withOdeArgs) {
                                // Resolve IPs
                                String testIp
                                String managerIp = ""
                                if (isAgentMode && nessusManager) {
                                    def inventory = readJSON file: 'inventory.json'
                                    logger.debug("Environment inventory: ${inventory}")
                                    managerIp = inventory.manager.collect { it.value }[0]
                                    testIp = inventory.agents.collect { it.value }[0]
                                    logger.info("Manager IP: ${managerIp}")
                                } else if (isAgentMode) {
                                    testIp = TEST_ENV_IPS
                                } else {
                                    testIp = TEST_ENV_IPS
                                }
                                logger.info("Test IP: ${testIp}")

                                stage("${config.type}_Tests") {
                                    logger.info("Running tests: ${testPath}")

                                    // Build env vars - shared base + product-specific
                                    Map env_vars = [
                                        CAT_LOG_LEVEL_CONSOLE: logLevelConsole,
                                        CAT_LOG_LEVEL: logLevel,
                                        CAT_SSH_USERNAME: 'qa',
                                        CAT_SSH_USE_SUDO: 'true',
                                        CAT_NESSUS_CLI_LOCAL: 'false',
                                        CAT_API_RETRY: 'true'
                                    ]

                                    if (isAgentMode) {
                                        env_vars.CAT_SITE = 'default'
                                        env_vars.CAT_TIO_URL = "https://${tvmUrl}"
                                        env_vars.CAT_TIO_USERNAME = tvmUsername
                                        env_vars.CAT_TIO_PASSWORD = tvmPassword
                                        env_vars.CAT_AGENT_URL = testIp
                                        env_vars.CAT_INITIAL_PLUGINS = initialPluginsetId
                                        env_vars.CAT_UPDATED_PLUGINS = updatedPluginsetId
                                        env_vars.CAT_PLUGINSET_LOOKBACK = pluginsetLookback
                                        env_vars.CAT_NESSUS_USERNAME = 'admin'
                                        env_vars.CAT_NESSUS_PASSWORD = 'admin'
                                        env_vars.CAT_API_MAX_RETRIES = '1'
                                        if (nessusManager) {
                                            env_vars.CAT_NESSUS_URL = "https://" + managerIp + ":8834"
                                            env_vars.CAT_NESSUS_VERSION = "manager"
                                        }
                                    } else {
                                        env_vars.CAT_SITE = 'Ondemand'
                                        env_vars.CAT_NESSUS_VERSION = "${config.type}"
                                        env_vars.CAT_TIO_URL = 'qa-staging.cloud.aws.tenablesecurity.com'
                                        env_vars.CAT_INITIAL_PLUGINSET = nessusPluginsetId
                                        env_vars.CAT_PREPROD_PLUGINSET = updatedPluginsetId
                                        env_vars.CAT_API_MAX_RETRIES = '3'
                                        env_vars.ENV_VARIABLE = ''
                                    }

                                    List sensitiveKeys = ['CAT_TIO_PASSWORD', 'CAT_NESSUS_PASSWORD', 'CAT_SSH_PASSWORD']
                                    Map redactedEnvVars = env_vars.collectEntries { k, v ->
                                        [(k): sensitiveKeys.contains(k) ? '****' : v]
                                    }
                                    logger.debug("Environment variables: ${redactedEnvVars}")

                                    withCredentials([
                                        string(credentialsId: 'NES_DD_API_KEY', variable: 'LOCUST_DD_API_KEY'),
                                        string(credentialsId: 'NES_DD_APP_KEY', variable: 'LOCUST_DD_APP_KEY'),
                                    ]) {
                                        defaultParams.setAutomationEnvironment([
                                            'DD_API_KEY': LOCUST_DD_API_KEY,
                                            'LOCUST_DD_APP_KEY': LOCUST_DD_APP_KEY,
                                            'DD_GIT_REPOSITORY_URL': gitRepoUrl,
                                            'DD_GIT_BRANCH': ddGitBranch,
                                            'DD_TAGS': DD_TAG,
                                            'DD_AGENT_HOST': ddAgentHost,
                                            'DD_TRACE_AGENT_URL': ddAgentHost,
                                            'DD_SITE': ddSite,
                                        ])
                                    }

                                    String xdistHost = testIp
                                    AutomationDirectBuild builder = new AutomationDirectBuild(this)
                                    common.copyProperties(defaultParams, builder.parameters)
                                    builder.parameters.lambdatestCredentialsId = 'nessusLambdatest'
                                    builder.parameters.pytestAWSAutomationRoleDuration = 36000
                                    builder.parameters.pytestTestPaths = [testPath]
                                    builder.parameters.pytestSetupCommand = 'python3 autoconfig.py --no-download'
                                    builder.parameters.pytestOptions += " -m ${config.markers} --ddtrace --xdist-hosts ${xdistHost}"
                                    builder.parameters.setPytestParallelName("${config.type}", false)
                                    builder.parameters.setAutomationEnvironment(env_vars)
                                    builder.parameters.pytestSshAgents = ['ODE-privkey']
                                    builder.parameters.pytestRepositoryUrl = gitRepoUrl
                                    builder.parameters.pytestBranch = "${catiumBranch}"
                                    builder.parameters.pytestNotificationFormat = "healthcheck"
                                    logger.debug("Pytest parameters: testPaths=${builder.parameters.pytestTestPaths}, branch=${builder.parameters.pytestBranch}, options=${builder.parameters.pytestOptions}")
                                    try {
                                        builder.execute(createNode: false)
                                    } catch (Exception e) {
                                        String errMsg = e.getMessage() ?: ''
                                        if (errMsg =~ /exit code 5\b/) {
                                            logger.warn("No tests collected for ${config.type} on ${config.os} with markers ${config.markers} — marking as UNSTABLE")
                                            unstable("No tests collected for ${config.type} on ${config.os} with markers ${config.markers}")
                                        } else {
                                            throw e
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        try {
            parallel(testers)
        } catch (Exception e) {
            parallelException = e
            logger.warn("One or more parallel branches failed: ${e.getMessage()}")
        }
    }

    // ===========================================
    // STAGE: REPORT RESULTS
    // ===========================================
    def testFailures = [:]

    stage("Report Results") {
        List failedTestsData = common.getTestResultData(common.getFailedTests())
        testResultsMap = common.getTestResultsMap()
        Integer totalFailures = failedTestsData.size()

        logger.debug("Failed Tests: ${failedTestsData}")

        failedTestsData.each { Map failureData ->
            String failureMessage = (failureData["ReasonForFailure"] =~ /^.*/)[0]
            Integer failureCount = testFailures.get(failureMessage)
            if (failureCount == null) {
                testFailures.put(failureMessage, 1)
            } else {
                testFailures.put(failureMessage, failureCount + 1)
            }
        }

        AutomationDirectBuild builder = new AutomationDirectBuild(this)
        common.copyProperties(defaultParams, builder.parameters)
        builder.parameters.channels = slackChannel
        builder.sendNotification(slackChannel)

        List buildDescriptionLast = ["<h5> ${sanitizedVersion} </h5>"]
        this.currentBuild.description = common.getCauseDescriptions()
        this.currentBuild.description += '\n' + buildDescriptionLast.join('\n')

        testFailures.each { k, v -> logger.debug("Failure message: ${k}, count: ${v}") }
        logger.info("Total failures in pipeline: ${totalFailures}")
    }

    failedTests = testResultsMap["failCount"]
    passedTests = testResultsMap["passedCount"]
    Integer totalTests = testResultsMap["totalCount"]
    testResultsMap["failureCountList"] = testFailures

    // Flag the exception in the returned results so callers can detect it
    if (parallelException) {
        testResultsMap["parallelException"] = parallelException.getMessage()
    }

    // Mark build UNSTABLE (not FAILURE) when branches failed or no tests ran
    if (parallelException || testResultsMap["totalCount"] == 0) {
        currentBuild.result = 'UNSTABLE'
        logger.warn("Build marked UNSTABLE: ${parallelException ? 'parallel branch failure' : 'no tests were executed'}")
    }

    return testResultsMap
}

// ===========================================
// HELPER FUNCTIONS
// ===========================================

/**
 * Build marker string for pytest
 */
def buildMarkerString(String markers, String osMarkers, Boolean arm, Boolean offlineMode) {
    String markerString
    if (markers in [null, "", "no_markers"]) {
        markerString = ""
    } else if (markers.contains(",")) {
        markerString = markers.replace(",", " and ")
    } else if (markers) {
        markerString = markers
    }

    if (osMarkers) {
        if (markerString) {
            markerString = markerString + " and " + osMarkers
        } else {
            markerString = osMarkers
        }
    }

    if (arm && markerString) {
        markerString = markerString + " and not skip_arm"
    } else if (arm) {
        markerString = "not skip_arm"
    }

    if (offlineMode && markerString) {
        markerString = markerString + " and offline_mode"
    } else if (offlineMode) {
        markerString = "offline_mode"
    } else if (markerString) {
        markerString = markerString + " and not offline_mode"
    } else {
        markerString = "not offline_mode"
    }

    return markerString
}

/**
 * Determine EC2 instance type
 */
def determineInstanceType(String instanceType, Boolean arm, Boolean isAgentMode = false) {
    if (instanceType == "default") {
        if (isAgentMode) {
            return arm ? "t4g.small" : "t3.small"
        }
        return arm ? "c6g.xlarge" : "c5.xlarge"
    }
    return instanceType
}

/**
 * Configure AWS network settings
 */
def configureAwsNetwork(String awsSubnetIdOverride, String awsSecurityGroup, String awsRole, String awsRegion, String awsAlternateVpcId) {
    String awsSubnetId = ''
    String awsInstanceSecurityGroup = awsSecurityGroup

    if (awsSubnetIdOverride == 'default' || !awsSubnetIdOverride) {
        awsSubnetId = ''
    } else if (awsSubnetIdOverride == 'alternate') {
        if (!awsInstanceSecurityGroup) {
            awsInstanceSecurityGroup = 'sg-06002c2b65eea1721'
        }
        withAWS(role: awsRole, region: awsRegion) {
            def subnets = []
            def describeSubnetsCmd = "aws ec2 describe-subnets --filters Name=vpc-id,Values=${awsAlternateVpcId} Name=map-public-ip-on-launch,Values=false --query 'Subnets[*].SubnetId' --output text"
            try {
                def subnetList = sh(script: describeSubnetsCmd, returnStdout: true).trim()
                if (subnetList && subnetList != 'None') {
                    subnets = subnetList.split()
                }
            } catch (Exception e) {
                error "Failed to lookup private subnets in alternate VPC: ${e}"
            }
            if (subnets && subnets.size() > 0) {
                awsSubnetId = subnets[new Random().nextInt(subnets.size())]
                logger.info("Selected private subnet ${awsSubnetId} from alternate VPC ${awsAlternateVpcId}")
            } else {
                error "No private subnets found for alternate VPC ${awsAlternateVpcId}"
            }
        }
    } else {
        awsSubnetId = awsSubnetIdOverride
    }

    return [subnetId: awsSubnetId, securityGroup: awsInstanceSecurityGroup]
}

/**
 * Build package URL based on source type
 */
def buildPackageUrl(String packageSourceType, String packageUrl, String jenkinsBranch, String jenkinsBuildNumber,
                    String filesLabBuildNumber, String nessusVersion, Map config,
                    String fetchPackageAwsRole, String awsRegion) {
    String currentPackageUrl = ""
    Boolean shouldPassAwsRole = false

    if (config.preconfiguredAmi) {
        return [url: "", requiresAwsRole: false]
    }

    logger.info("Package Source Type: ${packageSourceType}")

    if (packageSourceType == 'Direct URL' && packageUrl) {
        currentPackageUrl = packageUrl
        if (currentPackageUrl.startsWith('s3://')) {
            shouldPassAwsRole = true
        }
        logger.info("Using direct URL: ${currentPackageUrl}")
    } else if (packageSourceType == 'Jenkins Branch' && jenkinsBranch) {
        // URL-encode the branch name for S3 path (replace / with %2F) to match Jenkins artifact storage
        String urlEncodedBranch = jenkinsBranch.replaceAll('/', '%2F')
        Boolean isAgent = config.downloadFilename?.startsWith('NessusAgent')
        String s3Team = isAgent ? 'teams-nessus-agents' : 'teams-nessus'
        String s3Product = isAgent ? 'nessus-agents' : 'nessus'
        String s3Job = isAgent ? 'nessusagentrpmbuild' : 'nessus_build'
        currentPackageUrl = "s3://tenb-jenkins-artefacts/${s3Team}/${s3Product}/${s3Job}/${urlEncodedBranch}/${jenkinsBuildNumber}/artifacts/${config.downloadFilename}"
        shouldPassAwsRole = true
        logger.info("Using Jenkins branch S3 URL: ${currentPackageUrl}")
    } else if (packageSourceType in ['Nessus Version', 'Agent Version']) {
        // Derive product path from download filename (Nessus vs NessusAgent)
        String filesLabProduct = config.downloadFilename?.startsWith('NessusAgent') ? 'Agent' : 'Nessus'
        String buildNumber = filesLabBuildNumber

        if (!buildNumber || buildNumber == 'latest') {
            logger.info("Attempting to auto-detect latest build number from files.lab for ${filesLabProduct} version ${nessusVersion}")
            try {
                String filesLabUrl = "https://files.lab.tenablesecurity.com/pub/files/Products/${filesLabProduct}/${nessusVersion}/"
                def response = httpRequest url: filesLabUrl, validResponseCodes: '200'
                String content = response?.content ?: ""

                // Extract directory names from href attributes (may have R/X prefix for Agent builds)
                def matcher = (content =~ /href="([RX]?\d+)\//)
                List buildNumbers = matcher.collect { it[1] }
                if (buildNumbers && buildNumbers.size() > 0) {
                    // Sort by numeric portion to find the highest build number
                    buildNumbers.sort { a, b ->
                        Integer numA = (a =~ /\d+/)[0] as Integer
                        Integer numB = (b =~ /\d+/)[0] as Integer
                        numA <=> numB
                    }
                    buildNumber = buildNumbers[-1]
                    logger.info("Auto-detected latest build number from files.lab: ${buildNumber}")
                } else {
                    logger.warn("Could not auto-detect build number from files.lab directory listing")
                }
            } catch (Exception e) {
                logger.warn("Could not auto-detect build number from files.lab: ${e.message}")
            }
        }

        if (buildNumber && buildNumber != 'latest') {
            currentPackageUrl = "https://files.lab.tenablesecurity.com/pub/files/Products/${filesLabProduct}/${nessusVersion}/${buildNumber}/${config.downloadFilename}"
            logger.info("Using Files Lab URL: ${currentPackageUrl}")
        } else {
            error "Build number is required for Files Lab package source and could not be auto-detected"
        }
    } else {
        error "No valid package source configuration. Package Source Type '${packageSourceType}' does not match any known source type, or required parameters are missing."
    }

    return [url: currentPackageUrl, requiresAwsRole: shouldPassAwsRole]
}

/**
 * Configure debug info URL
 */
def configureDebugInfoUrl(String debugInfoUrl, String customJemallocOpts, String nexusPath, String debugInfoFilename) {
    if ((debugInfoUrl == "None") && (customJemallocOpts)) {
        String url = "https://nexus.cloud.aws.tenablesecurity.com/repository/product-release/nessus/debuginfo/${nexusPath}/${debugInfoFilename}"
        logger.info("Using default debugInfo package URL: ${url}")
        return url
    } else if (customJemallocOpts) {
        logger.info("Using user-input debugInfo package URL: ${debugInfoUrl}")
        return debugInfoUrl
    }
    return ""
}

/**
 * Build package filename for a given product prefix, version, and OS.
 * Works for both Nessus and NessusAgent packages.
 */
def buildPackageFilename(String prefix, String version, String os, Boolean armInput) {
    Boolean arm = armInput || os.contains('arm')
    String architecture = ""

    switch (os) {
        case ~/.*arm.*/:
            arm = true
            architecture = "aarch64"
            break
        case ~/.*debian.*/:
            architecture = "amd64"
            break
        case ~/.*macos.*/:
            architecture = ""
            break
        case ~/.*ubuntu.*/:
            architecture = "amd64"
            break
        case ~/.*windows.*/:
            architecture = "x64"
            break
        default:
            architecture = "x86_64"
            break
    }

    os = os.toLowerCase()
    String baseFilename = "${prefix}-${version}"
    String packageOS
    String packageExtension
    String osMarkers = null
    String elVersion = null
    String baseDebugInfoFilename = "${prefix}_"
    String conanQueryAddition = null

    switch (os) {
        case ~/.*amazonlinux.*/:
            packageOS = "-amzn2."
            packageExtension = ".rpm"
            conanQueryAddition = " AND os.distro=AMZN2 AND arch=${architecture}"
            baseDebugInfoFilename = "all_"
            break
        case ~/.*centos.*/:
            elVersion = os.replaceAll("[^0-9]", "")
            packageOS = "-el${elVersion}."
            packageExtension = ".rpm"
            conanQueryAddition = " AND os.distro=RH${elVersion} AND arch=${architecture}"
            osMarkers = "not skip_centos${elVersion}"
            break
        case ~/.*debian.*/:
            packageOS = "-debian10_"
            packageExtension = ".deb"
            conanQueryAddition = " AND os.distro=Deb10 AND arch=x86_64"
            baseDebugInfoFilename = "all_"
            break
        case ~/.*fedora.*/:
            packageOS = "-fc38."
            packageExtension = ".rpm"
            break
        case ~/.*macos.*/:
            packageOS = ""
            packageExtension = ".dmg"
            break
        case ~/.*miraclelinux.*/:
            elVersion = os.replaceAll("[^0-9]", "")
            packageOS = "-el${elVersion}."
            packageExtension = ".rpm"
            conanQueryAddition = " AND os.distro=RH${elVersion} AND arch=${architecture}"
            osMarkers = "not skip_miraclelinux${elVersion}"
            break
        case ~/.*oraclelinux.*/:
            elVersion = os.replaceAll("[^0-9]", "")
            packageOS = "-el${elVersion}."
            packageExtension = ".rpm"
            conanQueryAddition = " AND os.distro=RH${elVersion} AND arch=${architecture}"
            osMarkers = "not skip_oraclelinux${elVersion}"
            break
        case ~/.*rhel.*/:
            elVersion = os.replaceAll("[^0-9]", "")
            packageOS = "-el${elVersion}."
            packageExtension = ".rpm"
            osMarkers = "not rhel8"
            break
        case ~/.*suse.*/:
            String suse_version = os.replaceAll("[^0-9]", "")
            packageOS = "-suse${suse_version}."
            packageExtension = ".rpm"
            conanQueryAddition = " AND os.distro=SLES15 AND arch=x86_64"
            osMarkers = "not skip_suse"
            break
        case ~/.*tenablecore.*/:
            elVersion = "7"
            packageOS = "-el${elVersion}."
            packageExtension = ".rpm"
            conanQueryAddition = " AND os.distro=RH${elVersion} AND arch=x86_64"
            osMarkers = "not skip_nessustc"
            break
        case ~/.*ubuntu.*/:
            if (arm) {
                packageOS = "-ubuntu1804_"
                conanQueryAddition = " AND os.distro=Ubuntu1804 AND arch=aarch64"
            } else {
                packageOS = "-ubuntu1604_"
                conanQueryAddition = " AND os.distro=Ubuntu1604 AND arch=x86_64"
            }
            packageExtension = ".deb"
            baseDebugInfoFilename = "all_"
            osMarkers = "not skip_ubuntu"
            break
        case ~/.*windows.*/:
            packageOS = ""
            packageExtension = ".msi"
            break
        default:
            packageOS = ""
            packageExtension = ".invalid"
    }

    if (packageOS == "-el10.") {
        packageOS = "-el9."
    }

    String downloadFilename = baseFilename + packageOS + architecture + packageExtension

    return [
        downloadFilename: downloadFilename,
        arm: arm,
        architecture: architecture,
        osMarkers: osMarkers,
        packageOS: packageOS,
        packageExtension: packageExtension,
        elVersion: elVersion,
        baseDebugInfoFilename: baseDebugInfoFilename,
        conanQueryAddition: conanQueryAddition
    ]
}

/**
 * Resolve package version from various source types.
 * Must be called from within a node block (uses sh, withCredentials, withAWS).
 * Returns [sanitizedVersion, resolvedBranch, resolvedBuildNumber, filesLabBuildNumber].
 */
def resolvePackageVersion(String sourceType, String directUrl, String jenkinsBranch,
                          String jenkinsBuildNumber, String buildBranch, String prefix,
                          String fetchPackageAwsRole, String awsRegion,
                          String filesLabBuildNumber = null) {
    String sanitizedVersion = buildBranch?.replaceAll("/", "-")?.replaceAll("%2F", "-") ?: ''
    String resolvedBranch = buildBranch ?: ''
    String resolvedBuildNumber = jenkinsBuildNumber
    String resolvedFilesLabBuildNumber = filesLabBuildNumber

    logger.info("Resolving package source for ${prefix}: ${sourceType}")

    if (sourceType == 'Direct URL' && directUrl) {
        try {
            def urlVersionMatch = directUrl =~ /${prefix}-([^-\/]+)-/
            if (urlVersionMatch) {
                String extractedVersion = urlVersionMatch[0][1]
                sanitizedVersion = extractedVersion
                resolvedBranch = extractedVersion
                logger.info("Extracted ${prefix} version from package URL: ${extractedVersion}")
            } else {
                logger.warn("Could not extract version from package URL: ${directUrl}")
            }
        } catch (Exception e) {
            logger.warn("Failed to extract ${prefix} version from package URL: ${e}. Using provided version.")
        }
    } else if (sourceType == 'Jenkins Branch' && jenkinsBranch) {
        String urlEncodedBranch = jenkinsBranch.replaceAll('/', '%2F')
        String actualBuildNumber = jenkinsBuildNumber
        Boolean isAgent = (prefix == 'NessusAgent')
        String s3Team = isAgent ? 'teams-nessus-agents' : 'teams-nessus'
        String s3Product = isAgent ? 'nessus-agents' : 'nessus'
        String s3Job = isAgent ? 'nessusagentrpmbuild' : 'nessus_build'
        String jenkinsTeam = isAgent ? 'teams-nessus-agents' : 'teams-nessus'
        String jenkinsFolder = isAgent ? 'nessus-agents' : 'nessus'

        if (jenkinsBuildNumber == 'latest') {
            logger.info("Querying Jenkins for latest build number on branch: ${jenkinsBranch}")
            try {
                withCredentials([
                    usernamePassword(credentialsId: 'cloudbees-service', passwordVariable: 'TOKEN', usernameVariable: 'USERNAME')
                ]) {
                    String jenkinsUrl = "https://cloudbees.eng.tenable.com/${jenkinsTeam}/job/${jenkinsFolder}/job/${s3Job}/job/${urlEncodedBranch}/lastSuccessfulBuild/buildNumber"
                    actualBuildNumber = sh(script: "curl -sf -u \"\${USERNAME}:\${TOKEN}\" '${jenkinsUrl}'", returnStdout: true).trim()
                    if (actualBuildNumber) {
                        logger.info("Latest build number for ${jenkinsBranch}: ${actualBuildNumber}")
                    } else {
                        error "Could not determine latest build number from Jenkins for branch ${jenkinsBranch}"
                    }
                }
            } catch (Exception e) {
                error "Failed to query Jenkins for latest build number on branch ${jenkinsBranch}: ${e}"
            }
        }

        resolvedBuildNumber = actualBuildNumber

        logger.info("Extracting ${prefix} version from S3 artifacts")
        try {
            withAWS(role: fetchPackageAwsRole, region: awsRegion) {
                String s3Path = "s3://tenb-jenkins-artefacts/${s3Team}/${s3Product}/${s3Job}/${urlEncodedBranch}/${actualBuildNumber}/artifacts/"
                String artifactFilename = sh(script: """aws s3 ls '${s3Path}' | grep -E '\\.rpm|\\.deb|\\.msi' | head -n 1 | awk '{print \$NF}'""", returnStdout: true).trim()
                if (artifactFilename) {
                    def versionMatch = artifactFilename =~ /${prefix}-([^-]+)-/
                    if (versionMatch) {
                        String extractedVersion = versionMatch[0][1]
                        sanitizedVersion = extractedVersion
                        resolvedBranch = extractedVersion
                        logger.info("Extracted ${prefix} version from S3 artifacts: ${extractedVersion}")
                    } else {
                        logger.warn("Could not extract version from artifact filename: ${artifactFilename}")
                    }
                } else {
                    logger.warn("No artifacts found in S3 path: ${s3Path}")
                }
            }
        } catch (Exception e) {
            logger.warn("Failed to extract ${prefix} version from S3 artifacts: ${e}. Using branch name as version.")
        }
    } else if (sourceType in ['Nessus Version', 'Agent Version']) {
        if (!resolvedFilesLabBuildNumber || resolvedFilesLabBuildNumber == 'latest') {
            String filesLabProduct = (prefix == 'NessusAgent') ? 'Agent' : 'Nessus'
            logger.info("Attempting to auto-detect latest build number from files.lab for ${filesLabProduct} version ${sanitizedVersion}")
            try {
                String filesLabUrl = "https://files.lab.tenablesecurity.com/pub/files/Products/${filesLabProduct}/${sanitizedVersion}/"
                def response = httpRequest url: filesLabUrl, validResponseCodes: '200'
                String content = response?.content ?: ""
                def matcher = (content =~ /href="([RX]?\d+)\//)
                List buildNumbers = matcher.collect { it[1] }
                if (buildNumbers && buildNumbers.size() > 0) {
                    buildNumbers.sort { a, b ->
                        Integer numA = (a =~ /\d+/)[0] as Integer
                        Integer numB = (b =~ /\d+/)[0] as Integer
                        numA <=> numB
                    }
                    resolvedFilesLabBuildNumber = buildNumbers[-1]
                    logger.info("Auto-detected latest build number from files.lab: ${resolvedFilesLabBuildNumber}")
                } else {
                    logger.warn("Could not auto-detect build number from files.lab directory listing")
                }
            } catch (Exception e) {
                logger.warn("Could not auto-detect build number from files.lab: ${e.message}")
            }
        }
    }

    logger.info("Resolved ${prefix} version: ${sanitizedVersion}")
    return [sanitizedVersion: sanitizedVersion, resolvedBranch: resolvedBranch, resolvedBuildNumber: resolvedBuildNumber, filesLabBuildNumber: resolvedFilesLabBuildNumber]
}

return this
