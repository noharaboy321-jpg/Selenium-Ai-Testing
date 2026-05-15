Nessus Framework Readme
-----------------------
<img src="https://s3.amazonaws.com/cbosdal/monster_cat.png" alt="Logo" align="bottom" height="131" width="100" style="float: right">


### Documentation
Documentation is available on our [Confluence page](https://confluence.corp.tenablesecurity.com/display/AUTO/Development+Guidelines).  In cases where the documents do not agree, Confluence is considered to be the relevant documentation.

The [Automation Repositories Documentation](https://confluence.corp.tenablesecurity.com/display/AUTO/Automation+Repositories) is also a great resource to check out.

### Installation
The framework depends on many external dependency packages which must be installed in order for the framework to operate.

#### Environment
It is recommended that you install this framework into a [Python Virtual Environment](https://confluence.corp.tenablesecurity.com/display/AUTO/Setup+a+virtual+environment).

#### Development
Installing the framework using the command below is the **only supported method** of installation for development purposes.
```
python3 autosetup.py
```

##### Some Supported Arguments

| Argument | Description |
|:---------|:------------|
| --all    | Installs all subprojects and brings them up-to-date with the stable changes |
| --silent | Less verbosity |
| catium:B | Optional, install `catium` @ `stable` or @ `B` (i.e. branch) |
| product:B| Optional, install `product` @ `stable` or `B` (i.e. branch) |

Run python3 autosetup.py --help or see [Automatic Repository Setup Tool](https://confluence.corp.tenablesecurity.com/pages/viewpage.action?pageId=54638420) for more information

##### Example

<small>**Please DO NOT run this example**</small>

```bash
$ python autosetup.py nessus:release/6.11 lce:feature/CI-12345-analyze_tio_logs securitycenter:feature/CI-12345-tio_integration
```

### Setting PYTHONPATH

```
PYTHONPATH=.
export PYTHONPATH
```

This will enable modules - catium, nessus, lce, pvs and so on - from the root of repository to be imported.
If you have issues with imports like

```
ImportError: Error importing plugin "catium.plugins.monkeypatch": No module named 'catium'
```

first verify your PYTHONPATH has been set correctly and you are in root of your repository (e.g. automation-tenableio, automation-nessus etc. directory).


### Important Note: Browser Support
Currently, the framework only supports the Google Chrome browser.  Chrome
is defined as the default browser and should not generally be changed.

In order for tests to run locally, download the latest Chrome driver from
https://sites.google.com/a/chromium.org/chromedriver/ and copy the file
to a PATH that's defined in your shell.

On MacOS X, if you have Homebrew installed you may run `brew install chromedriver`


### Configuration
Simply set the CAT_SITE environment variable for any one of the sites specified in the
site_config.ini. Please have a look at the site-config.ini for the available sites.


If you need to alter the configuration for debugging it can be performed by specifying the
environmental variables below. Note that this should never be done in Bamboo CI runs and
test results for pull requests must use **CAT_SITE only**.


### Variables

Variables are documented in Confluence:
https://confluence.corp.tenablesecurity.com/display/AUTO/Environment+Variables

### Running Tests

Environment variables influence testing, with that said, the following rules apply.

Only use CAT_SITE for Bamboo CI runs. Test must be able to run without additional CAT_* environment variables.
For exceptions please talk first to core automation group to see if issue can be solved in other ways.


Tests should be stored in the nessus/tests/<test type> folder.

Sample UI Test
```
py.test nessus/tests/ui/groups/test_groups.py
```

Sample API Tests
```
py.test nessus/tests/api/unit/test_nessus_api_fixtures.py
```

Tests can also be run on-demand using `run_onDemand.py` which will prompt for the necessary information and use the correct environmental variables. This is handy for testing targets on the fly (i.e. during development) without having to remember every variable needed.

Note: when using the on-demand tool, if a target is in labvc1, make sure it's using a development network adapter (labeled development) when running UI tests so it can have proper access to Selenium GRID. This can be used AWS as well, but has to be run from an AWS host due to firewall rules.

### Learn More About Webium

Webium is a lightweight Selenium library in Python for managing the web driver, extending page objects and web elements.  We have forked Webium and are maintaining it ourselves as it has been abandoned by the authors.

https://www.youtube.com/watch?v=se9Uoh02gZk
https://github.com/wgnet/webium

### Debugging

Logging is the primary way to get insight into automation issues. Logging to file
is enabled by default and logs can be viewed in the following location:

```
output/logs
```

### Contacting the Automation Development team

* General automation mailing list automation@tenable.com
* Automation development team mailing list autodevteam@tenable.com

#### HipChat Rooms

| Room | Description |
|------|-------------|
| Automation Dev | General automation help |
| UI Automation Framework | UI automation help |
| API Automation Framework | API automation help |


### Environment Variables used

CAT_ACCESS_KEY                          AWS Access key Id
CAT_BROWSER                             UI browser
CAT_LOADING_CIRCLE_TIMEOUT              Time to wait for loading circle
CAT_LOCAL_BROWSER_DOWNLOAD_PATH         Path to download files locally
CAT_NESSUS_CLI_LOCAL                    Run CLI commands locally from test runner
CAT_NESSUS_DB_DIRECTORY                 Nessus DB file storage directory
CAT_NESSUS_DB_DOWNLOAD                  Enable Nessus DB download
CAT_NESSUS_DB_FILENAME                  Nessus DB exported filename
CAT_NESSUS_DB_PASSWORD                  Nessus DB password
CAT_NESSUS_DEBUG_TESTS                  not used
CAT_NESSUS_DIR                          not used
CAT_NESSUS_MANAGER_LINKING_KEY          Linking key for Nessus manager
CAT_NESSUS_PASSWORD                     Login password
CAT_NESSUS_PLATFORM                     Platform running Nessus
CAT_NESSUS_SCAN_NAME                    Scan name
CAT_NESSUS_URL                          Nessus URL
CAT_NESSUS_USERNAME                     Login username
CAT_NESSUS_VERSION                      not used
CAT_NESSUS_VERSION_NUMBER               not used
CAT_NESSUS_WARN_SLEEP                   Enable sleeping if loading circle detection fails
CAT_PASSWORD                            Login password
CAT_PLUGIN_FEED_HOST                    Licence generator host
CAT_PROXY_HOST                          Proxy host
CAT_PROXY_PASSWORD                      Proxy password
CAT_PROXY_PORT                          Proxy port
CAT_PROXY_USERNAME                      Proxy username
CAT_SECRET_ACCESS_KEY                   AWS access key secret
CAT_SSH_PASSWORD                        Paramiko SSH connection password
CAT_SSH_PORT                            Paramiko SSH connection port
CAT_SSH_USERNAME                        Paramiko SSH connection username
CAT_SSH_USE_SUDO                        Paramiko SSH: use sudo for shell commands
CAT_TIO_URL                             Tenable.IO URL
CAT_URL                                 Target hostname or IP
CAT_USERNAME                            Login username
CAT_USER_DOMAIN                         Domain for user creation
CAT_USE_GRID                            Use Selenium Grid
CAT_USE_SAUCE                           Use Saucelabs