# CLAUDE.md — catium-nessus

## Repository Overview
**Repo:** catium-nessus
**Primary Language:** Python
**Purpose:** Automated testing for Nessus vulnerability scanner (UI, API, CLI)
**Test Framework:** pytest + Selenium/Webium (via Catium framework)

## Directory Layout

```
catium-nessus/
├── nessus/                      # Main automation framework
│   ├── apiobjects/              # REST API endpoint wrappers
│   │   ├── nessus_api.py        # Main NessusAPI client class
│   │   ├── routes.py            # Route constants
│   │   ├── xmlrpc_api.py        # XML-RPC API implementation
│   │   └── endpoints/           # Endpoint-specific classes
│   ├── pageobjects/             # Selenium page object models for UI
│   │   ├── basepage.py          # NessusBasePage — base class for all POs
│   │   ├── login/               # LoginPage
│   │   ├── scans/               # ScansPage, ScanList, ScanRecord, etc.
│   │   ├── policies/            # PoliciesPage, PolicyList, PolicyRecord
│   │   ├── users/               # UsersPage, UserList, UserRecord
│   │   ├── agents/              # AgentsPage, AgentsList
│   │   ├── sidenav/             # SideNav navigation component
│   │   ├── header/              # HeaderBasePage
│   │   ├── credentials/         # Credential configuration pages
│   │   ├── generic/             # Reusable generic components
│   │   └── ...
│   ├── helpers/                 # Utility modules
│   │   ├── scan.py              # Scan creation, launch, wait, export helpers
│   │   ├── waiters.py           # Wait-for-status helpers (scanner, scan, export)
│   │   ├── license.py           # License/registration management
│   │   ├── scanner.py           # Scanner linking/management
│   │   ├── agents.py            # Agent linking/management
│   │   ├── users.py             # User management helpers
│   │   ├── credentials/         # Credential builder helpers (SSH, DB, Cloud)
│   │   ├── audits/              # Audit configuration helpers (Cisco, VMware)
│   │   ├── dockernessus/        # Docker container management
│   │   └── ...
│   ├── models/                  # Data models for API requests
│   │   ├── base_object_model.py # NessusBaseObject (inherits catium BaseObject)
│   │   ├── base_scan_model.py   # BaseScanModel (100+ settings)
│   │   ├── scan.py              # ScanModel (extends BaseScanModel)
│   │   ├── policy.py            # PolicyModel
│   │   ├── user_model.py        # UserModelAPIMixin
│   │   ├── user.py              # UserModel (with factory method)
│   │   └── base_user_model.py   # Base user model
│   ├── plugins/                 # Custom pytest plugins
│   │   ├── fixtures/            # Fixture plugins
│   │   │   ├── login.py         # nessus_api_login fixture
│   │   │   ├── scans.py         # Scan creation/cleanup fixtures
│   │   │   ├── users.py         # User creation fixtures
│   │   │   ├── agents.py        # Agent fixtures
│   │   │   ├── policies.py      # Policy fixtures
│   │   │   └── ...
│   │   ├── deployment/          # Deployment-related plugins
│   │   └── version_marker/      # Version-based test markers
│   ├── lib/                     # Core library utilities
│   │   ├── const/               # Constants (API, Nessus, NessusCli)
│   │   ├── config/              # Configuration classes
│   │   └── ...
│   ├── controls/                # UI control abstractions
│   ├── commandline/             # CLI integration utilities
│   └── tests/                   # All test suites
│       ├── conftest.py          # Main conftest
│       ├── ui/                  # UI tests
│       │   ├── conftest.py      # UI conftest
│       │   └── ...
│       ├── api/                 # API tests
│       ├── nessuscli/           # CLI tests
│       ├── engine/              # Nessus engine tests
│       ├── docker/              # Docker deployment tests
│       ├── integration/         # Integration tests
│       ├── scan/                # Scan-specific tests
│       ├── sensor_proxy/        # Sensor proxy tests
│       ├── plugins/             # Plugin-related tests
│       ├── notarization/        # Notarization tests
│       └── utilities/           # Utility tests
├── pipelines/                   # Jenkins pipeline definitions
│   ├── ui_pipelines/            # UI test pipelines
│   ├── api_pipelines/           # API test pipelines
│   ├── nessuscli_pipelines/     # CLI test pipelines
│   ├── engine_pipelines/        # Engine test pipelines
│   └── ...
├── configuration/               # Build config & site settings
│   ├── buildchecks/             # Pre-commit checks, pylint config
│   └── site-configuration/      # Site-specific configurations
├── scripts/                     # Database & integration scripts
├── build_checks/                # Pre-commit validation tests
├── output/                      # Test execution logs/screenshots
├── pytest.ini                   # Pytest configuration with markers
├── requirements.txt             # Python dependencies
├── setup.py                     # Package setup
├── autosetup.py                 # Module loader for repo setup
├── run_onDemand.py              # Interactive test runner
└── run_target.py                # Target-specific test runner
```

## Test Organization

### Test Structure
- `nessus/tests/ui/<feature>/` — UI tests using page objects
- `nessus/tests/api/<endpoint>/` — API tests using NessusAPI
- `nessus/tests/nessuscli/` — CLI tests via SSH
- `nessus/tests/engine/` — Nessus engine tests
- `nessus/tests/docker/` — Docker deployment tests
- `nessus/tests/integration/` — Cross-feature integration tests
- `nessus/tests/scan/` — Scan-specific tests
- `nessus/tests/sensor_proxy/` — Sensor proxy tests
- `nessus/tests/plugins/` — Plugin-related tests

### UI Test Directories
`about`, `advanced_settings`, `agents`, `cluster`, `custom_ca`, `customized_reports`, `expert`, `groups`, `host_discovery_wizard`, `login`, `my_account`, `notifications`, `offline_mode`, `password_mgmt`, `plugin_rules`, `policies`, `profiles`, `registration`, `remote_link`, `resource_menu`, `scanner_health`, `scanners`, `scans`, `security_xss`, `server`, `session`, `setup_wizard`, `sidenav`, `software_update`, `unit`, `upgrade_assistant`, `users`

### API Test Directories
`agents`, `auth`, `blackout_window`, `cluster`, `editor`, `files`, `linked-scanner`, `migration`, `misc`, `multi-scanner`, `nessus_pro_7`, `nessus_qa`, `permissions`, `plugins`, `policy`, `profiles`, `registration`, `remote`, `reports`, `scan`, `scanner`, `scanner_health`, `server`, `settings`, `smoke`, `token_verification`, `unit`, `upgrade_downgrade`, `users`, `xmlrpc`, `zzz_nessusd`

### Test Discovery
- Pattern: `test_*.py` files with `Test*` classes and `test_*` methods
- Configuration in `pytest.ini`

## Page Objects

### Location
`nessus/pageobjects/<feature>/`

### Base Class
**File:** `nessus/pageobjects/basepage.py`

`NessusBasePage` inherits from `CATBasePage` (Catium framework):
- `open(**kwargs)` — Opens page URL using cat_registry routing
- `loaded(**kwargs)` — Checks if page is loaded, handles loading circles
- `wait_for_xhr_requests(timeout)` — Waits for AJAX requests to complete
- Uses `@cat_registry.route(r'...')` decorator for URL pattern routing
- Auto-hides notification divs via JavaScript injection

### Locator Patterns

Elements use `Find()` / `Finds()` decorators with Selenium `By` strategies:

```python
from catium.lib.webium import Find, Finds
from selenium.webdriver.common.by import By

# CSS Selector (most common)
sign_in_button = Find(by=By.CSS_SELECTOR, value='button[data-domselect="sign-in"]')

# CSS with typed control (TextField, CheckboxDiv, Clickable, Select2Dropdown)
username_field = Find(TextField, by=By.CSS_SELECTOR, value='.login-username')
remember_me = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='.login-remember')
delete_btn = Find(Clickable, by=By.ID, value='delete-bulk')
role_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='.new-user-permissions-select')

# XPath
new_scan_button = Find(by=By.XPATH, value='.//a[@href="#/scans/reports/new" and contains(@class, "button")]')

# By ID (default when no By specified)
save_button = Find(value='users-save-user')

# Multiple elements
sidenav_links = Finds(Link, by=By.CSS_SELECTOR, value='#sidenav a')

# Dynamic locators (constructed at runtime)
def get_scan_status(self, scan_name, scan_status):
    return Find(by=By.CSS_SELECTOR,
                value="tr[data-name='{}'] .scan-status.{}".format(scan_name, scan_status),
                context=self)
```

### Control Types
```python
from catium.lib.webium.controls.text_field import TextField       # .value = "text", .clear()
from catium.lib.webium.controls.checkbox_div import CheckboxDiv   # .check(), .uncheck(), .is_selected()
from catium.lib.webium.controls.click import Clickable            # .click()
from catium.lib.webium.controls.select2dropdown import Select2Dropdown  # .select_by_visible_text(text)
from catium.lib.webium.controls.table import GenericTableRow, GenericBaseTable
from catium.lib.webium.controls.link import Link
from catium.lib.webium.controls.date_picker import DatePicker
```

### Naming Conventions
- **Classes:** `{Name}Page`, `{Name}Modal`, `{Name}Record`, `{Name}List`
- **Locators:** `{action}_button`, `{field}_field`, `{item}_checkbox`, `{section}_tab`, `{item}_link`

### Key Page Objects

| Page Object | File | Route | Key Methods |
|-------------|------|-------|-------------|
| `NessusBasePage` | `basepage.py` | `''` | `open()`, `loaded()`, `wait_for_xhr_requests()` |
| `LoginPage` | `login/login_page.py` | `/#/` | `login_with_defaults()`, `login_with_credentials()`, `do_login()` |
| `ScansPage` | `scans/scans_page.py` | `scans` | `create_new_scan()`, `launch_scan()`, `copy_scan_to_selected_folder()` |
| `ScanList` | `scans/scan_list.py` | — | `get_all_scans()`, `select_scans()`, `launch_scan()`, `delete_scan()` |
| `ScanRecord` | `scans/scan_list.py` | — | `.scan_name`, `.scan_schedule`, `.scan_status`, `.launch_action_button` |
| `PoliciesPage` | `policies/policies_page.py` | `scans/policies` | `create_new_policy()`, `copy_policies()`, `delete_policies()` |
| `UsersPage` | `users/users_page.py` | `settings/users` | `add_new_user()`, `edit_user_account_settings()` |
| `AgentsPage` | `agents/agents_page.py` | `sensors/agents` | `create_group()`, `add_agents_to_group()` |
| `SideNav` | `sidenav/sidenav.py` | — | `get_sidenav_element()`, `delete_custom_folder()`, `rename_custom_folder()` |
| `HeaderBasePage` | `header/header_base.py` | — | `clear_notification_history()`, `click_by_link_text()` |
| `ActionCloseModal` | `generic/` | — | `accept_action()`, `wait_for_modal_closed()` |

### Page Object Usage Examples
```python
# Login
login_page = LoginPage()
login_page.login_with_defaults()
# Or static: LoginPage.do_login()

# Create and launch scan
scans_page = ScansPage()
scans_page.open()
scans_page.create_new_scan(
    scan_type='scanner',
    scan_template='Basic Network Scan',
    scan_name='My Scan',
    target_ip='192.168.1.1'
)
ScanList().launch_scan('My Scan')

# Navigate via sidenav
sidenav = SideNav()
sidenav.click_by_link_text('My Scans')
```

## API Objects

### Main API Class
**File:** `nessus/apiobjects/nessus_api.py`

```python
class NessusAPI(APIAuthorizationMixin, BaseApiObject):
    def __init__(self, login=False, logout=True, url=None):
        # Initializes all 26+ endpoint objects
        self.scans = ScansEndpoint(self)
        self.users = UsersEndpoint(self)
        self.agents = AgentsEndpoint(self)
        self.scanners = ScannersEndpoint(self)
        self.session = SessionEndpoint(self)
        self.folders = FoldersEndpoint(self)
        self.policies = PoliciesEndpoint(self)
        self.plugins = PluginsEndpoint(self)
        self.file = FileEndpoint(self)
        self.server = ServerEndpoint(self)
        # ... plus 16 more endpoints
```

### Endpoint Classes

| Endpoint | Class | File | Key Methods |
|----------|-------|------|-------------|
| `scans` | `ScansEndpoint` | `endpoints/scans.py` | `create(model)`, `configure(scan_id, payload)`, `copy()`, `delete()`, `compliance_output()` |
| `users` | `UsersEndpoint` | `endpoints/users.py` | `create(model/payload)`, `get(user_id)`, `edit()`, `delete_users(ids)` |
| `session` | `SessionEndpoint` | `endpoints/session.py` | `create(username, password)`, `delete()`, `password()`, `generate_keys()` |
| `agents` | `AgentsEndpoint` | `endpoints/agents.py` | `add_fake_agent()`, `get_agents()`, `delete_multiple(ids)` |
| `scanners` | `ScannersEndpoint` | `endpoints/scanners.py` | `edit()`, `get_linking_key()`, `get_agent_linking_key()` |
| `folders` | `FoldersEndpoint` | `endpoints/folders.py` | `create(name)`, `get_folders()`, `edit()`, `delete()` |
| `policies` | `PoliciesEndpoint` | `endpoints/policies.py` | `create()`, `configure()`, `copy()`, `delete()` |
| `plugins` | `PluginsEndpoint` | `endpoints/plugins.py` | `families()`, `family_details()`, `add_plugin_rules()`, `bulk_delete()` |
| `file` | `FileEndpoint` | `endpoints/file.py` | `upload(file, encrypted)` |
| `server` | `ServerEndpoint` | `endpoints/server.py` | `properties()`, `status()` |

Full list: `agent_groups`, `agents`, `clustergroups`, `editor`, `exclusions`, `file`, `folders`, `groups`, `mail`, `migration`, `misc`, `multi_scanner`, `nodes`, `passwordmgmt`, `permissions`, `plugin_locales`, `plugins`, `policies`, `profiles`, `registration`, `remote`, `reports`, `scanner_health`, `scanners`, `scans`, `server`, `session`, `settings`, `tokens`, `users`, `was`, `xmlrpc`

### Authentication Patterns
```python
# Session token auth (most common)
api = NessusAPI()
api.login(username='<username>', password='<password>')
# Sets X-Cookie: token=<session_token>
api.scans.get_scans()
api.logout()

# API keys auth
api = NessusAPI(login=False)
api.set_api_keys(access_key='...', secret_key='...')
# Sets X-ApiKeys: accessKey=...; secretKey=...

# Automation key (auto-added in __init__)
# Sets X-Automation-Key header
```

### Request/Response Patterns
```python
# All responses wrapped in ResponseObject (dict-like access)
response = api.users.create(model=user_model)
user_id = response['id']

# HTTP status available on api object
assert api.http_status_code == HTTPStatus.OK

# Model-based creation
scan_model = ScanModel(name='test', text_targets='192.168.1.1')
result = api.scans.create(scan_model)

# Raw payload creation
api.users.create(payload={'username': 'test', 'password': '<password>', 'permissions': 32})

# Error handling
with pytest.raises(HTTPError):
    api.users.create(payload=duplicate_user)
assert api.http_status_code == HTTPStatus.CONFLICT
```

### Endpoint Method Naming Convention
| HTTP Method | Pattern | Example |
|-------------|---------|---------|
| POST | `create(...)` | `api.users.create(model)` |
| GET (one) | `get(id)` or `details(id)` | `api.users.get(user_id)` |
| GET (many) | `get_<resources>()` | `api.folders.get_folders()` |
| PUT | `edit(id, ...)` or `configure(id, ...)` | `api.scans.configure(scan_id, payload)` |
| DELETE | `delete(id)` | `api.scans.delete(scan_id)` |
| DELETE (bulk) | `delete_<resources>(ids)` | `api.users.delete_users(user_ids)` |

## Test Framework

### pytest Configuration
From `pytest.ini`:
```ini
[pytest]
addopts = -v -s -rs
          -p "catium.plugins.monkeypatch"
          -p "catium.plugins.fixtures"
          -p "catium.plugins.catium_jira"
          -p "catium.plugins.maxskip"  --max_skip_perc 100
          -p "catium.plugins.user_agent"
          -p "nessus.plugins.deployment"
          --show-capture=no
```

### Auto-loaded Fixture Plugins
```python
pytest_plugins = [
    'nessus.plugins.fixtures.agents',
    'nessus.plugins.fixtures.nessus_plugins',
    'nessus.plugins.fixtures.policies',
    'nessus.plugins.fixtures.scans',
    'nessus.plugins.fixtures.users',
    'nessus.plugins.version_marker',
    'nessus.plugins.fixtures.api_handler',
    'nessus.plugins.fixtures.login',
    'nessus.plugins.fixtures.custom_ca',
    'nessus.plugins.fixtures.server',
    'nessus.plugins.fixtures.agents_new_endpoints',
    'nessus.plugins.fixtures.setting',
    'nessus.plugins.deployment.fixtures',
    'nessus.plugins.fixtures.xmlrpc',
    'nessus.plugins.fixtures.nessus_settings',
    'nessus.plugins.fixtures.system',
    'nessus.plugins.fixtures.was',
    'nessus.plugins.fixtures.profiles',
    'nessus.plugins.fixtures.locales',
]
```

### Markers

**Product Markers:**
- `@pytest.mark.nessus_pro` — Nessus Professional
- `@pytest.mark.nessus_expert` — Nessus Expert
- `@pytest.mark.nessus_manager` — Nessus Manager
- `@pytest.mark.nessus_essentials` — Nessus Essentials
- `@pytest.mark.nessus_home` — Nessus Home/Essentials (deprecated alias)
- `@pytest.mark.nessus_essentials_plus` — Nessus Essentials Plus
- `@pytest.mark.nessus_legacy` — Nessus Legacy
- `@pytest.mark.nessus_cli` — Nessus CLI tests
- `@pytest.mark.nessus_nasl` — Nessus NASL tests
- `@pytest.mark.nessus_agent` — Nessus Agent tests
- `@pytest.mark.sensor_manager` — Sensor Manager
- `@pytest.mark.sensor_proxy` — Sensor Proxy

**Test Type Markers:**
- `@pytest.mark.smoke` — Smoke test suite
- `@pytest.mark.extended_smoke` — Extended smoke tests
- `@pytest.mark.integration` — Integration tests
- `@pytest.mark.long_running` — Long-running tests
- `@pytest.mark.scanning` — Tests that perform scans
- `@pytest.mark.plugins` — Plugin tests
- `@pytest.mark.upload` — File upload tests
- `@pytest.mark.docker` — Docker tests
- `@pytest.mark.nessus_mat` — MAT tests for Nessus
- `@pytest.mark.nessus_engine` — Nessus engine tests
- `@pytest.mark.unittest` — Unit tests
- `@pytest.mark.sanity` — Catium sanity build tests

**Control Markers:**
- `@pytest.mark.disable_logout` — Disable automatic logout in fixtures
- `@pytest.mark.parallel` — Run in parallel
- `@pytest.mark.serial` — Run sequentially
- `@pytest.mark.skip_acceptance` — Skip in acceptance suite
- `@pytest.mark.linux_only` — Linux OS only
- `@pytest.mark.skip_centos7` / `skip_ubuntu` / `skip_oraclelinux8` / `skip_suse` — Platform skips
- `@pytest.mark.skip_nessustc` — Excluded for Tcore+Nessus OS
- `@pytest.mark.flaky_test` — Known flaky tests

**Feature Markers:**
- `@pytest.mark.agent` — Agent suite
- `@pytest.mark.controller` — Manager/controller
- `@pytest.mark.managed_scanner` — Managed scanner suite
- `@pytest.mark.cluster_manager` — Cluster manager
- `@pytest.mark.advanced_settings` — Advanced settings tests
- `@pytest.mark.scanner` — Scanner tests
- `@pytest.mark.license_change` — License change tests
- `@pytest.mark.offline_mode` — Offline mode tests
- `@pytest.mark.real_agent` — Tests using real agents
- `@pytest.mark.browser_file_download` — Browser file download tests

### Fixtures

**Main conftest:** `nessus/tests/conftest.py`
**UI conftest:** `nessus/tests/ui/conftest.py`
**Fixture plugins:** `nessus/plugins/fixtures/`

**Key fixtures:**

| Fixture | Scope | Source | Purpose |
|---------|-------|--------|---------|
| `login` | function | `conftest.py` | UI login — opens browser, logs in, handles wizard/banners, logs out on teardown |
| `nessus_api_login` | function | `plugins/fixtures/login.py` | API login — creates NessusAPI session, waits for READY status, logs out on teardown |
| `nessus_class_api_login` | class | `conftest.py` | Class-scoped API login — shared across test methods, stored in `request.cls.cat.api` |
| `driver_instance` | function | catium | Selenium WebDriver instance |
| `create_scan` | function | `plugins/fixtures/scans.py` | Creates a scan (parametrized), cleans up on teardown |
| `create_new_folder` | function | `conftest.py` | Creates scan folder, cleans up on teardown |
| `get_nessus_server_properties` | function | `conftest.py` | Returns server properties dict via API |
| `fresh_install_nessus` | function | `conftest.py` | Reinstalls Nessus fresh (parametrized by license type) |
| `delete_all_scans_in_nessus` | function | `conftest.py` | Deletes all scans via API |
| `empty_trash_and_create_or_import_bulk_scan` | function | `conftest.py` | Creates bulk scans, cleans up trash |
| `create_manager_cluster` | class | `conftest.py` | Creates Nessus cluster with nodes and agents |
| `link_scanner` | session | `conftest.py` | Links scanner to Tenable.io |

**Fixture usage patterns:**
```python
# UI test with login
@pytest.mark.usefixtures('login')
class TestMyFeature:
    cat = None
    def test_something(self):
        page = ScansPage()
        page.open()

# API test with login
@pytest.mark.usefixtures('nessus_api_login')
class TestMyAPI:
    cat = None
    def test_something(self, nessus_api_login):
        api = nessus_api_login
        result = api.scans.get_scans()

# Parametrized fixture (indirect)
@pytest.mark.parametrize('create_scan', [
    {"template_name": "Advanced Scan", "scan_type": "scanner"}
], indirect=True)
def test_with_scan(self, create_scan):
    scan_name, scan_id = create_scan

# Disable auto-logout
@pytest.mark.disable_logout
def test_session_handling(self, login):
    pass  # logout is skipped on teardown
```

## Helpers

### Location
`nessus/helpers/`

### Key Helpers

| Module | File | Key Functions |
|--------|------|---------------|
| **scan** | `helpers/scan.py` | `launch_scan()`, `create_scan_helper()`, `delete_scan_by_scan_id()`, `launch_scan_and_wait_for_completion()`, `download_scan()`, `empty_trash_folder()`, `save_and_configure_scan()`, `get_severity_count_from_scan_result()` |
| **waiters** | `helpers/waiters.py` | `wait_for_scanner_status()`, `wait_for_plugins()`, `wait_for_scan()`, `wait_scan_state()`, `wait_for_export_to_complete()`, `wait_for_scanner_login()`, `wait_for_scanner_restart()`, `wait_for_scanner_to_link()` |
| **license** | `helpers/license.py` | `get_activation_code()`, `remove_nessus_registration()`, `start_nessus_and_wait_till_it_becomes_ready()`, `close_welcome_nessus_10_modal_for_pro()` |
| **scanner** | `helpers/scanner.py` | `link_scanner_to_cloud()`, `unlink_scanner_to_cloud()`, `create_scanner()`, `restart_scanner()`, `wait_for_scanner_to_be_ready()` |
| **agents** | `helpers/agents.py` | `choose_agent_info()`, `check_agent_linked()`, `get_online_linked_agent()`, `get_agent_id_from_list()`, `create_freeze_window_via_api()` |
| **users** | `helpers/users.py` | User management helpers |
| **policy** | `helpers/policy.py` | Policy creation/management helpers |
| **editor** | `helpers/editor.py` | Template editor helpers |
| **credentials/** | `helpers/credentials/` | SSH, DB, Cloud credential builders |
| **audits/** | `helpers/audits/` | Audit config helpers (Cisco, VMware, Palo Alto) |
| **nessuscli/** | `helpers/nessuscli/` | CLI command helpers: `get_nessus_cli()`, `path_join()`, `get_nessus_var_dir()` |

### Helper Usage Examples
```python
from nessus.helpers.scan import launch_scan, create_scan_helper, delete_scan_by_scan_id
from nessus.helpers.waiters import wait_for_scanner_status, wait_for_plugins, wait_for_scan
from nessus.helpers.license import get_activation_code

# Launch scan and wait
launch_scan_and_wait_for_completion(api, scan_id, timeout_seconds=TIME_TEN_MINUTES)

# Wait for scanner to be ready
wait_for_scanner_status(api, status='ready', timeout=TIME_THIRTY_MINUTES, msg='Scanner to be ready')

# Create scan from template
scan_name, scan_id = create_scan_helper(api, file_name='template.nessus',
                                         template_title='Advanced Scan')
```

## Models

### Location
`nessus/models/`

### Key Models

| Model | File | Purpose |
|-------|------|---------|
| `NessusBaseObject` | `base_object_model.py` | Base class inheriting catium's `BaseObject` |
| `BaseScanModel` | `base_scan_model.py` | 100+ scan settings, credentials, audits, SCAP config; `create_payload()` serializer |
| `ScanModel` | `scan.py` | Extends `BaseScanModel`, default template = "Advanced Scan"; `create_model()` factory |
| `PolicyModel` | `policy.py` | Policy UUID, settings dict, credentials dict; `create_model()` factory |
| `UserModel` | `user.py` | User fields with `fields.Integer/String/Boolean`; `factory()` classmethod; `create()`/`delete()` API methods |
| `UserModelAPIMixin` | `user_model.py` | Mixin providing `create_payload()`, `create()`, `delete()` via API session context manager |

### Model Usage
```python
# Scan model
from nessus.models.scan import ScanModel
scan_model = ScanModel(name='My Scan', text_targets='192.168.1.1')
scan_model.add_ssh_credential({'auth_method': 'password', 'username': '<username>', 'password': '<password>'})
scan_model.enable_plugins([12345, 67890])
result = api.scans.create(scan_model)

# Auto-generated model
scan_model = ScanModel.create_model()

# User model
from nessus.models.user import UserModel
user = UserModel.factory(username='testuser', permissions=32)
user, response = user.create(api_session=api)

# Policy model
from nessus.models.policy import PolicyModel
policy = PolicyModel.create_model()
```

## Test Data

### Locations
- `nessus/tests/ui/scans/test_data/` — Scan-related test data
- `nessus/tests/ui/test_data/` — Shared UI test data
- `nessus/tests/api/nessus_qa/test_data/` — API test data (JSON payloads)
- `nessus/tests/api/scan/test_data/` — Scan API test data
- `nessus/tests/nessuscli/helpers/` — CLI test helpers/data

### Types
- `.json` — Test configuration, API payload templates, fixture data
- `.nessus` — Nessus scan export files for import testing
- `.db` — Scan database exports (encrypted, see test data fixtures for passwords)
- `.nasl` — NASL audit scripts
- `.audit` — Compliance audit files
- `.gz` — Compressed test archives
- `.sig` — Signature files
- `.pem`, `.crt`, `.key` — Certificate/key files for SSL testing

### How Test Data is Loaded
```python
# Via parametrized fixtures
@pytest.mark.parametrize('test_data_file',
    ['nessus/tests/api/nessus_qa/test_data/test_nessus_users.json'])
@pytest.mark.usefixtures('load_test_data')
class TestNessusUsers:
    ...

# Via helper functions
from catium.helpers.testdata import get_file_path
file_path = get_file_path('nessus/tests/ui/scans/test_data/Basic_Network_Scan_Result.db')

# Via indirect parametrize for scan import
@pytest.mark.parametrize('import_scan_file', [
    {"filename": 'Basic_Network_Scan_Result.db',
     "scan_file_path": 'nessus/tests/ui/scans/test_data/',
     "password": 'nessus'}
], indirect=True)
```

## Run Commands

### All tests
```bash
pytest nessus/tests/
```

### By test type
```bash
# UI tests
pytest nessus/tests/ui/
pytest nessus/tests/ui/scans/
pytest nessus/tests/ui/login/

# API tests
pytest nessus/tests/api/
pytest nessus/tests/api/scan/
pytest nessus/tests/api/users/

# CLI tests
pytest nessus/tests/nessuscli/

# Engine tests
pytest nessus/tests/engine/
```

### By marker
```bash
pytest -m nessus_pro
pytest -m nessus_expert
pytest -m nessus_manager
pytest -m smoke
pytest -m "smoke and nessus_pro"
pytest -m scanning
pytest -m nessus_cli
pytest -m nessus_engine
```

### Specific test file or class
```bash
pytest nessus/tests/ui/scans/test_scans_main_page.py
pytest nessus/tests/api/nessus_qa/test_nessus_users.py::TestNessusUsers
pytest nessus/tests/api/nessus_qa/test_nessus_users.py::TestNessusUsers::test_create_user
```

## Golden Samples

### UI Test
**File:** `nessus/tests/ui/scans/test_scans_main_page.py`
**Why chosen:** 50+ test methods, comprehensive page object usage (ScansPage, ScanList, SideNav), parametrized fixtures, compound assertions, representative of typical UI tests.

**Key patterns:**
```python
import pytest
from nessus.pageobjects.scans.scans_page import ScansPage, ScanList
from nessus.pageobjects.sidenav.sidenav import SideNav
from nessus.lib.const import API, Nessus

@pytest.mark.scans_2
@pytest.mark.nessus_home
@pytest.mark.nessus_expert
@pytest.mark.usefixtures('login')
class TestScansMainPage:
    cat = None

    def test_visibility_of_default_elements(self):
        scans_page = ScansPage()
        LoadingCircle(WAIT_SHORT)
        assert scans_page.get_page_heading == Nessus.Scan.Folder.MY_SCANS.split(' (')[0]

    @pytest.mark.parametrize("create_scan", [
        {"template_name": Nessus.TemplateNames.ADVANCED,
         "scan_type": API.Permissions.Types.SCANNER}
    ], indirect=True)
    def test_with_parametrized_scan(self, create_scan):
        scan_list = ScanList()
        assert scan_list.get_all_scans()
```

### API Test
**File:** `nessus/tests/api/nessus_qa/test_nessus_users.py`
**Why chosen:** Complete CRUD testing, model usage (UserModel), HTTP status validation, error handling with `pytest.raises(HTTPError)`, parametrized fixtures, positive and negative scenarios.

**Key patterns:**
```python
from http import HTTPStatus
from requests import HTTPError
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.models.user import UserModel
from nessus.lib.const import API

@pytest.mark.nessus_manager
@pytest.mark.smoke
@pytest.mark.usefixtures('nessus_api_login', 'load_test_data')
class TestNessusUsers:
    cat = None

    def test_create_user(self):
        user_data = {"username": random_name(prefix="user-"), "password": "pass",
                     "permissions": 16, "type": "local"}
        self.cat.api.users.create(payload=user_data)
        assert self.cat.api.http_status_code == HTTPStatus.OK

    def test_duplicate_user_error(self, nessus_create_parametrized_user):
        with pytest.raises(HTTPError):
            self.cat.api.users.create(UserModel(
                username=nessus_create_parametrized_user['name'],
                password=self.cat.nessus_password))
        assert self.cat.api.http_status_code == HTTPStatus.CONFLICT
```

### CLI Test
**File:** `nessus/tests/nessuscli/test_nessuscli_commands.py`
**Why chosen:** Demonstrates CLI execution via SSH, output parsing with regex, platform-specific paths, parametrized product markers.

**Key patterns:**
```python
import re
from catium.lib.ssh.ssh import SSH
from nessus.helpers.nessuscli.helper import get_nessus_cli
from nessus.lib.const.constants import NessusCli

@pytest.mark.nessus_mat
@pytest.mark.nessus_cli
class TestNessuscliHelpCommand:

    @pytest.mark.parametrize('license_type', [
        pytest.param("Nessus Professional", marks=(pytest.mark.nessus_pro)),
        pytest.param("Nessus Essentials", marks=(pytest.mark.nessus_home))
    ])
    def test_nessus_help_command(self, help_cmd_list, license_type):
        with SSH() as ssh:
            output = ssh.execute(command=f"{get_nessus_cli()} --help", sudo=True)
            for cmd_keyword in help_cmd_list:
                assert NessusCli.NessuscliHelp.HELP_CMD_VALIDATIONS[cmd_keyword] == [
                    cmd for cmd in output if cmd_keyword in cmd
                ]
```

## Code Generation Guidelines

When implementing tests from XRAY JSON:

### For UI tests:
1. Use page objects from `nessus/pageobjects/`
2. Follow golden UI test structure (class-based, `cat = None`)
3. Use `@pytest.mark.usefixtures('login')` for UI auth
4. Use `LoadingCircle()` before interacting with elements
5. Use `wait_for_xhr_requests()` after page transitions
6. Import helpers from `nessus/helpers/`
7. Add product markers: `@pytest.mark.nessus_pro`, `@pytest.mark.nessus_expert`, etc.

### For API tests:
1. Use `NessusAPI` and endpoint classes from `nessus/apiobjects/`
2. Follow golden API test structure
3. Use `@pytest.mark.usefixtures('nessus_api_login')` for API auth
4. Access API via `self.cat.api` (set by fixture) or `nessus_api_login` fixture arg
5. Use models from `nessus/models/` for structured requests
6. Assert `self.cat.api.http_status_code` for status validation
7. Use `pytest.raises(HTTPError)` for expected error responses

### For CLI tests:
1. Use `SSH()` context manager for remote command execution
2. Use `get_nessus_cli()` for CLI path
3. Parse output with regex or string matching
4. Constants in `nessus.lib.const.constants.NessusCli`

### Common patterns:
- Add appropriate pytest markers (product + test type)
- Use helpers for common operations (scan, wait, license)
- Include `cat = None` class attribute for fixture injection
- Use indirect parametrize for fixture configuration
- Include cleanup in fixture teardown (yield pattern)
- Use `from nessus.lib.const import API, Nessus` for constants

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `CAT_URL` / `CAT_NESSUS_URL` | Nessus server URL |
| `CAT_NESSUS_USERNAME` | Login username |
| `CAT_NESSUS_PASSWORD` | Login password |
| `CAT_TIO_URL` | Tenable.io URL |
| `CAT_PROXY_*` | Proxy settings |
| `DOCKER_REGISTRY` | Docker registry for containers |
| `DOCKER_NETWORK` | Docker network name |

## Additional Notes
- The framework is built on top of **Catium** (catium-core), which provides base classes for API objects, page objects, Selenium/Webium integration, SSH, and test infrastructure.
- Page objects use `@cat_registry.route()` decorator for URL pattern-based routing.
- The `ResponseObject` returned by API calls supports dict-like access (e.g., `response['id']`).
- Test classes use `cat = None` as a class attribute; fixtures inject the API session via `request.cls.cat.api` or `request.instance.cat.api`.
- The `LoadingCircle()` call is used to wait for UI loading spinners to disappear before interacting with elements.
- `wait()` from catium accepts `predicate` (lambda), `timeout_seconds`, `sleep_seconds`, and `waiting_for` (description string).
- Constants are centralized in `nessus.lib.const` — use `API.*` for API constants, `Nessus.*` for product constants, `NessusCli.*` for CLI constants.
