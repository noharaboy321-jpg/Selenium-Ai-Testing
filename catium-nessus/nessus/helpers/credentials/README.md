# Credential Helpers

This module returns dictionaries that can be added to a ScanModel object.

- Supported Credentials
    - Cloud Services
    - Database
    - Host
    - Miscellaneous
    - Plaintext Authentication

#### NOTE

---

The CredentialHelper is built using Mixin classes. With that said, the Mixin classes should never be used directly.
Instead, please leverage the CredentialHelper class.

---

Sample code for creating a MySQL Database credential dictionary
```
from nessus.helpers.credentials.credential import CredentialHelper

CredentialHelper.Database.create_mysql_credential('admin', 'admin', 3306)

Returns:
{'password': 'automation',
 'port': 3306,
 'type': 'MYSQL',
 'username': 'MRRobot'}
```

Sample code for creating a CyberArk Host Credential dictionary
```
from nessus.helpers.credentials.credential import CredentialHelper

CredentialHelper.Host.create_ssh_cyberark_credential('root', 'domain', 'valut', '10', '10', verify_ssl=False)

Returns:
{'auth_method': 'CyberArk',
 'username': 'mr.robot',
 'vault_app_id': '10',
 'vault_elevate_privileges_with': 'Nothing',
 'vault_folder_id': '10',
 'vault_host': 'automation.dev',
 'vault_port': 443,
 'vault_safe': 'auto-sec-priv',
 'vault_use_ssl': 'yes',
 'vault_verify_ssl': 'no'}
```
