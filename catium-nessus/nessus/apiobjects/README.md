# Nessus API Objects

This module provides coverage of the Nessus API.

The Nessus API resides in a class named NessusAPI and an instance of this class contains the necessary API resources as
class attributes.

To name a couple:

* **.scans**
    * Interact with the 'scans' resource


* **.file**
    * Interact with the 'file' resource

---

#### Example Usage

```python
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.models.scan import ScanModel

def test_create_scan_from_model():
    """Verifies a Scan can created using a ScanModel object"""
    api = NessusAPI()
    api.login()
    scan_model = ScanModel.create_model()
    scan = api.scans.create(scan_model)
    assert scan.id is not None, 'No Scan ID'
    api.scans.delete(scan.id)
    api.logout()
```
