"""
Nessus Migration Endpoint
"""
from nessus.apiobjects import routes
from catium.lib import const
from catium.lib.api.base_api_object import ResponseObject

class MigrationEndpoint(object):
    """Migration API Endpoint"""

    def __init__(self, cls):
        self._cls = cls

    def status(self) -> ResponseObject:
        """
        Get migration status
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.MIGRATION)
        return ResponseObject(response)

    def start(self, data: dict) -> ResponseObject:
        """
        Begin migration
        """
        response = self._cls.request(const.HTTPMethods.POST, routes.MIGRATION, json=data)
        return ResponseObject(response)

    def end_migration(self, finish: str = 'false'):
        """
        End a migration effort
        """
        resource = '%s/?finish=%s' % (routes.MIGRATION, finish)
        response = self._cls.request(const.HTTPMethods.DELETE, resource)
        return ResponseObject(response)

    def configuration(self):
        """
        Get Migration configuration
        """
        resource = '%s/config' % (routes.MIGRATION)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def configure_scan_history_setting(self, data: dict):
        """
        configuration scan history setting for extended migration
        """
        resource = '%s/scan-history/upload-settings' % (routes.MIGRATION)
        response = self._cls.request(const.HTTPMethods.POST, resource, json=data)
        return ResponseObject(response)

    def start_scan_history_migration(self):
        """
        starts the scan history migration process
        """
        resource = '%s/scan-history/start-upload' % (routes.MIGRATION)
        response = self._cls.request(const.HTTPMethods.POST, resource)
        return ResponseObject(response)

    def get_histroy_migration_status(self):
        """
        returns the scan history migration status
        """
        resource = '%s/scan-history?' % (routes.MIGRATION)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def scanner_migration_status(self):
        """
        returns the migration status of scanner
        """
        resource = '%s/scanners' % (routes.MIGRATION)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def agent_migration_status(self):
        """
        returns the migration status of agent
        """
        resource = '%s/agents' % (routes.MIGRATION)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)
