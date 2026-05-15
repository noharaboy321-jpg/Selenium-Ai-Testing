"""
Nessus Scan Model
"""
from nessus.models.base_scan_model import BaseScanModel


class ScanModel(BaseScanModel):
    """Nessus Scan Model"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.default_template = 'Advanced Scan'

    @staticmethod
    def create_model():
        """Method to auto-generate a default ScanModel with required parameters"""
        return ScanModel(autogen=True)
