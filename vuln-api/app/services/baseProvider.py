from abc import ABC, abstractmethod
from typing import List, Dict, Any

class VulnerabilityProvider(ABC):
    @abstractmethod
    def test_connection(self, indexer_url: str, user: str, password_decrypted: str) -> bool:
        """Test connection to the provider's data source."""
        pass

    @abstractmethod
    def fetch_vulnerabilities(self, indexer_url: str, user: str, password_decrypted: str) -> List[Dict[str, Any]]:
        """Fetch raw vulnerabilities from the provider's data source."""
        pass
