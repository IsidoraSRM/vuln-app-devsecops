from typing import List, Dict, Any
from .baseProvider import VulnerabilityProvider
from .wazuhClientService import test_connection as wazuh_test, fetch_all_vulns as wazuh_fetch

class WazuhVulnerabilityProvider(VulnerabilityProvider):
    def test_connection(self, indexer_url: str, user: str, password_decrypted: str) -> bool:
        return wazuh_test(indexer_url, user, password_decrypted)

    def fetch_vulnerabilities(self, indexer_url: str, user: str, password_decrypted: str) -> List[Dict[str, Any]]:
        return wazuh_fetch(indexer_url, user, password_decrypted)
