from typing import List, Dict, Any, Generator
from .baseProvider import VulnerabilityProvider
from .wazuhClientService import test_connection as wazuh_test, fetch_all_vulns as wazuh_fetch, iter_vulns_batches as wazuh_iter_batches

class WazuhVulnerabilityProvider(VulnerabilityProvider):
    def test_connection(self, indexer_url: str, user: str, password_decrypted: str) -> bool:
        return wazuh_test(indexer_url, user, password_decrypted)

    def fetch_vulnerabilities(self, indexer_url: str, user: str, password_decrypted: str) -> List[Dict[str, Any]]:
        return wazuh_fetch(indexer_url, user, password_decrypted)

    def fetch_vulnerabilities_batches(self, indexer_url: str, user: str, password_decrypted: str) -> Generator[List[Dict[str, Any]], None, None]:
        return wazuh_iter_batches(indexer_url, user, password_decrypted)
