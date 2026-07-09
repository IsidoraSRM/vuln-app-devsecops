from .baseProvider import VulnerabilityProvider
from .wazuhProvider import WazuhVulnerabilityProvider

class VulnerabilityProviderFactory:
    @staticmethod
    def get_provider(provider_type: str) -> VulnerabilityProvider:
        if provider_type.lower() == "wazuh":
            return WazuhVulnerabilityProvider()
        else:
            raise ValueError(f"Unknown provider type: {provider_type}")
