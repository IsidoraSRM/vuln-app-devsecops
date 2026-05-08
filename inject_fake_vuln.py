import requests
from requests.auth import HTTPBasicAuth
import urllib3
import json

# Desactivar advertencias de certificados autofirmados
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INDEXER_URL = "https://localhost:9200"
WAZUH_USER = "admin"
WAZUH_PASSWORD = "SecretPassword"
INDEX_NAME = "wazuh-states-vulnerabilities-fake"

fake_vuln = {
  "agent": {
    "id": "999",
    "name": "Servidor-Prueba-Local"
  },
  "host": {
    "os": {
      "full": "Ubuntu 22.04 LTS",
      "platform": "ubuntu",
      "version": "22.04"
    }
  },
  "package": {
    "name": "openssl",
    "version": "1.1.1f-1ubuntu2",
    "type": "deb",
    "architecture": "amd64"
  },
  "vulnerability": {
    "id": "CVE-2026-99999",
    "severity": "Critical",
    "score": {
      "base": 9.8,
      "version": "CVSS3"
    },
    "detected_at": "2026-05-08T00:00:00Z",
    "published_at": "2026-01-01T00:00:00Z",
    "description": "Vulnerabilidad de prueba inyectada manualmente para verificar la interfaz.",
    "reference": "https://nvd.nist.gov/",
    "scanner": {
      "vendor": "Wazuh"
    }
  }
}

print("Inyectando vulnerabilidad falsa en OpenSearch...")

# Usamos POST para crear el documento en el índice inventado
url = f"{INDEXER_URL}/{INDEX_NAME}/_doc/1"

try:
    resp = requests.post(
        url,
        json=fake_vuln,
        auth=HTTPBasicAuth(WAZUH_USER, WAZUH_PASSWORD),
        verify=False,
        headers={"Content-Type": "application/json"}
    )
    
    if resp.status_code in [200, 201]:
        print("✅ ¡Vulnerabilidad falsa inyectada con éxito!")
        print("Ahora puedes ir a tu Frontend, presionar 'Sincronizar' y debería aparecer.")
    else:
        print(f"❌ Error al inyectar. Código: {resp.status_code}")
        print(resp.text)
        
except Exception as e:
    print(f"❌ Excepción: {e}")
