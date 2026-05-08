import requests
from requests.auth import HTTPBasicAuth
import urllib3
import json

# Desactivar advertencias de certificados autofirmados
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INDEXER_URL = "https://localhost:9200"
WAZUH_USER = "admin"
WAZUH_PASSWORD = "SecretPassword"

print("Intentando conectar al Wazuh Indexer local...")

try:
    resp = requests.get(
        INDEXER_URL,
        auth=HTTPBasicAuth(WAZUH_USER, WAZUH_PASSWORD),
        verify=False,
        timeout=10
    )
    
    if resp.status_code == 200:
        print("[EXITO] Conexion exitosa al Indexer!")
        
        # Ahora simulamos fetch_all_vulns()
        print("\nBuscando vulnerabilidades en el indice...")
        VULN_INDEX = "wazuh-states-vulnerabilities-*/_search"
        url = f"{INDEXER_URL}/{VULN_INDEX}"
        body = {"size": 10, "_source": True}
        
        resp_vuln = requests.post(
            url,
            json=body,
            auth=HTTPBasicAuth(WAZUH_USER, WAZUH_PASSWORD),
            verify=False,
            timeout=10
        )
        
        if resp_vuln.status_code == 200:
            hits = resp_vuln.json().get("hits", {}).get("hits", [])
            print(f"[EXITO] Busqueda exitosa. Se encontraron {len(hits)} registros de vulnerabilidades.\n")
            
            # Imprimir en texto plano (JSON formateado)
            if len(hits) > 0:
                print("=== VULNERABILIDADES EN TEXTO PLANO ===")
                for hit in hits:
                    source = hit.get("_source", {})
                    # Imprimir el JSON con sangria para que se lea facil
                    print(json.dumps(source, indent=4))
                    print("-" * 50)
            else:
                print("[INFO] Es normal que haya 0 ahora mismo si no has inyectado nada.")
        else:
            print(f"[ERROR] Error al buscar vulnerabilidades. Codigo: {resp_vuln.status_code}")
            
    else:
        print(f"[ERROR] Error de conexion. Codigo: {resp.status_code}")
        
except Exception as e:
    print(f"[ERROR] Excepcion durante la conexion: {e}")
