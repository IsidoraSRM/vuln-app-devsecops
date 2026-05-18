import os
import shutil
import re

base_path = r"c:\Users\Public\Desktop\DevSecOps\vuln-app-devsecops\vuln-api\app"

# 1. Rename files in schemas/
schema_files = {"auth.py": "authSchema.py", "user.py": "userSchema.py", "wazuh.py": "wazuhSchema.py"}
for old, new in schema_files.items():
    old_path = os.path.join(base_path, "schemas", old)
    new_path = os.path.join(base_path, "schemas", new)
    if os.path.exists(old_path):
        os.rename(old_path, new_path)

# 2. Rename files in routers/
router_files = {
    "auth.py": "authRouter.py", 
    "connections.py": "connectionsRouter.py", 
    "system.py": "systemRouter.py", 
    "users.py": "usersRouter.py", 
    "vulnerabilities.py": "vulnerabilitiesRouter.py"
}
for old, new in router_files.items():
    old_path = os.path.join(base_path, "routers", old)
    new_path = os.path.join(base_path, "routers", new)
    if os.path.exists(old_path):
        os.rename(old_path, new_path)

# 3. Rename files in services/
service_files = {"auth.py": "authService.py", "wazuh.py": "wazuhService.py"}
for old, new in service_files.items():
    old_path = os.path.join(base_path, "services", old)
    new_path = os.path.join(base_path, "services", new)
    if os.path.exists(old_path):
        os.rename(old_path, new_path)

# 4. Move old unstructured files to services
root_auth = os.path.join(base_path, "auth.py")
services_auth = os.path.join(base_path, "services", "authService.py")
if os.path.exists(root_auth) and os.path.exists(services_auth):
    # Combine both
    with open(root_auth, "r", encoding="utf-8") as f1, open(services_auth, "r", encoding="utf-8") as f2:
        combined = f1.read() + "\n\n" + f2.read()
    with open(services_auth, "w", encoding="utf-8") as f:
        f.write(combined)
    os.remove(root_auth)

root_wazuh_client = os.path.join(base_path, "wazuh_client.py")
services_wazuh_client = os.path.join(base_path, "services", "wazuhClientService.py")
if os.path.exists(root_wazuh_client):
    os.rename(root_wazuh_client, services_wazuh_client)

# 5. Fix imports in all python files
def replace_imports(filepath):
    if not os.path.exists(filepath): return
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    # Schemas
    content = content.replace("..schemas.auth import", "..schemas.authSchema import")
    content = content.replace("..schemas.user import", "..schemas.userSchema import")
    content = content.replace("..schemas.wazuh import", "..schemas.wazuhSchema import")

    # Services
    content = content.replace("..services.auth import", "..services.authService import")
    content = content.replace("..services.wazuh import", "..services.wazuhService import")
    
    # Old root files now in services
    content = content.replace("..auth import", "..services.authService import")
    content = content.replace(".auth import", ".services.authService import")
    content = content.replace("..wazuh_client import", "..services.wazuhClientService import")
    content = content.replace(".wazuh_client import", ".services.wazuhClientService import")
    
    # main.py routers
    content = content.replace(".routers import auth, users, connections, vulnerabilities, system", 
                              ".routers import authRouter, usersRouter, connectionsRouter, vulnerabilitiesRouter, systemRouter")
    content = content.replace("auth.router", "authRouter.router")
    content = content.replace("users.router", "usersRouter.router")
    content = content.replace("connections.router", "connectionsRouter.router")
    content = content.replace("vulnerabilities.router", "vulnerabilitiesRouter.router")
    content = content.replace("system.router", "systemRouter.router")

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)

# Apply replacements to all files
for root, dirs, files in os.walk(base_path):
    for file in files:
        if file.endswith(".py"):
            replace_imports(os.path.join(root, file))

print("Estructura y nombres corregidos.")
