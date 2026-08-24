-- ==============================================================================
-- Script: drawsql_schema.sql
-- Descripción: Esquema DDL de PostgreSQL compatible con DrawSQL.
--              Copia y pega este contenido en: https://drawsql.app/draw?driver=pgsql
-- ==============================================================================

-- 1. Tabla de Servidores Wazuh
CREATE TABLE wazuh_connections (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    indexer_url VARCHAR(255) NOT NULL,
    wazuh_user VARCHAR(255) NOT NULL,
    wazuh_password VARCHAR(255) NOT NULL,
    provider_type VARCHAR(255) NOT NULL DEFAULT 'wazuh',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    tested BOOLEAN DEFAULT FALSE,
    last_tested_at TIMESTAMP WITH TIME ZONE,
    last_test_ok BOOLEAN
);

-- 2. Tabla de Usuarios
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT FALSE,
    is_default_password BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    role VARCHAR(255) DEFAULT 'superadmin',
    assigned_connection_id INTEGER REFERENCES wazuh_connections(id) ON DELETE SET NULL
);

-- 3. Tabla de Interacciones / Logs de Actividad de Usuarios
CREATE TABLE user_interactions (
    id SERIAL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    endpoint VARCHAR(255),
    method VARCHAR(50),
    details TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, timestamp)
);

-- 4. Tabla de Vulnerabilidades Sincronizadas
CREATE TABLE wazuh_vulnerabilities (
    id SERIAL PRIMARY KEY,
    connection_id INTEGER NOT NULL REFERENCES wazuh_connections(id) ON DELETE CASCADE,
    status VARCHAR(50) DEFAULT 'ACTIVE',
    agent_id VARCHAR(100) NOT NULL,
    agent_name VARCHAR(255),
    os_full TEXT,
    os_platform TEXT,
    os_version TEXT,
    package_name TEXT,
    package_version TEXT,
    package_type TEXT,
    package_arch TEXT,
    cve_id TEXT NOT NULL,
    severity TEXT,
    score_base NUMERIC,
    score_version TEXT,
    detected_at TIMESTAMP WITH TIME ZONE,
    published_at TIMESTAMP WITH TIME ZONE,
    description TEXT,
    reference TEXT,
    scanner_vendor TEXT,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uniq_wazuh_vuln UNIQUE (connection_id, agent_id, package_name, package_version, cve_id)
);

-- 5. Tabla de Historial / Auditoría de Vulnerabilidades
CREATE TABLE vulnerability_history (
    id SERIAL,
    vulnerability_id INTEGER NOT NULL REFERENCES wazuh_vulnerabilities(id) ON DELETE CASCADE,
    action VARCHAR(255) NOT NULL,
    details TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, timestamp)
);

-- 6. Tabla de Ejecuciones de Sincronización
CREATE TABLE sync_runs (
    id SERIAL PRIMARY KEY,
    connection_id INTEGER NOT NULL REFERENCES wazuh_connections(id) ON DELETE CASCADE,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
