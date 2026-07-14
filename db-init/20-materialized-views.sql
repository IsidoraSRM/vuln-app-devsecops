-- Creación de Vistas Materializadas para Filtros
-- Estas vistas pre-calculan los valores únicos para los selectores del frontend.

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_unique_agents AS 
SELECT DISTINCT connection_id, agent_name FROM wazuh_vulnerabilities;

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_unique_cves AS 
SELECT DISTINCT connection_id, cve_id FROM wazuh_vulnerabilities;

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_unique_packages AS 
SELECT DISTINCT connection_id, package_name FROM wazuh_vulnerabilities;

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_unique_severities AS 
SELECT DISTINCT connection_id, severity FROM wazuh_vulnerabilities;

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_unique_os AS 
SELECT DISTINCT connection_id, os_platform, os_version FROM wazuh_vulnerabilities;

-- Creación del Procedimiento Almacenado (Function en PostgreSQL)
-- Llama a este procedimiento para refrescar todas las vistas de manera concurrente.

CREATE OR REPLACE FUNCTION refresh_vulnerability_filters() RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW mv_unique_agents;
    REFRESH MATERIALIZED VIEW mv_unique_cves;
    REFRESH MATERIALIZED VIEW mv_unique_packages;
    REFRESH MATERIALIZED VIEW mv_unique_severities;
    REFRESH MATERIALIZED VIEW mv_unique_os;
END;
$$ LANGUAGE plpgsql;
