-- 1. ÍNDICES PARA ALTA ESCALABILIDAD (1 Millón+ de registros)
-- Estos índices garantizan que los filtros sean de baja latencia.
CREATE INDEX IF NOT EXISTS idx_vuln_severity ON wazuh_vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vuln_status ON wazuh_vulnerabilities(status);
CREATE INDEX IF NOT EXISTS idx_vuln_os_platform ON wazuh_vulnerabilities(os_platform);
CREATE INDEX IF NOT EXISTS idx_vuln_first_seen ON wazuh_vulnerabilities(first_seen);

-- 2. PROCEDIMIENTOS ALMACENADOS INDIVIDUALES (Para máxima modularidad)

-- Filtro SOLO por Criticidad
CREATE OR REPLACE FUNCTION sp_filter_by_severity(p_severity TEXT) 
RETURNS TABLE(id INT, agent_name VARCHAR, cve_id TEXT, severity TEXT, os_platform TEXT, status VARCHAR, first_seen TIMESTAMP WITH TIME ZONE) AS $$
BEGIN
    RETURN QUERY SELECT v.id, v.agent_name, v.cve_id, v.severity, v.os_platform, v.status, v.first_seen
    FROM wazuh_vulnerabilities v WHERE UPPER(v.severity) = UPPER(p_severity);
END;
$$ LANGUAGE plpgsql;

-- Filtro SOLO por Estado
CREATE OR REPLACE FUNCTION sp_filter_by_status(p_status TEXT) 
RETURNS TABLE(id INT, agent_name VARCHAR, cve_id TEXT, severity TEXT, os_platform TEXT, status VARCHAR, first_seen TIMESTAMP WITH TIME ZONE) AS $$
BEGIN
    RETURN QUERY SELECT v.id, v.agent_name, v.cve_id, v.severity, v.os_platform, v.status, v.first_seen
    FROM wazuh_vulnerabilities v WHERE UPPER(v.status) = UPPER(p_status);
END;
$$ LANGUAGE plpgsql;

-- 3. PROCEDIMIENTO ALMACENADO GENERAL (Combina múltiples filtros dinámicamente)
-- Este procedimiento aprovecha los índices creados arriba.
CREATE OR REPLACE FUNCTION sp_filter_vulnerabilities(
    p_severity TEXT DEFAULT NULL,
    p_os_platform TEXT DEFAULT NULL,
    p_status TEXT DEFAULT NULL,
    p_days_ago INT DEFAULT NULL
) 
RETURNS TABLE (
    id INT,
    agent_name VARCHAR,
    cve_id TEXT,
    severity TEXT,
    os_platform TEXT,
    status VARCHAR,
    first_seen TIMESTAMP WITH TIME ZONE
) AS $$
BEGIN
    RETURN QUERY 
    SELECT 
        v.id, 
        v.agent_name, 
        v.cve_id, 
        v.severity, 
        v.os_platform, 
        v.status, 
        v.first_seen
    FROM 
        wazuh_vulnerabilities v
    WHERE 
        (p_severity IS NULL OR UPPER(v.severity) = UPPER(p_severity))
        AND (p_os_platform IS NULL OR v.os_platform ILIKE '%' || p_os_platform || '%')
        AND (p_status IS NULL OR UPPER(v.status) = UPPER(p_status))
        AND (p_days_ago IS NULL OR v.first_seen >= CURRENT_DATE - (p_days_ago || ' days')::interval);
END;
$$ LANGUAGE plpgsql;


