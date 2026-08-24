-- 1. ÍNDICES PARA ALTA ESCALABILIDAD (1 Millón+ de registros)
-- Estos índices garantizan que los filtros sean de baja latencia.
CREATE INDEX IF NOT EXISTS idx_vuln_severity ON wazuh_vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vuln_status ON wazuh_vulnerabilities(status);
CREATE INDEX IF NOT EXISTS idx_vuln_os_platform ON wazuh_vulnerabilities(os_platform);
CREATE INDEX IF NOT EXISTS idx_vuln_first_seen ON wazuh_vulnerabilities(first_seen);
CREATE INDEX IF NOT EXISTS idx_vuln_agent_name ON wazuh_vulnerabilities(agent_name);
-- (status, first_seen): index-only scan para la "exposicion en curso" (antiguedad de las activas)
CREATE INDEX IF NOT EXISTS idx_vuln_status_first_seen ON wazuh_vulnerabilities(status, first_seen);

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

-- Filtro SOLO por Sistema Operativo
CREATE OR REPLACE FUNCTION sp_filter_by_os(p_os_platform TEXT) 
RETURNS TABLE(id INT, agent_name VARCHAR, cve_id TEXT, severity TEXT, os_platform TEXT, status VARCHAR, first_seen TIMESTAMP WITH TIME ZONE) AS $$
BEGIN
    RETURN QUERY SELECT v.id, v.agent_name, v.cve_id, v.severity, v.os_platform, v.status, v.first_seen
    FROM wazuh_vulnerabilities v WHERE v.os_platform ILIKE '%' || p_os_platform || '%';
END;
$$ LANGUAGE plpgsql;

-- Filtro SOLO por Agente
CREATE OR REPLACE FUNCTION sp_filter_by_agent(p_agent_name TEXT) 
RETURNS TABLE(id INT, agent_name VARCHAR, cve_id TEXT, severity TEXT, os_platform TEXT, status VARCHAR, first_seen TIMESTAMP WITH TIME ZONE) AS $$
BEGIN
    RETURN QUERY SELECT v.id, v.agent_name, v.cve_id, v.severity, v.os_platform, v.status, v.first_seen
    FROM wazuh_vulnerabilities v WHERE v.agent_name ILIKE '%' || p_agent_name || '%';
END;
$$ LANGUAGE plpgsql;

-- 3. PROCEDIMIENTO ALMACENADO GENERAL (Conectado a la API y Frontend)
-- Recibe arreglos (arrays) para soportar múltiples selecciones del frontend y devuelve la tabla completa.
--
-- IMPORTANTE (rendimiento a escala): esta función es LANGUAGE sql STABLE, NO plpgsql. Una función SQL
-- de un solo SELECT es INLINEABLE por el planner de PostgreSQL: cuando list_vulns hace
-- "... WHERE id IN (SELECT id FROM sp_filter_vulnerabilities(...))", el planner empuja los filtros a
-- los índices y NO materializa las filas. Con plpgsql (caja negra) el planner materializaba las 500k
-- filas COMPLETAS (todas las columnas) antes de contar -> el COUNT del dashboard tardaba segundos.
-- Medido a 500k: el count sin filtro pasó de ~800ms (plpgsql) a ~70ms (sql) = 12x; en prod, con filas
-- más anchas, la mejora es aún mayor (~6s -> sub-segundo). Sigue siendo un stored procedure.
CREATE OR REPLACE FUNCTION sp_filter_vulnerabilities(
    p_severities TEXT[] DEFAULT NULL,
    p_os_platforms TEXT[] DEFAULT NULL,
    p_statuses TEXT[] DEFAULT NULL,
    p_agent_names TEXT[] DEFAULT NULL,
    p_days_ago INT DEFAULT NULL
)
RETURNS SETOF wazuh_vulnerabilities
LANGUAGE sql STABLE AS $$
    SELECT v.*
    FROM wazuh_vulnerabilities v
    WHERE
        (p_severities IS NULL OR array_length(p_severities, 1) IS NULL OR UPPER(v.severity) = ANY(SELECT UPPER(unnest) FROM unnest(p_severities)))
        -- os_platform y agent_name: coincidencia EXACTA (= ANY) en vez de ILIKE '%x%'. El frontend
        -- manda valores exactos (checkbox/dropdown), y el '%' al inicio inutilizaba idx_vuln_os_platform
        -- e idx_vuln_agent_name -> seq scan de millones. Con = ANY el planner usa el indice (11s -> 90ms a 4M).
        AND (p_os_platforms IS NULL OR array_length(p_os_platforms, 1) IS NULL OR v.os_platform = ANY(p_os_platforms))
        AND (p_statuses IS NULL OR array_length(p_statuses, 1) IS NULL OR UPPER(v.status) = ANY(SELECT UPPER(unnest) FROM unnest(p_statuses)))
        AND (p_agent_names IS NULL OR array_length(p_agent_names, 1) IS NULL OR v.agent_name = ANY(p_agent_names))
        AND (p_days_ago IS NULL OR v.first_seen >= CURRENT_DATE - (p_days_ago || ' days')::interval);
$$;

