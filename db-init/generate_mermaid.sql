-- ==============================================================================
-- Script: generate_mermaid.sql
-- Descripción: Genera dinámicamente el código de un diagrama ER en formato
--              Mermaid basándose en el esquema de tablas y relaciones de la BD.
-- Ejecución: Ejecute todo el script y copie el resultado de la consulta final.
-- ==============================================================================

CREATE OR REPLACE FUNCTION generate_mermaid_er() 
RETURNS TEXT AS $$
DECLARE
    r RECORD;
    col RECORD;
    rel RECORD;
    mermaid_text TEXT := 'erDiagram' || chr(10);
BEGIN
    -- Recorrer todas las tablas físicas del esquema público
    FOR r IN 
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public' 
          AND table_type = 'BASE TABLE'
        ORDER BY table_name
    LOOP
        mermaid_text := mermaid_text || '    ' || r.table_name || ' {' || chr(10);
        
        -- Recorrer las columnas de la tabla e identificar claves (PK, FK)
        FOR col IN 
            SELECT 
                c.column_name, 
                c.udt_name AS data_type,
                CASE WHEN pk.column_name IS NOT NULL THEN 'PK' ELSE '' END AS is_pk,
                CASE WHEN fk.column_name IS NOT NULL THEN 'FK' ELSE '' END AS is_fk
            FROM information_schema.columns c
            LEFT JOIN (
                SELECT kcu.table_name, kcu.column_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu
                  ON tc.constraint_name = kcu.constraint_name
                  AND tc.table_schema = kcu.table_schema
                WHERE tc.constraint_type = 'PRIMARY KEY' AND tc.table_schema = 'public'
            ) pk ON c.table_name = pk.table_name AND c.column_name = pk.column_name
            LEFT JOIN (
                SELECT DISTINCT kcu.table_name, kcu.column_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu
                  ON tc.constraint_name = kcu.constraint_name
                  AND tc.table_schema = kcu.table_schema
                WHERE tc.constraint_type = 'FOREIGN KEY' AND tc.table_schema = 'public'
            ) fk ON c.table_name = fk.table_name AND c.column_name = fk.column_name
            WHERE c.table_schema = 'public' AND c.table_name = r.table_name
            ORDER BY c.ordinal_position
        LOOP
            mermaid_text := mermaid_text || '        ' || col.data_type || ' ' || col.column_name;
            IF col.is_pk = 'PK' AND col.is_fk = 'FK' THEN
                mermaid_text := mermaid_text || ' PK,FK';
            ELSIF col.is_pk = 'PK' THEN
                mermaid_text := mermaid_text || ' PK';
            ELSIF col.is_fk = 'FK' THEN
                mermaid_text := mermaid_text || ' FK';
            END IF;
            mermaid_text := mermaid_text || chr(10);
        END LOOP;
        
        mermaid_text := mermaid_text || '    }' || chr(10);
    END LOOP;
    
    -- Agregar relaciones (Foreign Keys)
    FOR rel IN 
        SELECT DISTINCT
            kcu.table_name AS foreign_table,
            rel_kcu.table_name AS primary_table,
            kcu.column_name AS foreign_column
        FROM information_schema.table_constraints tco
        JOIN information_schema.key_column_usage kcu
          ON tco.constraint_schema = kcu.constraint_schema
          AND tco.constraint_name = kcu.constraint_name
        JOIN information_schema.referential_constraints rco
          ON tco.constraint_schema = rco.constraint_schema
          AND tco.constraint_name = rco.constraint_name
        JOIN information_schema.key_column_usage rel_kcu
          ON rco.unique_constraint_schema = rel_kcu.constraint_schema
          AND rco.unique_constraint_name = rel_kcu.constraint_name
          AND kcu.ordinal_position = rel_kcu.ordinal_position
        WHERE tco.constraint_type = 'FOREIGN KEY' AND tco.table_schema = 'public'
    LOOP
        mermaid_text := mermaid_text || '    ' || rel.primary_table || ' ||--o{ ' || rel.foreign_table || ' : "' || rel.foreign_column || '"' || chr(10);
    END LOOP;

    RETURN mermaid_text;
END;
$$ LANGUAGE plpgsql;

-- Ejecuta esta consulta para obtener el código Mermaid:
SELECT generate_mermaid_er() AS mermaid_diagram;
