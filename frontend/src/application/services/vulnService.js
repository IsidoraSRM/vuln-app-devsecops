// src/application/services/vulnService.js
import apiClient from '../../infrastructure/http/apiClient';

export default {
    getVulns: async (params = {}) => {
        const queryParams = {}

        // Parámetros de control de paginación
        if (params.page !== undefined && params.page !== null) {
            queryParams.page = params.page
        }
        if (params.limit !== undefined && params.limit !== null) {
            queryParams.limit = params.limit
        }

        // Filtro de conexión raíz
        if (params.connectionId !== undefined && params.connectionId !== null) {
            queryParams.connection_id = params.connectionId
        }

        // Filtros combinados múltiples (arreglos)
        if (params.agent_name && params.agent_name.length > 0) {
            queryParams.agent_name = params.agent_name
        }
        if (params.cve_id && params.cve_id.length > 0) {
            queryParams.cve_id = params.cve_id
        }
        if (params.package_name && params.package_name.length > 0) {
            queryParams.package_name = params.package_name
        }
        if (params.severity && params.severity.length > 0) {
            queryParams.severity = params.severity
        }

        // Rangos de Score numérico
        if (params.score_min !== undefined && params.score_min !== null && params.score_min !== '') {
            queryParams.score_min = params.score_min
        }
        if (params.score_max !== undefined && params.score_max !== null && params.score_max !== '') {
            queryParams.score_max = params.score_max
        }

        // Criterios de ordenamiento
        if (params.sort_key) {
            queryParams.sort_key = params.sort_key
        }
        if (params.sort_order) {
            queryParams.sort_order = params.sort_order
        }

        return apiClient.get('/vulns', {
            params: queryParams,
        })
    },

    getUniqueFilters: async (connectionId = null) => {
        const params = {}
        if (connectionId !== null && connectionId !== undefined && connectionId !== '') {
            params.connection_id = connectionId
        }
        return apiClient.get('/vulns/filters', { params })
    },

    syncVulns: async () => {
        return apiClient.post('/vulns/sync-all')
    },
}
