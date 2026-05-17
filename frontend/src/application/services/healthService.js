import apiClient from '../../infrastructure/http/apiClient';

export default {
    getHealth: async () => {
        return apiClient.get('/health');
    }
}
