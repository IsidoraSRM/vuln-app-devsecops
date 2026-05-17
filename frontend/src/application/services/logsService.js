import apiClient from '../../infrastructure/http/apiClient'

export default {
  tail: async (lines = 200) => {
    return apiClient.get(`/logs?lines=${lines}`)
  }
}
