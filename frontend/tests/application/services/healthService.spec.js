import { describe, it, expect, vi } from 'vitest'
import healthService from '@/application/services/healthService'
import apiClient from '@/infrastructure/http/apiClient'

vi.mock('@/infrastructure/http/apiClient', () => ({
    default: { get: vi.fn() }
}))

describe('healthService.js', () => {
    it('getHealth consulta /health', async () => {
        apiClient.get.mockResolvedValueOnce({ status: 200, data: { status: 'ok' } })

        const res = await healthService.getHealth()

        expect(apiClient.get).toHaveBeenCalledWith('/health')
        expect(res.data.status).toBe('ok')
    })
})
