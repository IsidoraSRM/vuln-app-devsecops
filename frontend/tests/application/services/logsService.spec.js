import { describe, it, expect, vi } from 'vitest'
import logsService from '@/application/services/logsService'
import apiClient from '@/infrastructure/http/apiClient'

vi.mock('@/infrastructure/http/apiClient', () => ({
    default: { get: vi.fn() }
}))

describe('logsService.js', () => {
    it('tail pide /logs con la cantidad de líneas indicada', async () => {
        apiClient.get.mockResolvedValueOnce({ data: { lines: [] } })

        await logsService.tail(50)

        expect(apiClient.get).toHaveBeenCalledWith('/logs?lines=50')
    })

    it('tail usa 200 líneas por defecto', async () => {
        apiClient.get.mockResolvedValueOnce({ data: { lines: [] } })

        await logsService.tail()

        expect(apiClient.get).toHaveBeenCalledWith('/logs?lines=200')
    })
})
