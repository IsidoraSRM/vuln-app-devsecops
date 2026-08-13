import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import Metrics from '@/presentation/views/Metrics.vue'
import apiClient from '@/infrastructure/http/apiClient'

vi.mock('@/infrastructure/http/apiClient', () => ({
    default: { get: vi.fn() }
}))

describe('Metrics.vue', () => {
    beforeEach(() => {
        vi.clearAllMocks()
    })

    it('carga y muestra las métricas al montar, con promedio de sync calculado', async () => {
        // El backend expone sync_duration_ms (milisegundos); la UI lo muestra en segundos.
        apiClient.get.mockResolvedValue({
            data: {
                vulnerabilities_detected_total: 42,
                login_attempts_total: 10,
                sync_duration_ms_count: 2,
                sync_duration_ms_sum: 10000,
            }
        })

        const wrapper = mount(Metrics)
        await flushPromises()

        expect(apiClient.get).toHaveBeenCalledWith('/metrics-summary')
        expect(wrapper.text()).toContain('42')
        // mean = 10000 ms / 2 / 1000 = 5.000 s
        expect(wrapper.text()).toContain('5.000')
    })

    it('sin syncs el promedio queda vacío (no divide por cero)', async () => {
        apiClient.get.mockResolvedValue({
            data: { sync_duration_ms_count: 0, sync_duration_ms_sum: 0 }
        })

        const wrapper = mount(Metrics)
        await flushPromises()

        expect(wrapper.text()).toContain('Sync promedio')
    })

    it('el botón Actualizar vuelve a pedir métricas y tolera errores', async () => {
        apiClient.get.mockResolvedValueOnce({ data: {} })
        apiClient.get.mockRejectedValueOnce(new Error('server down'))

        const wrapper = mount(Metrics)
        await flushPromises()

        await wrapper.find('button').trigger('click')
        await flushPromises()

        expect(apiClient.get).toHaveBeenCalledTimes(2)
    })
})
