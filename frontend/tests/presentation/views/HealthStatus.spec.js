import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import HealthStatus from '@/presentation/views/HealthStatus.vue'
import healthService from '@/application/services/healthService'

vi.mock('@/application/services/healthService', () => ({
    default: { getHealth: vi.fn() }
}))

describe('HealthStatus.vue', () => {
    beforeEach(() => {
        vi.clearAllMocks()
    })

    it('muestra Operativo cuando /health responde ok', async () => {
        healthService.getHealth.mockResolvedValue({ status: 200, data: { status: 'ok' } })

        const wrapper = mount(HealthStatus)
        await flushPromises()

        expect(wrapper.text()).toContain('Operativo')
        expect(wrapper.find('.status-dot').classes()).toContain('ok')
    })

    it('muestra Problemas con detalle cuando la respuesta no es ok', async () => {
        healthService.getHealth.mockResolvedValue({ status: 200, data: { status: 'degraded' } })

        const wrapper = mount(HealthStatus)
        await flushPromises()

        expect(wrapper.text()).toContain('Problemas')
        expect(wrapper.text()).toContain('degraded')
        expect(wrapper.find('.status-dot').classes()).toContain('fail')
    })

    it('muestra Problemas con el mensaje cuando el servicio lanza error', async () => {
        healthService.getHealth.mockRejectedValue(new Error('sin conexion'))

        const wrapper = mount(HealthStatus)
        await flushPromises()

        expect(wrapper.text()).toContain('Problemas')
        expect(wrapper.text()).toContain('sin conexion')
    })

    it('el botón Revisar ahora vuelve a consultar', async () => {
        healthService.getHealth.mockResolvedValue({ status: 200, data: { status: 'ok' } })

        const wrapper = mount(HealthStatus)
        await flushPromises()
        expect(healthService.getHealth).toHaveBeenCalledTimes(1)

        await wrapper.find('button').trigger('click')
        await flushPromises()
        expect(healthService.getHealth).toHaveBeenCalledTimes(2)
    })
})
