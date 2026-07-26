import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import Logs from '@/presentation/views/Logs.vue'
import logsService from '@/application/services/logsService'

vi.mock('@/application/services/logsService', () => ({
    default: { tail: vi.fn() }
}))

const jsonLine = (over = {}) => JSON.stringify({
    timestamp: '2026-07-19T10:00:00Z',
    level: 'INFO',
    event: 'sync_started',
    request_id: 'req-1',
    trace_id: 'tr-1',
    batch: 3,
    ...over,
})

describe('Logs.vue', () => {
    beforeEach(() => {
        vi.clearAllMocks()
    })

    it('carga y parsea logs JSON al montar (orden invertido: lo último primero)', async () => {
        logsService.tail.mockResolvedValue({
            data: { lines: [jsonLine(), 'linea de texto plano'] }
        })

        const wrapper = mount(Logs)
        await flushPromises()

        const rows = wrapper.findAll('tbody tr')
        expect(rows).toHaveLength(2)
        // reverse(): la línea de texto plano (última del archivo) queda primera
        expect(rows[0].text()).toContain('linea de texto plano')
        expect(rows[1].text()).toContain('sync_started')
        expect(rows[1].text()).toContain('req-1')
        // Los campos no estándar quedan en extra_preview
        expect(rows[1].text()).toContain('batch')
    })

    it('filtra por texto libre y por request_id', async () => {
        logsService.tail.mockResolvedValue({
            data: { lines: [jsonLine(), jsonLine({ event: 'sync_failed', request_id: 'req-2' })] }
        })

        const wrapper = mount(Logs)
        await flushPromises()
        expect(wrapper.findAll('tbody tr')).toHaveLength(2)

        await wrapper.find('input[placeholder="request_id or free text"]').setValue('sync_failed')
        expect(wrapper.findAll('tbody tr')).toHaveLength(1)
        expect(wrapper.find('tbody').text()).toContain('req-2')

        await wrapper.find('input[placeholder="request_id or free text"]').setValue('req-1')
        expect(wrapper.findAll('tbody tr')).toHaveLength(1)
        expect(wrapper.find('tbody').text()).toContain('sync_started')
    })

    it('el link del request_id fija el filtro y Limpiar lo quita', async () => {
        logsService.tail.mockResolvedValue({
            data: { lines: [jsonLine(), jsonLine({ request_id: 'req-2' })] }
        })

        const wrapper = mount(Logs)
        await flushPromises()

        await wrapper.find('tbody a').trigger('click')
        expect(wrapper.findAll('tbody tr')).toHaveLength(1)

        const buttons = wrapper.findAll('button')
        await buttons.find(b => b.text() === 'Limpiar').trigger('click')
        expect(wrapper.findAll('tbody tr')).toHaveLength(2)
    })

    it('el botón Actualizar vuelve a pedir los logs', async () => {
        logsService.tail.mockResolvedValue({ data: { lines: [jsonLine()] } })

        const wrapper = mount(Logs)
        await flushPromises()
        expect(logsService.tail).toHaveBeenCalledTimes(1)

        const buttons = wrapper.findAll('button')
        await buttons.find(b => b.text() === 'Actualizar').trigger('click')
        await flushPromises()
        expect(logsService.tail).toHaveBeenCalledTimes(2)
    })

    it('muestra el error como fila cuando el servicio falla', async () => {
        logsService.tail.mockRejectedValue(new Error('backend caido'))

        const wrapper = mount(Logs)
        await flushPromises()

        expect(wrapper.find('tbody').text()).toContain('Error: backend caido')
    })
})
