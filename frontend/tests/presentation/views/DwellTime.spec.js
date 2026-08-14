import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import DwellTime from '@/presentation/views/DwellTime.vue'
import vulnService from '@/application/services/vulnService'
import wazuhService from '@/application/services/wazuhService'

vi.mock('@/application/services/vulnService', () => ({ default: { getDwellTime: vi.fn() } }))
vi.mock('@/application/services/wazuhService', () => ({ default: { getConnections: vi.fn() } }))

// chart.js no puede renderizar en jsdom (no hay canvas real) -> se mockea
vi.mock('chart.js', () => {
    const Chart = vi.fn(() => ({ destroy: vi.fn() }))
    Chart.register = vi.fn()
    return { Chart, registerables: [] }
})

describe('DwellTime.vue', () => {
    beforeEach(() => {
        vi.clearAllMocks()
        wazuhService.getConnections.mockResolvedValue({ data: [] })
    })

    it('pide el dwell-time y muestra KPIs, SLA y exposición en curso cuando hay datos', async () => {
        vulnService.getDwellTime.mockResolvedValue({
            data: {
                overall: { count: 5, avg_days: 12.3, median_days: 10, p90_days: 20, min_days: 1, max_days: 30 },
                by_severity: { CRITICAL: { count: 2, median_days: 8 } },
                monthly_trend: [{ month: '2026-01', resolved_count: 5, avg_days: 12.3 }],
                sla: {
                    targets: { CRITICAL: 15 },
                    overall: { within: 4, total: 5, pct: 80 },
                    by_severity: { CRITICAL: { within: 2, total: 2, pct: 100, target_days: 15 } },
                },
                active_exposure: {
                    overall: { count: 7, avg_days: 40, max_days: 120, over_30: 5, over_90: 2 },
                    by_severity: {},
                },
            }
        })

        const wrapper = mount(DwellTime)
        await flushPromises()

        expect(vulnService.getDwellTime).toHaveBeenCalled()
        // Remediación
        expect(wrapper.text()).toContain('Mediana')
        expect(wrapper.text()).toContain('10')       // mediana
        expect(wrapper.text()).toContain('Remediadas')
        expect(wrapper.find('canvas').exists()).toBe(true)
        // SLA
        expect(wrapper.text()).toContain('Cumplimiento de SLA')
        expect(wrapper.text()).toContain('80')       // % global SLA
        // Exposición en curso
        expect(wrapper.text()).toContain('Exposición en curso')
        expect(wrapper.text()).toContain('Activas')
    })

    it('muestra estado vacío cuando no hay vulnerabilidades remediadas', async () => {
        vulnService.getDwellTime.mockResolvedValue({
            data: { overall: { count: 0 }, by_severity: {}, monthly_trend: [] }
        })

        const wrapper = mount(DwellTime)
        await flushPromises()

        expect(wrapper.text()).toContain('Sin vulnerabilidades remediadas')
        expect(wrapper.find('canvas').exists()).toBe(false)
    })

    it('tolera errores del servicio sin romperse', async () => {
        vulnService.getDwellTime.mockRejectedValue(new Error('backend caido'))

        const wrapper = mount(DwellTime)
        await flushPromises()

        expect(wrapper.text()).toContain('No se pudieron cargar')
    })
})
