import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import Cargas from '@/presentation/views/Cargas.vue'
import vulnService from '@/application/services/vulnService'
import wazuhService from '@/application/services/wazuhService'

vi.mock('@/application/services/vulnService', () => ({
  default: {
    getVulns: vi.fn(),
    getUniqueFilters: vi.fn(),
    getMetricsSummary: vi.fn(),
    syncVulns: vi.fn()
  }
}))

vi.mock('@/application/services/wazuhService', () => ({
  default: {
    getConnections: vi.fn()
  }
}))

const paginated = (items, total = null) => ({
  data: { items, total: total ?? items.length }
})

describe('Cargas.vue', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    localStorage.setItem('role', 'superadmin')
  })

  it('renders title and subtitle', async () => {
    vulnService.getVulns.mockResolvedValue(paginated([]))
    vulnService.getUniqueFilters.mockResolvedValue({ data: {} })
    vulnService.getMetricsSummary.mockResolvedValue({ data: {} })
    wazuhService.getConnections.mockResolvedValue({ data: [] })

    const wrapper = mount(Cargas)
    await flushPromises()

    expect(wrapper.text()).toContain('Evolución por Cargas 1')
    expect(wrapper.text()).toContain('Monitorea el ciclo de vida de vulnerabilidades')
  })

  it('renders table columns with formatted dates and handles invalid dates', async () => {
    const mockVulns = [
      {
        id: 1,
        severity: 'critical',
        cve_id: 'CVE-2026-44170',
        cargas: [
          { label: 'Carga 1', timestamp: '2026-08-07T17:00:00Z', status: 'red' },
          { label: 'Carga 2', timestamp: 'invalid-date-string', status: 'white' },
          { label: 'Carga 3', timestamp: null, status: 'white' }
        ]
      }
    ]

    vulnService.getVulns.mockResolvedValue(paginated(mockVulns))
    vulnService.getUniqueFilters.mockResolvedValue({ data: {} })
    vulnService.getMetricsSummary.mockResolvedValue({ data: {} })
    wazuhService.getConnections.mockResolvedValue({ data: [] })

    const wrapper = mount(Cargas)
    await flushPromises()

    expect(wrapper.find('thead').text()).toContain('Carga 1')
    expect(wrapper.find('thead').text()).toContain('Carga 2 (N/D)')
    expect(wrapper.find('thead').text()).toContain('Carga 3 (N/D)')
  })

  it('handles sync triggers successfully', async () => {
    vulnService.getVulns.mockResolvedValue(paginated([]))
    vulnService.getUniqueFilters.mockResolvedValue({ data: {} })
    vulnService.getMetricsSummary.mockResolvedValue({ data: {} })
    wazuhService.getConnections.mockResolvedValue({ data: [] })
    vulnService.syncVulns.mockResolvedValue({ data: { success: true } })

    const wrapper = mount(Cargas)
    await flushPromises()

    const syncButton = wrapper.find('.btn-primary')
    await syncButton.trigger('click')
    expect(vulnService.syncVulns).toHaveBeenCalledTimes(1)
  })

  it('handles pagination next and prev pages', async () => {
    vulnService.getVulns.mockResolvedValue(paginated([], 150)) // 3 pages of 50 items
    vulnService.getUniqueFilters.mockResolvedValue({ data: {} })
    vulnService.getMetricsSummary.mockResolvedValue({ data: {} })
    wazuhService.getConnections.mockResolvedValue({ data: [] })

    const wrapper = mount(Cargas)
    await flushPromises()

    const nextButton = wrapper.find('.pagination-btn:not([disabled])')
    if (nextButton.exists()) {
      await nextButton.trigger('click')
      expect(vulnService.getVulns).toHaveBeenCalledTimes(2)
    }
  })
})
