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
    
    // Default mock resolutions to let mount succeed without errors
    vulnService.getVulns.mockResolvedValue(paginated([]))
    vulnService.getUniqueFilters.mockResolvedValue({
      data: {
        agents: ['Agent1', 'Agent2'],
        cves: ['CVE-2026-0001', 'CVE-2026-0002'],
        packages: ['pkg1', 'pkg2'],
        severities: ['critical', 'high']
      }
    })
    vulnService.getMetricsSummary.mockResolvedValue({
      data: { total: 10, critical: 2, high: 3, medium: 4, low: 1 }
    })
    wazuhService.getConnections.mockResolvedValue({
      data: [{ id: 1, name: 'Conn1' }]
    })
  })

  it('exercises lifecycle onMounted hooks and data loading', async () => {
    const wrapper = mount(Cargas)
    await flushPromises()

    expect(wazuhService.getConnections).toHaveBeenCalledTimes(1)
    expect(vulnService.getUniqueFilters).toHaveBeenCalledTimes(1)
    expect(vulnService.getVulns).toHaveBeenCalledTimes(1)
    expect(vulnService.getMetricsSummary).toHaveBeenCalledTimes(1)
  })

  it('renders title and UI elements correctly', async () => {
    const wrapper = mount(Cargas)
    await flushPromises()
    expect(wrapper.text()).toContain('Evolución por Cargas 1')
  })

  it('handles sorting columns', async () => {
    const wrapper = mount(Cargas)
    await flushPromises()

    // Call sortBy via vm methods
    wrapper.vm.sortBy('severity')
    expect(wrapper.vm.sortKey).toBe('severity')
    expect(wrapper.vm.sortOrder).toBe('asc')

    wrapper.vm.sortBy('severity')
    expect(wrapper.vm.sortKey).toBe('severity')
    expect(wrapper.vm.sortOrder).toBe('desc')

    wrapper.vm.sortBy('severity')
    expect(wrapper.vm.sortKey).toBe('')
    expect(wrapper.vm.sortOrder).toBe('')
  })

  it('handles pagination next, prev, jump forward, jump backward', async () => {
    // Mock 150 items so we have 3 pages (50 items per page)
    vulnService.getVulns.mockResolvedValue(paginated([], 150))
    const wrapper = mount(Cargas)
    await flushPromises()

    expect(wrapper.vm.totalPages).toBe(3)

    // Next page
    wrapper.vm.nextPage()
    expect(wrapper.vm.currentPage).toBe(2)

    // Prev page
    wrapper.vm.prevPage()
    expect(wrapper.vm.currentPage).toBe(1)

    // Jump forward
    wrapper.vm.jumpForward()
    expect(wrapper.vm.currentPage).toBe(3)

    // Jump backward
    wrapper.vm.jumpBackward()
    expect(wrapper.vm.currentPage).toBe(1)
  })

  it('exercises severity, description and date format helpers', async () => {
    const wrapper = mount(Cargas)
    await flushPromises()

    // getSeverityLevel
    expect(wrapper.vm.getSeverityLevel('critical')).toBe(4)
    expect(wrapper.vm.getSeverityLevel('high')).toBe(3)
    expect(wrapper.vm.getSeverityLevel('medium')).toBe(2)
    expect(wrapper.vm.getSeverityLevel('low')).toBe(1)
    expect(wrapper.vm.getSeverityLevel(null)).toBe(0)

    // getBrief
    expect(wrapper.vm.getBrief('Short description')).toBe('Short description')
    expect(wrapper.vm.getBrief(null)).toBe('Sin descripción disponible')
    const longDesc = 'a'.repeat(200)
    expect(wrapper.vm.getBrief(longDesc)).toHaveLength(150)
    expect(wrapper.vm.getBrief(longDesc)).toContain('...')

    // formatDate
    expect(wrapper.vm.formatDate(null)).toBe('N/A')
    expect(wrapper.vm.formatDate('2026-08-07T17:00:00Z')).toContain('2026')

    // getSeverityClass
    expect(wrapper.vm.getSeverityClass('critical')).toBe('badge badge-critical')
    expect(wrapper.vm.getSeverityClass('medium')).toBe('badge badge-medium')
    expect(wrapper.vm.getSeverityClass('low')).toBe('badge badge-low')
    expect(wrapper.vm.getSeverityClass(null)).toBe('badge badge-low')

    // getSeverityBadgeClass
    expect(wrapper.vm.getSeverityBadgeClass('critical')).toBe('badge-critical')
    expect(wrapper.vm.getSeverityBadgeClass('high')).toBe('badge-high')
    expect(wrapper.vm.getSeverityBadgeClass('medium')).toBe('badge-medium')
    expect(wrapper.vm.getSeverityBadgeClass('low')).toBe('badge-low')
  })

  it('exercises filter fields and search computeds', async () => {
    const wrapper = mount(Cargas)
    await flushPromises()

    wrapper.vm.search.agent = 'Agent1'
    expect(wrapper.vm.filteredAgents).toEqual(['Agent1'])

    wrapper.vm.search.vuln = 'CVE-2026-0001'
    expect(wrapper.vm.filteredCVEOptions).toEqual(['CVE-2026-0001'])

    wrapper.vm.search.package = 'pkg1'
    expect(wrapper.vm.filteredPackages).toEqual(['pkg1'])
  })

  it('handles sync triggers and options reloading', async () => {
    vulnService.syncVulns.mockResolvedValue({ data: { success: true } })
    const wrapper = mount(Cargas)
    await flushPromises()

    await wrapper.vm.syncVulns()
    expect(vulnService.syncVulns).toHaveBeenCalledTimes(1)
    expect(wrapper.vm.syncing).toBe(false)

    // Check error handling in sync
    vulnService.syncVulns.mockRejectedValue(new Error('Sync failed'))
    await wrapper.vm.syncVulns()
    expect(wrapper.vm.error).toBe('Error durante la sincronización con Wazuh.')
  })

  it('handles changing connections and clearing filters', async () => {
    const wrapper = mount(Cargas)
    await flushPromises()

    wrapper.vm.selectedConnection = '1'
    await wrapper.vm.onConnectionChange()
    expect(wrapper.vm.currentPage).toBe(1)

    wrapper.vm.clearFilters()
    expect(wrapper.vm.selectedConnection).toBe('')
    expect(wrapper.vm.currentPage).toBe(1)
  })

  it('handles filterBySeverity shortcut calls', async () => {
    const wrapper = mount(Cargas)
    await flushPromises()

    wrapper.vm.filterBySeverity(['CRITICAL'])
    expect(wrapper.vm.selectedSeverities).toEqual(['CRITICAL'])
    expect(wrapper.vm.currentPage).toBe(1)
  })

  it('triggers filter changes with a debounce timeout', async () => {
    vi.useFakeTimers()
    const wrapper = mount(Cargas)
    await flushPromises()

    wrapper.vm.triggerFilterChange()
    expect(wrapper.vm.currentPage).toBe(1)

    // Fast-forward debounce time
    vi.advanceTimersByTime(500)
    expect(vulnService.getVulns).toHaveBeenCalled()
    vi.useRealTimers()
  })

  it('renders headers list and formats dates safely', async () => {
    const mockVulns = [
      {
        id: 1,
        severity: 'critical',
        cve_id: 'CVE-2026-44170',
        cargas: [
          { label: 'Carga 1', timestamp: '2026-08-07T17:00:00Z', status: 'red' },
          { label: 'Carga 2', timestamp: 'invalid-date', status: 'white' },
          { label: 'Carga 3', timestamp: null, status: 'white' }
        ]
      }
    ]

    vulnService.getVulns.mockResolvedValue(paginated(mockVulns))
    const wrapper = mount(Cargas)
    await flushPromises()

    // formatShortDate test cases through computed headers
    expect(wrapper.vm.cargasHeaders).toHaveLength(3)
    expect(wrapper.vm.cargasHeaders[0].date).not.toBe('N/D')
    expect(wrapper.vm.cargasHeaders[1].date).toBe('N/D')
    expect(wrapper.vm.cargasHeaders[2].date).toBe('N/D')
  })
})
