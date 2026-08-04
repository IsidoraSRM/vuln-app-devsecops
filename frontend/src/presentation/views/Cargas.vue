<template>
  <div class="fade-in">
    <div class="header-actions">
      <div>
        <h1 class="title">Evolución por Cargas</h1>
        <p class="subtitle">Monitorea el ciclo de vida de vulnerabilidades y su remediación a través de las sincronizaciones.</p>
      </div>
      <div>
        <button class="btn btn-primary" @click="syncVulns" :disabled="syncing">
          <svg v-if="syncing" class="spin" xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="2" x2="12" y2="6"></line><line x1="12" y1="18" x2="12" y2="22"></line><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"></line><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"></line><line x1="2" y1="12" x2="6" y2="12"></line><line x1="18" y1="12" x2="22" y2="12"></line><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"></line><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"></line></svg>
          <svg v-else xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.59-9.5l1.75 1.93"></path></svg>
          {{ syncing ? 'Sincronizando...' : 'Sincronizar' }}
        </button>
      </div>
    </div>

    <div v-if="error" class="alert alert-danger fade-in">
      <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
      {{ error }}
    </div>

    <!-- Tarjetas de Métricas -->
    <div class="metrics-grid">
      <div class="metric-card total" @click="filterBySeverity(null)">
        <div class="metric-icon">
          <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
        </div>
        <div class="metric-details">
          <div class="metric-val">{{ metricsSummary.total }}</div>
          <div class="metric-lbl">Vulnerabilidades Totales</div>
        </div>
      </div>
      <div class="metric-card critical" @click="filterBySeverity(['CRITICAL', 'CRITICA'])">
        <div class="metric-icon">
          <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
        </div>
        <div class="metric-details">
          <div class="metric-val">{{ metricsSummary.critical }}</div>
          <div class="metric-lbl">Críticas (CVEs Únicos)</div>
        </div>
      </div>
      <div class="metric-card high" @click="filterBySeverity(['HIGH', 'ALTA'])">
        <div class="metric-icon">
          <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 7 13.5 15.5 8.5 10.5 2 17"></polyline><polyline points="16 7 22 7 22 13"></polyline></svg>
        </div>
        <div class="metric-details">
          <div class="metric-val">{{ metricsSummary.high }}</div>
          <div class="metric-lbl">Altas (CVEs Únicos)</div>
        </div>
      </div>
      <div class="metric-card medium-low" @click="filterBySeverity(['MEDIUM', 'MEDIA', 'LOW', 'BAJA'])">
        <div class="metric-icon">
          <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2a10 10 0 0 0-10 10v1a10 10 0 0 0 10 10h1a10 10 0 0 0 10-10V12a10 10 0 0 0-10-10z"></path></svg>
        </div>
        <div class="metric-details">
          <div class="metric-val">{{ metricsSummary.medium + metricsSummary.low }}</div>
          <div class="metric-lbl">Medias y Bajas</div>
        </div>
      </div>
    </div>

    <div v-if="!loading" class="filter-toggle-bar">
      <button class="btn-filter-toggle" @click="showFilters = !showFilters">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"></polygon>
        </svg>
        <span>{{ showFilters ? 'Ocultar filtros' : 'Filtros avanzados' }}</span>
      </button>
      <button v-if="showFilters" class="btn-clear-filters" @click="clearFilters">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M3 6h18"></path>
          <path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"></path>
          <path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"></path>
        </svg>
        <span>Limpiar</span>
      </button>
    </div>

    <div v-show="showFilters" class="card filter-panel">
      <div class="filter-row">
        <div v-if="role === 'superadmin'" class="f-group">
          <label>Conexión Wazuh</label>
          <select v-model="selectedConnection" @change="onConnectionChange" class="filter-input">
            <option value="">Todas las conexiones</option>
            <option v-for="conn in connections" :key="conn.id" :value="conn.id">{{ conn.name }}</option>
          </select>
        </div>

        <div class="f-group popover-wrap" v-click-outside="() => (dropdowns.agents = false)">
          <label>Agentes</label>
          <button class="filter-input dd-btn" @click="dropdowns.agents = !dropdowns.agents" :disabled="!agentOptions.length">
            <span>{{ selectedAgents.length ? selectedAgents.length + ' sel.' : 'Todos' }}</span>
            <span>▼</span>
          </button>
          <div v-if="dropdowns.agents" class="dd-panel fade-in">
            <input type="text" v-model="search.agent" placeholder="Buscar agente..." class="dd-search">
            <div class="dd-actions">
              <span @click="selectedAgents = [...agentOptions]; fetchVulns();">Todos</span>
              <span @click="selectedAgents = []; fetchVulns();">Limpiar</span>
            </div>
            <div class="dd-list custom-scroll">
              <label v-for="agent in filteredAgents" :key="agent" class="dd-item">
                <input type="checkbox" :value="agent" v-model="selectedAgents" @change="triggerFilterChange"> {{ agent }}
              </label>
            </div>
          </div>
        </div>

        <div class="f-group popover-wrap" v-click-outside="() => (dropdowns.vulns = false)">
          <label>CVE ID</label>
          <button class="filter-input dd-btn" @click="dropdowns.vulns = !dropdowns.vulns" :disabled="!vulnOptions.length">
            <span>{{ selectedVulns.length ? selectedVulns.length + ' sel.' : 'Todas' }}</span>
            <span>▼</span>
          </button>
          <div v-if="dropdowns.vulns" class="dd-panel fade-in">
            <input type="text" v-model="search.vuln" placeholder="Buscar CVE..." class="dd-search">
            <div class="dd-actions">
              <span @click="selectedVulns = [...vulnOptions]; fetchVulns();">Todas</span>
              <span @click="selectedVulns = []; fetchVulns();">Limpiar</span>
            </div>
            <div class="dd-list custom-scroll">
              <label v-for="vuln in filteredCVEOptions" :key="vuln" class="dd-item">
                <input type="checkbox" :value="vuln" v-model="selectedVulns" @change="triggerFilterChange"> {{ vuln }}
              </label>
            </div>
          </div>
        </div>

        <div class="f-group popover-wrap" v-click-outside="() => (dropdowns.packages = false)">
          <label>Software Afectado</label>
          <button class="filter-input dd-btn" @click="dropdowns.packages = !dropdowns.packages" :disabled="!packageOptions.length">
            <span>{{ selectedPackages.length ? selectedPackages.length + ' sel.' : 'Todos' }}</span>
            <span>▼</span>
          </button>
          <div v-if="dropdowns.packages" class="dd-panel fade-in">
            <input type="text" v-model="search.package" placeholder="Buscar software..." class="dd-search">
            <div class="dd-actions">
              <span @click="selectedPackages = [...packageOptions]; fetchVulns();">Todos</span>
              <span @click="selectedPackages = []; fetchVulns();">Limpiar</span>
            </div>
            <div class="dd-list custom-scroll">
              <label v-for="pkg in filteredPackages" :key="pkg" class="dd-item">
                <input type="checkbox" :value="pkg" v-model="selectedPackages" @change="triggerFilterChange"> {{ pkg }}
              </label>
            </div>
          </div>
        </div>

        <div class="f-group popover-wrap" v-click-outside="() => (dropdowns.severity = false)">
          <label>Severidad</label>
          <button class="filter-input dd-btn" @click="dropdowns.severity = !dropdowns.severity" :disabled="!severityOptions.length">
            <span>{{ selectedSeverities.length ? selectedSeverities.length + ' sel.' : 'Todas' }}</span>
            <span>▼</span>
          </button>
          <div v-if="dropdowns.severity" class="dd-panel fade-in">
            <div class="dd-actions">
              <span @click="selectedSeverities = [...severityOptions]; fetchVulns();">Todas</span>
              <span @click="selectedSeverities = []; fetchVulns();">Limpiar</span>
            </div>
            <div class="dd-list custom-scroll">
              <label v-for="sev in severityOptions" :key="sev" class="dd-item">
                <input type="checkbox" :value="sev" v-model="selectedSeverities" @change="triggerFilterChange"> 
                <span :class="'badge-mini ' + getSeverityBadgeClass(sev)">{{ sev }}</span>
              </label>
            </div>
          </div>
        </div>

        <div class="f-group">
          <label>Score CVSS (Base)</label>
          <div class="range-inputs">
            <input type="number" v-model.number="scoreMin" @input="triggerFilterChange" min="0" max="10" step="0.1" placeholder="Min" class="filter-input-sm">
            <span>-</span>
            <input type="number" v-model.number="scoreMax" @input="triggerFilterChange" min="0" max="10" step="0.1" placeholder="Max" class="filter-input-sm">
          </div>
        </div>
      </div>
    </div>

    <div v-show="loading" class="empty-state">
      <div class="spinner-box">
        <svg class="spin" xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="2" x2="12" y2="6"></line><line x1="12" y1="18" x2="12" y2="22"></line><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"></line><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"></line><line x1="2" y1="12" x2="6" y2="12"></line><line x1="18" y1="12" x2="22" y2="12"></line><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"></line><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"></line></svg>
      </div>
      <p>Cargando evolución de cargas...</p>
    </div>

    <div v-show="!loading" class="card" style="padding: 0;">
      <div class="table-wrapper">
        <div v-if="totalPages > 1" class="pagination-header">
          <span class="pagination-info">
            Mostrando {{ (currentPage - 1) * itemsPerPage + 1 }} - {{ Math.min(currentPage * itemsPerPage, totalVulns) }} de {{ totalVulns }} vulnerabilidades
          </span>
          <div class="pagination-nav">
            <button class="btn-icon-page" :disabled="currentPage === 1" @click="jumpBackward" title="Retroceder 10 páginas" aria-label="Retroceder 10 páginas">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><polyline points="13 17 8 12 13 7"></polyline><polyline points="19 17 14 12 19 7"></polyline></svg>
            </button>
            <button class="btn-icon-page" :disabled="currentPage === 1" @click="prevPage" title="Anterior">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"></polyline></svg>
            </button>
            <div class="page-numbers">
              <template v-for="(item, idx) in visiblePages" :key="`top-${item}-${idx}`">
                <button
                  v-if="typeof item === 'number'"
                  class="btn-page"
                  :class="{ 'active': currentPage === item }"
                  @click="currentPage = item"
                >
                  {{ item }}
                </button>
                <span v-else class="pagination-ellipsis">...</span>
              </template>
            </div>
            <button class="btn-icon-page" :disabled="currentPage === totalPages" @click="nextPage" title="Siguiente">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg>
            </button>
            <button class="btn-icon-page" :disabled="currentPage === totalPages" @click="jumpForward" title="Avanzar 10 páginas" aria-label="Avanzar 10 páginas">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><polyline points="11 17 16 12 11 7"></polyline><polyline points="5 17 10 12 5 7"></polyline></svg>
            </button>
          </div>
        </div>

        <table v-if="vulns.length > 0" class="vuln-table">
          <caption class="visually-hidden">
            Tabla de evolución de vulnerabilidades por carga.
          </caption>
          <thead>
            <tr>
              <th style="width: 25%;" @click="sortBy('severity')">
                Severidad
                <span v-if="sortKey === 'severity'" class="sort-indicator">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="4" :class="sortOrder === 'asc' ? '' : 'rotate-180'">
                    <path d="M7 14l5-5 5 5z"/>
                  </svg>
                </span>
              </th>
              <th class="col-cve" style="width: 45%;" @click="sortBy('cve_id')">
                CVE ID
                <span v-if="sortKey === 'cve_id'" class="sort-indicator">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="4" :class="sortOrder === 'asc' ? '' : 'rotate-180'">
                    <path d="M7 14l5-5 5 5z"/>
                  </svg>
                </span>
              </th>
              <th style="width: 30%;">Evolución por Carga</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="vuln in vulns" :key="vuln.id">
              <td>
                <span :class="getSeverityClass(vuln.severity)">
                  {{ (vuln.severity || 'UNKNOWN').toUpperCase() }}
                </span>
              </td>
              <td class="font-medium text-black">{{ vuln.cve_id || 'N/A' }}</td>
              <td>
                <div class="cargas-evolution">
                  <div 
                    v-for="(carga, idx) in vuln.cargas" 
                    :key="idx" 
                    :class="['carga-box', carga.status]"
                    :title="`${carga.label}: ${carga.status === 'red' ? 'Presente (Activa)' : 'Ausente (Remediada)'} (${formatDate(carga.timestamp)})`"
                  ></div>
                  <span v-if="!vuln.cargas || vuln.cargas.length === 0" class="no-cargas-text">N/D</span>
                </div>
              </td>
            </tr>
          </tbody>
        </table>

        <div v-if="totalPages > 1" class="pagination-controls-bottom">
          <div class="pagination-nav" style="margin-left: auto;">
            <button class="btn-icon-page" :disabled="currentPage === 1" @click="jumpBackward" title="Retroceder 10 páginas" aria-label="Retroceder 10 páginas">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><polyline points="13 17 8 12 13 7"></polyline><polyline points="19 17 14 12 19 7"></polyline></svg>
            </button>
            <button class="btn-icon-page" :disabled="currentPage === 1" @click="prevPage" title="Anterior">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"></polyline></svg>
            </button>
            <div class="page-numbers">
              <template v-for="(item, idx) in visiblePages" :key="`bottom-${item}-${idx}`">
                <button
                  v-if="typeof item === 'number'"
                  class="btn-page"
                  :class="{ 'active': currentPage === item }"
                  @click="currentPage = item"
                >
                  {{ item }}
                </button>
                <span v-else class="pagination-ellipsis">...</span>
              </template>
            </div>
            <button class="btn-icon-page" :disabled="currentPage === totalPages" @click="nextPage" title="Siguiente">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg>
            </button>
            <button class="btn-icon-page" :disabled="currentPage === totalPages" @click="jumpForward" title="Avanzar 10 páginas" aria-label="Avanzar 10 páginas">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><polyline points="11 17 16 12 11 7"></polyline><polyline points="5 17 10 12 5 7"></polyline></svg>
            </button>
          </div>
        </div>

        <div v-if="vulns.length === 0 && !loading" class="empty-state" style="padding: 4rem 2rem;">
          <div class="shield-box">
             <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--success)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="M9 12l2 2 4-4"></path></svg>
          </div>
          <p style="color: var(--text-main); font-weight: 500; font-size: 1.1rem; margin-bottom: 0.5rem;">No se encontraron vulnerabilidades</p>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, computed, watch, reactive } from 'vue'
import vulnService from '../../application/services/vulnService'
import wazuhService from '../../application/services/wazuhService'

const vulns = ref([])
const totalVulns = ref(0)
const loading = ref(true)
const syncing = ref(false)
const error = ref('')
const sortKey = ref('last_seen')
const sortOrder = ref('desc')
const showFilters = ref(false)

const role = ref(localStorage.getItem('role') || 'operator')

// Configuración fija de paginación
const currentPage = ref(1)
const itemsPerPage = 50
const pageJump = 10

// Opciones de checklists para filtros
const connections = ref([])
const agentOptions = ref([])
const vulnOptions = ref([])
const packageOptions = ref([])
const severityOptions = ref([])

// Valores seleccionados
const selectedConnection = ref('')
const selectedAgents = ref([])
const selectedVulns = ref([])
const selectedPackages = ref([])
// FILTRO PREESTABLECIDO: Críticas
const selectedSeverities = ref(['CRITICAL'])
const scoreMin = ref('')
const scoreMax = ref('')

const metricsSummary = ref({ total: 0, critical: 0, high: 0, medium: 0, low: 0 })

const search = reactive({ agent: '', vuln: '', package: '' })
const dropdowns = reactive({ agents: false, vulns: false, packages: false, severity: false })

const filteredAgents = computed(() =>
  agentOptions.value.filter(agent => agent.toLowerCase().includes(search.agent.toLowerCase()))
)
const filteredCVEOptions = computed(() =>
  vulnOptions.value.filter(vuln => vuln.toLowerCase().includes(search.vuln.toLowerCase()))
)
const filteredPackages = computed(() =>
  packageOptions.value.filter(pkg => pkg.toLowerCase().includes(search.package.toLowerCase()))
)

const getSeverityLevel = (s) => {
  if (!s) return 0
  const severity = s.toLowerCase()
  if (severity === 'critical' || severity === 'critica') return 4
  if (severity === 'high' || severity === 'alta') return 3
  if (severity === 'medium' || severity === 'media') return 2
  return 1
}

const getBrief = (desc) => {
  if (!desc) return 'Sin descripción disponible'
  if (desc.length <= 150) return desc
  return desc.substring(0, 147) + '...'
}

const filterBySeverity = (sevs) => {
  selectedSeverities.value = sevs || []
  currentPage.value = 1
  fetchVulns()
}

const fetchMetrics = async () => {
  try {
    const res = await vulnService.getMetricsSummary(selectedConnection.value || null)
    metricsSummary.value = res.data
  } catch (err) {
    console.error('Error fetching metrics summary:', err)
  }
}

const fetchVulns = async () => {
  loading.value = true
  error.value = ''
  try {
    const params = {
      page: currentPage.value,
      limit: itemsPerPage,
      sort_key: sortKey.value || 'last_seen',
      sort_order: sortOrder.value || 'desc',
      connectionId: selectedConnection.value || null,
      agent_name: selectedAgents.value,
      cve_id: selectedVulns.value,
      package_name: selectedPackages.value,
      severity: selectedSeverities.value,
      score_min: scoreMin.value,
      score_max: scoreMax.value,
    }

    const res = await vulnService.getVulns(params)
    if (res.data && res.data.items) {
      vulns.value = res.data.items
      totalVulns.value = res.data.total
    } else {
      vulns.value = []
      totalVulns.value = 0
    }
    
    await fetchMetrics()
  } catch (err) {
    console.error('Error fetching vulns:', err)
  } finally {
    loading.value = false
  }
}

const fetchFilterOptionsData = async () => {
  try {
    const res = await vulnService.getUniqueFilters(selectedConnection.value || null)
    const { agents, cves, packages, severities } = res.data || {}
    
    agentOptions.value = (agents || []).sort()
    vulnOptions.value = (cves || []).sort()
    packageOptions.value = (packages || []).sort()
    
    severityOptions.value = (severities || [])
      .map(s => s.toUpperCase())
      .sort((a, b) => {
        return getSeverityLevel(b.toLowerCase()) - getSeverityLevel(a.toLowerCase())
      })
  } catch (err) {
    console.error('Error fetching options layout:', err)
  }
}

const fetchConnections = async () => {
  if (role.value !== 'superadmin') return
  try {
    const res = await wazuhService.getConnections()
    connections.value = res?.data || []
  } catch (err) {
    connections.value = []
  }
}

let timeoutId = null
const triggerFilterChange = () => {
  currentPage.value = 1
  if (timeoutId) clearTimeout(timeoutId)
  timeoutId = setTimeout(() => {
    fetchVulns()
  }, 400)
}

const totalPages = computed(() => Math.ceil(totalVulns.value / itemsPerPage))

const visiblePages = computed(() => {
  const pages = []
  const total = totalPages.value
  const current = currentPage.value
  const maxNumericButtons = 7

  if (total <= maxNumericButtons) {
    for (let i = 1; i <= total; i++) pages.push(i)
    return pages
  }

  pages.push(1)
  const middleSlots = maxNumericButtons - 2
  let start = Math.max(2, current - Math.floor(middleSlots / 2))
  let end = start + middleSlots - 1

  if (end > total - 1) {
    end = total - 1
    start = end - middleSlots + 1
  }

  if (start > 2) pages.push('left-ellipsis')
  for (let i = start; i <= end; i++) pages.push(i)
  if (end < total - 1) pages.push('right-ellipsis')

  pages.push(total)
  return pages
})

const nextPage = () => { if (currentPage.value < totalPages.value) currentPage.value++ }
const prevPage = () => { if (currentPage.value > 1) currentPage.value-- }
const jumpBackward = () => { currentPage.value = Math.max(1, currentPage.value - pageJump) }
const jumpForward = () => { currentPage.value = Math.min(totalPages.value, currentPage.value + pageJump) }

watch(currentPage, () => { fetchVulns() })

const sortBy = (key) => {
  if (sortKey.value !== key) {
    sortKey.value = key
    sortOrder.value = 'asc'
  } else if (sortOrder.value === 'asc') {
    sortOrder.value = 'desc'
  } else {
    sortKey.value = ''
    sortOrder.value = ''
  }
  currentPage.value = 1
  fetchVulns()
}

const onConnectionChange = () => {
  selectedAgents.value = []
  selectedVulns.value = []
  selectedPackages.value = []
  selectedSeverities.value = []
  scoreMin.value = ''
  scoreMax.value = ''
  currentPage.value = 1
  fetchFilterOptionsData()
  fetchVulns()
}

const clearFilters = () => {
  selectedConnection.value = ''
  selectedAgents.value = []
  selectedVulns.value = []
  selectedPackages.value = []
  selectedSeverities.value = []
  scoreMin.value = ''
  scoreMax.value = ''
  currentPage.value = 1
  fetchFilterOptionsData()
  fetchVulns()
}

const syncVulns = async () => {
  syncing.value = true
  error.value = ''
  try {
    await vulnService.syncVulns()
    await fetchFilterOptionsData()
    await fetchVulns()
  } catch (err) {
    error.value = 'Error durante la sincronización con Wazuh.'
  } finally {
    syncing.value = false
  }
}

const formatDate = (dateString) => {
  if (!dateString) return 'N/A'
  const d = new Date(dateString)
  return d.toLocaleDateString('es-ES', { 
    day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' 
  })
}

const getSeverityClass = (severity) => {
  if (!severity) return 'badge badge-low'
  const s = severity.toLowerCase()
  if (['critical', 'high', 'alta', 'critica'].includes(s)) return 'badge badge-critical'
  if (['medium', 'media'].includes(s)) return 'badge badge-medium'
  return 'badge badge-low'
}

const getSeverityBadgeClass = (severity) => {
  const s = severity.toLowerCase()
  if (['critical', 'critica'].includes(s)) return 'badge-critical'
  if (['high', 'alta'].includes(s)) return 'badge-high'
  if (['medium', 'media'].includes(s)) return 'badge-medium'
  return 'badge-low'
}

onMounted(() => {
  fetchConnections()
  fetchFilterOptionsData()
  fetchVulns()
})
</script>

<style scoped>
.metrics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 1.5rem;
  margin-bottom: 2rem;
}
.metric-card {
  display: flex;
  align-items: center;
  gap: 1.25rem;
  padding: 1.5rem;
  background-color: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  cursor: pointer;
  transition: all 0.3s ease;
}
.metric-card:hover {
  transform: translateY(-4px);
  border-color: var(--primary);
  box-shadow: 0 4px 20px var(--primary-glow);
}
.metric-icon {
  width: 48px;
  height: 48px;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}
.total .metric-icon {
  background-color: rgba(59, 130, 246, 0.1);
  color: #3b82f6;
}
.critical .metric-icon {
  background-color: rgba(220, 38, 38, 0.1);
  color: #dc2626;
}
.high .metric-icon {
  background-color: rgba(234, 88, 12, 0.1);
  color: #ea580c;
}
.medium-low .metric-icon {
  background-color: rgba(234, 179, 8, 0.1);
  color: #eab308;
}
.metric-val {
  font-size: 2rem;
  font-weight: 700;
  color: var(--text-main);
  line-height: 1;
}
.metric-lbl {
  font-size: 0.85rem;
  color: var(--text-muted);
  font-weight: 500;
  margin-top: 0.25rem;
}
.cargas-evolution {
  display: flex;
  gap: 0.35rem;
  align-items: center;
}
.carga-box {
  width: 16px;
  height: 16px;
  border-radius: 4px;
  transition: all 0.2s ease;
  position: relative;
}
.carga-box.red {
  background-color: #ef4444;
  border: 1px solid #dc2626;
  box-shadow: 0 0 6px rgba(239, 68, 68, 0.4);
}
.carga-box.white {
  background-color: #ffffff;
  border: 1px solid #d1d5db;
  box-shadow: 0 0 6px rgba(255, 255, 255, 0.2);
}
.carga-box:hover {
  transform: scale(1.25);
  z-index: 10;
}
.no-cargas-text {
  font-size: 0.75rem;
  color: var(--text-muted);
}
.vuln-brief {
  font-size: 0.85rem;
  color: var(--text-main);
  max-width: 350px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.header-actions { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1.5rem; }
th { cursor: pointer; }
.sort-indicator { margin-left: 0.5rem; display: inline-block; transition: transform 0.2s ease; }
.visually-hidden { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0; }
.rotate-180 { transform: rotate(180deg); }
.empty-state { display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; padding: 3rem; color: var(--text-muted); }
.spinner-box { margin-bottom: 1rem; }
.shield-box { width: 80px; height: 80px; background-color: var(--success-bg); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 1.5rem; border: 4px solid rgba(16, 185, 129, 0.1); }
.font-medium { font-weight: 500; }
.text-black { color: var(--text-main); font-weight: 400; }
.alert { padding: 1rem; border-radius: var(--radius-sm); margin-bottom: 1.5rem; font-size: 0.9rem; display: flex; align-items: center; gap: 0.5rem; font-weight: 500; }
.alert-danger { color: var(--danger); background-color: var(--danger-bg); border: 1px solid rgba(239, 68, 68, 0.3); }
.pagination-header { display: flex; justify-content: space-between; align-items: center; padding: 1rem 1.5rem; border-bottom: 1px solid var(--border); background-color: var(--bg-panel); }
.pagination-info { font-size: 0.85rem; font-weight: 500; color: var(--text-muted); }
.pagination-controls-bottom { display: flex; justify-content: flex-end; align-items: center; padding: 1rem 1.5rem; border-top: 1px solid var(--border); background-color: var(--bg-card); }
.pagination-nav { display: flex; align-items: center; gap: 0.35rem; }
.page-numbers { display: flex; gap: 0.2rem; }
.btn-icon-page { display: inline-flex; align-items: center; justify-content: center; width: 28px; height: 28px; background: transparent; border: 1px solid var(--border); color: var(--text-main); border-radius: 6px; cursor: pointer; transition: all 0.2s; }
.btn-icon-page:hover:not(:disabled) { background-color: var(--bg-hover); border-color: var(--text-muted); }
.btn-icon-page:disabled { opacity: 0.3; cursor: not-allowed; border-color: transparent; }
.btn-page { display: inline-flex; align-items: center; justify-content: center; min-width: 28px; height: 28px; padding: 0 0.25rem; border: 1px solid transparent; background: transparent; color: var(--text-muted); border-radius: 6px; font-size: 0.8rem; font-weight: 500; cursor: pointer; transition: all 0.2s; }
.btn-page:hover:not(.active) { background-color: var(--bg-hover); color: var(--text-main); }
.btn-page.active { background-color: var(--primary); color: #000; }
.filter-toggle-bar { display: flex; justify-content: flex-end; align-items: center; gap: 0.5rem; padding: 0.75rem 0; margin-bottom: 0.5rem; }
.btn-filter-toggle, .btn-clear-filters { display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem 0.85rem; background: transparent; border: 1px solid var(--border); color: var(--text-muted); border-radius: 6px; font-size: 0.85rem; cursor: pointer; transition: all 0.2s; font-weight: 500; }
.btn-filter-toggle:hover { background-color: var(--bg-hover); border-color: var(--text-muted); color: var(--text-main); }
.btn-clear-filters:hover { background-color: var(--bg-hover); border-color: var(--danger); color: var(--danger); }
.pagination-ellipsis { display: inline-flex; align-items: center; justify-content: center; min-width: 20px; color: var(--text-muted); font-size: 0.8rem; font-weight: 600; }
.filter-panel { padding: 0; margin-bottom: 1.5rem; overflow: visible; }
.filter-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); align-items: center; }
.f-group { display: flex; flex-direction: column; padding: 1rem 1.2rem; border-right: 1px solid var(--border); }
.f-group:last-child { border-right: none; }
.f-group label { font-size: 0.7rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 0.5rem; }
.filter-input, .dd-btn { width: 100%; padding: 0.55rem 0.8rem; border: 1px solid var(--border); background: var(--bg-dark); border-radius: var(--radius-sm); color: var(--text-main); cursor: pointer; font-size: 0.85rem; }
.filter-input:disabled, .dd-btn:disabled { opacity: 0.5; cursor: not-allowed; }
.filter-input-sm { width: 100%; padding: 0.45rem 0.6rem; border: 1px solid var(--border); background: var(--bg-dark); border-radius: var(--radius-sm); color: var(--text-main); font-size: 0.8rem; }
.range-inputs { display: flex; align-items: center; gap: 0.4rem; }
.range-inputs span { color: var(--text-muted); font-weight: 600; }
.popover-wrap { position: relative; }
.dd-btn { display: flex; justify-content: space-between; }
.dd-panel { position: absolute; top: calc(100% + 6px); left: 0; width: 280px; border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--bg-panel); z-index: 20; overflow: hidden; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15); }
.dd-search { width: 100%; border: none; border-bottom: 1px solid var(--border); padding: 0.65rem 0.9rem; background: var(--bg-hover); color: var(--text-main); }
.dd-actions { display: flex; justify-content: space-between; padding: 0.5rem 0.9rem; border-bottom: 1px solid var(--border); font-size: 0.75rem; color: var(--primary); }
.dd-actions span { cursor: pointer; }
.dd-actions span:hover { text-decoration: underline; }
.dd-list { max-height: 220px; overflow-y: auto; }
.dd-item { display: flex; gap: 0.6rem; padding: 0.5rem 0.9rem; font-size: 0.82rem; cursor: pointer; align-items: center; }
.dd-item:hover { background: var(--bg-hover); }
.badge-mini { padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; }
.badge-critical { background: rgba(220, 38, 38, 0.15); color: #dc2626; }
.badge-high { background: rgba(234, 88, 12, 0.15); color: #ea580c; }
.badge-medium { background: rgba(234, 179, 8, 0.15); color: #eab308; }
.badge-low { background: rgba(59, 130, 246, 0.15); color: #3b82f6; }
@media (max-width: 1400px) { .filter-row { grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); } }
@media (max-width: 1100px) { .filter-row { grid-template-columns: 1fr 1fr; } .f-group { border-right: none; border-bottom: 1px solid var(--border); } }
</style>
