<template>
  <div class="fade-in">
    <div class="header-actions">
      <div>
        <h1 class="title">Evolución por Cargas 1</h1>
        <p class="subtitle">Monitorea el ciclo de vida de vulnerabilidades y su remediación a través de las sincronizaciones.</p>
      </div>
      <div>
        <button type="button" class="btn btn-primary" @click="syncVulns" :disabled="syncing">
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

    <!-- Dashboard Hero Panel -->
    <div class="card dashboard-hero" v-if="!loading && metricsSummary.total > 0">
      <!-- Left: Pie/Donut Chart Container -->
      <div class="hero-chart-container">
        <h3>Distribución por Severidad</h3>
        <div class="canvas-wrapper">
          <canvas id="donutChart"></canvas>
        </div>
      </div>
      
      <!-- Right: Metrics Container -->
      <div class="hero-metrics-container">
        <h2 class="hero-title">Evolución por cargas</h2>
        <div class="metrics-2x2-grid">
          <div class="metric-card total" @click="filterBySeverity(null)" style="margin: 0; cursor: pointer;">
            <div class="metric-icon">
              <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
            </div>
            <div class="metric-details">
              <div class="metric-val">{{ metricsSummary.total }}</div>
              <div class="metric-lbl">Vulnerabilidades Totales</div>
            </div>
          </div>
          
          <div class="metric-card critical" @click="filterBySeverity(['CRITICAL', 'CRITICA'])" style="margin: 0; cursor: pointer;">
            <div class="metric-icon">
              <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
            </div>
            <div class="metric-details">
              <div class="metric-val">{{ metricsSummary.critical }}</div>
              <div class="metric-lbl">Críticas (CVEs Únicos)</div>
            </div>
          </div>
          
          <div class="metric-card high" @click="filterBySeverity(['HIGH', 'ALTA'])" style="margin: 0; cursor: pointer;">
            <div class="metric-icon">
              <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 7 13.5 15.5 8.5 10.5 2 17"></polyline><polyline points="16 7 22 7 22 13"></polyline></svg>
            </div>
            <div class="metric-details">
              <div class="metric-val">{{ metricsSummary.high }}</div>
              <div class="metric-lbl">Altas (CVEs Únicos)</div>
            </div>
          </div>
          
          <div class="metric-card medium-low" @click="filterBySeverity(['MEDIUM', 'MEDIA', 'LOW', 'BAJA'])" style="margin: 0; cursor: pointer;">
            <div class="metric-icon">
              <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2a10 10 0 0 0-10 10v1a10 10 0 0 0 10 10h1a10 10 0 0 0 10-10V12a10 10 0 0 0-10-10z"></path></svg>
            </div>
            <div class="metric-details">
              <div class="metric-val">{{ metricsSummary.medium + metricsSummary.low }}</div>
              <div class="metric-lbl">Medias y Bajas</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div v-if="!loading" class="filter-toggle-bar">
      <button type="button" class="btn-clear-filters" @click="clearFilters">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M3 6h18"></path>
          <path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"></path>
          <path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"></path>
        </svg>
        <span>Limpiar filtros</span>
      </button>
    </div>

    <div class="card filter-panel">
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
          <button type="button" class="filter-input dd-btn" @click="dropdowns.agents = !dropdowns.agents" :disabled="!agentOptions.length">
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
          <button type="button" class="filter-input dd-btn" @click="dropdowns.vulns = !dropdowns.vulns" :disabled="!vulnOptions.length">
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
          <button type="button" class="filter-input dd-btn" @click="dropdowns.packages = !dropdowns.packages" :disabled="!packageOptions.length">
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
          <button type="button" class="filter-input dd-btn" @click="dropdowns.severity = !dropdowns.severity" :disabled="!severityOptions.length">
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

        <div class="f-group popover-wrap" v-click-outside="() => (dropdowns.os = false)">
          <label for="btn-os">Sistema Operativo</label>
          <button id="btn-os" type="button" class="filter-input dd-btn" @click="dropdowns.os = !dropdowns.os" :disabled="!osOptions.length">
            <span>{{ selectedOS.length ? selectedOS.length + ' sel.' : 'Todos' }}</span>
            <span>▼</span>
          </button>
          <div v-if="dropdowns.os" class="dd-panel fade-in">
            <label for="search-os" style="display:none;">Buscar Sistema Operativo</label>
            <input id="search-os" type="text" v-model="search.os" placeholder="Buscar SO..." class="dd-search">
            <div class="dd-actions">
              <span @click="selectedOS = [...osOptions]; fetchVulns();">Todos</span>
              <span @click="selectedOS = []; fetchVulns();">Limpiar</span>
            </div>
            <div class="dd-list custom-scroll">
              <label v-for="os in filteredOS" :key="os" :for="'chk-os-' + os" class="dd-item">
                <input :id="'chk-os-' + os" type="checkbox" :value="os" v-model="selectedOS" @change="triggerFilterChange"> {{ os }}
              </label>
            </div>
          </div>
        </div>

        <div class="f-group date-group">
          <span class="f-label">Fecha Detección</span>
          <div class="range-inputs">
            <label for="date-after" style="display:none;">Desde</label>
            <input id="date-after" type="date" v-model="detectedAfter" @change="triggerFilterChange" class="filter-input-sm" title="Desde">
            <span>-</span>
            <label for="date-before" style="display:none;">Hasta</label>
            <input id="date-before" type="date" v-model="detectedBefore" @change="triggerFilterChange" class="filter-input-sm" title="Hasta">
          </div>
        </div>

        <div class="f-group">
          <span class="f-label">Score CVSS (Base)</span>
          <div class="range-inputs">
            <label for="cvss-min" style="display:none;">Mínimo</label>
            <input id="cvss-min" type="number" v-model.number="scoreMin" @input="triggerFilterChange" min="0" max="10" step="0.1" placeholder="Min" class="filter-input-sm">
            <span>-</span>
            <label for="cvss-max" style="display:none;">Máximo</label>
            <input id="cvss-max" type="number" v-model.number="scoreMax" @input="triggerFilterChange" min="0" max="10" step="0.1" placeholder="Max" class="filter-input-sm">
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
      <!-- Cargas Pagination Bar -->
      <div v-if="cargasTotal > 0" class="cargas-pagination-bar">
        <div class="cargas-pagination-info">
          <span>Historial de Cargas: </span>
          <strong>Cargas {{ cargasRangeText }}</strong>
        </div>
        <div class="cargas-pagination-nav">
          <button 
            type="button"
            class="btn-cargas-page"
            @click="toggleCargasOrder"
            title="Cambiar orden cronológico de las columnas"
          >
            Orden: {{ cargasOrder === 'asc' ? 'Antiguas primero ➔' : 'Recientes primero ➔' }}
          </button>
          <button 
            type="button"
            class="btn-cargas-page"
            :disabled="!hasOlderCargas" 
            @click="olderCargas"
            title="Ver cargas más antiguas"
          >
            ◀ Cargas más antiguas
          </button>
          <button 
            type="button"
            class="btn-cargas-page"
            :disabled="!hasNewerCargas" 
            @click="newerCargas"
            title="Ver cargas más recientes"
          >
            Cargas más recientes ▶
          </button>
        </div>
      </div>

      <div class="table-wrapper">
        <div v-if="totalPages > 1" class="pagination-header">
          <span class="pagination-info">
            Mostrando {{ (currentPage - 1) * itemsPerPage + 1 }} - {{ Math.min(currentPage * itemsPerPage, totalVulns) }} de {{ totalVulns }} vulnerabilidades
          </span>
          <div class="pagination-nav">
            <button type="button" class="btn-icon-page" :disabled="currentPage === 1" @click="jumpBackward" title="Retroceder 10 páginas" aria-label="Retroceder 10 páginas">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><polyline points="13 17 8 12 13 7"></polyline><polyline points="19 17 14 12 19 7"></polyline></svg>
            </button>
            <button type="button" class="btn-icon-page" :disabled="currentPage === 1" @click="prevPage" title="Anterior">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"></polyline></svg>
            </button>
            <div class="page-numbers">
              <template v-for="(item, idx) in visiblePages" :key="`top-${item}-${idx}`">
                <button
                  type="button"
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
            <button type="button" class="btn-icon-page" :disabled="currentPage === totalPages" @click="nextPage" title="Siguiente">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg>
            </button>
            <button type="button" class="btn-icon-page" :disabled="currentPage === totalPages" @click="jumpForward" title="Avanzar 10 páginas" aria-label="Avanzar 10 páginas">
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
              <th style="width: 15%;" @click="sortBy('severity')">
                Severidad
                <span v-if="sortKey === 'severity'" class="sort-indicator">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="4" :class="sortOrder === 'asc' ? '' : 'rotate-180'">
                    <path d="M7 14l5-5 5 5z"/>
                  </svg>
                </span>
              </th>
              <th class="col-cve" style="width: 25%;" @click="sortBy('cve_id')">
                CVE ID
                <span v-if="sortKey === 'cve_id'" class="sort-indicator">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="4" :class="sortOrder === 'asc' ? '' : 'rotate-180'">
                    <path d="M7 14l5-5 5 5z"/>
                  </svg>
                </span>
              </th>
              <template v-if="cargasHeaders.length > 0">
                <th v-for="header in cargasHeaders" :key="header.index" style="text-align: center;">
                  {{ header.label }} ({{ header.date }})
                </th>
              </template>
              <th v-else style="width: 60%;">Evolución por Carga</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="vuln in vulns" :key="vuln.id">
              <td>
                <span :class="getSeverityClass(vuln.severity)">
                  {{ (vuln.severity || 'UNKNOWN').toUpperCase() }}
                </span>
              </td>
              <td class="font-medium text-black">
                {{ vuln.cve_id || 'N/A' }}
                <span v-if="vuln.status && vuln.status !== 'ACTIVE'"
                      class="status-chip"
                      :class="vuln.status === 'AGENT_REMOVED' ? 'st-removed' : 'st-resolved'">
                  {{ vuln.status === 'AGENT_REMOVED' ? 'Host dado de baja' : 'Resuelta' }}
                </span>
              </td>
              <template v-if="cargasHeaders.length > 0">
                <td v-for="header in cargasHeaders" :key="header.index" style="text-align: center;">
                  <div class="cargas-evolution-cell">
                    <div 
                      v-if="vuln.cargas[header.index]" 
                      :class="['carga-box', vuln.cargas[header.index].status]"
                      :title="`${vuln.cargas[header.index].label}: ${vuln.cargas[header.index].status === 'red' ? 'Presente (Activa)' : 'Ausente (Remediada)'} (${formatDate(vuln.cargas[header.index].timestamp)})`"
                    ></div>
                    <span v-else class="no-cargas-text">-</span>
                  </div>
                </td>
              </template>
              <td v-else>
                <span class="no-cargas-text">N/D</span>
              </td>
            </tr>
          </tbody>
        </table>

        <div v-if="totalPages > 1" class="pagination-controls-bottom">
          <div class="pagination-nav" style="margin-left: auto;">
            <button type="button" class="btn-icon-page" :disabled="currentPage === 1" @click="jumpBackward" title="Retroceder 10 páginas" aria-label="Retroceder 10 páginas">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><polyline points="13 17 8 12 13 7"></polyline><polyline points="19 17 14 12 19 7"></polyline></svg>
            </button>
            <button type="button" class="btn-icon-page" :disabled="currentPage === 1" @click="prevPage" title="Anterior">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"></polyline></svg>
            </button>
            <div class="page-numbers">
              <template v-for="(item, idx) in visiblePages" :key="`bottom-${item}-${idx}`">
                <button
                  type="button"
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
            <button type="button" class="btn-icon-page" :disabled="currentPage === totalPages" @click="nextPage" title="Siguiente">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg>
            </button>
            <button type="button" class="btn-icon-page" :disabled="currentPage === totalPages" @click="jumpForward" title="Avanzar 10 páginas" aria-label="Avanzar 10 páginas">
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
import { ref, onMounted, computed, watch, reactive, nextTick } from 'vue'
import vulnService from '../../application/services/vulnService'
import wazuhService from '../../application/services/wazuhService'
import { Chart, registerables } from 'chart.js'

Chart.register(...registerables)

const vulns = ref([])
const totalVulns = ref(0)
const loading = ref(true)
const syncing = ref(false)
const error = ref('')
const sortKey = ref('last_seen')
const sortOrder = ref('desc')
const showFilters = ref(true)

// Column pagination state
const cargasPage = ref(1)
const cargasLimit = ref(10)
const cargasTotal = ref(0)
const cargasOrder = ref('asc')

const toggleCargasOrder = () => {
  cargasOrder.value = cargasOrder.value === 'asc' ? 'desc' : 'asc'
  fetchVulns()
}

const hasOlderCargas = computed(() => cargasPage.value * cargasLimit.value < cargasTotal.value)
const hasNewerCargas = computed(() => cargasPage.value > 1)
const olderCargas = () => {
  cargasPage.value++
  fetchVulns()
}
const newerCargas = () => {
  if (cargasPage.value > 1) {
    cargasPage.value--
    fetchVulns()
  }
}
const cargasRangeText = computed(() => {
  if (cargasTotal.value === 0) return '0 - 0 de 0'
  const startRank = Math.max(1, cargasTotal.value - (cargasPage.value * cargasLimit.value) + 1)
  const endRank = cargasTotal.value - ((cargasPage.value - 1) * cargasLimit.value)
  return `${startRank} - ${endRank} de ${cargasTotal.value}`
})

const formatShortDate = (dateString) => {
  if (!dateString) return 'N/D'
  const d = new Date(dateString)
  if (Number.isNaN(d.getTime())) return 'N/D'
  const day = String(d.getDate()).padStart(2, '0')
  const month = String(d.getMonth() + 1).padStart(2, '0')
  const year = String(d.getFullYear()).slice(-2)
  return `${day}-${month}-${year}`
}

const cargasHeaders = computed(() => {
  if (vulns.value.length === 0) return []
  let maxCargas = []
  for (const vuln of vulns.value) {
    if (vuln.cargas && vuln.cargas.length > maxCargas.length) {
      maxCargas = vuln.cargas
    }
  }
  return maxCargas.map((carga, index) => ({
    index,
    label: carga.label,
    date: formatShortDate(carga.timestamp)
  }))
})

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
const osOptions = ref([])

// Valores seleccionados
const selectedConnection = ref('')
const selectedAgents = ref([])
const selectedVulns = ref([])
const selectedPackages = ref([])
const selectedOS = ref([])
const detectedAfter = ref('')
const detectedBefore = ref('')
// FILTRO PREESTABLECIDO: Críticas
const selectedSeverities = ref(['CRITICAL'])
const scoreMin = ref('')
const scoreMax = ref('')

const metricsSummary = ref({ total: 0, critical: 0, high: 0, medium: 0, low: 0 })

// Visualizations Logic
let donutChartInstance = null

const renderCharts = () => {
  // Donut Chart
  const donutCtx = document.getElementById('donutChart')?.getContext('2d')
  if (donutCtx) {
    if (donutChartInstance) donutChartInstance.destroy()
    
    const total = metricsSummary.value.total || 1
    const criticalPercent = ((metricsSummary.value.critical / total) * 100).toFixed(1)
    const highPercent = ((metricsSummary.value.high / total) * 100).toFixed(1)
    const mediumPercent = ((metricsSummary.value.medium / total) * 100).toFixed(1)
    const lowPercent = ((metricsSummary.value.low / total) * 100).toFixed(1)

    donutChartInstance = new Chart(donutCtx, {
      type: 'doughnut',
      data: {
        labels: [
          `Críticas (${metricsSummary.value.critical} - ${criticalPercent}%)`,
          `Altas (${metricsSummary.value.high} - ${highPercent}%)`,
          `Medias (${metricsSummary.value.medium} - ${mediumPercent}%)`,
          `Bajas/Otras (${metricsSummary.value.low} - ${lowPercent}%)`
        ],
        datasets: [{
          data: [
            metricsSummary.value.critical,
            metricsSummary.value.high,
            metricsSummary.value.medium,
            metricsSummary.value.low
          ],
          backgroundColor: ['#ef4444', '#f97316', '#eab308', '#3b82f6'],
          borderWidth: 1,
          borderColor: 'rgba(255, 255, 255, 0.1)'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: {
              color: '#d1d5db',
              font: { size: 11, family: 'Inter, sans-serif' }
            }
          }
        }
      }
    })
  }
}

watch([vulns, metricsSummary, loading], () => {
  nextTick(() => {
    if (!loading.value) {
      renderCharts()
    }
  })
}, { deep: true })

onMounted(() => {
  nextTick(() => {
    if (!loading.value) {
      renderCharts()
    }
  })
})

const search = reactive({ agent: '', vuln: '', package: '', os: '' })
const dropdowns = reactive({ agents: false, vulns: false, packages: false, severity: false, os: false })

const filteredAgents = computed(() =>
  agentOptions.value.filter(agent => agent.toLowerCase().includes(search.agent.toLowerCase()))
)
const filteredCVEOptions = computed(() =>
  vulnOptions.value.filter(vuln => vuln.toLowerCase().includes(search.vuln.toLowerCase()))
)
const filteredPackages = computed(() =>
  packageOptions.value.filter(pkg => pkg.toLowerCase().includes(search.package.toLowerCase()))
)
const filteredOS = computed(() =>
  osOptions.value.filter(os => os.toLowerCase().includes(search.os.toLowerCase()))
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
      cargas_page: cargasPage.value,
      cargas_limit: cargasLimit.value,
      cargas_order: cargasOrder.value,
      os_platform: selectedOS.value,
      detected_after: detectedAfter.value || null,
      detected_before: detectedBefore.value || null,
    }

    const res = await vulnService.getVulns(params)
    if (res.data && res.data.items) {
      vulns.value = res.data.items
      totalVulns.value = res.data.total
      cargasTotal.value = res.data.cargas_total || 0
    } else {
      vulns.value = []
      totalVulns.value = 0
      cargasTotal.value = 0
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
    const { agents, cves, packages, severities, os_list } = res.data || {}
    
    agentOptions.value = (agents || []).sort()
    vulnOptions.value = (cves || []).sort()
    packageOptions.value = (packages || []).sort()
    
    const uniquePlatforms = [...new Set((os_list || []).map(o => o.platform).filter(Boolean))]
    osOptions.value = uniquePlatforms.sort()
    
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
  cargasPage.value = 1
  fetchFilterOptionsData()
  fetchVulns()
}

const clearFilters = () => {
  selectedConnection.value = ''
  selectedAgents.value = []
  selectedVulns.value = []
  selectedPackages.value = []
  selectedSeverities.value = []
  selectedOS.value = []
  detectedAfter.value = ''
  detectedBefore.value = ''
  scoreMin.value = ''
  scoreMax.value = ''
  currentPage.value = 1
  cargasPage.value = 1
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
.cargas-evolution-cell {
  display: flex;
  justify-content: center;
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
.filter-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); align-items: center; }
.f-group { display: flex; flex-direction: column; padding: 1rem 1.2rem; border-right: 1px solid var(--border); border-bottom: 1px solid var(--border); }
.f-group.date-group { grid-column: span 2; }
.f-group:last-child { border-right: none; }
.f-group label, .f-group .f-label { display: block; font-size: 0.7rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 0.5rem; }
.filter-input, .dd-btn { width: 100%; padding: 0.55rem 0.8rem; border: 1px solid var(--border); background: var(--bg-dark); border-radius: var(--radius-sm); color: var(--text-main); cursor: pointer; font-size: 0.85rem; }
.filter-input:disabled, .dd-btn:disabled { opacity: 0.5; cursor: not-allowed; }
.range-inputs { display: flex; flex-wrap: nowrap; align-items: center; gap: 0.4rem; }
.range-inputs span { color: var(--text-muted); font-weight: 600; }
.filter-input-sm { flex: 1; min-width: 80px; padding: 0.45rem 0.6rem; border: 1px solid var(--border); background: var(--bg-dark); border-radius: var(--radius-sm); color: var(--text-main); font-size: 0.8rem; }
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
.status-chip { display: inline-block; margin-left: 0.5rem; padding: 0.1rem 0.45rem; border-radius: 999px; font-size: 0.68rem; font-weight: 700; vertical-align: middle; white-space: nowrap; }
.st-removed { background: #fef3c7; color: #92400e; border: 1px solid #fcd34d; }
.st-resolved { background: #dcfce7; color: #166534; border: 1px solid #86efac; }
.badge-critical { background: rgba(220, 38, 38, 0.15); color: #dc2626; }
.badge-high { background: rgba(234, 88, 12, 0.15); color: #ea580c; }
.badge-medium { background: rgba(234, 179, 8, 0.15); color: #eab308; }
.badge-low { background: rgba(59, 130, 246, 0.15); color: #3b82f6; }
@media (max-width: 1600px) { .filter-row { grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); } }
@media (max-width: 1200px) { .filter-row { grid-template-columns: 1fr 1fr; } .f-group { border-right: none; } }

/* Cargas Pagination Styles */
.cargas-pagination-bar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.75rem 1.5rem;
  background-color: var(--bg-dark);
  border-bottom: 1px solid var(--border);
  border-top-left-radius: var(--radius-md);
  border-top-right-radius: var(--radius-md);
  font-size: 0.85rem;
  color: var(--text-muted);
}
.cargas-pagination-info strong {
  color: var(--primary);
}
.cargas-pagination-nav {
  display: flex;
  gap: 0.5rem;
}
.btn-cargas-page {
  display: inline-flex;
  align-items: center;
  padding: 0.4rem 0.75rem;
  background-color: var(--bg-panel);
  border: 1px solid var(--border);
  color: var(--text-main);
  border-radius: 6px;
  font-size: 0.8rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s ease;
}
.btn-cargas-page:hover:not(:disabled) {
  background-color: var(--bg-hover);
  border-color: var(--primary);
  color: var(--primary);
}
.btn-cargas-page:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

/* Sticky columns for the table */
.vuln-table {
  border-collapse: separate;
  border-spacing: 0;
}

.vuln-table th:first-child,
.vuln-table td:first-child {
  position: sticky;
  left: 0;
  background-color: var(--bg-card) !important;
  z-index: 5;
  border-right: 1px solid var(--border);
  width: 110px !important;
  min-width: 110px !important;
  max-width: 110px !important;
}

.vuln-table th:first-child {
  background-color: var(--bg-panel) !important;
  z-index: 6;
}

.vuln-table th:nth-child(2),
.vuln-table td:nth-child(2) {
  position: sticky;
  left: 110px;
  background-color: var(--bg-card) !important;
  z-index: 5;
  border-right: 1px solid var(--border);
  width: 200px !important;
  min-width: 200px !important;
  max-width: 200px !important;
}

.vuln-table th:nth-child(2) {
  background-color: var(--bg-panel) !important;
  z-index: 6;
}

.vuln-table th:not(:first-child):not(:nth-child(2)),
.vuln-table td:not(:first-child):not(:nth-child(2)) {
  min-width: 130px;
  text-align: center;
}

/* Dashboard layout hero card */
.dashboard-hero {
  display: grid;
  grid-template-columns: 1fr 1.6fr;
  gap: 2rem;
  margin-bottom: 2rem;
  background-color: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 1.5rem;
}
@media (max-width: 1024px) {
  .dashboard-hero {
    grid-template-columns: 1fr;
  }
}
.hero-chart-container {
  background-color: var(--bg-dark);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 1.5rem;
  display: flex;
  flex-direction: column;
  justify-content: center;
}
.hero-chart-container h3 {
  font-size: 0.9rem;
  color: var(--text-muted);
  text-transform: uppercase;
  margin-bottom: 1.25rem;
  letter-spacing: 0.05em;
  font-weight: 600;
  text-align: center;
}
.hero-metrics-container {
  display: flex;
  flex-direction: column;
  justify-content: center;
  gap: 1rem;
}
.hero-title {
  font-size: 1.5rem;
  font-weight: 700;
  color: var(--text-main);
  margin-bottom: 0.5rem;
  border-left: 4px solid var(--primary);
  padding-left: 0.75rem;
}
.metrics-2x2-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
}
@media (max-width: 520px) {
  .metrics-2x2-grid {
    grid-template-columns: 1fr;
  }
}

.chart-container {
  background-color: var(--bg-dark);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 1.5rem;
}
.chart-container h3 {
  font-size: 0.9rem;
  color: var(--text-muted);
  text-transform: uppercase;
  margin-bottom: 1.25rem;
  letter-spacing: 0.05em;
  font-weight: 600;
}
.canvas-wrapper {
  height: 250px;
  position: relative;
}
</style>
