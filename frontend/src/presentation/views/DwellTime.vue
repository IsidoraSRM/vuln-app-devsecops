<template>
  <div class="dwell-panel">
    <div class="dwell-head">
      <div>
        <h2>Tiempo de Exposición <span class="tag">Dwell Time</span></h2>
        <p class="subtitle">Días que una vulnerabilidad estuvo activa desde que se detectó hasta que se remedió.</p>
      </div>
      <label class="conn">
        <span>Conexión</span>
        <select v-model="selectedConnection" @change="load">
          <option :value="null">Todas las conexiones</option>
          <option v-for="c in connections" :key="c.id" :value="c.id">{{ c.name }}</option>
        </select>
      </label>
    </div>

    <div v-if="loading" class="state">Cargando métricas de exposición…</div>
    <div v-else-if="error" class="state err">{{ error }}</div>
    <div v-else-if="!overall.count && !activeCount" class="state empty">
      <strong>Sin vulnerabilidades remediadas aún.</strong>
      <span>El tiempo de exposición se calcula cuando una vulnerabilidad pasa a estado <b>RESOLVED</b>.
      En cuanto haya remediaciones (tras una sincronización que las detecte como resueltas), aparecerán aquí.</span>
    </div>

    <template v-else>
      <!-- ===== REMEDIACIÓN (resueltas) ===== -->
      <template v-if="overall.count">
        <div class="kpis">
          <div class="kpi accent"><span class="kpi-val">{{ fmt(overall.median_days) }}<small> d</small></span><span class="kpi-lbl">Mediana</span></div>
          <div class="kpi"><span class="kpi-val">{{ fmt(overall.avg_days) }}<small> d</small></span><span class="kpi-lbl">Promedio</span></div>
          <div class="kpi warn"><span class="kpi-val">{{ fmt(overall.p90_days) }}<small> d</small></span><span class="kpi-lbl">P90 (peor 10%)</span></div>
          <div class="kpi"><span class="kpi-val">{{ fmt(overall.min_days) }}<small> d</small></span><span class="kpi-lbl">Mínimo</span></div>
          <div class="kpi"><span class="kpi-val">{{ fmt(overall.max_days) }}<small> d</small></span><span class="kpi-lbl">Máximo</span></div>
          <div class="kpi good"><span class="kpi-val">{{ (overall.count || 0).toLocaleString() }}</span><span class="kpi-lbl">Remediadas</span></div>
        </div>

        <!-- ===== CUMPLIMIENTO DE SLA ===== -->
        <section class="section" v-if="slaRows.length">
          <div class="section-head">
            <h3>Cumplimiento de SLA</h3>
            <span class="section-sub">% remediadas dentro del objetivo por severidad</span>
          </div>
          <div class="sla-grid">
            <div class="sla-overall" :class="pctClass(sla.overall && sla.overall.pct)">
              <span class="sla-pct">{{ sla.overall && sla.overall.pct != null ? sla.overall.pct : '—' }}<small>%</small></span>
              <span class="sla-lbl">Global<br>{{ sla.overall ? sla.overall.within : 0 }}/{{ sla.overall ? sla.overall.total : 0 }} a tiempo</span>
            </div>
            <div class="sla-bars">
              <div v-for="row in slaRows" :key="row.sev" class="sla-row">
                <span class="sla-sev" :style="{ color: SEV_COLOR[row.sev] }">{{ SEV_LABEL[row.sev] }}</span>
                <div class="sla-track"><div class="sla-fill" :style="{ width: (row.pct || 0) + '%', background: SEV_COLOR[row.sev] }"></div></div>
                <span class="sla-num">{{ row.pct != null ? row.pct : '—' }}% <small>≤{{ row.target_days }}d ({{ row.within }}/{{ row.total }})</small></span>
              </div>
            </div>
          </div>
        </section>

        <!-- ===== GRÁFICOS ===== -->
        <div class="charts">
          <div class="chart-card">
            <h3 class="chart-title">Mediana de exposición por severidad</h3>
            <div class="chart-box"><canvas ref="sevCanvas"></canvas></div>
          </div>
          <div class="chart-card">
            <h3 class="chart-title">Tendencia mensual de remediaciones</h3>
            <div class="chart-box"><canvas ref="monthCanvas"></canvas></div>
          </div>
        </div>
      </template>

      <!-- ===== EXPOSICIÓN EN CURSO (activas) ===== -->
      <section class="section active-section" v-if="activeCount">
        <div class="section-head">
          <h3>Exposición en curso <span class="tag warn-tag">activas sin remediar</span></h3>
          <span class="section-sub">Antigüedad de las vulnerabilidades aún abiertas (hoy − detección)</span>
        </div>
        <div class="kpis">
          <div class="kpi warn"><span class="kpi-val">{{ activeCount.toLocaleString() }}</span><span class="kpi-lbl">Activas</span></div>
          <div class="kpi"><span class="kpi-val">{{ fmt(activeExposure.overall.median_days) }}<small> d</small></span><span class="kpi-lbl">Antigüedad mediana</span></div>
          <div class="kpi"><span class="kpi-val">{{ fmt(activeExposure.overall.p90_days) }}<small> d</small></span><span class="kpi-lbl">P90</span></div>
          <div class="kpi"><span class="kpi-val">{{ fmt(activeExposure.overall.max_days) }}<small> d</small></span><span class="kpi-lbl">Máxima</span></div>
          <div class="kpi warn"><span class="kpi-val">{{ (activeExposure.overall.over_30 || 0).toLocaleString() }}</span><span class="kpi-lbl">&gt; 30 días</span></div>
          <div class="kpi bad"><span class="kpi-val">{{ (activeExposure.overall.over_90 || 0).toLocaleString() }}</span><span class="kpi-lbl">&gt; 90 días</span></div>
        </div>
      </section>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted, nextTick } from 'vue'
import vulnService from '../../application/services/vulnService'
import wazuhService from '../../application/services/wazuhService'
import { Chart, registerables } from 'chart.js'

Chart.register(...registerables)

const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
const SEV_COLOR = { CRITICAL: '#dc2626', HIGH: '#ea580c', MEDIUM: '#d97706', LOW: '#2563eb' }
const SEV_LABEL = { CRITICAL: 'Crítica', HIGH: 'Alta', MEDIUM: 'Media', LOW: 'Baja' }

const connections = ref([])
const selectedConnection = ref(null)
const loading = ref(true)
const error = ref('')
const overall = ref({ count: 0 })
const bySeverity = ref({})
const monthly = ref([])
const sla = ref({})
const activeExposure = ref({ overall: {} })
const sevCanvas = ref(null)
const monthCanvas = ref(null)
let sevChart = null
let monthChart = null

const activeCount = computed(() => (activeExposure.value.overall && activeExposure.value.overall.count) || 0)
const slaRows = computed(() =>
  SEV_ORDER.filter((s) => sla.value.by_severity && sla.value.by_severity[s])
    .map((s) => ({ sev: s, ...sla.value.by_severity[s] }))
)

function fmt(v) {
  return (v === null || v === undefined) ? '—' : Number(v).toLocaleString(undefined, { maximumFractionDigits: 1 })
}
function pctClass(pct) {
  if (pct == null) return ''
  if (pct >= 90) return 'ok'
  if (pct >= 70) return 'mid'
  return 'low'
}

async function loadConnections() {
  try {
    const res = await wazuhService.getConnections()
    connections.value = res.data || []
  } catch (e) {
    connections.value = []
  }
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const res = await vulnService.getDwellTime(selectedConnection.value)
    const d = res.data || {}
    overall.value = d.overall || { count: 0 }
    bySeverity.value = d.by_severity || {}
    monthly.value = d.monthly_trend || []
    sla.value = d.sla || {}
    activeExposure.value = d.active_exposure || { overall: {} }
  } catch (e) {
    error.value = 'No se pudieron cargar las métricas: ' + (e.message || String(e))
    overall.value = { count: 0 }
    activeExposure.value = { overall: {} }
  } finally {
    loading.value = false
  }
  // El bloque con los <canvas> solo existe con loading=false; por eso el render va DESPUES del finally.
  await nextTick()
  renderCharts()
}

function destroyCharts() {
  if (sevChart) { sevChart.destroy(); sevChart = null }
  if (monthChart) { monthChart.destroy(); monthChart = null }
}

function renderCharts() {
  destroyCharts()
  if (!overall.value.count) return

  if (sevCanvas.value) {
    const sevs = SEV_ORDER.filter((s) => bySeverity.value[s])
    sevChart = new Chart(sevCanvas.value, {
      type: 'bar',
      data: {
        labels: sevs.map((s) => SEV_LABEL[s] || s),
        datasets: [{
          label: 'Mediana (días)',
          data: sevs.map((s) => bySeverity.value[s].median_days),
          backgroundColor: sevs.map((s) => SEV_COLOR[s] || '#6b7280'),
          borderRadius: 6,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true, title: { display: true, text: 'Días' } } },
      },
    })
  }

  if (monthCanvas.value) {
    monthChart = new Chart(monthCanvas.value, {
      data: {
        labels: monthly.value.map((m) => m.month),
        datasets: [
          {
            type: 'bar', label: 'Remediadas', data: monthly.value.map((m) => m.resolved_count),
            backgroundColor: 'rgba(110,164,42,0.35)', borderColor: '#6ea42a', borderWidth: 1,
            yAxisID: 'y', borderRadius: 4,
          },
          {
            type: 'line', label: 'Promedio exposición (días)', data: monthly.value.map((m) => m.avg_days),
            borderColor: '#dc2626', backgroundColor: '#dc2626', tension: 0.3, pointRadius: 3, yAxisID: 'y1',
          },
        ],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        interaction: { mode: 'index', intersect: false },
        scales: {
          y: { beginAtZero: true, position: 'left', title: { display: true, text: 'Remediadas' } },
          y1: { beginAtZero: true, position: 'right', grid: { drawOnChartArea: false }, title: { display: true, text: 'Días' } },
        },
      },
    })
  }
}

onMounted(async () => {
  await loadConnections()
  await load()
})
onUnmounted(destroyCharts)
</script>

<style scoped>
.dwell-panel { padding: 1.25rem 1.5rem; background: var(--bg-panel); border: 1px solid var(--border); border-radius: 12px; }
.dwell-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.25rem; }
.dwell-head h2 { margin: 0; font-size: 1.35rem; color: var(--text-main); display: flex; align-items: center; gap: 0.5rem; }
.tag { font-size: 0.62rem; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase; color: var(--primary); background: var(--primary-glow); padding: 0.2rem 0.45rem; border-radius: 5px; }
.tag.warn-tag { color: var(--warning); background: var(--warning-bg); }
.subtitle { margin: 0.25rem 0 0; color: var(--text-muted); font-size: 0.85rem; }
.conn { display: inline-flex; flex-direction: column; gap: 0.25rem; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-muted); }
.conn select { padding: 0.45rem 0.6rem; border: 1px solid var(--border); border-radius: 8px; background: var(--bg-dark); color: var(--text-main); font-size: 0.85rem; min-width: 200px; }

.state { padding: 2.5rem 1rem; text-align: center; color: var(--text-muted); }
.state.err { color: var(--danger); background: var(--danger-bg); border-radius: 8px; }
.state.empty { display: flex; flex-direction: column; gap: 0.5rem; align-items: center; }
.state.empty strong { color: var(--text-main); font-size: 1.05rem; }
.state.empty span { max-width: 520px; font-size: 0.88rem; line-height: 1.5; }

.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 0.75rem; margin-bottom: 1.5rem; }
.kpi { background: var(--bg-dark); border: 1px solid var(--border); border-left: 3px solid var(--border); border-radius: 10px; padding: 0.9rem 1rem; display: flex; flex-direction: column; gap: 0.2rem; }
.kpi.accent { border-left-color: var(--primary); }
.kpi.warn { border-left-color: var(--warning); }
.kpi.good { border-left-color: var(--success); }
.kpi.bad { border-left-color: var(--danger); }
.kpi-val { font-size: 1.55rem; font-weight: 700; color: var(--text-main); font-variant-numeric: tabular-nums; line-height: 1.1; }
.kpi-val small { font-size: 0.85rem; font-weight: 600; color: var(--text-muted); }
.kpi-lbl { font-size: 0.76rem; color: var(--text-muted); }

.section { margin-bottom: 1.5rem; }
.section-head { display: flex; align-items: baseline; gap: 0.6rem; flex-wrap: wrap; margin-bottom: 0.8rem; }
.section-head h3 { margin: 0; font-size: 1rem; color: var(--text-main); display: flex; align-items: center; gap: 0.4rem; }
.section-sub { font-size: 0.8rem; color: var(--text-muted); }
.active-section { border-top: 1px solid var(--border); padding-top: 1.25rem; }

.sla-grid { display: grid; grid-template-columns: 150px 1fr; gap: 1.25rem; align-items: center; }
.sla-overall { display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 0.3rem; padding: 1rem; border-radius: 12px; border: 1px solid var(--border); background: var(--bg-dark); text-align: center; }
.sla-overall.ok { border-color: var(--success); background: var(--success-bg); }
.sla-overall.mid { border-color: var(--warning); background: var(--warning-bg); }
.sla-overall.low { border-color: var(--danger); background: var(--danger-bg); }
.sla-pct { font-size: 2.1rem; font-weight: 800; color: var(--text-main); line-height: 1; font-variant-numeric: tabular-nums; }
.sla-pct small { font-size: 1rem; font-weight: 600; }
.sla-lbl { font-size: 0.72rem; color: var(--text-muted); }
.sla-bars { display: flex; flex-direction: column; gap: 0.55rem; }
.sla-row { display: grid; grid-template-columns: 60px 1fr auto; gap: 0.7rem; align-items: center; }
.sla-sev { font-size: 0.82rem; font-weight: 700; }
.sla-track { height: 10px; background: var(--bg-dark); border: 1px solid var(--border); border-radius: 999px; overflow: hidden; }
.sla-fill { height: 100%; border-radius: 999px; transition: width 0.4s; }
.sla-num { font-size: 0.8rem; color: var(--text-main); font-variant-numeric: tabular-nums; white-space: nowrap; }
.sla-num small { color: var(--text-muted); font-size: 0.72rem; }

.charts { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
.chart-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 1rem 1.1rem; }
.chart-title { margin: 0 0 0.8rem; font-size: 0.9rem; color: var(--text-main); }
.chart-box { position: relative; height: 280px; }

@media (max-width: 640px) { .sla-grid { grid-template-columns: 1fr; } }
</style>
