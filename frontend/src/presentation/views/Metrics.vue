<template>
  <div class="metrics-panel">
    <div class="metrics-head">
      <div>
        <h2>Métricas</h2>
        <p class="subtitle">Contadores del backend desde su arranque (se reinician al redeploy).</p>
      </div>
      <span v-if="autoRefresh" class="live"><span class="live-dot"></span> EN VIVO · {{ intervalSec }}s</span>
    </div>

    <div v-if="data.error" class="err">No se pudieron cargar las métricas: {{ data.error }}</div>

    <section class="group">
      <h3 class="group-title">Vulnerabilidades</h3>
      <div class="cards">
        <div class="card accent">
          <span class="card-val">{{ fmt(data.vulnerabilities_detected_total) }}</span>
          <span class="card-lbl">Detectadas (en esta ejecución)</span>
        </div>
      </div>
    </section>

    <section class="group">
      <h3 class="group-title">Autenticación</h3>
      <div class="cards">
        <div class="card">
          <span class="card-val">{{ fmt(data.login_attempts_total) }}</span>
          <span class="card-lbl">Intentos de login</span>
        </div>
        <div class="card good">
          <span class="card-val">{{ fmt(data.login_success_total) }}</span>
          <span class="card-lbl">Logins exitosos</span>
        </div>
        <div class="card bad">
          <span class="card-val">{{ fmt(data.login_failures_total) }}</span>
          <span class="card-lbl">Logins fallidos</span>
        </div>
      </div>
    </section>

    <section class="group">
      <h3 class="group-title">Sincronización</h3>
      <div class="cards">
        <div class="card">
          <span class="card-val">{{ fmt(data.sync_duration_ms_count) }}</span>
          <span class="card-lbl">Sync ejecutados</span>
        </div>
        <div class="card">
          <span class="card-val">{{ syncTotalS ?? '—' }}<small v-if="syncTotalS"> s</small></span>
          <span class="card-lbl">Tiempo total</span>
        </div>
        <div class="card">
          <span class="card-val">{{ syncMeanS ?? '—' }}<small v-if="syncMeanS"> s</small></span>
          <span class="card-lbl">Sync promedio</span>
        </div>
      </div>
    </section>

    <div class="actions">
      <button class="btn" @click="refresh">Actualizar</button>
      <label class="chk"><input type="checkbox" v-model="autoRefresh" /> Auto-refresh</label>
      <label class="chk">cada <input type="number" v-model.number="intervalSec" min="1" style="width:4rem" /> s</label>
      <a :href="metricsUrl" target="_blank" rel="noopener" class="btn ghost">Ver raw /metrics</a>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import apiClient from '../../infrastructure/http/apiClient'

const data = ref({})
const metricsUrl = '/api/metrics'
const autoRefresh = ref(false)
const intervalSec = ref(10)
let timer = null

function fmt(v) {
  const n = Number(v)
  return Number.isFinite(n) ? n.toLocaleString() : '—'
}

// La métrica del backend es `sync_duration_ms` (milisegundos). Se muestra en segundos.
const syncCount = computed(() => Number(data.value.sync_duration_ms_count || 0))
const syncMeanS = computed(() => {
  if (!syncCount.value) return null
  return (Number(data.value.sync_duration_ms_sum || 0) / syncCount.value / 1000).toFixed(3)
})
const syncTotalS = computed(() => {
  const sum = Number(data.value.sync_duration_ms_sum || 0)
  if (!sum) return null
  return (sum / 1000).toFixed(3)
})

async function refresh() {
  try {
    const res = await apiClient.get('/metrics-summary')
    data.value = res.data
  } catch (e) {
    data.value = { error: e.message || String(e) }
  }
}

function startTimer() {
  stopTimer()
  if (autoRefresh.value) {
    timer = setInterval(() => {
      if (typeof document === 'undefined' || document.visibilityState === 'visible') refresh()
    }, Math.max(1000, intervalSec.value * 1000))
  }
}
function stopTimer() {
  if (timer) { clearInterval(timer); timer = null }
}

watch([autoRefresh, intervalSec], startTimer)
onMounted(refresh)
onUnmounted(stopTimer)
</script>

<style scoped>
.metrics-panel { padding: 1.25rem 1.5rem; background: var(--bg-panel); border: 1px solid var(--border); border-radius: 12px; }
.metrics-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 1rem; margin-bottom: 1rem; }
.metrics-head h2 { margin: 0; font-size: 1.35rem; color: var(--text-main); }
.subtitle { margin: 0.2rem 0 0; color: var(--text-muted); font-size: 0.85rem; }

.live { display: inline-flex; align-items: center; gap: 0.4rem; font-size: 0.72rem; font-weight: 700; letter-spacing: 0.04em; color: var(--success); background: var(--success-bg); padding: 0.3rem 0.6rem; border-radius: 999px; white-space: nowrap; }
.live-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--success); animation: pulse 1.6s infinite; }
@keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(5,150,105,0.5); } 70% { box-shadow: 0 0 0 6px rgba(5,150,105,0); } 100% { box-shadow: 0 0 0 0 rgba(5,150,105,0); } }

.err { background: var(--danger-bg); color: var(--danger); padding: 0.6rem 0.8rem; border-radius: 8px; font-size: 0.85rem; margin-bottom: 1rem; }

.group { margin-bottom: 1.4rem; }
.group-title { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-muted); margin: 0 0 0.6rem; font-weight: 700; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 0.75rem; }
.card { background: var(--bg-dark); border: 1px solid var(--border); border-left: 3px solid var(--border); border-radius: 10px; padding: 0.9rem 1rem; display: flex; flex-direction: column; gap: 0.25rem; }
.card.accent { border-left-color: var(--primary); }
.card.good { border-left-color: var(--success); }
.card.bad { border-left-color: var(--danger); }
.card-val { font-size: 1.6rem; font-weight: 700; color: var(--text-main); font-variant-numeric: tabular-nums; line-height: 1.1; }
.card-val small { font-size: 0.9rem; font-weight: 600; color: var(--text-muted); }
.card-lbl { font-size: 0.78rem; color: var(--text-muted); }

.actions { display: flex; align-items: center; gap: 0.8rem; flex-wrap: wrap; margin-top: 0.5rem; }
.chk { display: inline-flex; align-items: center; gap: 0.4rem; font-size: 0.8rem; color: var(--text-muted); }
.chk input[type="number"] { padding: 0.35rem 0.45rem; border: 1px solid var(--border); border-radius: 6px; background: var(--bg-panel); color: var(--text-main); }
.btn { background: var(--primary); color: #fff; border: none; padding: 0.45rem 0.9rem; border-radius: 7px; font-size: 0.82rem; font-weight: 600; cursor: pointer; text-decoration: none; }
.btn:hover { background: var(--primary-hover); }
.btn.ghost { background: transparent; color: var(--text-muted); border: 1px solid var(--border); }
.btn.ghost:hover { background: var(--bg-hover); color: var(--text-main); }
</style>
