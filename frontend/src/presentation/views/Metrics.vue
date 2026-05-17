<template>
  <div class="metrics-panel">
    <h2>Métricas</h2>
    <div class="metrics-list">
        <div class="metric"><strong>Vulns detectadas:</strong> {{ data.vulnerabilities_detected_total }}</div>
        <div class="metric"><strong>Intentos login:</strong> {{ data.login_attempts_total }}</div>
        <div class="metric"><strong>Logins exitosos:</strong> {{ data.login_success_total }}</div>
        <div class="metric"><strong>Fallos login:</strong> {{ data.login_failures_total }}</div>
        <div class="metric"><strong>Sync count:</strong> {{ data.sync_duration_seconds_count }}</div>
        <div class="metric"><strong>Sync sum (s):</strong> {{ data.sync_duration_seconds_sum }}</div>
        <div class="metric"><strong>Sync p50 (s):</strong> {{ data.sync_duration_p50 }}</div>
        <div class="metric"><strong>Sync p95 (s):</strong> {{ data.sync_duration_p95 }}</div>
        <div class="metric"><strong>Sync mean (s):</strong> {{ meanSync }}</div>
      </div>
    <div class="actions">
      <button class="btn" @click="refresh">Actualizar</button>
      <a :href="metricsUrl" target="_blank" class="btn btn-link">Ver raw /metrics</a>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import apiClient from '../../infrastructure/http/apiClient'

const data = ref({})
const base = (apiClient.defaults && apiClient.defaults.baseURL) ? apiClient.defaults.baseURL.replace(/\/$/, '') : (import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000')
const metricsUrl = `${base}/metrics`
const autoRefresh = ref(false)
const intervalSec = ref(10)
let timer = null

const meanSync = computed(() => {
  const count = Number(data.value.sync_duration_seconds_count || 0)
  const sum = Number(data.value.sync_duration_seconds_sum || 0)
  if (!count) return null
  return (sum / count).toFixed(3)
})

async function refresh() {
  try {
    const res = await apiClient.get('/metrics/json')
    data.value = res.data
  } catch (e) {
    data.value = { error: e.message || String(e) }
  }
}

function startTimer() {
  stopTimer()
  if (autoRefresh.value) {
    timer = setInterval(refresh, Math.max(1000, intervalSec.value * 1000))
  }
}

function stopTimer() {
  if (timer) {
    clearInterval(timer)
    timer = null
  }
}

onMounted(() => {
  refresh()
})

</script>

<style scoped>
.metrics-panel { padding:1rem; background:var(--bg-panel); border-radius:8px }
.metric { margin:0.5rem 0 }
.actions { margin-top:0.5rem }
.btn { background:var(--primary); color:#fff; padding:0.4rem 0.6rem; border-radius:6px }
.btn-link { background:transparent; color:var(--primary); border:1px solid transparent }
</style>
