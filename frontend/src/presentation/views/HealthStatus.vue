<template>
  <div class="health-panel">
    <h2>Estado del Sistema</h2>
    <div class="status-row">
      <div class="status-dot" :class="statusClass"></div>
      <div class="status-info">
        <div class="status-text">{{ statusText }}</div>
        <div class="status-details" v-if="details">{{ details }}</div>
      </div>
    </div>

    <div class="actions">
      <button class="btn" @click="checkHealth">Revisar ahora</button>
      <a class="btn btn-link" :href="metricsUrl" target="_blank">Ver métricas</a>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue'
import healthService from '../../application/services/healthService'

const status = ref('unknown')
const details = ref('')

const metricsUrl = `${import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000'}/metrics`

const statusText = computed(() => {
  if (status.value === 'ok') return 'Operativo'
  if (status.value === 'fail') return 'Problemas'
  return 'Desconocido'
})

const statusClass = computed(() => {
  return status.value === 'ok' ? 'ok' : status.value === 'fail' ? 'fail' : 'unknown'
})

async function checkHealth() {
  try {
    const res = await healthService.getHealth()
    if (res.status === 200 && res.data && res.data.status === 'ok') {
      status.value = 'ok'
      details.value = ''
    } else {
      status.value = 'fail'
      details.value = JSON.stringify(res.data)
    }
  } catch (err) {
    status.value = 'fail'
    details.value = err.message || String(err)
  }
}

onMounted(() => {
  checkHealth()
})
</script>

<style scoped>
.health-panel { max-width: 720px; padding: 1rem; background: var(--bg-panel); border-radius: 8px; }
.status-row { display:flex; align-items:center; gap:1rem; margin:1rem 0 }
.status-dot { width:18px; height:18px; border-radius:50%; background:#ccc }
.status-dot.ok { background: #16a34a }
.status-dot.fail { background: #dc2626 }
.status-text { font-weight:700 }
.status-details { color:var(--text-muted); font-size:0.9rem }
.actions { margin-top:1rem; display:flex; gap:0.5rem }
.btn { background:var(--primary); color:white; padding:0.5rem 0.75rem; border-radius:6px; border:none }
.btn-link { background:transparent; color:var(--primary); border:1px solid transparent }
</style>
