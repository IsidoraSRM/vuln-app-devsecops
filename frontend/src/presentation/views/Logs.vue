<template>
  <div class="logs-panel">
    <h2>Logs</h2>
    <div class="controls">
      <label>Lines: <input type="number" v-model.number="lines" min="10" step="10" /></label>
      <label>Filter: <input v-model="filter" placeholder="request_id or free text" /></label>
      <label><input type="checkbox" v-model="autoRefresh" /> Auto-refresh</label>
      <label>Interval (s): <input type="number" v-model.number="intervalSec" min="1" style="width:5rem"/></label>
      <button class="btn" @click="refresh">Actualizar</button>
      <button class="btn" @click="clearFilter">Limpiar</button>
    </div>

    <div class="log-list">
      <table class="log-table" aria-label="Lista de logs">
        <caption class="table-caption">Últimas entradas de log</caption>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Level</th>
            <th>Event</th>
            <th>Request ID</th>
            <th>Trace ID</th>
            <th>Extra</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(l, idx) in filteredLogs" :key="idx">
            <td>{{ l.timestamp || '-' }}</td>
            <td>{{ l.level || '-' }}</td>
            <td>{{ l.event || l.raw }}</td>
            <td>
              <a href="#" @click.prevent="setFilter(l.request_id)" v-if="l.request_id">{{ l.request_id }}</a>
            </td>
            <td>{{ l.trace_id || '-' }}</td>
            <td><pre class="extra">{{ l.extra_preview }}</pre></td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import logsService from '../../application/services/logsService'

const lines = ref(200)
const rawText = ref('')
const parsedLogs = ref([])
const filter = ref('')
const autoRefresh = ref(false)
const intervalSec = ref(5)
let timerId = null

function parseLines(linesArr) {
  const parsed = linesArr.map(line => {
    if (!line) return { raw: '' }
    try {
      const obj = JSON.parse(line)
      const { timestamp, level, event, request_id, trace_id, exception, ...rest } = obj
      const extra_preview = Object.keys(rest).length ? JSON.stringify(rest) : ''
      return { raw: line, timestamp, level, event, request_id, trace_id, exception, extra_preview }
    } catch (e) {
      return { raw: line }
    }
  })
  return parsed.reverse()
}

async function refresh() {
  try {
    const res = await logsService.tail(lines.value)
    rawText.value = res.data.lines.join('\n')
    parsedLogs.value = parseLines(res.data.lines)
  } catch (e) {
    rawText.value = 'Error: ' + (e.message || JSON.stringify(e))
    parsedLogs.value = [{ raw: rawText.value }]
  }
}

const filteredLogs = computed(() => {
  if (!filter.value) return parsedLogs.value
  const f = filter.value.toLowerCase()
  return parsedLogs.value.filter(l => {
    return (
      (l.request_id && l.request_id.toLowerCase().includes(f)) ||
      (l.trace_id && l.trace_id.toLowerCase().includes(f)) ||
      (l.event && String(l.event).toLowerCase().includes(f)) ||
      (l.raw && l.raw.toLowerCase().includes(f))
    )
  })
})

function setFilter(id) {
  if (!id) return
  filter.value = id
}

function clearFilter() {
  filter.value = ''
}

function startTimer() {
  stopTimer()
  if (autoRefresh.value) {
    timerId = setInterval(refresh, Math.max(1000, intervalSec.value * 1000))
  }
}

function stopTimer() {
  if (timerId) {
    clearInterval(timerId)
    timerId = null
  }
}

onMounted(() => {
  refresh()
  startTimer()
})

onUnmounted(() => {
  stopTimer()
})

// watch autoRefresh/interval
const stopWatchAuto = () => {
  // simple polling via setInterval managed in startTimer
}

</script>

<style scoped>
.logs-panel { padding:1rem; background:var(--bg-panel); border-radius:8px }
.controls { display:flex; gap:0.5rem; align-items:center; margin-bottom:0.5rem; flex-wrap:wrap }
.log-table { width:100%; border-collapse:collapse; font-family:monospace }
.log-table th { text-align:left; padding:0.4rem; border-bottom:1px solid var(--border) }
.log-table td { padding:0.4rem; border-bottom:1px solid rgba(255,255,255,0.03); vertical-align:top }
.extra { margin:0; white-space:pre-wrap; max-width:28rem }
.btn { background:var(--primary); color:#fff; padding:0.4rem 0.6rem; border-radius:6px }
</style>
