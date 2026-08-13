<template>
  <div class="logs-panel">
    <div class="logs-head">
      <div>
        <h2>Logs</h2>
        <p class="subtitle">Últimas entradas del backend en tiempo real.</p>
      </div>
      <span v-if="autoRefresh" class="live"><span class="live-dot"></span> EN VIVO · {{ intervalSec }}s</span>
    </div>

    <div class="controls">
      <label class="ctrl">Líneas
        <input type="number" v-model.number="lines" min="10" step="10" @change="refresh" />
      </label>
      <label class="ctrl grow">Filtro
        <input v-model="filter" placeholder="request_id or free text" />
      </label>

      <div class="seg" aria-label="Filtrar por nivel">
        <button
          type="button"
          v-for="opt in levelOptions" :key="opt.key"
          :class="['seg-btn', `seg-${opt.key}`, { active: levelFilter === opt.key }]"
          @click="levelFilter = opt.key"
        >{{ opt.label }} <span class="seg-count">{{ levelCounts[opt.key] }}</span></button>
      </div>

      <label class="ctrl chk"><input type="checkbox" v-model="autoRefresh" /> Auto-refresh</label>
      <label class="ctrl">cada
        <input type="number" v-model.number="intervalSec" min="1" style="width:4rem" /> s
      </label>
      <button type="button" class="btn" @click="refresh">Actualizar</button>
      <button type="button" class="btn ghost" @click="clearFilter">Limpiar</button>
    </div>

    <div class="log-scroll">
      <table class="log-table" aria-label="Lista de logs">
        <caption class="sr-only">Últimas entradas de log</caption>
        <thead>
          <tr>
            <th class="c-time">Hora</th>
            <th class="c-lvl">Nivel</th>
            <th class="c-evt">Evento</th>
            <th class="c-det">Detalle</th>
            <th class="c-req">Request</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(l, idx) in filteredLogs" :key="idx" :class="['row', `row-${levelKey(l.level)}`]">
            <td class="c-time">
              <span class="t-main">{{ fmtTime(l.timestamp).t || '—' }}</span>
              <span class="t-date" v-if="fmtTime(l.timestamp).d">{{ fmtTime(l.timestamp).d }}</span>
            </td>
            <td class="c-lvl">
              <span :class="['badge', `lvl-${levelKey(l.level)}`]">{{ (l.level || 'RAW').toUpperCase() }}</span>
            </td>
            <td class="c-evt">
              <span class="evt">{{ l.event || l.raw }}</span>
              <span class="logger" v-if="l.logger">{{ l.logger }}</span>
            </td>
            <td class="c-det">
              <div class="chips">
                <span v-for="[k, v] in extraEntries(l)" :key="k" class="chip" :title="`${k}: ${formatVal(v)}`">
                  <b>{{ k }}</b>{{ formatVal(v) }}
                </span>
                <span v-if="l.trace_id" class="chip trace" :title="l.trace_id"><b>trace</b>{{ shortId(l.trace_id) }}</span>
              </div>
              <pre v-if="l.exception" class="exc">{{ l.exception }}</pre>
            </td>
            <td class="c-req">
              <a href="#" class="req" @click.prevent="setFilter(l.request_id)" v-if="l.request_id" :title="l.request_id">{{ shortId(l.request_id) }}</a>
              <span v-else class="dash">—</span>
            </td>
          </tr>
        </tbody>
      </table>
      <div v-if="!filteredLogs.length" class="empty">
        {{ filter || levelFilter !== 'ALL' ? 'Ningún log coincide con el filtro.' : 'Sin entradas de log.' }}
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import logsService from '../../application/services/logsService'

const lines = ref(200)
const parsedLogs = ref([])
const filter = ref('')
const levelFilter = ref('ALL')
const autoRefresh = ref(false)
const intervalSec = ref(5)
let timerId = null

const levelOptions = [
  { key: 'ALL', label: 'Todos' },
  { key: 'info', label: 'Info' },
  { key: 'warn', label: 'Warn' },
  { key: 'error', label: 'Error' },
]

function levelKey(level) {
  const l = (level || '').toUpperCase()
  if (['ERROR', 'CRITICAL', 'FATAL', 'EXCEPTION'].includes(l)) return 'error'
  if (['WARNING', 'WARN'].includes(l)) return 'warn'
  if (l === 'INFO') return 'info'
  if (l === 'DEBUG') return 'debug'
  return 'raw'
}

function fmtTime(ts) {
  if (!ts) return { t: '', d: '' }
  const dt = new Date(ts)
  if (Number.isNaN(dt.getTime())) return { t: String(ts), d: '' }
  const pad = (n) => String(n).padStart(2, '0')
  const ms = String(dt.getMilliseconds()).padStart(3, '0')
  return {
    t: `${pad(dt.getHours())}:${pad(dt.getMinutes())}:${pad(dt.getSeconds())}.${ms}`,
    d: `${dt.getFullYear()}-${pad(dt.getMonth() + 1)}-${pad(dt.getDate())}`,
  }
}

function formatVal(v) {
  if (v === null || v === undefined) return ''
  const s = typeof v === 'object' ? JSON.stringify(v) : String(v)
  return s.length > 140 ? s.slice(0, 140) + '…' : s
}

function shortId(id) {
  if (!id) return ''
  return id.length > 10 ? id.slice(0, 8) + '…' : id
}

function extraEntries(l) {
  return Object.entries(l.extra || {})
}

function parseLines(linesArr) {
  const parsed = linesArr.map((line) => {
    if (!line) return { raw: '' }
    try {
      const obj = JSON.parse(line)
      const { timestamp, level, event, request_id, trace_id, logger, exception, ...rest } = obj
      return { raw: line, timestamp, level, event, request_id, trace_id, logger, exception, extra: rest }
    } catch (e) {
      return { raw: line }
    }
  })
  return parsed.reverse()
}

async function refresh() {
  try {
    const res = await logsService.tail(lines.value)
    parsedLogs.value = parseLines(res.data.lines)
  } catch (e) {
    parsedLogs.value = [{ raw: 'Error: ' + (e.message || JSON.stringify(e)), level: 'ERROR' }]
  }
}

const levelCounts = computed(() => {
  const c = { ALL: parsedLogs.value.length, info: 0, warn: 0, error: 0 }
  for (const l of parsedLogs.value) {
    const k = levelKey(l.level)
    if (k in c) c[k]++
  }
  return c
})

const filteredLogs = computed(() => {
  let logs = parsedLogs.value
  if (levelFilter.value !== 'ALL') {
    logs = logs.filter((l) => levelKey(l.level) === levelFilter.value)
  }
  if (filter.value) {
    const f = filter.value.toLowerCase()
    logs = logs.filter((l) =>
      (l.request_id && l.request_id.toLowerCase().includes(f)) ||
      (l.trace_id && l.trace_id.toLowerCase().includes(f)) ||
      (l.event && String(l.event).toLowerCase().includes(f)) ||
      (l.raw && l.raw.toLowerCase().includes(f))
    )
  }
  return logs
})

function setFilter(id) {
  if (!id) return
  filter.value = id
}
function clearFilter() {
  filter.value = ''
  levelFilter.value = 'ALL'
}

function startTimer() {
  stopTimer()
  if (autoRefresh.value) {
    timerId = setInterval(() => {
      // No malgastar peticiones si la pestaña no está visible
      if (typeof document === 'undefined' || document.visibilityState === 'visible') refresh()
    }, Math.max(1000, intervalSec.value * 1000))
  }
}
function stopTimer() {
  if (timerId) {
    clearInterval(timerId)
    timerId = null
  }
}

watch([autoRefresh, intervalSec], startTimer)

onMounted(refresh)
onUnmounted(stopTimer)
</script>

<style scoped>
.logs-panel { padding: 1.25rem 1.5rem; background: var(--bg-panel); border: 1px solid var(--border); border-radius: 12px; }
.logs-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 1rem; margin-bottom: 1rem; }
.logs-head h2 { margin: 0; font-size: 1.35rem; color: var(--text-main); }
.subtitle { margin: 0.2rem 0 0; color: var(--text-muted); font-size: 0.85rem; }

.live { display: inline-flex; align-items: center; gap: 0.4rem; font-size: 0.72rem; font-weight: 700; letter-spacing: 0.04em; color: var(--success); background: var(--success-bg); padding: 0.3rem 0.6rem; border-radius: 999px; white-space: nowrap; }
.live-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--success); box-shadow: 0 0 0 0 var(--success); animation: pulse 1.6s infinite; }
@keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(5,150,105,0.5); } 70% { box-shadow: 0 0 0 6px rgba(5,150,105,0); } 100% { box-shadow: 0 0 0 0 rgba(5,150,105,0); } }

.controls { display: flex; gap: 0.6rem; align-items: center; margin-bottom: 0.85rem; flex-wrap: wrap; }
.ctrl { display: inline-flex; align-items: center; gap: 0.35rem; font-size: 0.8rem; color: var(--text-muted); }
.ctrl.grow { flex: 1 1 200px; }
.ctrl.chk { gap: 0.4rem; }
.controls input[type="number"] { width: 4.5rem; }
.controls input { padding: 0.4rem 0.55rem; border: 1px solid var(--border); border-radius: 7px; background: var(--bg-dark); color: var(--text-main); font-size: 0.82rem; }
.ctrl.grow input { width: 100%; }
.controls input:focus-visible { outline: 2px solid var(--primary); outline-offset: 1px; }

.seg { display: inline-flex; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
.seg-btn { display: inline-flex; align-items: center; gap: 0.3rem; border: none; background: var(--bg-panel); color: var(--text-muted); padding: 0.4rem 0.7rem; font-size: 0.78rem; font-weight: 600; cursor: pointer; border-right: 1px solid var(--border); }
.seg-btn:last-child { border-right: none; }
.seg-btn:hover { background: var(--bg-hover); }
.seg-btn.active { color: #fff; background: var(--primary); }
.seg-btn.seg-warn.active { background: var(--warning); }
.seg-btn.seg-error.active { background: var(--danger); }
.seg-count { font-size: 0.68rem; opacity: 0.8; font-variant-numeric: tabular-nums; }
.seg-btn.active .seg-count { opacity: 0.95; }

.btn { background: var(--primary); color: #fff; border: none; padding: 0.45rem 0.85rem; border-radius: 7px; font-size: 0.82rem; font-weight: 600; cursor: pointer; }
.btn:hover { background: var(--primary-hover); }
.btn.ghost { background: transparent; color: var(--text-muted); border: 1px solid var(--border); }
.btn.ghost:hover { background: var(--bg-hover); color: var(--text-main); }

.log-scroll { max-height: 62vh; overflow: auto; border: 1px solid var(--border); border-radius: 10px; }
.log-table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
.log-table thead th { position: sticky; top: 0; z-index: 1; text-align: left; padding: 0.6rem 0.75rem; background: var(--bg-dark); color: var(--text-muted); font-weight: 600; font-size: 0.72rem; letter-spacing: 0.04em; text-transform: uppercase; border-bottom: 1px solid var(--border); }
.log-table td { padding: 0.55rem 0.75rem; border-bottom: 1px solid var(--border); vertical-align: top; }
.row:hover { background: var(--bg-hover); }
.row td.c-lvl { border-left: 3px solid transparent; }
.row-error td.c-lvl { border-left-color: var(--danger); }
.row-warn td.c-lvl { border-left-color: var(--warning); }
.row-error { background: var(--danger-bg); }
.row-warn { background: var(--warning-bg); }
.row-error:hover, .row-warn:hover { filter: brightness(0.98); }

.c-time { white-space: nowrap; }
.t-main { display: block; font-family: ui-monospace, monospace; color: var(--text-main); font-variant-numeric: tabular-nums; }
.t-date { display: block; font-size: 0.68rem; color: var(--text-muted); }

.badge { display: inline-block; font-size: 0.66rem; font-weight: 700; letter-spacing: 0.05em; padding: 0.15rem 0.45rem; border-radius: 5px; }
.lvl-info { color: #1e40af; background: #dbeafe; }
.lvl-warn { color: var(--warning); background: var(--warning-bg); }
.lvl-error { color: var(--danger); background: var(--danger-bg); }
.lvl-debug { color: var(--text-muted); background: var(--bg-dark); }
.lvl-raw { color: var(--text-muted); background: var(--bg-dark); }

.evt { display: block; color: var(--text-main); font-weight: 600; overflow-wrap: break-word; }
.logger { display: block; font-size: 0.68rem; color: var(--text-muted); font-family: ui-monospace, monospace; margin-top: 0.1rem; }

.chips { display: flex; flex-wrap: wrap; gap: 0.3rem; }
.chip { display: inline-flex; align-items: baseline; gap: 0.3rem; max-width: 100%; font-family: ui-monospace, monospace; font-size: 0.72rem; color: var(--text-main); background: var(--bg-dark); border: 1px solid var(--border); border-radius: 5px; padding: 0.1rem 0.4rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.chip b { color: var(--text-muted); font-weight: 600; }
.chip.trace b { color: var(--primary); }
.exc { margin: 0.4rem 0 0; padding: 0.5rem; background: var(--danger-bg); color: var(--danger); border-radius: 6px; font-size: 0.72rem; white-space: pre-wrap; max-height: 12rem; overflow: auto; }

.req { font-family: ui-monospace, monospace; font-size: 0.75rem; color: var(--primary); text-decoration: none; }
.req:hover { text-decoration: underline; }
.dash { color: var(--text-muted); }

.empty { padding: 2rem; text-align: center; color: var(--text-muted); font-size: 0.85rem; }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); border: 0; }
</style>
