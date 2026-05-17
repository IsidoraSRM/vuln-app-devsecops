<template>
  <div class="traces-panel">
    <h2>Trazas</h2>
    <p>Abre tu visualizador de trazas (Jaeger/Tempo) configurado.</p>
    <div class="actions">
      <a :href="tracesUrl" target="_blank" class="btn">Abrir Trazas</a>
    </div>
    <p v-if="!tracesUrl">No hay URL configurada. Define `VITE_TRACES_URL` en frontend/.env</p>
  </div>
</template>

<script setup>
const tracesUrl = import.meta.env.VITE_TRACES_URL || ''
</script>

<style scoped>
.traces-panel { padding:1rem; background:var(--bg-panel); border-radius:8px }
.btn { background:var(--primary); color:#fff; padding:0.4rem 0.6rem; border-radius:6px }
</style>
