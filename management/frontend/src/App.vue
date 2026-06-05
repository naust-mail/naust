<script setup lang="ts">
import { onMounted } from 'vue'
import { Toaster } from 'vue-sonner'

// Apply dark class to <html> based on OS preference. No manual toggle needed.
onMounted(() => {
  const mq = window.matchMedia('(prefers-color-scheme: dark)')
  document.documentElement.classList.toggle('dark', mq.matches)
  mq.addEventListener('change', (e) => document.documentElement.classList.toggle('dark', e.matches))
})
</script>

<template>
  <router-view />
  <Toaster position="bottom-right" rich-colors />
</template>
