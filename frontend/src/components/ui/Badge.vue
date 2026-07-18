<script setup lang="ts">
import { computed } from 'vue'

type BadgeVariant = 'default' | 'success' | 'warning' | 'error'

const props = withDefaults(defineProps<{ variant?: BadgeVariant }>(), { variant: 'default' })

const classes = computed(() => {
  const variants: Record<BadgeVariant, string> = {
    default: 'bg-hover text-text',
    success: 'bg-success-bg text-success',
    warning: 'bg-warning-bg text-warning',
    error: 'bg-error-bg text-error',
  }
  return ['inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium transition-colors', variants[props.variant]]
})
</script>

<template>
  <span :class="classes"><slot /></span>
</template>
