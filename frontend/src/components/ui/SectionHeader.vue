<script setup lang="ts">
defineProps<{ title: string; description?: string }>()
</script>

<template>
  <div :class="['flex justify-between mb-3 gap-3', description ? 'items-start' : 'items-center']">
    <div>
      <h2 class="text-base font-semibold">{{ title }}</h2>
      <p v-if="description" class="text-sm text-muted mt-0.5">{{ description }}</p>
    </div>
    <div class="flex items-center gap-2 shrink-0">
      <slot name="actions" />
    </div>
  </div>
</template>
