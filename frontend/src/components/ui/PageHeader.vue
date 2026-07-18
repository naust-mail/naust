<script setup lang="ts">
defineProps<{ title: string; description?: string }>()
</script>

<template>
  <div class="flex items-start justify-between mb-6">
    <div>
      <h1 class="text-2xl font-semibold">{{ title }}</h1>
      <p v-if="description" class="text-xs text-muted mt-0.5">{{ description }}</p>
      <slot name="description" />
    </div>
    <div class="flex items-center gap-2">
      <slot name="actions" />
    </div>
  </div>
</template>
