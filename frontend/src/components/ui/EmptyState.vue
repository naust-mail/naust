<script setup lang="ts">
withDefaults(
  defineProps<{
    title: string
    description?: string
    /** Set when this EmptyState stands in for a Table or Card in an
     * AsyncState rotation, so it keeps the same visual boundary as its
     * loading/content siblings instead of losing its container. Leave
     * false when it's already nested inside a Card. */
    bordered?: boolean
  }>(),
  { bordered: false },
)
</script>

<template>
  <div
    :class="[
      'flex flex-col items-center justify-center py-16 text-center',
      bordered && 'rounded-2xl border border-border bg-surface',
    ]"
  >
    <div v-if="$slots.icon" class="text-3xl mb-3">
      <slot name="icon" />
    </div>
    <h3 class="text-lg font-medium text-text">{{ title }}</h3>
    <p v-if="description" class="text-xs text-muted mt-1">{{ description }}</p>
    <div v-if="$slots.action" class="mt-4">
      <slot name="action" />
    </div>
  </div>
</template>
