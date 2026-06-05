<script setup lang="ts">
defineProps<{ class?: string }>()
</script>

<template>
  <div class="animate-pulse rounded bg-gray-200 dark:bg-gray-800" :class="$props.class" />
</template>
