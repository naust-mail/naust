<script setup lang="ts">
defineProps<{ clickable?: boolean }>()
defineEmits<{ click: [] }>()
</script>

<template>
  <tr
    :class="[
      'border-b border-border last:border-0',
      clickable && 'cursor-pointer hover:bg-hover-subtle transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:-ring-offset-2 focus-visible:ring-accent',
    ]"
    :tabindex="clickable ? 0 : undefined"
    @click="clickable && $emit('click')"
    @keydown.enter="clickable && $emit('click')"
    @keydown.space.prevent="clickable && $emit('click')"
  >
    <slot />
  </tr>
</template>
