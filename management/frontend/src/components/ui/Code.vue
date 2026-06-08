<script setup lang="ts">
/** Inline or block monospace code element using the design system's muted surface. */
withDefaults(defineProps<{ block?: boolean }>(), { block: false })
</script>

<template>
  <code
    :class="block
      ? 'block text-xs font-mono bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 px-3 py-2 rounded-lg select-all tracking-wider'
      : 'text-xs bg-gray-100 dark:bg-gray-800 px-1 py-0.5 rounded font-mono'"
  ><slot /></code>
</template>
