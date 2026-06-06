<script setup lang="ts">
import { ChevronDown } from 'lucide-vue-next'

const model = defineModel<string>()
defineProps<{ disabled?: boolean }>()
</script>

<template>
  <div class="relative">
    <select
      v-model="model"
      :disabled="disabled"
      class="w-full rounded-lg py-2 px-3 pr-8 text-sm border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-850 dark:text-gray-300 outline-none focus:border-gray-400 dark:focus:border-gray-500 transition-colors appearance-none"
    >
      <slot />
    </select>
    <ChevronDown class="absolute right-2.5 top-1/2 -translate-y-1/2 size-4 text-gray-400 pointer-events-none" />
  </div>
</template>
