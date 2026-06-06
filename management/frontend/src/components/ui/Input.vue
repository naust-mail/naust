<script setup lang="ts">
const model = defineModel<string>()

defineProps<{
  type?: string
  placeholder?: string
  disabled?: boolean
  autocomplete?: string
  inputmode?: 'text' | 'numeric' | 'decimal' | 'email' | 'tel' | 'search' | 'url' | 'none'
  maxlength?: number
  required?: boolean
}>()
</script>

<template>
  <input
    v-model="model"
    :type="type ?? 'text'"
    :placeholder="placeholder"
    :disabled="disabled"
    :autocomplete="autocomplete"
    :inputmode="inputmode"
    :maxlength="maxlength"
    :required="required"
    class="w-full rounded-lg py-2 px-4 text-sm bg-gray-50 dark:bg-gray-850 dark:text-gray-300 outline-none border border-gray-200 dark:border-gray-700 focus:border-gray-400 dark:focus:border-gray-500 ring-2 ring-transparent focus:ring-gray-200 dark:focus:ring-gray-700 transition-colors"
  />
</template>
