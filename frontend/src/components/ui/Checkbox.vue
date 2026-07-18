<script setup lang="ts">
withDefaults(defineProps<{ modelValue: boolean; id?: string; disabled?: boolean }>(), {
  id: undefined,
  disabled: false,
})
defineEmits<{ 'update:modelValue': [value: boolean] }>()
</script>

<template>
  <input
    :id="id"
    type="checkbox"
    :checked="modelValue"
    :disabled="disabled"
    class="size-4 rounded border-border-strong bg-surface outline-none ring-2 ring-transparent focus:ring-accent-ring transition-colors"
    @change="$emit('update:modelValue', ($event.target as HTMLInputElement).checked)"
  />
</template>
