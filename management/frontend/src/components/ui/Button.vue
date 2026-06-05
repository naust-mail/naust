<script setup lang="ts">
import { computed } from 'vue'

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'destructive'
type ButtonSize = 'sm' | 'md' | 'lg'

const props = withDefaults(
  defineProps<{
    variant?: ButtonVariant
    size?: ButtonSize
    disabled?: boolean
    type?: 'button' | 'submit' | 'reset'
  }>(),
  { variant: 'primary', size: 'md', type: 'button' },
)

const classes = computed(() => {
  const base =
    'inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 disabled:pointer-events-none disabled:opacity-50'

  const variants: Record<ButtonVariant, string> = {
    primary:
      'bg-black text-white hover:bg-gray-900 dark:bg-white dark:text-black dark:hover:bg-gray-100',
    secondary:
      'bg-gray-50 text-gray-700 hover:bg-gray-100 dark:bg-gray-850 dark:text-gray-100 dark:hover:bg-gray-800',
    ghost: 'hover:bg-gray-100 dark:hover:bg-gray-900 text-gray-700 dark:text-gray-300',
    destructive: 'bg-red-600 text-white hover:bg-red-700',
  }

  const sizes: Record<ButtonSize, string> = {
    sm: 'h-8 px-3 text-xs',
    md: 'h-9 px-4 text-sm',
    lg: 'h-10 px-5 text-sm',
  }

  return [base, variants[props.variant], sizes[props.size]]
})
</script>

<template>
  <button :class="classes" :type="type" :disabled="disabled">
    <slot />
  </button>
</template>
