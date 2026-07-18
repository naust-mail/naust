<script setup lang="ts">
import { computed } from 'vue'
import { UI_SIZE_HEIGHT, UI_SIZE_TEXT, type UiSize } from '@/components/ui/sizes'

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'destructive' | 'link'
type ButtonSize = UiSize | 'icon'

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
    'inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 disabled:opacity-50'

  const variants: Record<ButtonVariant, string> = {
    primary:
      'bg-accent text-accent-fg hover:bg-accent-hover',
    // Bordered so the button reads as a control against page/card backgrounds
    // that sit close to --color-surface in some palettes, instead of vanishing.
    secondary:
      'bg-surface text-text border border-border hover:bg-hover',
    ghost: 'hover:bg-hover text-text',
    destructive: 'bg-destructive text-destructive-fg hover:bg-destructive-hover',
    // Inline text button - no background, just text color transition. Suitable for
    // "Change", "show more", icon-adjacent actions. Pass class="text-faint" to de-emphasise.
    link: 'text-muted hover:text-text',
  }

  const paddingBySize: Record<UiSize, string> = { sm: 'px-3', md: 'px-4', lg: 'px-5' }

  const sizes: Record<ButtonSize, string> = {
    sm: `${UI_SIZE_HEIGHT.sm} ${paddingBySize.sm} ${UI_SIZE_TEXT.sm}`,
    md: `${UI_SIZE_HEIGHT.md} ${paddingBySize.md} ${UI_SIZE_TEXT.md}`,
    lg: `${UI_SIZE_HEIGHT.lg} ${paddingBySize.lg} ${UI_SIZE_TEXT.lg}`,
    // Icon-only: square with no horizontal padding. Set explicit size on the icon slot.
    icon: 'size-8 p-0',
  }

  // Disabled buttons keep the native `disabled` attribute for real interaction
  // blocking, but hover: utilities still match :hover on disabled elements in
  // CSS - strip them so a disabled button doesn't visually react to hover.
  const variantClass = props.disabled ? variants[props.variant].replace(/hover:\S+/g, '').trim() : variants[props.variant]

  return [base, variantClass, sizes[props.size]]
})
</script>

<template>
  <button :class="classes" :type="type" :disabled="disabled">
    <slot />
  </button>
</template>
