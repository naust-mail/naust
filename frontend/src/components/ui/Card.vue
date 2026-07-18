<script setup lang="ts">
/** The card's own padding scale, so pages share one source of truth
 * instead of each hand-picking a p-4/p-5/p-6 utility. "none" is the
 * default for cards that wrap their own padded content (e.g. a Table). */
type CardPadding = 'none' | 'sm' | 'md' | 'lg'

const PADDING_CLASS: Record<CardPadding, string> = {
  none: '',
  sm: 'p-4',
  md: 'p-5',
  lg: 'p-6',
}

const props = withDefaults(defineProps<{ class?: string; padding?: CardPadding }>(), {
  padding: 'none',
})
</script>

<template>
  <div
    class="rounded-2xl border border-border bg-surface"
    :class="[PADDING_CLASS[props.padding], $props.class]"
  >
    <slot />
  </div>
</template>
