<script setup lang="ts">
import { computed } from 'vue'
import { ChevronDown } from 'lucide-vue-next'
import { UI_SIZE_HEIGHT, UI_SIZE_TEXT, type UiSize } from '@/components/ui/sizes'

defineOptions({ inheritAttrs: false })

const model = defineModel<string>()
const props = withDefaults(defineProps<{ disabled?: boolean; size?: UiSize }>(), { size: 'md' })

const paddingBySize: Record<UiSize, string> = { sm: 'px-3', md: 'px-3', lg: 'px-4' }

const selectClass = computed(
  () =>
    `w-full ${UI_SIZE_HEIGHT[props.size]} rounded-lg ${paddingBySize[props.size]} pr-8 ${UI_SIZE_TEXT[props.size]} border border-border-input bg-subtle text-text outline-none focus:border-accent ring-2 ring-transparent focus:ring-accent-ring transition-colors appearance-none`,
)
</script>

<template>
  <div class="relative">
    <select
      v-model="model"
      v-bind="$attrs"
      :disabled="disabled"
      :class="selectClass"
    >
      <slot />
    </select>
    <ChevronDown class="absolute right-2.5 top-1/2 -translate-y-1/2 size-4 text-faint pointer-events-none" />
  </div>
</template>
