<script setup lang="ts">
import { computed, ref } from 'vue';
import { Eye, EyeOff } from 'lucide-vue-next'
import { UI_SIZE_HEIGHT, UI_SIZE_TEXT, type UiSize } from '@/components/ui/sizes'

defineOptions({ inheritAttrs: false })

const model = defineModel<string>()

const props = withDefaults(
  defineProps<{
    type?: string
    placeholder?: string
    disabled?: boolean
    autocomplete?: string
    inputmode?: 'text' | 'numeric' | 'decimal' | 'email' | 'tel' | 'search' | 'url' | 'none'
    maxlength?: number
    required?: boolean
    size?: UiSize
  }>(),
  { size: 'md' },
)

const showPassword = ref(false)

const computedType = computed(() => {
  if (props.type !== 'password') return props.type ?? 'text'
  return showPassword.value ? 'text' : 'password'
})

function togglePassword() {
  showPassword.value = !showPassword.value
}

const paddingBySize: Record<UiSize, string> = { sm: 'px-3', md: 'px-4', lg: 'px-5' }

const inputClass = computed(() => {
  return [
    `w-full rounded-lg ${UI_SIZE_HEIGHT[props.size]} ${paddingBySize[props.size]} ${UI_SIZE_TEXT[props.size]} bg-subtle text-text outline-none border border-border-input focus:border-accent ring-2 ring-transparent focus:ring-accent-ring transition-colors`,
    props.type === 'password' ? 'pr-10' : ''
  ]
})
</script>

<template>
  <div class="relative w-full">
    <input
      v-model="model"
      v-bind="$attrs"
      :type="computedType"
      :placeholder="placeholder"
      :disabled="disabled"
      :autocomplete="autocomplete"
      :inputmode="inputmode"
      :maxlength="maxlength"
      :required="required"
      :class="inputClass"
    />

    <button
      v-if="type === 'password'"
      type="button"
      @click="togglePassword"
      class="absolute right-3 top-1/2 -translate-y-1/2 text-muted hover:text-text transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent rounded"
      :aria-label="showPassword ? 'Hide password' : 'Show password'"
      :aria-pressed="showPassword"
    >
      <Eye v-if="!showPassword" :size="18" />
      <EyeOff v-else :size="18" />
    </button>
  </div>
</template>
