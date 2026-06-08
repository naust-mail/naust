<script setup lang="ts">
import { ref, watch, nextTick } from 'vue'

const open = defineModel<boolean>()
defineProps<{
  title: string
  description?: string
}>()

const panelRef = ref<HTMLElement | null>(null)
let triggerEl: HTMLElement | null = null

watch(open, async (val) => {
  if (val) {
    triggerEl = document.activeElement as HTMLElement | null
    await nextTick()
    panelRef.value?.focus()
  } else {
    triggerEl?.focus()
    triggerEl = null
  }
})
</script>

<template>
  <Teleport to="body">
    <!-- Backdrop -->
    <Transition
      enter-from-class="opacity-0"
      enter-active-class="transition duration-150"
      leave-to-class="opacity-0"
      leave-active-class="transition duration-150"
    >
      <div
        v-if="open"
        class="fixed inset-0 z-50 bg-black/60"
        @click="open = false"
      />
    </Transition>

    <!-- Panel - flyAndScale: 200ms, translateY -8px + scale 0.95→1 -->
    <Transition
      enter-from-class="opacity-0 -translate-y-2 scale-95"
      enter-active-class="transition duration-200 ease-out"
      leave-to-class="opacity-0 -translate-y-2 scale-95"
      leave-active-class="transition duration-200 ease-in"
    >
      <div
        v-if="open"
        class="fixed inset-0 z-50 flex items-center justify-center p-4"
        @click.self="open = false"
      >
        <div
          ref="panelRef"
          role="dialog"
          aria-modal="true"
          aria-labelledby="dialog-title"
          tabindex="-1"
          class="bg-white/95 dark:bg-gray-950/95 backdrop-blur-sm rounded-4xl w-full max-w-[32rem] p-6 shadow-3xl outline-none"
        >
          <h3 id="dialog-title" class="text-base font-semibold mb-1">{{ title }}</h3>
          <p v-if="description" class="text-sm text-gray-500 mb-5">{{ description }}</p>
          <div v-if="$slots.default" class="mb-5"><slot /></div>
          <div class="flex justify-end gap-2">
            <slot name="actions" />
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>
