<script setup lang="ts">
import { ref, watch, nextTick } from 'vue'
import { X } from 'lucide-vue-next'
import { useModalKeyboard } from '@/composables/useModalKeyboard'

const open = defineModel<boolean>()
defineProps<{ title?: string }>()

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

useModalKeyboard(open, panelRef, () => { open.value = false })
</script>

<template>
  <Teleport to="body">
    <!-- Backdrop -->
    <Transition
      enter-from-class="opacity-0"
      enter-active-class="transition duration-200"
      leave-to-class="opacity-0"
      leave-active-class="transition duration-200"
    >
      <div
        v-if="open"
        class="fixed inset-0 z-40 bg-black/60"
        @click="open = false"
      />
    </Transition>

    <!-- Panel -->
    <Transition
      enter-from-class="translate-x-full"
      enter-active-class="transition-transform duration-200 ease-out"
      leave-to-class="translate-x-full"
      leave-active-class="transition-transform duration-200 ease-in"
    >
      <div
        v-if="open"
        ref="panelRef"
        role="dialog"
        aria-modal="true"
        :aria-label="title"
        tabindex="-1"
        class="fixed inset-y-0 right-0 z-50 flex flex-col w-full sm:w-[480px] lg:w-[560px] bg-surface shadow-3xl rounded-l-2xl outline-none"
      >
        <div class="flex items-center justify-between px-6 py-4 border-b border-border shrink-0">
          <h2 class="text-base font-semibold">{{ title }}</h2>
          <button
            class="rounded-xl hover:bg-hover size-8 flex items-center justify-center transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            aria-label="Close"
            @click="open = false"
          >
            <X class="size-4" />
          </button>
        </div>
        <div class="flex-1 overflow-y-auto p-6">
          <slot />
        </div>
        <!-- danger slot: adds a top border divider before destructive actions -->
        <div v-if="$slots.danger" class="px-6 py-4 border-t border-border shrink-0">
          <slot name="danger" />
        </div>
        <div v-if="$slots.footer" class="px-6 py-4 border-t border-border shrink-0">
          <slot name="footer" />
        </div>
      </div>
    </Transition>
  </Teleport>
</template>
