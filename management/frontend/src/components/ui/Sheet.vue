<script setup lang="ts">
import { X } from 'lucide-vue-next'

const open = defineModel<boolean>()
defineProps<{ title?: string }>()
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
        class="fixed inset-y-0 right-0 z-50 flex flex-col w-full sm:w-[480px] lg:w-[560px] bg-white dark:bg-gray-850 shadow-3xl rounded-l-2xl"
      >
        <div class="flex items-center justify-between px-6 py-4 border-b border-gray-100 dark:border-gray-800 shrink-0">
          <h2 class="text-base font-semibold">{{ title }}</h2>
          <button
            class="rounded-xl hover:bg-gray-100 dark:hover:bg-gray-850 size-8 flex items-center justify-center transition"
            @click="open = false"
          >
            <X class="size-4" />
          </button>
        </div>
        <div class="flex-1 overflow-y-auto p-6">
          <slot />
        </div>
        <!-- danger slot: adds a top border divider before destructive actions -->
        <div v-if="$slots.danger" class="px-6 py-4 border-t border-gray-100 dark:border-gray-800 shrink-0">
          <slot name="danger" />
        </div>
        <div v-if="$slots.footer" class="px-6 py-4 border-t border-gray-100 dark:border-gray-800 shrink-0">
          <slot name="footer" />
        </div>
      </div>
    </Transition>
  </Teleport>
</template>
