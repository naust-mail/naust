<script setup lang="ts">
import { useUiStore } from '@/stores/ui'
import AppSidebar from './AppSidebar.vue'

const ui = useUiStore()
</script>

<template>
  <Teleport to="body">
    <!-- Backdrop -->
    <Transition
      enter-from-class="opacity-0"
      enter-active-class="transition duration-[10ms]"
      leave-to-class="opacity-0"
      leave-active-class="transition duration-[10ms]"
    >
      <div
        v-if="ui.mobileSidebarOpen"
        class="fixed inset-0 z-40 bg-black/60 md:hidden"
        @click="ui.closeMobileSidebar()"
      />
    </Transition>

    <!-- Drawer -->
    <Transition
      enter-from-class="-translate-x-full"
      enter-active-class="transition-transform duration-250"
      leave-to-class="-translate-x-full"
      leave-active-class="transition-transform duration-250"
    >
      <div v-if="ui.mobileSidebarOpen" class="fixed inset-y-0 left-0 z-50 md:hidden">
        <AppSidebar class="flex" />
      </div>
    </Transition>
  </Teleport>
</template>
