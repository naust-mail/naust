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
      enter-active-class="transition duration-150"
      leave-to-class="opacity-0"
      leave-active-class="transition duration-150"
    >
      <div
        v-if="ui.mobileSidebarOpen"
        class="fixed inset-0 z-40 bg-black/60 md:hidden"
        @click="ui.closeMobileSidebar()"
      />
    </Transition>

    <!-- Drawer: explicit w-[260px] so -translate-x-full = -260px (fully off-screen).
         The transform makes this div the containing block for the fixed AppSidebar inside,
         so the sidebar slides with the wrapper. -->
    <Transition
      enter-from-class="-translate-x-full"
      enter-active-class="transition-transform duration-[250ms] ease-out"
      leave-to-class="-translate-x-full"
      leave-active-class="transition-transform duration-[200ms] ease-in"
    >
      <div v-if="ui.mobileSidebarOpen" class="fixed inset-y-0 left-0 z-50 w-[260px] md:hidden">
        <AppSidebar class="flex" force-expanded />
      </div>
    </Transition>
  </Teleport>
</template>
