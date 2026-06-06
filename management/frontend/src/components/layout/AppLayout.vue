<script setup lang="ts">
import AppSidebar from './AppSidebar.vue'
import AppMobileDrawer from './AppMobileDrawer.vue'
import { useUiStore } from '@/stores/ui'
import { Menu } from 'lucide-vue-next'

const ui = useUiStore()
</script>

<template>
  <div class="min-h-screen bg-white dark:bg-gray-900 text-gray-700 dark:text-gray-100">
    <AppSidebar class="hidden md:flex" />
    <AppMobileDrawer />

    <div
      :class="[
        'transition-[margin] duration-300 md:min-h-screen',
        ui.sidebarCollapsed ? 'md:ml-14' : 'md:ml-[260px]',
      ]"
    >
      <!-- Mobile top bar -->
      <div class="flex items-center gap-3 px-4 py-3 border-b border-gray-100 dark:border-gray-800 md:hidden">
        <button
          class="rounded-xl hover:bg-gray-100 dark:hover:bg-gray-850 size-9 flex items-center justify-center transition"
          @click="ui.openMobileSidebar()"
        >
          <Menu class="size-5" />
        </button>
        <span class="text-sm font-medium">Mail-in-a-Box</span>
      </div>

      <div class="p-6">
        <slot />
      </div>
    </div>
  </div>
</template>
