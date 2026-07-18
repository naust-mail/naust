<script setup lang="ts">
import AppSidebar from './AppSidebar.vue'
import AppMobileDrawer from './AppMobileDrawer.vue'
import { useUiStore } from '@/stores/ui'
import { useAuthStore } from '@/stores/auth'
import { Menu } from 'lucide-vue-next'

const ui = useUiStore()
const auth = useAuthStore()
</script>

<template>
  <div class="min-h-screen bg-bg text-text">
    <AppSidebar class="hidden md:flex" />
    <AppMobileDrawer />

    <div
      :class="[
        'transition-[margin] duration-300 md:min-h-screen',
        ui.sidebarCollapsed ? 'md:ml-14' : 'md:ml-[260px]',
      ]"
    >
      <!-- Mobile top bar -->
      <div class="flex items-center gap-3 px-4 py-3 border-b border-border md:hidden">
        <button
          class="rounded-xl hover:bg-hover size-9 flex items-center justify-center transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          @click="ui.openMobileSidebar()"
        >
          <Menu class="size-5" />
        </button>
        <span class="text-sm font-medium">{{ auth.hostname || 'Naust' }}</span>
      </div>

      <div class="p-6">
        <div class="mx-auto w-full max-w-5xl page relative overflow-hidden">
          <!-- This router-view is nested INSIDE AppLayout's own template - it
               only resolves AppLayout's child page (UsersPage, etc.), never
               AppLayout itself. Transitioning its output can't remount
               AppLayout or the sidebar above; that's resolved once by the
               outer router-view in App.vue, which is untouched. -->
          <router-view v-slot="{ Component, route }">
            <Transition name="crossfade">
              <!-- Transition needs a single-root direct child; pages have
                   multi-root templates (PageHeader/AsyncState/Dialogs as
                   siblings), so the key and the animated element live on
                   this plain div, not on <component> itself. -->
              <div :key="route.path">
                <component :is="Component" />
              </div>
            </Transition>
          </router-view>
        </div>
      </div>
    </div>
  </div>
</template>
