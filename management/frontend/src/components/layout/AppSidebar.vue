<script setup lang="ts">
import { computed } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useUiStore } from '@/stores/ui'
import { useAuthStore } from '@/stores/auth'
import { useConfigStore } from '@/stores/config'
import {
  Users, AtSign, Globe, ExternalLink, Activity, Database, Shield,
  Lock, Layout, BookOpen, RefreshCw, BarChart2,
  ChevronLeft, ChevronRight, LogOut, Settings,
} from 'lucide-vue-next'
import type { NavGroup } from '@/types'

const ui = useUiStore()
const auth = useAuthStore()
const config = useConfigStore()
const route = useRoute()
const router = useRouter()

const navGroups: NavGroup[] = [
  {
    label: 'Mail',
    items: [
      { label: 'Users', path: '/users', icon: Users },
      { label: 'Aliases', path: '/aliases', icon: AtSign },
    ],
  },
  {
    label: 'DNS',
    items: [
      { label: 'Custom DNS', path: '/custom-dns', icon: Globe },
      { label: 'External DNS', path: '/external-dns', icon: ExternalLink },
    ],
  },
  {
    label: 'System',
    items: [
      { label: 'Status', path: '/system-status', icon: Activity },
      { label: 'Backup', path: '/system-backup', icon: Database },
      { label: 'TLS', path: '/ssl', icon: Shield },
    ],
  },
  {
    label: 'Settings',
    items: [
      { label: 'Two-Factor Auth', path: '/mfa', icon: Lock },
      { label: 'Web', path: '/web', icon: Layout },
    ],
  },
  {
    label: 'Guides',
    items: [
      { label: 'Mail', path: '/mail-guide', icon: BookOpen },
      { label: 'Sync', path: '/sync-guide', icon: RefreshCw },
      { label: 'Munin', path: '/munin', icon: BarChart2 },
    ],
  },
]

const collapsed = computed(() => ui.sidebarCollapsed)

function isActive(path: string): boolean {
  return route.path === path
}

async function handleLogout(): Promise<void> {
  await auth.logout()
  await router.push('/login')
}
</script>

<template>
  <aside
    :class="[
      'fixed top-0 left-0 h-screen flex flex-col z-50 transition-all duration-300',
      'bg-gray-50/70 dark:bg-gray-950/70 backdrop-blur-md',
      collapsed ? 'w-16 px-2 border-e-[0.5px] border-gray-50 dark:border-gray-850/30' : 'w-[260px] px-3',
    ]"
  >
    <!-- Logo row -->
    <div :class="['flex items-center h-14 mb-2', collapsed ? 'justify-center' : 'justify-between px-1']">
      <span v-if="!collapsed" class="text-sm font-semibold truncate">{{ config.hostname || 'Mail-in-a-Box' }}</span>
      <button
        :class="[
          'flex items-center justify-center transition rounded-xl',
          collapsed ? 'size-9 hover:bg-gray-100 dark:hover:bg-gray-850' : 'size-7 hover:bg-gray-100 dark:hover:bg-gray-900',
        ]"
        :title="collapsed ? 'Expand sidebar' : 'Collapse sidebar'"
        @click="ui.toggleSidebar()"
      >
        <component :is="collapsed ? ChevronRight : ChevronLeft" class="size-4" />
      </button>
    </div>

    <!-- Nav -->
    <nav class="flex-1 overflow-y-auto space-y-4">
      <div v-for="group in navGroups" :key="group.label">
        <p
          v-if="!collapsed"
          class="text-[10px] font-semibold uppercase tracking-wider text-gray-400 px-2.5 mb-1"
        >
          {{ group.label }}
        </p>
        <div class="space-y-0.5">
          <router-link
            v-for="item in group.items"
            :key="item.path"
            :to="item.path"
            :class="[
              'flex items-center transition',
              collapsed
                ? 'justify-center rounded-xl size-9 hover:bg-gray-100 dark:hover:bg-gray-850'
                : 'space-x-3 rounded-2xl px-2.5 py-2 hover:bg-gray-100 dark:hover:bg-gray-900',
              isActive(item.path) && !collapsed && 'bg-gray-100 dark:bg-gray-900',
              isActive(item.path) && collapsed && 'bg-gray-100 dark:bg-gray-900',
            ]"
            :title="collapsed ? item.label : undefined"
          >
            <component :is="item.icon" class="size-4 shrink-0" />
            <span v-if="!collapsed" class="text-sm">{{ item.label }}</span>
          </router-link>
        </div>
      </div>
    </nav>

    <!-- Bottom: settings + logout -->
    <div :class="['py-3 space-y-0.5', collapsed ? '' : '']">
      <button
        :class="[
          'flex items-center w-full transition',
          collapsed
            ? 'justify-center rounded-xl size-9 hover:bg-gray-100 dark:hover:bg-gray-850'
            : 'space-x-3 rounded-2xl px-2.5 py-2 hover:bg-gray-100 dark:hover:bg-gray-900',
        ]"
        :title="collapsed ? 'Settings' : undefined"
      >
        <Settings class="size-4 shrink-0" />
        <span v-if="!collapsed" class="text-sm">Settings</span>
      </button>
      <button
        :class="[
          'flex items-center w-full transition text-gray-500 hover:text-gray-700 dark:hover:text-gray-300',
          collapsed
            ? 'justify-center rounded-xl size-9 hover:bg-gray-100 dark:hover:bg-gray-850'
            : 'space-x-3 rounded-2xl px-2.5 py-2 hover:bg-gray-100 dark:hover:bg-gray-900',
        ]"
        title="Sign out"
        @click="handleLogout"
      >
        <LogOut class="size-4 shrink-0" />
        <span v-if="!collapsed" class="text-sm">Sign out</span>
      </button>
      <p v-if="!collapsed" class="text-[10px] text-gray-400 px-2.5 pt-1">
        {{ config.hostname }}
      </p>
    </div>
  </aside>
</template>
