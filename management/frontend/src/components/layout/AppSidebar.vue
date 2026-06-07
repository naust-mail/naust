<script setup lang="ts">
import { computed, ref, onMounted, onUnmounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useUiStore } from '@/stores/ui'
import { useAuthStore } from '@/stores/auth'
import { useConfigStore } from '@/stores/config'
import {
  Users, AtSign, Globe, ExternalLink, Activity, Database, Shield,
  Lock, Layout, BookOpen, RefreshCw, BarChart2,
  ChevronLeft, ChevronRight, LogOut, Settings, Info,
} from 'lucide-vue-next'
import type { NavGroup } from '@/types'

const props = defineProps<{ forceExpanded?: boolean }>()

const ui = useUiStore()
const auth = useAuthStore()
const config = useConfigStore()
const route = useRoute()
const router = useRouter()

const navGroups: NavGroup[] = [
  {
    label: 'Mail',
    items: [
      { label: 'Users', path: '/users', icon: Users, adminOnly: true },
      { label: 'Aliases', path: '/aliases', icon: AtSign, adminOnly: true },
    ],
  },
  {
    label: 'System',
    items: [
      { label: 'Status', path: '/system-status', icon: Activity, adminOnly: true },
      { label: 'Backup', path: '/system-backup', icon: Database, adminOnly: true },
      { label: 'TLS', path: '/ssl', icon: Shield, adminOnly: true },
      { label: 'Custom DNS', path: '/custom-dns', icon: Globe, adminOnly: true },
      { label: 'External DNS', path: '/external-dns', icon: ExternalLink, adminOnly: true },
    ],
  },
  {
    label: 'Settings',
    items: [
      { label: 'Two-Factor Auth', path: '/mfa', icon: Lock },
      { label: 'Web', path: '/web', icon: Layout, adminOnly: true },
    ],
  },
  {
    label: 'Guides',
    items: [
      { label: 'Mail', path: '/mail-guide', icon: BookOpen, adminOnly: true },
      { label: 'Sync', path: '/sync-guide', icon: RefreshCw, adminOnly: true },
      { label: 'Munin', path: '/munin', icon: BarChart2, adminOnly: true },
    ],
  },
]

const visibleNavGroups = computed(() =>
  navGroups
    .map(g => ({ ...g, items: g.items.filter(i => !i.adminOnly || auth.isAdmin) }))
    .filter(g => g.items.length > 0)
)

const collapsed = computed(() => props.forceExpanded ? false : ui.sidebarCollapsed)

const settingsOpen = ref(false)
const settingsRef = ref<HTMLElement | null>(null)

function onOutsideClick(e: MouseEvent): void {
  if (settingsOpen.value && settingsRef.value && !settingsRef.value.contains(e.target as Node)) {
    settingsOpen.value = false
  }
}
onMounted(() => document.addEventListener('click', onOutsideClick))
onUnmounted(() => document.removeEventListener('click', onOutsideClick))

function isActive(path: string): boolean {
  return route.path === path
}

async function handleLogout(): Promise<void> {
  settingsOpen.value = false
  await auth.logout()
  await router.push('/login')
}
</script>

<template>
  <aside
    :class="[
      'fixed top-0 left-0 h-screen flex flex-col z-50 overflow-hidden transition-all duration-300',
      forceExpanded
        ? 'bg-gray-50 dark:bg-gray-950'
        : 'bg-gray-50/70 dark:bg-gray-950/70 backdrop-blur-md',
      collapsed ? 'w-14 px-[5px] border-e-[0.5px] border-gray-50 dark:border-gray-850/30' : 'w-[260px] px-3',
    ]"
  >
    <!-- Logo row -->
    <div :class="['flex items-center h-14 mb-2', collapsed ? 'justify-center' : 'justify-between px-1']">
      <span class="text-sm font-semibold whitespace-nowrap overflow-hidden transition-[max-width] duration-300" :class="collapsed ? 'max-w-0' : 'max-w-full'">{{ config.hostname || 'Mail-in-a-Box' }}</span>
      <button
        v-if="!forceExpanded"
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
      <div v-for="group in visibleNavGroups" :key="group.label">
        <!-- Divider replaces section label in collapsed mode -->
        <div v-if="collapsed" class="border-t border-gray-100 dark:border-gray-850/30 mx-1 mb-1" />
        <p class="text-[10px] font-semibold uppercase tracking-wider text-gray-600 dark:text-gray-400 px-2.5 overflow-hidden transition-[max-height,opacity] duration-300"
           :class="collapsed ? 'max-h-0 opacity-0' : 'max-h-8 opacity-100 mb-1'">
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
                ? 'mx-auto justify-center rounded-xl size-9 hover:bg-gray-100 dark:hover:bg-gray-850'
                : 'space-x-3 h-9 items-center rounded-2xl px-2.5 hover:bg-gray-100 dark:hover:bg-gray-900',
              isActive(item.path) && !collapsed && 'bg-gray-100 dark:bg-gray-900',
              isActive(item.path) && collapsed && 'bg-gray-100 dark:bg-gray-900',
            ]"
            :title="collapsed ? item.label : undefined"
          >
            <component :is="item.icon" class="size-4 shrink-0" />
            <span class="text-sm whitespace-nowrap overflow-hidden transition-[max-width] duration-300" :class="collapsed ? 'max-w-0' : 'max-w-[200px]'">{{ item.label }}</span>
          </router-link>
        </div>
      </div>
    </nav>

    <!-- Bottom: settings dropdown -->
    <div class="py-3">
      <div ref="settingsRef" class="relative">
        <button
          :class="[
            'flex items-center transition',
            collapsed
              ? 'mx-auto justify-center rounded-xl size-9 hover:bg-gray-100 dark:hover:bg-gray-850'
              : 'w-full space-x-3 h-9 items-center rounded-2xl px-2.5 hover:bg-gray-100 dark:hover:bg-gray-900',
          ]"
          :title="collapsed ? 'Settings' : undefined"
          @click="settingsOpen = !settingsOpen"
        >
          <Settings class="size-4 shrink-0" />
          <span class="text-sm whitespace-nowrap overflow-hidden transition-[max-width] duration-300" :class="collapsed ? 'max-w-0' : 'max-w-[200px]'">Settings</span>
        </button>

        <!-- Dropdown -->
        <div
          v-if="settingsOpen"
          :class="[
            'absolute bottom-full mb-1 z-10',
            'w-[240px] rounded-2xl px-1 py-1',
            'border border-gray-100 dark:border-gray-800',
            'bg-white dark:bg-gray-850 shadow-lg',
            collapsed ? 'left-0' : 'left-0',
          ]"
        >
          <div class="flex items-center gap-2 px-3 py-2 border-b border-gray-100 dark:border-gray-800 mb-1">
            <Info class="size-4 text-gray-400 shrink-0" />
            <div class="text-xs text-gray-500 truncate">{{ config.hostname || 'Guest' }}</div>
          </div>
          <button
            class="flex w-full items-center gap-2 rounded-xl py-1.5 px-3 text-sm hover:bg-gray-50 dark:hover:bg-gray-800 transition text-gray-700 dark:text-gray-300"
            @click="handleLogout"
          >
            <LogOut class="size-4 shrink-0" />
            Sign out
          </button>
        </div>
      </div>
    </div>
  </aside>
</template>
