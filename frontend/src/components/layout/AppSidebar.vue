<script setup lang="ts">
import { computed, ref, onMounted, onUnmounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useUiStore } from '@/stores/ui'
import { useAuthStore } from '@/stores/auth'
import {
  Users, AtSign, Globe, ExternalLink, Activity, Database, Shield,
  Lock, LockKeyhole, Key, Layout, BookOpen, RefreshCw, BarChart2, Send,
  ChevronLeft, ChevronRight, LogOut, Settings, Info, Sun, Moon, Monitor,
} from 'lucide-vue-next'
import type { NavGroup, Palette } from '@/types'

const props = defineProps<{ forceExpanded?: boolean }>()

const ui = useUiStore()
const auth = useAuthStore()
const route = useRoute()
const router = useRouter()

const visibleNavGroups = computed<NavGroup[]>(() => {
  const groups: NavGroup[] = [
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
        { label: 'Relay', path: '/smtp-relay', icon: Send, adminOnly: true },
      ],
    },
    {
      label: 'DNS',
      items: [
        { label: 'Custom DNS', path: '/custom-dns', icon: Globe, adminOnly: true },
        { label: 'External DNS', path: '/external-dns', icon: ExternalLink, adminOnly: true },
      ],
    },
    {
      label: 'Settings',
      items: [
        { label: 'Two-Factor Auth', path: '/mfa', icon: Lock },
        // Self-service, only shown when the box has encryption at rest enabled.
        ...(auth.capabilities.includes('encryption_at_rest') ? [{ label: 'Encryption', path: '/encryption', icon: LockKeyhole }] : []),
        { label: 'API Tokens', path: '/api-tokens', icon: Key, adminOnly: true },
        { label: 'Web', path: '/web', icon: Layout, adminOnly: true },
      ],
    },
  ]

  const guidesItems = [
    { label: 'Mail', path: '/mail-guide', icon: BookOpen, adminOnly: true },
    { label: 'Sync', path: '/sync-guide', icon: RefreshCw, adminOnly: true },
  ]
  if (auth.capabilities.includes('monitoring')) {
    guidesItems.push({ label: 'Monitoring', path: '/monitoring', icon: BarChart2, adminOnly: true })
  }
  groups.push({ label: 'Guides', items: guidesItems })

  return groups
    .map(g => ({ ...g, items: g.items.filter(i => !i.adminOnly || auth.isAdmin) }))
    .filter(g => g.items.length > 0)
})

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

// Each entry: [palette id, display color, tooltip label]
// Colors are sourced from each theme's canonical accent/primary values:
// rav: primary from rav globals.css; Indigo: from docs tailwind config;
// Nord: Nord8 frost cyan (#88C0D0) from nordtheme.com palette;
// Emerald: mid forest green representative of the muted green surface hue;
// Catppuccin: Mocha mauve (#CBA6F7), the signature Catppuccin accent.
const PALETTES: [Palette, string, string][] = [
  ['zinc',       '#9b9b9b',  'Zinc'],
  ['rav', 'hsl(20 70% 50%)', 'Rav'],
  ['indigo',     '#6366f1',  'Indigo'],
  ['nord',       '#88C0D0',  'Nord'],
  ['emerald',    'hsl(152 42% 36%)', 'Emerald'],
  ['catppuccin', '#CBA6F7',  'Catppuccin'],
]
</script>

<template>
  <aside
    :class="[
      // Below every overlay (Dialog/Sheet backdrops start at z-40) so a Sheet
      // or Dialog always covers the persistent sidebar, never sits under it.
      'fixed top-0 left-0 h-screen flex flex-col z-30 transition-all duration-300',
      forceExpanded
        ? 'bg-sidebar'
        : 'bg-sidebar backdrop-blur-md',
      collapsed ? 'w-14 px-[5px] border-e-[0.5px] border-border' : 'w-[260px] px-3',
    ]"
  >
    <!--
      overflow-hidden is on this inner wrapper, not the aside itself.
      This clips text during the width animation but leaves the settings
      button area below free to show its dropdown without clipping.
    -->
    <div class="flex flex-col flex-1 overflow-hidden min-h-0">
      <!-- Logo row -->
      <div :class="['flex items-center h-14 mb-2', collapsed ? 'justify-center' : 'justify-between px-1']">
        <span class="text-sm font-semibold whitespace-nowrap overflow-hidden transition-[max-width] duration-300" :class="collapsed ? 'max-w-0' : 'max-w-full'">{{ auth.hostname || 'Naust' }}</span>
        <button
          v-if="!forceExpanded"
          :class="[
            'flex items-center justify-center transition rounded-xl focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
            collapsed ? 'size-9 hover:bg-hover' : 'size-7 hover:bg-hover',
          ]"
          :title="collapsed ? 'Expand sidebar' : 'Collapse sidebar'"
          @click="ui.toggleSidebar()"
        >
          <component :is="collapsed ? ChevronRight : ChevronLeft" class="size-4" />
        </button>
      </div>

      <!-- Nav -->
      <nav :class="['flex-1 overflow-y-auto', collapsed ? 'space-y-2' : 'space-y-4']">
        <div v-for="group in visibleNavGroups" :key="group.label">
          <!-- Divider replaces section label in collapsed mode -->
          <div v-if="collapsed" class="border-t border-border mx-1 mb-2" />
          <p class="text-[10px] font-semibold uppercase tracking-wider text-muted px-2.5 overflow-hidden transition-[max-height,opacity] duration-300"
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
                  ? 'mx-auto justify-center rounded-xl size-9 hover:bg-hover'
                  : 'space-x-3 h-9 items-center rounded-2xl px-2.5 hover:bg-hover',
                isActive(item.path) ? 'bg-accent/10 text-accent font-medium' : '',
              ]"
              :title="collapsed ? item.label : undefined"
            >
              <component :is="item.icon" class="size-4 shrink-0" />
              <span class="text-sm whitespace-nowrap overflow-hidden transition-[max-width] duration-300" :class="collapsed ? 'max-w-0' : 'max-w-[200px]'">{{ item.label }}</span>
            </router-link>
          </div>
        </div>
      </nav>
    </div>

    <!-- Settings - outside overflow-hidden wrapper so dropdown is never clipped -->
    <div class="py-3">
      <div ref="settingsRef" class="relative">
        <button
          :class="[
            'flex items-center transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
            collapsed
              ? 'mx-auto justify-center rounded-xl size-9 hover:bg-hover'
              : 'w-full space-x-3 h-9 items-center rounded-2xl px-2.5 hover:bg-hover',
          ]"
          :title="collapsed ? (auth.email || 'Account') : undefined"
          @click="settingsOpen = !settingsOpen"
        >
          <Settings class="size-4 shrink-0" />
          <span class="text-sm whitespace-nowrap overflow-hidden transition-[max-width] duration-300" :class="collapsed ? 'max-w-0' : 'max-w-[200px]'">{{ auth.email || 'Account' }}</span>
        </button>

        <div
          v-if="settingsOpen"
          class="absolute bottom-full mb-1 left-0 z-10 w-[240px] rounded-2xl px-1 py-1 border border-border bg-surface shadow-lg"
        >
          <div class="flex items-center gap-2 px-3 py-2 border-b border-border mb-1">
            <Info class="size-4 text-faint shrink-0" />
            <div class="text-xs text-muted truncate">{{ auth.email || 'Guest' }}</div>
          </div>
          <!-- Palette picker - 2 rows of 3 color dots -->
          <div class="grid grid-cols-3 gap-1 px-2 py-1.5 border-b border-border mb-1">
            <button
              v-for="[p, color, label] in PALETTES"
              :key="p"
              :title="label"
              class="flex items-center justify-center py-1.5 rounded-lg transition hover:bg-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              :class="ui.palette === p ? 'bg-hover' : ''"
              @click="ui.setPalette(p)"
            >
              <span
                class="size-4 rounded-full transition"
                :style="ui.palette === p
                  ? { background: color, outline: `2px solid ${color}`, outlineOffset: '2px' }
                  : { background: color }"
              />
            </button>
          </div>
          <!-- Mode toggle -->
          <div class="flex items-center gap-1 px-2 py-1.5 border-b border-border mb-1">
            <button
              v-for="[t, icon] in ([['light', Sun], ['system', Monitor], ['dark', Moon]] as const)"
              :key="t"
              :title="t.charAt(0).toUpperCase() + t.slice(1)"
              :class="[
                'flex-1 flex items-center justify-center py-1 rounded-lg transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
                ui.theme === t
                  ? 'bg-hover text-text'
                  : 'text-faint hover:bg-hover-subtle',
              ]"
              @click="ui.setTheme(t)"
            >
              <component :is="icon" class="size-3.5" />
            </button>
          </div>
          <button
            class="flex w-full items-center gap-2 rounded-xl py-1.5 px-3 text-sm hover:bg-hover-subtle transition text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
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
