<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { toast } from 'vue-sonner'
import { RefreshCw, WifiOff } from 'lucide-vue-next'
import AppLayout from '@/components/layout/AppLayout.vue'
import Button from '@/components/ui/Button.vue'
import Skeleton from '@/components/ui/Skeleton.vue'
import Card from '@/components/ui/Card.vue'
import Dialog from '@/components/ui/Dialog.vue'
import Divider from '@/components/ui/Divider.vue'
import EmptyState from '@/components/ui/EmptyState.vue'
import StatusIcon from '@/components/shared/StatusIcon.vue'
import { useApi } from '@/composables/useApi'
import type { StatusCheckItem, StatusCheckResponse } from '@/types'

// Status checks take 10-30s. 8s balances responsiveness against server load:
// fast enough that results appear promptly once ready, slow enough not to hammer
// the endpoint while the subprocess pool is still working.
const POLL_INTERVAL_MS = 8_000

const api = useApi()

const jobStatus = ref<'idle' | 'running' | 'done'>('idle')
const items = ref<StatusCheckItem[]>([])
const checkedAt = ref<string | null>(null)
const source = ref<'cron' | 'manual' | null>(null)
const loadError = ref(false)
const expanded = ref(new Set<number>())
let pollTimer: ReturnType<typeof setInterval> | null = null

// Privacy and reboot are cheap fetches loaded independently so they never
// gate or slow down the expensive status check display.
const privacy = ref<boolean | null>(null)
const rebootNeeded = ref<boolean | null>(null)
const rebootOpen = ref(false)
const rebooting = ref(false)

type SectionItem = { item: StatusCheckItem; idx: number }
type Section = { heading: string; items: SectionItem[] }

const sections = computed<Section[]>(() => {
  const result: Section[] = []
  let current: Section | null = null
  items.value.forEach((item, idx) => {
    if (item.type === 'heading') {
      current = { heading: item.text, items: [] }
      result.push(current)
    } else if (current) {
      current.items.push({ item, idx })
    }
  })
  return result
})

const summary = computed(() => ({
  ok: items.value.filter(i => i.type === 'ok').length,
  errors: items.value.filter(i => i.type === 'error').length,
  warnings: items.value.filter(i => i.type === 'warning').length,
}))

const checkedAtLabel = computed(() => {
  if (!checkedAt.value) return null
  const diff = Math.round((Date.now() - new Date(checkedAt.value).getTime()) / 1000)
  if (diff < 60) return 'just now'
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
})

function applyResponse(data: StatusCheckResponse): void {
  jobStatus.value = data.status
  if (data.items) items.value = data.items
  checkedAt.value = data.checked_at
  source.value = data.source
}

function startPolling(): void {
  if (pollTimer !== null) return
  pollTimer = setInterval(async () => {
    try {
      const res = await api.get('/admin/system/status')
      const data: StatusCheckResponse = await res.json()
      applyResponse(data)
      if (data.status !== 'running') stopPolling()
    } catch {
      // Keep polling on transient network errors
    }
  }, POLL_INTERVAL_MS)
}

function stopPolling(): void {
  if (pollTimer !== null) {
    clearInterval(pollTimer)
    pollTimer = null
  }
}

async function loadStatus(): Promise<void> {
  loadError.value = false
  try {
    const res = await api.get('/admin/system/status')
    const data: StatusCheckResponse = await res.json()
    applyResponse(data)
    if (data.status === 'running') {
      startPolling()
    } else if (data.status === 'idle') {
      // No cache yet (fresh install or cleared cache) - trigger automatically.
      await triggerRefresh()
    }
  } catch {
    loadError.value = true
    toast.error('Failed to load system status.')
  }
}

async function loadPrivacyAndReboot(): Promise<void> {
  try {
    const [privacyRes, rebootRes] = await Promise.all([
      api.get('/admin/system/privacy'),
      api.get('/admin/system/reboot'),
    ])
    privacy.value = await privacyRes.json()
    rebootNeeded.value = await rebootRes.json()
  } catch {
    // Non-critical - silently ignore
  }
}

async function triggerRefresh(): Promise<void> {
  try {
    const res = await api.post('/admin/system/status')
    const data: StatusCheckResponse = await res.json()
    applyResponse(data)
    startPolling()
    if (res.status === 202 && data.status === 'running' && items.value.length > 0) {
      toast.info('A check is already in progress.')
    }
  } catch {
    toast.error('Failed to start status check.')
  }
}

function toggleExpand(idx: number): void {
  if (expanded.value.has(idx)) {
    expanded.value.delete(idx)
  } else {
    expanded.value.add(idx)
  }
}

async function togglePrivacy(): Promise<void> {
  if (privacy.value === null) return
  const newVal = !privacy.value
  const res = await api.post('/admin/system/privacy', { value: newVal ? 'private' : 'off' })
  if (res.ok) {
    privacy.value = newVal
    toast.success(newVal ? 'Version check enabled.' : 'Version check disabled.')
  }
}

async function doReboot(): Promise<void> {
  rebooting.value = true
  try {
    const res = await api.post('/admin/system/reboot')
    if (res.ok) {
      toast.success('Reboot initiated. Reload this page in about a minute.')
      rebootOpen.value = false
    }
  } catch {
    toast.error('Failed to initiate reboot.')
  } finally {
    rebooting.value = false
  }
}

onMounted(() => {
  // Fire independently - privacy/reboot never block the status check display.
  loadStatus()
  loadPrivacyAndReboot()
})

onUnmounted(stopPolling)
</script>

<template>
  <AppLayout>
    <div class="flex items-center justify-between mb-6">
      <div>
        <h1 class="text-2xl font-semibold">System Status</h1>
        <p v-if="checkedAtLabel" class="text-xs text-gray-500 mt-0.5">
          Last checked {{ checkedAtLabel }}
          <span v-if="source === 'cron'" class="ml-1 text-gray-400">(nightly)</span>
        </p>
      </div>
      <Button
        variant="secondary"
        size="sm"
        :disabled="jobStatus === 'running'"
        @click="triggerRefresh"
      >
        <RefreshCw class="size-4 mr-1.5" :class="{ 'animate-spin': jobStatus === 'running' }" />
        {{ jobStatus === 'running' ? 'Checking...' : 'Refresh' }}
      </Button>
    </div>

    <!-- Reboot banner -->
    <Card
      v-if="rebootNeeded"
      class="p-4 mb-5 border-yellow-300 dark:border-yellow-700 bg-yellow-50 dark:bg-yellow-950/30"
    >
      <p class="text-sm font-medium text-yellow-800 dark:text-yellow-200">
        A system reboot is required to apply package updates.
      </p>
      <Button variant="secondary" size="sm" class="mt-2" @click="rebootOpen = true">
        Reboot Now
      </Button>
    </Card>

    <!-- Error state -->
    <EmptyState
      v-if="loadError"
      title="Could not load status checks"
      description="The server did not respond. Check your connection and try again."
    >
      <template #icon><WifiOff /></template>
      <template #action>
        <Button variant="secondary" @click="loadStatus">Try again</Button>
      </template>
    </EmptyState>

    <template v-else>
      <!-- Running with no prior results: skeleton -->
      <template v-if="jobStatus === 'running' && items.length === 0">
        <div v-for="s in 3" :key="s" class="mb-6">
          <Skeleton class="h-5 w-40 mb-3" />
          <div class="space-y-2">
            <div v-for="i in 4" :key="i" class="flex items-center gap-3 py-2">
              <Skeleton class="size-4 rounded-full shrink-0" />
              <Skeleton class="h-4" :class="i % 2 === 0 ? 'w-3/4' : 'w-1/2'" />
            </div>
          </div>
        </div>
      </template>

      <!-- Results (shown even while running if we have prior cached data) -->
      <template v-else-if="items.length > 0">
        <p v-if="jobStatus === 'running'" class="text-xs text-gray-400 mb-4">
          Showing previous results while the new check runs...
        </p>

        <!-- Summary -->
        <div class="flex gap-4 mb-6 text-sm font-medium">
          <span v-if="summary.ok" class="text-emerald-600 dark:text-emerald-400">
            {{ summary.ok }} OK
          </span>
          <span v-if="summary.errors" class="text-red-600 dark:text-red-400">
            {{ summary.errors }} {{ summary.errors === 1 ? 'error' : 'errors' }}
          </span>
          <span v-if="summary.warnings" class="text-yellow-600 dark:text-yellow-400">
            {{ summary.warnings }} {{ summary.warnings === 1 ? 'warning' : 'warnings' }}
          </span>
          <span
            v-if="!summary.errors && !summary.warnings"
            class="text-emerald-600 dark:text-emerald-400 font-semibold"
          >
            All checks passed
          </span>
        </div>

        <!-- Sections -->
        <div v-for="section in sections" :key="section.heading" class="mb-6">
          <h2 class="text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400 mb-2 px-1">
            {{ section.heading }}
          </h2>
          <Card>
            <template
              v-for="({ item, idx }, i) in section.items"
              :key="idx"
            >
              <Divider v-if="i > 0" />
              <div class="px-4 py-3">
              <div class="flex items-start gap-3">
                <StatusIcon :status="item.type as 'ok' | 'error' | 'warning'" class="mt-0.5 shrink-0" />
                <div class="flex-1 min-w-0">
                  <p class="text-sm">{{ item.text }}</p>
                  <div v-if="expanded.has(idx) && item.extra.length" class="mt-2 space-y-1">
                    <p
                      v-for="(ex, ei) in item.extra.filter(e => e.text.trim())"
                      :key="ei"
                      class="text-xs text-gray-500 dark:text-gray-400"
                      :class="{ 'font-mono whitespace-pre-wrap': ex.monospace }"
                    >
                      {{ ex.text }}
                    </p>
                  </div>
                  <button
                    v-if="item.extra.some(e => e.text.trim())"
                    :aria-expanded="expanded.has(idx)"
                    class="mt-1 text-xs text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 transition-colors"
                    @click="toggleExpand(idx)"
                  >
                    {{ expanded.has(idx) ? 'show less' : 'show more' }}
                  </button>
                </div>
              </div>
            </div>
            </template>
          </Card>
        </div>

        <!-- System Tools -->
        <Card class="p-5 mt-6">
          <h2 class="text-sm font-semibold mb-3">System Tools</h2>
          <div class="flex flex-wrap gap-3">
            <div>
              <p class="text-xs text-gray-500 mb-1.5">
                Version check: {{ privacy === true ? 'enabled' : privacy === false ? 'disabled' : '...' }}
              </p>
              <Button variant="secondary" size="sm" :disabled="privacy === null" @click="togglePrivacy">
                {{ privacy ? 'Disable Version Check' : 'Enable Version Check' }}
              </Button>
            </div>
            <div v-if="rebootNeeded === false">
              <p class="text-xs text-gray-500 mb-1.5">No reboot required.</p>
              <Button variant="secondary" size="sm" disabled>Reboot</Button>
            </div>
            <div v-else-if="rebootNeeded">
              <p class="text-xs text-gray-500 mb-1.5">Reboot pending.</p>
              <Button variant="secondary" size="sm" @click="rebootOpen = true">Reboot Now</Button>
            </div>
          </div>
        </Card>
      </template>
    </template>

    <!-- Reboot confirm -->
    <Dialog
      v-model="rebootOpen"
      title="Reboot server?"
      description="This will reboot your Mail-in-a-Box instance. Mail will be unavailable for about a minute."
    >
      <template #actions>
        <Button variant="secondary" @click="rebootOpen = false">Cancel</Button>
        <Button variant="destructive" :disabled="rebooting" @click="doReboot">
          {{ rebooting ? 'Rebooting...' : 'Reboot Now' }}
        </Button>
      </template>
    </Dialog>
  </AppLayout>
</template>
