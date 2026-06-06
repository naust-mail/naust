<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { toast } from 'vue-sonner'
import { RefreshCw } from 'lucide-vue-next'
import AppLayout from '@/components/layout/AppLayout.vue'
import Button from '@/components/ui/Button.vue'
import Skeleton from '@/components/ui/Skeleton.vue'
import Card from '@/components/ui/Card.vue'
import Dialog from '@/components/ui/Dialog.vue'
import StatusIcon from '@/components/shared/StatusIcon.vue'
import { useApi } from '@/composables/useApi'
import type { StatusCheckItem } from '@/types'

const api = useApi()

const loading = ref(true)
const items = ref<StatusCheckItem[]>([])
const privacy = ref<boolean | null>(null)
const rebootNeeded = ref<boolean | null>(null)
const rebootOpen = ref(false)
const rebooting = ref(false)
const expanded = ref(new Set<number>())

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

async function load(): Promise<void> {
  loading.value = true
  expanded.value.clear()
  try {
    const [statusRes, privacyRes, rebootRes] = await Promise.all([
      api.post('/admin/system/status'),
      api.get('/admin/system/privacy'),
      api.get('/admin/system/reboot'),
    ])
    items.value = await statusRes.json()
    privacy.value = await privacyRes.json()
    rebootNeeded.value = await rebootRes.json()
  } catch {
    toast.error('Failed to load system status.')
  } finally {
    loading.value = false
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

onMounted(load)
</script>

<template>
  <AppLayout>
    <div class="flex items-center justify-between mb-6">
      <h1 class="text-2xl font-semibold">System Status</h1>
      <Button variant="secondary" size="sm" :disabled="loading" @click="load">
        <RefreshCw class="size-4 mr-1.5" :class="{ 'animate-spin': loading }" />
        Refresh
      </Button>
    </div>

    <!-- Reboot banner -->
    <Card v-if="rebootNeeded" class="p-4 mb-5 border-yellow-300 dark:border-yellow-700 bg-yellow-50 dark:bg-yellow-950/30">
      <p class="text-sm font-medium text-yellow-800 dark:text-yellow-200">
        A system reboot is required to apply package updates.
      </p>
      <Button variant="secondary" size="sm" class="mt-2" @click="rebootOpen = true">
        Reboot Now
      </Button>
    </Card>

    <!-- Loading skeletons -->
    <template v-if="loading">
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

    <template v-else>
      <!-- Summary -->
      <div v-if="items.length" class="flex gap-4 mb-6 text-sm font-medium">
        <span v-if="summary.ok" class="text-emerald-600 dark:text-emerald-400">
          {{ summary.ok }} OK
        </span>
        <span v-if="summary.errors" class="text-red-600 dark:text-red-400">
          {{ summary.errors }} {{ summary.errors === 1 ? 'error' : 'errors' }}
        </span>
        <span v-if="summary.warnings" class="text-yellow-600 dark:text-yellow-400">
          {{ summary.warnings }} {{ summary.warnings === 1 ? 'warning' : 'warnings' }}
        </span>
        <span v-if="!summary.errors && !summary.warnings" class="text-emerald-600 dark:text-emerald-400 font-semibold">
          All checks passed
        </span>
      </div>

      <!-- Sections -->
      <div v-for="section in sections" :key="section.heading" class="mb-6">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400 mb-2 px-1">
          {{ section.heading }}
        </h2>
        <Card>
          <div
            v-for="({ item, idx }, i) in section.items"
            :key="idx"
            class="px-4 py-3"
            :class="{ 'border-t border-gray-100 dark:border-gray-800': i > 0 }"
          >
            <div class="flex items-start gap-3">
              <StatusIcon :status="item.type as 'ok' | 'error' | 'warning'" class="mt-0.5 shrink-0" />
              <div class="flex-1 min-w-0">
                <p class="text-sm">{{ item.text }}</p>

                <!-- Expanded extras -->
                <div
                  v-if="expanded.has(idx) && item.extra.length"
                  class="mt-2 space-y-1"
                >
                  <p
                    v-for="(ex, ei) in item.extra.filter(e => e.text.trim())"
                    :key="ei"
                    class="text-xs text-gray-500 dark:text-gray-400"
                    :class="{ 'font-mono whitespace-pre-wrap': ex.monospace }"
                  >
                    {{ ex.text }}
                  </p>
                </div>

                <!-- Show more toggle -->
                <button
                  v-if="item.extra.some(e => e.text.trim())"
                  class="mt-1 text-xs text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 transition-colors"
                  @click="toggleExpand(idx)"
                >
                  {{ expanded.has(idx) ? 'show less' : 'show more' }}
                </button>
              </div>
            </div>
          </div>
        </Card>
      </div>

      <!-- Bottom actions -->
      <Card class="p-5 mt-2">
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
