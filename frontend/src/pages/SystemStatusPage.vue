<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted } from 'vue'
import { toast } from 'vue-sonner'
import { RefreshCw, ChevronDown } from 'lucide-vue-next'
import AsyncState from '@/components/ui/AsyncState.vue'
import Button from '@/components/ui/Button.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import Skeleton from '@/components/ui/Skeleton.vue'
import Card from '@/components/ui/Card.vue'
import Dialog from '@/components/ui/Dialog.vue'
import Divider from '@/components/ui/Divider.vue'
import StatusIcon from '@/components/shared/StatusIcon.vue'
import CheckRow from '@/components/shared/CheckRow.vue'
import { api, ApiError } from '@/api/client'
import type { CheckMeta, CheckResultInfo, CheckStep, ChecksConfig, ChecksConfigResponse, ChecksStatusResponse } from '@/api/types.gen'

// Checks run in the background; results render instantly from the
// store. 5s keeps a manual run feeling live without hammering the API.
const POLL_INTERVAL_MS = 5_000

// A manual run can complete faster than a human perceives as "it did
// something" - hold the button's spinner up for at least this long so
// clicking Run Checks always reads as a real, visible action.
const MIN_SPIN_MS = 5_000

const loading = ref(true)
const loadError = ref(false)
const results = ref<CheckResultInfo[]>([])
const running = ref(false)
const minSpinActive = ref(false)
const showSpinner = computed(() => running.value || minSpinActive.value)
const activeTab = ref<string | null>(null)
const rebootOpen = ref(false)
const rebooting = ref(false)
const detailRowKey = ref<string | null>(null)
const detailOpen = computed({
  get: () => detailRowKey.value !== null,
  set: (v: boolean) => { if (!v) detailRowKey.value = null },
})
const checksConfig = ref<ChecksConfig | null>(null)
const catalog = ref<CheckMeta[]>([])
const configSaving = ref(false)
let pollTimer: ReturnType<typeof setInterval> | null = null
let minSpinTimer: ReturnType<typeof setTimeout> | null = null

const SEVERITY: Record<string, number> = { error: 0, warning: 1, ok: 2, skipped: 3 }

// Stable tab order for the known categories; anything new lands after.
const CATEGORY_ORDER = ['system', 'services', 'dns', 'mail', 'web']
const CATEGORY_LABELS: Record<string, string> = {
  system: 'System',
  services: 'Services',
  dns: 'DNS',
  mail: 'Mail',
  web: 'Web',
}

// rows holds every result of the category (tab counts and triage read
// it); visible is what renders as individual rows after the two
// collapse groups are carved out: healthy "service:" port probes fold
// into one "N services running" line, and quiet-class checks with
// nothing to report fold into a "background checks" line. Failing
// members of either group stay in visible - collapsing only ever
// hides good news.
type Section = {
  category: string
  label: string
  rows: CheckResultInfo[]
  visible: CheckResultInfo[]
  servicesOk: CheckResultInfo[]
  quiet: CheckResultInfo[]
}

const metaByName = computed<Map<string, CheckMeta>>(() => {
  const m = new Map<string, CheckMeta>()
  for (const meta of catalog.value) m.set(meta.name, meta)
  return m
})

function checkClass(r: CheckResultInfo): string {
  return metaByName.value.get(r.check)?.class ?? 'standard'
}

// True once the admin has turned a check off via the config API. Applied
// client-side immediately on toggle rather than waiting for the next
// background run to write the "disabled by configuration" result.
function isDisabled(check: string): boolean {
  return checksConfig.value?.checks?.[check]?.enabled === false
}

const displayResults = computed<CheckResultInfo[]>(() =>
  results.value.map((r) =>
    isDisabled(r.check) ? { ...r, status: 'skipped', message: 'Disabled by configuration', steps: [] } : r,
  ),
)

const sections = computed<Section[]>(() => {
  const byCategory = new Map<string, CheckResultInfo[]>()
  for (const r of displayResults.value) {
    const list = byCategory.get(r.category)
    if (list) {
      list.push(r)
    } else {
      byCategory.set(r.category, [r])
    }
  }
  const categories = [...byCategory.keys()].sort((a, b) => {
    const ia = CATEGORY_ORDER.indexOf(a)
    const ib = CATEGORY_ORDER.indexOf(b)
    return (ia === -1 ? CATEGORY_ORDER.length : ia) - (ib === -1 ? CATEGORY_ORDER.length : ib)
  })
  return categories.map((category) => {
    const rows = byCategory
      .get(category)!
      .slice()
      .sort((a, b) => {
        const sd = (SEVERITY[a.status] ?? 4) - (SEVERITY[b.status] ?? 4)
        if (sd !== 0) return sd
        const cd = rowTitle(a).localeCompare(rowTitle(b))
        if (cd !== 0) return cd
        return (a.domain ?? '').localeCompare(b.domain ?? '')
      })
    const visible: CheckResultInfo[] = []
    const servicesOk: CheckResultInfo[] = []
    const quiet: CheckResultInfo[] = []
    for (const r of rows) {
      if (r.check.startsWith('service:') && r.status === 'ok') {
        servicesOk.push(r)
      } else if (r.status === 'skipped' || (checkClass(r) === 'quiet' && r.status === 'ok')) {
        // Skipped is never a failure - not-applicable and
        // disabled-by-configuration rows always have nothing to
        // report, regardless of the check's own class.
        quiet.push(r)
      } else {
        visible.push(r)
      }
    }
    return { category, label: CATEGORY_LABELS[category] ?? category, rows, visible, servicesOk, quiet }
  })
})

// Collapse groups the admin has expanded, keyed "category:group".
// Reassigned (not mutated) on toggle so the computed template updates.
const expandedGroups = ref<Set<string>>(new Set())

function toggleGroup(key: string): void {
  const next = new Set(expandedGroups.value)
  if (next.has(key)) {
    next.delete(key)
  } else {
    next.add(key)
  }
  expandedGroups.value = next
}

function servicesLabel(section: Section): string {
  const n = section.servicesOk.length
  const failing = section.rows.some(
    (r) => r.check.startsWith('service:') && (r.status === 'error' || r.status === 'warning'),
  )
  if (failing) return `${n} other service${n === 1 ? '' : 's'} running`
  return `All ${n} services running`
}

function quietLabel(section: Section): string {
  const n = section.quiet.length
  if (section.quiet.every((r) => r.status === 'ok')) {
    return `${n} background check${n === 1 ? '' : 's'} passing`
  }
  return `${n} background check${n === 1 ? '' : 's'} with nothing to report`
}

// Keep the current tab if it survives a refresh, otherwise jump to the
// first section that has errors.
watch(sections, (newSections) => {
  if (!newSections.length) return
  if (activeTab.value && newSections.some((s) => s.category === activeTab.value)) return
  const withErrors = newSections.find((s) => s.rows.some((r) => r.status === 'error'))
  activeTab.value = (withErrors ?? newSections[0]).category
}, { immediate: true })

const activeSection = computed(() =>
  sections.value.find((s) => s.category === activeTab.value) ?? null,
)

function sectionCount(section: Section, status: string): number {
  return section.rows.filter((r) => r.status === status).length
}

// The software-updates check flags a pending reboot via its fix hint;
// the server re-verifies before actually rebooting.
const rebootNeeded = computed(() =>
  displayResults.value.some((r) => (r.steps ?? []).some((s) => s.fix_hint === 'system.reboot')),
)

const checkedAtLabel = computed(() => {
  let latest = 0
  for (const r of results.value) {
    const t = new Date(r.ran_at).getTime()
    if (t > latest) latest = t
  }
  if (!latest) return null
  return ago(latest)
})

function ago(ts: number): string {
  const diff = Math.round((Date.now() - ts) / 1000)
  if (diff < 60) return 'just now'
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

function failingSince(r: CheckResultInfo): string | null {
  if (!r.first_failed_at || r.status === 'ok' || r.status === 'skipped') return null
  return `failing since ${ago(new Date(r.first_failed_at).getTime())}`
}

function rowKey(r: CheckResultInfo): string {
  return r.domain ? `${r.check}:${r.domain}` : r.check
}

function rowTitle(r: CheckResultInfo): string {
  const base = metaByName.value.get(r.check)?.title ?? r.check
  return r.domain ? `${base} (${r.domain})` : base
}

// Metric-class checks carry a number worth glancing at even when
// green (disk %, queue depth, backup age). The run only writes a
// message on failure, so pull the reading from the first structured
// step observation instead.
function metricReading(r: CheckResultInfo): string | null {
  if (checkClass(r) !== 'metric' || r.status !== 'ok' || r.message) return null
  for (const s of r.steps ?? []) {
    if (s.observed !== undefined) return s.observed
  }
  return null
}

// Looked up by key (rather than held as a snapshot) so toggling the
// check's enabled state while the dialog is open updates it live.
const detailRow = computed<CheckResultInfo | null>(() =>
  displayResults.value.find((r) => rowKey(r) === detailRowKey.value) ?? null,
)

const detailMeta = computed<CheckMeta | null>(() =>
  detailRow.value ? metaByName.value.get(detailRow.value.check) ?? null : null,
)

function stepDetail(s: CheckStep): string | null {
  if (s.expected === undefined && s.observed === undefined) return null
  const parts: string[] = []
  if (s.expected !== undefined) parts.push(`expected: ${s.expected}`)
  if (s.observed !== undefined) parts.push(`observed: ${s.observed}`)
  return parts.join('\n')
}

async function loadConfig(): Promise<void> {
  try {
    const resp = await api.get<ChecksConfigResponse>('/api/system/checks/config')
    checksConfig.value = resp.config
    catalog.value = resp.available ?? []
  } catch {
    // The view/disable dialog just hides the toggle if this never loads.
  }
}

async function toggleCheckEnabled(check: string): Promise<void> {
  const willEnable = isDisabled(check)
  const next: ChecksConfig = {
    ...checksConfig.value,
    checks: {
      ...checksConfig.value?.checks,
      [check]: { ...checksConfig.value?.checks?.[check], enabled: willEnable },
    },
  }
  configSaving.value = true
  try {
    const resp = await api.put<ChecksConfigResponse>('/api/system/checks/config', next)
    checksConfig.value = resp.config
    toast.success(willEnable ? `"${check}" enabled.` : `"${check}" disabled.`)
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : 'Failed to update check configuration.')
  } finally {
    configSaving.value = false
  }
}

function applyResponse(data: ChecksStatusResponse): void {
  results.value = data.results ?? []
  running.value = data.running
}

// A handful of transient blips are expected; a run of failures this long
// means the backend is actually down, so give up rather than leaving the
// page polling (and "Run checks" disabled) forever with no way out.
const MAX_CONSECUTIVE_POLL_FAILURES = 5

function startPolling(): void {
  if (pollTimer !== null) return
  let consecutiveFailures = 0
  pollTimer = setInterval(async () => {
    try {
      const data = await api.get<ChecksStatusResponse>('/api/system/checks')
      consecutiveFailures = 0
      applyResponse(data)
      if (!data.running) stopPolling()
    } catch {
      consecutiveFailures++
      if (consecutiveFailures >= MAX_CONSECUTIVE_POLL_FAILURES) {
        stopPolling()
        running.value = false
        toast.error('Lost contact with the server while checks were running. Try again once it is reachable.')
      }
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
  loading.value = true
  loadError.value = false
  try {
    const data = await api.get<ChecksStatusResponse>('/api/system/checks')
    applyResponse(data)
    if (data.running) {
      startPolling()
    } else if (results.value.length === 0) {
      // Fresh box with no stored results yet: kick a first run.
      await triggerRefresh()
    }
  } catch {
    loadError.value = true
    toast.error('Failed to load system status.')
  } finally {
    loading.value = false
  }
}

async function triggerRefresh(): Promise<void> {
  if (running.value) return
  running.value = true
  minSpinActive.value = true
  if (minSpinTimer !== null) clearTimeout(minSpinTimer)
  minSpinTimer = setTimeout(() => { minSpinActive.value = false }, MIN_SPIN_MS)
  try {
    await api.post<undefined>('/api/system/checks/run', {})
    startPolling()
  } catch (e) {
    // Report the failure immediately, but let the armed minSpinTimer (not
    // this catch block) be the only thing that clears minSpinActive - the
    // button should still hold its minimum spin time even on failure.
    running.value = false
    toast.error(e instanceof ApiError ? e.message : 'Failed to start status check.')
  }
}

async function doReboot(): Promise<void> {
  rebooting.value = true
  try {
    await api.post<undefined>('/api/system/reboot')
    toast.success('Reboot initiated. Reload this page in about a minute.')
    rebootOpen.value = false
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : 'Failed to initiate reboot.')
  } finally {
    rebooting.value = false
  }
}

onMounted(() => {
  loadStatus()
  loadConfig()
})
onUnmounted(() => {
  stopPolling()
  if (minSpinTimer !== null) clearTimeout(minSpinTimer)
})
</script>

<template>
    <PageHeader title="System Status" description="Health and configuration checks for this server.">
      <template #description>
        <p v-if="checkedAtLabel" class="text-xs text-faint mt-0.5">Last checked {{ checkedAtLabel }}</p>
        <Skeleton v-else class="h-3 w-24 mt-0.5" />
      </template>
      <template #actions>
        <Button
          variant="secondary"
          size="sm"
          :disabled="showSpinner"
          @click="triggerRefresh"
        >
          <RefreshCw class="size-4 mr-1.5" :class="{ 'animate-spin': showSpinner }" />
          {{ showSpinner ? 'Checking...' : 'Run checks' }}
        </Button>
      </template>
    </PageHeader>

    <!-- Reboot banner -->
    <Card
      v-if="rebootNeeded"
      padding="sm" class="mb-5 border-warning-border bg-warning-bg"
    >
      <p class="text-sm font-medium text-warning-fg">
        A system reboot is required to apply package updates.
      </p>
      <Button variant="secondary" size="sm" class="mt-2" @click="rebootOpen = true">
        Reboot Now
      </Button>
    </Card>

    <AsyncState
      :loading="loading || (running && results.length === 0)"
      :error="loadError"
      :empty="false"
      error-title="Could not load status checks"
      @retry="loadStatus"
    >
      <template #loading>
        <div class="flex gap-0 border-b border-border mb-6">
          <Skeleton v-for="i in 4" :key="i" class="h-9 w-24 mr-2 mb-px rounded-b-none" />
        </div>
        <div class="space-y-2">
          <div v-for="i in 6" :key="i" class="flex items-center gap-3 py-2">
            <Skeleton class="size-4 rounded-full shrink-0" />
            <Skeleton class="h-4" :class="i % 2 === 0 ? 'w-3/4' : 'w-1/2'" />
          </div>
        </div>
      </template>

      <!-- Tab bar -->
      <div class="flex gap-0 border-b border-border mb-6">
        <button
          v-for="section in sections"
          :key="section.category"
          :class="[
            'px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors flex items-center gap-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent rounded',
            activeTab === section.category
              ? 'border-text text-text'
              : 'border-transparent text-muted hover:text-text',
          ]"
          @click="activeTab = section.category"
        >
          {{ section.label }}
          <span
            v-if="sectionCount(section, 'error') > 0"
            class="text-xs px-1.5 py-0.5 rounded-full font-medium bg-error-bg text-error"
          >{{ sectionCount(section, 'error') }}</span>
          <span
            v-else-if="sectionCount(section, 'warning') > 0"
            class="text-xs px-1.5 py-0.5 rounded-full font-medium bg-warning-bg text-warning"
          >{{ sectionCount(section, 'warning') }}</span>
          <span v-else class="size-2 rounded-full bg-success" />
        </button>
      </div>

      <!-- Active section -->
      <div class="relative overflow-hidden">
      <Transition name="crossfade">
      <div :key="activeTab ? activeTab : undefined">
      <Card v-if="activeSection">
        <template v-for="(row, i) in activeSection.visible" :key="rowKey(row)">
          <Divider v-if="i > 0" />
          <CheckRow
            :row="row"
            :title="rowTitle(row)"
            :since="failingSince(row)"
            :reading="metricReading(row)"
            @detail="detailRowKey = rowKey(row)"
          />
        </template>

        <!-- Healthy port probes fold into one line; failing ones stay
             above as individual rows. -->
        <template v-if="activeSection.servicesOk.length > 0">
          <Divider v-if="activeSection.visible.length > 0" />
          <button
            type="button"
            class="w-full px-4 py-3 flex items-center gap-3 text-left rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            :aria-expanded="expandedGroups.has(activeSection.category + ':services')"
            @click="toggleGroup(activeSection.category + ':services')"
          >
            <StatusIcon status="ok" class="shrink-0" />
            <span class="text-sm text-muted dark:text-faint flex-1">{{ servicesLabel(activeSection) }}</span>
            <ChevronDown
              class="size-4 text-faint transition-transform"
              :class="{ '-rotate-180': expandedGroups.has(activeSection.category + ':services') }"
            />
          </button>
          <template v-if="expandedGroups.has(activeSection.category + ':services')">
            <template v-for="row in activeSection.servicesOk" :key="rowKey(row)">
              <Divider />
              <div class="pl-7">
                <CheckRow
                  :row="row"
                  :title="rowTitle(row)"
                  :since="failingSince(row)"
                  :reading="metricReading(row)"
                  @detail="detailRowKey = rowKey(row)"
                />
              </div>
            </template>
          </template>
        </template>

        <!-- Quiet checks verify invariants the software maintains
             itself: success carries no information, so they only get a
             count until one fails (failures render above as rows). -->
        <template v-if="activeSection.quiet.length > 0">
          <Divider v-if="activeSection.visible.length > 0 || activeSection.servicesOk.length > 0" />
          <button
            type="button"
            class="w-full px-4 py-3 flex items-center gap-3 text-left rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            :aria-expanded="expandedGroups.has(activeSection.category + ':quiet')"
            @click="toggleGroup(activeSection.category + ':quiet')"
          >
            <StatusIcon v-if="activeSection.quiet.every((r) => r.status === 'ok')" status="ok" class="shrink-0" />
            <span v-else class="size-2.5 rounded-full bg-border shrink-0" />
            <span class="text-sm text-muted dark:text-faint flex-1">{{ quietLabel(activeSection) }}</span>
            <ChevronDown
              class="size-4 text-faint transition-transform"
              :class="{ '-rotate-180': expandedGroups.has(activeSection.category + ':quiet') }"
            />
          </button>
          <template v-if="expandedGroups.has(activeSection.category + ':quiet')">
            <template v-for="row in activeSection.quiet" :key="rowKey(row)">
              <Divider />
              <div class="pl-7">
                <CheckRow
                  :row="row"
                  :title="rowTitle(row)"
                  :since="failingSince(row)"
                  :reading="metricReading(row)"
                  @detail="detailRowKey = rowKey(row)"
                />
              </div>
            </template>
          </template>
        </template>
      </Card>
      </div>
      </Transition>
      </div>
    </AsyncState>

    <!-- Check detail -->
    <Dialog v-model="detailOpen" :title="detailRow ? rowTitle(detailRow) : ''" :description="detailMeta?.description">
      <template v-if="detailRow">
        <p v-if="failingSince(detailRow)" class="text-xs text-error mb-4">{{ failingSince(detailRow) }}</p>

        <div v-if="(detailRow.steps ?? []).length > 0" class="space-y-3">
          <div
            v-for="(step, si) in detailRow.steps ?? []"
            :key="si"
            class="flex items-start gap-2"
          >
            <StatusIcon
              v-if="step.status === 'ok' || step.status === 'warning' || step.status === 'error'"
              :status="step.status"
              class="mt-0.5 shrink-0 scale-75"
            />
            <span v-else class="mt-1.5 size-2 rounded-full bg-border shrink-0" />
            <div class="min-w-0 flex-1">
              <p class="text-xs">
                <span class="font-medium">{{ step.name }}</span>
                <span v-if="step.message" class="text-muted dark:text-faint"> - {{ step.message }}</span>
              </p>
              <pre
                v-if="stepDetail(step)"
                class="text-xs font-mono text-muted dark:text-faint whitespace-pre-wrap mt-0.5"
              >{{ stepDetail(step) }}</pre>
            </div>
          </div>
        </div>
      </template>

      <template #actions>
        <Button variant="link" @click="detailOpen = false">Close</Button>
        <Button
          v-if="detailRow"
          variant="secondary"
          :disabled="configSaving"
          @click="toggleCheckEnabled(detailRow.check)"
        >
          {{ isDisabled(detailRow.check) ? 'Enable check' : 'Disable check' }}
        </Button>
      </template>
    </Dialog>

    <!-- Reboot confirm -->
    <Dialog
      v-model="rebootOpen"
      title="Reboot server?"
      description="This will reboot your Naust instance. Mail will be unavailable for about a minute."
    >
      <template #actions>
        <Button variant="secondary" @click="rebootOpen = false">Cancel</Button>
        <Button variant="destructive" :disabled="rebooting" @click="doReboot">
          {{ rebooting ? 'Rebooting...' : 'Reboot Now' }}
        </Button>
      </template>
    </Dialog>
</template>
