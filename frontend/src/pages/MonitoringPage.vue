<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { ExternalLink, Cpu, HardDrive, Mail, Network } from 'lucide-vue-next'
import AsyncState from '@/components/ui/AsyncState.vue'
import Button from '@/components/ui/Button.vue'
import Card from '@/components/ui/Card.vue'
import Code from '@/components/ui/Code.vue'
import EmptyState from '@/components/ui/EmptyState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import Skeleton from '@/components/ui/Skeleton.vue'
import { api } from '@/api/client'
import type { WebStatusResponse } from '@/api/types.gen'

const loading = ref(true)
const loadError = ref(false)
// The enabled monitoring dashboard: app name and mount path from the
// web tier's monitoring slot. nginx guards the path with auth_request
// against the admin session, so opening it just works when logged in.
const tool = ref('')
const path = ref('')

const hasMonitoring = computed(() => tool.value !== '')

const TOOL_LABELS: Record<string, string> = {
  netdata: 'Netdata',
  beszel: 'Beszel',
  munin: 'Munin',
}

const updateNote = computed(() =>
  tool.value === 'munin' ? 'Graphs are updated every 5 minutes.' : 'Dashboard updates in real time.'
)

async function load(): Promise<void> {
  loading.value = true
  loadError.value = false
  try {
    const data = await api.get<WebStatusResponse>('/api/web')
    const mount = (data.mounts ?? []).find(m => m.role === 'monitoring')
    if (mount?.enabled && mount.app) {
      tool.value = mount.app
      path.value = mount.path
    }
  } catch {
    loadError.value = true
  } finally {
    loading.value = false
  }
}

function openMonitoring(): void {
  if (!path.value) return
  window.open(`${path.value}/`, '_blank')
}

type MonitoringCategory = {
  icon: typeof Cpu
  label: string
  description: string
}

const CATEGORIES: MonitoringCategory[] = [
  { icon: Cpu,       label: 'System',  description: 'CPU usage, load average, memory, swap, and process counts over time.' },
  { icon: HardDrive, label: 'Disk',    description: 'Disk I/O throughput, latency, and filesystem usage trends.' },
  { icon: Network,   label: 'Network', description: 'Bandwidth in/out per interface, connection states, and error rates.' },
  { icon: Mail,      label: 'Mail',    description: 'Postfix queue depth, delivery rates, spam/virus filter hits, and Dovecot connections.' },
]

onMounted(load)
</script>

<template>
    <PageHeader title="Monitoring" description="View server health and performance metrics." />

    <AsyncState :loading="loading" :error="loadError" :empty="!hasMonitoring" error-title="Could not load monitoring status" @retry="load">
      <template #loading>
        <Skeleton class="h-4 w-full max-w-md mb-6" />
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6">
          <Card v-for="i in 4" :key="i" padding="sm">
            <Skeleton class="h-4 w-24 mb-2" />
            <Skeleton class="h-3 w-full" />
          </Card>
        </div>
        <Card padding="sm">
          <Skeleton class="h-4 w-40 mb-2" />
          <Skeleton class="h-3 w-64" />
        </Card>
      </template>

      <template #empty>
        <EmptyState
          bordered
          title="No monitoring tool configured"
          description="Run the command below and select a monitoring tool, or re-run setup to enable one."
        >
          <template #icon><Cpu /></template>
          <template #action>
            <Code>sudo boxctl doctor</Code>
          </template>
        </EmptyState>
      </template>

      <p class="text-sm text-muted mb-6">
        System metrics are collected and rendered as historical graphs.
        Use them to spot trends, diagnose performance issues, or verify that services are behaving normally.
      </p>

      <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6">
        <Card v-for="cat in CATEGORIES" :key="cat.label" padding="sm" class="flex items-start gap-3">
          <div class="mt-0.5 rounded-lg bg-accent/10 p-2 shrink-0">
            <component :is="cat.icon" class="size-4 text-accent" />
          </div>
          <div>
            <p class="text-sm font-medium mb-0.5">{{ cat.label }}</p>
            <p class="text-xs text-muted">{{ cat.description }}</p>
          </div>
        </Card>
      </div>

      <Card padding="sm" class="flex items-center justify-between gap-4">
        <div>
          <p class="text-sm font-medium mb-0.5">Open {{ TOOL_LABELS[tool] ?? tool }}</p>
          <p class="text-xs text-muted">Opens in a new tab. {{ updateNote }}</p>
        </div>
        <Button size="sm" @click="openMonitoring">
          <ExternalLink class="size-3.5" />Open Monitoring
        </Button>
      </Card>
    </AsyncState>
</template>
