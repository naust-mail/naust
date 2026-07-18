<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted } from 'vue'
import { toast } from 'vue-sonner'
import { ShieldCheck, Upload, RefreshCw } from 'lucide-vue-next'
import AsyncState from '@/components/ui/AsyncState.vue'
import Button from '@/components/ui/Button.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import SectionHeader from '@/components/ui/SectionHeader.vue'
import Field from '@/components/ui/Field.vue'
import Select from '@/components/ui/Select.vue'
import Card from '@/components/ui/Card.vue'
import Table from '@/components/ui/Table.vue'
import TableHead from '@/components/ui/TableHead.vue'
import Th from '@/components/ui/Th.vue'
import TableRow from '@/components/ui/TableRow.vue'
import Skeleton from '@/components/ui/Skeleton.vue'
import EmptyState from '@/components/ui/EmptyState.vue'
import Sheet from '@/components/ui/Sheet.vue'
import Textarea from '@/components/ui/Textarea.vue'
import StatusIcon from '@/components/shared/StatusIcon.vue'
import { api, ApiError } from '@/api/client'
import type {
  SSLCSRRequest,
  SSLCSRResponse,
  SSLDomainInfo,
  SSLInstallRequest,
  SSLProvisionRequest,
  SSLStatusResponse,
} from '@/api/types.gen'

// Provisioning runs in the background; ACME rounds take tens of
// seconds, so a relaxed poll is plenty.
const POLL_INTERVAL_MS = 4_000

// Country codes are only needed when the install-cert sheet opens.
// Dynamic import keeps them out of the initial bundle.
const countryCodes = ref<[string, string][]>([])
async function ensureCountryCodes(): Promise<void> {
  if (countryCodes.value.length) return
  const mod = await import('@/data/countryCodes')
  countryCodes.value = mod.CSR_COUNTRY_CODES
}

const loading = ref(true)
const loadError = ref(false)
const domains = ref<SSLDomainInfo[]>([])
const running = ref(false)
const lastError = ref('')
let pollTimer: ReturnType<typeof setInterval> | null = null

// Install cert sheet
const installOpen = ref(false)
const selectedDomain = ref('')
const selectedCc = ref('')
const csr = ref('')
const loadingCsr = ref(false)
const pastedCert = ref('')
const pastedChain = ref('')
const installing = ref(false)

const needsAttention = computed(() =>
  domains.value.filter(d => d.cert !== 'valid').map(d => d.domain),
)

function certIcon(d: SSLDomainInfo): 'ok' | 'warning' | 'error' {
  switch (d.cert) {
    case 'valid':
      return 'ok'
    case 'expiring':
    case 'self-signed':
      return 'warning'
    default:
      return 'error'
  }
}

function certLabel(d: SSLDomainInfo): string {
  const until = d.not_after
    ? new Date(d.not_after).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
    : ''
  switch (d.cert) {
    case 'valid':
      return until ? `Valid until ${until}` : 'Valid'
    case 'expiring':
      return until ? `Expires soon (${until})` : 'Expires soon'
    case 'expired':
      return 'Expired'
    case 'self-signed':
      return 'Self-signed certificate'
    default:
      return 'No certificate'
  }
}

function lastRunLabel(d: SSLDomainInfo): string | null {
  if (!d.last_status) return null
  const detail = d.last_detail ? ` - ${d.last_detail}` : ''
  return `Last run: ${d.last_status}${detail}`
}

function applyResponse(data: SSLStatusResponse): void {
  domains.value = data.domains ?? []
  running.value = data.running
  lastError.value = data.last_error ?? ''
}

// A handful of transient blips are expected; a run of failures this long
// means the backend is actually down, so give up rather than leaving the
// page polling (and "Provision" disabled) forever with no way out.
const MAX_CONSECUTIVE_POLL_FAILURES = 5

function startPolling(): void {
  if (pollTimer !== null) return
  let consecutiveFailures = 0
  pollTimer = setInterval(async () => {
    try {
      const data = await api.get<SSLStatusResponse>('/api/ssl')
      consecutiveFailures = 0
      applyResponse(data)
      if (!data.running) {
        stopPolling()
        toast.info('Certificate provisioning finished.')
      }
    } catch {
      consecutiveFailures++
      if (consecutiveFailures >= MAX_CONSECUTIVE_POLL_FAILURES) {
        stopPolling()
        running.value = false
        toast.error('Lost contact with the server during certificate provisioning. Try again once it is reachable.')
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

async function load(): Promise<void> {
  loading.value = true
  loadError.value = false
  try {
    const data = await api.get<SSLStatusResponse>('/api/ssl')
    applyResponse(data)
    if (data.running) startPolling()
  } catch {
    loadError.value = true
    toast.error('Failed to load TLS certificate status.')
  } finally {
    loading.value = false
  }
}

async function provision(): Promise<void> {
  if (running.value) return
  try {
    const req: SSLProvisionRequest = { domains: [] }
    await api.post('/api/ssl/provision', req)
    running.value = true
    startPolling()
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : 'Failed to start provisioning.')
  }
}

async function openInstall(domain?: string): Promise<void> {
  await ensureCountryCodes()
  selectedDomain.value = domain ?? (domains.value[0]?.domain ?? '')
  selectedCc.value = countryCodes.value[0]?.[0] ?? ''
  csr.value = ''
  pastedCert.value = ''
  pastedChain.value = ''
  installOpen.value = true
}

let csrRequestId = 0

async function fetchCsr(): Promise<void> {
  if (!selectedDomain.value || !selectedCc.value) return
  const requestId = ++csrRequestId
  loadingCsr.value = true
  csr.value = ''
  try {
    const req: SSLCSRRequest = {
      domain: selectedDomain.value,
      country_code: selectedCc.value,
    }
    const resp = await api.post<SSLCSRResponse>('/api/ssl/csr', req)
    // Domain/country may have changed again while this was in flight;
    // only the most recent request is allowed to write the result.
    if (requestId === csrRequestId) csr.value = resp.csr
  } catch {
    // CSR fetch failed silently; user can retry by reselecting.
  } finally {
    if (requestId === csrRequestId) loadingCsr.value = false
  }
}

async function installCert(): Promise<void> {
  if (!selectedDomain.value || !pastedCert.value || installing.value) return
  installing.value = true
  try {
    const req: SSLInstallRequest = {
      domain: selectedDomain.value,
      cert: pastedCert.value,
      chain: pastedChain.value,
    }
    await api.post('/api/ssl/install', req)
    toast.success('Certificate installed successfully.')
    installOpen.value = false
    await load()
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : 'Failed to install certificate.')
  } finally {
    installing.value = false
  }
}

watch([selectedDomain, selectedCc], fetchCsr)

onMounted(load)
onUnmounted(stopPolling)
</script>

<template>
    <PageHeader title="TLS Certificates" description="Keep your domains trusted and connections encrypted.">
      <template #actions>
        <Button variant="secondary" size="sm" @click="openInstall()"><Upload class="size-3.5" />Install Certificate</Button>
      </template>
    </PageHeader>

    <SectionHeader title="Certificate Status" />

    <!-- Run-level failure of the last provisioning attempt -->
    <Card v-if="lastError" padding="sm" class="mb-6 border-error-border bg-error-bg animate-fade-in">
      <p class="text-sm font-medium text-error-fg">Last provisioning run failed</p>
      <p class="text-sm text-error-fg mt-1">{{ lastError }}</p>
    </Card>

    <!-- Provision card -->
    <Card v-if="!loading && (needsAttention.length > 0 || running)" padding="md" class="mb-6 animate-fade-in">
      <SectionHeader title="Provision certificates" />
      <p class="text-sm text-muted mb-3">
        <template v-if="running">A provisioning run is in progress...</template>
        <template v-else>
          {{ needsAttention.join(', ') }}
          {{ needsAttention.length === 1 ? 'needs' : 'need' }} a certificate.
          Free Let's Encrypt certificates are provisioned automatically where DNS allows.
        </template>
      </p>
      <Button :disabled="running" @click="provision">
        <RefreshCw v-if="running" class="size-4 mr-1.5 animate-spin" />
        {{ running ? 'Provisioning...' : 'Provision' }}
      </Button>
    </Card>

    <!-- Domain table -->
    <AsyncState :loading="loading" :error="loadError" :empty="domains.length === 0" error-title="Could not load TLS status" @retry="load">
      <template #loading>
        <Table>
          <TableHead>
            <Th>Domain</Th>
            <Th>Status</Th>
            <Th />
          </TableHead>
          <tbody>
            <TableRow v-for="i in 5" :key="i">
              <td class="px-4 py-3"><Skeleton class="h-4 w-48" /></td>
              <td class="px-4 py-3"><Skeleton class="h-4 w-64" /></td>
              <td class="px-4 py-3"></td>
            </TableRow>
          </tbody>
        </Table>
      </template>

      <template #empty>
        <EmptyState bordered title="No domains" description="No web domains are configured.">
          <template #icon><ShieldCheck /></template>
        </EmptyState>
      </template>

      <Table>
        <TableHead>
          <Th>Domain</Th>
          <Th>Status</Th>
          <Th />
        </TableHead>
        <tbody>
          <TableRow v-for="d in domains" :key="d.domain">
            <td class="px-4 py-3 font-medium text-sm">
              <a :href="`https://${d.domain}`" target="_blank" class="hover:underline">{{ d.domain }}</a>
            </td>
            <td class="px-4 py-3 text-sm text-muted">
              <div class="flex items-center gap-2">
                <StatusIcon :status="certIcon(d)" class="shrink-0 mr-1" />
                <span>
                  {{ certLabel(d) }}
                  <span v-if="lastRunLabel(d)" class="block text-xs text-faint">{{ lastRunLabel(d) }}</span>
                </span>
              </div>
            </td>
            <td class="px-4 py-3 text-right">
              <Button variant="secondary" size="sm" @click="openInstall(d.domain)">
                {{ d.cert === 'valid' ? 'Replace' : 'Install' }}
              </Button>
            </td>
          </TableRow>
        </tbody>
      </Table>
    </AsyncState>

    <!-- Install cert sheet -->
    <Sheet v-model="installOpen" title="Install TLS Certificate">
      <div class="space-y-5">
        <Field label="Domain" for="installDomain">
          <Select id="installDomain" v-model="selectedDomain">
            <option v-for="d in domains" :key="d.domain" :value="d.domain">{{ d.domain }}</option>
          </Select>
        </Field>

        <Field label="Country code (for CSR)" for="installCc">
          <Select id="installCc" v-model="selectedCc">
            <option
              v-for="[code, name] in countryCodes"
              :key="code"
              :value="code"
            >{{ code }} - {{ name }}</option>
          </Select>
        </Field>

        <Field label="Certificate Signing Request (CSR)" for="installCsr">
          <p class="text-xs text-muted mb-2">Submit this to your certificate authority.</p>
          <Textarea
            id="installCsr"
            :model-value="loadingCsr ? 'Generating...' : csr"
            readonly
            :rows="6"
            class="font-mono text-xs"
            placeholder="Select a domain and country code above."
          />
        </Field>

        <Field label="Paste certificate" for="installCert">
          <Textarea
            id="installCert"
            v-model="pastedCert"
            :rows="6"
            placeholder="-----BEGIN CERTIFICATE-----"
            class="font-mono text-xs"
          />
        </Field>

        <Field label="Paste chain (optional)" for="installChain">
          <Textarea
            id="installChain"
            v-model="pastedChain"
            :rows="4"
            placeholder="-----BEGIN CERTIFICATE----- (intermediate/chain cert)"
            class="font-mono text-xs"
          />
        </Field>

        <Button
          class="w-full"
          :disabled="!selectedDomain || !pastedCert || installing"
          @click="installCert"
        >
          {{ installing ? 'Installing...' : 'Install Certificate' }}
        </Button>
      </div>
    </Sheet>
</template>
