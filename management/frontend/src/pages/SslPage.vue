<script setup lang="ts">
import { ref, watch, onMounted } from 'vue'
import { toast } from 'vue-sonner'
import { ShieldCheck } from 'lucide-vue-next'
import AppLayout from '@/components/layout/AppLayout.vue'
import Button from '@/components/ui/Button.vue'
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
import { useApi } from '@/composables/useApi'
import { useConfigStore } from '@/stores/config'
import type { SslDomainStatus, SslStatus, SslProvisionResult } from '@/types'

const api = useApi()
const config = useConfigStore()

const loading = ref(true)
const domains = ref<SslDomainStatus[]>([])
const canProvision = ref<string[]>([])
const provisioning = ref(false)
const provisionResult = ref<SslProvisionResult | null>(null)

// Install cert sheet
const installOpen = ref(false)
const selectedDomain = ref('')
const selectedCc = ref('')
const csr = ref('')
const loadingCsr = ref(false)
const pastedCert = ref('')
const pastedChain = ref('')
const installing = ref(false)

async function load(): Promise<void> {
  loading.value = true
  provisionResult.value = null
  try {
    const res = await api.get('/admin/ssl/status')
    const data: SslStatus = await res.json()
    canProvision.value = data.can_provision
    domains.value = data.status
  } catch {
    toast.error('Failed to load TLS certificate status.')
  } finally {
    loading.value = false
  }
}

async function provision(): Promise<void> {
  if (provisioning.value) return
  provisioning.value = true
  provisionResult.value = null
  try {
    const res = await api.post('/admin/ssl/provision')
    const data: SslProvisionResult = await res.json()
    provisionResult.value = data
    const installed = data.requests.filter(r => r.result === 'installed').length
    const errors = data.requests.filter(r => r.result === 'error').length
    if (installed > 0) {
      toast.success(`${installed} certificate${installed > 1 ? 's' : ''} provisioned.`)
      await load()
    }
    if (errors > 0) {
      toast.error(`${errors} domain${errors > 1 ? 's' : ''} failed to provision.`)
    }
    if (data.requests.length === 0) {
      toast.info('No domains needed provisioning.')
    }
  } catch {
    toast.error('Failed to provision certificates.')
  } finally {
    provisioning.value = false
  }
}

function openInstall(domain?: string): void {
  selectedDomain.value = domain ?? (domains.value[0]?.domain ?? '')
  selectedCc.value = config.csrCountryCodes[0]?.[0] ?? ''
  csr.value = ''
  pastedCert.value = ''
  pastedChain.value = ''
  installOpen.value = true
}

async function fetchCsr(): Promise<void> {
  if (!selectedDomain.value || !selectedCc.value) return
  loadingCsr.value = true
  csr.value = ''
  try {
    const res = await api.post(`/admin/ssl/csr/${encodeURIComponent(selectedDomain.value)}`, {
      countrycode: selectedCc.value,
    })
    if (res.ok) {
      csr.value = await res.text()
    }
  } catch {
    // CSR fetch failed silently; user can retry
  } finally {
    loadingCsr.value = false
  }
}

async function installCert(): Promise<void> {
  if (!selectedDomain.value || !pastedCert.value || installing.value) return
  installing.value = true
  try {
    const res = await api.post('/admin/ssl/install', {
      domain: selectedDomain.value,
      cert: pastedCert.value,
      chain: pastedChain.value,
    })
    const text = await res.text()
    if (!res.ok) {
      toast.error(text)
      return
    }
    if (/^OK($|\n)/.test(text)) {
      toast.success('Certificate installed successfully.')
      installOpen.value = false
      await load()
    } else {
      toast.error(text)
    }
  } finally {
    installing.value = false
  }
}

watch([selectedDomain, selectedCc], fetchCsr)

onMounted(load)
</script>

<template>
  <AppLayout>
    <div class="flex items-center justify-between mb-6">
      <h1 class="text-2xl font-semibold">TLS Certificates</h1>
      <Button variant="secondary" size="sm" @click="openInstall()">Install Certificate</Button>
    </div>

    <!-- Provision card -->
    <Card v-if="!loading && canProvision.length > 0" class="p-5 mb-6">
      <h2 class="text-base font-semibold mb-1">Provision certificates</h2>
      <p class="text-sm text-gray-500 mb-3">
        {{ canProvision.join(', ') }}
        {{ canProvision.length === 1 ? 'is' : 'are' }} eligible for a free Let's Encrypt certificate.
      </p>
      <Button :disabled="provisioning" @click="provision">
        {{ provisioning ? 'Provisioning...' : 'Provision' }}
      </Button>

      <!-- Provision results -->
      <div v-if="provisionResult" class="mt-4 space-y-3">
        <div
          v-for="(req, i) in provisionResult.requests.filter(r => r.result !== 'skipped')"
          :key="i"
          class="rounded-lg px-4 py-3 text-sm"
          :class="req.result === 'installed'
            ? 'bg-emerald-50 dark:bg-emerald-950/30 text-emerald-800 dark:text-emerald-200'
            : 'bg-red-50 dark:bg-red-950/30 text-red-800 dark:text-red-200'"
        >
          <p class="font-medium">{{ req.domains.join(', ') }}</p>
          <p v-if="req.message">{{ req.message }}</p>
          <p v-if="req.result === 'installed'">Certificate installed successfully.</p>
        </div>
      </div>
    </Card>

    <!-- Domain table -->
    <template v-if="loading">
      <Table>
        <TableHead>
          <Th>Domain</Th>
          <Th>Status</Th>
          <th class="px-4 py-3"></th>
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

    <template v-else-if="domains.length === 0">
      <EmptyState title="No domains" description="No web domains are configured.">
        <template #icon><ShieldCheck /></template>
      </EmptyState>
    </template>

    <template v-else>
      <Table>
        <TableHead>
          <Th>Domain</Th>
          <Th>Status</Th>
          <th class="px-4 py-3"></th>
        </TableHead>
        <tbody>
          <TableRow v-for="d in domains" :key="d.domain">
            <td class="px-4 py-3 font-medium text-sm">
              <a
                v-if="d.status !== 'not-applicable'"
                :href="`https://${d.domain}`"
                target="_blank"
                class="hover:underline"
              >{{ d.domain }}</a>
              <span v-else class="text-gray-400">{{ d.domain }}</span>
            </td>
            <td class="px-4 py-3 text-sm text-gray-500">
              <div class="flex items-start gap-2">
                <StatusIcon
                  v-if="d.status !== 'not-applicable'"
                  :status="d.status === 'success' ? 'ok' : d.status"
                  class="mt-0.5 shrink-0"
                />
                <span>{{ d.text }}</span>
              </div>
            </td>
            <td class="px-4 py-3 text-right">
              <Button
                v-if="d.status !== 'not-applicable'"
                variant="ghost"
                size="sm"
                @click="openInstall(d.domain)"
              >
                {{ d.status === 'success' ? 'Replace' : 'Install' }}
              </Button>
            </td>
          </TableRow>
        </tbody>
      </Table>
    </template>

    <!-- Install cert sheet -->
    <Sheet v-model="installOpen" title="Install TLS Certificate">
      <div class="space-y-5">
        <div>
          <label class="block text-sm font-medium mb-1.5">Domain</label>
          <Select v-model="selectedDomain">
            <option
              v-for="d in domains.filter(d => d.status !== 'not-applicable')"
              :key="d.domain"
              :value="d.domain"
            >{{ d.domain }}</option>
          </Select>
        </div>

        <div>
          <label class="block text-sm font-medium mb-1.5">Country code (for CSR)</label>
          <Select v-model="selectedCc">
            <option
              v-for="[code, name] in config.csrCountryCodes"
              :key="code"
              :value="code"
            >{{ code }} - {{ name }}</option>
          </Select>
        </div>

        <div>
          <label class="block text-sm font-medium mb-1.5">Certificate Signing Request (CSR)</label>
          <p class="text-xs text-gray-400 mb-2">Submit this to your certificate authority.</p>
          <Textarea
            :model-value="loadingCsr ? 'Generating...' : csr"
            readonly
            :rows="6"
            class="font-mono text-xs"
            placeholder="Select a domain and country code above."
          />
        </div>

        <div>
          <label class="block text-sm font-medium mb-1.5">Paste certificate</label>
          <Textarea
            v-model="pastedCert"
            :rows="6"
            placeholder="-----BEGIN CERTIFICATE-----"
            class="font-mono text-xs"
          />
        </div>

        <div>
          <label class="block text-sm font-medium mb-1.5">Paste chain (optional)</label>
          <Textarea
            v-model="pastedChain"
            :rows="4"
            placeholder="-----BEGIN CERTIFICATE----- (intermediate/chain cert)"
            class="font-mono text-xs"
          />
        </div>

        <Button
          class="w-full"
          :disabled="!selectedDomain || !pastedCert || installing"
          @click="installCert"
        >
          {{ installing ? 'Installing...' : 'Install Certificate' }}
        </Button>
      </div>
    </Sheet>
  </AppLayout>
</template>
