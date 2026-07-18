<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { toast } from 'vue-sonner'
import { Globe, Plus, Copy } from 'lucide-vue-next'
import AsyncState from '@/components/ui/AsyncState.vue'
import Button from '@/components/ui/Button.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import SectionHeader from '@/components/ui/SectionHeader.vue'
import Field from '@/components/ui/Field.vue'
import Input from '@/components/ui/Input.vue'
import Card from '@/components/ui/Card.vue'
import Sheet from '@/components/ui/Sheet.vue'
import Table from '@/components/ui/Table.vue'
import TableRow from '@/components/ui/TableRow.vue'
import Code from '@/components/ui/Code.vue'
import Skeleton from '@/components/ui/Skeleton.vue'
import EmptyState from '@/components/ui/EmptyState.vue'
import Dialog from '@/components/ui/Dialog.vue'
import Select from '@/components/ui/Select.vue'
import Badge from '@/components/ui/Badge.vue'
import TableHead from '@/components/ui/TableHead.vue'
import Th from '@/components/ui/Th.vue'
import { api, ApiError } from '@/api/client'
import type {
  CreateDNSRecordRequest,
  DNSRecord,
  DNSRecordsResponse,
  DNSZonesResponse,
  SecondaryNameservers,
} from '@/api/types.gen'

const records = ref<DNSRecord[]>([])
const zones = ref<string[]>([])
const loading = ref(true)
const loadError = ref(false)
const expandedKey = ref<string | null>(null)
const copiedKey = ref<string | null>(null)

function toggleExpand(key: string): void {
  expandedKey.value = expandedKey.value === key ? null : key
}

async function copyValue(key: string, value: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(value)
    copiedKey.value = key
    setTimeout(() => { if (copiedKey.value === key) copiedKey.value = null }, 2000)
  } catch {
    toast.error('Could not copy to clipboard.')
  }
}
const saving = ref(false)
const sheetOpen = ref(false)
const deleteOpen = ref(false)
const pendingDelete = ref<DNSRecord | null>(null)

// Secondary nameserver
const secondaryHostnames = ref('')
const secondaryLoading = ref(true)
const savingSecondary = ref(false)

// Add form
const fZone = ref('')
const fSubdomain = ref('')
const fRtype = ref('A')
const fValue = ref('')
const fHint = computed(() => rtypeOptions.find(o => o.value === fRtype.value)?.hint ?? '')

const rtypeOptions = [
  { value: 'A', hint: 'Enter an IPv4 address (e.g. 1.2.3.4). Use "local" to set to this box\'s public IPv4.' },
  { value: 'AAAA', hint: 'Enter an IPv6 address. Use "local" to set to this box\'s public IPv6.' },
  { value: 'CAA', hint: 'Enter in the form: FLAG TAG VALUE (e.g. 0 issuewild "letsencrypt.org").' },
  { value: 'CNAME', hint: 'Enter another domain name followed by a period (e.g. mypage.github.io.).' },
  { value: 'TXT', hint: 'Enter arbitrary text.' },
  { value: 'MX', hint: 'Enter: PRIORITY DOMAIN. including trailing period (e.g. 20 mx.example.com.).' },
  { value: 'SRV', hint: 'Enter: PRIORITY WEIGHT PORT TARGET. including trailing period (e.g. 10 10 5060 sip.example.com.).' },
  { value: 'SSHFP', hint: 'Enter: ALGORITHM TYPE FINGERPRINT.' },
  { value: 'NS', hint: 'Enter a hostname to which this subdomain should be delegated.' },
]

const qname = computed(() => {
  const sub = fSubdomain.value.trim()
  const zone = fZone.value
  if (!zone) return ''
  return sub && sub !== '@' ? `${sub}.${zone}` : zone
})

async function loadZones(): Promise<void> {
  const resp = await api.get<DNSZonesResponse>('/api/dns/zones')
  zones.value = resp.zones ?? []
  if (zones.value.length && !fZone.value) fZone.value = zones.value[0]
}

async function loadRecords(): Promise<void> {
  loading.value = true
  loadError.value = false
  try {
    const resp = await api.get<DNSRecordsResponse>('/api/dns/custom')
    records.value = resp.records ?? []
  } catch {
    loadError.value = true
    toast.error('Failed to load DNS records.')
  } finally {
    loading.value = false
  }
}

async function loadSecondary(): Promise<void> {
  secondaryLoading.value = true
  try {
    const resp = await api.get<SecondaryNameservers>('/api/dns/secondary-nameserver')
    secondaryHostnames.value = (resp.hostnames ?? []).join(' ')
  } finally {
    secondaryLoading.value = false
  }
}

async function addRecord(): Promise<void> {
  if (!qname.value || !fValue.value || saving.value) return
  saving.value = true
  try {
    const req: CreateDNSRecordRequest = {
      qname: qname.value,
      rtype: fRtype.value,
      value: fValue.value,
    }
    await api.post('/api/dns/custom', req)
    toast.success('Record added.')
    sheetOpen.value = false
    fSubdomain.value = ''
    fValue.value = ''
    await loadRecords()
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : 'Failed to add record.')
  } finally {
    saving.value = false
  }
}

function confirmDelete(record: DNSRecord): void {
  pendingDelete.value = record
  deleteOpen.value = true
}

async function doDelete(): Promise<void> {
  if (!pendingDelete.value) return
  saving.value = true
  try {
    const { qname: q, rtype, value } = pendingDelete.value
    await api.del(
      `/api/dns/custom/${encodeURIComponent(q)}/${rtype}?value=${encodeURIComponent(value)}`,
    )
    toast.success('Record deleted.')
    deleteOpen.value = false
    await loadRecords()
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : 'Failed to delete record.')
  } finally {
    saving.value = false
  }
}

async function saveSecondary(): Promise<void> {
  savingSecondary.value = true
  try {
    const req: SecondaryNameservers = {
      hostnames: secondaryHostnames.value.split(/[\s,]+/).filter(s => s.length > 0),
    }
    await api.put('/api/dns/secondary-nameserver', req)
    toast.success('Secondary nameserver updated.')
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : 'Failed to update secondary nameserver.')
  } finally {
    savingSecondary.value = false
  }
}

onMounted(async () => {
  await Promise.all([loadZones(), loadRecords(), loadSecondary()])
})
</script>

<template>
    <PageHeader title="Custom DNS" description="Add DNS records that this box does not create automatically.">
      <template #actions>
        <Button size="sm" @click="sheetOpen = true"><Plus class="size-3.5" />Add Record</Button>
      </template>
    </PageHeader>

    <!-- Existing records -->
    <AsyncState :loading="loading" :error="loadError" :empty="records.length === 0" error-title="Could not load DNS records" @retry="loadRecords">
      <template #loading>
        <SectionHeader title="Current Records" />
        <Table>
          <TableHead>
            <Th>Name</Th>
            <Th>Type</Th>
            <Th>Value</Th>
            <Th />
          </TableHead>
          <tbody>
            <TableRow v-for="i in 3" :key="i">
              <td class="px-4 py-3"><Skeleton class="h-4 w-40" /></td>
              <td class="px-4 py-3"><Skeleton class="h-4 w-12" /></td>
              <td class="px-4 py-3"><Skeleton class="h-4 w-32" /></td>
              <td class="px-4 py-3"></td>
            </TableRow>
          </tbody>
        </Table>
      </template>

      <template #empty>
        <EmptyState bordered title="No custom DNS records" description="Add a record to override or extend this box's DNS.">
          <template #icon><Globe /></template>
          <template #action><Button @click="sheetOpen = true">Add Record</Button></template>
        </EmptyState>
      </template>

      <SectionHeader title="Current Records" />
      <Table>
        <TableHead>
          <Th>Name</Th>
          <Th>Type</Th>
          <Th>Value</Th>
          <Th />
        </TableHead>
        <tbody>
          <template v-for="record in records" :key="`${record.qname}/${record.rtype}/${record.value}`">
            <TableRow clickable @click="toggleExpand(`${record.qname}/${record.rtype}/${record.value}`)">
              <td class="px-4 py-3">
                <div class="font-mono text-sm max-w-[220px] truncate" :title="record.qname">{{ record.qname }}</div>
              </td>
              <td class="px-4 py-3">
                <Badge variant="default" class="font-mono">{{ record.rtype }}</Badge>
              </td>
              <td class="px-4 py-3">
                <div class="font-mono text-sm text-muted max-w-[280px] truncate" :title="record.value">{{ record.value }}</div>
              </td>
              <td class="px-4 py-3 text-right">
                <Button variant="secondary" size="sm" @click.stop="confirmDelete(record)">Delete</Button>
              </td>
            </TableRow>
            <tr v-if="expandedKey === `${record.qname}/${record.rtype}/${record.value}`" class="border-b border-border">
              <td colspan="4" class="bg-sidebar px-4 py-3">
                <div class="flex items-start gap-3">
                  <Code block wrap class="flex-1 min-w-0">{{ record.value }}</Code>
                  <Button variant="secondary" size="sm" class="shrink-0 mt-1" @click.stop="copyValue(`${record.qname}/${record.rtype}/${record.value}`, record.value)">
                    <Copy class="size-3" />{{ copiedKey === `${record.qname}/${record.rtype}/${record.value}` ? 'Copied!' : 'Copy' }}
                  </Button>
                </div>
              </td>
            </tr>
          </template>
        </tbody>
      </Table>
    </AsyncState>

    <!-- Secondary nameserver -->
    <Card padding="md" class="mt-6">
      <SectionHeader title="Secondary Nameserver" />
      <p class="text-sm text-muted mb-3">
        Space-separated list of secondary nameserver hostnames.
      </p>
      <div v-if="secondaryLoading" class="flex gap-2">
        <Skeleton class="h-9 w-full max-w-sm" />
        <Skeleton class="h-9 w-16" />
      </div>
      <div v-else class="flex gap-2">
        <Input v-model="secondaryHostnames" placeholder="ns2.yourdomain.com" class="max-w-sm" aria-label="Secondary nameserver hostnames" />
        <Button :disabled="savingSecondary" @click="saveSecondary">
          {{ savingSecondary ? 'Saving...' : 'Save' }}
        </Button>
      </div>
    </Card>

    <!-- Add record sheet -->
    <Sheet v-model="sheetOpen" title="Add DNS Record">
      <div class="space-y-5">
        <Field label="Zone" for="fZone">
          <Select id="fZone" v-model="fZone" aria-placeholder="Select a zone">
            <option v-if="zones.length === 0" selected disabled value="none">No zones available</option>
            <option v-for="z in zones" :key="z" :value="z">{{ z }}</option>
          </Select>
        </Field>
        <Field label="Subdomain (optional)" for="fSubdomain">
          <Input id="fSubdomain" v-model="fSubdomain" placeholder="@ or leave blank for zone apex" />
        </Field>
        <Field label="Type" for="fRtype">
          <Select id="fRtype" v-model="fRtype">
            <option v-for="o in rtypeOptions" :key="o.value" :value="o.value">{{ o.value }}</option>
          </Select>
        </Field>
        <Field label="Value" for="fValue">
          <Input id="fValue" v-model="fValue" :placeholder="fHint" />
          <p v-if="fHint" class="text-xs text-muted mt-1.5">{{ fHint }}</p>
        </Field>
        <p v-if="qname" class="text-xs text-muted">
          Record will be set on: <span class="font-medium">{{ qname }}</span>
        </p>
        <Button class="w-full" :disabled="!qname || !fValue || saving" @click="addRecord">
          {{ saving ? 'Adding...' : 'Add Record' }}
        </Button>
      </div>
    </Sheet>

    <!-- Delete confirm -->
    <Dialog
      v-model="deleteOpen"
      title="Delete DNS record?"
      :description="pendingDelete ? `${pendingDelete.qname} ${pendingDelete.rtype} ${pendingDelete.value}` : ''"
    >
      <template #actions>
        <Button variant="secondary" @click="deleteOpen = false">Cancel</Button>
        <Button variant="destructive" :disabled="saving" @click="doDelete">
          {{ saving ? 'Deleting...' : 'Delete' }}
        </Button>
      </template>
    </Dialog>
</template>
