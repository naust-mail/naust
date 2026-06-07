<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { toast } from 'vue-sonner'
import { Globe } from 'lucide-vue-next'
import AppLayout from '@/components/layout/AppLayout.vue'
import Button from '@/components/ui/Button.vue'
import Input from '@/components/ui/Input.vue'
import Card from '@/components/ui/Card.vue'
import Table from '@/components/ui/Table.vue'
import TableRow from '@/components/ui/TableRow.vue'
import Skeleton from '@/components/ui/Skeleton.vue'
import EmptyState from '@/components/ui/EmptyState.vue'
import Dialog from '@/components/ui/Dialog.vue'
import Select from '@/components/ui/Select.vue'
import TableHead from '@/components/ui/TableHead.vue'
import Th from '@/components/ui/Th.vue'
import { useApi } from '@/composables/useApi'
import type { DnsRecord } from '@/types'

const api = useApi()

const records = ref<DnsRecord[]>([])
const zones = ref<string[]>([])
const loading = ref(true)
const saving = ref(false)
const deleteOpen = ref(false)
const pendingDelete = ref<DnsRecord | null>(null)

// Secondary nameserver
const secondaryHostnames = ref('')
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
  const res = await api.get('/admin/dns/zones')
  const data: string[] = await res.json()
  zones.value = data
  if (data.length && !fZone.value) fZone.value = data[0]
}

async function loadRecords(): Promise<void> {
  loading.value = true
  try {
    const res = await api.get('/admin/dns/custom')
    records.value = await res.json()
  } catch {
    toast.error('Failed to load DNS records.')
  } finally {
    loading.value = false
  }
}

async function loadSecondary(): Promise<void> {
  const res = await api.get('/admin/dns/secondary-nameserver')
  const data: { hostnames: string[] } = await res.json()
  secondaryHostnames.value = data.hostnames.join(' ')
}

async function addRecord(): Promise<void> {
  if (!qname.value || !fValue.value || saving.value) return
  saving.value = true
  try {
    // Value sent as raw text — daemon reads request.stream directly
    const res = await api.post(
      `/admin/dns/custom/${encodeURIComponent(qname.value)}/${fRtype.value}`,
      fValue.value,
    )
    const text = await res.text()
    if (!res.ok) { toast.error(text); return }
    toast.success(text || 'Record added.')
    fSubdomain.value = ''
    fValue.value = ''
    await loadRecords()
  } finally {
    saving.value = false
  }
}

function confirmDelete(record: DnsRecord): void {
  pendingDelete.value = record
  deleteOpen.value = true
}

async function doDelete(): Promise<void> {
  if (!pendingDelete.value) return
  saving.value = true
  try {
    const { qname: q, rtype, value } = pendingDelete.value
    const res = await api.del(
      `/admin/dns/custom/${encodeURIComponent(q)}/${rtype}`,
      value,
    )
    const text = await res.text()
    if (!res.ok) { toast.error(text); return }
    toast.success(text || 'Record deleted.')
    deleteOpen.value = false
    await loadRecords()
  } finally {
    saving.value = false
  }
}

async function saveSecondary(): Promise<void> {
  savingSecondary.value = true
  try {
    const res = await api.post('/admin/dns/secondary-nameserver', {
      hostnames: secondaryHostnames.value,
    })
    const text = await res.text()
    if (!res.ok) { toast.error(text); return }
    toast.success(text || 'Secondary nameserver updated.')
  } finally {
    savingSecondary.value = false
  }
}

onMounted(async () => {
  await Promise.all([loadZones(), loadRecords(), loadSecondary()])
})
</script>

<template>
  <AppLayout>
    <h1 class="text-2xl font-semibold mb-6">Custom DNS</h1>

    <!-- Add record -->
    <Card class="p-5 mb-6">
      <h2 class="text-base font-semibold mb-4">Add a DNS record</h2>
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">
        <div>
          <label for="fZone" class="block text-sm font-medium mb-1.5">Zone</label>
          <Select id="fZone" v-model="fZone" aria-placeholder="Select a zone">
            <option v-if="zones.length === 0" selected disabled value="none">No zones available</option>
            <option v-for="z in zones" :key="z" :value="z">{{ z }}</option>
          </Select>
        </div>
        <div>
          <label for="fSubdomain" class="block text-sm font-medium mb-1.5">Subdomain (optional)</label>
          <Input id="fSubdomain" v-model="fSubdomain" placeholder="@ or leave blank for zone apex" />
        </div>
        <div>
          <label for="fRtype" class="block text-sm font-medium mb-1.5">Type</label>
          <Select id="fRtype" v-model="fRtype">
            <option v-for="o in rtypeOptions" :key="o.value" :value="o.value">{{ o.value }}</option>
          </Select>
        </div>
        <div>
          <label for="fValue" class="block text-sm font-medium mb-1.5">Value</label>
          <Input id="fValue" v-model="fValue" :placeholder="fHint" />
        </div>
      </div>
      <p v-if="fHint" class="text-xs text-gray-500 mb-3">{{ fHint }}</p>
      <p v-if="qname" class="text-xs text-gray-500 mb-3">
        Record will be set on: <span class="font-medium">{{ qname }}</span>
      </p>
      <Button :disabled="!qname || !fValue || saving" @click="addRecord">
        {{ saving ? 'Adding...' : 'Add Record' }}
      </Button>
    </Card>

    <!-- Existing records -->
    <h2 class="text-base font-semibold mb-3">Current Records</h2>
    <Table>
      <TableHead>
        <Th>Name</Th>
        <Th>Type</Th>
        <Th>Value</Th>
        <th scope="col" class="px-4 py-3"></th>
      </TableHead>
      <tbody>
        <template v-if="loading">
          <TableRow v-for="i in 3" :key="i">
            <td class="px-4 py-3"><Skeleton class="h-4 w-40" /></td>
            <td class="px-4 py-3"><Skeleton class="h-4 w-12" /></td>
            <td class="px-4 py-3"><Skeleton class="h-4 w-32" /></td>
            <td class="px-4 py-3"></td>
          </TableRow>
        </template>
        <template v-else>
          <TableRow v-for="record in records" :key="`${record.qname}/${record.rtype}/${record.value}`">
            <td class="px-4 py-3 font-mono text-sm">{{ record.qname }}</td>
            <td class="px-4 py-3 text-sm font-medium">{{ record.rtype }}</td>
            <td class="px-4 py-3 font-mono text-sm text-gray-500 max-w-xs truncate">{{ record.value }}</td>
            <td class="px-4 py-3 text-right">
              <Button variant="ghost" size="sm" @click="confirmDelete(record)">Delete</Button>
            </td>
          </TableRow>
        </template>
      </tbody>
    </Table>

    <EmptyState
      v-if="!loading && records.length === 0"
      title="No custom DNS records"
      description="Add records above to override or extend this box's DNS."
    >
      <template #icon><Globe /></template>
    </EmptyState>

    <!-- Secondary nameserver -->
    <Card class="p-5 mt-6">
      <h2 class="text-base font-semibold mb-3">Secondary Nameserver</h2>
      <p class="text-sm text-gray-500 mb-3">
        Space-separated list of secondary nameserver hostnames.
      </p>
      <div class="flex gap-2">
        <Input v-model="secondaryHostnames" placeholder="ns2.yourdomain.com" class="max-w-sm" aria-label="Secondary nameserver hostnames" />
        <Button :disabled="savingSecondary" @click="saveSecondary">
          {{ savingSecondary ? 'Saving...' : 'Save' }}
        </Button>
      </div>
    </Card>

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
  </AppLayout>
</template>
