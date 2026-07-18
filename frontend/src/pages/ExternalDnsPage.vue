<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { toast } from 'vue-sonner'
import { Download, Copy, Check, ChevronRight } from 'lucide-vue-next'
import AsyncState from '@/components/ui/AsyncState.vue'
import Button from '@/components/ui/Button.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import SectionHeader from '@/components/ui/SectionHeader.vue'
import Badge from '@/components/ui/Badge.vue'
import Select from '@/components/ui/Select.vue'
import Table from '@/components/ui/Table.vue'
import TableRow from '@/components/ui/TableRow.vue'
import Code from '@/components/ui/Code.vue'
import TableHead from '@/components/ui/TableHead.vue'
import Th from '@/components/ui/Th.vue'
import Skeleton from '@/components/ui/Skeleton.vue'
import { api } from '@/api/client'
import type { ExternalDNSRecord, ExternalDNSResponse } from '@/api/types.gen'

type ZoneData = [string, ExternalDNSRecord[]]

const zones = ref<ZoneData[]>([])
const dnsZones = ref<string[]>([])
const selectedZone = ref('')
const loading = ref(true)
const loadError = ref(false)
const expandedKey = ref<string | null>(null)
const copiedKey = ref<string | null>(null)
const filterTab = ref<'required' | 'recommended' | 'all'>('required')
const hardeningOpen = ref<Record<string, boolean>>({})

function coreRecords(records: ExternalDNSRecord[]): ExternalDNSRecord[] {
  if (filterTab.value !== 'recommended') return records
  return records.filter(r => r.category !== 'hardening')
}

function hardeningRecords(records: ExternalDNSRecord[]): ExternalDNSRecord[] {
  return records.filter(r => r.category === 'hardening')
}

function toggleExpand(key: string): void {
  expandedKey.value = expandedKey.value === key ? null : key
}

const allRecords = computed(() => zones.value.flatMap(([, records]) => records))

const counts = computed(() => ({
  required:    allRecords.value.filter(r => r.category === 'required').length,
  recommended: allRecords.value.filter(r => r.category === 'recommended' || r.category === 'hardening').length,
  all:         allRecords.value.length,
}))

const TYPE_ORDER: Record<string, number> = { A: 0, AAAA: 1, MX: 2, TXT: 3, TLSA: 4, SSHFP: 5 }
const sortByType = (records: ExternalDNSRecord[]) =>
  [...records].sort((a, b) =>
    (TYPE_ORDER[a.type] ?? 9) - (TYPE_ORDER[b.type] ?? 9) || a.qname.localeCompare(b.qname)
  )

const filteredZones = computed<ZoneData[]>(() =>
  zones.value
    .map(([name, records]) => {
      const filtered = filterTab.value === 'all'
        ? records
        : filterTab.value === 'recommended'
          ? records.filter(r => r.category === 'recommended' || r.category === 'hardening')
          : records.filter(r => r.category === filterTab.value)
      return [name, sortByType(filtered)] as ZoneData
    })
    .filter(([, records]) => records.length > 0)
)

function recordSummary(r: ExternalDNSRecord): string {
  switch (r.type) {
    case 'A':
      if (r.qname.startsWith('autoconfig.'))  return 'Lets email apps find this server automatically'
      if (r.qname.startsWith('autodiscover.')) return 'Lets Outlook and compatible clients find this server'
      if (r.qname.startsWith('mta-sts.'))     return 'Serves the strict mail encryption policy'
      if (r.qname.startsWith('www.'))         return 'Points the www subdomain to this server'
      return 'Points this domain to the server'
    case 'AAAA':
      return 'IPv6 address for this domain'
    case 'MX':
      if (r.value === '0 .') return 'Declares this domain does not accept email'
      return 'Directs incoming email to this server'
    case 'TXT':
      if (r.value === 'v=spf1 -all')              return 'Prevents this domain from being used to send email'
      if (r.value.startsWith('v=spf1'))           return 'Authorizes this server to send email for this domain'
      if (r.value.startsWith('v=DKIM1'))          return 'Lets receiving servers verify your email is genuine'
      if (r.value.startsWith('v=DMARC1; p=quarantine')) return 'Marks suspicious email from this domain as spam'
      if (r.value.startsWith('v=DMARC1; p=reject'))    return 'Rejects email that fails authentication checks'
      if (r.value.startsWith('v=STSv1'))          return 'Signals that strict mail encryption is enforced'
      if (r.value.startsWith('v=TLSRPTv1'))       return 'Receives reports on mail delivery failures'
      return 'Custom text record'
    case 'TLSA':
      if (r.qname.startsWith('_25.'))  return 'Enables certificate pinning for incoming mail connections'
      if (r.qname.startsWith('_443.')) return 'Enables certificate pinning for HTTPS connections'
      return 'Certificate pinning record'
    case 'SSHFP':
      return 'Verifiable SSH fingerprint for this server'
    default:
      return `${r.type} record`
  }
}

function recordExplanation(r: ExternalDNSRecord): string {
  switch (r.type) {
    case 'A':    return `Resolves ${r.qname} to the server's IP address.`
    case 'AAAA': return `Resolves ${r.qname} to the server's IPv6 address. Not required for mail delivery.`
    case 'MX':
      if (r.value === '0 .') return `Null MX record. Declares that ${r.qname} does not accept incoming mail, preventing it from being used as a spoofed sending domain.`
      return `Tells other mail servers to deliver mail for @${r.qname} to this server.`
    case 'TXT':
      if (r.value.startsWith('v=spf1') && r.value.includes('-all') && !r.value.includes('mx'))
        return `Hard-fail SPF: declares no servers are authorized to send mail from @${r.qname}. Prevents this subdomain from being used in spoofed mail.`
      if (r.value.startsWith('v=spf1'))
        return `SPF record authorizing this server to send mail from @${r.qname}. Receiving servers use this to verify outbound mail.`
      if (r.value.startsWith('v=DKIM1'))
        return `DKIM public key. Receiving servers use this to verify the cryptographic signature on mail sent from this server.`
      if (r.value.startsWith('v=DMARC1; p=quarantine'))
        return `DMARC policy: mail from @${r.qname} that fails SPF or DKIM checks should be quarantined.`
      if (r.value.startsWith('v=DMARC1; p=reject'))
        return `DMARC policy: mail from @${r.qname} that fails SPF or DKIM checks should be rejected. Prevents subdomain spoofing.`
      if (r.value.startsWith('v=STSv1'))
        return `MTA-STS policy ID. Signals to sending servers that a strict TLS policy is published for this domain.`
      if (r.value.startsWith('v=TLSRPTv1'))
        return `SMTP TLS reporting. Receiving servers send TLS failure reports to this address.`
      return ''
    case 'TLSA':  return `DANE/TLSA record. When DNSSEC is enabled, this allows mail servers to verify the certificate used by this server without relying on a CA.`
    case 'SSHFP': return `SSH key fingerprint. Allows SSH clients to verify this server's key out-of-band using DNS. Requires DNSSEC and "VerifyHostKeyDNS yes" in your SSH config.`
    default:      return ''
  }
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

async function load(): Promise<void> {
  loading.value = true
  loadError.value = false
  try {
    const resp = await api.get<ExternalDNSResponse>('/api/dns/external')
    zones.value = (resp.zones ?? []).map(z => [z.zone, z.records ?? []])
    dnsZones.value = (resp.zones ?? []).map(z => z.zone)
    if (dnsZones.value.length) selectedZone.value = dnsZones.value[0]
  } catch {
    loadError.value = true
    toast.error('Failed to load DNS records.')
  } finally {
    loading.value = false
  }
}

// Rendered client-side from the loaded records: they are exactly the
// desired record set, so no separate server endpoint is needed.
function downloadZonefile(): void {
  if (!selectedZone.value) return
  const zone = zones.value.find(([name]) => name === selectedZone.value)
  if (!zone) return
  const lines = zone[1].map(r => `${r.qname}.\tIN\t${r.type}\t${r.value}`)
  const blob = new Blob([lines.join('\n') + '\n'], { type: 'text/plain' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `${selectedZone.value}.txt`
  a.click()
  URL.revokeObjectURL(url)
}


onMounted(load)
</script>

<template>
    <PageHeader title="External DNS" description="Required DNS records if another provider controls your domain's nameservers.">
      <template #actions>
        <div class="flex items-center gap-2">
          <Select v-model="selectedZone" size="sm" class="w-auto" :disabled="loadError" aria-label="Select zone">
            <option v-if="loadError" value="" disabled>No zones</option>
            <option v-for="z in dnsZones" :key="z" :value="z">{{ z }}</option>
          </Select>
          <Button variant="secondary" size="sm" @click="downloadZonefile" :disabled="loadError"><Download class="size-3.5" />Download zone file</Button>
        </div>
      </template>
    </PageHeader>

    <AsyncState :loading="loading" :error="loadError" :empty="false" error-title="Could not load DNS records" @retry="load">
      <template #loading>
        <div class="space-y-6">
          <div v-for="i in 2" :key="i">
            <Skeleton class="h-5 w-40 mb-3" />
            <div class="space-y-2">
              <Skeleton v-for="j in 4" :key="j" class="h-12 w-full" />
            </div>
          </div>
        </div>
      </template>

      <!-- Filter tabs -->
      <div class="flex gap-0 border-b border-border mb-6">
        <button
          v-for="tab in ([
            { id: 'required',    label: 'Required',    count: counts.required },
            { id: 'recommended', label: 'Recommended', count: counts.recommended },
            { id: 'all',         label: 'All',         count: counts.all },
          ] as const)"
          :key="tab.id"
          @click="filterTab = tab.id; expandedKey = null; hardeningOpen = {}"
          :class="[
            'px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors flex items-center gap-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent rounded',
            filterTab === tab.id
              ? 'border-text text-text'
              : 'border-transparent text-muted hover:text-text',
          ]"
        >
          {{ tab.label }}
          <span :class="[
            'text-xs px-1.5 py-0.5 rounded-full font-medium',
            filterTab === tab.id ? 'bg-hover text-text' : 'bg-hover text-faint',
          ]">{{ tab.count }}</span>
        </button>
      </div>

      <div v-for="[zoneName, zoneRecords] in filteredZones" :key="zoneName" class="mb-8">
        <SectionHeader :title="zoneName" />
        <Table class="table-fixed">
          <TableHead>
            <Th class="w-[25%]">Name</Th>
            <Th class="w-[60%]">Description</Th>
            <Th class="w-[10%]">Type</Th>
            <Th class="w-[5%]"></Th>
          </TableHead>
          <tbody>
            <template v-for="record in coreRecords(zoneRecords)" :key="`${record.qname}/${record.type}`">
              <TableRow clickable @click="toggleExpand(`${record.qname}/${record.type}`)">
                <td class="px-4 py-3 max-w-0 overflow-hidden">
                  <div class="font-mono text-xs truncate" :title="record.qname">{{ record.qname }}</div>
                </td>
                <td class="px-4 py-3">
                  <span class="text-xs text-muted">{{ recordSummary(record) }}</span>
                </td>
                <td class="px-4 py-3">
                  <Badge variant="default" class="font-mono">{{ record.type }}</Badge>
                </td>
                <td class="px-4 py-3 text-right">
                  <Button variant="secondary" size="icon" class="text-faint" @click.stop="copyValue(`${record.qname}/${record.type}`, record.value)" aria-label="Copy value">
                    <Check v-if="copiedKey === `${record.qname}/${record.type}`" class="size-3.5 text-success" />
                    <Copy v-else class="size-3.5" />
                  </Button>
                </td>
              </TableRow>

              <tr v-if="expandedKey === `${record.qname}/${record.type}`" class="border-b border-border">
                <td colspan="4" class="bg-sidebar px-4 py-3">
                  <Code block wrap>{{ record.value }}</Code>
                  <p v-if="recordExplanation(record)" class="text-xs text-muted mt-2">{{ recordExplanation(record) }}</p>
                </td>
              </tr>
            </template>

            <!-- Subdomain hardening records, collapsed by default -->
            <template v-if="filterTab === 'recommended' && hardeningRecords(zoneRecords).length">
              <tr class="border-t border-border">
                <td colspan="4" class="px-4 py-2">
                  <Button variant="link" size="sm" class="text-faint gap-1.5" @click="hardeningOpen[zoneName] = !hardeningOpen[zoneName]">
                    <ChevronRight :class="['size-3.5 transition-transform duration-150', hardeningOpen[zoneName] ? 'rotate-90' : '']" aria-hidden="true" />
                    Subdomain hardening ({{ hardeningRecords(zoneRecords).length }} records)
                  </Button>
                </td>
              </tr>
              <template v-if="hardeningOpen[zoneName]">
                <template v-for="record in hardeningRecords(zoneRecords)" :key="`${record.qname}/${record.type}`">
                  <TableRow clickable @click="toggleExpand(`${record.qname}/${record.type}`)">
                    <td class="px-4 py-3 max-w-0 overflow-hidden">
                      <div class="font-mono text-xs truncate" :title="record.qname">{{ record.qname }}</div>
                    </td>
                    <td class="px-4 py-3">
                      <span class="text-xs text-muted">{{ recordSummary(record) }}</span>
                    </td>
                    <td class="px-4 py-3">
                      <Badge variant="default" class="font-mono">{{ record.type }}</Badge>
                    </td>
                    <td class="px-4 py-3 text-right">
                      <Button variant="secondary" size="icon" class="text-faint" @click.stop="copyValue(`${record.qname}/${record.type}`, record.value)" aria-label="Copy value">
                        <Check v-if="copiedKey === `${record.qname}/${record.type}`" class="size-3.5 text-success" />
                        <Copy v-else class="size-3.5" />
                      </Button>
                    </td>
                  </TableRow>

                  <tr v-if="expandedKey === `${record.qname}/${record.type}`" class="border-b border-border">
                    <td colspan="4" class="bg-sidebar px-4 py-3">
                      <Code block wrap>{{ record.value }}</Code>
                      <p v-if="recordExplanation(record)" class="text-xs text-muted mt-2">{{ recordExplanation(record) }}</p>
                    </td>
                  </tr>
                </template>
              </template>
            </template>
          </tbody>
        </Table>
      </div>
    </AsyncState>
</template>

