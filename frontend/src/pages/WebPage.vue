<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { toast } from 'vue-sonner'
import { Globe, Plus, Trash2 } from 'lucide-vue-next'
import AsyncState from '@/components/ui/AsyncState.vue'
import Button from '@/components/ui/Button.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import SectionHeader from '@/components/ui/SectionHeader.vue'
import Field from '@/components/ui/Field.vue'
import Checkbox from '@/components/ui/Checkbox.vue'
import Input from '@/components/ui/Input.vue'
import Select from '@/components/ui/Select.vue'
import Card from '@/components/ui/Card.vue'
import Code from '@/components/ui/Code.vue'
import Badge from '@/components/ui/Badge.vue'
import Table from '@/components/ui/Table.vue'
import TableHead from '@/components/ui/TableHead.vue'
import Th from '@/components/ui/Th.vue'
import TableRow from '@/components/ui/TableRow.vue'
import Skeleton from '@/components/ui/Skeleton.vue'
import EmptyState from '@/components/ui/EmptyState.vue'
import Dialog from '@/components/ui/Dialog.vue'
import Sheet from '@/components/ui/Sheet.vue'
import { api, ApiError } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import type {
  WebDomainConfig,
  WebDomainInfo,
  WebMountInfo,
  WebMountsRequest,
  WebRule,
  WebStatusResponse,
} from '@/api/types.gen'

const auth = useAuthStore()

const loading = ref(true)
const loadError = ref(false)
const domains = ref<WebDomainInfo[]>([])
const mounts = ref<WebMountInfo[]>([])

// Domain editor sheet
const sheetOpen = ref(false)
const saving = ref(false)
const editing = ref<WebDomainInfo | null>(null)
const fHsts = ref('on')
const fServeStatic = ref(true)
const fRules = ref<WebRule[]>([])
const resetOpen = ref(false)

// Mount editor state: role -> path being edited
const mountPaths = ref<Record<string, string>>({})
const savingMounts = ref(false)

function applyStatus(resp: WebStatusResponse): void {
  domains.value = resp.domains ?? []
  mounts.value = resp.mounts ?? []
  const paths: Record<string, string> = {}
  for (const m of mounts.value) {
    if (!m.fixed && m.enabled) paths[m.role] = m.path
  }
  mountPaths.value = paths
}

async function load(): Promise<void> {
  loading.value = true
  loadError.value = false
  try {
    applyStatus(await api.get<WebStatusResponse>('/api/web'))
  } catch {
    loadError.value = true
    toast.error('Failed to load web configuration.')
  } finally {
    loading.value = false
  }
}

function openEdit(d: WebDomainInfo): void {
  editing.value = d
  fHsts.value = d.hsts
  fServeStatic.value = d.serve_static
  // Deep copy so cancel leaves the table untouched.
  fRules.value = (d.rules ?? []).map(r => ({ ...r }))
  sheetOpen.value = true
}

function addRule(): void {
  fRules.value.push({ kind: 'proxy', path: '/', target: '' })
}

function removeRule(i: number): void {
  fRules.value.splice(i, 1)
}

async function save(): Promise<void> {
  if (!editing.value || saving.value) return
  saving.value = true
  try {
    const config: WebDomainConfig = {
      hsts: fHsts.value,
      serve_static: fServeStatic.value,
    }
    if (fRules.value.length > 0) config.rules = fRules.value
    await api.put(`/api/web/domains/${encodeURIComponent(editing.value.domain)}`, config)
    toast.success('Domain configuration saved.')
    sheetOpen.value = false
    await load()
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : 'Failed to save configuration.')
  } finally {
    saving.value = false
  }
}

async function confirmReset(): Promise<void> {
  if (!editing.value) return
  saving.value = true
  try {
    await api.del(`/api/web/domains/${encodeURIComponent(editing.value.domain)}`)
    toast.success('Domain returned to defaults.')
    resetOpen.value = false
    sheetOpen.value = false
    await load()
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : 'Failed to reset domain.')
  } finally {
    saving.value = false
  }
}

async function saveMounts(): Promise<void> {
  if (savingMounts.value) return
  savingMounts.value = true
  try {
    const req: WebMountsRequest = { mounts: { ...mountPaths.value } }
    await api.put('/api/web/mounts', req)
    toast.success('App placement saved.')
    applyStatus(await api.get<WebStatusResponse>('/api/web'))
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : 'Failed to save app placement.')
  } finally {
    savingMounts.value = false
  }
}

function domainBadges(d: WebDomainInfo): string[] {
  const badges: string[] = []
  if (d.primary) badges.push('primary')
  if (d.redirect_to) badges.push(`redirects to ${d.redirect_to}`)
  if (d.customized) badges.push('customized')
  return badges
}

onMounted(load)
</script>

<template>
    <PageHeader title="Web" description="Websites, reverse proxies and app placement on this box." />

    <Card padding="md" class="mb-6">
      <SectionHeader title="Static website files" />
      <p class="text-sm text-muted mb-2">
        Every hosted domain serves static files. Upload them over SSH/SFTP
        (server credentials, not your mail password) to:
      </p>
      <Code block>/home/user-data/www/&lt;domain&gt;/</Code>
      <p class="text-xs text-muted mt-2">
        Domains without their own directory serve the shared default site
        from <span class="font-mono">/home/user-data/www/default/</span>.
        Create the domain directory to give a domain its own site.
      </p>
    </Card>

    <AsyncState :loading="loading" :error="loadError" :empty="domains.length === 0" error-title="Could not load web configuration" @retry="load">
      <template #loading>
        <SectionHeader title="Hosted Domains" />
        <Table>
          <TableHead>
            <Th>Domain</Th>
            <Th>HSTS</Th>
            <Th>Rules</Th>
            <Th />
          </TableHead>
          <tbody>
            <TableRow v-for="i in 3" :key="i">
              <td class="px-4 py-3"><Skeleton class="h-4 w-48" /></td>
              <td class="px-4 py-3"><Skeleton class="h-4 w-16" /></td>
              <td class="px-4 py-3"><Skeleton class="h-4 w-24" /></td>
              <td class="px-4 py-3"></td>
            </TableRow>
          </tbody>
        </Table>

        <SectionHeader title="App Placement" class="mt-8" />
        <Table>
          <TableHead>
            <Th>Role</Th>
            <Th>App</Th>
            <Th class="w-1/3">Path</Th>
          </TableHead>
          <tbody>
            <TableRow v-for="i in 3" :key="i">
              <td class="px-4 py-3"><Skeleton class="h-4 w-20" /></td>
              <td class="px-4 py-3"><Skeleton class="h-4 w-24" /></td>
              <td class="px-4 py-3"><Skeleton class="h-4 w-32" /></td>
            </TableRow>
          </tbody>
        </Table>
      </template>

      <template #empty>
        <EmptyState bordered title="No web domains" description="Add a mail user or alias on a domain to host web for it.">
          <template #icon><Globe /></template>
        </EmptyState>
      </template>

      <SectionHeader title="Hosted Domains" />
      <Table>
        <TableHead>
          <Th>Domain</Th>
          <Th>HSTS</Th>
          <Th>Rules</Th>
          <Th />
        </TableHead>
        <tbody>
          <TableRow v-for="d in domains" :key="d.domain">
            <td class="px-4 py-3">
              <span class="text-sm font-medium">{{ d.domain }}</span>
              <span class="ml-2 space-x-1">
                <Badge v-for="b in domainBadges(d)" :key="b" variant="default">{{ b }}</Badge>
              </span>
            </td>
            <td class="px-4 py-3 text-sm text-muted">{{ d.hsts }}</td>
            <td class="px-4 py-3 text-sm text-muted">
              {{ (d.rules ?? []).length || 'none' }}
              <span v-if="!d.serve_static" class="text-xs text-faint ml-1">(static off)</span>
            </td>
            <td class="px-4 py-3 text-right">
              <Button variant="secondary" size="sm" @click="openEdit(d)">Edit</Button>
            </td>
          </TableRow>
        </tbody>
      </Table>

      <!-- App placement -->
      <SectionHeader title="App Placement" class="mt-8">
        <template #actions>
          <Button variant="secondary" size="sm" :disabled="savingMounts" @click="saveMounts">
            {{ savingMounts ? 'Saving...' : 'Save Placement' }}
          </Button>
        </template>
      </SectionHeader>
      <p class="text-sm text-muted mb-3">
        Where applications mount on the primary domain
        ({{ auth.hostname }}). Fixed mounts cannot move.
      </p>
      <Table>
        <TableHead>
          <Th>Role</Th>
          <Th>App</Th>
          <Th class="w-1/3">Path</Th>
        </TableHead>
        <tbody>
          <TableRow v-for="m in mounts" :key="m.role">
            <td class="px-4 py-3 text-sm font-medium">
              {{ m.role }}
              <Badge v-if="!m.enabled" variant="default" class="ml-2">not installed</Badge>
            </td>
            <td class="px-4 py-3 text-sm text-muted">{{ m.app || '-' }}</td>
            <td class="px-4 py-3">
              <Input
                size="sm"
                v-if="!m.fixed && m.enabled"
                v-model="mountPaths[m.role]"
                class="font-mono text-xs"
                :aria-label="`Mount path for ${m.role}`"
              />
              <span v-else class="font-mono text-xs text-muted">{{ m.path }}<span v-if="m.fixed" class="text-faint ml-1">(fixed)</span></span>
            </td>
          </TableRow>
        </tbody>
      </Table>
    </AsyncState>

    <!-- Domain editor -->
    <Sheet v-model="sheetOpen" :title="editing ? `Configure ${editing.domain}` : 'Configure domain'">
      <template v-if="editing?.customized" #danger>
        <Button variant="destructive" class="w-full" @click="resetOpen = true">Reset to Defaults</Button>
      </template>
      <div class="space-y-5">
        <Field label="HSTS" for="fHsts">
          <Select id="fHsts" v-model="fHsts">
            <option value="on">On - browsers require HTTPS</option>
            <option value="preload">Preload - HSTS with preload flag</option>
            <option value="off">Off</option>
          </Select>
        </Field>

        <div class="flex items-center gap-2">
          <Checkbox id="fServeStatic" v-model="fServeStatic" />
          <label for="fServeStatic" class="text-sm">Serve static files</label>
        </div>

        <div>
          <div class="flex items-center justify-between mb-2">
            <span class="text-sm font-medium">Path rules</span>
            <Button variant="secondary" size="sm" @click="addRule"><Plus class="size-3.5" />Add rule</Button>
          </div>
          <p class="text-xs text-muted mb-3">
            Proxy a path to a local app, redirect it, or serve another
            directory. A rule at / replaces static serving at the root.
          </p>

          <div v-for="(rule, i) in fRules" :key="i" class="rounded-lg border border-border p-3 mb-3 space-y-3">
            <div class="flex items-center gap-2">
              <Select v-model="rule.kind" class="w-32" :aria-label="`Rule ${i + 1} kind`">
                <option value="proxy">Proxy</option>
                <option value="redirect">Redirect</option>
                <option value="alias">Alias</option>
              </Select>
              <Input v-model="rule.path" placeholder="/path" class="font-mono text-xs flex-1" :aria-label="`Rule ${i + 1} path`" />
              <Button variant="secondary" size="icon" :aria-label="`Remove rule ${i + 1}`" @click="removeRule(i)">
                <Trash2 class="size-3.5" />
              </Button>
            </div>
            <Input
              v-model="rule.target"
              class="font-mono text-xs"
              :placeholder="rule.kind === 'proxy' ? 'http://127.0.0.1:8080' : rule.kind === 'redirect' ? 'https://elsewhere.example/' : '/home/user-data/www/other'"
              :aria-label="`Rule ${i + 1} target`"
            />
            <div v-if="rule.kind === 'proxy'" class="grid grid-cols-2 gap-2 text-sm">
              <label class="flex items-center gap-2"><Checkbox v-model="rule.pass_host_header" />Pass Host header</label>
              <label class="flex items-center gap-2"><Checkbox v-model="rule.web_sockets" />WebSockets</label>
              <label class="flex items-center gap-2"><Checkbox v-model="rule.no_proxy_redirect" />No redirect rewrite</label>
              <label class="flex items-center gap-2"><Checkbox v-model="rule.frame_same_origin" />Allow same-origin frames</label>
            </div>
          </div>
        </div>
      </div>

      <template #footer>
        <div class="flex gap-2 justify-end">
          <Button variant="secondary" @click="sheetOpen = false">Cancel</Button>
          <Button :disabled="saving" @click="save">
            {{ saving ? 'Saving...' : 'Save Configuration' }}
          </Button>
        </div>
      </template>
    </Sheet>

    <!-- Reset confirm -->
    <Dialog
      v-model="resetOpen"
      title="Reset domain to defaults?"
      :description="`${editing?.domain} will lose its custom web configuration and return to default behavior.`"
    >
      <template #actions>
        <Button variant="secondary" @click="resetOpen = false">Cancel</Button>
        <Button variant="destructive" :disabled="saving" @click="confirmReset">
          {{ saving ? 'Resetting...' : 'Reset' }}
        </Button>
      </template>
    </Dialog>
</template>
