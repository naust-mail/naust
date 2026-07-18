<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { toast } from 'vue-sonner'
import { HardDrive, Settings2, Play, RefreshCw, FileKey } from 'lucide-vue-next'
import AsyncState from '@/components/ui/AsyncState.vue'
import Button from '@/components/ui/Button.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import SectionHeader from '@/components/ui/SectionHeader.vue'
import Field from '@/components/ui/Field.vue'
import Checkbox from '@/components/ui/Checkbox.vue'
import Input from '@/components/ui/Input.vue'
import Select from '@/components/ui/Select.vue'
import Card from '@/components/ui/Card.vue'
import Sheet from '@/components/ui/Sheet.vue'
import Table from '@/components/ui/Table.vue'
import TableHead from '@/components/ui/TableHead.vue'
import Th from '@/components/ui/Th.vue'
import TableRow from '@/components/ui/TableRow.vue'
import Skeleton from '@/components/ui/Skeleton.vue'
import EmptyState from '@/components/ui/EmptyState.vue'
import StatusIcon from '@/components/shared/StatusIcon.vue'
import { api, ApiError, API_BASE } from '@/api/client'
import type {
  BackupConfig,
  BackupRunInfo,
  BackupSnapshot,
  BackupStatusResponse,
  BackupTargetConfig,
} from '@/api/types.gen'

// A backup run can take a while; a relaxed poll is plenty.
const POLL_INTERVAL_MS = 5_000

// A manual run can complete faster than a human perceives as "it did
// something" - hold the button's spinner up for at least this long so
// clicking Back up now always reads as a real, visible action.
const MIN_SPIN_MS = 5_000

type BackupTargetType = 'off' | 'local' | 'rsync' | 's3' | 'b2'

const loading = ref(true)
const loadError = ref(false)
const saving = ref(false)
const configSheetOpen = ref(false)

// Status data
const runs = ref<BackupRunInfo[]>([])
const snapshots = ref<BackupSnapshot[]>([])
const tool = ref('')
const keySavedAt = ref<string | null>(null)
const sshPublicKey = ref('')
const running = ref(false)
const minSpinActive = ref(false)
const showSpinner = computed(() => running.value || minSpinActive.value)
let pollTimer: ReturnType<typeof setInterval> | null = null
let minSpinTimer: ReturnType<typeof setTimeout> | null = null

// Config form state
const targetType = ref<BackupTargetType>('local')
const keepDays = ref('30')
const checkAfterBackup = ref(true)
// rsync (SFTP)
const rsyncUser = ref('')
const rsyncHost = ref('')
const rsyncPort = ref('')
const rsyncPath = ref('')
// s3
const s3Endpoint = ref('')
const s3Region = ref('')
const s3Bucket = ref('')
const s3AccessKey = ref('')
const s3SecretKey = ref('')
// b2
const b2KeyId = ref('')
const b2AppKey = ref('')
const b2Bucket = ref('')

// Set when the stored config already has credentials: the GET response
// redacts them, so an empty field on save means "keep what is stored".
const hasStoredSecret = ref(false)

const enabled = computed(() => targetType.value !== 'off')

function niceSize(bytes: number): string {
  const units = ['bytes', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  while (bytes >= 1000 && i < units.length - 1) {
    bytes /= 1024
    i++
  }
  const rounded = bytes >= 100 ? Math.round(bytes) : Math.round(bytes * 10) / 10
  return `${rounded} ${units[i]}`
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

function isTargetType(v: string): v is BackupTargetType {
  return v === 'off' || v === 'local' || v === 'rsync' || v === 's3' || v === 'b2'
}

function fillForm(cfg: BackupConfig): void {
  const t = cfg.target
  targetType.value = isTargetType(t.type) ? t.type : 'off'
  keepDays.value = String(cfg.keep_within_days)
  checkAfterBackup.value = cfg.check_after_backup
  rsyncUser.value = t.user ?? ''
  rsyncHost.value = t.host ?? ''
  rsyncPort.value = t.port ? String(t.port) : ''
  rsyncPath.value = t.path ?? ''
  s3Endpoint.value = t.endpoint ?? ''
  s3Region.value = t.region ?? ''
  s3Bucket.value = targetType.value === 'b2' ? '' : (t.bucket ?? '')
  s3AccessKey.value = t.access_key ?? ''
  b2KeyId.value = t.key_id ?? ''
  b2Bucket.value = targetType.value === 'b2' ? (t.bucket ?? '') : ''
  // Credentials never come back from GET; a configured s3/b2 target
  // implies they exist server-side.
  s3SecretKey.value = ''
  b2AppKey.value = ''
  hasStoredSecret.value = targetType.value === 's3' || targetType.value === 'b2'
}

function buildConfig(): BackupConfig {
  const target: BackupTargetConfig = { type: targetType.value }
  if (targetType.value === 'rsync') {
    target.user = rsyncUser.value.trim()
    target.host = rsyncHost.value.trim()
    target.path = rsyncPath.value.trim()
    const port = Number(rsyncPort.value)
    if (rsyncPort.value.trim() !== '' && Number.isFinite(port)) target.port = port
  } else if (targetType.value === 's3') {
    target.endpoint = s3Endpoint.value.trim()
    target.region = s3Region.value.trim()
    target.bucket = s3Bucket.value.trim()
    target.access_key = s3AccessKey.value.trim()
    target.secret_key = s3SecretKey.value
  } else if (targetType.value === 'b2') {
    target.bucket = b2Bucket.value.trim()
    target.key_id = b2KeyId.value.trim()
    target.app_key = b2AppKey.value
  }
  return {
    target,
    keep_within_days: Number(keepDays.value) || 0,
    check_after_backup: checkAfterBackup.value,
  }
}

function applyStatus(data: BackupStatusResponse): void {
  runs.value = data.runs ?? []
  snapshots.value = data.snapshots ?? []
  tool.value = data.tool
  keySavedAt.value = data.key_saved_at ?? null
  sshPublicKey.value = data.ssh_public_key ?? ''
  running.value = data.running
  if (!configSheetOpen.value) fillForm(data.config)
}

function startPolling(): void {
  if (pollTimer !== null) return
  pollTimer = setInterval(async () => {
    try {
      const data = await api.get<BackupStatusResponse>('/api/system/backup')
      applyStatus(data)
      if (!data.running) {
        stopPolling()
        const last = runs.value[0]
        if (last?.status === 'error') {
          toast.error('Backup run failed.')
        } else {
          toast.success('Backup run finished.')
        }
      }
    } catch {
      // Keep polling through transient errors.
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
    const data = await api.get<BackupStatusResponse>('/api/system/backup')
    applyStatus(data)
    if (data.running) startPolling()
  } catch {
    loadError.value = true
    toast.error('Failed to load backup status.')
  } finally {
    loading.value = false
  }
}

async function runNow(): Promise<void> {
  if (running.value) return
  running.value = true
  minSpinActive.value = true
  if (minSpinTimer !== null) clearTimeout(minSpinTimer)
  minSpinTimer = setTimeout(() => { minSpinActive.value = false }, MIN_SPIN_MS)
  try {
    await api.post('/api/system/backup/run')
    startPolling()
    toast.info('Backup started.')
  } catch (e) {
    // Report the failure immediately, but let the armed minSpinTimer (not
    // this catch block) be the only thing that clears minSpinActive - the
    // button should still hold its minimum spin time even on failure.
    running.value = false
    toast.error(e instanceof ApiError ? e.message : 'Failed to start backup.')
  }
}

async function save(): Promise<void> {
  if (saving.value) return
  saving.value = true
  try {
    const saved = await api.put<BackupConfig>('/api/system/backup/config', buildConfig())
    fillForm(saved)
    toast.success('Backup configuration saved.')
    configSheetOpen.value = false
    await load()
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : 'Failed to save backup configuration.')
  } finally {
    saving.value = false
  }
}

function downloadRestoreSheet(): void {
  // Served as an attachment, so navigating downloads without leaving
  // the page. The server records key_saved_at on first download; give
  // it a moment, then refresh so the reminder card clears.
  window.location.href = API_BASE + '/api/system/backup/key'
  setTimeout(load, 1_500)
}

function runStatusIcon(run: BackupRunInfo): 'ok' | 'warning' | 'error' {
  if (run.status === 'error') return 'error'
  if (run.warning) return 'warning'
  return 'ok'
}

function runStatusLabel(run: BackupRunInfo): string {
  if (run.status === 'running') return 'Running...'
  if (run.status === 'error') return run.error ?? 'Failed'
  if (run.warning) return `Completed with warning: ${run.warning}`
  return 'Completed'
}

onMounted(load)
onUnmounted(() => {
  stopPolling()
  if (minSpinTimer !== null) clearTimeout(minSpinTimer)
})
</script>

<template>
    <PageHeader title="System Backup" description="Schedule and review backups of your mail, settings, and data.">
      <template #actions>
        <Button v-if="enabled" variant="secondary" size="sm" :disabled="showSpinner" @click="runNow">
          <RefreshCw v-if="showSpinner" class="size-3.5 animate-spin" />
          <Play v-else class="size-3.5" />
          {{ showSpinner ? 'Backing up...' : 'Back up now' }}
        </Button>
        <Button variant="secondary" size="sm" @click="configSheetOpen = true"><Settings2 class="size-3.5" />Configure</Button>
      </template>
    </PageHeader>

    <!-- Restore sheet reminder: passive custody signal, never a gate -->
    <Card v-if="!loading && enabled && !keySavedAt" padding="md" class="mb-6 border-warning-border bg-warning-bg">
      <div class="flex items-start gap-3">
        <FileKey class="size-5 shrink-0 mt-0.5 text-warning" />
        <div>
          <p class="text-sm font-medium text-warning-fg">Save your restore sheet</p>
          <p class="text-sm text-warning-fg mt-1 mb-3">
            Backups are encrypted. Without the key on the restore sheet they cannot
            be restored if this server is lost. Download it and keep it somewhere safe.
          </p>
          <Button variant="secondary" size="sm" @click="downloadRestoreSheet">
            Download restore sheet
          </Button>
        </div>
      </div>
    </Card>

    <!-- Recent runs -->
    <SectionHeader title="Recent Runs" />
    <AsyncState :loading="loading" :error="loadError" :empty="runs.length === 0" error-title="Could not load backup status" @retry="load">
      <template #loading>
        <Table>
          <TableHead>
            <Th>Started</Th>
            <Th>Result</Th>
            <Th class="text-right">Added</Th>
          </TableHead>
          <tbody>
            <TableRow v-for="i in 3" :key="i">
              <td class="px-4 py-3"><Skeleton class="h-4 w-40" /></td>
              <td class="px-4 py-3"><Skeleton class="h-4 w-64" /></td>
              <td class="px-4 py-3"><Skeleton class="h-4 w-16 ml-auto" /></td>
            </TableRow>
          </tbody>
        </Table>
      </template>

      <template #empty>
        <EmptyState
          bordered
          title="No backup runs yet"
          :description="enabled ? 'The first backup will run on the nightly schedule, or start one now.' : 'Backups are turned off. Use Configure to set a backup target.'"
        >
          <template #icon><HardDrive /></template>
        </EmptyState>
      </template>

      <Table>
        <TableHead>
          <Th>Started</Th>
          <Th>Result</Th>
          <Th class="text-right">Added</Th>
        </TableHead>
        <tbody>
          <TableRow v-for="run in runs" :key="run.started_at">
            <td class="px-4 py-3 text-sm whitespace-nowrap">{{ formatDate(run.started_at) }}</td>
            <td class="px-4 py-3 text-sm text-muted">
              <div class="flex items-start gap-2">
                <RefreshCw v-if="run.status === 'running'" class="size-4 mt-0.5 shrink-0 animate-spin text-muted" />
                <StatusIcon v-else :status="runStatusIcon(run)" class="mt-0.5 shrink-0" />
                <span class="break-all">{{ runStatusLabel(run) }}</span>
              </div>
            </td>
            <td class="px-4 py-3 text-sm text-right tabular-nums text-muted">
              <span v-if="run.data_added">+{{ niceSize(run.data_added) }}</span>
              <span v-else class="text-faint">-</span>
            </td>
          </TableRow>
        </tbody>
      </Table>
    </AsyncState>

    <!-- Snapshots -->
    <template v-if="!loading && !loadError && snapshots.length > 0">
      <SectionHeader title="Restore Points" class="mt-8" />
      <Table>
        <TableHead>
          <Th>Date</Th>
          <Th>Snapshot</Th>
          <Th class="text-right">Size</Th>
          <Th class="text-right">Files</Th>
        </TableHead>
        <tbody>
          <TableRow v-for="snap in snapshots" :key="snap.id">
            <td class="px-4 py-3 text-sm whitespace-nowrap">{{ formatDate(snap.time) }}</td>
            <td class="px-4 py-3 text-sm">
              <span class="font-mono text-muted">{{ snap.id }}</span>
              <span v-if="snap.full === false" class="text-xs text-faint ml-2">increment</span>
            </td>
            <td class="px-4 py-3 text-sm text-right tabular-nums text-muted">
              {{ snap.size ? niceSize(snap.size) : '-' }}
            </td>
            <td class="px-4 py-3 text-sm text-right tabular-nums text-muted">
              {{ snap.file_count ? snap.file_count.toLocaleString() : '-' }}
            </td>
          </TableRow>
        </tbody>
      </Table>
      <p class="text-xs text-muted mt-2 text-right px-1">Backup tool: {{ tool }}</p>
    </template>

    <!-- Restore sheet re-download, once custody is recorded -->
    <Card v-if="!loading && enabled && keySavedAt" padding="sm" class="mt-6 flex items-center justify-between gap-3">
      <p class="text-xs text-muted">Restore sheet first saved {{ formatDate(keySavedAt) }}.</p>
      <Button variant="secondary" size="sm" @click="downloadRestoreSheet">Download again</Button>
    </Card>

    <!-- Backup configuration sheet -->
    <Sheet v-model="configSheetOpen" title="Backup Configuration">
      <div class="space-y-5">
        <Field label="Backup target" for="targetType">
          <Select id="targetType" v-model="targetType">
            <option value="off">Disabled</option>
            <option value="local">Local storage (on this machine)</option>
            <option value="rsync">SFTP to remote server</option>
            <option value="s3">Amazon S3 (or compatible)</option>
            <option value="b2">Backblaze B2</option>
          </Select>
        </Field>

        <!-- Rsync (SFTP) fields -->
        <template v-if="targetType === 'rsync'">
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <Field label="Remote user" for="rsyncUser">
              <Input id="rsyncUser" v-model="rsyncUser" placeholder="backup-user" />
            </Field>
            <Field label="Remote host" for="rsyncHost">
              <Input id="rsyncHost" v-model="rsyncHost" placeholder="backup.example.com" />
            </Field>
            <Field label="Remote path" for="rsyncPath">
              <Input id="rsyncPath" v-model="rsyncPath" placeholder="backups/naust" />
            </Field>
            <Field label="Port (optional)" for="rsyncPort">
              <Input id="rsyncPort" v-model="rsyncPort" type="number" placeholder="22" />
            </Field>
          </div>
          <div v-if="sshPublicKey" class="space-y-1">
            <p class="text-sm text-muted">
              Add this public key to the remote user's <code>~/.ssh/authorized_keys</code> so the box can connect:
            </p>
            <pre class="text-xs font-mono bg-bg rounded p-2 overflow-x-auto select-all">{{ sshPublicKey }}</pre>
          </div>
        </template>

        <!-- S3 fields -->
        <template v-if="targetType === 's3'">
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <Field label="Endpoint" for="s3Endpoint">
              <Input id="s3Endpoint" v-model="s3Endpoint" placeholder="s3.amazonaws.com" />
            </Field>
            <Field label="Region" for="s3Region">
              <Input id="s3Region" v-model="s3Region" placeholder="us-east-1" />
            </Field>
            <Field label="Bucket" for="s3Bucket">
              <Input id="s3Bucket" v-model="s3Bucket" placeholder="my-naust-backups" />
            </Field>
            <Field label="Access key ID" for="s3AccessKey">
              <Input id="s3AccessKey" v-model="s3AccessKey" autocomplete="off" placeholder="AKIA..." />
            </Field>
            <Field label="Secret access key" for="s3SecretKey" class="sm:col-span-2">
              <Input
                id="s3SecretKey"
                v-model="s3SecretKey"
                type="password"
                autocomplete="off"
                :placeholder="hasStoredSecret ? 'Leave blank to keep the stored key' : 'wJalEXAMPLExFE...'"
              />
            </Field>
          </div>
        </template>

        <!-- B2 fields -->
        <template v-if="targetType === 'b2'">
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <Field label="Application key ID" for="b2KeyId">
              <Input id="b2KeyId" v-model="b2KeyId" autocomplete="off" placeholder="4a1b2c3d4e5f" />
            </Field>
            <Field label="Application key" for="b2AppKey">
              <Input
                id="b2AppKey"
                v-model="b2AppKey"
                type="password"
                autocomplete="off"
                :placeholder="hasStoredSecret ? 'Leave blank to keep the stored key' : 'K004...'"
              />
            </Field>
            <Field label="Bucket name" for="b2Bucket">
              <Input id="b2Bucket" v-model="b2Bucket" placeholder="my-naust-bucket" />
            </Field>
          </div>
        </template>

        <!-- Retention (shown for all enabled targets) -->
        <Field v-if="enabled" label="Keep backups for (days)" for="keepDays">
          <Input id="keepDays" v-model="keepDays" type="number" class="max-w-xs" placeholder="30" />
          <p class="text-xs text-muted mt-1">Restore points within this window are kept; older ones are pruned after each backup.</p>
        </Field>

        <div v-if="enabled" class="flex items-start gap-3">
          <Checkbox id="checkAfterBackup" v-model="checkAfterBackup" class="mt-0.5" />
          <div>
            <label for="checkAfterBackup" class="text-sm font-medium cursor-pointer">Verify backup integrity after each run</label>
            <p class="text-xs text-muted mt-0.5">Checks the repository for errors after each backup. Problems show up as run warnings and in System Status.</p>
          </div>
        </div>
      </div>

      <template #footer>
        <div class="flex gap-2 justify-end">
          <Button variant="secondary" @click="configSheetOpen = false">Cancel</Button>
          <Button :disabled="saving" @click="save">
            {{ saving ? 'Saving...' : 'Save Configuration' }}
          </Button>
        </div>
      </template>
    </Sheet>
</template>
