<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { toast } from 'vue-sonner'
import { HardDrive } from 'lucide-vue-next'
import AppLayout from '@/components/layout/AppLayout.vue'
import Button from '@/components/ui/Button.vue'
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
import Well from '@/components/ui/Well.vue'
import { useApi } from '@/composables/useApi'
import { useConfigStore } from '@/stores/config'
import type { BackupEntry, BackupStatus, BackupConfig } from '@/types'

const api = useApi()
const config = useConfigStore()

type BackupTargetType = 'off' | 'local' | 'rsync' | 's3' | 'b2'

const loadingStatus = ref(true)
const loadingConfig = ref(true)
const saving = ref(false)
const configSheetOpen = ref(false)

// Status data
const backups = ref<BackupEntry[]>([])
const unmatchedSize = ref(0)
const statusError = ref<string | null>(null)
const backupsOff = ref(false)

// Config read-only info
const fileTargetDir = ref('')
const encPwFile = ref('')
const sshPubKey = ref('')

// Config form state
const targetType = ref<BackupTargetType>('local')
const minAge = ref('3')
// rsync
const rsyncUser = ref('')
const rsyncHost = ref('')
const rsyncPath = ref('')
// s3
const s3Region = ref('')
const s3Host = ref('')
const s3Path = ref('')
const s3AccessKey = ref('')
const s3SecretKey = ref('')
// b2
const b2AppKeyId = ref('')
const b2AppKey = ref('')
const b2Bucket = ref('')

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

function urlSplit(url: string): { scheme: string; user: string; host: string; path: string } {
  const schemeSep = url.indexOf('://')
  const scheme = schemeSep >= 0 ? url.substring(0, schemeSep) : ''
  const rest = schemeSep >= 0 ? url.substring(schemeSep + 3) : url
  const atIdx = rest.indexOf('@')
  const user = atIdx >= 0 ? rest.substring(0, atIdx) : ''
  const afterAt = atIdx >= 0 ? rest.substring(atIdx + 1) : rest
  const slashIdx = afterAt.indexOf('/')
  const host = slashIdx >= 0 ? afterAt.substring(0, slashIdx) : afterAt
  const path = slashIdx >= 0 ? afterAt.substring(slashIdx + 1) : ''
  return { scheme, user, host, path }
}

function parseConfig(cfg: BackupConfig): void {
  fileTargetDir.value = cfg.file_target_directory ?? ''
  encPwFile.value = cfg.enc_pw_file ?? ''
  sshPubKey.value = cfg.ssh_pub_key ?? ''
  minAge.value = String(cfg.min_age_in_days ?? 3)

  const target = cfg.target ?? 'off'
  if (target === 'off') {
    targetType.value = 'off'
  } else if (target.startsWith('file://') || target === 'local') {
    targetType.value = 'local'
  } else if (target.startsWith('rsync://')) {
    targetType.value = 'rsync'
    const parts = urlSplit(target)
    rsyncUser.value = parts.user
    rsyncHost.value = parts.host
    rsyncPath.value = parts.path
  } else if (target.startsWith('s3://')) {
    targetType.value = 's3'
    const parts = urlSplit(target)
    // user part is the region name
    s3Region.value = parts.user
    s3Host.value = parts.host
    s3Path.value = parts.path
  } else if (target.startsWith('b2://')) {
    targetType.value = 'b2'
    const raw = target.substring(5)
    const colonIdx = raw.indexOf(':')
    b2AppKeyId.value = colonIdx >= 0 ? raw.substring(0, colonIdx) : raw
    const rest = colonIdx >= 0 ? raw.substring(colonIdx + 1) : ''
    const atIdx = rest.indexOf('@')
    b2AppKey.value = atIdx >= 0 ? decodeURIComponent(rest.substring(0, atIdx)) : rest
    b2Bucket.value = atIdx >= 0 ? rest.substring(atIdx + 1) : ''
  }
}

function buildTarget(): { target: string; target_user: string; target_pass: string } {
  switch (targetType.value) {
    case 'off':
      return { target: 'off', target_user: '', target_pass: '' }
    case 'local':
      return { target: 'local', target_user: '', target_pass: '' }
    case 'rsync':
      return {
        target: `rsync://${rsyncUser.value}@${rsyncHost.value}/${rsyncPath.value}`,
        target_user: '',
        target_pass: '',
      }
    case 's3':
      return {
        target: `s3://${s3Region.value ? s3Region.value + '@' : ''}${s3Host.value}/${s3Path.value}`,
        target_user: s3AccessKey.value,
        target_pass: s3SecretKey.value,
      }
    case 'b2':
      return {
        target: `b2://${b2AppKeyId.value}:${encodeURIComponent(b2AppKey.value)}@${b2Bucket.value}`,
        target_user: '',
        target_pass: '',
      }
  }
}

async function loadStatus(): Promise<void> {
  loadingStatus.value = true
  try {
    const res = await api.get('/admin/system/backup/status')
    const data: BackupStatus = await res.json()
    if (data.error) {
      statusError.value = data.error
    } else if (!data.backups) {
      backupsOff.value = true
    } else {
      backups.value = data.backups
      unmatchedSize.value = data.unmatched_file_size ?? 0
    }
  } catch {
    toast.error('Failed to load backup status.')
  } finally {
    loadingStatus.value = false
  }
}

async function loadConfig(): Promise<void> {
  loadingConfig.value = true
  try {
    const res = await api.get('/admin/system/backup/config')
    const data: BackupConfig = await res.json()
    parseConfig(data)
  } catch {
    toast.error('Failed to load backup configuration.')
  } finally {
    loadingConfig.value = false
  }
}

async function save(): Promise<void> {
  if (saving.value) return
  saving.value = true
  try {
    const { target, target_user, target_pass } = buildTarget()
    const res = await api.post('/admin/system/backup/config', {
      target,
      target_user,
      target_pass,
      min_age: minAge.value,
    })
    const text = await res.text()
    if (!res.ok) {
      toast.error(text)
      return
    }
    toast.success(text || 'Backup configuration saved.')
    configSheetOpen.value = false
    // Reload status after config change
    backupsOff.value = false
    backups.value = []
    statusError.value = null
    await loadStatus()
  } finally {
    saving.value = false
  }
}

const totalSize = computed(() => {
  const total = backups.value.reduce((sum, b) => sum + b.size, 0) + unmatchedSize.value
  return total > 0 ? niceSize(total) : null
})

const s3HostOptions = computed(() =>
  config.backupS3Hosts.map(([region, host]) => ({ region, host }))
)

onMounted(() => Promise.all([loadStatus(), loadConfig()]))
</script>

<template>
  <AppLayout>
    <div class="flex items-center justify-between mb-6">
      <h1 class="text-2xl font-semibold">System Backup</h1>
      <Button variant="secondary" @click="configSheetOpen = true">Configure</Button>
    </div>

    <!-- Backup history -->
    <h2 class="text-base font-semibold mb-3">Backup History</h2>

    <template v-if="loadingStatus">
      <Table>
        <TableHead>
          <Th>Date</Th>
          <Th>Age</Th>
          <Th>Type</Th>
          <Th class="text-right">Size</Th>
          <Th>Expires</Th>
        </TableHead>
        <tbody>
          <TableRow v-for="i in 4" :key="i">
            <td class="px-4 py-3"><Skeleton class="h-4 w-40" /></td>
            <td class="px-4 py-3"><Skeleton class="h-4 w-24" /></td>
            <td class="px-4 py-3"><Skeleton class="h-4 w-20" /></td>
            <td class="px-4 py-3"><Skeleton class="h-4 w-16 ml-auto" /></td>
            <td class="px-4 py-3"><Skeleton class="h-4 w-28" /></td>
          </TableRow>
        </tbody>
      </Table>
    </template>

    <template v-else-if="statusError">
      <Card class="p-5 border-red-200 dark:border-red-800">
        <p class="text-sm text-red-600 dark:text-red-400">{{ statusError }}</p>
      </Card>
    </template>

    <template v-else-if="backupsOff || backups.length === 0">
      <EmptyState
        title="No backups"
        :description="backupsOff ? 'Backups are turned off. Use Configure to set a backup target.' : 'No backups have been made yet.'"
      >
        <template #icon><HardDrive /></template>
      </EmptyState>
    </template>

    <template v-else>
      <Table>
        <TableHead>
          <Th>Date</Th>
          <Th>Age</Th>
          <Th>Type</Th>
          <Th class="text-right">Size</Th>
          <Th>Expires</Th>
        </TableHead>
        <tbody>
          <TableRow v-for="b in backups" :key="b.date">
            <td class="px-4 py-3 text-sm font-mono">{{ b.date_str }}</td>
            <td class="px-4 py-3 text-sm text-gray-500">{{ b.date_delta }} ago</td>
            <td class="px-4 py-3 text-sm">{{ b.full ? 'full' : 'increment' }}</td>
            <td class="px-4 py-3 text-sm text-right tabular-nums">{{ niceSize(b.size) }}</td>
            <td class="px-4 py-3 text-sm text-gray-500">{{ b.deleted_in ?? 'unknown' }}</td>
          </TableRow>
        </tbody>
      </Table>
      <p v-if="totalSize" class="text-xs text-gray-500 mt-2 text-right px-1">
        Total storage: {{ totalSize }}
      </p>
    </template>

    <!-- Backup configuration sheet -->
    <Sheet v-model="configSheetOpen" title="Backup Configuration">
      <template v-if="loadingConfig">
        <div class="space-y-4">
          <Skeleton class="h-4 w-32" />
          <Skeleton class="h-9 w-full" />
          <Skeleton class="h-9 w-full" />
        </div>
      </template>
      <div v-else class="space-y-5">
        <div>
          <label for="targetType" class="block text-sm font-medium mb-1.5">Backup target</label>
          <Select id="targetType" v-model="targetType">
            <option value="off">Disabled</option>
            <option value="local">Local storage (on this machine)</option>
            <option value="rsync">Rsync to remote server</option>
            <option value="s3">Amazon S3 (or compatible)</option>
            <option value="b2">Backblaze B2</option>
          </Select>
        </div>

        <!-- Local info -->
        <template v-if="targetType === 'local'">
          <Well class="text-sm space-y-1">
            <p class="text-gray-500">Storage location: <span class="font-mono text-gray-700 dark:text-gray-300">{{ fileTargetDir }}</span></p>
            <p class="text-gray-500">Encryption key: <span class="font-mono text-gray-700 dark:text-gray-300">{{ encPwFile }}</span></p>
          </Well>
        </template>

        <!-- Rsync fields -->
        <template v-if="targetType === 'rsync'">
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label for="rsyncUser" class="block text-sm font-medium mb-1.5">Remote user</label>
              <Input id="rsyncUser" v-model="rsyncUser" placeholder="backup-user" />
            </div>
            <div>
              <label for="rsyncHost" class="block text-sm font-medium mb-1.5">Remote host</label>
              <Input id="rsyncHost" v-model="rsyncHost" placeholder="backup.example.com" />
            </div>
            <div class="sm:col-span-2">
              <label for="rsyncPath" class="block text-sm font-medium mb-1.5">Remote path</label>
              <Input id="rsyncPath" v-model="rsyncPath" placeholder="backups/mailinabox" />
            </div>
          </div>
          <Well v-if="sshPubKey">
            <p class="text-xs font-medium text-gray-500 mb-1.5">SSH public key (add to remote authorized_keys)</p>
            <pre class="text-xs font-mono text-gray-700 dark:text-gray-300 whitespace-pre-wrap break-all select-all">{{ sshPubKey }}</pre>
          </Well>
        </template>

        <!-- S3 fields -->
        <template v-if="targetType === 's3'">
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label for="s3Host" class="block text-sm font-medium mb-1.5">S3 endpoint / host</label>
              <Select v-if="s3HostOptions.length" id="s3Host" v-model="s3Host">
                <option v-for="o in s3HostOptions" :key="o.host" :value="o.host">{{ o.host }}</option>
                <option value="">Other...</option>
              </Select>
              <Input v-else id="s3Host" v-model="s3Host" placeholder="s3.amazonaws.com" />
            </div>
            <div>
              <label for="s3Region" class="block text-sm font-medium mb-1.5">Region name</label>
              <Input id="s3Region" v-model="s3Region" placeholder="us-east-1" />
            </div>
            <div>
              <label for="s3Path" class="block text-sm font-medium mb-1.5">Bucket path</label>
              <Input id="s3Path" v-model="s3Path" placeholder="my-bucket/mailinabox" />
            </div>
            <div>
              <label for="s3AccessKey" class="block text-sm font-medium mb-1.5">Access key ID</label>
              <Input id="s3AccessKey" v-model="s3AccessKey" autocomplete="off" placeholder="AKIA..." />
            </div>
            <div class="sm:col-span-2">
              <label for="s3SecretKey" class="block text-sm font-medium mb-1.5">Secret access key</label>
              <Input id="s3SecretKey" v-model="s3SecretKey" type="password" autocomplete="off" placeholder="wJalEXAMPLExFE..." />
            </div>
          </div>
        </template>

        <!-- B2 fields -->
        <template v-if="targetType === 'b2'">
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label for="b2AppKeyId" class="block text-sm font-medium mb-1.5">Application key ID</label>
              <Input id="b2AppKeyId" v-model="b2AppKeyId" autocomplete="off" placeholder="4a1b2c3d4e5f6g7h8i9j0k" />
            </div>
            <div>
              <label for="b2AppKey" class="block text-sm font-medium mb-1.5">Application key</label>
              <Input id="b2AppKey" v-model="b2AppKey" type="password" autocomplete="off" placeholder="b2_app_key_..." />
            </div>
            <div>
              <label for="b2Bucket" class="block text-sm font-medium mb-1.5">Bucket name</label>
              <Input id="b2Bucket" v-model="b2Bucket" placeholder="my-mailinabox-bucket" />
            </div>
          </div>
        </template>

        <!-- Min age (shown for all enabled targets) -->
        <div v-if="targetType !== 'off'">
          <label for="minAge" class="block text-sm font-medium mb-1.5">Minimum backup age (days)</label>
          <Input id="minAge" v-model="minAge" type="number" class="max-w-xs" placeholder="3" />
          <p class="text-xs text-gray-500 mt-1">Backups are kept for at least this many days before being deleted.</p>
        </div>

        <Button class="w-full" :disabled="saving" @click="save">
          {{ saving ? 'Saving...' : 'Save Configuration' }}
        </Button>
      </div>
    </Sheet>
  </AppLayout>
</template>
