<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { toast } from 'vue-sonner'
import { UserPlus } from 'lucide-vue-next'
import AsyncState from '@/components/ui/AsyncState.vue'
import Button from '@/components/ui/Button.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import Field from '@/components/ui/Field.vue'
import Checkbox from '@/components/ui/Checkbox.vue'
import Input from '@/components/ui/Input.vue'
import Table from '@/components/ui/Table.vue'
import TableRow from '@/components/ui/TableRow.vue'
import Skeleton from '@/components/ui/Skeleton.vue'
import EmptyState from '@/components/ui/EmptyState.vue'
import Badge from '@/components/ui/Badge.vue'
import TableHead from '@/components/ui/TableHead.vue'
import Th from '@/components/ui/Th.vue'
import Sheet from '@/components/ui/Sheet.vue'
import Dialog from '@/components/ui/Dialog.vue'
import { api, ApiError } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import type {
  CreateUserRequest,
  SetPasswordRequest,
  UpdateUserRequest,
  User,
  UsersResponse,
} from '@/api/types.gen'

const auth = useAuthStore()

const users = ref<User[]>([])
const loading = ref(true)
const loadError = ref(false)
const search = ref('')
const sheetOpen = ref(false)
const deleteOpen = ref(false)
const saving = ref(false)
const editingUser = ref<User | null>(null)

// Admin reset on an encryption-at-rest account: the server answers 409
// until the reset is explicitly acknowledged, because it cannot re-wrap
// the user's mail key without their old password.
const encryptionAckOpen = ref(false)
const encryptionAckMessage = ref('')

const fEmail = ref('')
const fPassword = ref('')
const fAdmin = ref(false)
const fQuota = ref('0')

const filteredUsers = computed(() =>
  users.value.filter(u => u.email.toLowerCase().includes(search.value.toLowerCase())),
)

/** Parse human quota input ("10G", "500M", "0") to bytes; null = invalid. */
function parseQuota(input: string): number | null {
  const m = input.trim().toUpperCase().match(/^(\d+(?:\.\d+)?)\s*([KMGT]?)B?$/)
  if (!m) return null
  const units: Record<string, number> = { '': 1, K: 1024, M: 1024 ** 2, G: 1024 ** 3, T: 1024 ** 4 }
  return Math.round(Number(m[1]) * units[m[2]])
}

function formatQuota(bytes: number): string {
  if (bytes === 0) return 'unlimited'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let v = bytes
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${Number.isInteger(v) ? v : v.toFixed(1)} ${units[i]}`
}

/** Quota back into the form's shorthand ("10G"), for editing. */
function quotaInputValue(bytes: number): string {
  if (bytes === 0) return '0'
  for (const [suffix, size] of [['T', 1024 ** 4], ['G', 1024 ** 3], ['M', 1024 ** 2], ['K', 1024]] as const) {
    if (bytes % size === 0) return `${bytes / size}${suffix}`
  }
  return String(bytes)
}

async function load(): Promise<void> {
  loading.value = true
  loadError.value = false
  try {
    const resp = await api.get<UsersResponse>('/api/users')
    users.value = resp.users ?? []
  } catch {
    loadError.value = true
    toast.error('Failed to load users.')
  } finally {
    loading.value = false
  }
}

function generatePassword(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
  const values = crypto.getRandomValues(new Uint32Array(12))
  return Array.from(values, v => chars[v % chars.length]).join('')
}

function openAdd(): void {
  editingUser.value = null
  fEmail.value = ''
  fPassword.value = generatePassword()
  fAdmin.value = false
  fQuota.value = '0'
  sheetOpen.value = true
}

function openEdit(user: User): void {
  editingUser.value = user
  fEmail.value = user.email
  fPassword.value = ''
  fAdmin.value = user.role === 'admin'
  fQuota.value = quotaInputValue(user.quota_bytes)
  sheetOpen.value = true
}

function toastApiError(e: unknown, fallback: string): void {
  toast.error(e instanceof ApiError ? e.message : fallback)
}

async function setPassword(email: string, acknowledge: boolean): Promise<boolean> {
  const req: SetPasswordRequest = { password: fPassword.value }
  if (acknowledge) req.acknowledge_encryption = true
  try {
    await api.put(`/api/users/${encodeURIComponent(email)}/password`, req)
    return true
  } catch (e) {
    if (e instanceof ApiError && e.status === 409 && !acknowledge) {
      encryptionAckMessage.value = e.message
      encryptionAckOpen.value = true
      return false
    }
    toastApiError(e, 'Failed to set password.')
    return false
  }
}

async function confirmEncryptionAck(): Promise<void> {
  if (!editingUser.value) return
  saving.value = true
  try {
    if (await setPassword(editingUser.value.email, true)) {
      encryptionAckOpen.value = false
      toast.success('Password reset. The user must re-link with a recovery code or passkey to read encrypted mail.')
      sheetOpen.value = false
      await load()
    }
  } finally {
    saving.value = false
  }
}

async function save(): Promise<void> {
  if (saving.value) return
  const quotaBytes = parseQuota(fQuota.value)
  if (quotaBytes === null) {
    toast.error('Invalid quota. Use a number with an optional K, M, G or T suffix.')
    return
  }
  saving.value = true
  try {
    if (!editingUser.value) {
      const req: CreateUserRequest = {
        email: fEmail.value.trim(),
        password: fPassword.value,
        role: fAdmin.value ? 'admin' : 'user',
        quota_bytes: quotaBytes,
      }
      try {
        await api.post('/api/users', req)
        toast.success('User added.')
        sheetOpen.value = false
        await load()
      } catch (e) {
        toastApiError(e, 'Failed to add user.')
      }
      return
    }

    const user = editingUser.value
    const wasAdmin = user.role === 'admin'
    if (!fAdmin.value && wasAdmin && user.email === auth.email) {
      toast.error('You cannot remove admin from yourself.')
      return
    }

    // Role and quota travel in one PATCH; the password has its own
    // endpoint because of the encryption acknowledgement flow.
    const patch: UpdateUserRequest = {}
    if (fAdmin.value !== wasAdmin) patch.role = fAdmin.value ? 'admin' : 'user'
    if (quotaBytes !== user.quota_bytes) patch.quota_bytes = quotaBytes

    if (Object.keys(patch).length > 0) {
      try {
        await api.patch(`/api/users/${encodeURIComponent(user.email)}`, patch)
      } catch (e) {
        toastApiError(e, 'Failed to update user.')
        return
      }
    }
    if (fPassword.value) {
      if (!(await setPassword(user.email, false))) return
    }
    if (Object.keys(patch).length === 0 && !fPassword.value) {
      toast.success('No changes.')
      sheetOpen.value = false
      return
    }
    toast.success('User updated.')
    sheetOpen.value = false
    await load()
  } finally {
    saving.value = false
  }
}

// System mail (postmaster@, abuse@, root@) is routed automatically to
// the oldest administrator; archiving an admin makes it re-derive, so
// the confirm dialog says where that mail goes next.
const archiveDescription = computed(() => {
  const base = `${editingUser.value?.email} will lose all access. Their mailbox stays on disk.`
  if (editingUser.value?.role !== 'admin') return base
  return base + ' Any system mail (postmaster, abuse, root) routed to this administrator will automatically re-route to the oldest remaining administrator.'
})

async function confirmDelete(): Promise<void> {
  if (!editingUser.value) return
  if (editingUser.value.email === auth.email) {
    toast.error('You cannot archive yourself.')
    deleteOpen.value = false
    return
  }
  saving.value = true
  try {
    await api.del(`/api/users/${encodeURIComponent(editingUser.value.email)}`)
    toast.success('User archived.')
    deleteOpen.value = false
    sheetOpen.value = false
    await load()
  } catch (e) {
    toastApiError(e, 'Failed to archive user.')
  } finally {
    saving.value = false
  }
}

onMounted(load)
</script>

<template>
    <PageHeader title="Users" description="Add or remove accounts that can send and receive mail on this box.">
      <template #actions>
        <Button size="sm" @click="openAdd"><UserPlus class="size-3.5" />Add User</Button>
      </template>
    </PageHeader>

    <div class="mb-4 max-w-sm">
      <Input v-model="search" placeholder="Search users..." aria-label="Search users" />
    </div>

    <AsyncState :loading="loading" :error="loadError" :empty="users.length === 0" error-title="Could not load users" @retry="load">
      <template #loading>
        <Table>
          <TableHead>
            <Th class="w-full">Email</Th>
            <Th class="whitespace-nowrap">Role</Th>
            <Th class="whitespace-nowrap">Quota</Th>
            <Th />
          </TableHead>
          <tbody>
            <TableRow v-for="i in 2" :key="i">
              <td class="px-4 py-3"><Skeleton class="h-4 w-48" /></td>
              <td class="px-4 py-3"><Skeleton class="h-4 w-12" /></td>
              <td class="px-4 py-3"><Skeleton class="h-4 w-18" /></td>
              <td class="px-4 py-3"><Skeleton class="h-4 w-8"  /></td>
            </TableRow>
          </tbody>
        </Table>
      </template>

      <template #empty>
        <EmptyState bordered title="No mail users" description="Create your first account to get started.">
          <template #icon><UserPlus /></template>
          <template #action><Button @click="openAdd">Add User</Button></template>
        </EmptyState>
      </template>

      <Table>
        <TableHead>
          <Th class="w-full">Email</Th>
          <Th class="whitespace-nowrap">Role</Th>
          <Th class="whitespace-nowrap">Quota</Th>
          <Th />
        </TableHead>
        <tbody>
          <TableRow v-for="user in filteredUsers" :key="user.email">
            <td class="px-4 py-3 font-medium">{{ user.email }}</td>
            <td class="px-4 py-3"><Badge v-if="user.role === 'admin'">admin</Badge></td>
            <td class="px-4 py-3 text-sm text-muted">{{ formatQuota(user.quota_bytes) }}</td>
            <td class="px-4 py-3 text-right">
              <Button variant="secondary" size="sm" @click.stop="openEdit(user)">Edit</Button>
            </td>
          </TableRow>
          <tr v-if="filteredUsers.length === 0">
            <td colspan="4" class="px-4 py-8 text-center text-sm text-muted">No users match your search.</td>
          </tr>
        </tbody>
      </Table>
    </AsyncState>

    <Sheet v-model="sheetOpen" :title="editingUser ? 'Edit User' : 'Add User'">
      <template v-if="editingUser" #danger>
        <Button variant="destructive" class="w-full" @click="deleteOpen = true">Archive User</Button>
      </template>
      <div class="space-y-5">
        <Field label="Email" for="fEmail">
          <Input
            v-if="!editingUser"
            id="fEmail"
            v-model="fEmail"
            type="email"
            autocomplete="off"
            placeholder="user@example.com"
          />
          <p v-else class="text-sm text-muted py-2">{{ editingUser.email }}</p>
        </Field>

        <Field :label="editingUser ? 'New Password' : 'Password'" for="fPassword">
          <div class="flex gap-2">
            <Input
              id="fPassword"
              v-model="fPassword"
              type="text"
              :placeholder="editingUser ? 'Leave blank to keep current' : ''"
              autocomplete="off"
            />
            <Button variant="primary" type="button" @click="fPassword = generatePassword()">
              Generate
            </Button>
          </div>
        </Field>

        <Field label="Quota" for="fQuota">
          <Input id="fQuota" v-model="fQuota" placeholder="0 = unlimited (e.g. 10G, 500M)" />
          <p class="text-xs text-muted mt-1">Use G or M suffix. 0 = unlimited.</p>
        </Field>

        <div class="flex items-center gap-2">
          <Checkbox id="fAdmin" v-model="fAdmin" />
          <label for="fAdmin" class="text-sm">Administrator</label>
        </div>

      </div>

      <template #footer>
        <div class="flex gap-2 justify-end">
          <Button variant="secondary" @click="sheetOpen = false">Cancel</Button>
          <Button :disabled="saving" @click="save">
            {{ saving ? 'Saving...' : editingUser ? 'Save Changes' : 'Add User' }}
          </Button>
        </div>
      </template>
    </Sheet>

    <Dialog
      v-model="deleteOpen"
      title="Archive user?"
      :description="archiveDescription"
    >
      <template #actions>
        <Button variant="secondary" @click="deleteOpen = false">Cancel</Button>
        <Button variant="destructive" :disabled="saving" @click="confirmDelete">
          {{ saving ? 'Archiving...' : 'Archive' }}
        </Button>
      </template>
    </Dialog>

    <Dialog
      v-model="encryptionAckOpen"
      title="Reset password on an encrypted account?"
      :description="encryptionAckMessage"
    >
      <template #actions>
        <Button variant="secondary" @click="encryptionAckOpen = false">Cancel</Button>
        <Button variant="destructive" :disabled="saving" @click="confirmEncryptionAck">
          {{ saving ? 'Resetting...' : 'Reset Anyway' }}
        </Button>
      </template>
    </Dialog>
</template>
