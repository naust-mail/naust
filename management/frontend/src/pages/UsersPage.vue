<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { toast } from 'vue-sonner'
import { UserPlus } from 'lucide-vue-next'
import AppLayout from '@/components/layout/AppLayout.vue'
import Button from '@/components/ui/Button.vue'
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
import { useApi } from '@/composables/useApi'
import { useAuthStore } from '@/stores/auth'
import type { MailUser, MailUserDomain } from '@/types'

const api = useApi()
const auth = useAuthStore()

const users = ref<MailUser[]>([])
const loading = ref(true)
const search = ref('')
const sheetOpen = ref(false)
const deleteOpen = ref(false)
const saving = ref(false)
const editingUser = ref<MailUser | null>(null)

const fEmail = ref('')
const fPassword = ref('')
const fAdmin = ref(false)
const fQuota = ref('0')

const filteredUsers = computed(() =>
  users.value.filter(u => u.email.toLowerCase().includes(search.value.toLowerCase())),
)

async function load(): Promise<void> {
  loading.value = true
  try {
    const res = await api.get('/admin/mail/users?format=json')
    const domains: MailUserDomain[] = await res.json()
    users.value = domains.flatMap(d => d.users).filter(u => u.status === 'active')
  } catch {
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

function openEdit(user: MailUser): void {
  editingUser.value = user
  fEmail.value = user.email
  fPassword.value = ''
  fAdmin.value = user.privileges.includes('admin')
  fQuota.value = user.quota
  sheetOpen.value = true
}

async function apiText(path: string, body: Record<string, string>): Promise<boolean> {
  const res = await api.post(path, body)
  const text = await res.text()
  if (!res.ok) { toast.error(text); return false }
  toast.success(text || 'Done.')
  return true
}

async function save(): Promise<void> {
  if (saving.value) return
  saving.value = true
  try {
    if (!editingUser.value) {
      const ok = await apiText('/admin/mail/users/add', {
        email: fEmail.value,
        password: fPassword.value,
        privileges: fAdmin.value ? 'admin' : '',
        quota: fQuota.value,
      })
      if (ok) { sheetOpen.value = false; await load() }
    } else {
      const email = editingUser.value.email
      const steps: Array<Promise<boolean>> = []

      if (fPassword.value) {
        steps.push(apiText('/admin/mail/users/password', { email, password: fPassword.value }))
      }
      if (fQuota.value !== editingUser.value.quota) {
        steps.push(apiText('/admin/mail/users/quota', { email, quota: fQuota.value }))
      }

      const wasAdmin = editingUser.value.privileges.includes('admin')
      if (fAdmin.value && !wasAdmin) {
        steps.push(apiText('/admin/mail/users/privileges/add', { email, privilege: 'admin' }))
      } else if (!fAdmin.value && wasAdmin) {
        if (email === auth.email) { toast.error('You cannot remove admin from yourself.'); return }
        steps.push(apiText('/admin/mail/users/privileges/remove', { email, privilege: 'admin' }))
      }

      if (steps.length === 0) { toast.success('No changes.'); sheetOpen.value = false; return }
      const results = await Promise.all(steps)
      if (results.every(Boolean)) { sheetOpen.value = false; await load() }
    }
  } finally {
    saving.value = false
  }
}

async function confirmDelete(): Promise<void> {
  if (!editingUser.value) return
  if (editingUser.value.email === auth.email) {
    toast.error('You cannot archive yourself.')
    deleteOpen.value = false
    return
  }
  saving.value = true
  try {
    const ok = await apiText('/admin/mail/users/remove', { email: editingUser.value.email })
    if (ok) { deleteOpen.value = false; sheetOpen.value = false; await load() }
  } finally {
    saving.value = false
  }
}

onMounted(load)
</script>

<template>
  <AppLayout>
    <div class="flex items-center justify-between mb-6">
      <h1 class="text-2xl font-semibold">Users</h1>
      <Button @click="openAdd">Add User</Button>
    </div>

    <div class="mb-4 max-w-sm">
      <Input v-model="search" placeholder="Search users..." aria-label="Search users" />
    </div>

    <Table>
      <TableHead>
        <Th class="w-full">Email</Th>
        <Th class="whitespace-nowrap">Privileges</Th>
        <Th class="whitespace-nowrap">Quota</Th>
        <th scope="col" class="px-4 py-3"></th>
      </TableHead>
      <tbody>
        <template v-if="loading">
          <TableRow v-for="i in 4" :key="i">
            <td class="px-4 py-3"><Skeleton class="h-4 w-48" /></td>
            <td class="px-4 py-3"><Skeleton class="h-4 w-16" /></td>
            <td class="px-4 py-3"><Skeleton class="h-4 w-20" /></td>
            <td class="px-4 py-3"></td>
          </TableRow>
        </template>
        <template v-else>
          <TableRow
            v-for="user in filteredUsers"
            :key="user.email"
            clickable
            @click="openEdit(user)"
          >
            <td class="px-4 py-3 font-medium">{{ user.email }}</td>
            <td class="px-4 py-3">
              <Badge v-if="user.privileges.includes('admin')">admin</Badge>
            </td>
            <td class="px-4 py-3 text-sm text-gray-500">
              {{ user.quota === '0' ? 'unlimited' : user.quota }}
              <span v-if="user.percent?.trim()" class="ml-1 text-xs">({{ user.percent.trim() }})</span>
            </td>
            <td class="px-4 py-3 text-right">
              <Button variant="ghost" size="sm" @click.stop="openEdit(user)">Edit</Button>
            </td>
          </TableRow>
        </template>
      </tbody>
    </Table>

    <EmptyState
      v-if="!loading && users.length === 0"
      title="No mail users"
      description="Create your first account to get started."
    >
      <template #icon><UserPlus /></template>
      <template #action>
        <Button @click="openAdd">Add User</Button>
      </template>
    </EmptyState>

    <Sheet v-model="sheetOpen" :title="editingUser ? 'Edit User' : 'Add User'">
      <template v-if="editingUser" #danger>
        <Button variant="destructive" class="w-full" @click="deleteOpen = true">Archive User</Button>
      </template>
      <div class="space-y-5">
        <div>
          <label for="fEmail" class="block text-sm font-medium mb-1.5">Email</label>
          <Input
            v-if="!editingUser"
            id="fEmail"
            v-model="fEmail"
            type="email"
            autocomplete="off"
            placeholder="user@example.com"
          />
          <p v-else class="text-sm text-gray-500 py-2">{{ editingUser.email }}</p>
        </div>

        <div>
          <label for="fPassword" class="block text-sm font-medium mb-1.5">
            {{ editingUser ? 'New Password' : 'Password' }}
          </label>
          <div class="flex gap-2">
            <Input
              id="fPassword"
              v-model="fPassword"
              type="text"
              :placeholder="editingUser ? 'Leave blank to keep current' : ''"
              autocomplete="off"
            />
            <Button variant="primary" size="sm" type="button" @click="fPassword = generatePassword()">
              Generate
            </Button>
          </div>
        </div>

        <div>
          <label for="fQuota" class="block text-sm font-medium mb-1.5">Quota</label>
          <Input id="fQuota" v-model="fQuota" placeholder="0 = unlimited (e.g. 10G, 500M)" />
          <p class="text-xs text-gray-500 mt-1">Use G or M suffix. 0 = unlimited.</p>
        </div>

        <div class="flex items-center gap-2">
          <input id="fAdmin" v-model="fAdmin" type="checkbox" class="size-4 rounded" />
          <label for="fAdmin" class="text-sm">Administrator</label>
        </div>

        <Button class="w-full" :disabled="saving" @click="save">
          {{ saving ? 'Saving...' : editingUser ? 'Save Changes' : 'Add User' }}
        </Button>

      </div>
    </Sheet>

    <Dialog
      v-model="deleteOpen"
      title="Archive user?"
      :description="`${editingUser?.email} will lose all access. Their mailbox stays on disk.`"
    >
      <template #actions>
        <Button variant="secondary" @click="deleteOpen = false">Cancel</Button>
        <Button variant="destructive" :disabled="saving" @click="confirmDelete">
          {{ saving ? 'Archiving...' : 'Archive' }}
        </Button>
      </template>
    </Dialog>
  </AppLayout>
</template>
