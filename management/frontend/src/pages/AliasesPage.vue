<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { toast } from 'vue-sonner'
import { AtSign } from 'lucide-vue-next'
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
import Textarea from '@/components/ui/Textarea.vue'
import { useApi } from '@/composables/useApi'
import type { MailAlias, MailAliasDomain } from '@/types'

const api = useApi()

const aliases = ref<MailAlias[]>([])
const loading = ref(true)
const search = ref('')
const sheetOpen = ref(false)
const deleteOpen = ref(false)
const saving = ref(false)
const editingAlias = ref<MailAlias | null>(null)

const fAddress = ref('')
const fForwardsTo = ref('')
const fPermittedSenders = ref('')
const fAdvanced = ref(false)

const filteredAliases = computed(() =>
  aliases.value.filter(a =>
    a.address_display.toLowerCase().includes(search.value.toLowerCase()),
  ),
)

async function load(): Promise<void> {
  loading.value = true
  try {
    const res = await api.get('/admin/mail/aliases?format=json')
    const domains: MailAliasDomain[] = await res.json()
    // Exclude auto domain-map aliases (address starts with @, auto=true)
    aliases.value = domains
      .flatMap(d => d.aliases)
      .filter(a => !(a.auto && a.address.startsWith('@')))
  } catch {
    toast.error('Failed to load aliases.')
  } finally {
    loading.value = false
  }
}

function openAdd(): void {
  editingAlias.value = null
  fAddress.value = ''
  fForwardsTo.value = ''
  fPermittedSenders.value = ''
  fAdvanced.value = false
  sheetOpen.value = true
}

function openEdit(alias: MailAlias): void {
  editingAlias.value = alias
  fAddress.value = alias.address_display
  fForwardsTo.value = alias.forwards_to.join('\n')
  fPermittedSenders.value = alias.permitted_senders ? alias.permitted_senders.join('\n') : ''
  fAdvanced.value = !!alias.permitted_senders
  sheetOpen.value = true
}

async function save(): Promise<void> {
  if (saving.value) return
  saving.value = true
  try {
    const res = await api.post('/admin/mail/aliases/add', {
      address: fAddress.value,
      forwards_to: fForwardsTo.value,
      permitted_senders: fAdvanced.value ? fPermittedSenders.value : '',
      update_if_exists: editingAlias.value ? '1' : '0',
    })
    const text = await res.text()
    if (!res.ok) { toast.error(text); return }
    toast.success(text || 'Saved.')
    sheetOpen.value = false
    await load()
  } finally {
    saving.value = false
  }
}

async function confirmDelete(): Promise<void> {
  if (!editingAlias.value) return
  saving.value = true
  try {
    const res = await api.post('/admin/mail/aliases/remove', {
      address: editingAlias.value.address,
    })
    const text = await res.text()
    if (!res.ok) { toast.error(text); return }
    toast.success(text || 'Alias removed.')
    deleteOpen.value = false
    sheetOpen.value = false
    await load()
  } finally {
    saving.value = false
  }
}

onMounted(load)
</script>

<template>
  <AppLayout>
    <div class="flex items-center justify-between mb-6">
      <h1 class="text-2xl font-semibold">Aliases</h1>
      <Button @click="openAdd">Add Alias</Button>
    </div>

    <div class="mb-4 max-w-sm">
      <Input v-model="search" placeholder="Search aliases..." aria-label="Search aliases" />
    </div>

    <Table>
      <TableHead>
        <Th>Address</Th>
        <Th>Forwards To</Th>
        <Th class="hidden sm:table-cell">Type</Th>
        <th scope="col" class="px-4 py-3"></th>
      </TableHead>
      <tbody>
        <template v-if="loading">
          <TableRow v-for="i in 4" :key="i">
            <td class="px-4 py-3"><Skeleton class="h-4 w-48" /></td>
            <td class="px-4 py-3"><Skeleton class="h-4 w-40" /></td>
            <td class="px-4 py-3 hidden sm:table-cell"><Skeleton class="h-4 w-16" /></td>
            <td class="px-4 py-3"></td>
          </TableRow>
        </template>
        <template v-else>
          <TableRow
            v-for="alias in filteredAliases"
            :key="alias.address"
            clickable
            @click="openEdit(alias)"
          >
            <td class="px-4 py-3 font-medium">{{ alias.address_display }}</td>
            <td class="px-4 py-3 text-sm text-gray-500">
              {{ alias.forwards_to.join(', ') }}
            </td>
            <td class="px-4 py-3 hidden sm:table-cell">
              <Badge v-if="alias.auto" variant="default">auto</Badge>
            </td>
            <td class="px-4 py-3 text-right">
              <Button variant="ghost" size="sm" @click.stop="openEdit(alias)">Edit</Button>
            </td>
          </TableRow>
        </template>
      </tbody>
    </Table>

    <EmptyState
      v-if="!loading && aliases.length === 0"
      title="No aliases"
      description="Aliases forward mail from one address to another."
    >
      <template #icon><AtSign /></template>
      <template #action>
        <Button @click="openAdd">Add Alias</Button>
      </template>
    </EmptyState>

    <Sheet v-model="sheetOpen" :title="editingAlias ? 'Edit Alias' : 'Add Alias'">
      <template v-if="editingAlias && !editingAlias.auto" #danger>
        <Button variant="destructive" class="w-full" @click="deleteOpen = true">Remove Alias</Button>
      </template>
      <div class="space-y-5">
        <div>
          <label for="fAddress" class="block text-sm font-medium mb-1.5">Address</label>
          <Input
            v-if="!editingAlias"
            id="fAddress"
            v-model="fAddress"
            type="email"
            placeholder="alias@yourdomain.com or @yourdomain.com"
            autocomplete="off"
          />
          <p v-else class="text-sm text-gray-500 py-2">{{ editingAlias.address_display }}</p>
        </div>

        <div>
          <label for="fForwardsTo" class="block text-sm font-medium mb-1.5">Forwards To</label>
          <Textarea id="fForwardsTo" v-model="fForwardsTo" placeholder="One address per line or comma-separated" />
        </div>

        <div>
          <div class="flex items-center gap-2 mb-3">
            <input id="fAdvanced" v-model="fAdvanced" type="checkbox" class="size-4 rounded" />
            <label for="fAdvanced" class="text-sm">Restrict permitted senders</label>
          </div>
          <div v-if="fAdvanced">
            <label for="fPermittedSenders" class="block text-sm font-medium mb-1.5">Permitted Senders</label>
            <Textarea id="fPermittedSenders" v-model="fPermittedSenders" placeholder="One sender per line - only these addresses may send as this alias" />
          </div>
        </div>

        <Button class="w-full" :disabled="saving" @click="save">
          {{ saving ? 'Saving...' : editingAlias ? 'Update Alias' : 'Add Alias' }}
        </Button>

      </div>
    </Sheet>

    <Dialog
      v-model="deleteOpen"
      title="Remove alias?"
      :description="`Remove the alias ${editingAlias?.address_display}?`"
    >
      <template #actions>
        <Button variant="secondary" @click="deleteOpen = false">Cancel</Button>
        <Button variant="destructive" :disabled="saving" @click="confirmDelete">
          {{ saving ? 'Removing...' : 'Remove' }}
        </Button>
      </template>
    </Dialog>
  </AppLayout>
</template>
