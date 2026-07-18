<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { toast } from 'vue-sonner'
import { AtSign, Plus } from 'lucide-vue-next'
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
import Textarea from '@/components/ui/Textarea.vue'
import { api, ApiError } from '@/api/client'
import type { Alias, AliasesResponse, SystemRoute, UpsertAliasRequest } from '@/api/types.gen'

const aliases = ref<Alias[]>([])
const systemRoutes = ref<SystemRoute[]>([])
const loading = ref(true)
const loadError = ref(false)
const search = ref('')
const sheetOpen = ref(false)
const deleteOpen = ref(false)
const saving = ref(false)
const editingAlias = ref<Alias | null>(null)

const fAddress = ref('')
const fForwardsTo = ref('')
const fPermittedSenders = ref('')
const fAdvanced = ref(false)

const filteredAliases = computed(() =>
  aliases.value.filter(a => a.source.toLowerCase().includes(search.value.toLowerCase())),
)

const filteredSystemRoutes = computed(() =>
  systemRoutes.value.filter(r => r.source.toLowerCase().includes(search.value.toLowerCase())),
)

/** Split textarea input on newlines and commas into a clean list. */
function splitAddresses(input: string): string[] {
  return input
    .split(/[\n,]/)
    .map(s => s.trim())
    .filter(s => s.length > 0)
}

async function load(): Promise<void> {
  loading.value = true
  loadError.value = false
  try {
    const resp = await api.get<AliasesResponse>('/api/aliases')
    // Hide the auto domain-map catch-alls (@domain, auto=true): they
    // are system plumbing, not something to edit here.
    aliases.value = (resp.aliases ?? []).filter(a => !(a.auto && a.source.startsWith('@')))
    systemRoutes.value = resp.system ?? []
  } catch {
    loadError.value = true
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

// Overriding a system route is just creating a real alias at the same
// address: the derived route yields to it automatically.
function openOverride(route: SystemRoute): void {
  openAdd()
  fAddress.value = route.source
  fForwardsTo.value = route.destination
}

function openEdit(alias: Alias): void {
  editingAlias.value = alias
  fAddress.value = alias.source
  fForwardsTo.value = (alias.destinations ?? []).join('\n')
  fPermittedSenders.value = alias.permitted_senders ? alias.permitted_senders.join('\n') : ''
  fAdvanced.value = !!alias.permitted_senders?.length
  sheetOpen.value = true
}

async function save(): Promise<void> {
  if (saving.value) return
  saving.value = true
  try {
    const req: UpsertAliasRequest = {
      source: fAddress.value.trim(),
      destinations: splitAddresses(fForwardsTo.value),
    }
    if (fAdvanced.value) {
      const senders = splitAddresses(fPermittedSenders.value)
      if (senders.length > 0) req.permitted_senders = senders
    }
    await api.post('/api/aliases', req)
    toast.success(editingAlias.value ? 'Alias updated.' : 'Alias added.')
    sheetOpen.value = false
    await load()
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : 'Failed to save alias.')
  } finally {
    saving.value = false
  }
}

async function confirmDelete(): Promise<void> {
  if (!editingAlias.value) return
  saving.value = true
  try {
    await api.del(`/api/aliases/${encodeURIComponent(editingAlias.value.source)}`)
    toast.success('Alias removed.')
    deleteOpen.value = false
    sheetOpen.value = false
    await load()
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : 'Failed to remove alias.')
  } finally {
    saving.value = false
  }
}

onMounted(load)
</script>

<template>
    <PageHeader title="Aliases" description="Redirect mail sent to one address to one or more other addresses.">
      <template #actions>
        <Button size="sm" @click="openAdd"><Plus class="size-3.5" />Add Alias</Button>
      </template>
    </PageHeader>

    <div class="mb-4 max-w-sm">
      <Input v-model="search" placeholder="Search aliases..." aria-label="Search aliases" />
    </div>

    <AsyncState :loading="loading" :error="loadError" :empty="aliases.length === 0" error-title="Could not load aliases" @retry="load">
      <template #loading>
        <Table>
          <TableHead>
            <Th>Address</Th>
            <Th>Forwards To</Th>
            <Th class="hidden sm:table-cell">Type</Th>
            <Th />
          </TableHead>
          <tbody>
            <TableRow v-for="i in 2" :key="i">
              <td class="px-4 py-3"><Skeleton class="h-4 w-48" /></td>
              <td class="px-4 py-3"><Skeleton class="h-4 w-40" /></td>
              <td class="px-4 py-3 hidden sm:table-cell"><Skeleton class="h-4 w-16" /></td>
              <td class="px-4 py-3"></td>
            </TableRow>
          </tbody>
        </Table>
      </template>

      <template #empty>
        <EmptyState bordered title="No aliases" description="Aliases forward mail from one address to another.">
          <template #icon><AtSign /></template>
          <template #action><Button @click="openAdd">Add Alias</Button></template>
        </EmptyState>
      </template>

      <Table>
        <TableHead>
          <Th>Address</Th>
          <Th>Forwards To</Th>
          <Th class="hidden sm:table-cell">Type</Th>
          <Th />
        </TableHead>
        <tbody>
          <TableRow v-for="alias in filteredAliases" :key="alias.source" clickable @click="openEdit(alias)">
            <td class="px-4 py-3 font-medium">{{ alias.source }}</td>
            <td class="px-4 py-3 text-sm text-muted">{{ (alias.destinations ?? []).join(', ') }}</td>
            <td class="px-4 py-3 hidden sm:table-cell">
              <Badge v-if="alias.auto" variant="default">auto</Badge>
            </td>
            <td class="px-4 py-3 text-right">
              <Button variant="secondary" size="sm" @click.stop="openEdit(alias)">Edit</Button>
            </td>
          </TableRow>
          <tr v-if="filteredAliases.length === 0">
            <td colspan="4" class="px-4 py-8 text-center text-sm text-muted">No aliases match your search.</td>
          </tr>
        </tbody>
      </Table>

      <!-- Derived system routing: maintained automatically, shown so
           operators can see where role mail goes without it being an
           editable (or deletable) row. -->
      <template v-if="filteredSystemRoutes.length > 0">
        <h2 class="text-sm font-medium mt-8 mb-1">System routing</h2>
        <p class="text-xs text-muted mb-3">
          Mail addressed to these role addresses is delivered to the oldest administrator
          automatically. Adding an alias (or a user) at one of these addresses overrides it.
        </p>
        <Table>
          <TableHead>
            <Th>Address</Th>
            <Th>Delivers To</Th>
            <Th />
          </TableHead>
          <tbody>
            <TableRow v-for="route in filteredSystemRoutes" :key="route.source">
              <td class="px-4 py-3 text-sm text-muted">{{ route.source }}</td>
              <td class="px-4 py-3 text-sm text-muted">{{ route.destination }}</td>
              <td class="px-4 py-3 text-right">
                <Button variant="secondary" size="sm" @click="openOverride(route)">Override</Button>
              </td>
            </TableRow>
          </tbody>
        </Table>
      </template>
    </AsyncState>

    <Sheet v-model="sheetOpen" :title="editingAlias ? 'Edit Alias' : 'Add Alias'">
      <template v-if="editingAlias && !editingAlias.auto" #danger>
        <Button variant="destructive" class="w-full" @click="deleteOpen = true">Remove Alias</Button>
      </template>
      <div class="space-y-5">
        <Field label="Address" for="fAddress">
          <Input
            v-if="!editingAlias"
            id="fAddress"
            v-model="fAddress"
            type="email"
            placeholder="alias@yourdomain.com or @yourdomain.com"
            autocomplete="off"
          />
          <p v-else class="text-sm text-muted py-2">{{ editingAlias.source }}</p>
        </Field>

        <p v-if="editingAlias?.auto" class="text-xs text-muted">
          This is a system-generated alias. Saving changes converts it to a
          manual alias that no longer updates automatically.
        </p>

        <Field label="Forwards To" for="fForwardsTo">
          <Textarea id="fForwardsTo" v-model="fForwardsTo" placeholder="One address per line or comma-separated" />
        </Field>

        <div>
          <div class="flex items-center gap-2 mb-3">
            <Checkbox id="fAdvanced" v-model="fAdvanced" />
            <label for="fAdvanced" class="text-sm">Restrict permitted senders</label>
          </div>
          <Field v-if="fAdvanced" label="Permitted Senders" for="fPermittedSenders">
            <Textarea id="fPermittedSenders" v-model="fPermittedSenders" placeholder="One sender per line - only these addresses may send as this alias" />
          </Field>
        </div>

      </div>

      <template #footer>
        <div class="flex gap-2 justify-end">
          <Button variant="secondary" @click="sheetOpen = false">Cancel</Button>
          <Button :disabled="saving" @click="save">
            {{ saving ? 'Saving...' : editingAlias ? 'Update Alias' : 'Add Alias' }}
          </Button>
        </div>
      </template>
    </Sheet>

    <Dialog
      v-model="deleteOpen"
      title="Remove alias?"
      :description="`Remove the alias ${editingAlias?.source}?`"
    >
      <template #actions>
        <Button variant="secondary" @click="deleteOpen = false">Cancel</Button>
        <Button variant="destructive" :disabled="saving" @click="confirmDelete">
          {{ saving ? 'Removing...' : 'Remove' }}
        </Button>
      </template>
    </Dialog>
</template>
