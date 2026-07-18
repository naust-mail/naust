<script setup lang="ts">
import { ref, watch, onMounted } from 'vue'
import { toast } from 'vue-sonner'
import { Key, Plus } from 'lucide-vue-next'
import AsyncState from '@/components/ui/AsyncState.vue'
import Button from '@/components/ui/Button.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import Field from '@/components/ui/Field.vue'
import Input from '@/components/ui/Input.vue'
import Select from '@/components/ui/Select.vue'
import Code from '@/components/ui/Code.vue'
import Badge from '@/components/ui/Badge.vue'
import Skeleton from '@/components/ui/Skeleton.vue'
import EmptyState from '@/components/ui/EmptyState.vue'
import Dialog from '@/components/ui/Dialog.vue'
import Sheet from '@/components/ui/Sheet.vue'
import Table from '@/components/ui/Table.vue'
import TableHead from '@/components/ui/TableHead.vue'
import Th from '@/components/ui/Th.vue'
import TableRow from '@/components/ui/TableRow.vue'
import { api, ApiError } from '@/api/client'
import type {
  APIToken,
  APITokensResponse,
  CreateAPITokenRequest,
  CreateAPITokenResponse,
} from '@/api/types.gen'

const loading = ref(true)
const loadError = ref(false)
const tokens = ref<APIToken[]>([])

// Create sheet state
const createOpen = ref(false)
const creating = ref(false)
const newName = ref('')
const newScope = ref('read')

// Reveal dialog state - shown once after token creation
const revealOpen = ref(false)
const revealedToken = ref('')
const copied = ref(false)

// Revoke confirm dialog state
const revokeOpen = ref(false)
const revokeTarget = ref<APIToken | null>(null)
const revoking = ref(false)

async function load(): Promise<void> {
  loading.value = true
  loadError.value = false
  try {
    const resp = await api.get<APITokensResponse>('/api/tokens')
    tokens.value = resp.tokens ?? []
  } catch {
    loadError.value = true
    toast.error('Failed to load API tokens.')
  } finally {
    loading.value = false
  }
}

async function createToken(): Promise<void> {
  if (!newName.value.trim() || creating.value) return
  creating.value = true
  try {
    const req: CreateAPITokenRequest = {
      name: newName.value.trim(),
      scope: newScope.value,
    }
    const data = await api.post<CreateAPITokenResponse>('/api/tokens', req)
    createOpen.value = false
    newName.value = ''
    newScope.value = 'read'
    revealedToken.value = data.token
    copied.value = false
    revealOpen.value = true
    await load()
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : 'Failed to create token.')
  } finally {
    creating.value = false
  }
}

async function copyToken(): Promise<void> {
  try {
    await navigator.clipboard.writeText(revealedToken.value)
    copied.value = true
  } catch {
    toast.error('Could not copy to clipboard.')
  }
}

function openRevoke(token: APIToken): void {
  revokeTarget.value = token
  revokeOpen.value = true
}

async function confirmRevoke(): Promise<void> {
  if (!revokeTarget.value || revoking.value) return
  revoking.value = true
  try {
    await api.del(`/api/tokens/${revokeTarget.value.id}`)
    toast.success(`Token "${revokeTarget.value.name}" revoked.`)
    revokeOpen.value = false
    await load()
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : 'Failed to revoke token.')
  } finally {
    revoking.value = false
  }
}

// Timestamps arrive as RFC 3339 with timezone (Go time.Time).
function formatDate(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

watch(revealOpen, (open) => {
  if (!open) {
    revealedToken.value = ''
    copied.value = false
  }
})

onMounted(load)
</script>

<template>
    <PageHeader title="API Tokens" description="Allow external apps and automations to manage this box.">
      <template #actions>
        <Button size="sm" @click="createOpen = true"><Plus class="size-3.5" />New token</Button>
      </template>
    </PageHeader>

    <AsyncState :loading="loading" :error="loadError" :empty="tokens.length === 0" error-title="Could not load tokens" @retry="load">
      <template #loading>
        <Table>
          <TableHead>
            <Th>Name</Th>
            <Th>Scope</Th>
            <Th>Created</Th>
            <Th>Last used</Th>
            <Th />
          </TableHead>
          <tbody>
            <TableRow v-for="i in 2" :key="i">
              <td class="px-4 py-3"><Skeleton class="h-4 w-48" /></td>
              <td class="px-4 py-3"><Skeleton class="h-4 w-14" /></td>
              <td class="px-4 py-3"><Skeleton class="h-4 w-32" /></td>
              <td class="px-4 py-3"><Skeleton class="h-4 w-24" /></td>
              <td class="px-4 py-3"></td>
            </TableRow>
          </tbody>
        </Table>
      </template>

      <template #empty>
        <EmptyState bordered title="No API tokens" description="Create a token to authenticate scripts and tools against the admin API.">
          <template #icon><Key /></template>
          <template #action><Button @click="createOpen = true">New token</Button></template>
        </EmptyState>
      </template>

      <Table>
        <TableHead>
          <Th>Name</Th>
          <Th>Scope</Th>
          <Th>Created</Th>
          <Th>Last used</Th>
          <Th />
        </TableHead>
        <tbody>
          <TableRow v-for="token in tokens" :key="token.id">
            <td class="px-4 py-3 text-sm font-medium">{{ token.name }}</td>
            <td class="px-4 py-3">
              <Badge :variant="token.scope === 'write' ? 'warning' : 'default'">
                {{ token.scope }}
              </Badge>
            </td>
            <td class="px-4 py-3 text-sm text-muted">{{ formatDate(token.created_at) }}</td>
            <td class="px-4 py-3 text-sm text-muted">
              {{ token.last_used ? formatDate(token.last_used) : 'Never' }}
            </td>
            <td class="px-4 py-3 text-right">
              <Button variant="secondary" size="sm" @click="openRevoke(token)">Revoke</Button>
            </td>
          </TableRow>
        </tbody>
      </Table>
    </AsyncState>

    <!-- Create token sheet -->
    <Sheet v-model="createOpen" title="New API token">
      <div class="space-y-5">
        <Field label="Name" for="tokenName">
          <Input
            id="tokenName"
            v-model="newName"
            placeholder="e.g. Backup script"
            @keydown.enter="createToken"
          />
          <p class="text-xs text-muted mt-1.5">A label so you can identify this token later.</p>
        </Field>

        <Field label="Scope" for="tokenScope">
          <Select id="tokenScope" v-model="newScope">
            <option value="read">Read - can only read data, no changes</option>
            <option value="write">Write - can read and make changes</option>
          </Select>
          <p class="text-xs text-muted mt-1.5">
            Read tokens can fetch data but cannot change settings, send email, or trigger actions.
            Write tokens have full access to the API except for managing other tokens and admin users.
          </p>
        </Field>
      </div>

      <template #footer>
        <div class="flex gap-2 justify-end">
          <Button variant="secondary" @click="createOpen = false">Cancel</Button>
          <Button :disabled="!newName.trim() || creating" @click="createToken">
            {{ creating ? 'Creating...' : 'Create token' }}
          </Button>
        </div>
      </template>
    </Sheet>

    <!-- Token reveal dialog - shown once after creation -->
    <Dialog
      v-model="revealOpen"
      title="Copy your new token"
      description="This token will not be shown again. Copy it now and store it somewhere safe."
    >
      <div class="space-y-3">
        <Code block class="break-all select-all">{{ revealedToken }}</Code>
        <Button variant="secondary" class="w-full" @click="copyToken">
          {{ copied ? 'Copied!' : 'Copy to clipboard' }}
        </Button>
      </div>
      <template #actions>
        <Button @click="revealOpen = false">I've copied it</Button>
      </template>
    </Dialog>

    <!-- Revoke confirm dialog -->
    <Dialog
      v-model="revokeOpen"
      title="Revoke token?"
      :description="`'${revokeTarget?.name}' will stop working immediately. This cannot be undone.`"
    >
      <template #actions>
        <Button variant="secondary" @click="revokeOpen = false">Cancel</Button>
        <Button variant="destructive" :disabled="revoking" @click="confirmRevoke">
          {{ revoking ? 'Revoking...' : 'Revoke' }}
        </Button>
      </template>
    </Dialog>
</template>
