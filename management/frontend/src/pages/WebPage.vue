<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { toast } from 'vue-sonner'
import { Globe } from 'lucide-vue-next'
import AppLayout from '@/components/layout/AppLayout.vue'
import Button from '@/components/ui/Button.vue'
import Card from '@/components/ui/Card.vue'
import Code from '@/components/ui/Code.vue'
import Table from '@/components/ui/Table.vue'
import TableHead from '@/components/ui/TableHead.vue'
import Th from '@/components/ui/Th.vue'
import TableRow from '@/components/ui/TableRow.vue'
import Skeleton from '@/components/ui/Skeleton.vue'
import EmptyState from '@/components/ui/EmptyState.vue'
import Dialog from '@/components/ui/Dialog.vue'
import { useApi } from '@/composables/useApi'
import { useConfigStore } from '@/stores/config'
import type { WebDomain } from '@/types'

const api = useApi()
const config = useConfigStore()

const loading = ref(true)
const updating = ref(false)
const updateResult = ref<string | null>(null)
const domains = ref<WebDomain[]>([])

// Change-root confirmation
const changeOpen = ref(false)
const changeDomain = ref<WebDomain | null>(null)

async function load(): Promise<void> {
  loading.value = true
  try {
    const res = await api.get('/admin/web/domains')
    const data: WebDomain[] = await res.json()
    domains.value = data.filter(d => d.static_enabled)
  } catch {
    toast.error('Failed to load web domains.')
  } finally {
    loading.value = false
  }
}

async function doUpdate(): Promise<void> {
  if (updating.value) return
  updating.value = true
  updateResult.value = null
  try {
    const res = await api.post('/admin/web/update')
    const text = await res.text()
    updateResult.value = text || 'Nothing changed.'
    if (res.ok) {
      await load()
    } else {
      toast.error(text)
    }
  } finally {
    updating.value = false
    changeOpen.value = false
    changeDomain.value = null
  }
}

function openChangeRoot(domain: WebDomain): void {
  changeDomain.value = domain
  changeOpen.value = true
}

onMounted(load)
</script>

<template>
  <AppLayout>
    <h1 class="text-2xl font-semibold mb-6">Static Web Hosting</h1>

    <Card class="p-5 mb-6">
      <p class="text-sm text-gray-600 dark:text-gray-400 mb-3">
        This box serves a static website at
        <a :href="`https://${config.hostname}`" target="_blank" class="underline font-medium">https://{{ config.hostname || 'example.com' }}</a>
        and at every domain you have email users or aliases configured for.
      </p>

      <h2 class="text-sm font-semibold mb-2">Uploading web files</h2>
      <ol class="text-sm text-gray-600 dark:text-gray-400 space-y-2 list-decimal list-inside">
        <li>
          Ensure your domains have no problems on the
          <router-link to="/system-status" class="underline">Status Checks</router-link> page.
        </li>
        <li>
          Install an SFTP client such as
          <a href="https://filezilla-project.org/" target="_blank" class="underline">FileZilla</a>
          or use <Code>scp</Code>.
        </li>
        <li>
          Connect to <strong>{{ config.hostname }}</strong> over SSH/SFTP using your
          server's SSH credentials (not your mail password).
        </li>
        <li>Upload files to the directory shown in the table below for each domain.</li>
      </ol>
    </Card>

    <!-- Domains table -->
    <div class="flex items-center justify-between mb-3">
      <h2 class="text-base font-semibold">Hosted Websites</h2>
      <Button variant="secondary" size="sm" :disabled="updating" @click="doUpdate">
        {{ 'Update Web Settings' }}
      </Button>
    </div>

    <template v-if="loading">
      <Table>
        <TableHead>
          <Th>Site</Th>
          <Th>Directory</Th>
          <th scope="col" class="px-4 py-3"></th>
        </TableHead>
        <tbody>
          <TableRow v-for="i in 3" :key="i">
            <td class="px-4 py-3"><Skeleton class="h-4 w-48" /></td>
            <td class="px-4 py-3"><Skeleton class="h-4 w-64" /></td>
            <td class="px-4 py-3"></td>
          </TableRow>
        </tbody>
      </Table>
    </template>

    <template v-else-if="domains.length === 0">
      <EmptyState
        title="No static websites"
        description="Add a mail user or alias on a domain to enable static hosting for it."
      >
        <template #icon><Globe /></template>
      </EmptyState>
    </template>

    <template v-else>
      <Table>
        <TableHead>
          <Th>Site</Th>
          <Th>Upload directory</Th>
          <th scope="col" class="px-4 py-3"></th>
        </TableHead>
        <tbody>
          <TableRow v-for="d in domains" :key="d.domain">
            <td class="px-4 py-3 text-sm font-medium">
              <a :href="`https://${d.domain}`" target="_blank" class="hover:underline">
                https://{{ d.domain }}
              </a>
            </td>
            <td class="px-4 py-3 font-mono text-xs text-gray-500">{{ d.root }}</td>
            <td class="px-4 py-3 text-right">
              <Button
                v-if="d.root !== d.custom_root"
                variant="ghost"
                size="sm"
                @click="openChangeRoot(d)"
              >
                Change
              </Button>
            </td>
          </TableRow>
        </tbody>
      </Table>

      <p class="text-xs text-gray-400 mt-2">
        To add a site, create a mail user or alias for that domain.
        See the <a href="https://mailinabox.email/guide.html#domain-name-configuration" target="_blank" class="underline">setup guide</a>
        for nameserver configuration.
      </p>
    </template>

    <!-- Update result -->
    <Card v-if="updateResult" class="p-4 mt-4">
      <p class="text-xs font-medium text-gray-500 mb-1">Update result</p>
      <pre class="text-xs text-gray-700 dark:text-gray-300 whitespace-pre-wrap">{{ updateResult }}</pre>
    </Card>

    <!-- Change root confirm dialog -->
    <Dialog
      v-model="changeOpen"
      :title="`Change root for ${changeDomain?.domain}`"
      :description="`The directory will be changed to ${changeDomain?.custom_root}. Create this directory on the server first, then click Update to apply.`"
    >
      <template #actions>
        <Button variant="secondary" @click="changeOpen = false">Cancel</Button>
        <Button :disabled="updating" @click="doUpdate">
          {{ updating ? 'Updating...' : 'Update' }}
        </Button>
      </template>
    </Dialog>
  </AppLayout>
</template>
