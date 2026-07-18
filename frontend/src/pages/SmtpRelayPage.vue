<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { toast } from 'vue-sonner'
import { Settings2, Send, CheckCircle, XCircle } from 'lucide-vue-next'
import AsyncState from '@/components/ui/AsyncState.vue'
import Button from '@/components/ui/Button.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import Field from '@/components/ui/Field.vue'
import Input from '@/components/ui/Input.vue'
import Select from '@/components/ui/Select.vue'
import Badge from '@/components/ui/Badge.vue'
import Card from '@/components/ui/Card.vue'
import Sheet from '@/components/ui/Sheet.vue'
import Skeleton from '@/components/ui/Skeleton.vue'
import Well from '@/components/ui/Well.vue'
import { api, ApiError } from '@/api/client'
import type { MessageResponse, RelayConfig, RelayTestRequest, SetRelayRequest } from '@/api/types.gen'

type ProviderId = 'direct' | 'ses' | 'brevo' | 'mailgun' | 'mailjet' | 'postmark' | 'resend' | 'sendgrid' | 'smtp2go' | 'custom'

type ProviderPreset = {
  label: string
  host: string
  port: number
  userPlaceholder: string
  spfInclude: string
}

// Direct first, real providers alphabetical, Custom last.
const PROVIDERS: Record<ProviderId, ProviderPreset> = {
  direct:   { label: 'Direct delivery (no relay)', host: '', port: 587, userPlaceholder: '', spfInclude: '' },
  ses:      { label: 'Amazon SES', host: 'email-smtp.us-east-1.amazonaws.com', port: 587, userPlaceholder: 'SMTP username from SES console', spfInclude: 'amazonses.com' },
  brevo:    { label: 'Brevo', host: 'smtp-relay.brevo.com', port: 587, userPlaceholder: 'Your Brevo login email', spfInclude: 'spf.sendinblue.com' },
  mailgun:  { label: 'Mailgun', host: 'smtp.mailgun.org', port: 587, userPlaceholder: 'SMTP login from Mailgun dashboard', spfInclude: 'mailgun.org' },
  mailjet:  { label: 'Mailjet', host: 'in-v3.mailjet.com', port: 587, userPlaceholder: 'Mailjet API key', spfInclude: 'spf.mailjet.com' },
  postmark: { label: 'Postmark', host: 'smtp.postmarkapp.com', port: 587, userPlaceholder: 'Postmark server API token', spfInclude: 'spf.mtasv.net' },
  resend:   { label: 'Resend', host: 'smtp.resend.com', port: 587, userPlaceholder: 'resend', spfInclude: 'spf.resend.com' },
  sendgrid: { label: 'SendGrid', host: 'smtp.sendgrid.net', port: 587, userPlaceholder: 'apikey', spfInclude: 'sendgrid.net' },
  smtp2go:  { label: 'SMTP2GO', host: 'mail.smtp2go.com', port: 587, userPlaceholder: 'SMTP2GO username', spfInclude: 'spf.smtp2go.com' },
  custom:   { label: 'Custom relay', host: '', port: 587, userPlaceholder: 'Username', spfInclude: '' },
}

const loading = ref(true)
const loadError = ref(false)
const saving = ref(false)
const testing = ref(false)
const sendingTest = ref(false)
const testResult = ref<{ ok: boolean; message: string } | null>(null)
const sheetOpen = ref(false)

const current = ref<RelayConfig | null>(null)
const provider = ref<ProviderId>('direct')
const host = ref('')
const port = ref('587')
const user = ref('')
const password = ref('')
const spfInclude = ref('')

const isActive = computed(() => !!current.value?.host)
const showFields = computed(() => provider.value !== 'direct')
const currentPreset = computed(() => PROVIDERS[provider.value])

// Label for the active relay shown on the main page
const activeProviderLabel = computed(() => {
  if (!current.value?.host) return null
  const id = detectProvider(current.value.host)
  return PROVIDERS[id]?.label ?? current.value.host
})

const pageTestResult = ref<{ ok: boolean; message: string } | null>(null)
const sendingPageTest = ref(false)

async function sendPageTestEmail(): Promise<void> {
  if (sendingPageTest.value) return
  sendingPageTest.value = true
  pageTestResult.value = null
  try {
    const resp = await api.post<MessageResponse>('/api/system/relay/send-test')
    pageTestResult.value = { ok: true, message: resp.message }
  } catch (e) {
    pageTestResult.value = { ok: false, message: e instanceof ApiError ? e.message : 'Request failed.' }
  } finally {
    sendingPageTest.value = false
  }
}

const FIXED_USERNAMES = new Set(['apikey', 'resend'])

function onProviderChange(raw: string | undefined): void {
  if (!raw) return
  const p = raw as ProviderId
  provider.value = p
  testResult.value = null
  if (p !== 'custom' && p !== 'direct') {
    const preset = PROVIDERS[p]
    host.value = preset.host
    port.value = String(preset.port)
    spfInclude.value = preset.spfInclude
    // Clear auto-filled usernames so the placeholder shows for the new provider.
    // User-typed values are left intact.
    if (FIXED_USERNAMES.has(user.value)) user.value = ''
    if (p === 'sendgrid') user.value = 'apikey'
    if (p === 'resend') user.value = 'resend'
  }
}

function detectProvider(h: string): ProviderId {
  const found = (Object.entries(PROVIDERS) as [ProviderId, ProviderPreset][])
    .find(([id, preset]) => id !== 'direct' && id !== 'custom' && preset.host === h)
  return found ? found[0] : 'custom'
}

function openSheet(): void {
  if (current.value?.host) {
    host.value = current.value.host
    port.value = String(current.value.port)
    user.value = current.value.user
    spfInclude.value = current.value.spf_include
    provider.value = detectProvider(current.value.host)
  } else {
    provider.value = 'direct'
    host.value = ''
    port.value = '587'
    user.value = ''
    spfInclude.value = ''
  }
  password.value = ''
  testResult.value = null
  sheetOpen.value = true
}

async function load(): Promise<void> {
  loading.value = true
  loadError.value = false
  try {
    current.value = await api.get<RelayConfig>('/api/system/relay')
  } catch {
    loadError.value = true
    toast.error('Failed to load relay configuration.')
  } finally {
    loading.value = false
  }
}

const ALLOWED_TEST_PORTS = new Set([25, 465, 587, 2525])

async function testConnection(): Promise<void> {
  if (testing.value) return
  const portNum = parseInt(port.value, 10)
  if (!ALLOWED_TEST_PORTS.has(portNum)) {
    testResult.value = { ok: false, message: 'Invalid port. Use 25, 465, 587, or 2525.' }
    return
  }
  testing.value = true
  testResult.value = null
  try {
    const req: RelayTestRequest = {
      host: host.value,
      port: portNum,
      user: user.value,
      password: password.value,
    }
    const resp = await api.post<MessageResponse>('/api/system/relay/test', req)
    testResult.value = { ok: true, message: resp.message }
  } catch (e) {
    testResult.value = { ok: false, message: e instanceof ApiError ? e.message : 'Request failed.' }
  } finally {
    testing.value = false
  }
}

async function sendTestEmail(): Promise<void> {
  if (sendingTest.value) return
  sendingTest.value = true
  testResult.value = null
  try {
    const resp = await api.post<MessageResponse>('/api/system/relay/send-test')
    testResult.value = { ok: true, message: resp.message }
  } catch (e) {
    testResult.value = { ok: false, message: e instanceof ApiError ? e.message : 'Request failed.' }
  } finally {
    sendingTest.value = false
  }
}

async function save(): Promise<void> {
  if (saving.value) return
  const portNum = parseInt(port.value, 10)
  if (provider.value !== 'direct' && !Number.isFinite(portNum)) {
    toast.error('Invalid port.')
    return
  }
  saving.value = true
  try {
    const req: SetRelayRequest = {
      host: provider.value === 'direct' ? '' : host.value,
      port: provider.value === 'direct' ? 587 : portNum,
      user: user.value,
      spf_include: spfInclude.value,
    }
    if (password.value) req.password = password.value

    current.value = await api.put<RelayConfig>('/api/system/relay', req)
    toast.success(provider.value === 'direct' ? 'Relay disabled.' : 'Relay configured.')
    sheetOpen.value = false
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : 'Failed to save relay configuration.')
  } finally {
    saving.value = false
  }
}

onMounted(load)
</script>

<template>
    <PageHeader title="Outbound Mail Relay" description="Send outbound mail through an external mail provider.">
      <template #actions>
        <Button variant="secondary" size="sm" @click="openSheet"><Settings2 class="size-3.5" />Configure</Button>
      </template>
    </PageHeader>

    <!-- Status card -->
    <AsyncState :loading="loading" :error="loadError" error-title="Could not load relay configuration" @retry="load">
      <template #loading>
        <Card padding="md" class="space-y-3">
          <Skeleton class="h-5 w-32" />
          <Skeleton class="h-4 w-64" />
          <Skeleton class="h-4 w-48" />
        </Card>
      </template>

      <Card padding="md">
      <!-- Active relay -->
      <template v-if="isActive">
        <div class="flex items-start justify-between gap-4 mb-4">
          <div>
            <div class="flex items-center gap-2 mb-1">
              <span class="text-sm font-semibold">{{ activeProviderLabel }}</span>
              <Badge variant="success">Active</Badge>
            </div>
            <p class="text-sm text-muted">Outbound mail is routed through this relay.</p>
          </div>
          <Button variant="secondary" size="sm" :disabled="sendingPageTest" @click="sendPageTestEmail">
            <Send class="size-3.5" />{{ sendingPageTest ? 'Sending...' : 'Send test' }}
          </Button>
        </div>

        <!-- Detail rows -->
        <div class="rounded-lg border border-border divide-y divide-border text-sm">
          <div class="flex items-center justify-between px-3 py-2">
            <span class="text-muted">Host</span>
            <span class="font-mono text-text">{{ current?.host }}:{{ current?.port }}</span>
          </div>
          <div class="flex items-center justify-between px-3 py-2">
            <span class="text-muted">Username</span>
            <span class="font-mono text-text">{{ current?.user }}</span>
          </div>
          <div v-if="current?.spf_include" class="flex items-center justify-between px-3 py-2">
            <span class="text-muted">SPF include</span>
            <span class="font-mono text-text">{{ current.spf_include }}</span>
          </div>
          <div class="flex items-center justify-between px-3 py-2">
            <span class="text-muted">Password</span>
            <span class="text-text">{{ current?.password_set ? 'Stored' : 'Not set' }}</span>
          </div>
        </div>

        <!-- Test result feedback -->
        <div v-if="pageTestResult" class="mt-3 flex items-start gap-2 text-xs" :class="pageTestResult.ok ? 'text-success' : 'text-error'">
          <component :is="pageTestResult.ok ? CheckCircle : XCircle" class="size-3.5 mt-0.5 shrink-0" />
          {{ pageTestResult.message }}
        </div>

        <Well class="mt-4 text-sm text-muted">
          DANE verification is disabled when using a relay. Deliverability depends on
          your provider's IP reputation and correct SPF/DKIM configuration.
        </Well>
      </template>

      <!-- Direct delivery -->
      <template v-else>
        <div class="flex items-start justify-between gap-4 mb-4">
          <div>
            <div class="flex items-center gap-2 mb-1">
              <span class="text-sm font-semibold">Direct delivery</span>
              <Badge variant="default">No relay</Badge>
            </div>
            <p class="text-sm text-muted">Outbound mail is sent directly on port 25 from this server.</p>
          </div>
          <Button variant="secondary" size="sm" @click="openSheet"><Settings2 class="size-3.5" />Configure relay</Button>
        </div>

        <div class="rounded-lg border border-border divide-y divide-border text-sm">
          <div class="px-3 py-2.5">
            <p class="font-medium mb-0.5">Port 25 may be blocked</p>
            <p class="text-muted text-xs">Many cloud providers and ISPs block outbound port 25. If mail is not being delivered, a relay is required.</p>
          </div>
          <div class="px-3 py-2.5">
            <p class="font-medium mb-0.5">IP reputation matters</p>
            <p class="text-muted text-xs">New or residential IPs are often pre-emptively blocked by major providers. A relay with an established sending IP improves deliverability.</p>
          </div>
          <div class="px-3 py-2.5">
            <p class="font-medium mb-0.5">Supported providers</p>
            <p class="text-muted text-xs">{{ Object.values(PROVIDERS).filter(p => p.host).map(p => p.label).join(', ') }}.</p>
          </div>
        </div>
      </template>
    </Card>
    </AsyncState>

    <Sheet v-model="sheetOpen" title="Relay Configuration">
      <div class="space-y-5">
        <Field label="Provider" for="relayProvider">
          <Select id="relayProvider" :model-value="provider" @update:model-value="onProviderChange">
            <option v-for="(preset, id) in PROVIDERS" :key="id" :value="id">{{ preset.label }}</option>
          </Select>
        </Field>

        <template v-if="showFields">
          <div class="grid grid-cols-1 sm:grid-cols-[1fr_100px] gap-4">
            <Field label="SMTP host" for="relayHost">
              <Input id="relayHost" v-model="host" placeholder="smtp.example.com" />
            </Field>
            <Field label="Port" for="relayPort">
              <Input id="relayPort" v-model="port" inputmode="numeric" placeholder="587" />
            </Field>
          </div>

          <Field label="Username" for="relayUser">
            <Input id="relayUser" v-model="user" :placeholder="currentPreset.userPlaceholder || 'Username'" autocomplete="off" />
          </Field>

          <Field label="Password" for="relayPass">
            <Input
              id="relayPass"
              v-model="password"
              type="password"
              :placeholder="current?.password_set ? 'Set - leave blank to keep current' : 'Password'"
              autocomplete="new-password"
            />
          </Field>

          <Field label="SPF include" for="relaySpf">
            <template #label>SPF include <span class="font-normal text-faint">- optional</span></template>
            <Input id="relaySpf" v-model="spfInclude" placeholder="e.g. sendgrid.net" :maxlength="256" />
            <p class="text-xs text-muted mt-1">
              When set, <code class="font-mono break-all">include:{{ spfInclude || 'relay-domain.com' }}</code> is added
              to your auto-generated SPF record. Pre-filled for known providers.
              Leave blank if you manage DNS externally.
            </p>
          </Field>
        </template>

        <template v-if="showFields">
          <div class="flex gap-2">
            <Button variant="secondary" class="flex-1" :disabled="testing || sendingTest || !host" @click="testConnection">
              {{ testing ? 'Testing...' : 'Test Connection' }}
            </Button>
            <Button variant="secondary" class="flex-1" :disabled="testing || sendingTest || (!isActive && !testResult?.ok)" @click="sendTestEmail">
              {{ sendingTest ? 'Sending...' : 'Send Test Email' }}
            </Button>
          </div>
          <Button class="w-full" :disabled="saving" @click="save">
            {{ saving ? 'Saving...' : 'Save Configuration' }}
          </Button>
        </template>
        <Button v-else class="w-full" :disabled="saving" @click="save">
          {{ saving ? 'Saving...' : 'Disable Relay' }}
        </Button>
        <p v-if="testResult" class="text-xs" :class="testResult.ok ? 'text-success' : 'text-error'">
          {{ testResult.message }}
        </p>
      </div>
    </Sheet>
</template>
