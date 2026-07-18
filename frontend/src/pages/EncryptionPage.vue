<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue'
import { toast } from 'vue-sonner'
import { LockKeyhole, Copy, AlertTriangle, KeyRound } from 'lucide-vue-next'
import { startAuthentication } from '@simplewebauthn/browser'
import type { PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/browser'
import AsyncState from '@/components/ui/AsyncState.vue'
import Button from '@/components/ui/Button.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import SectionHeader from '@/components/ui/SectionHeader.vue'
import Field from '@/components/ui/Field.vue'
import Input from '@/components/ui/Input.vue'
import Card from '@/components/ui/Card.vue'
import Badge from '@/components/ui/Badge.vue'
import Code from '@/components/ui/Code.vue'
import Skeleton from '@/components/ui/Skeleton.vue'
import EmptyState from '@/components/ui/EmptyState.vue'
import Sheet from '@/components/ui/Sheet.vue'
import { api, ApiError } from '@/api/client'
import type {
  EncryptionChallengeRequest,
  EncryptionPRFCompleteRequest,
  EncryptionRelinkRequest,
  EncryptionSetupRequest,
  EncryptionSetupResponse,
  EncryptionStatusResponse,
  WebAuthnBeginResponse,
} from '@/api/types.gen'

const loading = ref(true)
const loadError = ref(false)
// The server itself has encryption at rest turned off (GET returns 404).
const serverOff = ref(false)
const status = ref<EncryptionStatusResponse | null>(null)

// The ceremony lives in a Sheet. Stages:
//   password  - destructive warning + confirm current password
//   codes     - recovery codes generated, waiting for user to confirm they saved them
//   challenge - user must re-enter one specific code to prove they saved it
const sheetOpen = ref(false)
// 'setup' = initial encryption enable, 'rotate' = replace recovery codes
const mode = ref<'setup' | 'rotate'>('setup')
const stage = ref<'password' | 'codes' | 'challenge'>('password')
const password = ref('')
const starting = ref(false)
const recoveryCodes = ref<string[]>([])
// Which code (1-based display) we ask the user to re-enter. Chosen client-side at random.
const challengeIndex = ref(1)
const challengeCode = ref('')
const submitting = ref(false)

// Re-link state (recover the password slot after a password change/reset).
const relinkOpen = ref(false)
const relinkCode = ref('')
const relinkPassword = ref('')
const relinking = ref(false)
// Shown after a successful re-link to prompt the user to rotate their codes.
const showRotatePrompt = ref(false)

// Passkey (PRF) ceremony state: enroll a passkey as an unlock method,
// or re-link the password slot using an already-enrolled passkey.
const prfOpen = ref(false)
const prfMode = ref<'enroll' | 'relink'>('enroll')
const prfPassword = ref('')
const prfBusy = ref(false)

const enabled = computed(() => status.value?.enabled === true)
const hasPrfSlot = computed(() => status.value?.has_prf_slot === true)

const SLOT_LABELS: Record<string, string> = {
  password: 'Login password',
  recovery_code: 'Recovery code',
  passkey_prf: 'Passkey',
}

// Wipe any secrets held in memory whenever the ceremony sheet closes.
watch(sheetOpen, (open) => {
  if (!open) {
    password.value = ''
    recoveryCodes.value = []
    challengeCode.value = ''
    stage.value = 'password'
  }
})

// Client-side recovery-code CRC (mirrors the server's Crockford check).
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'

function normalizeCode(code: string): string {
  return code.trim().toUpperCase().replace(/[-\s]/g, '')
    .replace(/O/g, '0').replace(/I/g, '1').replace(/L/g, '1')
}

function validateCrc(code: string): boolean {
  const s = normalizeCode(code)
  if (s.length !== 16) return false
  const values: number[] = []
  for (const ch of s) {
    const v = CROCKFORD.indexOf(ch)
    if (v < 0) return false
    values.push(v)
  }
  const data = values.slice(0, 15)
  const cs = data.reduce((acc, v, i) => acc + v * (i + 1), 0) % 37
  if (cs >= 32) return false
  return CROCKFORD[cs] === s[15]
}

const challengeCodeValid = computed(() => validateCrc(challengeCode.value))
const challengeOrdinal = computed(() => {
  const n = challengeIndex.value
  return n === 1 ? '1st' : n === 2 ? '2nd' : n === 3 ? '3rd' : `${n}th`
})

async function load(): Promise<void> {
  loading.value = true
  loadError.value = false
  serverOff.value = false
  try {
    status.value = await api.get<EncryptionStatusResponse>('/api/user/encryption/status')
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) {
      serverOff.value = true
    } else {
      loadError.value = true
    }
  } finally {
    loading.value = false
  }
}

function openCeremony(m: 'setup' | 'rotate'): void {
  mode.value = m
  password.value = ''
  recoveryCodes.value = []
  challengeCode.value = ''
  stage.value = 'password'
  sheetOpen.value = true
}

async function startSetup(): Promise<void> {
  if (!password.value || starting.value) return
  starting.value = true
  try {
    const endpoint = mode.value === 'rotate'
      ? '/api/user/encryption/rotate-recovery'
      : '/api/user/encryption/setup'
    const req: EncryptionSetupRequest = { password: password.value }
    const data = await api.post<EncryptionSetupResponse>(endpoint, req)
    recoveryCodes.value = data.recovery_codes ?? []
    password.value = ''
    stage.value = 'codes'
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : 'Could not start the ceremony.')
  } finally {
    starting.value = false
  }
}

async function copyCodes(): Promise<void> {
  try {
    await navigator.clipboard.writeText(recoveryCodes.value.join('\n'))
    toast.success('Recovery codes copied to clipboard.')
  } catch {
    toast.error('Could not copy. Select and copy the codes manually.')
  }
}

function confirmSaved(): void {
  // Pick a random code for the challenge so users cannot blindly click through.
  challengeIndex.value = Math.floor(Math.random() * recoveryCodes.value.length) + 1
  challengeCode.value = ''
  stage.value = 'challenge'
}

async function submitChallenge(): Promise<void> {
  if (submitting.value) return
  if (!validateCrc(challengeCode.value)) {
    toast.error('That does not look like a valid recovery code. Check for typos.')
    return
  }
  submitting.value = true
  try {
    const endpoint = mode.value === 'rotate'
      ? '/api/user/encryption/rotate-recovery-confirm'
      : '/api/user/encryption/challenge'
    // challengeIndex is 1-based for display; the server indexes from 0.
    const req: EncryptionChallengeRequest = {
      code_index: challengeIndex.value - 1,
      code: challengeCode.value,
    }
    await api.post(endpoint, req)
    sheetOpen.value = false
    if (mode.value === 'rotate') {
      showRotatePrompt.value = false
      toast.success('Recovery codes rotated. Keep your new codes safe.')
    } else {
      toast.success('Encryption at rest is now enabled.')
      await load()
    }
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : 'Verification failed.')
  } finally {
    submitting.value = false
  }
}

const relinkCodeValid = computed(() => validateCrc(relinkCode.value))

// Wipe re-link secrets when its sheet closes.
watch(relinkOpen, (open) => {
  if (!open) {
    relinkCode.value = ''
    relinkPassword.value = ''
  }
})

async function submitRelink(): Promise<void> {
  if (relinking.value) return
  if (!validateCrc(relinkCode.value)) {
    toast.error('That does not look like a valid recovery code. Check for typos.')
    return
  }
  if (!relinkPassword.value) {
    toast.error('Enter your current password.')
    return
  }
  relinking.value = true
  try {
    const req: EncryptionRelinkRequest = {
      code: relinkCode.value,
      password: relinkPassword.value,
    }
    await api.post('/api/user/encryption/relink', req)
    relinkOpen.value = false
    showRotatePrompt.value = true
    toast.success('Encryption re-linked. Your password now unlocks your mail again.')
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : 'Re-link failed.')
  } finally {
    relinking.value = false
  }
}

// Passkey (PRF) ceremony.

function b64urlToBuffer(s: string): ArrayBuffer {
  const pad = '='.repeat((4 - (s.length % 4)) % 4)
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return bytes.buffer
}

function bufferToB64url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf)
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

// The server sends prf eval salts base64url-encoded (WebAuthn JSON
// encoding) and reads the prf result from an explicit prf_output
// field: simplewebauthn passes extensions through untouched, so the
// salts are converted to buffers here, and the raw ArrayBuffer result
// is read from getClientExtensionResults() and re-encoded.
type PRFEvalInput = { first: string }
type PRFExtensionInput = { eval?: PRFEvalInput; evalByCredential?: Record<string, PRFEvalInput> }
type PRFExtensionOutput = { prf?: { results?: { first?: ArrayBuffer } } }

async function runPrfCeremony(purpose: 'enroll' | 'relink', pw: string): Promise<void> {
  const base = `/api/user/encryption/prf/${purpose}`
  const begin = await api.post<WebAuthnBeginResponse>(`${base}/begin`)
  const options = begin.options as { publicKey: PublicKeyCredentialRequestOptionsJSON }
  const prf = (options.publicKey.extensions as { prf?: PRFExtensionInput } | undefined)?.prf
  if (prf?.eval) {
    (prf.eval as unknown as { first: BufferSource }).first = b64urlToBuffer(prf.eval.first)
  }
  if (prf?.evalByCredential) {
    for (const id of Object.keys(prf.evalByCredential)) {
      const entry = prf.evalByCredential[id]
      if (entry) (entry as unknown as { first: BufferSource }).first = b64urlToBuffer(entry.first)
    }
  }
  const credential = await startAuthentication({ optionsJSON: options.publicKey })
  const extResults = credential.clientExtensionResults as PRFExtensionOutput
  const first = extResults.prf?.results?.first
  if (!first) throw new Error('prf-unsupported')
  const prfOutput = bufferToB64url(first)
  // The raw ArrayBuffer result does not survive JSON; drop it before
  // the credential is sent.
  delete extResults.prf
  const req: EncryptionPRFCompleteRequest = {
    nonce: begin.nonce,
    credential,
    prf_output: prfOutput,
    password: pw,
  }
  await api.post(`${base}/complete`, req)
}

function openPrf(m: 'enroll' | 'relink'): void {
  prfMode.value = m
  prfPassword.value = ''
  prfOpen.value = true
}

watch(prfOpen, (open) => {
  if (!open) prfPassword.value = ''
})

async function submitPrf(): Promise<void> {
  if (!prfPassword.value || prfBusy.value) return
  prfBusy.value = true
  try {
    await runPrfCeremony(prfMode.value, prfPassword.value)
    prfOpen.value = false
    if (prfMode.value === 'enroll') {
      toast.success('Passkey enrolled. It can now unlock your encrypted mail.')
      await load()
    } else {
      toast.success('Encryption re-linked. Your password now unlocks your mail again.')
    }
  } catch (e) {
    if (e instanceof ApiError) {
      toast.error(e.message)
    } else if ((e as Error).message === 'prf-unsupported') {
      toast.error('This passkey does not support encryption (PRF). Try a different passkey.')
    } else if ((e as Error).name !== 'NotAllowedError') {
      toast.error('Passkey ceremony failed. Please try again.')
    }
  } finally {
    prfBusy.value = false
  }
}

onMounted(load)
</script>

<template>
    <PageHeader title="Encryption at Rest" description="Encrypt your mailbox with a key only you can unlock." />

    <AsyncState :loading="loading" :error="loadError" :empty="false" error-title="Could not load encryption settings" @retry="load">
      <template #loading>
        <SectionHeader title="Status" />
        <Card padding="lg">
          <Skeleton class="size-12 rounded-full mb-4" />
          <Skeleton class="h-5 w-56 mb-2" />
          <Skeleton class="h-4 w-80 mb-4" />
          <Skeleton class="h-5 w-24" />
        </Card>
      </template>

      <!-- Feature disabled server-wide -->
      <EmptyState
        v-if="serverOff"
        bordered
        title="Not available on this server"
        description="Encryption at rest is not enabled on this server. Ask your administrator about turning it on."
      >
        <template #icon><LockKeyhole /></template>
      </EmptyState>

      <template v-else>
        <SectionHeader title="Status" />

        <!-- Enabled -->
        <Card v-if="enabled" padding="lg">
          <div class="flex items-start gap-5">
            <div class="flex-none size-12 rounded-full bg-success-bg flex items-center justify-center">
              <LockKeyhole class="size-6 text-success" />
            </div>
            <div class="min-w-0">
              <div class="flex items-center gap-2 mb-1">
                <p class="text-base font-semibold text-text">Your mailbox is encrypted at rest</p>
                <Badge variant="success">Enabled</Badge>
              </div>
              <p class="text-sm text-muted mb-4">
                Your mail is unlocked with your login password. Keep your recovery codes safe -
                they are the only other way to unlock it if you lose access.
              </p>
              <div v-if="status?.slot_types?.length" class="flex flex-wrap gap-1.5">
                <span class="text-xs text-muted mr-1 self-center">Active unlock methods:</span>
                <Badge v-for="t in status.slot_types" :key="t" variant="default">{{ SLOT_LABELS[t] ?? t }}</Badge>
              </div>
            </div>
          </div>
        </Card>

        <!-- Actions available when encryption is enabled -->
        <template v-if="enabled">
          <SectionHeader title="Passkey unlock" class="mt-8" />
          <Card padding="md">
            <template v-if="hasPrfSlot">
              <p class="text-sm text-muted mb-4">
                A passkey is enrolled as an unlock method. If your password is ever reset,
                that passkey can restore access to your mail without a recovery code.
                You can enroll additional passkeys.
              </p>
            </template>
            <template v-else>
              <p class="text-sm text-muted mb-4">
                Enroll a passkey as an unlock method. If an administrator ever resets your
                password, the passkey can restore access to your encrypted mail without
                typing a recovery code. Requires a passkey registered on your account.
              </p>
            </template>
            <Button variant="secondary" @click="openPrf('enroll')">
              <KeyRound class="size-4" /> {{ hasPrfSlot ? 'Enroll another passkey' : 'Enroll a passkey' }}
            </Button>
          </Card>

          <SectionHeader title="Recover access" class="mt-8" />
          <Card padding="md">
            <p class="text-sm text-muted mb-4">
              If your password was changed or reset, your login may no longer unlock your encrypted mail.
              Re-link it to restore access - this does not change your recovery codes.
            </p>
            <div class="flex flex-wrap gap-2">
              <Button variant="secondary" @click="relinkOpen = true">Re-link with a recovery code</Button>
              <Button v-if="hasPrfSlot" variant="secondary" @click="openPrf('relink')">Re-link with your passkey</Button>
            </div>
          </Card>

          <SectionHeader title="Recovery codes" class="mt-8" />
          <Card padding="md">
            <div v-if="showRotatePrompt" class="flex gap-3 rounded-lg border border-warning-border bg-warning-bg p-4 mb-4">
              <AlertTriangle class="size-5 flex-none text-warning mt-0.5" />
              <p class="text-sm text-muted">
                You used a recovery code to re-link.
                <span class="font-medium text-text">Generate a new set now</span>
                so your old codes cannot be reused by someone who may have seen them.
              </p>
            </div>
            <p class="text-sm text-muted mb-4">
              Your 4 recovery codes are the only way to unlock your mail if you forget your password.
              Rotate them if you think any code was exposed.
            </p>
            <Button variant="secondary" @click="openCeremony('rotate')">Generate new recovery codes</Button>
          </Card>
        </template>

        <!-- Not enabled -->
        <EmptyState
          v-else
          bordered
          title="Encryption at rest is off"
          description="Enable it to encrypt your mailbox with a key derived from your login password. You will be given recovery codes to store safely."
        >
          <template #icon><LockKeyhole /></template>
          <template #action>
            <Button @click="openCeremony('setup')">Enable encryption</Button>
          </template>
        </EmptyState>
      </template>
    </AsyncState>

    <!-- Setup / rotate ceremony (shared sheet, mode-aware) -->
    <Sheet v-model="sheetOpen" :title="mode === 'rotate' ? 'Generate new recovery codes' : 'Enable encryption at rest'">
      <!-- Stage: password -->
      <template v-if="stage === 'password'">
        <div v-if="mode === 'setup'" class="flex gap-3 rounded-lg border border-error-border bg-error-bg p-4 mb-5">
          <AlertTriangle class="size-5 flex-none text-error mt-0.5" />
          <div class="text-sm">
            <p class="font-medium text-error mb-1">Read this before you continue.</p>
            <ul class="list-disc pl-4 space-y-1 text-muted">
              <li>Your mail is unlocked by your login password. If you forget it, only a recovery code can restore access.</li>
              <li>If you lose your password <span class="font-medium">and</span> all recovery codes, your mail is permanently unrecoverable. There is no master key.</li>
              <li>If an administrator resets your password, you will need a recovery code to regain access to your mail.</li>
            </ul>
          </div>
        </div>
        <p v-else class="text-sm text-muted mb-5">
          Your current password is needed to unlock your mail key before generating new codes.
          Your old codes will remain valid until you confirm the new ones.
        </p>

        <Field :label="mode === 'rotate' ? 'Current password' : 'Confirm your current password to continue'" for="encPassword">
          <Input
            id="encPassword"
            v-model="password"
            type="password"
            autocomplete="current-password"
            placeholder="Your account password"
          />
        </Field>
      </template>

      <!-- Stage: codes -->
      <template v-else-if="stage === 'codes'">
        <p class="text-sm text-muted mb-4">
          These codes are shown <span class="font-medium text-text">once</span> and cannot be retrieved later.
          Store them somewhere safe and offline. Each code can unlock your mailbox if you forget your password.
        </p>

        <div class="space-y-2 mb-4">
          <div v-for="(code, i) in recoveryCodes" :key="i" class="flex items-center gap-3">
            <span class="text-xs font-mono text-faint w-5 text-right shrink-0">{{ i + 1 }}.</span>
            <Code block class="flex-1 text-center tracking-widest">{{ code }}</Code>
          </div>
        </div>

        <Button variant="secondary" size="sm" @click="copyCodes">
          <Copy class="size-4" /> Copy all
        </Button>
      </template>

      <!-- Stage: challenge -->
      <template v-else-if="stage === 'challenge'">
        <p class="text-sm text-muted mb-4">
          To make sure you saved them correctly, enter recovery code
          <span class="font-medium text-text">#{{ challengeIndex }}</span>.
        </p>
        <Field :label="`Recovery code #${challengeIndex}`" for="challengeCode">
          <Input
            id="challengeCode"
            v-model="challengeCode"
            placeholder="XXXX-XXXX-XXXX-XXXX"
            class="font-mono tracking-widest uppercase"
            autocomplete="off"
          />
          <p class="text-xs text-muted mt-1.5">Enter the {{ challengeOrdinal }} code exactly as shown.</p>
        </Field>
      </template>

      <!-- Footer: stage-specific actions -->
      <template #footer>
        <div class="flex justify-end gap-2">
          <template v-if="stage === 'password'">
            <Button variant="secondary" @click="sheetOpen = false">Cancel</Button>
            <Button :disabled="!password || starting" @click="startSetup">
              {{ starting ? 'Generating...' : 'Continue' }}
            </Button>
          </template>
          <template v-else-if="stage === 'codes'">
            <Button variant="secondary" @click="sheetOpen = false">Cancel</Button>
            <Button @click="confirmSaved">I have saved my codes</Button>
          </template>
          <template v-else>
            <Button variant="ghost" @click="stage = 'codes'">Back</Button>
            <Button :disabled="!challengeCodeValid || submitting" @click="submitChallenge">
              {{ submitting ? 'Verifying...' : 'Confirm' }}
            </Button>
          </template>
        </div>
      </template>
    </Sheet>

    <!-- Re-link ceremony (recovery code) -->
    <Sheet v-model="relinkOpen" title="Re-link encryption">
      <p class="text-sm text-muted mb-5">
        Enter one of your recovery codes and your <span class="font-medium text-text">current</span> password.
        We will unlock your mail key with the recovery code and re-attach it to your current password.
      </p>
      <div class="space-y-4">
        <Field label="Recovery code" for="relinkCode">
          <Input
            id="relinkCode"
            v-model="relinkCode"
            placeholder="XXXX-XXXX-XXXX-XXXX"
            class="font-mono tracking-widest uppercase"
            autocomplete="off"
          />
        </Field>
        <Field label="Current password" for="relinkPassword">
          <Input
            id="relinkPassword"
            v-model="relinkPassword"
            type="password"
            autocomplete="current-password"
            placeholder="Your current account password"
          />
        </Field>
      </div>
      <template #footer>
        <div class="flex justify-end gap-2">
          <Button variant="secondary" @click="relinkOpen = false">Cancel</Button>
          <Button :disabled="!relinkCodeValid || !relinkPassword || relinking" @click="submitRelink">
            {{ relinking ? 'Re-linking...' : 'Re-link' }}
          </Button>
        </div>
      </template>
    </Sheet>

    <!-- Passkey (PRF) ceremony: enroll or re-link -->
    <Sheet v-model="prfOpen" :title="prfMode === 'enroll' ? 'Enroll a passkey' : 'Re-link with your passkey'">
      <p v-if="prfMode === 'enroll'" class="text-sm text-muted mb-5">
        Your password unlocks your mail key so the passkey can be added as an unlock
        method. Your browser will then ask you to use your passkey.
      </p>
      <p v-else class="text-sm text-muted mb-5">
        Your enrolled passkey unlocks your mail key, and it is re-attached to your
        <span class="font-medium text-text">current</span> password.
        Your browser will ask you to use your passkey.
      </p>
      <Field :label="prfMode === 'enroll' ? 'Confirm your password' : 'Current password'" for="prfPassword">
        <Input
          id="prfPassword"
          v-model="prfPassword"
          type="password"
          autocomplete="current-password"
          placeholder="Your account password"
        />
      </Field>
      <template #footer>
        <div class="flex justify-end gap-2">
          <Button variant="secondary" @click="prfOpen = false">Cancel</Button>
          <Button :disabled="!prfPassword || prfBusy" @click="submitPrf">
            {{ prfBusy ? 'Waiting for passkey...' : 'Continue with passkey' }}
          </Button>
        </div>
      </template>
    </Sheet>
</template>
