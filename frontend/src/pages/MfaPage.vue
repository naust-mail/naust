<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { toast } from 'vue-sonner'
import { KeyRound } from 'lucide-vue-next'
import { startRegistration } from '@simplewebauthn/browser'
import type { PublicKeyCredentialCreationOptionsJSON } from '@simplewebauthn/browser'
import AsyncState from '@/components/ui/AsyncState.vue'
import Button from '@/components/ui/Button.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import SectionHeader from '@/components/ui/SectionHeader.vue'
import Field from '@/components/ui/Field.vue'
import Input from '@/components/ui/Input.vue'
import Card from '@/components/ui/Card.vue'
import Badge from '@/components/ui/Badge.vue'
import Code from '@/components/ui/Code.vue'
import Divider from '@/components/ui/Divider.vue'
import Skeleton from '@/components/ui/Skeleton.vue'
import EmptyState from '@/components/ui/EmptyState.vue'
import Dialog from '@/components/ui/Dialog.vue'
import { api, ApiError } from '@/api/client'
import type {
  EnableTOTPRequest,
  MFACredential,
  MFAStateResponse,
  TOTPSetupResponse,
  WebAuthnBeginResponse,
  WebAuthnRegisterCompleteRequest,
} from '@/api/types.gen'

const loading = ref(true)
const loadError = ref(false)
const totpEntries = ref<MFACredential[]>([])
const passkeyEntries = ref<MFACredential[]>([])

// TOTP enrollment: setup is requested on demand; nothing is stored
// server-side until the enable call proves the app produces codes.
const totpSetup = ref<TOTPSetupResponse | null>(null)
const settingUp = ref(false)
const enrollLabel = ref('')
const enrollToken = ref('')
const enrolling = ref(false)

// Disable confirm state
const disableOpen = ref(false)
const disableTarget = ref<MFACredential | null>(null)
const disabling = ref(false)

const disableDescription = computed(() => {
  if (disableTarget.value?.type === 'totp') {
    return 'Logins will no longer require a one-time code.'
  }
  return `Remove "${disableTarget.value?.label || 'this passkey'}"? You will no longer be able to sign in with it.`
})

// Passkey add state
const showAddPasskey = ref(false)
const passkeyName = ref('')
const addingPasskey = ref(false)

const enrollTokenValid = computed(() => /^\d{6}$/.test(enrollToken.value.trim()))

// Discrete view keys so the whole card body can crossfade as one block
// when list/empty/form visibility flips, instead of each piece popping
// in and out on its own with no transition.
const passkeyViewKey = computed(() => `${passkeyEntries.value.length > 0}-${showAddPasskey.value}`)
const totpViewKey = computed(() => `${totpEntries.value.length > 0}-${!!totpSetup.value}`)

async function load(): Promise<void> {
  loading.value = true
  loadError.value = false
  try {
    const resp = await api.get<MFAStateResponse>('/api/auth/mfa')
    const creds = resp.credentials ?? []
    totpEntries.value = creds.filter(c => c.type === 'totp')
    passkeyEntries.value = creds.filter(c => c.type === 'webauthn')
    totpSetup.value = null
    enrollToken.value = ''
    enrollLabel.value = ''
  } catch {
    loadError.value = true
    toast.error('Failed to load MFA status.')
  } finally {
    loading.value = false
  }
}

async function startTotpSetup(): Promise<void> {
  if (settingUp.value) return
  settingUp.value = true
  try {
    totpSetup.value = await api.post<TOTPSetupResponse>('/api/auth/totp/setup')
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : 'Failed to start TOTP setup.')
  } finally {
    settingUp.value = false
  }
}

async function enableTotp(): Promise<void> {
  if (!enrollTokenValid.value || !totpSetup.value || enrolling.value) return
  enrolling.value = true
  try {
    const req: EnableTOTPRequest = {
      secret: totpSetup.value.secret,
      code: enrollToken.value.trim(),
      label: enrollLabel.value,
    }
    await api.post('/api/auth/totp/enable', req)
    toast.success('Two-factor authentication enabled.')
    await load()
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : 'Failed to enable TOTP.')
  } finally {
    enrolling.value = false
  }
}

function openDisable(entry: MFACredential): void {
  disableTarget.value = entry
  disableOpen.value = true
}

async function confirmDisable(): Promise<void> {
  if (!disableTarget.value || disabling.value) return
  disabling.value = true
  try {
    await api.del(`/api/auth/mfa/${disableTarget.value.type}/${disableTarget.value.id}`)
    disableOpen.value = false
    toast.success(disableTarget.value.type === 'totp' ? 'Two-factor authentication disabled.' : 'Passkey removed.')
    await load()
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : 'Failed to remove credential.')
  } finally {
    disabling.value = false
  }
}

async function addPasskey(): Promise<void> {
  if (!passkeyName.value.trim() || addingPasskey.value) return
  addingPasskey.value = true
  try {
    const begin = await api.post<WebAuthnBeginResponse>('/api/auth/webauthn/register/begin')
    const options = begin.options as { publicKey: PublicKeyCredentialCreationOptionsJSON }
    const credential = await startRegistration({ optionsJSON: options.publicKey })

    const complete: WebAuthnRegisterCompleteRequest = {
      nonce: begin.nonce,
      name: passkeyName.value.trim(),
      credential,
    }
    await api.post('/api/auth/webauthn/register/complete', complete)

    toast.success('Passkey added.')
    passkeyName.value = ''
    showAddPasskey.value = false
    await load()
  } catch (e) {
    if (e instanceof ApiError) {
      toast.error(e.message)
    } else if (e instanceof Error && e.name !== 'NotAllowedError') {
      toast.error('Failed to add passkey.')
    }
  } finally {
    addingPasskey.value = false
  }
}

onMounted(load)
</script>

<template>
    <PageHeader title="Two-Factor Authentication" description="Protect your admin account with a second login step." />

    <AsyncState :loading="loading" :error="loadError" :empty="false" error-title="Could not load MFA settings" @retry="load">
      <template #loading>
        <SectionHeader title="Passkeys" />
        <Card padding="md" class="mb-6">
          <Skeleton class="h-4 w-48 mb-3"/>
          <Skeleton class="h-9 w-32"/>
        </Card>
        <SectionHeader title="Authenticator App (TOTP)" />
        <Card padding="md">
          <Skeleton class="h-4 w-64 mb-3"/>
          <Skeleton class="h-9 w-40"/>
        </Card>
      </template>

      <!-- Passkeys Section -->
      <SectionHeader title="Passkeys" />
      <Card padding="md" class="mb-6">
        <div class="relative overflow-hidden">
        <Transition name="crossfade">
        <div :key="passkeyViewKey">
        <!-- Existing passkeys -->
        <div v-if="passkeyEntries.length > 0" class="mb-4 divide-y divide-border">
          <div
            v-for="entry in passkeyEntries"
            :key="entry.id"
            class="flex items-center justify-between py-3 first:pt-0 last:pb-0"
          >
            <p class="text-sm font-medium">{{ entry.label || 'Unnamed passkey' }}</p>
            <Button variant="secondary" size="sm" @click="openDisable(entry)">Remove</Button>
          </div>
        </div>

        <!-- Empty state -->
        <EmptyState
          v-else-if="!showAddPasskey"
          title="No passkeys registered"
          description="Passkeys let you sign in with your fingerprint, face, or device PIN."
          class="py-4"
        >
          <template #icon>
            <KeyRound/>
          </template>
          <template #action>
            <Button @click="showAddPasskey = true">Add a passkey</Button>
          </template>
        </EmptyState>

        <!-- Add passkey button (when passkeys exist) -->
        <template v-if="passkeyEntries.length > 0 && !showAddPasskey">
          <Divider class="mt-4" />
          <div class="pt-4">
            <Button variant="secondary" @click="showAddPasskey = true">Add a passkey</Button>
          </div>
        </template>

        <!-- Add passkey form -->
        <template v-if="showAddPasskey">
          <Divider v-if="passkeyEntries.length > 0" class="mt-4"/>
          <div :class="{ 'pt-4': passkeyEntries.length > 0 }">
            <label for="passkeyName" class="block text-sm font-medium mb-2">Name this passkey:</label>
            <div class="flex gap-2 max-w-sm">
              <Input id="passkeyName" v-model="passkeyName" placeholder="e.g. My MacBook"/>
              <Button :disabled="!passkeyName.trim() || addingPasskey" @click="addPasskey">
                {{ addingPasskey ? 'Adding...' : 'Add' }}
              </Button>
              <Button variant="ghost" @click="showAddPasskey = false; passkeyName = ''">Cancel</Button>
            </div>
            <p class="text-xs text-muted mt-1.5">Your browser will prompt you to create a passkey.</p>
          </div>
        </template>
        </div>
        </Transition>
        </div>
      </Card>

      <!-- TOTP Section -->
      <SectionHeader title="Authenticator App (TOTP)" />
      <Card padding="md">
        <div class="relative overflow-hidden">
        <Transition name="crossfade">
        <div :key="totpViewKey">
        <!-- TOTP active -->
        <template v-if="totpEntries.length > 0">
          <div v-for="entry in totpEntries" :key="entry.id" class="flex items-center justify-between">
            <div class="flex items-center gap-3">
              <Badge variant="success">Active</Badge>
              <div>
                <p class="text-sm font-medium">{{ entry.label || 'Authenticator app' }}</p>
                <p class="text-xs text-muted mt-0.5">A 6-digit code is required at login.</p>
              </div>
            </div>
            <Button variant="destructive" size="sm" @click="openDisable(entry)">Disable</Button>
          </div>
        </template>

        <!-- Offer setup -->
        <EmptyState
          v-else-if="!totpSetup"
          title="No authenticator app configured"
          description="Require a 6-digit code from your phone at every password login."
          class="py-4"
        >
          <template #action>
            <Button :disabled="settingUp" @click="startTotpSetup">
              {{ settingUp ? 'Preparing...' : 'Set up authenticator' }}
            </Button>
          </template>
        </EmptyState>

        <!-- TOTP setup form -->
        <template v-else>
          <p class="text-sm text-muted mb-5">
            Use <a href="https://freeotp.github.io/" target="_blank" rel="noopener"
                   class="underline underline-offset-2">FreeOTP</a>,
            Google Authenticator, or any TOTP app.
          </p>

          <div class="space-y-6">
            <!-- Step 1: secret -->
            <div class="flex gap-5 items-start">
              <Badge class="flex-none mt-0.5 size-6 justify-center rounded-full px-0">1</Badge>
              <div class="min-w-0">
                <p class="text-sm font-medium mb-2">Add the account to your app</p>
                <p class="text-xs text-muted mb-1">
                  On this device,
                  <a :href="totpSetup.otpauth_uri" class="underline underline-offset-2">open in your authenticator app</a>.
                  Elsewhere, enter the secret manually:
                </p>
                <Code block class="max-w-xs break-all">{{ totpSetup.secret }}</Code>
              </div>
            </div>

            <!-- Step 2: Label -->
            <div class="flex gap-5 items-start">
              <Badge class="flex-none mt-0.5 size-6 justify-center rounded-full px-0">2</Badge>
              <Field for="enrollLabel" class="w-full max-w-xs">
                <template #label>Label this device <span class="font-normal text-faint">(optional)</span></template>
                <Input id="enrollLabel" v-model="enrollLabel" placeholder="e.g. my phone"/>
              </Field>
            </div>

            <!-- Step 3: Verify -->
            <div class="flex gap-5 items-start">
              <Badge class="flex-none mt-0.5 size-6 justify-center rounded-full px-0">3</Badge>
              <Field label="Enter the 6-digit code from your app" for="enrollToken" class="w-full">
                <div class="flex gap-2 items-center max-w-xs">
                  <Input
                    id="enrollToken"
                    v-model="enrollToken"
                    inputmode="numeric"
                    :maxlength="6"
                    placeholder="000000"
                    class="font-mono tracking-widest text-center"
                  />
                  <Button :disabled="!enrollTokenValid || enrolling" @click="enableTotp">
                    {{ enrolling ? 'Enabling...' : 'Enable' }}
                  </Button>
                </div>
                <p class="text-xs text-muted mt-1.5">Nothing is saved until the code verifies.</p>
              </Field>
            </div>
          </div>
        </template>
        </div>
        </Transition>
        </div>
      </Card>
    </AsyncState>

    <!-- Disable confirm dialog -->
    <Dialog
      v-model="disableOpen"
      :title="disableTarget?.type === 'totp' ? 'Disable TOTP?' : 'Remove passkey?'"
      :description="disableDescription"
    >
      <template #actions>
        <Button variant="secondary" @click="disableOpen = false">Cancel</Button>
        <Button variant="destructive" :disabled="disabling" @click="confirmDisable">
          {{ disabling ? 'Removing...' : disableTarget?.type === 'totp' ? 'Disable' : 'Remove' }}
        </Button>
      </template>
    </Dialog>
</template>
