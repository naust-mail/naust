<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { toast } from 'vue-sonner'
import { KeyRound, WifiOff } from 'lucide-vue-next'
import { startRegistration } from '@simplewebauthn/browser'
import AppLayout from '@/components/layout/AppLayout.vue'
import Button from '@/components/ui/Button.vue'
import Input from '@/components/ui/Input.vue'
import Card from '@/components/ui/Card.vue'
import Badge from '@/components/ui/Badge.vue'
import Code from '@/components/ui/Code.vue'
import Divider from '@/components/ui/Divider.vue'
import Skeleton from '@/components/ui/Skeleton.vue'
import EmptyState from '@/components/ui/EmptyState.vue'
import Dialog from '@/components/ui/Dialog.vue'
import { useApi } from '@/composables/useApi'
import { useAuthStore } from '@/stores/auth'
import { useRouter } from 'vue-router'
import type { MfaEntry, MfaStatus, TotpProvision } from '@/types'

const api = useApi()
const auth = useAuthStore()
const router = useRouter()

const loading = ref(true)
const loadError = ref(false)
const totpEntries = ref<MfaEntry[]>([])
const passkeyEntries = ref<MfaEntry[]>([])
const totpSetup = ref<TotpProvision | null>(null)

// TOTP enroll state
const enrollLabel = ref('')
const enrollToken = ref('')
const enrolling = ref(false)

// TOTP/entry disable state
const disableOpen = ref(false)
const disableTarget = ref<MfaEntry | null>(null)
const disabling = ref(false)

// Passkey add state
const showAddPasskey = ref(false)
const passkeyName = ref('')
const addingPasskey = ref(false)

const enrollTokenValid = computed(() =>
  /^\d{6}$/.test(enrollToken.value.trim()),
)

async function load(): Promise<void> {
  loading.value = true
  loadError.value = false
  try {
    const res = await api.post('/admin/mfa/status')
    if (!res.ok) {
      loadError.value = true;
      toast.error('Failed to load MFA status.');
      return
    }
    const data: MfaStatus = await res.json()
    totpEntries.value = data.enabled_mfa.filter(e => e.type === 'totp')
    passkeyEntries.value = data.enabled_mfa.filter(e => e.type === 'webauthn')
    totpSetup.value = data.new_mfa?.totp ?? null
    enrollToken.value = ''
    enrollLabel.value = ''
  } catch {
    loadError.value = true
    toast.error('Failed to load MFA status.')
  } finally {
    loading.value = false
  }
}

async function enableTotp(): Promise<void> {
  if (!enrollTokenValid.value || !totpSetup.value || enrolling.value) return
  enrolling.value = true
  try {
    const res = await api.post('/admin/mfa/totp/enable', {
      token: enrollToken.value.trim(),
      secret: totpSetup.value.secret,
      label: enrollLabel.value,
    })
    if (!res.ok) {
      toast.error(await res.text())
      return
    }
    toast.success('Two-factor authentication enabled. Please log in again.')
    await auth.logout()
    await router.push('/login')
  } finally {
    enrolling.value = false
  }
}

function openDisable(entry: MfaEntry): void {
  disableTarget.value = entry
  disableOpen.value = true
}

async function confirmDisable(): Promise<void> {
  if (!disableTarget.value || disabling.value) return
  disabling.value = true
  try {
    const body: Record<string, string> = { 'mfa-id': String(disableTarget.value.id) }
    const res = await api.post('/admin/mfa/disable', body)
    if (!res.ok) {
      toast.error(await res.text())
      return
    }
    const isTotp = disableTarget.value.type === 'totp'
    disableOpen.value = false

    if (isTotp) {
      toast.success('Two-factor authentication disabled. Please log in again.')
      await auth.logout()
      await router.push('/login')
    } else {
      toast.success('Passkey removed.')
      await load()
    }
  } finally {
    disabling.value = false
  }
}

async function addPasskey(): Promise<void> {
  if (!passkeyName.value.trim() || addingPasskey.value) return
  addingPasskey.value = true
  try {
    const beginRes = await api.post('/admin/mfa/webauthn/register/begin')
    if (!beginRes.ok) {
      toast.error(await beginRes.text());
      return
    }
    const { options, nonce } = await beginRes.json()

    const credential = await startRegistration({ optionsJSON: options.publicKey })

    const completeRes = await api.post('/admin/mfa/webauthn/register/complete', {
      nonce,
      name: passkeyName.value.trim(),
      credential: JSON.stringify(credential),
    })
    if (!completeRes.ok) {
      toast.error(await completeRes.text());
      return
    }

    toast.success('Passkey added.')
    passkeyName.value = ''
    showAddPasskey.value = false
    await load()
  } catch (e) {
    if (e instanceof Error && e.name !== 'NotAllowedError') {
      toast.error('Failed to add passkey.')
    }
  } finally {
    addingPasskey.value = false
  }
}

onMounted(load)
</script>

<template>
  <AppLayout>
    <h1 class="text-2xl font-semibold mb-6">Two-Factor Authentication</h1>

    <p class="text-sm text-gray-500 mb-6 max-w-2xl">
      Two-factor authentication adds an extra layer of security to this control panel.
      It does not protect email access - use a strong password for that.
    </p>

    <!-- Top-level error state replaces both cards -->
    <EmptyState
      v-if="loadError"
      title="Could not load MFA settings"
      description="The server did not respond. Check your connection and try again."
    >
      <template #icon>
        <WifiOff/>
      </template>
      <template #action>
        <Button variant="secondary" @click="load">Try again</Button>
      </template>
    </EmptyState>

    <template v-else>
      <!-- Passkeys Section -->
      <h2 class="text-base font-semibold mb-3">Passkeys</h2>
      <Card class="p-5 mb-6">
        <template v-if="loading">
          <Skeleton class="h-4 w-48 mb-3"/>
          <Skeleton class="h-9 w-32"/>
        </template>

        <template v-else>
          <!-- Existing passkeys -->
          <div v-if="passkeyEntries.length > 0" class="mb-4 divide-y divide-gray-100 dark:divide-gray-800">
            <div
              v-for="entry in passkeyEntries"
              :key="entry.id"
              class="flex items-center justify-between py-3 first:pt-0 last:pb-0"
            >
              <div>
                <p class="text-sm font-medium">{{ entry.name || 'Unnamed passkey' }}</p>
                <p v-if="entry.last_used" class="text-xs text-gray-500 mt-0.5">Last used {{ entry.last_used }}</p>
                <p v-else class="text-xs text-gray-500 mt-0.5">Never used</p>
              </div>
              <Button variant="ghost" size="sm" @click="openDisable(entry)">Remove</Button>
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
              <p class="text-xs text-gray-500 mt-1.5">Your browser will prompt you to create a passkey.</p>
            </div>
          </template>
        </template>
      </Card>

      <!-- TOTP Section -->
      <h2 class="text-base font-semibold mb-3">Authenticator App (TOTP)</h2>
      <Card class="p-5">
        <template v-if="loading">
          <Skeleton class="h-4 w-64 mb-3"/>
          <Skeleton class="h-9 w-40"/>
        </template>

        <!-- TOTP active -->
        <template v-else-if="totpEntries.length > 0">
          <div v-for="entry in totpEntries" :key="entry.id" class="flex items-center justify-between">
            <div class="flex items-center gap-3">
              <span class="flex size-2 rounded-full bg-green-500"/>
              <div>
                <p class="text-sm font-medium">Active{{ entry.label ? ` - ${entry.label}` : '' }}</p>
                <p class="text-xs text-gray-500 mt-0.5">A 6-digit code is required at login.</p>
              </div>
            </div>
            <Button variant="destructive" size="sm" @click="openDisable(entry)">Disable</Button>
          </div>
        </template>

        <!-- TOTP setup form -->
        <template v-else-if="totpSetup">
          <p class="text-sm text-gray-500 mb-5">
            Use <a href="https://freeotp.github.io/" target="_blank" rel="noopener"
                   class="underline underline-offset-2">FreeOTP</a>,
            Google Authenticator, or any TOTP app.
          </p>

          <div class="space-y-6">
            <!-- Step 1: QR code -->
            <div class="flex gap-5 items-start">
              <Badge class="flex-none mt-0.5 size-6 justify-center rounded-full px-0">1</Badge>
              <div>
                <p class="text-sm font-medium mb-3">Scan the QR code with your app</p>
                <Card class="inline-flex p-3 mb-3">
                  <img
                    :src="`data:image/png;base64,${totpSetup.qr_code_base64}`"
                    alt="QR code for TOTP setup"
                    class="w-40 h-40"
                  />
                </Card>
                <p class="text-xs text-gray-500 mb-1">Or enter the secret manually:</p>
                <Code block class="max-w-xs">{{ totpSetup.secret }}</Code>
              </div>
            </div>

            <!-- Step 2: Label -->
            <div class="flex gap-5 items-start">
              <Badge class="flex-none mt-0.5 size-6 justify-center rounded-full px-0">2</Badge>
              <div class="w-full max-w-xs">
                <label for="enrollLabel" class="block text-sm font-medium mb-1.5">
                  Label this device <span class="font-normal text-gray-400">(optional)</span>
                </label>
                <Input id="enrollLabel" v-model="enrollLabel" placeholder="e.g. my phone"/>
              </div>
            </div>

            <!-- Step 3: Verify -->
            <div class="flex gap-5 items-start">
              <Badge class="flex-none mt-0.5 size-6 justify-center rounded-full px-0">3</Badge>
              <div class="w-full">
                <label for="enrollToken" class="block text-sm font-medium mb-1.5">Enter the 6-digit code from your
                  app</label>
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
                <p class="text-xs text-gray-500 mt-1.5">You will be logged out after enabling.</p>
              </div>
            </div>
          </div>
        </template>
      </Card>
    </template>

    <!-- Disable confirm dialog -->
    <Dialog
      v-model="disableOpen"
      :title="disableTarget?.type === 'totp' ? 'Disable TOTP?' : 'Remove passkey?'"
      :description="disableTarget?.type === 'totp'
        ? 'You will be logged out and can log back in without a one-time code.'
        : `Remove &quot;${disableTarget?.name || 'this passkey'}&quot;? You will no longer be able to sign in with it.`"
    >
      <template #actions>
        <Button variant="secondary" @click="disableOpen = false">Cancel</Button>
        <Button variant="destructive" :disabled="disabling" @click="confirmDisable">
          {{ disabling ? 'Removing...' : disableTarget?.type === 'totp' ? 'Disable' : 'Remove' }}
        </Button>
      </template>
    </Dialog>
  </AppLayout>
</template>
