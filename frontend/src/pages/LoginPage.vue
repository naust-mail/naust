<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { startAuthentication } from '@simplewebauthn/browser'
import type { PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/browser'
import { toast } from 'vue-sonner'
import { useAuthStore } from '@/stores/auth'
import { api, ApiError } from '@/api/client'
import Button from '@/components/ui/Button.vue'
import Checkbox from '@/components/ui/Checkbox.vue'
import Input from '@/components/ui/Input.vue'
import Card from '@/components/ui/Card.vue'
import PageBackground from '@/components/ui/PageBackground.vue'
import type {
  AuthMethodsResponse,
  LoginResponse,
  WebAuthnBeginResponse,
  WebAuthnLoginCompleteRequest,
} from '@/api/types.gen'

type Step = 'email' | 'password' | 'totp' | 'passkey'

const REMEMBERED_EMAIL_KEY = 'admin_remembered_email'

const router = useRouter()
const auth = useAuthStore()

const email = ref('')
const password = ref('')
const totpToken = ref('')
const rememberEmail = ref(false)
const loading = ref(false)
const step = ref<Step>('email')
const availableMethods = ref<string[]>([])

onMounted(() => {
  const saved = localStorage.getItem(REMEMBERED_EMAIL_KEY)
  if (saved) {
    email.value = saved
    rememberEmail.value = true
  }
})

function saveEmailPreference(): void {
  if (rememberEmail.value) {
    localStorage.setItem(REMEMBERED_EMAIL_KEY, email.value)
  } else {
    localStorage.removeItem(REMEMBERED_EMAIL_KEY)
  }
}

async function finishLogin(): Promise<void> {
  saveEmailPreference()
  await router.push(auth.isAdmin ? '/system-status' : '/mfa')
}

async function continueFromEmail(): Promise<void> {
  if (!email.value || loading.value) return
  loading.value = true
  try {
    const data = await api.get<AuthMethodsResponse>(
      `/api/auth/methods?email=${encodeURIComponent(email.value)}`,
    )
    availableMethods.value = data.methods ?? []
    // The probe is what lets us land on the right form directly:
    // passkey accounts never see a password field, TOTP accounts get
    // the code field up front instead of a failed first attempt.
    if (availableMethods.value.includes('passkey')) {
      step.value = 'passkey'
    } else if (availableMethods.value.includes('password+totp')) {
      step.value = 'totp'
    } else {
      step.value = 'password'
    }
  } catch {
    step.value = 'password'
  } finally {
    loading.value = false
  }
}

async function submitPassword(): Promise<void> {
  if (loading.value) return
  loading.value = true
  try {
    const result = await auth.login(
      email.value,
      password.value,
      step.value === 'totp' ? totpToken.value : undefined,
    )
    if (result === 'ok') {
      await finishLogin()
    } else if (result === 'missing-totp-code') {
      step.value = 'totp'
    } else if (result === 'use-passkey') {
      step.value = 'passkey'
      toast.info('This account signs in with a passkey.')
    } else {
      toast.error(result)
    }
  } catch {
    toast.error('Login failed. Please try again.')
  } finally {
    loading.value = false
  }
}

async function submitPasskey(): Promise<void> {
  if (loading.value) return
  loading.value = true
  try {
    const begin = await api.post<WebAuthnBeginResponse>('/api/auth/webauthn/login/begin', {
      email: email.value,
    })
    const options = begin.options as { publicKey: PublicKeyCredentialRequestOptionsJSON }
    const credential = await startAuthentication({ optionsJSON: options.publicKey })

    const complete: WebAuthnLoginCompleteRequest = {
      nonce: begin.nonce,
      credential,
    }
    const resp = await api.post<LoginResponse>('/api/auth/webauthn/login/complete', complete)
    auth.handleAuthSuccess(resp.user)
    await finishLogin()
  } catch (err) {
    // NotAllowedError is the user dismissing the browser prompt.
    if (err instanceof ApiError) {
      toast.error(err.message)
    } else if ((err as Error).name !== 'NotAllowedError') {
      toast.error('Passkey authentication failed.')
    }
  } finally {
    loading.value = false
  }
}

function backToEmail(): void {
  step.value = 'email'
  password.value = ''
  totpToken.value = ''
  availableMethods.value = []
}
</script>

<template>
  <PageBackground class="flex items-center justify-center p-4">
    <Card padding="lg" class="w-full max-w-sm">
      <h1 class="text-2xl font-semibold text-center mb-1">
        {{ auth.hostname || 'Naust' }}
      </h1>
      <p class="text-sm text-muted text-center mb-7">Control panel</p>

      <div class="relative overflow-hidden">
        <Transition name="crossfade">
          <div :key="step">
            <!-- Email step -->
            <form v-if="step === 'email'" class="space-y-4" @submit.prevent="continueFromEmail">
              <div>
                <label for="loginEmail" class="block text-sm font-medium mb-1.5">Email</label>
                <Input id="loginEmail" v-model="email" type="email" autocomplete="email" required />
              </div>
              <div class="flex items-center gap-2">
                <Checkbox id="rememberEmail" v-model="rememberEmail" />
                <label for="rememberEmail" class="text-sm text-muted">Remember email</label>
              </div>
              <Button type="submit" class="w-full" :disabled="loading">
                {{ loading ? 'Checking...' : 'Continue' }}
              </Button>
            </form>

            <!-- Password / TOTP step -->
            <form v-else-if="step === 'password' || step === 'totp'" class="space-y-4" @submit.prevent="submitPassword">
              <div class="flex items-center justify-between text-sm mb-1">
                <span class="text-muted">{{ email }}</span>
                <Button variant="link" size="sm" class="text-faint" @click="backToEmail">Change</Button>
              </div>

              <div>
                <label for="loginPassword" class="block text-sm font-medium mb-1.5">Password</label>
                <Input id="loginPassword" v-model="password" type="password" autocomplete="current-password" required />
              </div>

              <div v-if="step === 'totp'">
                <label for="loginTotp" class="block text-sm font-medium mb-1.5">Authenticator code</label>
                <Input
                  id="loginTotp"
                  v-model="totpToken"
                  type="text"
                  inputmode="numeric"
                  autocomplete="one-time-code"
                  :maxlength="6"
                  placeholder="6-digit code"
                />
              </div>

              <Button type="submit" class="w-full" :disabled="loading">
                {{ loading ? 'Signing in...' : 'Sign in' }}
              </Button>
            </form>

            <!-- Passkey step -->
            <div v-else-if="step === 'passkey'" class="space-y-4">
              <div class="flex items-center justify-between text-sm mb-1">
                <span class="text-muted">{{ email }}</span>
                <Button variant="link" size="sm" class="text-faint" @click="backToEmail">Change</Button>
              </div>

              <Button class="w-full" :disabled="loading" @click="submitPasskey">
                {{ loading ? 'Waiting for passkey...' : 'Sign in with passkey' }}
              </Button>

              <Button
                v-if="availableMethods.includes('password') || availableMethods.includes('password+totp')"
                variant="link"
                class="w-full py-2 text-sm"
                @click="step = availableMethods.includes('password+totp') ? 'totp' : 'password'"
              >
                Use password instead
              </Button>
            </div>
          </div>
        </Transition>
      </div>
    </Card>
  </PageBackground>
</template>
