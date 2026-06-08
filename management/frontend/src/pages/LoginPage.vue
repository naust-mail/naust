<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { startAuthentication } from '@simplewebauthn/browser'
import { toast } from 'vue-sonner'
import { useAuthStore } from '@/stores/auth'
import { useConfigStore } from '@/stores/config'
import Button from '@/components/ui/Button.vue'
import Input from '@/components/ui/Input.vue'
import Card from '@/components/ui/Card.vue'
import PageBackground from '@/components/ui/PageBackground.vue'
import type { AuthMethodsResponse } from '@/types'

type Step = 'email' | 'password' | 'totp' | 'passkey'

const REMEMBERED_EMAIL_KEY = 'admin_remembered_email'

const router = useRouter()
const auth = useAuthStore()
const config = useConfigStore()

const email = ref('')
const password = ref('')
const totpToken = ref('')
const rememberEmail = ref(false)
const loading = ref(false)
const step = ref<Step>('email')
const availablePaths = ref<AuthMethodsResponse['paths']>([])

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

async function continueFromEmail(): Promise<void> {
  if (!email.value || loading.value) return
  loading.value = true
  try {
    const res = await fetch(`/admin/auth/methods?email=${encodeURIComponent(email.value)}`)
    const data: AuthMethodsResponse = await res.json()
    availablePaths.value = data.paths
    step.value = data.paths.includes('passkey') ? 'passkey' : 'password'
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
      saveEmailPreference()
      await router.push('/system-status')
    } else if (result === 'missing-totp-token') {
      step.value = 'totp'
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
    const fd = new FormData()
    fd.append('email', email.value)
    const beginRes = await fetch('/admin/mfa/webauthn/authenticate/begin', {
      method: 'POST',
      headers: { 'X-Requested-With': 'XMLHttpRequest' },
      body: fd,
    })
    if (!beginRes.ok) throw new Error('begin failed')
    const { options, nonce } = await beginRes.json()

    const credential = await startAuthentication({ optionsJSON: options.publicKey })

    const completeFd = new FormData()
    completeFd.append('nonce', nonce)
    completeFd.append('credential', JSON.stringify(credential))
    const completeRes = await fetch('/admin/mfa/webauthn/authenticate/complete', {
      method: 'POST',
      headers: { 'X-Requested-With': 'XMLHttpRequest' },
      body: completeFd,
    })
    const result = await completeRes.json()

    if (result.status === 'ok') {
      auth.handleAuthSuccess(result.email, result.privileges)
      saveEmailPreference()
      await router.push('/system-status')
    } else {
      toast.error(result.reason || 'Passkey authentication failed.')
    }
  } catch (err) {
    if ((err as Error).name !== 'NotAllowedError') {
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
  availablePaths.value = []
}
</script>

<template>
  <PageBackground class="flex items-center justify-center p-4">
    <Card class="w-full max-w-sm p-6">
      <h1 class="text-2xl font-semibold text-center mb-1">
        {{ config.hostname || 'Mail-in-a-Box' }}
      </h1>
      <p class="text-sm text-gray-500 text-center mb-7">Control panel</p>

      <!-- Email step -->
      <form v-if="step === 'email'" class="space-y-4" @submit.prevent="continueFromEmail">
        <div>
          <label for="loginEmail" class="block text-sm font-medium mb-1.5">Email</label>
          <Input id="loginEmail" v-model="email" type="email" autocomplete="email" required />
        </div>
        <div class="flex items-center gap-2">
          <input id="rememberEmail" v-model="rememberEmail" type="checkbox" class="size-4 rounded" />
          <label for="rememberEmail" class="text-sm text-gray-500">Remember email</label>
        </div>
        <Button type="submit" class="w-full" :disabled="loading">
          {{ loading ? 'Checking...' : 'Continue' }}
        </Button>
      </form>

      <!-- Password / TOTP step -->
      <form v-else-if="step === 'password' || step === 'totp'" class="space-y-4" @submit.prevent="submitPassword">
        <div class="flex items-center justify-between text-sm mb-1">
          <span class="text-gray-500">{{ email }}</span>
          <button type="button" class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors" @click="backToEmail">
            Change
          </button>
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
          <span class="text-gray-500">{{ email }}</span>
          <button type="button" class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors" @click="backToEmail">
            Change
          </button>
        </div>

        <Button class="w-full" :disabled="loading" @click="submitPasskey">
          {{ loading ? 'Waiting for passkey...' : 'Sign in with passkey' }}
        </Button>

        <button
          v-if="availablePaths.includes('password') || availablePaths.includes('password+totp')"
          type="button"
          class="w-full text-sm text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 transition-colors py-2"
          @click="step = 'password'"
        >
          Use password instead
        </button>
      </div>
    </Card>
  </PageBackground>
</template>
