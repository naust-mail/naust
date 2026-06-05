<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { toast } from 'vue-sonner'

const router = useRouter()
const auth = useAuthStore()

const email = ref('')
const password = ref('')
const totpToken = ref('')
const remember = ref(false)
const needsTotp = ref(false)
const loading = ref(false)

async function submit(): Promise<void> {
  if (loading.value) return
  loading.value = true
  try {
    const result = await auth.login(
      email.value,
      password.value,
      needsTotp.value ? totpToken.value : undefined,
      remember.value,
    )
    if (result === 'ok') {
      await router.push('/welcome')
    } else if (result === 'missing-totp-token') {
      needsTotp.value = true
    } else {
      toast.error(result)
    }
  } catch {
    toast.error('Login failed. Please try again.')
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="min-h-screen flex items-center justify-center bg-white dark:bg-gray-900 p-4">
    <div class="w-full max-w-sm">
      <h1 class="text-2xl font-semibold text-gray-900 dark:text-white mb-8 text-center">
        Mail-in-a-Box
      </h1>

      <form class="space-y-4" @submit.prevent="submit">
        <div>
          <label class="block text-sm text-gray-600 dark:text-gray-400 mb-1.5">Email</label>
          <input
            v-model="email"
            type="email"
            autocomplete="email"
            required
            class="w-full rounded-lg py-2 px-4 text-sm bg-gray-50 dark:bg-gray-850 dark:text-gray-300 outline-none border border-gray-200 dark:border-gray-700 focus:border-gray-400 dark:focus:border-gray-500 transition-colors"
          />
        </div>

        <div>
          <label class="block text-sm text-gray-600 dark:text-gray-400 mb-1.5">Password</label>
          <input
            v-model="password"
            type="password"
            autocomplete="current-password"
            required
            class="w-full rounded-lg py-2 px-4 text-sm bg-gray-50 dark:bg-gray-850 dark:text-gray-300 outline-none border border-gray-200 dark:border-gray-700 focus:border-gray-400 dark:focus:border-gray-500 transition-colors"
          />
        </div>

        <div v-if="needsTotp">
          <label class="block text-sm text-gray-600 dark:text-gray-400 mb-1.5">
            Authenticator code
          </label>
          <input
            v-model="totpToken"
            type="text"
            inputmode="numeric"
            autocomplete="one-time-code"
            maxlength="6"
            placeholder="6-digit code"
            class="w-full rounded-lg py-2 px-4 text-sm bg-gray-50 dark:bg-gray-850 dark:text-gray-300 outline-none border border-gray-200 dark:border-gray-700 focus:border-gray-400 dark:focus:border-gray-500 transition-colors"
          />
        </div>

        <div class="flex items-center gap-2">
          <input id="remember" v-model="remember" type="checkbox" class="size-4 rounded" />
          <label for="remember" class="text-sm text-gray-600 dark:text-gray-400">
            Stay signed in
          </label>
        </div>

        <button
          type="submit"
          :disabled="loading"
          class="w-full h-9 rounded-lg text-sm font-medium bg-black text-white hover:bg-gray-900 dark:bg-white dark:text-black dark:hover:bg-gray-100 transition-colors disabled:opacity-50"
        >
          {{ loading ? 'Signing in...' : 'Sign in' }}
        </button>
      </form>
    </div>
  </div>
</template>
