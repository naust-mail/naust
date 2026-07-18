<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { toast } from 'vue-sonner'
import { useAuthStore } from '@/stores/auth'
import { api, ApiError } from '@/api/client'
import Button from '@/components/ui/Button.vue'
import Code from '@/components/ui/Code.vue'
import Input from '@/components/ui/Input.vue'
import Card from '@/components/ui/Card.vue'
import PageBackground from '@/components/ui/PageBackground.vue'
import type { BootstrapRequest, LoginResponse } from '@/api/types.gen'

const router = useRouter()
const route = useRoute()
const auth = useAuthStore()

const code = ref('')

onMounted(() => {
  const urlCode = route.query.code
  if (urlCode) code.value = String(urlCode)
})
const email = ref('')
const password = ref('')
const confirmPassword = ref('')
const loading = ref(false)
// Server-crafted failure line ("incorrect setup code; 3 attempts
// remaining"), shown inline under the code field.
const codeError = ref<string | null>(null)

async function submit(): Promise<void> {
  if (loading.value) return

  if (password.value !== confirmPassword.value) {
    toast.error('Passwords do not match.')
    return
  }

  loading.value = true
  codeError.value = null

  try {
    const req: BootstrapRequest = {
      code: code.value,
      email: email.value.trim(),
      password: password.value,
    }
    const resp = await api.post<LoginResponse>('/api/bootstrap', req)
    // The server set the session cookie: straight into the panel.
    auth.handleAuthSuccess(resp.user)
    auth.clearBootstrap()
    await router.push('/system-status')
    toast.success('Admin account created.')
  } catch (e) {
    if (e instanceof ApiError) {
      if (e.hints.includes('invalid-code')) {
        codeError.value = e.message
      }
      toast.error(e.message)
    } else {
      toast.error('Something went wrong. Please try again.')
    }
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <PageBackground class="flex items-center justify-center p-4">
    <Card padding="lg" class="w-full max-w-sm">
      <h1 class="text-2xl font-semibold text-center mb-1">
        {{ auth.hostname || 'Naust' }}
      </h1>
      <p class="text-sm text-muted text-center mb-7">Initial setup</p>

      <p class="text-sm text-muted mb-5">
        No admin account exists yet. Run <Code>sudo boxctl bootstrap</Code> in your terminal to get a setup code, then fill in the form below.
      </p>

      <form class="space-y-4" @submit.prevent="submit">
        <div>
          <label for="setupCode" class="block text-sm font-medium mb-1.5">Setup code</label>
          <Input
            id="setupCode"
            v-model="code"
            type="text"
            autocomplete="off"
            spellcheck="false"
            placeholder="XXXXXXXX"
            :maxlength="9"
            class="font-mono tracking-widest uppercase"
            required
          />
          <p v-if="codeError" class="mt-1.5 text-xs text-error">
            {{ codeError }}
          </p>
        </div>

        <div>
          <label for="setupEmail" class="block text-sm font-medium mb-1.5">Admin email</label>
          <Input id="setupEmail" v-model="email" type="email" autocomplete="email" required />
        </div>

        <div>
          <label for="setupPassword" class="block text-sm font-medium mb-1.5">Password</label>
          <Input id="setupPassword" v-model="password" type="password" autocomplete="new-password" required />
        </div>

        <div>
          <label for="setupConfirm" class="block text-sm font-medium mb-1.5">Confirm password</label>
          <Input id="setupConfirm" v-model="confirmPassword" type="password" autocomplete="new-password" required />
        </div>

        <Button type="submit" class="w-full" :disabled="loading">
          {{ loading ? 'Creating account...' : 'Create admin account' }}
        </Button>
      </form>
    </Card>
  </PageBackground>
</template>
