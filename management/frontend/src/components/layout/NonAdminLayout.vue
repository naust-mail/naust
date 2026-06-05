<script setup lang="ts">
import { useAuthStore } from '@/stores/auth'
import { useRouter } from 'vue-router'
import { LogOut } from 'lucide-vue-next'

const auth = useAuthStore()
const router = useRouter()

async function handleLogout(): Promise<void> {
  await auth.logout()
  await router.push('/login')
}
</script>

<template>
  <div class="min-h-screen flex items-center justify-center bg-white dark:bg-gray-900 p-4">
    <div class="w-full max-w-lg">
      <div class="flex items-center justify-between mb-6">
        <span class="text-sm text-gray-500">{{ auth.email }}</span>
        <button
          class="flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 transition"
          @click="handleLogout"
        >
          <LogOut class="size-4" />
          Sign out
        </button>
      </div>
      <slot />
    </div>
  </div>
</template>
