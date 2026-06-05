<script setup lang="ts">
import AppLayout from '@/components/layout/AppLayout.vue'
import { useConfigStore } from '@/stores/config'
import { useAuthStore } from '@/stores/auth'

const config = useConfigStore()
const auth = useAuthStore()
</script>

<template>
  <AppLayout>
    <div class="max-w-2xl">
      <h1 class="text-2xl font-semibold mb-1">Welcome</h1>
      <p class="text-sm text-gray-500 mb-8">{{ config.hostname }}</p>

      <div class="rounded-2xl border border-gray-100 dark:border-gray-800 p-5 space-y-2">
        <p class="text-sm text-gray-600 dark:text-gray-400">
          Signed in as <span class="font-medium text-gray-900 dark:text-white">{{ auth.email }}</span>
        </p>
        <p v-if="config.noUsersExist" class="text-sm text-amber-600 dark:text-amber-400">
          No mail users exist yet. Create a user to get started.
        </p>
        <p v-if="config.noAdminsExist" class="text-sm text-amber-600 dark:text-amber-400">
          No admin accounts exist. Promote a user to admin.
        </p>
      </div>
    </div>
  </AppLayout>
</template>
