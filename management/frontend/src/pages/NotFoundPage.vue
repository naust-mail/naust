<script setup lang="ts">
import { useRouter } from 'vue-router'

const router = useRouter()
</script>

<template>
  <div class="min-h-screen flex items-center justify-center bg-white dark:bg-gray-900">
    <div class="text-center">
      <p class="text-3xl mb-3">🔍</p>
      <h1 class="text-lg font-medium text-gray-700 dark:text-gray-100">Page not found</h1>
      <p class="text-xs text-gray-500 mt-1">The page you're looking for doesn't exist.</p>
      <button
        class="mt-4 text-sm text-gray-600 dark:text-gray-400 hover:underline"
        @click="router.push('/welcome')"
      >
        Go home
      </button>
    </div>
  </div>
</template>
