<script setup lang="ts">
import { useRouter } from 'vue-router'
import { SearchX } from 'lucide-vue-next'
import EmptyState from '@/components/ui/EmptyState.vue'
import Button from '@/components/ui/Button.vue'
import PageBackground from '@/components/ui/PageBackground.vue'

const router = useRouter()
</script>

<template>
  <PageBackground class="flex items-center justify-center">
    <EmptyState title="Page not found" description="The page you're looking for doesn't exist.">
      <template #icon><SearchX /></template>
      <template #action>
        <Button variant="secondary" @click="router.push('/system-status')">Go home</Button>
      </template>
    </EmptyState>
  </PageBackground>
</template>
