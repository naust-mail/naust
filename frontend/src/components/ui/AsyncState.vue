<script setup lang="ts">
import { computed } from 'vue'
import { WifiOff } from 'lucide-vue-next'
import EmptyState from '@/components/ui/EmptyState.vue'
import Button from '@/components/ui/Button.vue'

/** Controls the state machine a data-fetching page cycles through. */
type AsyncStateProps = {
  /** True while the request is in flight. */
  loading?: boolean
  /** True when the request failed (network or server error). */
  error?: boolean
  /** True when the request succeeded but there is nothing to show. */
  empty?: boolean
  /** Heading for the default WifiOff error card. Override via #error slot for custom markup. */
  errorTitle?: string
  /** Body text for the default WifiOff error card. */
  errorDescription?: string
}

const props = withDefaults(defineProps<AsyncStateProps>(), {
  loading: false,
  error: false,
  empty: false,
  errorTitle: 'Could not load data',
  errorDescription: 'Check your connection and try again.',
})

const emit = defineEmits<{ retry: [] }>()

type StateKey = 'loading' | 'error' | 'empty' | 'content'

const stateKey = computed<StateKey>(() => {
  if (props.loading) return 'loading'
  if (props.error) return 'error'
  if (props.empty) return 'empty'
  return 'content'
})
</script>

<template>
  <div class="relative overflow-hidden">
    <Transition name="crossfade">
      <div :key="stateKey">
        <slot v-if="stateKey === 'loading'" name="loading" />
        <slot v-else-if="stateKey === 'error'" name="error">
          <EmptyState :title="errorTitle" :description="errorDescription">
            <template #icon><WifiOff /></template>
            <template #action>
              <Button variant="secondary" @click="emit('retry')">Try again</Button>
            </template>
          </EmptyState>
        </slot>
        <slot v-else-if="stateKey === 'empty'" name="empty" />
        <slot v-else />
      </div>
    </Transition>
  </div>
</template>
