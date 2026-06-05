<script setup lang="ts">
import { computed } from 'vue'
import { CheckCircle, XCircle, AlertTriangle, MinusCircle } from 'lucide-vue-next'

type StatusValue = 'ok' | 'error' | 'warning' | 'not-applicable'

const props = defineProps<{ status: StatusValue }>()

const icon = computed(() =>
  ({ ok: CheckCircle, error: XCircle, warning: AlertTriangle, 'not-applicable': MinusCircle }[props.status]),
)

const colorClass = computed(() =>
  ({
    ok: 'text-emerald-500',
    error: 'text-red-500',
    warning: 'text-yellow-500',
    'not-applicable': 'text-gray-400',
  }[props.status]),
)
</script>

<template>
  <component :is="icon" :class="['size-4', colorClass]" />
</template>
