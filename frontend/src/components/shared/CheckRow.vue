<script setup lang="ts">
import { Eye } from 'lucide-vue-next'
import Button from '@/components/ui/Button.vue'
import StatusIcon from '@/components/shared/StatusIcon.vue'
import type { CheckResultInfo } from '@/api/types.gen'

// One status-check row: icon, title, dynamic message (or a metric
// reading while green), and the detail-dialog trigger. Presentation
// only - the parent owns the catalog join and the dialog state.
defineProps<{
  row: CheckResultInfo
  title: string
  /** "failing since ..." label, when the row is failing. */
  since: string | null
  /** Metric observation to show while the row is green. */
  reading: string | null
}>()

const emit = defineEmits<{ detail: [] }>()
</script>

<template>
  <div class="px-4 py-3">
    <div class="flex items-start gap-3">
      <StatusIcon
        v-if="row.status !== 'skipped'"
        :status="row.status as 'ok' | 'error' | 'warning'"
        class="mt-0.5 shrink-0"
      />
      <span v-else class="mt-1.5 size-2.5 rounded-full bg-border shrink-0" />
      <div class="flex-1 min-w-0 break-words">
        <div class="flex items-baseline gap-2 flex-wrap">
          <p class="text-sm font-medium">{{ title }}</p>
          <span v-if="since" class="text-xs text-error">{{ since }}</span>
        </div>
        <p v-if="row.message" class="text-sm text-muted dark:text-faint mt-0.5">
          {{ row.message }}
        </p>
        <p v-else-if="reading" class="text-sm text-faint mt-0.5">
          {{ reading }}
        </p>
      </div>
      <Button
        variant="secondary"
        size="icon"
        class="shrink-0 text-faint"
        :aria-label="`View details for ${title}`"
        @click="emit('detail')"
      >
        <Eye class="size-4" />
      </Button>
    </div>
  </div>
</template>
