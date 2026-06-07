<script setup lang="ts">
import AppLayout from '@/components/layout/AppLayout.vue'
import Card from '@/components/ui/Card.vue'
import Table from '@/components/ui/Table.vue'
import TableRow from '@/components/ui/TableRow.vue'
import { useConfigStore } from '@/stores/config'

const config = useConfigStore()

type SettingRow = [string, string]

const activeSyncRows: SettingRow[] = [
  ['Server', config.hostname],
  ['Username', 'Your full email address'],
  ['Password', 'Your mail password'],
  ['Domain', '(leave blank)'],
  ['Options', 'Secure Connection (SSL)'],
]
</script>

<template>
  <AppLayout>
    <h1 class="text-2xl font-semibold mb-6">Sync to Devices</h1>

    <!-- ActiveSync -->
    <h2 class="text-base font-semibold mb-3">Exchange / ActiveSync</h2>
    <Card class="p-5 mb-6">
      <p class="text-sm text-gray-500 mb-3">
        Push email sync to mobile devices and Outlook using Exchange ActiveSync.
        Compatible with iOS, Android, and Outlook 2007 and later.
      </p>
      <Table>
        <tbody>
          <TableRow v-for="[label, value] in activeSyncRows" :key="label">
            <th scope="row" class="px-4 py-2.5 text-sm text-gray-500 font-normal text-left w-40">{{ label }}</th>
            <td class="px-4 py-2.5 text-sm font-medium">{{ value }}</td>
          </TableRow>
        </tbody>
      </Table>
      <p class="text-xs text-gray-500 mt-3 px-1">
        Autodiscover is supported - iOS and Outlook can configure automatically using just your email address and password.
      </p>
    </Card>

    <!-- Autodiscover -->
    <h2 class="text-base font-semibold mb-3">Autodiscover</h2>
    <Card class="p-5 mb-6">
      <p class="text-sm text-gray-500 mb-2">
        Clients that support autodiscover configure themselves automatically.
        Enter your email address and password - no manual server entry needed.
      </p>
      <a
        :href="`https://${config.hostname}/autodiscover/autodiscover.xml`"
        target="_blank"
        rel="noopener"
        class="text-sm font-medium underline underline-offset-2"
      >
        https://{{ config.hostname }}/autodiscover/autodiscover.xml
      </a>
    </Card>

    <!-- Contacts & Calendar -->
    <h2 class="text-base font-semibold mb-3">Contacts &amp; Calendar</h2>
    <Card class="p-5">
      <p class="text-sm text-gray-500 mb-3">
        This server does not provide CalDAV or CardDAV. Only email is synchronised via ActiveSync.
        Use webmail to manage contacts and calendar events.
      </p>
      <a
        :href="`https://${config.hostname}/mail`"
        target="_blank"
        rel="noopener"
        class="text-sm font-medium underline underline-offset-2"
      >
        https://{{ config.hostname }}/mail
      </a>
    </Card>
  </AppLayout>
</template>
