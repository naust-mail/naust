<script setup lang="ts">
import AppLayout from '@/components/layout/AppLayout.vue'
import Card from '@/components/ui/Card.vue'
import Code from '@/components/ui/Code.vue'
import Divider from '@/components/ui/Divider.vue'
import Table from '@/components/ui/Table.vue'
import TableRow from '@/components/ui/TableRow.vue'
import { useConfigStore } from '@/stores/config'

const config = useConfigStore()

type SettingRow = [string, string]

const imapSmtpRows: SettingRow[] = [
  ['Protocol', 'IMAP'],
  ['Mail server', config.hostname],
  ['IMAP port', '993'],
  ['IMAP security', 'SSL or TLS'],
  ['SMTP port', '465'],
  ['SMTP security', 'SSL or TLS'],
  ['Username', 'Your full email address'],
  ['Password', 'Your mail password'],
]

const activeSyncRows: SettingRow[] = [
  ['Server', config.hostname],
  ['Options', 'Secure Connection'],
]
</script>

<template>
  <AppLayout>
    <h1 class="text-2xl font-semibold mb-6">Checking and Sending Mail</h1>

    <!-- Webmail -->
    <h2 class="text-base font-semibold mb-3">Webmail</h2>
    <Card class="p-5 mb-6">
      <p class="text-sm text-gray-500 mb-2">
        Access your email from any web browser - no setup required.
      </p>
      <a
        :href="`https://${config.hostname}/mail`"
        target="_blank"
        rel="noopener"
        class="text-sm font-medium underline underline-offset-2"
      >
        https://{{ config.hostname || 'example.com' }}/mail
      </a>
      <p class="text-xs text-gray-500 mt-2">Your username is your full email address.</p>
    </Card>

    <!-- IMAP / SMTP -->
    <h2 class="text-base font-semibold mb-3">Mobile &amp; Desktop Apps</h2>
    <Card class="mb-6">
      <div class="p-5">
        <p class="text-sm text-gray-500 mb-2">
          iOS and macOS users can set up Mail automatically using the configuration profile:
        </p>
        <a
          :href="`https://${config.hostname}/mailinabox.mobileconfig`"
          class="text-sm font-medium underline underline-offset-2"
        >
          Download configuration profile
        </a>
      </div>
      <Divider />
      <div class="p-5">
        <p class="text-sm font-medium mb-3">Manual IMAP / SMTP settings</p>
        <Table>
          <tbody>
            <TableRow v-for="[label, value] in imapSmtpRows" :key="label">
              <th scope="row" class="px-4 py-2.5 text-sm text-gray-500 font-normal text-left w-40">{{ label }}</th>
              <td class="px-4 py-2.5 text-sm font-medium">{{ value }}</td>
            </TableRow>
          </tbody>
        </Table>
        <p class="text-xs text-gray-500 mt-3 px-1">
          POP is also available on port 995 with SSL/TLS. IMAP is recommended.
        </p>
      </div>
    </Card>

    <!-- Exchange / ActiveSync -->
    <h2 class="text-base font-semibold mb-3">Exchange / ActiveSync</h2>
    <Card class="p-5 mb-6">
      <p class="text-sm text-gray-500 mb-3">
        Compatible with iOS devices and Outlook 2007 and later on Windows 7 and later.
        ActiveSync setup can be unreliable - IMAP is generally more stable.
      </p>
      <Table>
        <tbody>
          <TableRow v-for="[label, value] in activeSyncRows" :key="label">
            <td class="px-4 py-2.5 text-sm text-gray-500 w-40">{{ label }}</td>
            <td class="px-4 py-2.5 text-sm font-medium">{{ value }}</td>
          </TableRow>
        </tbody>
      </Table>
      <p class="text-xs text-gray-500 mt-3 px-1">Push email sync is supported on compatible devices.</p>
    </Card>

    <!-- Other info -->
    <h2 class="text-base font-semibold mb-3">Other Information</h2>
    <Card class="p-5">
      <div class="divide-y divide-gray-100 dark:divide-gray-800">
        <div class="pb-4">
          <p class="text-sm font-medium mb-1">Greylisting</p>
          <p class="text-sm text-gray-500">
            First-time messages from new senders are delayed by at least 3 minutes to reduce spam.
            Legitimate mail always arrives - just slightly delayed on the first contact.
          </p>
        </div>
        <div class="py-4">
          <p class="text-sm font-medium mb-1">Tagged addresses</p>
          <p class="text-sm text-gray-500">
            Mail sent to
            <Code>you+anything@yourdomain.com</Code>
            is delivered to your inbox automatically. Useful for filtering.
          </p>
        </div>
        <div class="pt-4">
          <p class="text-sm font-medium mb-1">Outbound sending policy</p>
          <p class="text-sm text-gray-500">
            Only this box is authorised to send mail on behalf of your domains.
            This prevents spoofing and helps with spam scores.
          </p>
        </div>
      </div>
    </Card>
  </AppLayout>
</template>
