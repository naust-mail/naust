<script setup lang="ts">
import Card from '@/components/ui/Card.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import SectionHeader from '@/components/ui/SectionHeader.vue'
import Code from '@/components/ui/Code.vue'
import Divider from '@/components/ui/Divider.vue'
import Table from '@/components/ui/Table.vue'
import TableRow from '@/components/ui/TableRow.vue'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()

type SettingRow = [string, string]

const imapSmtpRows: SettingRow[] = [
  ['Protocol', 'IMAP'],
  ['Mail server', auth.hostname],
  ['IMAP port', '993 (SSL/TLS)'],
  ['SMTP port', '465 (SSL/TLS)'],
  ['SMTP port', '587 (STARTTLS)'],
  ['Username', 'Your full email address'],
  ['Password', 'Your mail password'],
]

</script>

<template>
    <PageHeader title="Checking and Sending Mail" description="How to connect your mail app, or use the built-in webmail." />

    <!-- Webmail -->
    <SectionHeader title="Webmail" />
    <Card padding="md" class="mb-6">
      <p class="text-sm text-muted mb-2">
        Access your email from any web browser - no setup required.
      </p>
      <a
        :href="`https://${auth.hostname}/mail`"
        target="_blank"
        rel="noopener"
        class="text-sm font-medium underline underline-offset-2"
      >
        https://{{ auth.hostname || 'example.com' }}/mail
      </a>
      <p class="text-xs text-muted mt-2">Your username is your full email address.</p>
    </Card>

    <!-- IMAP / SMTP -->
    <SectionHeader title="Mobile &amp; Desktop Apps" />
    <Card class="mb-6">
      <div class="p-5">
        <p class="text-sm text-muted mb-2">
          iOS and macOS users can set up Mail automatically using the configuration profile:
        </p>
        <a
          :href="`https://${auth.hostname}/naust.mobileconfig`"
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
            <TableRow v-for="([label, value], i) in imapSmtpRows" :key="i">
              <th scope="row" class="px-4 py-2.5 text-sm text-muted font-normal text-left w-40">{{ label }}</th>
              <td class="px-4 py-2.5 text-sm font-medium">{{ value }}</td>
            </TableRow>
          </tbody>
        </Table>
        <p class="text-xs text-muted mt-3 px-1">
          POP is also available on port 995 with SSL/TLS. IMAP is recommended.
        </p>
      </div>
    </Card>

    <!-- Other info -->
    <SectionHeader title="Other Information" />
    <Card padding="md">
      <div class="divide-y divide-border">
        <div class="pb-4">
          <p class="text-sm font-medium mb-1">Greylisting</p>
          <p class="text-sm text-muted">
            First-time messages from new senders are delayed by at least 3 minutes to reduce spam.
            Legitimate mail always arrives - just slightly delayed on the first contact.
          </p>
        </div>
        <div class="py-4">
          <p class="text-sm font-medium mb-1">Tagged addresses</p>
          <p class="text-sm text-muted">
            Mail sent to
            <Code>you+anything@yourdomain.com</Code>
            is delivered to your inbox automatically. Useful for filtering.
          </p>
        </div>
        <div class="pt-4">
          <p class="text-sm font-medium mb-1">Outbound sending policy</p>
          <p class="text-sm text-muted">
            Only this box is authorised to send mail on behalf of your domains.
            This prevents spoofing and helps with spam scores.
          </p>
        </div>
      </div>
    </Card>
</template>
