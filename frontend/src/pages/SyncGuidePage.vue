<script setup lang="ts">
import Card from '@/components/ui/Card.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import SectionHeader from '@/components/ui/SectionHeader.vue'
import Code from '@/components/ui/Code.vue'
import Table from '@/components/ui/Table.vue'
import TableRow from '@/components/ui/TableRow.vue'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()

type SettingRow = [string, string]

const imapRows: SettingRow[] = [
  ['IMAP server', auth.hostname],
  ['IMAP port', '993 (SSL/TLS)'],
  ['SMTP server', auth.hostname],
  ['SMTP port', '465 (SSL/TLS)'],
  ['SMTP port', '587 (STARTTLS)'],
  ['Username', 'Your full email address'],
  ['Password', 'Your mail password'],
]

const caldavRows: SettingRow[] = [
  ['Server URL', `https://${auth.hostname}/radicale/`],
  ['Username', 'Your full email address'],
  ['Password', 'Your mail password'],
]
</script>

<template>
    <PageHeader title="Sync to Devices" description="Sync your calendar and contacts with your phone or desktop app." />

    <!-- IMAP / SMTP -->
    <SectionHeader title="Email (IMAP / SMTP)" />
    <Card padding="md" class="mb-6">
      <p class="text-sm text-muted mb-3">
        Configure any mail client using these settings. Autoconfig and autodiscover are
        supported - most clients can configure themselves with just your email address and password.
      </p>
      <Table>
        <tbody>
          <TableRow v-for="([label, value], i) in imapRows" :key="i">
            <th scope="row" class="px-4 py-2.5 text-sm text-muted font-normal text-left w-48">{{ label }}</th>
            <td class="px-4 py-2.5 text-sm font-medium font-mono">{{ value }}</td>
          </TableRow>
        </tbody>
      </Table>
    </Card>

    <!-- CalDAV / CardDAV -->
    <SectionHeader title="Contacts &amp; Calendar (CalDAV / CardDAV)" />
    <Card padding="md" class="mb-6">
      <p class="text-sm text-muted mb-3">
        Contacts and calendars are served by <a href="https://radicale.org/" target="_blank" rel="noopener" class="underline underline-offset-2">Radicale</a>.
        Use these settings in iOS, Android, Thunderbird, or any CalDAV/CardDAV client.
        Clients that support <Code>.well-known</Code> autodiscovery
        only need the server URL and credentials.
      </p>
      <Table>
        <tbody>
          <TableRow v-for="[label, value] in caldavRows" :key="label">
            <th scope="row" class="px-4 py-2.5 text-sm text-muted font-normal text-left w-48">{{ label }}</th>
            <td class="px-4 py-2.5 text-sm font-medium font-mono">{{ value }}</td>
          </TableRow>
        </tbody>
      </Table>
      <p class="text-xs text-muted mt-3 px-1">
        CalDAV and CardDAV autodiscovery is configured via
        <Code>/.well-known/caldav</Code> and
        <Code>/.well-known/carddav</Code>.
        Enter just <span class="font-mono">{{ auth.hostname }}</span> as the server in clients that support it.
      </p>
    </Card>

    <!-- Autodiscover -->
    <SectionHeader title="Autodiscover" />
    <Card padding="md" class="mb-6">
      <p class="text-sm text-muted mb-3">
        Outlook, iOS, and most modern mail clients can configure themselves automatically.
        Enter your email address and password - no manual server settings needed.
      </p>
      <div class="space-y-1">
        <div>
          <span class="text-xs text-faint uppercase tracking-wide">Outlook (autodiscover)</span>
          <div>
            <a
              :href="`https://${auth.hostname}/autodiscover/autodiscover.xml`"
              target="_blank"
              rel="noopener"
              class="text-sm font-medium underline underline-offset-2 font-mono"
            >https://{{ auth.hostname }}/autodiscover/autodiscover.xml</a>
          </div>
        </div>
        <div class="pt-1">
          <span class="text-xs text-faint uppercase tracking-wide">Thunderbird (autoconfig)</span>
          <div>
            <a
              :href="`https://${auth.hostname}/.well-known/autoconfig/mail/config-v1.1.xml`"
              target="_blank"
              rel="noopener"
              class="text-sm font-medium underline underline-offset-2 font-mono"
            >https://{{ auth.hostname }}/.well-known/autoconfig/mail/config-v1.1.xml</a>
          </div>
        </div>
      </div>
    </Card>

    <!-- Webmail -->
    <SectionHeader title="Webmail" />
    <Card padding="md">
      <p class="text-sm text-muted mb-3">
        Access your email from a browser without installing a client.
      </p>
      <a
        :href="`https://${auth.hostname}/mail`"
        target="_blank"
        rel="noopener"
        class="text-sm font-medium underline underline-offset-2"
      >
        https://{{ auth.hostname }}/mail
      </a>
    </Card>
</template>
