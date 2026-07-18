import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const router = createRouter({
  // Dev: serve from root so proxy + routing are simple.
  // Prod: nginx serves the app at /admin/, Flask sees paths without the prefix.
  history: createWebHistory(import.meta.env.DEV ? '/' : '/admin/'),
  routes: [
    { path: '/login', component: () => import('@/pages/LoginPage.vue'), meta: { public: true } },
    { path: '/setup', component: () => import('@/pages/OnboardingPage.vue'), meta: { public: true } },
    { path: '/', redirect: '/system-status' },
    {
      // Shared sidebar/shell for every authed page, nested so it mounts
      // once and persists across navigation instead of remounting per page.
      path: '/',
      component: () => import('@/components/layout/AppLayout.vue'),
      children: [
        { path: 'mfa', component: () => import('@/pages/MfaPage.vue') },
        { path: 'encryption', component: () => import('@/pages/EncryptionPage.vue') },
        { path: 'api-tokens', component: () => import('@/pages/ApiTokensPage.vue'), meta: { adminOnly: true } },
        { path: 'users', component: () => import('@/pages/UsersPage.vue'), meta: { adminOnly: true } },
        { path: 'aliases', component: () => import('@/pages/AliasesPage.vue'), meta: { adminOnly: true } },
        { path: 'system-status', component: () => import('@/pages/SystemStatusPage.vue'), meta: { adminOnly: true } },
        { path: 'system-backup', component: () => import('@/pages/SystemBackupPage.vue'), meta: { adminOnly: true } },
        { path: 'smtp-relay', component: () => import('@/pages/SmtpRelayPage.vue'), meta: { adminOnly: true } },
        { path: 'ssl', component: () => import('@/pages/SslPage.vue'), meta: { adminOnly: true } },
        { path: 'custom-dns', component: () => import('@/pages/CustomDnsPage.vue'), meta: { adminOnly: true } },
        { path: 'external-dns', component: () => import('@/pages/ExternalDnsPage.vue'), meta: { adminOnly: true } },
        { path: 'web', component: () => import('@/pages/WebPage.vue'), meta: { adminOnly: true } },
        { path: 'mail-guide', component: () => import('@/pages/MailGuidePage.vue'), meta: { adminOnly: true } },
        { path: 'sync-guide', component: () => import('@/pages/SyncGuidePage.vue'), meta: { adminOnly: true } },
        { path: 'monitoring', component: () => import('@/pages/MonitoringPage.vue'), meta: { adminOnly: true } },
      ],
    },
    { path: '/:pathMatch(.*)*', component: () => import('@/pages/NotFoundPage.vue'), meta: { public: true } },
  ],
})

const legacyHashMap: Record<string, string> = {
  '#system_status': '/system-status',
  '#system_backup': '/system-backup',
  '#mail-users': '/users',
  '#mail-aliases': '/aliases',
  '#ssl': '/ssl',
  '#dns': '/custom-dns',
  '#external_dns': '/external-dns',
  '#web': '/web',
  '#mfa': '/mfa',

  '#mail-guide': '/mail-guide',
  '#sync-guide': '/sync-guide',
  '#welcome': '/system-status',
}

router.beforeEach(async (to) => {
  // Redirect legacy hash-based URLs from the old vanilla JS admin panel.
  if (to.hash && legacyHashMap[to.hash]) {
    return legacyHashMap[to.hash]
  }

  const auth = useAuthStore()

  // First navigation: resolve the session cookie and box metadata
  // before any guard decision, so a reload deep in the panel does not
  // bounce through /login while the probe is in flight.
  if (!auth.ready) {
    await auth.init()
  }

  // Bootstrap takes priority: no admins exist, send everyone to /setup.
  if (auth.needsBootstrap && to.path !== '/setup') {
    return '/setup'
  }
  // Once bootstrap is done, /setup should not be accessible.
  if (!auth.needsBootstrap && to.path === '/setup') {
    return '/login'
  }

  if (to.path === '/login' && auth.isLoggedIn) {
    return auth.isAdmin ? '/system-status' : '/mfa'
  }
  if (!to.meta.public && !auth.isLoggedIn) {
    return '/login'
  }
  if (to.meta.adminOnly && !auth.isAdmin) {
    return '/mfa'
  }
})

export default router
