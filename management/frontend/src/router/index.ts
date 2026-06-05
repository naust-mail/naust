import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const router = createRouter({
  // Dev: serve from root so proxy + routing are simple.
  // Prod: nginx serves the app at /admin/, Flask sees paths without the prefix.
  history: createWebHistory(import.meta.env.DEV ? '/' : '/admin/'),
  routes: [
    { path: '/login', component: () => import('@/pages/LoginPage.vue'), meta: { public: true } },
    { path: '/', redirect: '/welcome' },
    { path: '/welcome', component: () => import('@/pages/WelcomePage.vue') },
    { path: '/users', component: () => import('@/pages/UsersPage.vue') },
    { path: '/aliases', component: () => import('@/pages/AliasesPage.vue') },
    { path: '/system-status', component: () => import('@/pages/SystemStatusPage.vue') },
    { path: '/system-backup', component: () => import('@/pages/SystemBackupPage.vue') },
    { path: '/ssl', component: () => import('@/pages/SslPage.vue') },
    { path: '/custom-dns', component: () => import('@/pages/CustomDnsPage.vue') },
    { path: '/external-dns', component: () => import('@/pages/ExternalDnsPage.vue') },
    { path: '/mfa', component: () => import('@/pages/MfaPage.vue') },
    { path: '/web', component: () => import('@/pages/WebPage.vue') },
    { path: '/mail-guide', component: () => import('@/pages/MailGuidePage.vue') },
    { path: '/sync-guide', component: () => import('@/pages/SyncGuidePage.vue') },
    { path: '/munin', component: () => import('@/pages/MuninPage.vue') },
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
  '#munin': '/munin',
  '#mail-guide': '/mail-guide',
  '#sync-guide': '/sync-guide',
  '#welcome': '/welcome',
}

router.beforeEach((to) => {
  // Redirect legacy hash-based URLs from the old vanilla JS admin panel.
  if (to.hash && legacyHashMap[to.hash]) {
    return legacyHashMap[to.hash]
  }

  const auth = useAuthStore()
  if (!to.meta.public && !auth.isLoggedIn) {
    return '/login'
  }
})

export default router
