import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import { api, ApiError } from '@/api/client'
import type { LoginRequest, LoginResponse, MetaResponse, User } from '@/api/types.gen'

/** Pre-auth facts stamped into boot.js by setup at install time, so
 *  the first paint never waits on the API. /api/meta stays the source
 *  of truth and overwrites the seed on init(). */
type BoxBoot = { hostname?: string }

export const useAuthStore = defineStore('auth', () => {
  const boot = (window as Window & { __BOX__?: BoxBoot }).__BOX__
  const user = ref<User | null>(null)
  const hostname = ref(boot?.hostname ?? '')
  const needsBootstrap = ref(false)
  /** True once init() has resolved; the router waits on it before the
   *  first navigation so guards see real auth state. */
  const ready = ref(false)

  /** Box-level feature flags from /api/meta ("encryption_at_rest",
   *  "monitoring"). */
  const capabilities = ref<string[]>([])

  const email = computed(() => user.value?.email ?? null)
  const isLoggedIn = computed(() => !!user.value)
  const isAdmin = computed(() => user.value?.role === 'admin')

  /** The panel's single boot request: /api/meta answers the pre-auth
   *  facts and resolves the session cookie in one round trip (user is
   *  null when not logged in). */
  async function init(): Promise<void> {
    try {
      const meta = await api.get<MetaResponse>('/api/meta')
      hostname.value = meta.hostname
      needsBootstrap.value = meta.needs_bootstrap
      user.value = meta.user
      capabilities.value = meta.capabilities ?? []
    } catch {
      // Unreachable API: leave defaults, the login attempt will surface it.
    }
    ready.value = true
  }

  /** Called by login paths that complete outside login() (passkey,
   *  bootstrap). The session key lives in the HttpOnly cookie the
   *  server just set; only the user metadata is stored here. */
  function handleAuthSuccess(u: User): void {
    user.value = u
  }

  function clearBootstrap(): void {
    needsBootstrap.value = false
  }

  function clearSession(): void {
    user.value = null
  }

  async function login(
    emailAddr: string,
    password: string,
    totpCode?: string,
  ): Promise<'ok' | 'missing-totp-code' | string> {
    const req: LoginRequest = { email: emailAddr, password }
    if (totpCode) req.totp_code = totpCode
    try {
      const resp = await api.post<LoginResponse>('/api/auth/login', req)
      user.value = resp.user
      return 'ok'
    } catch (e) {
      if (e instanceof ApiError) {
        if (e.hints.includes('missing-totp-code')) return 'missing-totp-code'
        if (e.hints.includes('use-passkey')) return 'use-passkey'
        return e.message
      }
      return 'Login failed. Please try again.'
    }
  }

  async function logout(): Promise<void> {
    clearSession()
    try {
      await api.post<undefined>('/api/auth/logout', undefined, { silent401: true })
    } catch {
      // Session already gone server-side; the cookie is cleared either way.
    }
  }

  return {
    user,
    hostname,
    email,
    needsBootstrap,
    ready,
    capabilities,
    isLoggedIn,
    isAdmin,
    init,
    handleAuthSuccess,
    clearBootstrap,
    clearSession,
    login,
    logout,
  }
})
