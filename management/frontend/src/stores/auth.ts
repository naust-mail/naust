import { ref, computed } from 'vue'
import { defineStore } from 'pinia'
import type { InitData, LoginApiResponse } from '@/types'

export const useAuthStore = defineStore('auth', () => {
  // Seed initial state from the __INIT__ bootstrap data injected by the server.
  // On an authenticated page load the server validates the admin_session cookie
  // and injects email + privileges so the app starts in the correct state
  // without an extra round-trip. On unauthenticated loads these are absent.
  const el = document.getElementById('__INIT__')
  const init: Partial<InitData> = el?.textContent ? JSON.parse(el.textContent) : {}

  const email = ref<string | null>(init.email ?? null)
  const privileges = ref<string[]>(init.privileges ?? [])

  const isLoggedIn = computed(() => !!email.value)
  const isAdmin = computed(() => privileges.value.includes('admin'))

  /** Called by all login paths (password, password+TOTP, passkey) after the server
   *  sets the admin_session cookie. Only metadata is stored here - the session key
   *  lives exclusively in the HttpOnly cookie, never in JavaScript. */
  function handleAuthSuccess(emailAddr: string, privs: string[]): void {
    email.value = emailAddr
    privileges.value = privs
  }

  function clearSession(): void {
    email.value = null
    privileges.value = []
  }

  async function login(
    emailAddr: string,
    password: string,
    totpToken?: string,
  ): Promise<'ok' | 'missing-totp-token' | string> {
    const headers: Record<string, string> = {
      Authorization: 'Basic ' + btoa(`${emailAddr}:${password}`),
      'X-Requested-With': 'XMLHttpRequest',
    }
    if (totpToken) headers['X-Auth-Token'] = totpToken

    const res = await fetch('/admin/login', { method: 'POST', headers })
    const data: LoginApiResponse = await res.json()

    if (data.status === 'ok' && data.email && data.privileges) {
      // Server has set the admin_session cookie. Store metadata in Pinia.
      handleAuthSuccess(data.email, data.privileges)
      return 'ok'
    }
    if (data.status === 'missing-totp-token') return 'missing-totp-token'
    return data.reason || 'Login failed.'
  }

  async function logout(): Promise<void> {
    clearSession()
    await fetch('/admin/logout', {
      method: 'POST',
      headers: { 'X-Requested-With': 'XMLHttpRequest' },
      // Credentials included so the browser sends the admin_session cookie,
      // allowing the server to invalidate it.
      credentials: 'same-origin',
    }).catch(() => {})
  }

  return { email, privileges, isLoggedIn, isAdmin, handleAuthSuccess, clearSession, login, logout }
})
