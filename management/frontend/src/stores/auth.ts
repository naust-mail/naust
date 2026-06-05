import { ref, computed } from 'vue'
import { defineStore } from 'pinia'
import type { LoginApiResponse } from '@/types'

export const useAuthStore = defineStore('auth', () => {
  // Session state is read from localStorage (remember me) or sessionStorage (tab-only).
  const sessionKey = ref<string | null>(
    localStorage.getItem('session_key') || sessionStorage.getItem('session_key'),
  )
  const email = ref<string | null>(
    localStorage.getItem('email') || sessionStorage.getItem('email'),
  )
  const privileges = ref<string[]>(
    JSON.parse(
      localStorage.getItem('privileges') || sessionStorage.getItem('privileges') || '[]',
    ),
  )

  const isLoggedIn = computed(() => !!sessionKey.value)
  const isAdmin = computed(() => privileges.value.includes('admin'))

  /** Called by all three login paths (password, password+TOTP, passkey) once auth succeeds. */
  function handleAuthSuccess(key: string, privs: string[], remember: boolean): void {
    sessionKey.value = key
    privileges.value = privs
    const store = remember ? localStorage : sessionStorage
    store.setItem('session_key', key)
    store.setItem('email', email.value ?? '')
    store.setItem('privileges', JSON.stringify(privs))
  }

  function clearSession(): void {
    sessionKey.value = null
    email.value = null
    privileges.value = []
    for (const storage of [localStorage, sessionStorage]) {
      storage.removeItem('session_key')
      storage.removeItem('email')
      storage.removeItem('privileges')
    }
  }

  /**
   * Authenticate with email + password (+ optional TOTP token).
   * Returns 'ok' on success, 'missing-totp-token' if TOTP is required, or an error string.
   */
  async function login(
    emailAddr: string,
    password: string,
    totpToken?: string,
    remember = false,
  ): Promise<'ok' | 'missing-totp-token' | string> {
    const headers: Record<string, string> = {
      Authorization: 'Basic ' + btoa(`${emailAddr}:${password}`),
      'X-Requested-With': 'XMLHttpRequest',
    }
    if (totpToken) headers['X-Auth-Token'] = totpToken

    const res = await fetch('/admin/login', { method: 'POST', headers })
    const data: LoginApiResponse = await res.json()

    if (data.status === 'ok' && data.api_key && data.privileges) {
      email.value = emailAddr
      handleAuthSuccess(data.api_key, data.privileges, remember)
      return 'ok'
    }
    if (data.status === 'missing-totp-token') return 'missing-totp-token'
    return data.reason || 'Login failed.'
  }

  async function logout(): Promise<void> {
    const key = sessionKey.value
    const em = email.value
    clearSession()
    if (key && em) {
      await fetch('/admin/logout', {
        method: 'POST',
        headers: {
          Authorization: 'Basic ' + btoa(`${em}:${key}`),
          'X-Requested-With': 'XMLHttpRequest',
        },
      }).catch(() => {})
    }
  }

  return { sessionKey, email, privileges, isLoggedIn, isAdmin, handleAuthSuccess, clearSession, login, logout }
})
