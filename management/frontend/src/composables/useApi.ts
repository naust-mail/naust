import { useAuthStore } from '@/stores/auth'
import router from '@/router'

export function useApi() {
  function authHeader(): string {
    const auth = useAuthStore()
    if (!auth.sessionKey || !auth.email) return ''
    return 'Basic ' + btoa(`${auth.email}:${auth.sessionKey}`)
  }

  async function request(
    method: string,
    url: string,
    body?: Record<string, string> | FormData,
    extraHeaders?: Record<string, string>,
  ): Promise<Response> {
    const headers: Record<string, string> = {
      'X-Requested-With': 'XMLHttpRequest',
      ...extraHeaders,
    }
    const auth = authHeader()
    if (auth) headers['Authorization'] = auth

    const init: RequestInit = { method, headers }
    if (body) {
      if (body instanceof FormData) {
        init.body = body
      } else {
        const fd = new FormData()
        for (const [k, v] of Object.entries(body)) fd.append(k, v)
        init.body = fd
      }
    }

    const res = await fetch(url, init)

    if (res.status === 401 || res.status === 403) {
      useAuthStore().clearSession()
      await router.push('/login')
      throw new Error('Session expired')
    }

    return res
  }

  return {
    get: (url: string, headers?: Record<string, string>) =>
      request('GET', url, undefined, headers),
    post: (url: string, body?: Record<string, string> | FormData, headers?: Record<string, string>) =>
      request('POST', url, body, headers),
    put: (url: string, body?: Record<string, string> | FormData, headers?: Record<string, string>) =>
      request('PUT', url, body, headers),
    del: (url: string, body?: Record<string, string>, headers?: Record<string, string>) =>
      request('DELETE', url, body, headers),
  }
}
