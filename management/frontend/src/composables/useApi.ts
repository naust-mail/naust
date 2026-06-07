import { useAuthStore } from '@/stores/auth'
import router from '@/router'

export function useApi() {
  async function request(
    method: string,
    url: string,
    body?: Record<string, string> | FormData | string,
    extraHeaders?: Record<string, string>,
  ): Promise<Response> {
    const headers: Record<string, string> = {
      'X-Requested-With': 'XMLHttpRequest',
      ...extraHeaders,
    }

    const init: RequestInit = { method, headers, credentials: 'same-origin' }
    if (body) {
      if (typeof body === 'string') {
        // Raw text body — used by DNS endpoints that read request.stream directly
        init.body = body
        headers['Content-Type'] = 'text/plain; charset=ascii'
      } else if (body instanceof FormData) {
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
    post: (url: string, body?: Record<string, string> | FormData | string, headers?: Record<string, string>) =>
      request('POST', url, body, headers),
    put: (url: string, body?: Record<string, string> | FormData | string, headers?: Record<string, string>) =>
      request('PUT', url, body, headers),
    del: (url: string, body?: Record<string, string> | string, headers?: Record<string, string>) =>
      request('DELETE', url, body, headers),
  }
}
