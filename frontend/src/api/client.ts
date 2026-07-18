import { toast } from 'vue-sonner'
import router from '@/router'
import { useAuthStore } from '@/stores/auth'
import type { ErrorResponse } from './types.gen'

/**
 * Typed client for the managerd API (/api/*). Bodies are JSON both
 * ways, per the generated contract in types.gen.ts. Authentication
 * rides the HttpOnly session cookie the server sets on login; no
 * token ever passes through JavaScript.
 */

const TIMEOUT_MS = 15_000

/**
 * Call sites use managerd's canonical /api/* paths. In production
 * nginx mounts the panel's API under /admin/api so root /api stays
 * free for the webmail app mounted at /; in dev the vite proxy serves
 * /api directly.
 */
export const API_BASE = import.meta.env.DEV ? '' : '/admin'

/** Thrown for any non-2xx response, carrying the parsed error body. */
export class ApiError extends Error {
  readonly status: number
  readonly hints: string[]

  constructor(status: number, message: string, hints: string[] = []) {
    super(message)
    this.status = status
    this.hints = hints
  }
}

type RequestOptions = {
  /**
   * Suppress the automatic redirect to /login on 401, for calls where
   * "not authenticated" is an expected answer (the startup session
   * probe) rather than an expired session.
   */
  silent401?: boolean
}

async function request<T>(method: string, path: string, body?: unknown, opts?: RequestOptions): Promise<T> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS)

  let res: Response
  try {
    res = await fetch(API_BASE + path, {
      method,
      credentials: 'same-origin',
      headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    })
  } finally {
    clearTimeout(timer)
  }

  // 401 means the credential itself is missing or dead - the session
  // expired. 403 is an authorization outcome (wrong password, not an
  // admin, read-only token) and is surfaced to the caller instead.
  if (res.status === 401 && !opts?.silent401) {
    useAuthStore().clearSession()
    // The redirect below unmounts whatever page/Sheet made this call
    // before its own catch block runs, so any unsaved input in an open
    // form is lost silently unless this explains why here.
    toast.error('Your session expired. Please sign in again.')
    await router.push('/login')
    throw new ApiError(401, 'Session expired')
  }

  if (!res.ok) {
    let message = `Request failed (${res.status})`
    let hints: string[] = []
    try {
      const err = (await res.json()) as ErrorResponse
      if (err.error) message = err.error
      hints = err.hints ?? []
    } catch {
      // Non-JSON error body (e.g. a proxy error page); keep the default.
    }
    throw new ApiError(res.status, message, hints)
  }

  // 202 Accepted (async work queued, e.g. checks/run, reboot) carries no
  // body, same as 204 - res.json() on an empty body throws SyntaxError.
  if (res.status === 204 || res.status === 202) return undefined as T
  return (await res.json()) as T
}

export const api = {
  get: <T>(path: string, opts?: RequestOptions) => request<T>('GET', path, undefined, opts),
  post: <T>(path: string, body?: unknown, opts?: RequestOptions) => request<T>('POST', path, body, opts),
  put: <T>(path: string, body?: unknown, opts?: RequestOptions) => request<T>('PUT', path, body, opts),
  patch: <T>(path: string, body?: unknown, opts?: RequestOptions) => request<T>('PATCH', path, body, opts),
  del: <T>(path: string, opts?: RequestOptions) => request<T>('DELETE', path, undefined, opts),
}
