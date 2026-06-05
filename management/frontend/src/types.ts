import type { Component } from 'vue'

/** Bootstrap data injected by Flask into the __INIT__ script tag on page load. */
type InitData = {
  hostname: string
  noUsersExist: boolean
  noAdminsExist: boolean
  backupS3Hosts: [string, string][]
  csrCountryCodes: [string, string][]
}

/** JSON response from POST /admin/login. */
type LoginApiResponse = {
  status: 'ok' | 'missing-totp-token' | 'invalid'
  /** The user's email address (present on ok). */
  email?: string
  /** User privilege list, e.g. ["admin"] (present on ok). */
  privileges?: string[]
  /** Session key used as Basic Auth password for subsequent requests (present on ok). */
  api_key?: string
  /** Human-readable failure reason (present on invalid / missing-totp-token). */
  reason?: string
}

/** JSON response from GET /admin/auth/methods. */
type AuthMethodsResponse = {
  paths: ('passkey' | 'password+totp' | 'password')[]
}

/** A single navigation link in the sidebar. */
type NavItem = {
  label: string
  path: string
  icon: Component
}

/** A labeled group of navigation links in the sidebar. */
type NavGroup = {
  label: string
  items: NavItem[]
}

export type { InitData, LoginApiResponse, AuthMethodsResponse, NavItem, NavGroup }
