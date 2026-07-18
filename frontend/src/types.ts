import type { Component } from 'vue'

/** The 6 available color palettes for the admin panel. */
export type Palette = 'zinc' | 'rav' | 'indigo' | 'nord' | 'emerald' | 'catppuccin'

/** A single navigation link in the sidebar. */
type NavItem = {
  label: string
  path: string
  icon: Component
  /** If true, only rendered for admin users. */
  adminOnly?: boolean
}

/** A labeled group of navigation links in the sidebar. */
type NavGroup = {
  label: string
  items: NavItem[]
}

export type { NavItem, NavGroup }
