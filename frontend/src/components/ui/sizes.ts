/**
 * Shared size scale for form controls and buttons. Button, Input, and Select
 * all pull height/text classes from here so a control and its paired button
 * (e.g. a "Generate" button next to a password field) always line up.
 */
export type UiSize = 'sm' | 'md' | 'lg'

export const UI_SIZE_HEIGHT: Record<UiSize, string> = {
  sm: 'h-8',
  md: 'h-9',
  lg: 'h-10',
}

export const UI_SIZE_TEXT: Record<UiSize, string> = {
  sm: 'text-xs',
  md: 'text-sm',
  lg: 'text-sm',
}
