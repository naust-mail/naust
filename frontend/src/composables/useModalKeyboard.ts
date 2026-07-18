import { watch, onUnmounted, type Ref } from 'vue'

const FOCUSABLE = 'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'

/**
 * Escape-to-close and Tab focus trapping for an overlay panel (Dialog,
 * Sheet, mobile drawer). Wires a single document-level keydown listener
 * while `open` is true so focus never leaves the panel and Escape always
 * closes it, matching standard modal keyboard behavior.
 */
export function useModalKeyboard(open: Ref<boolean | undefined>, panel: Ref<HTMLElement | null>, close: () => void): void {
  function onKeydown(e: KeyboardEvent): void {
    if (e.key === 'Escape') {
      close()
      return
    }
    if (e.key !== 'Tab' || !panel.value) return
    const focusables = Array.from(panel.value.querySelectorAll<HTMLElement>(FOCUSABLE))
    if (focusables.length === 0) return
    const first = focusables[0]
    const last = focusables[focusables.length - 1]
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault()
      last.focus()
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault()
      first.focus()
    }
  }

  watch(open, (val) => {
    if (val) {
      document.addEventListener('keydown', onKeydown)
    } else {
      document.removeEventListener('keydown', onKeydown)
    }
  })

  onUnmounted(() => document.removeEventListener('keydown', onKeydown))
}
