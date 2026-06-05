import { ref } from 'vue'
import { defineStore } from 'pinia'

export const useUiStore = defineStore('ui', () => {
  const sidebarCollapsed = ref(localStorage.getItem('sidebar_collapsed') === 'true')
  const mobileSidebarOpen = ref(false)

  function toggleSidebar(): void {
    sidebarCollapsed.value = !sidebarCollapsed.value
    localStorage.setItem('sidebar_collapsed', String(sidebarCollapsed.value))
  }

  function openMobileSidebar(): void {
    mobileSidebarOpen.value = true
  }

  function closeMobileSidebar(): void {
    mobileSidebarOpen.value = false
  }

  return { sidebarCollapsed, mobileSidebarOpen, toggleSidebar, openMobileSidebar, closeMobileSidebar }
})
