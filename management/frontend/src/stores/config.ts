import { ref } from 'vue'
import { defineStore } from 'pinia'
import type { InitData } from '@/types'

export const useConfigStore = defineStore('config', () => {
  const el = document.getElementById('__INIT__')
  const init: Partial<InitData> = el?.textContent ? JSON.parse(el.textContent) : {}

  const hostname = ref(init.hostname ?? '')
  const noUsersExist = ref(init.noUsersExist ?? false)
  const noAdminsExist = ref(init.noAdminsExist ?? false)
  const backupS3Hosts = ref<[string, string][]>(init.backupS3Hosts ?? [])

  return { hostname, noUsersExist, noAdminsExist, backupS3Hosts }
})
