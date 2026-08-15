import { defineStore } from 'pinia'

export function applyTheme(dark) {
  document.documentElement.classList.toggle('dark', dark)
  localStorage.setItem('opnsense-sftp-theme', dark ? 'dark' : 'light')
}

export function readInitialTheme() {
  const saved = localStorage.getItem('opnsense-sftp-theme')
  if (saved === 'dark') return true
  if (saved === 'light') return false
  return window.matchMedia('(prefers-color-scheme: dark)').matches
}

export const useThemeStore = defineStore('theme', {
  state: () => ({ dark: readInitialTheme() }),
  actions: {
    toggle() {
      this.dark = !this.dark
      applyTheme(this.dark)
    },
  },
})
