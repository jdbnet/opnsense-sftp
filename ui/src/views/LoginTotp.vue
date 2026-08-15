<script setup>
import { ref } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const route = useRoute()
const auth = useAuthStore()
const code = ref('')
const error = ref('')
const loading = ref(false)

function isSafeRedirect(path) {
  return typeof path === 'string' && path.startsWith('/') && !path.startsWith('//')
}

async function submit() {
  error.value = ''
  loading.value = true
  try {
    await auth.loginTotp(code.value)
    const redirect = route.query.redirect
    router.push(isSafeRedirect(redirect) ? redirect : '/')
  } catch {
    error.value = 'Invalid authentication code'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="flex min-h-screen items-center justify-center bg-surface px-4">
    <div class="card w-full max-w-md p-8 shadow-xl">
      <div class="mb-6 text-center">
        <h1 class="text-2xl font-semibold text-heading">Two-factor authentication</h1>
        <p class="mt-1 text-sm text-muted">Enter the code from your authenticator app</p>
      </div>
      <form class="space-y-4" @submit.prevent="submit">
        <div v-if="error" class="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-center text-sm text-red-600 dark:text-red-300">
          {{ error }}
        </div>
        <div>
          <label class="mb-1 block text-sm text-muted">Authentication code</label>
          <input v-model="code" type="text" inputmode="numeric" autocomplete="one-time-code" required autofocus class="input-field" />
        </div>
        <button type="submit" class="btn-primary w-full py-2" :disabled="loading">
          {{ loading ? 'Verifying...' : 'Verify' }}
        </button>
      </form>
    </div>
  </div>
</template>
