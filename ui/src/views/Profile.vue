<script setup>
import { onMounted, ref } from 'vue'
import { useAuthStore } from '@/stores/auth'
import api from '@/api/client'

const auth = useAuthStore()
const username = ref('')
const currentPassword = ref('')
const newPassword = ref('')
const totpCode = ref('')
const totpSecret = ref('')
const totpURI = ref('')
const message = ref('')
const error = ref('')

onMounted(() => {
  username.value = auth.me?.user?.username || ''
})

async function saveProfile() {
  error.value = ''
  message.value = ''
  try {
    await api.put('/profile', {
      username: username.value,
      current_password: currentPassword.value || undefined,
      new_password: newPassword.value || undefined,
    })
    currentPassword.value = ''
    newPassword.value = ''
    message.value = 'Profile updated'
    await auth.check()
  } catch (e) {
    error.value = e.response?.data?.error || 'Update failed'
  }
}

async function generateTOTP() {
  error.value = ''
  try {
    const { data } = await api.post('/profile/totp/generate')
    totpSecret.value = data.secret
    totpURI.value = data.uri
    message.value = 'Scan the URI in your authenticator app, then enter a code to enable'
  } catch (e) {
    error.value = e.response?.data?.error || 'Failed to generate TOTP'
  }
}

async function enableTOTP() {
  error.value = ''
  try {
    await api.post('/profile/totp/enable', { code: totpCode.value })
    totpCode.value = ''
    totpSecret.value = ''
    message.value = 'TOTP enabled'
    await auth.check()
  } catch (e) {
    error.value = e.response?.data?.error || 'Invalid code'
  }
}

async function disableTOTP() {
  error.value = ''
  try {
    await api.post('/profile/totp/disable')
    message.value = 'TOTP disabled'
    await auth.check()
  } catch (e) {
    error.value = e.response?.data?.error || 'Failed to disable TOTP'
  }
}
</script>

<template>
  <div class="mx-auto max-w-xl space-y-6">
    <div>
      <h1 class="text-xl font-semibold text-heading">Profile</h1>
      <p class="text-sm text-muted">Manage your account settings</p>
    </div>

    <div v-if="message" class="rounded-lg border border-accent/40 bg-accent/10 px-3 py-2 text-sm text-accent">{{ message }}</div>
    <div v-if="error" class="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-600 dark:text-red-300">{{ error }}</div>

    <form class="card space-y-4" @submit.prevent="saveProfile">
      <h2 class="font-medium text-heading">Account</h2>
      <div>
        <label class="mb-1 block text-sm text-muted">Username</label>
        <input v-model="username" type="text" required class="input-field" />
      </div>
      <div>
        <label class="mb-1 block text-sm text-muted">Current password</label>
        <input v-model="currentPassword" type="password" class="input-field" autocomplete="current-password" />
      </div>
      <div>
        <label class="mb-1 block text-sm text-muted">New password</label>
        <input v-model="newPassword" type="password" class="input-field" autocomplete="new-password" />
      </div>
      <button type="submit" class="btn-primary">Save changes</button>
    </form>

    <div class="card space-y-4">
      <h2 class="font-medium text-heading">Two-factor authentication</h2>
      <p class="text-sm text-muted">
        Status:
        <span :class="auth.me?.user?.totp_enabled ? 'text-accent' : ''">
          {{ auth.me?.user?.totp_enabled ? 'Enabled' : 'Disabled' }}
        </span>
      </p>
      <template v-if="!auth.me?.user?.totp_enabled">
        <button type="button" class="btn-secondary" @click="generateTOTP">Generate TOTP secret</button>
        <div v-if="totpSecret" class="space-y-2 text-sm">
          <p class="text-muted">Secret: <code>{{ totpSecret }}</code></p>
          <p class="break-all text-muted">URI: {{ totpURI }}</p>
          <div>
            <label class="mb-1 block text-sm text-muted">Verification code</label>
            <input v-model="totpCode" type="text" class="input-field" />
          </div>
          <button type="button" class="btn-primary" @click="enableTOTP">Enable TOTP</button>
        </div>
      </template>
      <button v-else type="button" class="btn-danger" @click="disableTOTP">Disable TOTP</button>
    </div>
  </div>
</template>
