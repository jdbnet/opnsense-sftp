<script setup>
import { ref } from 'vue'
import { useRouter, RouterLink } from 'vue-router'
import api from '@/api/client'

const router = useRouter()
const name = ref('')
const identifier = ref('')
const description = ref('')
const error = ref('')
const loading = ref(false)

async function submit() {
  error.value = ''
  loading.value = true
  try {
    const { data } = await api.post('/instances', {
      name: name.value,
      identifier: identifier.value,
      description: description.value,
    })
    router.push(`/instances/${data.id}`)
  } catch (e) {
    error.value = e.response?.data?.error || 'Failed to create instance'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="mx-auto max-w-xl">
    <h1 class="mb-1 text-xl font-semibold text-heading">New instance</h1>
    <p class="mb-6 text-sm text-muted">Add an OPNsense firewall to receive backups from</p>
    <form class="card space-y-4" @submit.prevent="submit">
      <div v-if="error" class="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-600 dark:text-red-300">
        {{ error }}
      </div>
      <div>
        <label class="mb-1 block text-sm text-muted">Name</label>
        <input v-model="name" type="text" required class="input-field" placeholder="Office firewall" />
      </div>
      <div>
        <label class="mb-1 block text-sm text-muted">Identifier</label>
        <input v-model="identifier" type="text" required pattern="[a-zA-Z0-9_-]+" class="input-field" placeholder="office" />
        <p class="mt-1 text-xs text-muted">Used as the SFTP username. Letters, numbers, underscores, hyphens only.</p>
      </div>
      <div>
        <label class="mb-1 block text-sm text-muted">Description</label>
        <textarea v-model="description" rows="3" class="input-field" />
      </div>
      <div class="flex gap-2">
        <button type="submit" class="btn-primary" :disabled="loading">
          {{ loading ? 'Creating...' : 'Create instance' }}
        </button>
        <RouterLink to="/instances" class="btn-secondary">Cancel</RouterLink>
      </div>
    </form>
  </div>
</template>
