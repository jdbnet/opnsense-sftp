<script setup>
import { onMounted, ref } from 'vue'
import { Copy, Trash2 } from '@lucide/vue'
import api from '@/api/client'
import { confirm } from '@/lib/confirm'
import { formatDate } from '@/lib/bytes'

const keys = ref([])
const showForm = ref(false)
const name = ref('')
const createdKey = ref('')
const copied = ref(false)
const error = ref('')
const loading = ref(true)

onMounted(load)

async function load() {
  loading.value = true
  try {
    const { data } = await api.get('/api-keys')
    keys.value = data
  } finally {
    loading.value = false
  }
}

async function createKey() {
  error.value = ''
  copied.value = false
  try {
    const { data } = await api.post('/api-keys', { name: name.value })
    createdKey.value = data.key
    name.value = ''
    showForm.value = false
    await load()
  } catch (e) {
    error.value = e.response?.data?.error || 'Failed to create API key'
  }
}

async function copyKey() {
  await navigator.clipboard.writeText(createdKey.value)
  copied.value = true
}

async function revokeKey(item) {
  const ok = await confirm({
    title: 'Revoke API key?',
    message: `Revoke ${item.name}? Clients using it will no longer be able to read backup status.`,
    confirmLabel: 'Revoke',
  })
  if (!ok) return
  error.value = ''
  try {
    await api.delete(`/api-keys/${item.id}`)
    await load()
  } catch (e) {
    error.value = e.response?.data?.error || 'Failed to revoke API key'
  }
}

function sourceLabel(source) {
  return source === 'config' ? 'Configuration' : 'App'
}
</script>

<template>
  <div>
    <div class="mb-6 flex flex-wrap items-center justify-between gap-3">
      <div>
        <h1 class="text-xl font-semibold text-heading">API keys</h1>
        <p class="text-sm text-muted">Read-only keys for the backup status API. They cannot change backups or settings.</p>
      </div>
      <button type="button" class="btn-primary" @click="showForm = !showForm">
        {{ showForm ? 'Cancel' : 'Create API key' }}
      </button>
    </div>

    <div v-if="error" class="mb-4 rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-600 dark:text-red-300">{{ error }}</div>

    <div v-if="createdKey" class="card mb-6 space-y-3 border-amber-500/50">
      <p class="text-sm text-heading">Copy this key now. It is shown only once and cannot be retrieved later.</p>
      <code class="block break-all rounded-lg bg-black/5 px-3 py-2 text-sm dark:bg-white/5">{{ createdKey }}</code>
      <div class="flex gap-2">
        <button type="button" class="btn-secondary" @click="copyKey">
          <Copy class="h-4 w-4" />
          {{ copied ? 'Copied' : 'Copy key' }}
        </button>
        <button type="button" class="btn-ghost" @click="createdKey = ''">Dismiss</button>
      </div>
    </div>

    <form v-if="showForm" class="card mb-6 space-y-4" @submit.prevent="createKey">
      <div>
        <label class="mb-1 block text-sm text-muted">Name</label>
        <input v-model="name" type="text" required maxlength="128" class="input-field" placeholder="Dashboard" />
      </div>
      <button type="submit" class="btn-primary">Create API key</button>
    </form>

    <div v-if="loading" class="text-muted">Loading...</div>
    <div v-else class="card">
      <p v-if="keys.length === 0" class="text-sm text-muted">No API keys yet.</p>
      <div v-else class="table-scroll">
        <table class="data-table">
          <thead>
            <tr class="text-muted">
              <th>Name</th>
              <th>Prefix</th>
              <th>Source</th>
              <th>Created</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in keys" :key="item.id" class="table-row-hover border-default">
              <td class="font-medium text-heading">{{ item.name }}</td>
              <td class="font-mono text-muted">{{ item.prefix }}...</td>
              <td>{{ sourceLabel(item.source) }}</td>
              <td class="text-muted">{{ formatDate(item.created_at) }}</td>
              <td>
                <button
                  v-if="item.source !== 'config'"
                  type="button"
                  class="btn-row btn-row-danger"
                  @click="revokeKey(item)"
                >
                  <Trash2 class="h-3.5 w-3.5" />
                  Revoke
                </button>
                <span v-else class="text-xs text-muted">Remove from configuration</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <p class="mt-4 text-xs text-muted">Keys from configuration are applied when the service starts. Remove them from the config file to revoke them.</p>
    </div>
  </div>
</template>
