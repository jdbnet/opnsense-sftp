<script setup>
import { onMounted, ref } from 'vue'
import { useRoute, RouterLink } from 'vue-router'
import { Copy, Download, Trash2 } from '@lucide/vue'
import api from '@/api/client'
import { confirm } from '@/lib/confirm'
import { formatBytes, formatDate } from '@/lib/bytes'

const route = useRoute()
const instance = ref(null)
const loading = ref(true)
const copied = ref('')

onMounted(load)

async function load() {
  loading.value = true
  try {
    const { data } = await api.get(`/instances/${route.params.id}`)
    instance.value = data
  } finally {
    loading.value = false
  }
}

async function copyText(text, label) {
  await navigator.clipboard.writeText(text)
  copied.value = label
  setTimeout(() => { copied.value = '' }, 2000)
}

function downloadKey() {
  window.location.href = `/api/v1/instances/${route.params.id}/private-key`
}

function downloadBackup(id) {
  window.location.href = `/api/v1/backups/${id}/download`
}

async function removeBackup(id, filename) {
  const ok = await confirm({ title: 'Delete backup?', message: `Delete ${filename}? This cannot be undone.` })
  if (!ok) return
  await api.delete(`/backups/${id}`)
  await load()
}
</script>

<template>
  <div v-if="loading" class="text-muted">Loading...</div>
  <div v-else-if="instance">
    <div class="mb-6">
      <RouterLink to="/instances" class="text-sm text-accent hover:text-accent-muted">← Back to instances</RouterLink>
      <h1 class="mt-2 text-xl font-semibold text-heading">{{ instance.name }}</h1>
      <p v-if="instance.description" class="text-sm text-muted">{{ instance.description }}</p>
    </div>

    <div class="mb-6 grid gap-4 lg:grid-cols-2">
      <div class="card space-y-4">
        <h2 class="font-medium text-heading">OPNsense configuration</h2>
        <p class="text-sm text-muted">Configure in System → Configuration → Backups</p>
        <div>
          <label class="mb-1 block text-xs text-muted">SFTP URI</label>
          <div class="flex gap-2">
            <input :value="instance.sftp_uri" readonly class="input-field font-mono text-xs" />
            <button type="button" class="btn-secondary shrink-0" @click="copyText(instance.sftp_uri, 'uri')">
              <Copy class="h-4 w-4" />
            </button>
          </div>
          <p v-if="copied === 'uri'" class="mt-1 text-xs text-accent">Copied!</p>
        </div>
        <div>
          <label class="mb-1 block text-xs text-muted">Private key</label>
          <button type="button" class="btn-secondary gap-2" @click="downloadKey">
            <Download class="h-4 w-4" />
            Download private key
          </button>
        </div>
      </div>

      <div class="card space-y-2 text-sm">
        <h2 class="font-medium text-heading">Details</h2>
        <div class="flex justify-between"><span class="text-muted">Identifier</span><code>{{ instance.identifier }}</code></div>
        <div class="flex justify-between"><span class="text-muted">Last backup</span><span>{{ formatDate(instance.last_backup) }}</span></div>
        <div class="flex justify-between"><span class="text-muted">Created</span><span>{{ formatDate(instance.created_at) }}</span></div>
      </div>
    </div>

    <div class="card">
      <h2 class="mb-4 font-medium text-heading">Recent backups</h2>
      <div v-if="!instance.recent_backups?.length" class="text-muted">No backups yet</div>
      <div v-else class="table-scroll">
        <table class="data-table">
          <thead>
            <tr class="text-muted">
              <th>Filename</th>
              <th>Size</th>
              <th>Uploaded</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="b in instance.recent_backups" :key="b.id" class="table-row-hover border-default">
              <td>{{ b.filename }}</td>
              <td>{{ formatBytes(b.file_size) }}</td>
              <td class="text-muted">{{ formatDate(b.uploaded_at) }}</td>
              <td class="flex gap-1">
                <button type="button" class="btn-row btn-row-copy" @click="downloadBackup(b.id)">
                  <Download class="h-3.5 w-3.5" />
                </button>
                <button type="button" class="btn-row btn-row-danger" @click="removeBackup(b.id, b.filename)">
                  <Trash2 class="h-3.5 w-3.5" />
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>
