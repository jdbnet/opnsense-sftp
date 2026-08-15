<script setup>
import { onMounted, ref, watch } from 'vue'
import { Download, Trash2 } from '@lucide/vue'
import api from '@/api/client'
import { confirm } from '@/lib/confirm'
import { formatBytes, formatDate } from '@/lib/bytes'

const backups = ref([])
const instances = ref([])
const instanceId = ref('')
const page = ref(1)
const pages = ref(1)
const total = ref(0)
const loading = ref(true)

async function load() {
  loading.value = true
  try {
    const params = { page: page.value, per_page: 25 }
    if (instanceId.value) params.instance_id = instanceId.value
    const { data } = await api.get('/backups', { params })
    backups.value = data.items
    pages.value = data.pages
    total.value = data.total
  } finally {
    loading.value = false
  }
}

onMounted(async () => {
  const { data } = await api.get('/instances')
  instances.value = data
  await load()
})

watch([page, instanceId], load)

function download(id) {
  window.location.href = `/api/v1/backups/${id}/download`
}

async function remove(id, filename) {
  const ok = await confirm({ title: 'Delete backup?', message: `Delete ${filename}? This cannot be undone.` })
  if (!ok) return
  await api.delete(`/backups/${id}`)
  await load()
}
</script>

<template>
  <div>
    <div class="mb-6">
      <h1 class="text-xl font-semibold text-heading">Backups</h1>
      <p class="text-sm text-muted">{{ total }} backup(s) stored</p>
    </div>

    <div class="card">
      <div class="mb-4 flex flex-wrap gap-3">
        <select v-model="instanceId" class="input-field w-auto min-w-[200px]">
          <option value="">All instances</option>
          <option v-for="inst in instances" :key="inst.id" :value="inst.id">{{ inst.name }}</option>
        </select>
      </div>

      <div v-if="loading" class="text-muted">Loading...</div>
      <div v-else-if="backups.length === 0" class="text-center text-muted">No backups found</div>
      <div v-else class="table-scroll">
        <table class="data-table">
        <thead>
          <tr class="text-muted">
            <th>Instance</th>
            <th>Filename</th>
            <th>Size</th>
            <th>Uploaded</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="b in backups" :key="b.id" class="table-row-hover border-default">
            <td>{{ b.instance_name }}</td>
            <td>{{ b.filename }}</td>
            <td>{{ formatBytes(b.file_size) }}</td>
            <td class="text-muted">{{ formatDate(b.uploaded_at) }}</td>
            <td class="flex gap-1">
              <button type="button" class="btn-row btn-row-copy" @click="download(b.id)">
                <Download class="h-3.5 w-3.5" />
              </button>
              <button type="button" class="btn-row btn-row-danger" @click="remove(b.id, b.filename)">
                <Trash2 class="h-3.5 w-3.5" />
              </button>
            </td>
          </tr>
        </tbody>
      </table>
      </div>

      <div v-if="!loading && pages > 1" class="mt-4 flex items-center gap-2">
        <button type="button" class="btn-secondary" :disabled="page <= 1" @click="page--">Previous</button>
        <span class="text-sm text-muted">Page {{ page }} of {{ pages }}</span>
        <button type="button" class="btn-secondary" :disabled="page >= pages" @click="page++">Next</button>
      </div>
    </div>
  </div>
</template>
