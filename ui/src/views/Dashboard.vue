<script setup>
import { onMounted, ref, computed } from 'vue'
import { RouterLink } from 'vue-router'
import { PlusCircle, Server, Archive, HardDrive } from '@lucide/vue'
import api from '@/api/client'
import { formatBytes, formatDate } from '@/lib/bytes'

const stats = ref(null)
const instances = ref([])
const loading = ref(true)

onMounted(async () => {
  try {
    const [statsRes, instancesRes] = await Promise.all([
      api.get('/dashboard'),
      api.get('/instances'),
    ])
    stats.value = statsRes.data
    instances.value = instancesRes.data
  } finally {
    loading.value = false
  }
})

const sortedInstances = computed(() => {
  return [...instances.value].sort((a, b) => {
    if (!a.last_backup && !b.last_backup) return a.name.localeCompare(b.name)
    if (!a.last_backup) return 1
    if (!b.last_backup) return -1
    return new Date(b.last_backup) - new Date(a.last_backup)
  })
})
</script>

<template>
  <div>
    <div class="mb-6 flex flex-wrap items-center justify-between gap-3">
      <div>
        <h1 class="text-xl font-semibold text-heading">Dashboard</h1>
        <p class="text-sm text-muted">Overview of your OPNsense backup receiver</p>
      </div>
      <RouterLink to="/instances/new" class="btn-primary gap-2">
        <PlusCircle class="h-4 w-4" />
        New instance
      </RouterLink>
    </div>
    <div v-if="loading" class="text-muted">Loading...</div>
    <div v-else-if="stats" class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <div class="card">
        <div class="flex items-center gap-3">
          <Server class="h-8 w-8 text-accent" />
          <div>
            <div class="text-2xl font-semibold text-heading">{{ stats.instance_count }}</div>
            <div class="text-sm text-muted">Instances</div>
          </div>
        </div>
      </div>
      <div class="card">
        <div class="flex items-center gap-3">
          <Archive class="h-8 w-8 text-accent" />
          <div>
            <div class="text-2xl font-semibold text-heading">{{ stats.backup_count }}</div>
            <div class="text-sm text-muted">Backups</div>
          </div>
        </div>
      </div>
      <div class="card">
        <div class="flex items-center gap-3">
          <HardDrive class="h-8 w-8 text-accent" />
          <div>
            <div class="text-2xl font-semibold text-heading">{{ formatBytes(stats.total_size) }}</div>
            <div class="text-sm text-muted">Total size</div>
          </div>
        </div>
      </div>
      <div class="card">
        <div class="text-sm text-muted">SFTP port</div>
        <div class="mt-1 text-2xl font-semibold text-heading">{{ stats.sftp_port }}</div>
        <div v-if="stats.sftp_host" class="mt-1 text-xs text-muted">Host: {{ stats.sftp_host }}</div>
      </div>
    </div>

    <div v-if="!loading" class="card mt-6">
      <h2 class="mb-4 font-medium text-heading">Last backup by instance</h2>
      <div v-if="instances.length === 0" class="text-muted">No instances yet.</div>
      <div v-else class="table-scroll">
        <table class="data-table">
          <thead>
            <tr class="text-muted">
              <th>Instance</th>
              <th>Identifier</th>
              <th>Last backup</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="inst in sortedInstances" :key="inst.id" class="table-row-hover border-default">
              <td class="font-medium text-heading">{{ inst.name }}</td>
              <td><code class="text-sm">{{ inst.identifier }}</code></td>
              <td class="text-muted">{{ formatDate(inst.last_backup) }}</td>
              <td>
                <RouterLink :to="`/instances/${inst.id}`" class="btn-row btn-row-edit">View</RouterLink>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>
