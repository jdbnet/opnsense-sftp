<script setup>
import { onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'
import { PlusCircle } from '@lucide/vue'
import api from '@/api/client'
import { formatDate } from '@/lib/bytes'

const instances = ref([])
const loading = ref(true)

onMounted(async () => {
  try {
    const { data } = await api.get('/instances')
    instances.value = data
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div>
    <div class="mb-6 flex flex-wrap items-center justify-between gap-3">
      <div>
        <h1 class="text-xl font-semibold text-heading">Instances</h1>
        <p class="text-sm text-muted">OPNsense firewalls configured for backup</p>
      </div>
      <RouterLink to="/instances/new" class="btn-primary gap-2">
        <PlusCircle class="h-4 w-4" />
        New instance
      </RouterLink>
    </div>
    <div v-if="loading" class="text-muted">Loading...</div>
    <div v-else-if="instances.length === 0" class="card text-center text-muted">
      No instances yet. Create one to get started.
    </div>
    <div v-else class="card">
      <div class="table-scroll">
        <table class="data-table">
        <thead>
          <tr class="text-muted">
            <th>Name</th>
            <th>Identifier</th>
            <th>Last backup</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="inst in instances" :key="inst.id" class="table-row-hover border-default">
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
