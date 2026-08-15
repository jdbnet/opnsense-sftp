<script setup>
import { onMounted, ref } from 'vue'
import api from '@/api/client'

const instances = ref([])
const settings = ref({
  enabled: false,
  scope_type: 'all',
  scope_instance_id: null,
  keep_days: null,
  keep_count: null,
  interval_seconds: 86400,
})
const keepMode = ref('days')
const manual = ref({
  scope_type: 'all',
  scope_instance_id: null,
  keep_days: 30,
  keep_count: 10,
})
const message = ref('')
const error = ref('')
const loading = ref(true)
const saving = ref(false)
const running = ref(false)

onMounted(async () => {
  try {
    const [instRes, settingsRes] = await Promise.all([
      api.get('/instances'),
      api.get('/prune/settings'),
    ])
    instances.value = instRes.data
    settings.value = settingsRes.data
    keepMode.value = settings.value.keep_count != null ? 'count' : 'days'
  } finally {
    loading.value = false
  }
})

async function saveSettings() {
  error.value = ''
  message.value = ''
  saving.value = true
  try {
    const payload = {
      enabled: settings.value.enabled,
      scope_type: settings.value.scope_type,
      scope_instance_id: settings.value.scope_type === 'instance' ? settings.value.scope_instance_id : null,
      keep_days: keepMode.value === 'days' ? settings.value.keep_days : null,
      keep_count: keepMode.value === 'count' ? settings.value.keep_count : null,
      interval_seconds: settings.value.interval_seconds,
    }
    const { data } = await api.put('/prune/settings', payload)
    settings.value = data
    message.value = 'Settings saved'
  } catch (e) {
    error.value = e.response?.data?.error || 'Failed to save settings'
  } finally {
    saving.value = false
  }
}

async function runManual() {
  error.value = ''
  message.value = ''
  running.value = true
  try {
    const payload = {
      scope_type: manual.value.scope_type,
      scope_instance_id: manual.value.scope_type === 'instance' ? manual.value.scope_instance_id : null,
      keep_days: keepMode.value === 'days' ? manual.value.keep_days : null,
      keep_count: keepMode.value === 'count' ? manual.value.keep_count : null,
    }
    const { data } = await api.post('/prune/run', payload)
    message.value = `Pruned ${data.deleted_backups} backup(s), deleted ${data.deleted_files} file(s)`
  } catch (e) {
    error.value = e.response?.data?.error || 'Prune failed'
  } finally {
    running.value = false
  }
}
</script>

<template>
  <div>
    <h1 class="mb-1 text-xl font-semibold text-heading">Backup pruning</h1>
    <p class="mb-6 text-sm text-muted">Configure automated retention or run a manual prune</p>

    <div v-if="loading" class="text-muted">Loading...</div>
    <template v-else>
      <div v-if="message" class="mb-4 rounded-lg border border-accent/40 bg-accent/10 px-3 py-2 text-sm text-accent">{{ message }}</div>
      <div v-if="error" class="mb-4 rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-600 dark:text-red-300">{{ error }}</div>

      <div class="mb-6 card space-y-4">
        <h2 class="font-medium text-heading">Automated pruning</h2>
        <label class="flex items-center gap-2 text-sm">
          <input v-model="settings.enabled" type="checkbox" class="rounded border-default" />
          Enable automated pruning
        </label>
        <div class="grid gap-4 sm:grid-cols-2">
          <div>
            <label class="mb-1 block text-sm text-muted">Scope</label>
            <select v-model="settings.scope_type" class="input-field">
              <option value="all">All instances</option>
              <option value="instance">Single instance</option>
            </select>
          </div>
          <div v-if="settings.scope_type === 'instance'">
            <label class="mb-1 block text-sm text-muted">Instance</label>
            <select v-model="settings.scope_instance_id" class="input-field">
              <option v-for="inst in instances" :key="inst.id" :value="inst.id">{{ inst.name }}</option>
            </select>
          </div>
        </div>
        <div>
          <label class="mb-2 block text-sm text-muted">Retention</label>
          <div class="flex flex-wrap gap-4">
            <label class="flex items-center gap-2 text-sm">
              <input v-model="keepMode" type="radio" value="days" />
              Keep days
            </label>
            <label class="flex items-center gap-2 text-sm">
              <input v-model="keepMode" type="radio" value="count" />
              Keep count
            </label>
          </div>
        </div>
        <div v-if="keepMode === 'days'">
          <label class="mb-1 block text-sm text-muted">Keep backups newer than (days)</label>
          <input v-model.number="settings.keep_days" type="number" min="1" class="input-field w-32" />
        </div>
        <div v-else>
          <label class="mb-1 block text-sm text-muted">Keep newest N backups per instance</label>
          <input v-model.number="settings.keep_count" type="number" min="1" class="input-field w-32" />
        </div>
        <div>
          <label class="mb-1 block text-sm text-muted">Check interval (seconds)</label>
          <input v-model.number="settings.interval_seconds" type="number" min="60" class="input-field w-40" />
        </div>
        <button type="button" class="btn-primary" :disabled="saving" @click="saveSettings">
          {{ saving ? 'Saving...' : 'Save settings' }}
        </button>
      </div>

      <div class="card space-y-4">
        <h2 class="font-medium text-heading">Manual prune</h2>
        <div class="grid gap-4 sm:grid-cols-2">
          <div>
            <label class="mb-1 block text-sm text-muted">Scope</label>
            <select v-model="manual.scope_type" class="input-field">
              <option value="all">All instances</option>
              <option value="instance">Single instance</option>
            </select>
          </div>
          <div v-if="manual.scope_type === 'instance'">
            <label class="mb-1 block text-sm text-muted">Instance</label>
            <select v-model="manual.scope_instance_id" class="input-field">
              <option v-for="inst in instances" :key="inst.id" :value="inst.id">{{ inst.name }}</option>
            </select>
          </div>
        </div>
        <div v-if="keepMode === 'days'">
          <label class="mb-1 block text-sm text-muted">Delete backups older than (days)</label>
          <input v-model.number="manual.keep_days" type="number" min="1" class="input-field w-32" />
        </div>
        <div v-else>
          <label class="mb-1 block text-sm text-muted">Keep newest N backups per instance</label>
          <input v-model.number="manual.keep_count" type="number" min="1" class="input-field w-32" />
        </div>
        <button type="button" class="btn-danger" :disabled="running" @click="runManual">
          {{ running ? 'Running...' : 'Run prune now' }}
        </button>
      </div>
    </template>
  </div>
</template>
