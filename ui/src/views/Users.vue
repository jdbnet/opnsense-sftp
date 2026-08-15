<script setup>
import { onMounted, ref } from 'vue'
import { Trash2 } from '@lucide/vue'
import api from '@/api/client'
import { confirm } from '@/lib/confirm'
import { formatDate } from '@/lib/bytes'

const users = ref([])
const showForm = ref(false)
const username = ref('')
const password = ref('')
const isAdmin = ref(false)
const error = ref('')
const loading = ref(true)

onMounted(load)

async function load() {
  loading.value = true
  try {
    const { data } = await api.get('/users')
    users.value = data
  } finally {
    loading.value = false
  }
}

async function createUser() {
  error.value = ''
  try {
    await api.post('/users', { username: username.value, password: password.value, is_admin: isAdmin.value })
    username.value = ''
    password.value = ''
    isAdmin.value = false
    showForm.value = false
    await load()
  } catch (e) {
    error.value = e.response?.data?.error || 'Failed to create user'
  }
}

async function toggleAdmin(user) {
  await api.put(`/users/${user.id}/toggle-admin`)
  await load()
}

async function removeUser(user) {
  const ok = await confirm({ title: 'Delete user?', message: `Delete ${user.username}?` })
  if (!ok) return
  try {
    await api.delete(`/users/${user.id}`)
    await load()
  } catch (e) {
    error.value = e.response?.data?.error || 'Failed to delete user'
  }
}
</script>

<template>
  <div>
    <div class="mb-6 flex flex-wrap items-center justify-between gap-3">
      <div>
        <h1 class="text-xl font-semibold text-heading">Users</h1>
        <p class="text-sm text-muted">Manage application users</p>
      </div>
      <button type="button" class="btn-primary" @click="showForm = !showForm">
        {{ showForm ? 'Cancel' : 'Add user' }}
      </button>
    </div>

    <div v-if="error" class="mb-4 rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-600 dark:text-red-300">{{ error }}</div>

    <form v-if="showForm" class="card mb-6 space-y-4" @submit.prevent="createUser">
      <div>
        <label class="mb-1 block text-sm text-muted">Username</label>
        <input v-model="username" type="text" required class="input-field" />
      </div>
      <div>
        <label class="mb-1 block text-sm text-muted">Password</label>
        <input v-model="password" type="password" required class="input-field" />
      </div>
      <label class="flex items-center gap-2 text-sm">
        <input v-model="isAdmin" type="checkbox" class="rounded border-default" />
        Administrator
      </label>
      <button type="submit" class="btn-primary">Create user</button>
    </form>

    <div v-if="loading" class="text-muted">Loading...</div>
    <div v-else class="card">
      <div class="table-scroll">
        <table class="data-table">
        <thead>
          <tr class="text-muted">
            <th>Username</th>
            <th>Role</th>
            <th>TOTP</th>
            <th>Created</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="user in users" :key="user.id" class="table-row-hover border-default">
            <td class="font-medium text-heading">{{ user.username }}</td>
            <td>{{ user.is_admin ? 'Admin' : 'User' }}</td>
            <td>{{ user.totp_enabled ? 'Yes' : 'No' }}</td>
            <td class="text-muted">{{ formatDate(user.created_at) }}</td>
            <td class="flex gap-1">
              <button type="button" class="btn-row btn-row-edit" @click="toggleAdmin(user)">
                {{ user.is_admin ? 'Revoke admin' : 'Make admin' }}
              </button>
              <button type="button" class="btn-row btn-row-danger" @click="removeUser(user)">
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
