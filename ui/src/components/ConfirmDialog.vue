<script setup>
import { onMounted, onUnmounted, watch } from 'vue'
import { confirmAccept, confirmCancel, confirmState } from '@/lib/confirm'

function onKey(ev) {
  if (ev.key === 'Escape' && confirmState.open) confirmCancel()
}

watch(() => confirmState.open, (open) => {
  document.body.style.overflow = open ? 'hidden' : ''
})

onMounted(() => window.addEventListener('keydown', onKey))
onUnmounted(() => {
  window.removeEventListener('keydown', onKey)
  document.body.style.overflow = ''
})
</script>

<template>
  <Teleport to="body">
    <div v-if="confirmState.open" class="fixed inset-0 z-[100] flex items-center justify-center p-4">
      <div class="absolute inset-0 bg-black/50" aria-hidden="true" @click="confirmCancel" />
      <div role="alertdialog" aria-modal="true" class="card relative z-10 w-full max-w-md shadow-xl">
        <h2 class="text-lg font-semibold text-heading">{{ confirmState.title }}</h2>
        <p v-if="confirmState.message" class="mt-2 text-sm text-muted">{{ confirmState.message }}</p>
        <div class="mt-5 flex justify-end gap-2">
          <button type="button" class="btn-ghost" @click="confirmCancel">{{ confirmState.cancelLabel }}</button>
          <button type="button" class="btn-danger" @click="confirmAccept">{{ confirmState.confirmLabel }}</button>
        </div>
      </div>
    </div>
  </Teleport>
</template>
