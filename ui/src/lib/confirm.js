import { reactive } from 'vue'

export const confirmState = reactive({
  open: false,
  title: 'Are you sure?',
  message: '',
  confirmLabel: 'Delete',
  cancelLabel: 'Cancel',
  resolve: null,
})

export function confirm({ title, message, confirmLabel, cancelLabel } = {}) {
  return new Promise((resolve) => {
    confirmState.title = title || 'Are you sure?'
    confirmState.message = message || ''
    confirmState.confirmLabel = confirmLabel || 'Delete'
    confirmState.cancelLabel = cancelLabel || 'Cancel'
    confirmState.resolve = resolve
    confirmState.open = true
  })
}

function finish(result) {
  confirmState.open = false
  const resolve = confirmState.resolve
  confirmState.resolve = null
  if (resolve) resolve(result)
}

export function confirmAccept() {
  finish(true)
}

export function confirmCancel() {
  finish(false)
}
