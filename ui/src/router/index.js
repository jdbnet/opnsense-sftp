import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import Login from '@/views/Login.vue'
import LoginTotp from '@/views/LoginTotp.vue'
import Dashboard from '@/views/Dashboard.vue'
import Instances from '@/views/Instances.vue'
import NewInstance from '@/views/NewInstance.vue'
import InstanceDetail from '@/views/InstanceDetail.vue'
import Backups from '@/views/Backups.vue'
import Prune from '@/views/Prune.vue'
import Profile from '@/views/Profile.vue'
import Users from '@/views/Users.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', name: 'login', component: Login, meta: { public: true } },
    { path: '/login/totp', name: 'login-totp', component: LoginTotp, meta: { public: true } },
    { path: '/', name: 'dashboard', component: Dashboard },
    { path: '/instances', name: 'instances', component: Instances },
    { path: '/instances/new', name: 'new-instance', component: NewInstance },
    { path: '/instances/:id', name: 'instance-detail', component: InstanceDetail },
    { path: '/backups', name: 'backups', component: Backups },
    { path: '/prune', name: 'prune', component: Prune },
    { path: '/profile', name: 'profile', component: Profile },
    { path: '/users', name: 'users', component: Users },
  ],
})

router.beforeEach(async (to) => {
  const auth = useAuthStore()
  if (!auth.checked) {
    try {
      await auth.check()
    } catch {
      auth.checked = true
    }
  }
  if (to.meta.public) {
    if (auth.authenticated && to.path === '/login') return '/'
    return true
  }
  if (auth.authRequired && !auth.authenticated) {
    return { path: '/login', query: { redirect: to.fullPath } }
  }
  if (to.path === '/users' && !auth.me?.user?.is_admin) {
    return '/'
  }
  return true
})

export default router
