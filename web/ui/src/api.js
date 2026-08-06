// API 客户端：封装 fetch，支持 Basic Auth 与错误处理。
//
// 认证流程：
//   1. 若 localStorage 有 relay_auth，每次请求带 Authorization: Basic <base64>
//      （用 localStorage 而非 sessionStorage，是为了让登录状态跨标签页 /
//       关闭重开浏览器后仍然保持，等价于“记住我”）
//   2. 收到 401 → 清除认证、抛 AuthError，App 弹出登录框
//   3. 未配置 auth 的实例，不带头也能正常访问；是否需要登录完全由
//      实际请求是否返回 401 决定，不再由“本地是否存有 token”猜测

const AUTH_KEY = 'relay_auth'

export class AuthError extends Error {
  constructor(msg = '需要登录') {
    super(msg)
    this.name = 'AuthError'
  }
}

/** 保存 base64(user:pass) 到 localStorage，跨会话保持登录。 */
export function setAuth(username, password) {
  const raw = `${username}:${password}`
  const encoded = btoa(raw)
  localStorage.setItem(AUTH_KEY, encoded)
}

export function clearAuth() {
  localStorage.removeItem(AUTH_KEY)
}

export function hasAuth() {
  return !!localStorage.getItem(AUTH_KEY)
}

function authHeader() {
  const token = localStorage.getItem(AUTH_KEY)
  return token ? { Authorization: `Basic ${token}` } : {}
}

async function apiGet(path, params) {
  let url = path
  if (params) {
    const sp = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') sp.append(k, v)
    }
    const qs = sp.toString()
    if (qs) url += `?${qs}`
  }
  const resp = await fetch(url, { headers: { ...authHeader(), Accept: 'application/json' } })
  if (resp.status === 401) {
    clearAuth()
    throw new AuthError()
  }
  if (!resp.ok) {
    throw new Error(`HTTP ${resp.status}: ${await resp.text().catch(() => resp.statusText)}`)
  }
  return resp.json()
}

// ============================================================
// API 端点
// ============================================================

export const api = {
  /** 总览计数器 */
  stats: () => apiGet('/api/stats'),

  /** 上游延迟/成功率 */
  upstreams: () => apiGet('/api/upstreams'),

  /** 规则命中排行 */
  rules: () => apiGet('/api/rules'),

  /** 客户端 Top N */
  clients: (limit = 20) => apiGet('/api/clients', { limit }),

  /** 查询日志 */
  queryLog: (limit = 100, opts = {}) =>
    apiGet('/api/querylog', { limit, domain: opts.domain, client: opts.client, history: opts.history }),

  /** 一次返回全部门面数据（推荐首屏用） */
  dashboard: () => apiGet('/api/dashboard'),
}
