import { useState, useEffect, useCallback, useRef } from 'react'
import { api, AuthError, setAuth, clearAuth } from './api.js'

const REFRESH_INTERVAL = 3000 // 自动刷新间隔（ms）

export default function App() {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [showLogin, setShowLogin] = useState(false)
  const [tab, setTab] = useState('overview')
  const timerRef = useRef(null)

  const fetchData = useCallback(async () => {
    try {
      const d = await api.dashboard()
      setData(d)
      setError(null)
    } catch (e) {
      if (e instanceof AuthError) {
        setShowLogin(true)
      } else {
        setError(e.message)
      }
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  useEffect(() => {
    if (autoRefresh && !showLogin) {
      timerRef.current = setInterval(fetchData, REFRESH_INTERVAL)
      return () => clearInterval(timerRef.current)
    }
  }, [autoRefresh, showLogin, fetchData])

  // 只有明确收到过 401（showLogin）才显示登录框。
  // 不能仅凭本地是否存有 token（hasAuth）来判断——
  // 服务端未开启 auth.enable 时，即使没有 token 也应直接放行，
  // 让下面的实际请求结果（成功 / AuthError）来决定要不要弹登录框。
  if (showLogin) {
    return <Login onLogin={() => { setShowLogin(false); setLoading(true); fetchData() }} />
  }

  if (loading && !data) return <div className="loading">加载中…</div>

  return (
    <div className="app">
      <header className="header">
        <h1>Relay</h1>
        <div className="header-controls">
          <label className="toggle">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
            />
            自动刷新
          </label>
          <button
            className="btn-refresh"
            onClick={fetchData}
          >
            刷新
          </button>
          <button
            className="btn-logout"
            onClick={() => { clearAuth(); setShowLogin(true) }}
          >
            退出
          </button>
        </div>
      </header>

      {error && <div className="error-bar">错误：{error}</div>}

      <nav className="tabs">
        <button className={tab === 'overview' ? 'active' : ''} onClick={() => setTab('overview')}>总览</button>
        <button className={tab === 'upstreams' ? 'active' : ''} onClick={() => setTab('upstreams')}>上游</button>
        <button className={tab === 'rules' ? 'active' : ''} onClick={() => setTab('rules')}>规则</button>
        <button className={tab === 'clients' ? 'active' : ''} onClick={() => setTab('clients')}>客户端</button>
        <button className={tab === 'querylog' ? 'active' : ''} onClick={() => setTab('querylog')}>查询日志</button>
      </nav>

      <main className="main">
        {tab === 'overview' && <Overview data={data} />}
        {tab === 'upstreams' && <Upstreams data={data} />}
        {tab === 'rules' && <Rules data={data} />}
        {tab === 'clients' && <Clients data={data} />}
        {tab === 'querylog' && <QueryLog data={data} />}
      </main>

      <footer className="footer">
        Relay · 自动刷新 {autoRefresh ? '开启' : '关闭'} ·
        更新于 {data ? new Date().toLocaleTimeString() : '-'}
      </footer>
    </div>
  )
}

// ============================================================
// 登录表单
// ============================================================
function Login({ onLogin }) {
  const [user, setUser] = useState('')
  const [pass, setPass] = useState('')
  const [err, setErr] = useState(null)

  const submit = async (e) => {
    e.preventDefault()
    setAuth(user, pass)
    try {
      await api.stats()
      onLogin()
    } catch (e) {
      setErr('用户名或密码错误')
      clearAuth()
    }
  }

  return (
    <div className="login-page">
      <form className="login-form" onSubmit={submit}>
        <h2>Relay 登录</h2>
        {err && <div className="error-bar">{err}</div>}
        <input
          type="text"
          placeholder="用户名"
          value={user}
          onChange={(e) => setUser(e.target.value)}
          autoFocus
          required
        />
        <input
          type="password"
          placeholder="密码"
          value={pass}
          onChange={(e) => setPass(e.target.value)}
          required
        />
        <button type="submit">登录</button>
      </form>
    </div>
  )
}

// ============================================================
// 总览页
// ============================================================
function Overview({ data }) {
  const { stats, upstreams, recent_queries } = data

  return (
    <>
      <div className="cards">
        <Card label="总查询" value={fmt(stats.total_queries)} color="blue" />
        <Card label="已拦截" value={fmt(stats.total_blocked)} color="red" />
        <Card label="失败" value={fmt(stats.total_failed)} color="orange" />
        <Card label="缓存命中" value={fmt(stats.cache_hits)} color="green" />
        <Card label="Hosts 命中" value={fmt(stats.hosts_hits)} color="purple" />
        <Card label="平均延迟" value={`${stats.avg_latency_ms.toFixed(1)} ms`} color="cyan" />
      </div>

      <div className="two-col">
        <section className="panel">
          <h3>响应码分布</h3>
          <BarList
            items={stats.by_rcode.map(([k, v]) => ({ label: k, value: v }))}
            color="#3b82f6"
          />
        </section>

        <section className="panel">
          <h3>查询类型分布</h3>
          <BarList
            items={stats.by_type.map(([k, v]) => ({ label: k, value: v }))}
            color="#8b5cf6"
          />
        </section>
      </div>

      <section className="panel">
        <h3>上游性能</h3>
        <UpstreamTable rows={upstreams} />
      </section>

      <section className="panel">
        <h3>最近查询</h3>
        <QueryLogTable rows={recent_queries} />
      </section>
    </>
  )
}

// ============================================================
// 上游页
// ============================================================
function Upstreams({ data }) {
  return (
    <section className="panel">
      <h3>上游性能详情</h3>
      <UpstreamTable rows={data.upstreams} />
    </section>
  )
}

// ============================================================
// 规则页
// ============================================================
function Rules({ data }) {
  return (
    <section className="panel">
      <h3>规则命中排行</h3>
      <BarList
        items={data.rules.map(([k, v]) => ({ label: k, value: v }))}
        color="#10b981"
      />
    </section>
  )
}

// ============================================================
// 客户端页
// ============================================================
function Clients({ data }) {
  return (
    <section className="panel">
      <h3>客户端 Top 20</h3>
      <BarList
        items={data.clients.map(([k, v]) => ({ label: k, value: v }))}
        color="#f59e0b"
      />
    </section>
  )
}

// ============================================================
// 查询日志页
// ============================================================
function QueryLog({ data }) {
  return (
    <section className="panel">
      <h3>最近查询</h3>
      <QueryLogTable rows={data.recent_queries} />
    </section>
  )
}

// ============================================================
// 子组件
// ============================================================
function Card({ label, value, color }) {
  return (
    <div className={`card card-${color}`}>
      <div className="card-value">{value}</div>
      <div className="card-label">{label}</div>
    </div>
  )
}

function BarList({ items, color }) {
  if (!items || items.length === 0) return <p className="empty">暂无数据</p>
  const max = Math.max(...items.map((i) => i.value), 1)
  return (
    <div className="bar-list">
      {items.map((item, i) => (
        <div className="bar-row" key={i}>
          <span className="bar-label">{item.label}</span>
          <div className="bar-track">
            <div
              className="bar-fill"
              style={{ width: `${(item.value / max) * 100}%`, background: color }}
            />
          </div>
          <span className="bar-value">{fmt(item.value)}</span>
        </div>
      ))}
    </div>
  )
}

function UpstreamTable({ rows }) {
  if (!rows || rows.length === 0) return <p className="empty">暂无数据</p>
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>上游</th>
            <th>查询数</th>
            <th>成功</th>
            <th>失败</th>
            <th>成功率</th>
            <th>平均延迟</th>
            <th>最近延迟</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(([name, s]) => {
            const rate = s.queries > 0 ? (s.success / s.queries * 100).toFixed(1) : '0.0'
            return (
              <tr key={name}>
                <td className="mono">{name}</td>
                <td>{fmt(s.queries)}</td>
                <td className="ok">{fmt(s.success)}</td>
                <td className={s.failed > 0 ? 'bad' : ''}>{fmt(s.failed)}</td>
                <td>{rate}%</td>
                <td>{s.latency_ema_ms.toFixed(1)} ms</td>
                <td>{s.last_latency_ms.toFixed(1)} ms</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function QueryLogTable({ rows }) {
  if (!rows || rows.length === 0) return <p className="empty">暂无数据</p>
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>时间</th>
            <th>客户端</th>
            <th>域名</th>
            <th>类型</th>
            <th>上游</th>
            <th>响应码</th>
            <th>延迟</th>
            <th>标记</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((q) => (
            <tr key={q.id} className={q.blocked ? 'row-blocked' : ''}>
              <td className="time">{fmtTime(q.time)}</td>
              <td className="mono">{q.client}</td>
              <td className="domain">{q.domain}</td>
              <td>{q.qtype}</td>
              <td className="mono">{q.upstream}</td>
              <td className={`rcode rcode-${q.rcode.toLowerCase()}`}>{q.rcode}</td>
              <td>{q.latency_ms.toFixed(1)} ms</td>
              <td className="tags">
                {q.cached && <span className="tag tag-cache">缓存</span>}
                {q.blocked && <span className="tag tag-block">拦截</span>}
                {q.rule && <span className="tag tag-rule">{q.rule}</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ============================================================
// 工具函数
// ============================================================
function fmt(n) {
  if (n === undefined || n === null) return '-'
  if (typeof n !== 'number') return n
  if (n >= 1e9) return (n / 1e9).toFixed(2) + 'B'
  if (n >= 1e6) return (n / 1e6).toFixed(2) + 'M'
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K'
  return String(n)
}

function fmtTime(iso) {
  const d = new Date(iso)
  return d.toLocaleTimeString('zh-CN', { hour12: false })
}
