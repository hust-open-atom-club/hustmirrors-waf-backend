import { useCallback, useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import {
  Activity, BarChart3, ChevronRight, CircleHelp, FileSearch,
  LayoutDashboard, LockKeyhole, Menu, RefreshCw, Settings2, X,
} from 'lucide-react'
import { AuthRequiredError, rpc } from './api'
import ConfigManagement from './components/ConfigManagement'
import { Logo } from './components/Logo'
import type {
  AuditList, AuthState, DashboardSeries, DashboardSummary,
  SystemHealth, SystemInfo,
} from './types'
import { formatDate, formatNumber, shortCommit } from './utils'

type Page = 'overview' | 'stats' | 'audit' | 'config'
type StatsRange = '1h' | '6h' | '24h'
type StatsData = { range: StatsRange; series: Record<string, DashboardSeries> }

const navItems: Array<{ id: Page; label: string; icon: typeof Activity }> = [
  { id: 'overview', label: '总览', icon: LayoutDashboard },
  { id: 'stats', label: '统计', icon: BarChart3 },
  { id: 'audit', label: '审计', icon: FileSearch },
  { id: 'config', label: '配置', icon: Settings2 },
]

function initialAuth(): AuthState {
  try {
    const raw = window.localStorage.getItem('mirrors-waf.admin-token')
    if (raw) {
      const saved = JSON.parse(raw) as { token: string; exp: number }
      if (saved.token && Date.now() < saved.exp) return { mode: 'token', token: saved.token }
      window.localStorage.removeItem('mirrors-waf.admin-token')
    }
  } catch { /* corrupted entry - ignore */ }
  return { mode: 'none' }
}

function persistToken(token: string, remember: boolean) {
  try {
    if (remember && token) {
      window.localStorage.setItem('mirrors-waf.admin-token', JSON.stringify({ token, exp: Date.now() + 7 * 24 * 3600 * 1000 }))
    } else {
      window.localStorage.removeItem('mirrors-waf.admin-token')
    }
  } catch { /* storage unavailable - session only */ }
}

function App() {
  const [page, setPage] = useState<Page>(() => {
    const value = window.location.hash.replace('#/', '') as Page
    return navItems.some((item) => item.id === value) ? value : 'overview'
  })
  const [mobileNav, setMobileNav] = useState(false)
  const [auth, setAuth] = useState<AuthState>(initialAuth)
  const [authForm, setAuthForm] = useState({ token: '', remember: true })
  const [authRequired, setAuthRequired] = useState(false)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [configRefreshNonce, setConfigRefreshNonce] = useState(0)
  const [error, setError] = useState('')
  const [summary, setSummary] = useState<DashboardSummary | null>(null)
  const [series, setSeries] = useState<DashboardSeries | null>(null)
  const [statsRange, setStatsRange] = useState<StatsRange>('1h')
  const [stats, setStats] = useState<StatsData | null>(null)
  const [health, setHealth] = useState<SystemHealth | null>(null)
  const [info, setInfo] = useState<SystemInfo | null>(null)
  const [audit, setAudit] = useState<AuditList | null>(null)
  const [toast, setToast] = useState('')

  const handleLoadError = useCallback((reason: unknown) => {
    if (reason instanceof AuthRequiredError) {
      setAuthRequired(true)
      setError('管理 API 需要凭据')
      return
    }
    if (reason instanceof DOMException && reason.name === 'AbortError') return
    setError(reason instanceof Error ? reason.message : '无法连接到后台 API')
  }, [])

  const loadOverview = useCallback(async (signal?: AbortSignal) => {
    setError('')
    try {
      const [nextSummary, nextSeries, nextHealth, nextInfo] = await Promise.all([
        rpc<DashboardSummary>('dashboard.summary', {}, auth, signal),
        rpc<DashboardSeries>('dashboard.series', { metric: 'pow_denied_total', step: 300 }, auth, signal),
        rpc<SystemHealth>('system.health', {}, auth, signal),
        rpc<SystemInfo>('system.info', {}, auth, signal),
      ])
      setSummary(nextSummary)
      setSeries(nextSeries)
      setHealth(nextHealth)
      setInfo(nextInfo)
      setAuthRequired(false)
    } catch (reason) {
      handleLoadError(reason)
    }
  }, [auth, handleLoadError])

  const loadStats = useCallback(async (signal?: AbortSignal) => {
    setError('')
    const ranges: Record<StatsRange, { seconds: number; step: number }> = {
      '1h': { seconds: 60 * 60, step: 60 },
      '6h': { seconds: 6 * 60 * 3600, step: 300 },
      '24h': { seconds: 24 * 60 * 3600, step: 900 },
    }
    const range = ranges[statsRange]
    const to = Math.floor(Date.now() / 1000)
    const from = to - range.seconds
    const metrics = ['pow_verify_total', 'pow_allowed_total', 'pow_denied_total', 'risk_decision_total']
    try {
      const results = await Promise.all(metrics.map(async (metric) => [
        metric,
        await rpc<DashboardSeries>('stats.timeseries', { metric, from, to, step: range.step }, auth, signal),
      ] as const))
      setStats({ range: statsRange, series: Object.fromEntries(results) })
      setAuthRequired(false)
    } catch (reason) {
      handleLoadError(reason)
    }
  }, [auth, handleLoadError, statsRange])

  const loadPageData = useCallback(async (signal?: AbortSignal) => {
    if (page === 'overview') return loadOverview(signal)
    if (page === 'stats') return loadStats(signal)
    setError('')
    try {
      if (page === 'audit') setAudit(await rpc<AuditList>('audit.search', { limit: 100 }, auth, signal))
      setAuthRequired(false)
    } catch (reason) {
      handleLoadError(reason)
    }
  }, [auth, handleLoadError, loadOverview, loadStats, page])

  useEffect(() => {
    window.location.hash = `/${page}`
  }, [page])

  useEffect(() => {
    const handleHashChange = () => {
      const value = window.location.hash.replace('#/', '') as Page
      setPage(navItems.some((item) => item.id === value) ? value : 'overview')
    }
    window.addEventListener('hashchange', handleHashChange)
    return () => window.removeEventListener('hashchange', handleHashChange)
  }, [])

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)
    void loadPageData(controller.signal).finally(() => setLoading(false))
    return () => controller.abort()
  }, [loadPageData])

  useEffect(() => {
    if (page !== 'overview' || auth.mode === 'none' || authRequired) return
    const timer = window.setInterval(() => void loadOverview(), 30_000)
    return () => window.clearInterval(timer)
  }, [auth, authRequired, loadOverview, page])

  useEffect(() => {
    if (!toast) return
    const timer = window.setTimeout(() => setToast(''), 3600)
    return () => window.clearTimeout(timer)
  }, [toast])

  const refresh = async () => {
    setRefreshing(true)
    try {
      if (page === 'config') {
        setConfigRefreshNonce((value) => value + 1)
        return
      }
      await loadPageData()
      setToast('数据已刷新')
    } finally {
      setRefreshing(false)
    }
  }

  const signIn = async () => {
    const token = authForm.token.trim()
    const nextAuth: AuthState = { mode: 'token', token }
    setAuth(nextAuth)
    try {
      await rpc('system.ping', {}, nextAuth)
      setAuthRequired(false)
      setToast('已连接到 Admin API')
      persistToken(token, authForm.remember)
    } catch {
      setAuthRequired(true)
      setError('Token 校验失败')
    }
  }

  const signOut = () => {
    setAuth({ mode: 'none' })
    setAuthRequired(false)
    persistToken('', false)
    setToast('已退出登录')
  }

  const pageTitle = { overview: '总览', stats: '统计', audit: '审计', config: '配置' }[page]
  const connected = auth.mode === 'token'

  return (
    <div className="min-h-screen flex bg-background-secondary">
      <aside className={`fixed inset-y-0 left-0 z-30 w-52 flex flex-col bg-surface border-r border-border transition-transform lg:translate-x-0 ${mobileNav ? 'translate-x-0' : '-translate-x-full'}`}>
        <div className="flex items-center gap-2.5 px-4 h-14 border-b border-border">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
            <Logo size={20} />
          </div>
          <div className="min-w-0">
            <div className="text-sm font-semibold leading-tight">Garmr</div>
            <div className="text-[11px] text-muted-foreground">镜像站防刷网关</div>
          </div>
          <button className="ml-auto lg:hidden text-muted-foreground hover:text-foreground" onClick={() => setMobileNav(false)} aria-label="关闭导航"><X size={16} /></button>
        </div>
        <nav className="flex-1 px-2 py-3 space-y-0.5">
          {navItems.map((item) => {
            const Icon = item.icon
            const active = page === item.id
            return (
              <button key={item.id}
                className={`w-full flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition ${active ? 'bg-primary-soft text-primary font-medium' : 'text-muted-foreground hover:text-foreground hover:bg-accent'}`}
                onClick={() => { setPage(item.id); setMobileNav(false) }}>
                <Icon size={16} strokeWidth={1.8} />
                {item.label}
                {active && <ChevronRight size={14} className="ml-auto" />}
              </button>
            )
          })}
        </nav>
        <div className="px-4 py-3 border-t border-border text-[11px] text-faint-foreground flex justify-between">
          <span>build {shortCommit(info?.commit ?? '')}</span>
          <span>v{info?.version ?? 'dev'}</span>
        </div>
      </aside>
      {mobileNav && <button className="fixed inset-0 z-20 bg-backdrop lg:hidden" aria-label="关闭导航" onClick={() => setMobileNav(false)} />}

      <div className="flex-1 min-w-0 lg:pl-52">
        <header className="sticky top-0 z-10 flex items-center gap-3 h-14 px-4 lg:px-8 border-b border-border bg-surface/95 backdrop-blur">
          <button className="lg:hidden text-muted-foreground hover:text-foreground" onClick={() => setMobileNav(true)} aria-label="打开导航"><Menu size={18} /></button>
          <div className="text-sm font-medium">{pageTitle}</div>
          <div className="ml-auto flex items-center gap-2">
            <span className={`badge ${error ? 'bg-warning-soft text-warning' : 'bg-success-soft text-success'}`}>
              <span className={`h-1.5 w-1.5 rounded-full ${error ? 'bg-warning' : 'bg-success'}`} />
              <span className="hidden sm:inline">{error ? '连接异常' : '服务正常'}</span>
            </span>
            <button className="btn-outline !px-2.5" onClick={() => void refresh()} disabled={refreshing} aria-label="刷新数据">
              <RefreshCw size={15} className={refreshing ? 'animate-spin' : ''} />
            </button>
            {connected
              ? <button className="btn-outline" onClick={signOut}>已登录</button>
              : <button className="btn-primary" onClick={() => setAuthRequired(true)}>登录</button>}
          </div>
        </header>

        <main className="page space-y-6">
          {error && (
            <div className="card border-destructive/40 px-6 py-4 flex items-center gap-3 text-sm">
              <span className="text-destructive font-medium">控制面连接异常</span>
              <span className="text-muted-foreground flex-1">{error}</span>
              <button className="btn-outline" onClick={() => void refresh()}>重试</button>
            </div>
          )}
          {loading ? <Loading /> : <>
            {page === 'overview' && <OverviewPage summary={summary} series={series} health={health} />}
            {page === 'stats' && <StatsPage stats={stats} range={statsRange} onRangeChange={setStatsRange} />}
            {page === 'audit' && <AuditPage audit={audit} />}
            {page === 'config' && <ConfigManagement auth={auth} onError={handleLoadError} onToast={setToast} refreshNonce={configRefreshNonce} />}
          </>}
        </main>
      </div>

      {authRequired && <AuthModal authForm={authForm} setAuthForm={setAuthForm} onSubmit={() => void signIn()} onClose={() => setAuthRequired(false)} />}
      {toast && <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2 rounded-lg border border-success/30 bg-surface px-4 py-2.5 text-sm text-success shadow-pop">{toast}</div>}
    </div>
  )
}

function Loading() {
  return <div className="space-y-4">{Array.from({ length: 4 }).map((_, i) => <div key={i} className="card h-24 animate-pulse" />)}</div>
}

function PageHeader({ title, desc, actions }: { title: string; desc?: string; actions?: ReactNode }) {
  return (
    <div className="flex items-start justify-between">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {desc && <p className="mt-1 text-sm text-muted-foreground">{desc}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  )
}

const statDot: Record<string, string> = {
  success: 'bg-success', warning: 'bg-warning', destructive: 'bg-destructive', primary: 'bg-primary', info: 'bg-info',
}

function Stat({ label, value, unit, color }: { label: string; value: string; unit?: string; color: 'success' | 'warning' | 'destructive' | 'primary' | 'info' }) {
  return (
    <div className="card p-5">
      <div className="flex items-center gap-2 mb-2">
        <span className={`h-2.5 w-2.5 rounded-full ${statDot[color]}`} />
        <span className="text-xs text-muted-foreground">{label}</span>
      </div>
      <div className="text-2xl font-bold tabular-nums">
        {value}{unit && <span className="text-sm font-normal text-muted-foreground ml-1">{unit}</span>}
      </div>
    </div>
  )
}

function EmptyState({ title, desc }: { title: string; desc?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-16 text-muted-foreground">
      <CircleHelp size={36} className="opacity-30" />
      <p className="text-sm font-medium text-foreground">{title}</p>
      {desc && <p className="text-xs">{desc}</p>}
    </div>
  )
}

function TrendChart({ points, label = '速率' }: { points: Array<{ timestamp: number; value: number }>; label?: string }) {
  const width = 720
  const height = 220
  const pad = 24
  const max = Math.max(...points.map((point) => point.value), 1)
  const min = Math.min(...points.map((point) => point.value), 0)
  const range = max - min || 1
  const path = points.map((point, index) => {
    const x = pad + (index / Math.max(points.length - 1, 1)) * (width - pad * 2)
    const y = height - pad - ((point.value - min) / range) * (height - pad * 2)
    return `${index === 0 ? 'M' : 'L'} ${x.toFixed(2)} ${y.toFixed(2)}`
  }).join(' ')
  return <div>
    <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-auto" role="img" aria-label={`${label}趋势`}>
      {[44, 110, 176].map((y) => <line key={y} x1={pad} x2={width - pad} y1={y} y2={y} className="stroke-border" strokeDasharray="4 7" />)}
      <path d={`${path} L ${width - pad} ${height - pad} L ${pad} ${height - pad} Z`} fill="var(--chart-c2)" />
      <path d={path} fill="none" stroke="var(--chart-c7)" strokeWidth={2.5} strokeLinecap="round" />
    </svg>
    <div className="flex justify-between text-xs text-faint-foreground tabular-nums">
      <span>{formatDate(points[0]?.timestamp)}</span>
      <span>{formatDate(points.at(-1)?.timestamp)}</span>
    </div>
  </div>
}

function OverviewPage({ summary, series, health }: { summary: DashboardSummary | null; series: DashboardSeries | null; health: SystemHealth | null }) {
  const metrics = summary?.metrics
  return <>
    <div className="grid gap-4 grid-cols-2 xl:grid-cols-4">
      <Stat label="PoW 校验" value={formatNumber(metrics?.pow_verify_total ?? 0)} color="info" />
      <Stat label="放行" value={formatNumber(metrics?.pow_allowed_total ?? 0)} color="success" />
      <Stat label="拒绝" value={formatNumber(metrics?.pow_denied_total ?? 0)} color="destructive" />
      <Stat label="活跃签名" value={formatNumber(metrics?.active_signatures ?? 0)} color="primary" />
    </div>
    <div className="grid gap-4 lg:grid-cols-3">
      <div className="card lg:col-span-2">
        <div className="card-header flex items-center justify-between">
          <div>
            <div className="card-title">拒绝速率</div>
            <div className="card-desc">pow_denied_total</div>
          </div>
          <span className={`badge ${series?.available ? 'bg-success-soft text-success' : 'bg-muted text-muted-foreground'}`}>
            <Activity size={12} /> {series?.available ? '有数据' : '暂无数据'}
          </span>
        </div>
        <div className="card-body">
          {series?.available && series.points.length > 0
            ? <TrendChart points={series.points} label="拒绝" />
            : <EmptyState title="暂无时序数据" desc={series?.error ?? '未配置 Prometheus'} />}
        </div>
      </div>
      <div className="card">
        <div className="card-header flex items-center justify-between">
          <div className="card-title">依赖健康</div>
          <span className={`badge ${health === null ? 'bg-muted text-muted-foreground' : health.ok ? 'bg-success-soft text-success' : 'bg-destructive-soft text-destructive'}`}>
            {health === null ? '加载中' : health.ok ? '全部正常' : '需检查'}
          </span>
        </div>
        <div className="card-body !px-0">
          {(health?.components ?? []).map((component) => {
            const good = component.status === 'ok' || component.status === 'configured'
            return (
              <div key={component.name} className="flex items-center gap-3 px-6 py-3 border-b border-separator last:border-b-0">
                <span className={`h-2 w-2 rounded-full ${good ? 'bg-success' : component.status === 'disabled' ? 'bg-muted-foreground/40' : 'bg-destructive'}`} />
                <div className="flex-1 min-w-0">
                  <div className="text-sm capitalize">{component.name.replaceAll('_', ' ')}</div>
                  {component.detail && <div className="text-xs text-muted-foreground truncate">{component.detail}</div>}
                </div>
                <span className="text-xs text-faint-foreground tabular-nums">{component.latency_ms ? `${component.latency_ms}ms` : component.status}</span>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  </>
}

const statsMetricMeta = [
  { key: 'pow_verify_total', label: '验证请求', color: 'info' },
  { key: 'pow_allowed_total', label: '允许通过', color: 'success' },
  { key: 'pow_denied_total', label: '拒绝请求', color: 'destructive' },
  { key: 'risk_decision_total', label: '风险决策', color: 'warning' },
] as const

function StatsPage({ stats, range, onRangeChange }: { stats: StatsData | null; range: StatsRange; onRangeChange: (range: StatsRange) => void }) {
  return <>
    <PageHeader title="统计" actions={
      <div className="flex rounded-lg border border-border overflow-hidden">
        {(['1h', '6h', '24h'] as StatsRange[]).map((value) => (
          <button key={value} className={`px-3 py-1.5 text-sm transition ${range === value ? 'bg-primary text-primary-foreground' : 'hover:bg-accent'}`} onClick={() => onRangeChange(value)}>{value}</button>
        ))}
      </div>
    } />
    <div className="grid gap-4 grid-cols-2 xl:grid-cols-4">
      {statsMetricMeta.map((metric) => {
        const series = stats?.series[metric.key]
        const available = series?.available === true && series.points.length > 0
        return <Stat key={metric.key} label={metric.label} value={available ? `${formatNumber(series.points.at(-1)?.value ?? 0)}/s` : '—'} color={metric.color} />
      })}
    </div>
    <div className="grid gap-4 lg:grid-cols-2">
      {statsMetricMeta.map((metric) => {
        const series = stats?.series[metric.key]
        return <div className="card" key={metric.key}>
          <div className="card-header flex items-center justify-between">
            <div>
              <div className="card-title">{metric.label}</div>
              <div className="card-desc">{metric.key}</div>
            </div>
            <span className={`badge ${series?.available ? 'bg-success-soft text-success' : 'bg-muted text-muted-foreground'}`}>
              <Activity size={12} /> {series?.available ? 'LIVE' : 'N/A'}
            </span>
          </div>
          <div className="card-body">
            {series?.available && series.points.length > 0
              ? <TrendChart points={series.points} label={metric.label} />
              : <EmptyState title="暂无数据" desc={series?.error ?? '未配置 Prometheus'} />}
          </div>
        </div>
      })}
    </div>
  </>
}

function AuditPage({ audit }: { audit: AuditList | null }) {
  const events = audit?.events ?? []
  const [actionFilter, setActionFilter] = useState('')
  const [resultFilter, setResultFilter] = useState<'all' | 'ok' | 'error'>('all')
  const actions = Array.from(new Set(events.map((event) => event.action))).sort()
  const filtered = events.filter((event) => {
    if (actionFilter && event.action !== actionFilter) return false
    if (resultFilter === 'ok' && !event.ok) return false
    if (resultFilter === 'error' && event.ok) return false
    return true
  })
  return <div className="card overflow-hidden">
    <div className="card-header flex flex-wrap items-center gap-3">
      <div>
        <div className="card-title">审计事件</div>
        <div className="card-desc">管理操作记录 · 最近 100 条</div>
      </div>
      <div className="ml-auto flex items-center gap-2 text-sm">
        <select className="input !w-auto" value={actionFilter} onChange={(event) => setActionFilter(event.target.value)}>
          <option value="">全部动作</option>
          {actions.map((action) => <option key={action} value={action}>{action}</option>)}
        </select>
        <select className="input !w-auto" value={resultFilter} onChange={(event) => setResultFilter(event.target.value as 'all' | 'ok' | 'error')}>
          <option value="all">全部结果</option>
          <option value="ok">成功</option>
          <option value="error">失败</option>
        </select>
      </div>
    </div>
    {filtered.length === 0 ? <EmptyState title="没有审计事件" desc={audit?.error ?? '未配置 Loki'} /> : (
      <div className="table-wrap !rounded-none !border-x-0 !border-b-0">
        <table className="table">
          <thead><tr><th>时间</th><th>动作</th><th>操作者</th><th>结果</th><th>原因 / 详情</th><th>请求 ID</th></tr></thead>
          <tbody>{filtered.map((event, index) => (
            <tr key={`${event.timestamp}-${event.action}-${index}`}>
              <td className="tabular-nums text-muted-foreground">{formatDate(event.timestamp)}</td>
              <td className="font-medium">{event.action}</td>
              <td>{event.actor}</td>
              <td><span className={`badge ${event.ok ? 'bg-success-soft text-success' : 'bg-destructive-soft text-destructive'}`}>{event.ok ? 'OK' : event.code || 'ERROR'}</span></td>
              <td className="max-w-64 truncate text-muted-foreground" title={event.detail || event.reason}>{event.reason || event.target || event.detail || '—'}</td>
              <td className="tabular-nums text-faint-foreground font-mono text-xs">{event.request_id || '—'}</td>
            </tr>
          ))}</tbody>
        </table>
      </div>
    )}
  </div>
}

function AuthModal({ authForm, setAuthForm, onSubmit, onClose }: { authForm: { token: string; remember: boolean }; setAuthForm: (value: { token: string; remember: boolean }) => void; onSubmit: () => void; onClose: () => void }) {
  return <div className="fixed inset-0 z-50 grid place-items-center p-4 bg-backdrop" onClick={onClose}>
    <section className="w-full max-w-sm rounded-xl border border-border bg-overlay text-overlay-foreground shadow-pop p-6" role="dialog" aria-modal="true" aria-label="登录" onClick={(event) => event.stopPropagation()}>
      <div className="flex items-center gap-2.5 mb-5">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary text-primary-foreground"><LockKeyhole size={16} /></div>
        <div>
          <div className="font-semibold">登录</div>
          <div className="text-xs text-muted-foreground">Garmr Admin</div>
        </div>
        <button className="ml-auto text-muted-foreground hover:text-foreground" onClick={onClose} aria-label="关闭"><X size={16} /></button>
      </div>
      <form onSubmit={(event) => { event.preventDefault(); onSubmit() }}>
        <input className="visually-hidden" name="username" autoComplete="username" value="admin-token" readOnly tabIndex={-1} aria-hidden="true" />
        <label className="block mb-4">
          <span className="block mb-1.5 text-xs font-medium text-muted-foreground">管理 Token</span>
          <input className="input" name="password" type="password" autoComplete="current-password" value={authForm.token} autoFocus onChange={(event) => setAuthForm({ ...authForm, token: event.target.value })} />
        </label>
        <label className="flex items-center gap-2 mb-5 text-sm text-muted-foreground cursor-pointer">
          <input type="checkbox" className="accent-[var(--primary)]" checked={authForm.remember} onChange={(event) => setAuthForm({ ...authForm, remember: event.target.checked })} />
          7 天内自动登录
        </label>
        <button type="submit" className="btn-primary w-full">登录</button>
      </form>
    </section>
  </div>
}

export default App
