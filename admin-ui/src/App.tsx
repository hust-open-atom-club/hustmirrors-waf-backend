import { useCallback, useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import {
  Activity,
  AlertTriangle,
  Ban,
  BarChart3,
  Check,
  ChevronRight,
  CircleHelp,
  FileCode2,
  FileSearch,
  Gauge,
  KeyRound,
  LayoutDashboard,
  LockKeyhole,
  Menu,
  Network,
  RefreshCw,
  Search,
  ServerCog,
  Settings2,
  ShieldCheck,
  TerminalSquare,
  TimerReset,
  X,
  Zap,
} from 'lucide-react'
import { AuthRequiredError, rpc } from './api'
import ConfigManagement from './components/ConfigManagement'
import RuntimeControls from './components/RuntimeControls'
import type {
  AuditList,
  AuthState,
  DashboardSeries,
  DashboardSummary,
  PendingList,
  RuleList,
  RulePreview,
  RiskBlockMutation,
  RuntimeStatus,
  SystemHealth,
  SystemInfo,
  TokenGet,
} from './types'
import { formatDate, formatNumber, shortCommit } from './utils'

type Page = 'overview' | 'stats' | 'rules' | 'tokens' | 'pending' | 'audit' | 'config'
type StatsRange = '1h' | '6h' | '24h'
type StatsData = { range: StatsRange; series: Record<string, DashboardSeries> }

const navItems: Array<{ id: Page; label: string; kicker: string; icon: typeof Activity }> = [
  { id: 'overview', label: '总览', kicker: '', icon: LayoutDashboard },
  { id: 'stats', label: '统计', kicker: '', icon: BarChart3 },
  { id: 'audit', label: '审计', kicker: '', icon: FileSearch },
  { id: 'config', label: '配置', kicker: '', icon: Settings2 },
]

function initialAuth(): AuthState {
  return { mode: 'none' }
}

function App() {
  const [page, setPage] = useState<Page>(() => {
    const value = window.location.hash.replace('#/', '') as Page
    return navItems.some((item) => item.id === value) ? value : 'overview'
  })
  const [mobileNav, setMobileNav] = useState(false)
  const [auth, setAuth] = useState<AuthState>(initialAuth)
  const [authForm, setAuthForm] = useState({ mode: 'token' as 'token' | 'basic', token: '', username: '', password: '' })
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
  const [runtime, setRuntime] = useState<RuntimeStatus | null>(null)
  const [info, setInfo] = useState<SystemInfo | null>(null)
  const [rules, setRules] = useState<RuleList | null>(null)
  const [pending, setPending] = useState<PendingList | null>(null)
  const [audit, setAudit] = useState<AuditList | null>(null)
  const [toast, setToast] = useState('')

  const handleLoadError = useCallback((reason: unknown) => {
    if (reason instanceof AuthRequiredError) {
      setAuthRequired(true)
      setError('管理 API 需要凭据。凭据仅保存在当前页面内存中。')
      return
    }
    if (reason instanceof DOMException && reason.name === 'AbortError') return
    setError(reason instanceof Error ? reason.message : '无法连接到后台 API')
  }, [])

  const loadOverview = useCallback(async (signal?: AbortSignal) => {
    setError('')
    try {
      const [nextSummary, nextSeries, nextHealth, nextRuntime, nextInfo] = await Promise.all([
        rpc<DashboardSummary>('dashboard.summary', {}, auth, signal),
        rpc<DashboardSeries>('dashboard.series', { metric: 'pow_denied_total', step: 300 }, auth, signal),
        rpc<SystemHealth>('system.health', {}, auth, signal),
        rpc<RuntimeStatus>('runtime.status', {}, auth, signal),
        rpc<SystemInfo>('system.info', {}, auth, signal),
      ])
      setSummary(nextSummary)
      setSeries(nextSeries)
      setHealth(nextHealth)
      setRuntime(nextRuntime)
      setInfo(nextInfo)
      setAuthRequired(false)
    } catch (reason) {
      handleLoadError(reason)
    }
  }, [auth])

  const loadStats = useCallback(async (signal?: AbortSignal) => {
    setError('')
    const ranges: Record<StatsRange, { seconds: number; step: number }> = {
      '1h': { seconds: 60 * 60, step: 60 },
      '6h': { seconds: 6 * 60 * 60, step: 300 },
      '24h': { seconds: 24 * 60 * 60, step: 900 },
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
      if (page === 'rules') setRules(await rpc<RuleList>('rule.list', {}, auth, signal))
      if (page === 'pending') setPending(await rpc<PendingList>('risk.blocks.list', {}, auth, signal))
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
    const nextAuth: AuthState = authForm.mode === 'token'
      ? { mode: 'token', token: authForm.token.trim() }
      : { mode: 'basic', username: authForm.username, password: authForm.password }
    setAuth(nextAuth)
    try {
      await rpc('system.ping', {}, nextAuth)
      setAuthRequired(false)
      setToast('已连接到 Admin API')
    } catch {
      setAuthRequired(true)
      setError('凭据校验失败，请检查 Admin 配置。')
    }
  }

  const signOut = () => {
    setAuth(initialAuth())
    setAuthRequired(false)
    setToast('已清除当前页面凭据')
  }

  const navigate = (next: Page) => {
    setPage(next)
    setMobileNav(false)
  }

  return (
    <div className="app-shell">
      <aside className={`side-nav ${mobileNav ? 'is-open' : ''}`} aria-label="主导航">
        <div className="brand-lockup">
          <div className="brand-mark" aria-hidden="true"><ShieldCheck size={23} /></div>
          <div>
            <strong>Mirrors WAF</strong>
            <span>管理控制台</span>
          </div>
          <button className="icon-button mobile-close" aria-label="关闭导航" onClick={() => setMobileNav(false)}><X size={18} /></button>
        </div>
        <div className="nav-section-label">OPERATIONS</div>
        <nav>
          {navItems.map((item) => {
            const Icon = item.icon
            return (
              <button key={item.id} className={`nav-item ${page === item.id ? 'is-active' : ''}`} onClick={() => navigate(item.id)}>
                <Icon size={18} strokeWidth={1.8} />
                <span><b>{item.label}</b><small>{item.kicker}</small></span>
                {page === item.id && <ChevronRight className="nav-chevron" size={15} />}
              </button>
            )
          })}
        </nav>
        <div className="nav-spacer" />
        <div className="sidebar-footer"><span>build {shortCommit(info?.commit ?? '')}</span><span>v{info?.version ?? 'dev'}</span></div>
      </aside>
      {mobileNav && <button className="nav-scrim" aria-label="关闭导航" onClick={() => setMobileNav(false)} />}

      <main className="main-column" id="main-content">
        <header className="top-bar">
          <div className="top-left">
            <button className="icon-button mobile-menu" aria-label="打开导航" onClick={() => setMobileNav(true)}><Menu size={20} /></button>
            <div className="breadcrumbs"><strong>{navItems.find((item) => item.id === page)?.label}</strong></div>
          </div>
          <div className="top-actions">
            <div className="connection-pill"><span className={error ? 'warning' : 'online'} /> {error ? '连接异常' : '服务正常'}</div>
            <button className="icon-button" aria-label="刷新数据" onClick={() => void refresh()} disabled={refreshing}><RefreshCw size={17} className={refreshing ? 'spin' : ''} /></button>
            <button className="operator-chip" onClick={auth.mode === 'none' ? () => setAuthRequired(true) : signOut} title={auth.mode === 'none' ? '配置凭据' : '清除当前凭据'}><b>{auth.mode === 'none' ? '连接' : '已登录'}</b></button>
          </div>
        </header>

        <div className="content-wrap">
          <div className="page-heading">
            <div>
              <h1>{pageTitle(page)}</h1>
              <p>{pageDescription(page)}</p>
            </div>
            <div className="heading-meta"><span>当前时间</span><strong>{new Intl.DateTimeFormat('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).format(new Date())}</strong></div>
          </div>

          {error && <div className="alert-banner" role="alert"><AlertTriangle size={18} /><div><strong>控制面连接异常</strong><span>{error}</span></div><button onClick={() => void refresh()}>重试</button></div>}
          {loading ? <LoadingState /> : <>
            {page === 'overview' && <OverviewPage summary={summary} series={series} health={health} runtime={runtime} auth={auth} onRuntimeChanged={(nextRuntime, message) => { setRuntime(nextRuntime); setToast(message) }} onNavigate={navigate} />}
            {page === 'stats' && <StatsPage stats={stats} range={statsRange} onRangeChange={setStatsRange} />}
            {page === 'rules' && <RulesPage rules={rules} auth={auth} onError={handleLoadError} />}
            {page === 'tokens' && <TokensPage auth={auth} onError={handleLoadError} />}
            {page === 'pending' && <PendingPage pending={pending} auth={auth} onError={handleLoadError} onChanged={async (message) => { await loadPageData(); setToast(message) }} />}
            {page === 'audit' && <AuditPage audit={audit} />}
            {page === 'config' && <ConfigPage auth={auth} onError={handleLoadError} onToast={setToast} refreshNonce={configRefreshNonce} />}
          </>}
        </div>
      </main>

      {authRequired && <AuthModal authForm={authForm} setAuthForm={setAuthForm} onSubmit={() => void signIn()} onClose={() => setAuthRequired(false)} />}
      {toast && <div className="toast" role="status"><Check size={16} /> {toast}</div>}
    </div>
  )
}

function pageTitle(page: Page) {
  return { overview: '总览监控', stats: '统计分析', rules: '规则链', tokens: 'Token 检索', pending: 'Pending 守卫', audit: '审计轨迹', config: '配置管理' }[page]
}

function pageDescription(page: Page) {
  return {
    overview: '查看服务健康、关键开关、依赖状态和当前风险信号。',
    stats: '从固定 Prometheus 指标观察验证、放行、拒绝和风险决策趋势。',
    rules: '以只读方式检查当前风险链，并对请求上下文进行安全预览。',
    tokens: '按 sign ID 查询使用记录；敏感字段已在服务端剥离。',
    pending: '查看当前实例的 Pending 状态，并执行受审计的人工 IP Block/Unblock。',
    audit: '检索谁在什么时候对控制面执行了什么操作。',
    config: '使用 CAS 草稿、校验与差异预览安全管理配置，并查看或回滚历史修订。',
  }[page]
}

function LoadingState() {
  return <div className="loading-grid"><div className="skeleton hero-skeleton" /><div className="skeleton" /><div className="skeleton" /><div className="skeleton wide" /></div>
}

function OverviewPage({ summary, series, health, runtime, auth, onRuntimeChanged, onNavigate }: { summary: DashboardSummary | null; series: DashboardSeries | null; health: SystemHealth | null; runtime: RuntimeStatus | null; auth: AuthState; onRuntimeChanged: (runtime: RuntimeStatus, message: string) => void; onNavigate: (page: Page) => void }) {
  const metrics = summary?.metrics
  const cards = [
    { label: 'PoW 校验', value: formatNumber(metrics?.pow_verify_total ?? 0), sub: '进程累计', icon: Zap, accent: 'cyan' },
    { label: '放行', value: formatNumber(metrics?.pow_allowed_total ?? 0), sub: '通过验证', icon: ShieldCheck, accent: 'green' },
    { label: '拒绝', value: formatNumber(metrics?.pow_denied_total ?? 0), sub: '被拒绝', icon: LockKeyhole, accent: 'red' },
    { label: '活跃签名', value: formatNumber(metrics?.active_signatures ?? 0), sub: '使用记录', icon: KeyRound, accent: 'amber' },
  ]
  return <>
    <section className="metric-grid" aria-label="核心指标">
      {cards.map((card) => <MetricCard key={card.label} {...card} />)}
    </section>
    <section className="dashboard-grid">
      <div className="panel chart-panel">
        <PanelHeader title="拒绝速率" kicker="固定指标查询" action={<span className={`source-badge ${series?.available ? 'good' : 'muted'}`}><Activity size={13} /> {series?.available ? '有数据' : '暂无数据'}</span>} />
        {series?.available && series.points.length > 0 ? <TrendChart points={series.points} /> : <EmptyState icon={BarChart3} title="暂无时序数据" description={series?.error ?? '配置 Prometheus 后启用固定指标查询。'} />}
      </div>
      <div className="panel health-panel">
        <PanelHeader title="依赖健康" kicker="运行时组件" action={<span className={`source-badge ${health === null ? 'muted' : health.ok ? 'good' : 'danger'}`}><span className="tiny-dot" /> {health === null ? '加载中' : health.ok ? '全部正常' : '需检查'}</span>} />
        <div className="health-list">{(health?.components ?? []).map((component) => <HealthRow key={component.name} {...component} />)}</div>
      </div>
    </section>
    <section className="dashboard-grid lower-grid">
      <div className="panel insight-panel">
        <PanelHeader title="运行态势" kicker="当前实例" />
        <div className="insight-list">
          <Insight icon={Gauge} title="风险决策总量" value={formatNumber(metrics?.risk_decision_total ?? 0)} detail="由风险引擎累计产生的决策" />
          <Insight icon={Network} title="Pending 范围" value="本实例" detail="当前状态只覆盖本后端进程" />
          <Insight icon={ServerCog} title="管理能力" value="已启用" detail="支持实例级 IP Block / Unblock" />
        </div>
      </div>
      <div className="panel quick-panel">
        <PanelHeader title="快速入口" kicker="常用操作" />
        <div className="quick-grid">
          <QuickLink icon={BarChart3} title="打开统计" detail="查看固定指标趋势" onClick={() => onNavigate('stats')} />
          <QuickLink icon={FileSearch} title="审计轨迹" detail="检索管理操作事件" onClick={() => onNavigate('audit')} />
          <QuickLink icon={FileCode2} title="配置中心" detail="校验和审查配置版本" onClick={() => onNavigate('config')} />
        </div>
      </div>
    </section>
    <RuntimeControls runtime={runtime} auth={auth} onChanged={onRuntimeChanged} />
  </>
}

const statsMetricMeta = [
  { key: 'pow_verify_total', label: '验证请求', icon: Zap, accent: 'cyan', description: 'PoW 验证速率' },
  { key: 'pow_allowed_total', label: '允许通过', icon: ShieldCheck, accent: 'green', description: '有效验证速率' },
  { key: 'pow_denied_total', label: '拒绝请求', icon: LockKeyhole, accent: 'red', description: '失败验证速率' },
  { key: 'risk_decision_total', label: '风险决策', icon: Gauge, accent: 'amber', description: '风控决策速率' },
] as const

function StatsPage({ stats, range, onRangeChange }: { stats: StatsData | null; range: StatsRange; onRangeChange: (range: StatsRange) => void }) {
  return <>
    <div className="panel stats-toolbar">
      <div><span className="toolbar-kicker">固定指标</span><strong>统计窗口</strong><small>后端只执行固定指标查询，不接受任意 PromQL。</small></div>
      <div className="stats-range" role="group" aria-label="统计时间范围">
        {(['1h', '6h', '24h'] as StatsRange[]).map((value) => <button key={value} className={range === value ? 'is-active' : ''} onClick={() => onRangeChange(value)} aria-pressed={range === value}>{value}</button>)}
      </div>
    </div>
    <section className="metric-grid stats-kpi-grid" aria-label="统计速率">
      {statsMetricMeta.map((metric) => {
        const series = stats?.series[metric.key]
        const available = series?.available === true && series.points.length > 0
        const value = available ? `${formatNumber(latestPoint(series))}/s` : '—'
        const description = available ? metric.description : 'Prometheus 暂无数据'
        return <MetricCard key={metric.key} label={metric.label} value={value} sub={description} icon={metric.icon} accent={metric.accent} />
      })}
    </section>
    <section className="stats-chart-grid" aria-label="统计趋势图">
      {statsMetricMeta.map((metric) => <div className="panel stats-chart-panel" key={metric.key}>
        <PanelHeader title={metric.label} kicker={`${metric.key.toUpperCase()} · ${range.toUpperCase()}`} action={<span className={`source-badge ${stats?.series[metric.key]?.available ? 'good' : 'muted'}`}><Activity size={13} /> {stats?.series[metric.key]?.available ? 'LIVE' : 'UNAVAILABLE'}</span>} />
        {stats?.series[metric.key]?.available && stats.series[metric.key].points.length > 0
          ? <TrendChart points={stats.series[metric.key].points} label={metric.description} chartID={metric.key} />
          : <EmptyState icon={BarChart3} title="暂无时序数据" description={stats?.series[metric.key]?.error ?? '配置 Prometheus 后启用固定指标查询。'} />}
      </div>)}
    </section>
    <div className="stats-footnote" role="note"><Activity size={15} /><span>展示的是 Prometheus 速率查询结果；进程累计计数和依赖健康状态仍可在总览监控查看。</span></div>
  </>
}

function latestPoint(series?: DashboardSeries) {
  return series?.points.at(-1)?.value ?? 0
}

function MetricCard({ label, value, sub, icon: Icon, accent }: { label: string; value: string; sub: string; icon: typeof Activity; accent: string }) {
  return <article className={`metric-card accent-${accent}`}><div className="metric-top"><span>{label}</span><Icon size={18} /></div><strong>{value}</strong><small>{sub}</small><div className="metric-spark"><span /><span /><span /><span /><span /><span /><span /></div></article>
}

function PanelHeader({ title, kicker, action }: { title: string; kicker: string; action?: ReactNode }) {
  return <div className="panel-header"><div><span>{kicker}</span><h2>{title}</h2></div>{action}</div>
}

function HealthRow({ name, status, detail, latency_ms }: { name: string; status: string; detail?: string; latency_ms?: number }) {
  const good = status === 'ok' || status === 'configured'
  return <div className="health-row"><div className={`health-icon ${good ? 'good' : status === 'disabled' ? 'muted' : 'bad'}`}>{good ? <Check size={14} /> : status === 'disabled' ? <CircleHelp size={14} /> : <AlertTriangle size={14} />}</div><div className="health-copy"><strong>{name.replaceAll('_', ' ')}</strong><small>{detail ?? status}</small></div><span className="health-latency">{latency_ms ? `${latency_ms}ms` : status.toUpperCase()}</span></div>
}

function Insight({ icon: Icon, title, value, detail }: { icon: typeof Activity; title: string; value: string; detail: string }) {
  return <div className="insight-row"><div className="insight-icon"><Icon size={17} /></div><div><strong>{title}</strong><small>{detail}</small></div><b>{value}</b></div>
}

function QuickLink({ icon: Icon, title, detail, onClick }: { icon: typeof Activity; title: string; detail: string; onClick: () => void }) {
  return <button className="quick-link" onClick={onClick}><div className="quick-icon"><Icon size={18} /></div><span><strong>{title}</strong><small>{detail}</small></span><ChevronRight size={16} /></button>
}

function TrendChart({ points, label = '拒绝速率', chartID = 'trend-chart' }: { points: Array<{ timestamp: number; value: number }>; label?: string; chartID?: string }) {
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
  const fillID = `${chartID}-fill`
  return <div className="chart-wrap"><svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`${label}趋势，共 ${points.length} 个点`}><defs><linearGradient id={fillID} x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stopColor="#4ee6d0" stopOpacity=".22" /><stop offset="100%" stopColor="#4ee6d0" stopOpacity="0" /></linearGradient></defs><line x1="24" x2="696" y1="44" y2="44" className="chart-gridline" /><line x1="24" x2="696" y1="110" y2="110" className="chart-gridline" /><line x1="24" x2="696" y1="176" y2="176" className="chart-gridline" /><path d={`${path} L 696 196 L 24 196 Z`} fill={`url(#${fillID})`} /><path d={path} className="chart-line" fill="none" /></svg><div className="chart-axis"><span>{formatDate(points[0]?.timestamp)}</span><span>{formatDate(points.at(-1)?.timestamp)}</span></div><p className="chart-summary">服务端固定查询 · {label} · 可通过 Prometheus 配置启用</p></div>
}

function RulesPage({ rules, auth, onError }: { rules: RuleList | null; auth: AuthState; onError: (reason: unknown) => void }) {
  const [expanded, setExpanded] = useState<string | null>(rules?.chains[0]?.name ?? null)
  const [preview, setPreview] = useState<RulePreview | null>(null)
  const [form, setForm] = useState({ path: '/ubuntu-releases/example.iso', method: 'GET', ip: '192.0.2.10', pow_status: 'missing', pow_mode: '', is_protected: true })
  const chains = rules?.chains ?? []
  const runPreview = async () => {
    try {
      setPreview(await rpc<RulePreview>('rule.preview', { request: form }, auth))
    } catch (reason) { onError(reason) }
  }
  return <section className="split-layout"><div className="panel rules-panel"><PanelHeader title="风险链" kicker={`${chains.length} CHAINS · READ ONLY`} /><div className="chain-list">{chains.map((chain) => <div className={`chain-card ${expanded === chain.name ? 'expanded' : ''}`} key={chain.name}><button className="chain-heading" onClick={() => setExpanded(expanded === chain.name ? null : chain.name)}><span className="chain-index">{chain.name.slice(0, 2)}</span><span><strong>{chain.name}</strong><small>{chain.rules.length} rules · policy {chain.policy.target}</small></span><ChevronRight size={17} /></button>{expanded === chain.name && <div className="chain-body"><div className="policy-callout"><span>DEFAULT POLICY</span><strong>{chain.policy.target}</strong><small>{chain.policy.reason || '未填写原因'} · {chain.policy.limit_rate || 'no rate limit'}</small></div>{chain.rules.map((rule, index) => <div className="rule-row" key={`${rule.name}-${index}`}><span className="rule-number">{String(index + 1).padStart(2, '0')}</span><div><strong>{rule.name}</strong><small>{rule.target} · {rule.reason || 'no reason'}</small></div><code>{Object.keys(rule.match).join(' + ') || 'always'}</code></div>)}</div>}</div>)}</div></div><div className="panel preview-panel"><PanelHeader title="规则预览" kicker="DRY RUN · NO SIDE EFFECTS" /><div className="form-stack"><Field label="PATH"><input value={form.path} onChange={(event) => setForm({ ...form, path: event.target.value })} /></Field><div className="form-two"><Field label="METHOD"><input value={form.method} onChange={(event) => setForm({ ...form, method: event.target.value })} /></Field><Field label="CLIENT IP"><input value={form.ip} onChange={(event) => setForm({ ...form, ip: event.target.value })} /></Field></div><div className="form-two"><Field label="POW STATUS"><select value={form.pow_status} onChange={(event) => setForm({ ...form, pow_status: event.target.value })}><option value="missing">missing</option><option value="valid">valid</option><option value="invalid">invalid</option><option value="expired">expired</option></select></Field><Field label="POW MODE"><input value={form.pow_mode} placeholder="generic / ip_bound" onChange={(event) => setForm({ ...form, pow_mode: event.target.value })} /></Field></div><label className="check-field"><input type="checkbox" checked={form.is_protected} onChange={(event) => setForm({ ...form, is_protected: event.target.checked })} /><span>标记为受保护路径</span></label><button className="primary-button" onClick={() => void runPreview()}><TerminalSquare size={16} /> 执行模拟</button></div>{preview && <div className={`preview-result ${preview.ok ? 'ok' : 'bad'}`}><div className="result-top"><span>{preview.ok ? 'DECISION' : 'ERROR'}</span><strong>{preview.decision?.target ?? preview.error}</strong></div>{preview.decision && <p>{preview.decision.reason} · {preview.decision.chain}:{preview.decision.rule_name || 'policy'}</p>}{preview.trace && <div className="trace-list">{preview.trace.map((step, index) => <code key={`${step.chain}-${step.rule}-${index}`} className={step.matched ? 'matched' : ''}>{step.matched ? '✓' : '·'} {step.chain}:{step.rule}</code>)}</div>}</div>}</div></section>
}

function TokensPage({ auth, onError }: { auth: AuthState; onError: (reason: unknown) => void }) {
  const [signID, setSignID] = useState('')
  const [result, setResult] = useState<TokenGet | null>(null)
  const [searching, setSearching] = useState(false)
  const searchToken = async () => { setSearching(true); try { setResult(await rpc<TokenGet>('token.get', { sign_id: signID }, auth)) } catch (reason) { onError(reason) } finally { setSearching(false) } }
  return <section className="single-layout"><div className="panel lookup-panel"><PanelHeader title="查询使用记录" kicker="GENERIC MODE / SIGN ID" /><div className="lookup-form"><div className="input-with-button"><Search size={18} /><input value={signID} placeholder="输入 64 字符 sign ID" aria-label="sign ID" onChange={(event) => setSignID(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter') void searchToken() }} /><button className="primary-button" onClick={() => void searchToken()} disabled={searching || !signID.trim()}>{searching ? <RefreshCw size={16} className="spin" /> : <Search size={16} />} 查询</button></div><p className="helper-text"><LockKeyhole size={14} /> 服务端不会返回原始 sign、token hash、User-Agent 或 IP 地址。</p></div></div>{result && (result.found && result.token ? <div className="panel token-result"><PanelHeader title="Usage record" kicker="RECORD FOUND" action={<span className="source-badge good"><Check size={13} /> FOUND</span>} /><div className="record-grid"><RecordValue label="SIGN ID" value={result.token.id} mono /><RecordValue label="MODE" value={result.token.mode} /><RecordValue label="PATH" value={result.token.path} mono /><RecordValue label="USAGE" value={`${result.token.uses} / ${result.token.max_uses}`} /><RecordValue label="EXPIRES" value={formatDate(result.token.expires_at)} /><RecordValue label="IP HINT" value={result.token.ip_hint || '—'} mono /></div></div> : <EmptyState icon={Search} title="没有找到记录" description="确认 sign ID 完整且该 generic token 已至少被验证一次。" />)}</section>
}

function RecordValue({ label, value, mono }: { label: string; value: string; mono?: boolean }) { return <div className="record-value"><span>{label}</span><strong className={mono ? 'mono' : ''}>{value}</strong></div> }

function PendingPage({ pending, auth, onError, onChanged }: { pending: PendingList | null; auth: AuthState; onError: (reason: unknown) => void; onChanged: (message: string) => Promise<void> }) {
  const entries = pending?.entries ?? []
  const [dialog, setDialog] = useState<{ mode: 'add' | 'unblock'; fingerprint?: string } | null>(null)
  const [form, setForm] = useState({ ip: '', confirm_ip: '', ttl_seconds: '3600', reason: '' })
  const [submitting, setSubmitting] = useState(false)
  const [operationError, setOperationError] = useState('')

  const openDialog = (mode: 'add' | 'unblock', fingerprint?: string) => {
    setForm({ ip: '', confirm_ip: '', ttl_seconds: '3600', reason: '' })
    setOperationError('')
    setDialog({ mode, fingerprint })
  }

  const submit = async () => {
    if (!dialog) return
    setSubmitting(true)
    setOperationError('')
    try {
      const response = dialog.mode === 'add'
        ? await rpc<RiskBlockMutation>('risk.blocks.add', {
          ip: form.ip,
          confirm_ip: form.confirm_ip,
          ttl_seconds: Number(form.ttl_seconds),
          reason: form.reason,
        }, auth)
        : await rpc<RiskBlockMutation>('risk.blocks.unblock', {
          ip: form.ip,
          confirm_ip: form.confirm_ip,
        }, auth)
      const stillAutomatic = dialog.mode === 'unblock' && response.entry.blocked && response.entry.source === 'automatic'
      setDialog(null)
      await onChanged(stillAutomatic
        ? '人工阻断已解除，但自动 Pending 阻断仍在生效'
        : dialog.mode === 'add' ? '人工 IP Block 已应用' : '人工 IP Block 已解除')
    } catch (reason) {
      setOperationError(reason instanceof Error ? reason.message : '操作失败')
      if (reason instanceof AuthRequiredError) onError(reason)
    } finally {
      setSubmitting(false)
    }
  }

  const mutationEnabled = pending?.mutations_enabled ?? false
  return <section className="single-layout">
    <div className="panel operation-note">
      <div><Ban size={18} /><span><strong>实例级紧急阻断</strong><small>人工 Block 高于 bypass_all；状态不跨副本，重启后丢失。</small></span></div>
      <button className="danger-button" onClick={() => openDialog('add')} disabled={!mutationEnabled} title={mutationEnabled ? '添加人工 IP Block' : '需要显式开启 Admin mutation 与 IP block'}><Ban size={16} /> 添加 Block</button>
    </div>
    <div className="panel">
      <PanelHeader title="Pending / Block 状态" kicker={`SCOPE: ${pending?.scope?.toUpperCase() ?? 'INSTANCE'}`} action={<span className={`source-badge ${mutationEnabled ? 'good' : 'muted'}`}><TimerReset size={13} /> {mutationEnabled ? 'MUTATIONS ON' : 'MUTATIONS OFF'}</span>} />
      {entries.length === 0 ? <EmptyState icon={TimerReset} title="当前没有活跃 Pending 或 Block" description={mutationEnabled ? '可通过上方操作添加实例级人工 IP Block。' : '管理写操作默认关闭；启用后可添加人工 IP Block。'} /> : <div className="data-table-wrap"><table className="block-table"><thead><tr><th>IP 指纹</th><th>Pending</th><th>来源 / 原因</th><th>状态</th><th>阻断截止</th><th>操作者</th><th>操作</th></tr></thead><tbody>{entries.map((entry) => <tr key={entry.ip}><td className="mono">{entry.ip}</td><td>{entry.pending}</td><td><strong>{entry.source || 'pending'}</strong><small className="table-subtext">{entry.reason || '—'}</small></td><td><span className={`table-status ${entry.blocked ? 'danger' : 'good'}`}><span /> {entry.blocked ? 'BLOCKED' : 'ACTIVE'}</span></td><td>{formatDate(entry.blocked_until)}</td><td>{entry.actor || '—'}</td><td><button className="table-action" disabled={!mutationEnabled || !entry.source?.includes('manual')} onClick={() => openDialog('unblock', entry.ip)}>解除人工 Block</button></td></tr>)}</tbody></table></div>}
    </div>
    {dialog && <BlockMutationModal mode={dialog.mode} expectedFingerprint={dialog.fingerprint} form={form} setForm={setForm} submitting={submitting} error={operationError} onSubmit={() => void submit()} onClose={() => setDialog(null)} />}
  </section>
}

function BlockMutationModal({ mode, expectedFingerprint, form, setForm, submitting, error, onSubmit, onClose }: { mode: 'add' | 'unblock'; expectedFingerprint?: string; form: { ip: string; confirm_ip: string; ttl_seconds: string; reason: string }; setForm: (value: { ip: string; confirm_ip: string; ttl_seconds: string; reason: string }) => void; submitting: boolean; error: string; onSubmit: () => void; onClose: () => void }) {
  const isAdd = mode === 'add'
  const ready = form.ip.trim() !== '' && form.confirm_ip.trim() !== '' && form.ip.trim() === form.confirm_ip.trim() && (!isAdd || (form.reason.trim() !== '' && Number(form.ttl_seconds) > 0))
  return <div className="modal-scrim"><section className="auth-modal block-modal" role="dialog" aria-modal="true" aria-labelledby="block-title"><button className="modal-close icon-button" aria-label="关闭" onClick={onClose}><X size={18} /></button><div className="auth-icon danger-icon"><Ban size={22} /></div><span className="eyebrow">ADMIN MUTATION / INSTANCE</span><h2 id="block-title">{isAdd ? '添加人工 IP Block' : '解除人工 IP Block'}</h2><p>{isAdd ? '该操作优先于 bypass_all，并只作用于当前后端实例。' : '只清除人工 Block；仍有效的自动 Pending Block 不会被解除。'}</p>{expectedFingerprint && <div className="fingerprint-callout"><span>目标指纹</span><code>{expectedFingerprint}</code></div>}<div className="form-two block-form"><Field label="目标 IP"><input value={form.ip} autoFocus placeholder="192.0.2.1" onChange={(event) => setForm({ ...form, ip: event.target.value })} /></Field><Field label="再次输入 IP 确认"><input value={form.confirm_ip} placeholder="必须与目标 IP 完全一致" onChange={(event) => setForm({ ...form, confirm_ip: event.target.value })} /></Field></div>{isAdd && <><div className="form-two"><Field label="TTL（秒）"><input type="number" min="1" value={form.ttl_seconds} onChange={(event) => setForm({ ...form, ttl_seconds: event.target.value })} /></Field><Field label="原因"><input value={form.reason} maxLength={256} placeholder="必填，不得包含换行" onChange={(event) => setForm({ ...form, reason: event.target.value })} /></Field></div></>}{form.ip && form.confirm_ip && form.ip !== form.confirm_ip && <div className="inline-error" role="alert">两次输入的 IP 不一致。</div>}{error && <div className="inline-error" role="alert">{error}</div>}<div className="modal-actions"><button className="secondary-button" onClick={onClose} disabled={submitting}>取消</button><button className="danger-button" onClick={onSubmit} disabled={!ready || submitting}>{submitting ? <RefreshCw size={16} className="spin" /> : <Ban size={16} />} {isAdd ? '确认 Block' : '确认解除'}</button></div></section></div>
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
  return <section className="single-layout">
    <div className="panel">
      <PanelHeader title="审计事件" kicker="ADMIN_AUDIT · LOKI" action={<span className={`source-badge ${audit?.available ? 'good' : 'muted'}`}><Activity size={13} /> {audit?.available ? 'LIVE' : 'UNAVAILABLE'}</span>} />
      <div className="audit-toolbar">
        <label><span>动作</span><select value={actionFilter} onChange={(event) => setActionFilter(event.target.value)}><option value="">全部动作</option>{actions.map((action) => <option key={action} value={action}>{action}</option>)}</select></label>
        <label><span>结果</span><select value={resultFilter} onChange={(event) => setResultFilter(event.target.value as 'all' | 'ok' | 'error')}><option value="all">全部结果</option><option value="ok">成功</option><option value="error">失败</option></select></label>
        <span className="audit-count">显示 {filtered.length} / {events.length} 条 · 最近 24 小时</span>
      </div>
      {filtered.length === 0 ? <EmptyState icon={FileSearch} title="没有可展示的审计事件" description={audit?.error ?? (events.length > 0 ? '当前筛选条件没有匹配事件。' : '配置 Loki 后启用固定 LogQL 查询。')} /> : <div className="data-table-wrap"><table><thead><tr><th>时间</th><th>动作</th><th>操作者</th><th>目标 / 原因</th><th>结果</th><th>请求 ID</th><th>详情</th></tr></thead><tbody>{filtered.map((event, index) => <tr key={`${event.timestamp}-${event.action}-${index}`}><td className="mono">{formatDate(event.timestamp)}</td><td><strong>{event.action}</strong></td><td>{event.actor}</td><td><span className="mono">{event.target || '—'}</span><small className="table-subtext">{event.reason || event.source || '—'}</small></td><td><span className={`table-status ${event.ok ? 'good' : 'danger'}`}><span /> {event.ok ? 'OK' : event.code || 'ERROR'}</span></td><td className="mono">{event.request_id || '—'}</td><td>{event.detail || '—'}</td></tr>)}</tbody></table></div>}
    </div>
  </section>
}

function ConfigPage({ auth, onError, onToast, refreshNonce }: { auth: AuthState; onError: (reason: unknown) => void; onToast: (message: string) => void; refreshNonce: number }) { return <ConfigManagement auth={auth} onError={onError} onToast={onToast} refreshNonce={refreshNonce} /> }

function Field({ label, children }: { label: string; children: ReactNode }) { return <label className="field"><span>{label}</span>{children}</label> }
function EmptyState({ icon: Icon, title, description }: { icon: typeof Activity; title: string; description: string }) { return <div className="empty-state"><div className="empty-icon"><Icon size={22} /></div><strong>{title}</strong><p>{description}</p></div> }
function AuthModal({ authForm, setAuthForm, onSubmit, onClose }: { authForm: { mode: 'token' | 'basic'; token: string; username: string; password: string }; setAuthForm: (value: { mode: 'token' | 'basic'; token: string; username: string; password: string }) => void; onSubmit: () => void; onClose: () => void }) { return <div className="modal-scrim"><section className="auth-modal" role="dialog" aria-modal="true" aria-labelledby="auth-title"><button type="button" className="modal-close icon-button" aria-label="关闭" onClick={onClose}><X size={18} /></button><div className="auth-icon"><LockKeyhole size={22} /></div><h2 id="auth-title">连接运维控制面</h2><p>凭据只保存在当前页面内存，不会写入浏览器存储。</p><div className="auth-tabs"><button type="button" className={authForm.mode === 'token' ? 'active' : ''} onClick={() => setAuthForm({ ...authForm, mode: 'token' })}>Bearer Token</button><button type="button" className={authForm.mode === 'basic' ? 'active' : ''} onClick={() => setAuthForm({ ...authForm, mode: 'basic' })}>Basic Auth</button></div><form onSubmit={(event) => { event.preventDefault(); onSubmit() }}>{authForm.mode === 'token' ? <><input className="visually-hidden" name="username" autoComplete="username" value="admin-token" readOnly tabIndex={-1} aria-hidden="true" /><Field label="管理 Token"><input name="password" type="password" autoComplete="current-password" value={authForm.token} autoFocus onChange={(event) => setAuthForm({ ...authForm, token: event.target.value })} /></Field></> : <><Field label="用户名"><input autoComplete="username" value={authForm.username} onChange={(event) => setAuthForm({ ...authForm, username: event.target.value })} /></Field><Field label="密码"><input type="password" autoComplete="current-password" value={authForm.password} onChange={(event) => setAuthForm({ ...authForm, password: event.target.value })} /></Field></>}<button type="submit" className="primary-button full-button"><LockKeyhole size={16} /> 验证并连接</button></form></section></div> }

export default App
