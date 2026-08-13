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
  ListFilter,
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
import type {
  AuditList,
  AuthState,
  ConfigGet,
  ConfigValidate,
  DashboardSeries,
  DashboardSummary,
  PendingList,
  RuleList,
  RulePreview,
  RiskBlockMutation,
  SystemHealth,
  SystemInfo,
  TokenGet,
} from './types'
import { formatDate, formatNumber, shortCommit, stringify } from './utils'

type Page = 'overview' | 'rules' | 'tokens' | 'pending' | 'audit' | 'config'

const navItems: Array<{ id: Page; label: string; kicker: string; icon: typeof Activity }> = [
  { id: 'overview', label: '概览', kicker: 'Overview', icon: LayoutDashboard },
  { id: 'rules', label: '规则链', kicker: 'Risk chains', icon: ListFilter },
  { id: 'tokens', label: 'Token 检索', kicker: 'Usage records', icon: KeyRound },
  { id: 'pending', label: 'Pending', kicker: 'Instance guard', icon: TimerReset },
  { id: 'audit', label: '审计轨迹', kicker: 'Audit stream', icon: FileSearch },
  { id: 'config', label: '生效配置', kicker: 'Read-only view', icon: Settings2 },
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
  const [error, setError] = useState('')
  const [summary, setSummary] = useState<DashboardSummary | null>(null)
  const [series, setSeries] = useState<DashboardSeries | null>(null)
  const [health, setHealth] = useState<SystemHealth | null>(null)
  const [info, setInfo] = useState<SystemInfo | null>(null)
  const [rules, setRules] = useState<RuleList | null>(null)
  const [pending, setPending] = useState<PendingList | null>(null)
  const [audit, setAudit] = useState<AuditList | null>(null)
  const [config, setConfig] = useState<ConfigGet | null>(null)
  const [toast, setToast] = useState('')

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
  }, [auth])

  const loadPageData = useCallback(async (signal?: AbortSignal) => {
    if (page === 'overview') return loadOverview(signal)
    setError('')
    try {
      if (page === 'rules') setRules(await rpc<RuleList>('rule.list', {}, auth, signal))
      if (page === 'pending') setPending(await rpc<PendingList>('risk.blocks.list', {}, auth, signal))
      if (page === 'audit') setAudit(await rpc<AuditList>('audit.list', { limit: 100 }, auth, signal))
      if (page === 'config') setConfig(await rpc<ConfigGet>('config.get', {}, auth, signal))
      setAuthRequired(false)
    } catch (reason) {
      handleLoadError(reason)
    }
  }, [auth, loadOverview, page])

  const handleLoadError = (reason: unknown) => {
    if (reason instanceof AuthRequiredError) {
      setAuthRequired(true)
      setError('管理 API 需要凭据。凭据仅保存在当前页面内存中。')
      return
    }
    if (reason instanceof DOMException && reason.name === 'AbortError') return
    setError(reason instanceof Error ? reason.message : '无法连接到后台 API')
  }

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
    if (page !== 'overview') return
    const timer = window.setInterval(() => void loadOverview(), 30_000)
    return () => window.clearInterval(timer)
  }, [loadOverview, page])

  useEffect(() => {
    if (!toast) return
    const timer = window.setTimeout(() => setToast(''), 3600)
    return () => window.clearTimeout(timer)
  }, [toast])

  const refresh = async () => {
    setRefreshing(true)
    try {
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
            <strong>MIRRORS WAF</strong>
            <span>CONTROL PLANE</span>
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
        <div className="sidebar-status">
          <div className="status-dot"><span /> API GATEWAY</div>
          <strong>{auth.mode === 'none' ? '未配置凭据' : '会话凭据已载入'}</strong>
          <small>同源连接 · 内存会话</small>
        </div>
        <div className="sidebar-footer"><span>build {shortCommit(info?.commit ?? '')}</span><span>v{info?.version ?? 'dev'}</span></div>
      </aside>
      {mobileNav && <button className="nav-scrim" aria-label="关闭导航" onClick={() => setMobileNav(false)} />}

      <main className="main-column" id="main-content">
        <header className="top-bar">
          <div className="top-left">
            <button className="icon-button mobile-menu" aria-label="打开导航" onClick={() => setMobileNav(true)}><Menu size={20} /></button>
            <div className="breadcrumbs"><span>CONTROL PLANE</span><ChevronRight size={14} /><strong>{navItems.find((item) => item.id === page)?.label}</strong></div>
          </div>
          <div className="top-actions">
            <div className="connection-pill"><span className={error ? 'warning' : 'online'} /> {error ? 'DEGRADED' : 'OPERATIONAL'}</div>
            <button className="icon-button" aria-label="刷新数据" onClick={() => void refresh()} disabled={refreshing}><RefreshCw size={17} className={refreshing ? 'spin' : ''} /></button>
            <button className="operator-chip" onClick={auth.mode === 'none' ? () => setAuthRequired(true) : signOut} title={auth.mode === 'none' ? '配置凭据' : '清除当前凭据'}><span>OP</span><b>{auth.mode === 'none' ? 'CONNECT' : 'OPERATOR'}</b></button>
          </div>
        </header>

        <div className="content-wrap">
          <div className="page-heading">
            <div>
              <div className="eyebrow"><span className="eyebrow-line" /> MIRRORS-WAF / ADMIN</div>
              <h1>{pageTitle(page)}</h1>
              <p>{pageDescription(page)}</p>
            </div>
            <div className="heading-meta"><span>LOCAL TIME</span><strong>{new Intl.DateTimeFormat('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).format(new Date())}</strong></div>
          </div>

          {error && <div className="alert-banner" role="alert"><AlertTriangle size={18} /><div><strong>控制面连接异常</strong><span>{error}</span></div><button onClick={() => void refresh()}>重试</button></div>}
          {loading ? <LoadingState /> : <>
            {page === 'overview' && <OverviewPage summary={summary} series={series} health={health} onNavigate={navigate} />}
            {page === 'rules' && <RulesPage rules={rules} auth={auth} onError={handleLoadError} />}
            {page === 'tokens' && <TokensPage auth={auth} onError={handleLoadError} />}
            {page === 'pending' && <PendingPage pending={pending} auth={auth} onError={handleLoadError} onChanged={async (message) => { await loadPageData(); setToast(message) }} />}
            {page === 'audit' && <AuditPage audit={audit} />}
            {page === 'config' && <ConfigPage config={config} auth={auth} onError={handleLoadError} />}
          </>}
        </div>
      </main>

      {authRequired && <AuthModal authForm={authForm} setAuthForm={setAuthForm} onSubmit={() => void signIn()} onClose={() => setAuthRequired(false)} />}
      {toast && <div className="toast" role="status"><Check size={16} /> {toast}</div>}
    </div>
  )
}

function pageTitle(page: Page) {
  return { overview: '系统概览', rules: '规则链', tokens: 'Token 检索', pending: 'Pending 守卫', audit: '审计轨迹', config: '生效配置' }[page]
}

function pageDescription(page: Page) {
  return {
    overview: '实时查看 PoW、风控决策和运行时依赖的健康状态。',
    rules: '以只读方式检查当前风险链，并对请求上下文进行安全预览。',
    tokens: '按 sign ID 查询使用记录；敏感字段已在服务端剥离。',
    pending: '查看当前实例的 Pending 状态，并执行受审计的人工 IP Block/Unblock。',
    audit: '从结构化审计流中检索后台操作轨迹。',
    config: '查看已生效配置的脱敏视图，并在应用前验证候选 YAML。',
  }[page]
}

function LoadingState() {
  return <div className="loading-grid"><div className="skeleton hero-skeleton" /><div className="skeleton" /><div className="skeleton" /><div className="skeleton wide" /></div>
}

function OverviewPage({ summary, series, health, onNavigate }: { summary: DashboardSummary | null; series: DashboardSeries | null; health: SystemHealth | null; onNavigate: (page: Page) => void }) {
  const metrics = summary?.metrics
  const cards = [
    { label: 'PoW VERIFICATIONS', value: formatNumber(metrics?.pow_verify_total ?? 0), sub: '进程累计校验', icon: Zap, accent: 'cyan' },
    { label: 'ALLOWED', value: formatNumber(metrics?.pow_allowed_total ?? 0), sub: '通过验证请求', icon: ShieldCheck, accent: 'green' },
    { label: 'DENIED', value: formatNumber(metrics?.pow_denied_total ?? 0), sub: '被拒绝请求', icon: LockKeyhole, accent: 'red' },
    { label: 'ACTIVE SIGNATURES', value: formatNumber(metrics?.active_signatures ?? 0), sub: '当前使用记录', icon: KeyRound, accent: 'amber' },
  ]
  return <>
    <section className="metric-grid" aria-label="核心指标">
      {cards.map((card) => <MetricCard key={card.label} {...card} />)}
    </section>
    <section className="dashboard-grid">
      <div className="panel chart-panel">
        <PanelHeader title="拒绝速率" kicker="PROMETHEUS / FIXED QUERY" action={<span className={`source-badge ${series?.available ? 'good' : 'muted'}`}><Activity size={13} /> {series?.available ? 'LIVE' : 'UNAVAILABLE'}</span>} />
        {series?.available && series.points.length > 0 ? <TrendChart points={series.points} /> : <EmptyState icon={BarChart3} title="暂无时序数据" description={series?.error ?? '配置 Prometheus 后启用固定指标查询。'} />}
      </div>
      <div className="panel health-panel">
        <PanelHeader title="依赖健康" kicker="RUNTIME COMPONENTS" action={<span className="source-badge good"><span className="tiny-dot" /> {health?.ok ? 'ALL CLEAR' : 'CHECK REQUIRED'}</span>} />
        <div className="health-list">{(health?.components ?? []).map((component) => <HealthRow key={component.name} {...component} />)}</div>
      </div>
    </section>
    <section className="dashboard-grid lower-grid">
      <div className="panel insight-panel">
        <PanelHeader title="运行态势" kicker="OPERATOR NOTES" />
        <div className="insight-list">
          <Insight icon={Gauge} title="风险决策总量" value={formatNumber(metrics?.risk_decision_total ?? 0)} detail="由风险引擎累计产生的决策" />
          <Insight icon={Network} title="Pending 范围" value="INSTANCE" detail="当前状态只覆盖本后端进程" />
          <Insight icon={ServerCog} title="控制面" value="PHASE 2" detail="支持受控的实例级 IP Block/Unblock" />
        </div>
      </div>
      <div className="panel quick-panel">
        <PanelHeader title="快速入口" kicker="CONTROL SHORTCUTS" />
        <div className="quick-grid">
          <QuickLink icon={ListFilter} title="检查规则链" detail="查看链和策略" onClick={() => onNavigate('rules')} />
          <QuickLink icon={KeyRound} title="查 Token" detail="定位使用记录" onClick={() => onNavigate('tokens')} />
          <QuickLink icon={FileSearch} title="审计轨迹" detail="检索操作事件" onClick={() => onNavigate('audit')} />
          <QuickLink icon={FileCode2} title="生效配置" detail="查看脱敏配置" onClick={() => onNavigate('config')} />
        </div>
      </div>
    </section>
  </>
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

function TrendChart({ points }: { points: Array<{ timestamp: number; value: number }> }) {
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
  return <div className="chart-wrap"><svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`拒绝速率趋势，共 ${points.length} 个点`}><defs><linearGradient id="chart-fill" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stopColor="#4ee6d0" stopOpacity=".22" /><stop offset="100%" stopColor="#4ee6d0" stopOpacity="0" /></linearGradient></defs><line x1="24" x2="696" y1="44" y2="44" className="chart-gridline" /><line x1="24" x2="696" y1="110" y2="110" className="chart-gridline" /><line x1="24" x2="696" y1="176" y2="176" className="chart-gridline" /><path d={`${path} L 696 196 L 24 196 Z`} fill="url(#chart-fill)" /><path d={path} className="chart-line" fill="none" /></svg><div className="chart-axis"><span>{formatDate(points[0]?.timestamp)}</span><span>{formatDate(points.at(-1)?.timestamp)}</span></div><p className="chart-summary">服务端固定查询 · 仅展示拒绝速率 · 可通过 Prometheus 配置启用</p></div>
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

function AuditPage({ audit }: { audit: AuditList | null }) { const events = audit?.events ?? []; return <section className="single-layout"><div className="panel"><PanelHeader title="审计事件" kicker="ADMIN_AUDIT · LOKI" action={<span className={`source-badge ${audit?.available ? 'good' : 'muted'}`}><Activity size={13} /> {audit?.available ? 'LIVE' : 'UNAVAILABLE'}</span>} />{events.length === 0 ? <EmptyState icon={FileSearch} title="没有可展示的审计事件" description={audit?.error ?? '配置 Loki 后启用固定 LogQL 查询。'} /> : <div className="data-table-wrap"><table><thead><tr><th>时间</th><th>动作</th><th>操作者</th><th>目标 / 原因</th><th>结果</th><th>请求 ID</th><th>详情</th></tr></thead><tbody>{events.map((event, index) => <tr key={`${event.timestamp}-${event.action}-${index}`}><td className="mono">{formatDate(event.timestamp)}</td><td><strong>{event.action}</strong></td><td>{event.actor}</td><td><span className="mono">{event.target || '—'}</span><small className="table-subtext">{event.reason || event.source || '—'}</small></td><td><span className={`table-status ${event.ok ? 'good' : 'danger'}`}><span /> {event.ok ? 'OK' : event.code || 'ERROR'}</span></td><td className="mono">{event.request_id || '—'}</td><td>{event.detail || '—'}</td></tr>)}</tbody></table></div>}</div></section> }

function ConfigPage({ config, auth, onError }: { config: ConfigGet | null; auth: AuthState; onError: (reason: unknown) => void }) { const [yaml, setYaml] = useState(''); const [validation, setValidation] = useState<ConfigValidate | null>(null); const validate = async () => { try { setValidation(await rpc<ConfigValidate>('config.validate', { config_yaml: yaml }, auth)) } catch (reason) { onError(reason) } }; return <section className="split-layout config-layout"><div className="panel"><PanelHeader title="当前配置" kicker="EFFECTIVE · SANITIZED" /><pre className="config-view">{config ? stringify(config.config) : '暂无配置数据'}</pre></div><div className="panel"><PanelHeader title="候选校验" kicker="VALIDATE BEFORE APPLY" /><textarea className="yaml-editor" value={yaml} onChange={(event) => setYaml(event.target.value)} placeholder="粘贴候选 YAML，服务端只校验不写入…" /><button className="primary-button" onClick={() => void validate()} disabled={!yaml.trim()}><FileCode2 size={16} /> 校验候选配置</button>{validation && <div className={`validation-box ${validation.ok ? 'ok' : 'bad'}`}><strong>{validation.ok ? '配置通过校验' : '发现配置问题'}</strong>{validation.error && <p>{validation.error}</p>}{validation.problems?.map((problem) => <p key={problem}>· {problem}</p>)}</div>}</div></section> }

function Field({ label, children }: { label: string; children: ReactNode }) { return <label className="field"><span>{label}</span>{children}</label> }
function EmptyState({ icon: Icon, title, description }: { icon: typeof Activity; title: string; description: string }) { return <div className="empty-state"><div className="empty-icon"><Icon size={22} /></div><strong>{title}</strong><p>{description}</p></div> }
function AuthModal({ authForm, setAuthForm, onSubmit, onClose }: { authForm: { mode: 'token' | 'basic'; token: string; username: string; password: string }; setAuthForm: (value: { mode: 'token' | 'basic'; token: string; username: string; password: string }) => void; onSubmit: () => void; onClose: () => void }) { return <div className="modal-scrim"><section className="auth-modal" role="dialog" aria-modal="true" aria-labelledby="auth-title"><button type="button" className="modal-close icon-button" aria-label="关闭" onClick={onClose}><X size={18} /></button><div className="auth-icon"><LockKeyhole size={22} /></div><span className="eyebrow">ADMIN API / AUTH</span><h2 id="auth-title">连接运维控制面</h2><p>凭据只保存在当前页面内存，不会写入浏览器存储。</p><div className="auth-tabs"><button type="button" className={authForm.mode === 'token' ? 'active' : ''} onClick={() => setAuthForm({ ...authForm, mode: 'token' })}>Bearer Token</button><button type="button" className={authForm.mode === 'basic' ? 'active' : ''} onClick={() => setAuthForm({ ...authForm, mode: 'basic' })}>Basic Auth</button></div><form onSubmit={(event) => { event.preventDefault(); onSubmit() }}>{authForm.mode === 'token' ? <><input className="visually-hidden" name="username" autoComplete="username" value="admin-token" readOnly tabIndex={-1} aria-hidden="true" /><Field label="ADMIN TOKEN"><input name="password" type="password" autoComplete="current-password" value={authForm.token} autoFocus onChange={(event) => setAuthForm({ ...authForm, token: event.target.value })} /></Field></> : <><Field label="USERNAME"><input autoComplete="username" value={authForm.username} onChange={(event) => setAuthForm({ ...authForm, username: event.target.value })} /></Field><Field label="PASSWORD"><input type="password" autoComplete="current-password" value={authForm.password} onChange={(event) => setAuthForm({ ...authForm, password: event.target.value })} /></Field></>}<button type="submit" className="primary-button full-button"><LockKeyhole size={16} /> 验证并连接</button></form></section></div> }

export default App
