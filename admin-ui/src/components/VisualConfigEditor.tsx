import { useEffect, useMemo, useState } from 'react'
import { load as loadYaml, dump as dumpYaml } from 'js-yaml'
import { AlertTriangle, Lock } from 'lucide-react'

type Obj = Record<string, unknown>

/**
 * Visual form editor over the config draft YAML. Edits are serialized back to
 * YAML and flow through the existing draft / validate / diff / apply pipeline.
 * Secrets stay as ${SECRET:...} placeholders — the server merges real values.
 */
export default function VisualConfigEditor({ yamlText, onChange, disabled }: {
  yamlText: string
  onChange: (nextYaml: string) => void
  disabled: boolean
}) {
  const [showYaml, setShowYaml] = useState(false)

  const { doc, parseError } = useMemo(() => {
    if (!yamlText.trim()) return { doc: {} as Obj, parseError: '' }
    try {
      return { doc: (loadYaml(yamlText) ?? {}) as Obj, parseError: '' }
    } catch (reason) {
      return { doc: {} as Obj, parseError: reason instanceof Error ? reason.message : 'YAML 解析失败' }
    }
  }, [yamlText])

  const update = (mutate: (root: Obj) => void) => {
    const next: Obj = structuredClone(doc)
    mutate(next)
    onChange(dumpYaml(next, { lineWidth: 120, noRefs: true }))
  }

  const setPath = (path: string[], value: unknown) => {
    update((root) => {
      let node: Obj = root
      for (const key of path.slice(0, -1)) {
        if (typeof node[key] !== 'object' || node[key] === null) node[key] = {}
        node = node[key] as Obj
      }
      const leaf = path.at(-1)!
      if (value === undefined) delete node[leaf]
      else node[leaf] = value
    })
  }

  return <div className="flex flex-col min-h-0">
    <div className="flex gap-1 px-6 pt-3">
      <button type="button" className={`px-3 py-1.5 text-sm rounded-md transition ${!showYaml ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-accent'}`} onClick={() => setShowYaml(false)}>表单</button>
      <button type="button" className={`px-3 py-1.5 text-sm rounded-md transition ${showYaml ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-accent'}`} onClick={() => setShowYaml(true)}>YAML</button>
    </div>
    {parseError && <div className="mx-6 mt-3 rounded-lg border border-destructive/30 bg-destructive-soft px-3 py-2 text-xs text-destructive-foreground flex items-center gap-2"><AlertTriangle size={14} className="flex-none" />{parseError}</div>}
    {showYaml
      ? <textarea className="mx-6 my-3 min-h-[520px] w-[calc(100%-3rem)] rounded-lg border border-border bg-background p-4 font-mono text-xs outline-none focus:border-primary" spellCheck={false} value={yamlText} disabled={disabled} onChange={(event) => onChange(event.target.value)} aria-label="配置 YAML" />
      : <div className="p-4 pt-3 space-y-3 max-h-[640px] overflow-auto" aria-label="可视化配置表单">
          <ServerSection doc={doc} disabled={disabled || !!parseError} setPath={setPath} />
          <PowSection doc={doc} disabled={disabled || !!parseError} setPath={setPath} />
          <ProtectionSection doc={doc} disabled={disabled || !!parseError} setPath={setPath} />
          <RiskSection doc={doc} disabled={disabled || !!parseError} setPath={setPath} />
          <StorageSection doc={doc} disabled={disabled || !!parseError} setPath={setPath} />
          <LoggingSection doc={doc} disabled={disabled || !!parseError} setPath={setPath} />
          <CleanupSection doc={doc} disabled={disabled || !!parseError} setPath={setPath} />
          <AdminSection doc={doc} />
        </div>}
  </div>
}

/* ---------- field primitives ---------- */

function get(doc: Obj, path: string[]): unknown {
  let node: unknown = doc
  for (const key of path) {
    if (typeof node !== 'object' || node === null) return undefined
    node = (node as Obj)[key]
  }
  return node
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return <details className="rounded-lg border border-border bg-surface-secondary" open>
    <summary className="flex items-center px-4 py-2.5 cursor-pointer text-sm font-medium select-none list-none [&::-webkit-details-marker]:hidden">{title}</summary>
    <div className="border-t border-separator px-4 py-3">{children}</div>
  </details>
}

function Toggle({ label, path, doc, disabled, setPath }: { label: string; path: string[]; doc: Obj; disabled: boolean; setPath: (path: string[], value: unknown) => void }) {
  const value = get(doc, path) === true
  return <label className={`flex items-center gap-2.5 min-h-9 ${disabled ? 'opacity-55 cursor-not-allowed' : 'cursor-pointer'}`}>
    <input type="checkbox" className="peer sr-only" checked={value} disabled={disabled} onChange={(event) => setPath(path, event.target.checked)} />
    <span className={`w-8 h-[18px] rounded-full transition relative flex-none ring-primary ring-offset-2 ring-offset-surface-secondary peer-focus-visible:ring-2 ${value ? 'bg-primary' : 'bg-muted-foreground/30'}`}>
      <span className={`absolute top-[3px] h-3 w-3 rounded-full bg-white transition-all ${value ? 'left-[17px]' : 'left-[3px]'}`} />
    </span>
    <span className="text-sm">{label}</span>
  </label>
}

function TextRow({ label, path, doc, disabled, setPath, placeholder, mono }: { label: string; path: string[]; doc: Obj; disabled: boolean; setPath: (path: string[], value: unknown) => void; placeholder?: string; mono?: boolean }) {
  const raw = get(doc, path)
  const value = raw === undefined || raw === null ? '' : String(raw)
  const secret = typeof raw === 'string' && raw.startsWith('${SECRET:')
  return <label className="block">
    <span className="block mb-1 text-xs text-muted-foreground">{label}</span>
    {secret
      ? <span className="flex items-center gap-1.5 h-9 px-3 rounded-lg border border-dashed border-border text-xs text-muted-foreground"><Lock size={12} /> 保密值</span>
      : <input className={`input ${mono ? 'font-mono' : ''}`} value={value} disabled={disabled} placeholder={placeholder} onChange={(event) => setPath(path, event.target.value)} />}
  </label>
}

function NumberRow({ label, path, doc, disabled, setPath, min }: { label: string; path: string[]; doc: Obj; disabled: boolean; setPath: (path: string[], value: unknown) => void; min?: number }) {
  const raw = get(doc, path)
  const value = raw === undefined || raw === null ? '' : String(raw)
  const secret = typeof raw === 'string' && raw.startsWith('${SECRET:')
  return <label className="block">
    <span className="block mb-1 text-xs text-muted-foreground">{label}</span>
    {secret
      ? <span className="flex items-center gap-1.5 h-9 px-3 rounded-lg border border-dashed border-border text-xs text-muted-foreground"><Lock size={12} /> 保密值</span>
      : <input className="input tabular-nums" type="number" value={value} min={min} disabled={disabled} onChange={(event) => setPath(path, event.target.value === '' ? '' : Number(event.target.value))} />}
  </label>
}

function SelectRow({ label, path, doc, disabled, setPath, options }: { label: string; path: string[]; doc: Obj; disabled: boolean; setPath: (path: string[], value: unknown) => void; options: readonly string[] }) {
  const raw = get(doc, path)
  const value = raw === undefined || raw === null ? '' : String(raw)
  return <label className="block">
    <span className="block mb-1 text-xs text-muted-foreground">{label}</span>
    <select className="input" value={value} disabled={disabled} onChange={(event) => setPath(path, event.target.value)}>
      {options.map((option) => <option key={option} value={option}>{option}</option>)}
    </select>
  </label>
}

function StringList({ label, path, doc, disabled, setPath, placeholder }: { label: string; path: string[]; doc: Obj; disabled: boolean; setPath: (path: string[], value: unknown) => void; placeholder?: string }) {
  const list = Array.isArray(get(doc, path)) ? get(doc, path) as unknown[] : []
  const [draft, setDraft] = useState('')
  useEffect(() => { setDraft('') }, [label])
  const add = () => {
    const item = draft.trim()
    if (!item) return
    setPath(path, [...list, item])
    setDraft('')
  }
  return <div>
    <span className="block mb-1 text-xs text-muted-foreground">{label}</span>
    <div className="flex flex-wrap gap-1.5 min-h-9 items-center">
      {list.map((item, index) => <span className="badge bg-primary-soft text-primary font-mono" key={`${item}-${index}`}>
        {String(item)}
        {!disabled && <button type="button" className="opacity-60 hover:opacity-100" aria-label={`删除 ${item}`} onClick={() => setPath(path, list.filter((_, i) => i !== index))}>×</button>}
      </span>)}
      {list.length === 0 && <span className="text-xs text-faint-foreground">（空）</span>}
    </div>
    {!disabled && <div className="flex gap-2 mt-2">
      <input className="input h-8 py-1 font-mono text-xs" value={draft} placeholder={placeholder ?? '输入后回车添加'} disabled={disabled}
        onChange={(event) => setDraft(event.target.value)}
        onKeyDown={(event) => { if (event.key === 'Enter') { event.preventDefault(); add() } }} />
      <button type="button" className="btn-outline !py-1" onClick={add} disabled={!draft.trim()}>添加</button>
    </div>}
  </div>
}

/* ---------- sections ---------- */

type SectionProps = { doc: Obj; disabled: boolean; setPath: (path: string[], value: unknown) => void }

function ServerSection({ doc, disabled, setPath }: SectionProps) {
  return <Section title="服务">
    <div className="grid grid-cols-2 gap-3">
      <TextRow label="监听地址" path={['server', 'listen']} doc={doc} disabled={disabled} setPath={setPath} placeholder="127.0.0.1:8080" />
      <TextRow label="读超时" path={['server', 'read_timeout']} doc={doc} disabled={disabled} setPath={setPath} placeholder="2s" />
      <TextRow label="写超时" path={['server', 'write_timeout']} doc={doc} disabled={disabled} setPath={setPath} placeholder="2s" />
      <TextRow label="空闲超时" path={['server', 'idle_timeout']} doc={doc} disabled={disabled} setPath={setPath} placeholder="30s" />
    </div>
  </Section>
}

function PowModeFields({ doc, disabled, setPath, mode }: SectionProps & { mode: 'ip_bound' | 'generic' }) {
  const base = ['pow', 'modes', mode]
  const isGeneric = mode === 'generic'
  return <div className="rounded-lg bg-background p-3 mt-3">
    <div className="text-xs font-medium text-foreground mb-2.5">{isGeneric ? '通用模式' : 'IP 绑定模式'}</div>
    <div className="grid grid-cols-2 gap-3">
      <Toggle label="启用" path={[...base, 'enabled']} doc={doc} disabled={disabled} setPath={setPath} />
      <NumberRow label="最小难度" path={[...base, 'min_difficulty']} doc={doc} disabled={disabled} setPath={setPath} min={1} />
      <NumberRow label="最大难度" path={[...base, 'max_difficulty']} doc={doc} disabled={disabled} setPath={setPath} min={1} />
      <NumberRow label="TTL（秒）" path={[...base, 'max_ttl_seconds']} doc={doc} disabled={disabled} setPath={setPath} min={1} />
      {isGeneric && <NumberRow label="最大使用次数" path={[...base, 'max_uses']} doc={doc} disabled={disabled} setPath={setPath} min={1} />}
      {!isGeneric && <Toggle label="要求携带 IP" path={[...base, 'require_ip']} doc={doc} disabled={disabled} setPath={setPath} />}
      {isGeneric && <Toggle label="计数 HEAD 请求" path={[...base, 'count_head_request']} doc={doc} disabled={disabled} setPath={setPath} />}
    </div>
  </div>
}

function PowSection({ doc, disabled, setPath }: SectionProps) {
  return <Section title="PoW 验证">
    <div className="grid grid-cols-2 gap-3">
      <Toggle label="启用 PoW" path={['pow', 'enabled']} doc={doc} disabled={disabled} setPath={setPath} />
      <Toggle label="dry_run（只记录不拦截）" path={['pow', 'dry_run']} doc={doc} disabled={disabled} setPath={setPath} />
      <Toggle label="bypass_all（跳过验证与风控）" path={['pow', 'bypass_all']} doc={doc} disabled={disabled} setPath={setPath} />
      <SelectRow label="算法" path={['pow', 'algorithm']} doc={doc} disabled={disabled} setPath={setPath} options={['sha256', 'sha512']} />
      <TextRow label="token 参数名" path={['pow', 'token_param']} doc={doc} disabled={disabled} setPath={setPath} />
      <TextRow label="sign 参数名" path={['pow', 'sign_param']} doc={doc} disabled={disabled} setPath={setPath} />
      <NumberRow label="token 最大长度" path={['pow', 'max_token_length']} doc={doc} disabled={disabled} setPath={setPath} min={1} />
      <NumberRow label="sign 最大长度" path={['pow', 'max_sign_length']} doc={doc} disabled={disabled} setPath={setPath} min={1} />
      <TextRow label="公开盐值" path={['pow', 'public_salt']} doc={doc} disabled={disabled} setPath={setPath} />
    </div>
    <PowModeFields doc={doc} disabled={disabled} setPath={setPath} mode="ip_bound" />
    <PowModeFields doc={doc} disabled={disabled} setPath={setPath} mode="generic" />
  </Section>
}

function ProtectionSection({ doc, disabled, setPath }: SectionProps) {
  return <Section title="路径保护">
    <div className="space-y-3">
      <StringList label="受保护扩展名" path={['protection', 'protected_extensions']} doc={doc} disabled={disabled} setPath={setPath} placeholder=".iso" />
      <StringList label="受保护路径（正则）" path={['protection', 'protected_paths']} doc={doc} disabled={disabled} setPath={setPath} placeholder="^/ubuntu/" />
      <StringList label="排除路径（正则）" path={['protection', 'excluded_paths']} doc={doc} disabled={disabled} setPath={setPath} placeholder="^/static/" />
    </div>
  </Section>
}

function RiskSection({ doc, disabled, setPath }: SectionProps) {
  const counters = get(doc, ['risk_control', 'counters'])
  const chains = get(doc, ['risk_control', 'chains'])
  return <Section title="风控">
    <div className="grid grid-cols-2 gap-3">
      <Toggle label="启用风控" path={['risk_control', 'enabled']} doc={doc} disabled={disabled} setPath={setPath} />
      <Toggle label="Pending 并发限制" path={['risk_control', 'pending', 'enabled']} doc={doc} disabled={disabled} setPath={setPath} />
      <NumberRow label="单 IP Pending 上限" path={['risk_control', 'pending', 'max_per_ip']} doc={doc} disabled={disabled} setPath={setPath} min={1} />
      <TextRow label="超限 Block 时长" path={['risk_control', 'pending', 'block_ttl']} doc={doc} disabled={disabled} setPath={setPath} placeholder="1h" />
    </div>
    {(counters !== undefined || chains !== undefined) && <div className="rounded-lg bg-background p-3 mt-3">
      <div className="text-xs font-medium mb-1">计数器与规则链</div>
      <p className="text-xs text-muted-foreground">请用 YAML 编辑（{Array.isArray(counters) ? counters.length : 0} 个计数器 · {chains && typeof chains === 'object' ? Object.keys(chains as Obj).length : 0} 条链）。</p>
    </div>}
  </Section>
}

function LoggingSection({ doc, disabled, setPath }: SectionProps) {
  return <Section title="日志">
    <div className="grid grid-cols-2 gap-3">
      <SelectRow label="级别" path={['logging', 'level']} doc={doc} disabled={disabled} setPath={setPath} options={['debug', 'info', 'warn', 'error']} />
      <SelectRow label="格式" path={['logging', 'format']} doc={doc} disabled={disabled} setPath={setPath} options={['json', 'console']} />
      <Toggle label="记录放行" path={['logging', 'log_access']} doc={doc} disabled={disabled} setPath={setPath} />
      <Toggle label="记录拒绝" path={['logging', 'log_denied']} doc={doc} disabled={disabled} setPath={setPath} />
      <Toggle label="IP 哈希脱敏" path={['logging', 'hash_ip']} doc={doc} disabled={disabled} setPath={setPath} />
    </div>
  </Section>
}

function CleanupSection({ doc, disabled, setPath }: SectionProps) {
  return <Section title="过期清理">
    <div className="grid grid-cols-2 gap-3">
      <Toggle label="启用清理" path={['cleanup', 'enabled']} doc={doc} disabled={disabled} setPath={setPath} />
      <TextRow label="清理间隔" path={['cleanup', 'interval']} doc={doc} disabled={disabled} setPath={setPath} placeholder="10m" />
      <TextRow label="过期宽限期" path={['cleanup', 'expired_grace_period']} doc={doc} disabled={disabled} setPath={setPath} placeholder="24h" />
    </div>
  </Section>
}

function StorageSection({ doc, disabled, setPath }: SectionProps) {
  return <Section title="存储">
    <div className="grid grid-cols-2 gap-3">
      <SelectRow label="主存储驱动" path={['storage', 'driver']} doc={doc} disabled={disabled} setPath={setPath} options={['memory', 'postgres', 'redis']} />
      <SelectRow label="计数器驱动" path={['storage', 'counter_driver']} doc={doc} disabled={disabled} setPath={setPath} options={['memory', 'redis']} />
    </div>
    <div className="rounded-lg bg-background p-3 mt-3">
      <div className="text-xs font-medium text-foreground mb-2.5">PostgreSQL</div>
      <div className="grid grid-cols-2 gap-3">
        <TextRow label="DSN" path={['storage', 'postgres', 'dsn']} doc={doc} disabled={disabled} setPath={setPath} placeholder="postgres://user:pass@host:5432/db" />
        <NumberRow label="最大打开连接" path={['storage', 'postgres', 'max_open_conns']} doc={doc} disabled={disabled} setPath={setPath} min={1} />
        <NumberRow label="最大空闲连接" path={['storage', 'postgres', 'max_idle_conns']} doc={doc} disabled={disabled} setPath={setPath} min={0} />
      </div>
    </div>
    <div className="rounded-lg bg-background p-3 mt-3">
      <div className="text-xs font-medium text-foreground mb-2.5">Redis</div>
      <div className="grid grid-cols-2 gap-3">
        <TextRow label="地址" path={['storage', 'redis', 'addr']} doc={doc} disabled={disabled} setPath={setPath} placeholder="127.0.0.1:6379" />
        <TextRow label="密码" path={['storage', 'redis', 'password']} doc={doc} disabled={disabled} setPath={setPath} />
        <NumberRow label="DB 编号" path={['storage', 'redis', 'db']} doc={doc} disabled={disabled} setPath={setPath} min={0} />
        <TextRow label="Key 前缀" path={['storage', 'redis', 'key_prefix']} doc={doc} disabled={disabled} setPath={setPath} placeholder="mirrors-waf" />
      </div>
    </div>
  </Section>
}

function AdminSection({ doc }: { doc: Obj }) {
  const admin = get(doc, ['admin'])
  const rows: Array<[string, string]> = []
  if (admin && typeof admin === 'object') {
    const a = admin as Obj
    rows.push(['Admin 鉴权', String((a.auth as Obj | undefined)?.type ?? '—')])
    rows.push(['Admin 写操作', (a.mutations_enabled === true ? '开启' : '关闭')])
    rows.push(['配置管理', ((a.config_management as Obj | undefined)?.enabled === true ? '开启' : '关闭')])
  }
  if (rows.length === 0) return null
  return <Section title="管理 API（只读）">
    <div>
      {rows.map(([label, value]) => (
        <div className="flex items-center justify-between py-2 border-b border-separator last:border-b-0" key={label}>
          <span className="text-sm text-muted-foreground">{label}</span>
          <span className="text-sm font-medium font-mono">{value}</span>
        </div>
      ))}
    </div>
  </Section>
}
