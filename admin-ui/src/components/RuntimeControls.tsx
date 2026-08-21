import { useState } from 'react'
import type { ReactNode } from 'react'
import { AlertTriangle, Check, RefreshCw, ShieldAlert, TimerReset, X } from 'lucide-react'
import { AuthRequiredError, rpc } from '../api'
import type { AuthState, RuntimeStatus, RuntimeSwitch } from '../types'

type Props = {
  runtime: RuntimeStatus | null
  auth: AuthState
  onChanged: (runtime: RuntimeStatus, message: string) => void
}

const switchLabels: Record<RuntimeSwitch['key'], string> = {
  bypass_all: '紧急放行',
  dry_run: '演练模式',
}

function remaining(expiresAt?: string) {
  if (!expiresAt) return ''
  const seconds = Math.max(0, Math.floor((new Date(expiresAt).getTime() - Date.now()) / 1000))
  const minutes = Math.floor(seconds / 60)
  const hours = Math.floor(minutes / 60)
  if (hours > 0) return `${hours} 小时 ${minutes % 60} 分`
  if (minutes > 0) return `${minutes} 分钟`
  return `${seconds} 秒`
}

export default function RuntimeControls({ runtime, auth, onChanged }: Props) {
  const [dialog, setDialog] = useState<RuntimeSwitch | null>(null)
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [value, setValue] = useState(true)
  const [ttlSeconds, setTTLSeconds] = useState('600')
  const [reason, setReason] = useState('')

  const open = (item: RuntimeSwitch, nextValue: boolean) => {
    setDialog(item)
    setValue(nextValue)
    setTTLSeconds(item.key === 'bypass_all' ? '600' : '1800')
    setReason('')
    setError('')
  }

  const close = () => {
    if (!submitting) setDialog(null)
  }

  const apply = async () => {
    if (!dialog) return
    setSubmitting(true)
    setError('')
    try {
      const next = await rpc<RuntimeStatus>('runtime.override.set', {
        key: dialog.key,
        value,
        ttl_seconds: Number(ttlSeconds),
        reason,
      }, auth)
      onChanged(next, `${switchLabels[dialog.key]}已临时${value ? '启用' : '关闭'}`)
      setDialog(null)
    } catch (cause) {
      if (cause instanceof AuthRequiredError) setError('需要有效的管理凭据')
      else setError(cause instanceof Error ? cause.message : '操作失败')
    } finally {
      setSubmitting(false)
    }
  }

  const clear = async (item: RuntimeSwitch) => {
    setSubmitting(true)
    try {
      const next = await rpc<RuntimeStatus>('runtime.override.clear', { key: item.key }, auth)
      onChanged(next, `${switchLabels[item.key]}已恢复配置值`)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : '恢复失败')
    } finally {
      setSubmitting(false)
    }
  }

  if (!runtime) return null

  return <section className="panel runtime-panel">
    <PanelHeader />
    <div className="runtime-grid">
      {runtime.switches.map((item) => {
        const isBypass = item.key === 'bypass_all'
        return <article key={item.key} className={`runtime-switch ${isBypass ? 'runtime-danger' : ''}`}>
          <div className="runtime-switch-header">
            <div>
              <strong>{switchLabels[item.key]}</strong>
              <small>{item.description}</small>
            </div>
            <span className={`runtime-state ${item.active_value ? (isBypass ? 'danger' : 'active') : 'inactive'}`}>
              {item.active_value ? '已启用' : '未启用'}
            </span>
          </div>
          {item.overridden ? <div className="runtime-override-note">
            <TimerReset size={14} />
            <span>临时覆盖 · 剩余 {remaining(runtime.overrides.find((entry) => entry.key === item.key)?.expires_at)}</span>
          </div> : <div className="runtime-config-note">配置值：{item.config_value ? '启用' : '关闭'}</div>}
          {item.overridden && item.reason && <p className="runtime-reason">原因：{item.reason}</p>}
          <div className="runtime-actions">
            {item.overridden && <button className="secondary-button" disabled={submitting} onClick={() => void clear(item)}>恢复配置值</button>}
            <button className={isBypass ? 'danger-button' : 'primary-button'} disabled={submitting} onClick={() => open(item, !item.active_value)}>
              {isBypass ? <ShieldAlert size={15} /> : <TimerReset size={15} />}
              临时{item.active_value ? '关闭' : '启用'}
            </button>
          </div>
        </article>
      })}
    </div>
    {dialog && <div className="modal-scrim"><section className="auth-modal runtime-modal" role="dialog" aria-modal="true" aria-labelledby="runtime-title">
      <button className="modal-close icon-button" aria-label="关闭" onClick={close}><X size={18} /></button>
      <div className={`auth-icon ${dialog.key === 'bypass_all' ? 'danger-icon' : ''}`}>{dialog.key === 'bypass_all' ? <ShieldAlert size={22} /> : <TimerReset size={22} />}</div>
      <h2 id="runtime-title">临时{value ? '启用' : '关闭'}{switchLabels[dialog.key]}</h2>
      <p>{dialog.key === 'bypass_all' ? '紧急放行会跳过 PoW 与风控决策；手动 IP Block 仍然有效。覆盖会在 TTL 到期后自动恢复。' : '演练模式会继续记录和验证请求，但将原本的拒绝改为放行。覆盖会在 TTL 到期后自动恢复。'}</p>
      <div className="form-two runtime-form">
        <Field label="持续时间"><select value={ttlSeconds} onChange={(event) => setTTLSeconds(event.target.value)} disabled={submitting}><option value="300">5 分钟</option><option value="600">10 分钟</option><option value="1800">30 分钟</option><option value="3600">1 小时</option><option value="7200">2 小时</option></select></Field>
        <Field label="操作原因"><input value={reason} maxLength={256} autoFocus placeholder="必填，例如：上游故障排查" onChange={(event) => setReason(event.target.value)} disabled={submitting} /></Field>
      </div>
      {dialog.key === 'bypass_all' && <div className="runtime-warning"><AlertTriangle size={15} /> 紧急放行会降低防护能力，请仅在事故处置期间使用。</div>}
      {error && <div className="inline-error" role="alert">{error}</div>}
      <div className="modal-actions"><button className="secondary-button" onClick={close} disabled={submitting}>取消</button><button className={dialog.key === 'bypass_all' ? 'danger-button' : 'primary-button'} onClick={() => void apply()} disabled={submitting || !reason.trim()}>{submitting ? <RefreshCw size={16} className="spin" /> : <Check size={16} />} 确认临时{value ? '启用' : '关闭'}</button></div>
    </section></div>}
  </section>
}

function PanelHeader() {
  return <div className="panel-header"><div><span>临时运行时覆盖</span><h2>紧急开关</h2></div><span className="source-badge muted"><TimerReset size={13} /> 重启即清除</span></div>
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return <label className="field"><span>{label}</span>{children}</label>
}
