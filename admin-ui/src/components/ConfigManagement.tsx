import { useCallback, useEffect, useRef, useState } from 'react'
import { AlertTriangle, Check, FileCode2, RefreshCw, Settings2, Undo2, X } from 'lucide-react'
import { AuthRequiredError, RPCError, rpc } from '../api'
import type {
  AuthState,
  ConfigApply,
  ConfigCapabilities,
  ConfigDiff,
  ConfigDraft,
  ConfigGet,
  ConfigHistory,
  ConfigHistoryEntry,
  ConfigStatus,
  ConfigValidate,
} from '../types'
import { formatDate } from '../utils'

type Confirmation = { mode: 'apply'; diff: ConfigDiff } | { mode: 'rollback'; diff: ConfigDiff; target: ConfigHistoryEntry }
type Operation = 'save' | 'discard' | 'validate' | 'diff' | 'rollback-preview' | 'confirm' | null

const EMPTY_CAPABILITIES: ConfigCapabilities = {
  managed: false,
  mutations_enabled: false,
  apply_enabled: false,
  history_enabled: false,
}

export default function ConfigManagement({ auth, onError, onToast, refreshNonce }: {
  auth: AuthState
  onError: (reason: unknown) => void
  onToast: (message: string) => void
  refreshNonce: number
}) {
  const [config, setConfig] = useState<ConfigGet | null>(null)
  const [status, setStatus] = useState<ConfigStatus | null>(null)
  const [history, setHistory] = useState<ConfigHistoryEntry[]>([])
  const [draft, setDraft] = useState<ConfigDraft | null>(null)
  const [yaml, setYaml] = useState('')
  const [validation, setValidation] = useState<ConfigValidate | null>(null)
  const [diff, setDiff] = useState<ConfigDiff | null>(null)
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null)
  const [operation, setOperation] = useState<Operation>(null)
  const [notice, setNotice] = useState('')
  const [initializing, setInitializing] = useState(true)
  const initialized = useRef(false)

  const reportError = useCallback((reason: unknown, fallback: string) => {
    if (reason instanceof AuthRequiredError) onError(reason)
    const message = reason instanceof Error ? reason.message : fallback
    if (reason instanceof RPCError && (reason.status === 409 || reason.status === 410)) {
      setNotice(`${message}（HTTP ${reason.status}）。编辑内容已保留，请刷新状态后重试。`)
      return
    }
    setNotice(message)
  }, [onError])

  const loadState = useCallback(async (signal?: AbortSignal, preserveEditor = true) => {
    const [nextConfig, nextStatus, historyResult] = await Promise.all([
      rpc<ConfigGet>('config.get', {}, auth, signal),
      rpc<ConfigStatus>('config.status', {}, auth, signal),
      rpc<ConfigHistory>('config.history', { limit: 50 }, auth, signal)
        .then((value) => ({ value, error: null as unknown }))
        .catch((error: unknown) => ({ value: null, error })),
    ])
    if (historyResult.error && !(historyResult.error instanceof RPCError && historyResult.error.code === 'CONFIG_SOURCE_UNMANAGED')) {
      throw historyResult.error
    }
    const nextHistory = historyResult.value ?? { entries: [] }

    let nextDraft: ConfigDraft | null = null
    if (nextStatus.draft) {
      try {
        nextDraft = await rpc<ConfigDraft>('config.draft.get', { draft_id: nextStatus.draft.id }, auth, signal)
      } catch (reason) {
        if (!(reason instanceof RPCError && (reason.status === 404 || reason.status === 410))) throw reason
      }
    }

    setConfig(nextConfig)
    setStatus(nextStatus)
    setHistory(nextHistory.entries ?? [])
    setDraft(nextDraft)
    if (!preserveEditor || !initialized.current) {
      setYaml(nextDraft?.config_yaml ?? nextConfig.editable_yaml ?? '')
      setValidation(nextDraft?.validated ? {
        ok: true,
        valid: true,
        draft_id: nextDraft.draft_id,
        draft_revision: nextDraft.draft_revision,
        restart_required: true,
      } : null)
      setDiff(null)
      initialized.current = true
    }
  }, [auth])

  useEffect(() => {
    const controller = new AbortController()
    initialized.current = false
    setInitializing(true)
    setNotice('')
    void loadState(controller.signal, false)
      .catch((reason) => reportError(reason, '无法加载配置管理状态'))
      .finally(() => setInitializing(false))
    return () => controller.abort()
  }, [loadState, reportError])

  const refreshState = useCallback(async () => {
    setNotice('')
    setOperation('confirm')
    try {
      await loadState(undefined, true)
      onToast('配置状态已刷新，编辑内容保持不变')
    } catch (reason) {
      reportError(reason, '无法刷新配置状态')
    } finally {
      setOperation(null)
    }
  }, [loadState, onToast, reportError])

  useEffect(() => {
    if (refreshNonce === 0) return
    void refreshState()
  }, [refreshNonce, refreshState])

  const saveDraft = async (showBusy = true): Promise<ConfigDraft | null> => {
    setNotice('')
    if (showBusy) setOperation('save')
    try {
      const saved = await rpc<ConfigDraft>('config.draft.save', {
        draft_id: draft?.draft_id,
        expected_draft_revision: draft?.draft_revision,
        base_revision: draft?.base_revision ?? currentRevision,
        config_yaml: yaml,
      }, auth)
      setDraft(saved)
      setYaml(saved.config_yaml)
      setStatus((current) => current ? {
        ...current,
        draft: {
          id: saved.draft_id,
          revision: saved.draft_revision,
          base_revision: saved.base_revision,
          updated_at: saved.updated_at,
          validated: saved.validated,
        },
      } : current)
      setValidation(null)
      setDiff(null)
      onToast(`草稿 r${saved.draft_revision} 已保存`)
      return saved
    } catch (reason) {
      reportError(reason, '保存草稿失败')
      return null
    } finally {
      if (showBusy) setOperation(null)
    }
  }

  const discardDraft = async () => {
    if (!draft) return
    setNotice('')
    setOperation('discard')
    try {
      await rpc<Record<string, never>>('config.draft.discard', {
        draft_id: draft.draft_id,
        expected_draft_revision: draft.draft_revision,
      }, auth)
      setDraft(null)
      setValidation(null)
      setDiff(null)
      setYaml(config?.editable_yaml ?? '')
      setStatus((current) => current ? { ...current, draft: undefined } : current)
      onToast('配置草稿已丢弃')
    } catch (reason) {
      reportError(reason, '丢弃草稿失败')
    } finally {
      setOperation(null)
    }
  }

  const validateDraft = async () => {
    setOperation('validate')
    try {
      const candidate = await saveDraft(false)
      if (!candidate) return
      const result = await rpc<ConfigValidate>('config.validate', {
        draft_id: candidate.draft_id,
        draft_revision: candidate.draft_revision,
      }, auth)
      setValidation(result)
      setDraft({ ...candidate, validated: result.valid })
      setStatus((current) => current?.draft ? { ...current, draft: { ...current.draft, validated: result.valid } } : current)
      setDiff(null)
      if (result.valid) onToast('草稿已通过校验')
    } catch (reason) {
      reportError(reason, '校验草稿失败')
    } finally {
      setOperation(null)
    }
  }

  const previewDiff = async () => {
    setNotice('')
    setOperation('diff')
    try {
      let candidate = draft
      if (!candidate || candidate.config_yaml !== yaml) candidate = await saveDraft(false)
      if (!candidate) return
      if (!candidate.validated) {
        const result = await rpc<ConfigValidate>('config.validate', {
          draft_id: candidate.draft_id,
          draft_revision: candidate.draft_revision,
        }, auth)
        setValidation(result)
        candidate = { ...candidate, validated: result.valid }
        setDraft(candidate)
        if (!result.valid) {
          setNotice('草稿未通过校验，无法生成差异。')
          return
        }
      }
      const preview = await rpc<ConfigDiff>('config.diff', {
        draft_id: candidate.draft_id,
        draft_revision: candidate.draft_revision,
      }, auth)
      setDiff(preview)
      if (preview.changes.length === 0) onToast('草稿与当前配置没有差异')
    } catch (reason) {
      reportError(reason, '生成配置差异失败')
    } finally {
      setOperation(null)
    }
  }

  const openApplyConfirmation = () => {
    if (!diff?.preview_id || !draft || draft.config_yaml !== yaml) {
      setNotice('请先为当前编辑内容生成新的差异预览。')
      return
    }
    setConfirmation({ mode: 'apply', diff })
  }

  const previewRollback = async (target: ConfigHistoryEntry) => {
    setNotice('')
    setOperation('rollback-preview')
    try {
      const preview = await rpc<ConfigDiff>('config.diff', { target_revision: target.revision }, auth)
      if (!preview.preview_id || preview.changes.length === 0) {
        setNotice('目标 revision 与当前磁盘配置没有差异，无需回滚。')
        return
      }
      setConfirmation({ mode: 'rollback', diff: preview, target })
    } catch (reason) {
      reportError(reason, '生成回滚差异失败')
    } finally {
      setOperation(null)
    }
  }

  const completeMutation = async (message: string) => {
    setConfirmation(null)
    initialized.current = false
    await loadState(undefined, false)
    onToast(message)
  }

  const submitConfirmation = async (reason: string, phrase: string) => {
    if (!confirmation) return
    setOperation('confirm')
    setNotice('')
    try {
      if (confirmation.mode === 'apply') {
        if (!draft) throw new Error('草稿已不可用，请重新保存。')
        const result = await rpc<ConfigApply>('config.apply', {
          draft_id: draft.draft_id,
          draft_revision: draft.draft_revision,
          preview_id: confirmation.diff.preview_id,
          expected_revision: confirmation.diff.base_revision,
          reason,
          acknowledged: true,
          confirmation_phrase: phrase,
        }, auth)
        await completeMutation(`配置已写入 revision ${result.revision}${result.restart_required ? '，需要重启生效' : ''}`)
      } else {
        const result = await rpc<ConfigApply>('config.rollback', {
          target_revision: confirmation.target.revision,
          preview_id: confirmation.diff.preview_id,
          expected_revision: confirmation.diff.base_revision,
          reason,
          acknowledged: true,
          confirmation_phrase: phrase,
        }, auth)
        await completeMutation(`已回滚到 revision ${confirmation.target.revision}，生成 revision ${result.revision}`)
      }
    } catch (reasonValue) {
      reportError(reasonValue, '配置操作失败')
    } finally {
      setOperation(null)
    }
  }

  const capabilities = status?.capabilities ?? config?.capabilities ?? EMPTY_CAPABILITIES
  const managed = status?.managed ?? config?.managed ?? false
  const currentRevision = status?.current_revision ?? config?.current_revision ?? 0
  const pendingRestart = status?.pending_restart ?? config?.pending_restart ?? false
  const editorDirty = yaml !== (draft?.config_yaml ?? config?.editable_yaml ?? '')
  const canEdit = managed && capabilities.mutations_enabled && capabilities.apply_enabled
  const busy = operation !== null

  if (initializing) return <div className="config-loading" aria-live="polite"><RefreshCw size={18} className="spin" /> 正在加载配置、状态和历史…</div>

  return <section className="config-management">
    <div className="config-status-grid" aria-label="配置状态">
      <StatusCard label="MANAGED" value={managed ? 'YES' : 'NO'} tone={managed ? 'good' : 'danger'} detail={managed ? '配置源由控制面管理' : '当前配置源不可写'} />
      <StatusCard label="CURRENT REVISION" value={currentRevision ? `#${currentRevision}` : '—'} detail="CAS 基准修订" />
      <StatusCard label="PENDING RESTART" value={pendingRestart ? 'YES' : 'NO'} tone={pendingRestart ? 'warning' : 'good'} detail={pendingRestart ? '磁盘配置尚未载入运行时' : '没有待重启状态'} />
      <StatusCard label="DRAFT" value={draft ? `r${draft.draft_revision}` : 'NONE'} tone={draft?.validated ? 'good' : draft ? 'warning' : undefined} detail={draft ? `base #${draft.base_revision} · ${draft.validated ? 'validated' : 'not validated'}` : '尚未保存草稿'} />
    </div>

    <div className="panel capability-strip">
      <div><Settings2 size={18} /><span><strong>能力开关</strong><small>由服务端状态决定；前端不会绕过权限。</small></span></div>
      <div className="capability-list">
        <CapabilityBadge label="MANAGED" enabled={capabilities.managed} />
        <CapabilityBadge label="MUTATIONS" enabled={capabilities.mutations_enabled} />
        <CapabilityBadge label="APPLY" enabled={capabilities.apply_enabled} />
        <CapabilityBadge label="HISTORY" enabled={capabilities.history_enabled} />
      </div>
    </div>

    {notice && <div className="config-notice" role="alert"><AlertTriangle size={17} /><span>{notice}</span><button type="button" onClick={() => setNotice('')} aria-label="关闭提示"><X size={15} /></button></div>}
    {!canEdit && <div className="config-readonly-note"><AlertTriangle size={17} /><div><strong>配置写操作不可用</strong><span>仍可查看状态与历史。请检查 managed、Admin mutations、认证方式和 config management 开关。</span></div></div>}

    <div className="config-workspace">
      <div className="panel config-editor-panel">
        <div className="panel-header"><div><span>EDITABLE YAML · REDACTED</span><h2>配置草稿</h2></div><div className="editor-state"><span className={editorDirty ? 'dirty' : draft?.validated ? 'valid' : ''} />{editorDirty ? 'UNSAVED' : draft?.validated ? 'VALIDATED' : draft ? 'SAVED' : 'CURRENT'}</div></div>
        <label className="visually-hidden" htmlFor="config-yaml">可编辑配置 YAML</label>
        <textarea id="config-yaml" className="yaml-editor config-yaml-editor" spellCheck={false} value={yaml} disabled={!canEdit} onChange={(event) => { setYaml(event.target.value); setValidation(null); setDiff(null); setNotice('') }} aria-describedby="config-editor-help" />
        <p className="editor-help" id="config-editor-help">敏感值使用服务端占位符保留。草稿只保存在服务端和当前页面内存，不使用浏览器存储。</p>
        <div className="config-actions">
          <button type="button" className="secondary-button" onClick={() => void refreshState()} disabled={busy}><RefreshCw size={16} className={operation === 'confirm' ? 'spin' : ''} /> 刷新状态</button>
          <button type="button" className="secondary-button" onClick={() => void saveDraft()} disabled={!canEdit || !yaml.trim() || busy}><FileCode2 size={16} /> 保存草稿</button>
          <button type="button" className="secondary-button" onClick={() => void discardDraft()} disabled={!canEdit || !draft || busy}><X size={16} /> 丢弃草稿</button>
          <button type="button" className="secondary-button" onClick={() => void validateDraft()} disabled={!canEdit || !yaml.trim() || busy}><Check size={16} /> 校验草稿</button>
          <button type="button" className="primary-button" onClick={() => void previewDiff()} disabled={!canEdit || !yaml.trim() || busy}><FileCode2 size={16} /> 生成 Diff</button>
        </div>
        {validation && <div className={`validation-box ${validation.valid ? 'ok' : 'bad'}`} role="status"><strong>{validation.valid ? '草稿通过校验' : '草稿校验失败'}</strong>{validation.error && <p>{validation.error}</p>}{validation.problems?.map((problem, index) => <p key={`${problem}-${index}`}>· {problem}</p>)}</div>}
      </div>

      <div className="panel config-diff-panel">
        <div className="panel-header"><div><span>PREVIEW · EXPIRES IN 10 MIN</span><h2>差异预览</h2></div>{diff && <DangerBadge danger={diff.danger} />}</div>
        {diff ? <>
          <DiffSummary diff={diff} />
          <DiffChanges diff={diff} />
          <div className="diff-actions"><button type="button" className={diff.danger === 'normal' ? 'primary-button' : 'danger-button'} onClick={openApplyConfirmation} disabled={!diff.preview_id || diff.changes.length === 0 || editorDirty || busy}><Check size={16} /> Apply（二次确认）</button></div>
        </> : <div className="config-empty"><FileCode2 size={24} /><strong>尚未生成差异</strong><p>保存并校验草稿后生成 Diff，确认将要写入的字段和重启影响。</p></div>}
      </div>
    </div>

    <div className="panel config-history-panel">
      <div className="panel-header"><div><span>REVISION LOG · LATEST 50</span><h2>配置历史</h2></div><span className={`source-badge ${capabilities.history_enabled ? 'good' : 'muted'}`}>{history.length} ENTRIES</span></div>
      {history.length === 0 ? <div className="config-empty"><Undo2 size={24} /><strong>没有配置历史</strong><p>托管配置首次初始化或应用后会在此显示修订记录。</p></div> : <div className="data-table-wrap"><table className="config-history-table"><thead><tr><th>修订</th><th>时间 / 动作</th><th>变更</th><th>操作者 / 原因</th><th>影响</th><th>操作</th></tr></thead><tbody>{history.map((entry) => <tr key={entry.revision}><td><strong>#{entry.revision}</strong><small className="table-subtext">parent #{entry.parent_revision || '—'}</small></td><td><strong>{entry.action.toUpperCase()}</strong><small className="table-subtext">{formatDate(entry.created_at)}</small></td><td>{entry.changed}</td><td>{entry.actor || '—'}<small className="table-subtext" title={entry.reason}>{entry.reason || (entry.rollback_target ? `rollback → #${entry.rollback_target}` : '—')}</small></td><td><DangerBadge danger={entry.danger || 'normal'} />{entry.restart_required && <small className="restart-label">RESTART</small>}</td><td><button type="button" className="table-action" disabled={!capabilities.apply_enabled || entry.revision === currentRevision || busy} onClick={() => void previewRollback(entry)}><Undo2 size={13} /> 回滚预览</button></td></tr>)}</tbody></table></div>}
    </div>

    {confirmation && <ConfirmationModal confirmation={confirmation} submitting={operation === 'confirm'} onSubmit={(reason, phrase) => void submitConfirmation(reason, phrase)} onClose={() => setConfirmation(null)} />}
  </section>
}

function StatusCard({ label, value, detail, tone }: { label: string; value: string; detail: string; tone?: 'good' | 'warning' | 'danger' }) {
  return <article className={`config-status-card ${tone ? `is-${tone}` : ''}`}><span>{label}</span><strong>{value}</strong><small>{detail}</small></article>
}

function CapabilityBadge({ label, enabled }: { label: string; enabled: boolean }) {
  return <span className={`capability-badge ${enabled ? 'enabled' : ''}`}><span />{label}</span>
}

function DangerBadge({ danger }: { danger: string }) {
  return <span className={`danger-badge danger-${danger || 'normal'}`}>{(danger || 'normal').toUpperCase()}</span>
}

function DiffSummary({ diff }: { diff: ConfigDiff }) {
  return <div className="diff-summary"><div><span>BASE</span><strong>#{diff.base_revision}</strong></div><div><span>CHANGES</span><strong>{diff.changes.length}</strong></div><div><span>RESTART</span><strong>{diff.restart_required ? 'YES' : 'NO'}</strong></div></div>
}

function DiffChanges({ diff }: { diff: ConfigDiff }) {
  if (diff.changes.length === 0) return <div className="config-empty compact"><Check size={22} /><strong>没有配置变化</strong><p>当前草稿与已生效配置一致。</p></div>
  return <div className="diff-list">{diff.changes.map((change, index) => <article className={`diff-change danger-border-${change.danger}`} key={`${change.path}-${index}`}><div className="diff-change-heading"><code>{change.path || '(root)'}</code><span>{change.kind}</span></div><div className="diff-values"><DiffValue label="BEFORE" value={change.before} sensitive={change.sensitive} /><DiffValue label="AFTER" value={change.after} sensitive={change.sensitive} /></div><div className="diff-flags"><DangerBadge danger={change.danger} />{change.restart_required && <span className="restart-label">RESTART REQUIRED</span>}{change.sensitive && <span className="sensitive-label">REDACTED</span>}</div></article>)}</div>
}

function DiffValue({ label, value, sensitive }: { label: string; value: unknown; sensitive: boolean }) {
  const display = sensitive ? '••••••••' : value === undefined ? '—' : typeof value === 'string' ? value : JSON.stringify(value, null, 2)
  return <div><span>{label}</span><pre>{display}</pre></div>
}

function ConfirmationModal({ confirmation, submitting, onSubmit, onClose }: {
  confirmation: Confirmation
  submitting: boolean
  onSubmit: (reason: string, phrase: string) => void
  onClose: () => void
}) {
  const [reason, setReason] = useState('')
  const [phrase, setPhrase] = useState('')
  const [acknowledged, setAcknowledged] = useState(false)
  const rollback = confirmation.mode === 'rollback'
  const phraseRequired = Boolean(confirmation.diff.confirmation_phrase)
  const reasonRequired = rollback || confirmation.diff.danger !== 'normal'
  const ready = acknowledged && (!reasonRequired || reason.trim().length > 0) && (!phraseRequired || phrase === confirmation.diff.confirmation_phrase)
  return <div className="modal-scrim"><section className="auth-modal config-confirm-modal" role="dialog" aria-modal="true" aria-labelledby="config-confirm-title"><button type="button" className="modal-close icon-button" aria-label="关闭" onClick={onClose} disabled={submitting}><X size={18} /></button><div className="auth-icon danger-icon"><AlertTriangle size={22} /></div><span className="eyebrow">CONFIG / SECOND CONFIRMATION</span><h2 id="config-confirm-title">{rollback ? `确认回滚到 revision ${confirmation.target.revision}` : '确认应用配置草稿'}</h2><p>该预览基于 revision {confirmation.diff.base_revision}，包含 {confirmation.diff.changes.length} 项变化{confirmation.diff.restart_required ? '，写入后需要重启服务' : ''}。</p><DiffSummary diff={confirmation.diff} /><div className="confirmation-diff"><DiffChanges diff={confirmation.diff} /></div><label className="field"><span>操作原因{reasonRequired ? '（必填）' : '（可选）'}</span><input value={reason} maxLength={256} autoFocus placeholder={rollback ? '说明回滚原因' : '说明本次配置变更'} onChange={(event) => setReason(event.target.value)} /></label>{phraseRequired && <><div className="confirmation-phrase"><span>请输入确认短语</span><code>{confirmation.diff.confirmation_phrase}</code></div><label className="field"><span>CONFIRMATION PHRASE</span><input value={phrase} autoComplete="off" spellCheck={false} placeholder="严格区分大小写" onChange={(event) => setPhrase(event.target.value)} /></label></>}<label className="check-field confirmation-check"><input type="checkbox" checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} /> 我已检查差异并确认执行此操作</label><div className="modal-actions"><button type="button" className="secondary-button" onClick={onClose} disabled={submitting}>取消</button><button type="button" className="danger-button" onClick={() => onSubmit(reason.trim(), phrase)} disabled={!ready || submitting}>{submitting ? <RefreshCw size={16} className="spin" /> : rollback ? <Undo2 size={16} /> : <Check size={16} />} {rollback ? '确认回滚' : '确认 Apply'}</button></div></section></div>
}
