import { useCallback, useEffect, useRef, useState } from 'react'
import { AlertTriangle, Check, RefreshCw, Undo2, X } from 'lucide-react'
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
import VisualConfigEditor from './VisualConfigEditor'

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

  if (initializing) return <div className="flex items-center justify-center gap-2 py-16 text-muted-foreground"><RefreshCw size={16} className="animate-spin" /> 加载配置…</div>

  return <section className="space-y-6">
    <div className="grid gap-4 grid-cols-2 xl:grid-cols-4">
      <StatusCard label="MANAGED" value={managed ? 'YES' : 'NO'} tone={managed ? 'good' : 'danger'} />
      <StatusCard label="REVISION" value={currentRevision ? `#${currentRevision}` : '—'} />
      <StatusCard label="PENDING RESTART" value={pendingRestart ? 'YES' : 'NO'} tone={pendingRestart ? 'warning' : 'good'} />
      <StatusCard label="DRAFT" value={draft ? `r${draft.draft_revision}` : 'NONE'} tone={draft?.validated ? 'good' : draft ? 'warning' : undefined} />
    </div>

    <div className="card px-6 py-3 flex flex-wrap items-center gap-2">
      <span className="text-xs text-muted-foreground mr-1">能力</span>
      <CapabilityBadge label="MANAGED" enabled={capabilities.managed} />
      <CapabilityBadge label="MUTATIONS" enabled={capabilities.mutations_enabled} />
      <CapabilityBadge label="APPLY" enabled={capabilities.apply_enabled} />
      <CapabilityBadge label="HISTORY" enabled={capabilities.history_enabled} />
    </div>

    {notice && <div className="card border-warning/40 px-6 py-4 flex items-center gap-3 text-sm" role="alert"><AlertTriangle size={16} className="text-warning flex-none" /><span className="flex-1">{notice}</span><button type="button" className="text-muted-foreground hover:text-foreground" onClick={() => setNotice('')} aria-label="关闭提示"><X size={15} /></button></div>}
    {!canEdit && <div className="card border-warning/40 px-6 py-4 flex items-center gap-3 text-sm"><AlertTriangle size={16} className="text-warning flex-none" /><span className="font-medium">只读模式</span></div>}

    <div className="grid gap-4 xl:grid-cols-2">
      <div className="card flex flex-col">
        <div className="card-header flex items-center justify-between">
          <div className="card-title">配置草稿</div>
          <span className={`badge ${editorDirty ? 'bg-warning-soft text-warning-foreground' : draft?.validated ? 'bg-success-soft text-success-foreground' : 'bg-muted text-muted-foreground'}`}>
            {editorDirty ? 'UNSAVED' : draft?.validated ? 'VALIDATED' : draft ? 'SAVED' : 'CURRENT'}
          </span>
        </div>
        <VisualConfigEditor yamlText={yaml} disabled={!canEdit} onChange={(next) => { setYaml(next); setValidation(null); setDiff(null); setNotice('') }} />
        <div className="flex flex-wrap gap-2 px-6 py-4 border-t border-border mt-auto">
          <button type="button" className="btn-outline" onClick={() => void refreshState()} disabled={busy}><RefreshCw size={15} className={operation === 'confirm' ? 'animate-spin' : ''} /> 刷新</button>
          <button type="button" className="btn-outline" onClick={() => void saveDraft()} disabled={!canEdit || !yaml.trim() || busy}>保存草稿</button>
          <button type="button" className="btn-outline" onClick={() => void discardDraft()} disabled={!canEdit || !draft || busy}>丢弃</button>
          <button type="button" className="btn-outline" onClick={() => void validateDraft()} disabled={!canEdit || !yaml.trim() || busy}>校验</button>
          <button type="button" className="btn-primary" onClick={() => void previewDiff()} disabled={!canEdit || !yaml.trim() || busy}>生成 Diff</button>
        </div>
        {validation && <div className={`mx-6 mb-4 rounded-lg border px-4 py-3 text-sm ${validation.valid ? 'border-success/30 bg-success-soft text-success-foreground' : 'border-destructive/30 bg-destructive-soft text-destructive-foreground'}`} role="status">
          <div className="font-medium">{validation.valid ? '草稿通过校验' : '草稿校验失败'}</div>
          {validation.error && <p className="mt-1 text-xs opacity-80">{validation.error}</p>}
          {validation.problems?.map((problem, index) => <p key={`${problem}-${index}`} className="mt-1 text-xs opacity-80">· {problem}</p>)}
        </div>}
      </div>

      <div className="card">
        <div className="card-header flex items-center justify-between">
          <div className="card-title">差异预览</div>
          {diff && <DangerBadge danger={diff.danger} />}
        </div>
        {diff ? <>
          <DiffSummary diff={diff} />
          <DiffChanges diff={diff} />
          <div className="flex justify-end px-6 py-4"><button type="button" className={diff.danger === 'normal' ? 'btn-primary' : 'btn-danger'} onClick={openApplyConfirmation} disabled={!diff.preview_id || diff.changes.length === 0 || editorDirty || busy}><Check size={15} /> Apply</button></div>
        </> : <EmptyState title="尚未生成差异" />}
      </div>
    </div>

    <div className="card">
      <div className="card-header flex items-center justify-between">
        <div className="card-title">配置历史</div>
        <span className="badge bg-muted text-muted-foreground">{history.length}</span>
      </div>
      {history.length === 0 ? <EmptyState title="暂无记录" /> : (
        <div className="table-wrap !rounded-none !border-x-0 !border-b-0">
          <table className="table"><thead><tr><th>修订</th><th>动作</th><th>变更</th><th>操作者 / 原因</th><th>影响</th><th>操作</th></tr></thead>
          <tbody>{history.map((entry) => (
            <tr key={entry.revision}>
              <td><span className="font-medium">#{entry.revision}</span><span className="block text-xs text-faint-foreground">parent #{entry.parent_revision || '—'}</span></td>
              <td><span className="font-medium">{entry.action.toUpperCase()}</span><span className="block text-xs text-faint-foreground">{formatDate(entry.created_at)}</span></td>
              <td className="tabular-nums">{entry.changed}</td>
              <td>{entry.actor || '—'}<span className="block text-xs text-faint-foreground truncate max-w-48" title={entry.reason}>{entry.reason || (entry.rollback_target ? `rollback → #${entry.rollback_target}` : '—')}</span></td>
              <td><DangerBadge danger={entry.danger || 'normal'} />{entry.restart_required && <span className="block mt-1 text-xs text-warning-foreground">RESTART</span>}</td>
              <td><button type="button" className="btn-outline !px-2.5 !py-1 text-xs" disabled={!capabilities.apply_enabled || entry.revision === currentRevision || busy} onClick={() => void previewRollback(entry)}><Undo2 size={12} /> 回滚</button></td>
            </tr>
          ))}</tbody></table>
        </div>
      )}
    </div>

    {confirmation && <ConfirmationModal confirmation={confirmation} submitting={operation === 'confirm'} onSubmit={(reason, phrase) => void submitConfirmation(reason, phrase)} onClose={() => setConfirmation(null)} />}
  </section>
}

function StatusCard({ label, value, tone }: { label: string; value: string; tone?: 'good' | 'warning' | 'danger' }) {
  const toneCls = tone === 'good' ? 'text-success' : tone === 'warning' ? 'text-warning' : tone === 'danger' ? 'text-destructive' : 'text-foreground'
  return <article className="card px-5 py-4"><span className="text-xs text-muted-foreground">{label}</span><strong className={`block mt-1 text-xl tabular-nums ${toneCls}`}>{value}</strong></article>
}

function CapabilityBadge({ label, enabled }: { label: string; enabled: boolean }) {
  return <span className={`badge ${enabled ? 'bg-success-soft text-success-foreground' : 'bg-muted text-muted-foreground'}`}><span className={`h-1.5 w-1.5 rounded-full ${enabled ? 'bg-success' : 'bg-muted-foreground/40'}`} />{label}</span>
}

const dangerCls: Record<string, string> = {
  normal: 'bg-success-soft text-success-foreground',
  dangerous: 'bg-warning-soft text-warning-foreground',
  critical: 'bg-destructive-soft text-destructive-foreground',
}
const dangerBorder: Record<string, string> = {
  normal: 'border-l-success', dangerous: 'border-l-warning', critical: 'border-l-destructive',
}

function DangerBadge({ danger }: { danger: string }) {
  return <span className={`badge ${dangerCls[danger || 'normal']}`}>{(danger || 'normal').toUpperCase()}</span>
}

function EmptyState({ title }: { title: string }) {
  return <div className="flex flex-col items-center justify-center gap-1 py-16 text-muted-foreground"><p className="text-sm">{title}</p></div>
}

function DiffSummary({ diff }: { diff: ConfigDiff }) {
  return <div className="grid grid-cols-3 gap-px bg-border border-y border-border">
    <div className="bg-surface px-4 py-2.5"><span className="block text-xs text-muted-foreground">BASE</span><span className="font-semibold tabular-nums">#{diff.base_revision}</span></div>
    <div className="bg-surface px-4 py-2.5"><span className="block text-xs text-muted-foreground">CHANGES</span><span className="font-semibold tabular-nums">{diff.changes.length}</span></div>
    <div className="bg-surface px-4 py-2.5"><span className="block text-xs text-muted-foreground">RESTART</span><span className={`font-semibold ${diff.restart_required ? 'text-warning' : ''}`}>{diff.restart_required ? 'YES' : 'NO'}</span></div>
  </div>
}

function DiffChanges({ diff }: { diff: ConfigDiff }) {
  if (diff.changes.length === 0) return <EmptyState title="没有配置变化" />
  return <div className="p-4 space-y-2 max-h-96 overflow-auto">{diff.changes.map((change, index) => (
    <article className={`rounded-lg border border-border border-l-2 ${dangerBorder[change.danger] || 'border-l-border'} bg-surface-secondary px-4 py-3`} key={`${change.path}-${index}`}>
      <div className="flex items-center justify-between gap-3 mb-2">
        <code className="text-xs text-link break-all">{change.path || '(root)'}</code>
        <span className="text-xs text-faint-foreground uppercase">{change.kind}</span>
      </div>
      <div className="grid grid-cols-2 gap-2">
        <DiffValue label="BEFORE" value={change.before} sensitive={change.sensitive} />
        <DiffValue label="AFTER" value={change.after} sensitive={change.sensitive} />
      </div>
      <div className="flex flex-wrap items-center gap-2 mt-2">
        <DangerBadge danger={change.danger} />
        {change.restart_required && <span className="text-xs text-warning-foreground">RESTART</span>}
        {change.sensitive && <span className="text-xs text-muted-foreground">REDACTED</span>}
      </div>
    </article>
  ))}</div>
}

function DiffValue({ label, value, sensitive }: { label: string; value: unknown; sensitive: boolean }) {
  const display = sensitive ? '••••••••' : value === undefined ? '—' : typeof value === 'string' ? value : JSON.stringify(value, null, 2)
  return <div className="rounded-md bg-background px-3 py-2 min-w-0"><span className="block text-[10px] text-faint-foreground tracking-wider">{label}</span><pre className="mt-0.5 text-xs whitespace-pre-wrap break-all font-mono">{display}</pre></div>
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
  return <div className="fixed inset-0 z-50 grid place-items-center p-4 bg-backdrop overflow-y-auto">
    <section className="w-full max-w-2xl rounded-xl border border-border bg-overlay text-overlay-foreground shadow-pop p-6" role="dialog" aria-modal="true" aria-label="确认配置操作">
      <div className="flex items-center gap-2.5 mb-4">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-destructive text-destructive-foreground"><AlertTriangle size={16} /></div>
        <div>
          <div className="font-semibold">{rollback ? `回滚到 revision ${confirmation.target.revision}` : '应用配置草稿'}</div>
          <div className="text-xs text-muted-foreground">基于 revision {confirmation.diff.base_revision}，{confirmation.diff.changes.length} 项变化{confirmation.diff.restart_required ? '，需重启生效' : ''}</div>
        </div>
        <button type="button" className="ml-auto text-muted-foreground hover:text-foreground" onClick={onClose} disabled={submitting} aria-label="关闭"><X size={16} /></button>
      </div>
      <DiffSummary diff={confirmation.diff} />
      <div className="mt-3"><DiffChanges diff={confirmation.diff} /></div>
      <label className="block mt-4 mb-3">
        <span className="block mb-1.5 text-xs font-medium text-muted-foreground">原因{reasonRequired ? '（必填）' : ''}</span>
        <input className="input" value={reason} maxLength={256} autoFocus onChange={(event) => setReason(event.target.value)} />
      </label>
      {phraseRequired && <>
        <div className="flex items-center justify-between rounded-lg border border-destructive/30 bg-destructive-soft px-3 py-2 mb-3 text-sm">
          <span className="text-muted-foreground">确认短语</span>
          <code className="font-mono text-destructive-foreground">{confirmation.diff.confirmation_phrase}</code>
        </div>
        <label className="block mb-3">
          <span className="block mb-1.5 text-xs font-medium text-muted-foreground">输入短语</span>
          <input className="input font-mono" value={phrase} autoComplete="off" spellCheck={false} onChange={(event) => setPhrase(event.target.value)} />
        </label>
      </>}
      <label className="flex items-center gap-2 mb-5 text-sm cursor-pointer">
        <input type="checkbox" className="accent-[var(--primary)]" checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} /> 确认执行
      </label>
      <div className="flex justify-end gap-2">
        <button type="button" className="btn-outline" onClick={onClose} disabled={submitting}>取消</button>
        <button type="button" className="btn-danger" onClick={() => onSubmit(reason.trim(), phrase)} disabled={!ready || submitting}>{submitting ? <RefreshCw size={15} className="animate-spin" /> : rollback ? <Undo2 size={15} /> : <Check size={15} />} {rollback ? '确认回滚' : '确认 Apply'}</button>
      </div>
    </section>
  </div>
}
