export type AuthState =
  | { mode: 'none' }
  | { mode: 'token'; token: string }

export interface StandardResponse<T> {
  ok: boolean
  code: string
  message?: string
  data?: T
  request_id?: string
}

export interface SourceStatus {
  name: string
  status: 'ok' | 'configured' | 'disabled' | 'error' | string
  detail?: string
  latency_ms?: number
}

export interface DashboardSummary {
  available: boolean
  window: string
  metrics: {
    pow_verify_total: number
    pow_allowed_total: number
    pow_denied_total: number
    risk_decision_total: number
    active_signatures: number
  }
  sources: SourceStatus[]
}

export interface DashboardSeries {
  available: boolean
  metric: string
  points: Array<{ timestamp: number; value: number }>
  error?: string
}

export interface SystemInfo {
  version: string
  commit: string
  build_time: string
  go_version: string
}

export interface SystemHealth {
  ok: boolean
  components: SourceStatus[]
}

export interface AuditEvent {
  timestamp: number
  action: string
  actor: string
  request_id?: string
  ip?: string
  target?: string
  source?: string
  reason?: string
  code?: string
  ttl_seconds?: number
  revision?: number
  change_count?: number
  danger?: string
  restart_required?: boolean
  ok: boolean
  detail?: string
}

export interface AuditList {
  available: boolean
  events: AuditEvent[]
  error?: string
}

export interface ConfigCapabilities {
  managed: boolean
  mutations_enabled: boolean
  apply_enabled: boolean
  history_enabled: boolean
}

export interface ConfigDraftSummary {
  id: string
  revision: number
  base_revision: number
  updated_at: number
  validated: boolean
}

export interface ConfigGet {
  config: Record<string, unknown>
  editable_yaml?: string
  managed: boolean
  current_revision?: number
  pending_restart: boolean
  capabilities: ConfigCapabilities
}

export interface ConfigStatus {
  managed: boolean
  current_revision?: number
  pending_restart: boolean
  draft?: ConfigDraftSummary
  capabilities: ConfigCapabilities
}

export interface ConfigDraft {
  draft_id: string
  draft_revision: number
  base_revision: number
  updated_at: number
  config_yaml: string
  validated: boolean
}

export interface ConfigValidate {
  ok: boolean
  valid: boolean
  problems?: string[]
  error?: string
  draft_id?: string
  draft_revision?: number
  restart_required: boolean
}

export interface ConfigDiffChange {
  path: string
  kind: string
  before?: unknown
  after?: unknown
  sensitive: boolean
  danger: string
  restart_required: boolean
}

export interface ConfigDiff {
  preview_id: string
  base_revision: number
  candidate_revision?: number
  changes: ConfigDiffChange[]
  danger: string
  restart_required: boolean
  confirmation_phrase?: string
}

export interface ConfigApply {
  previous_revision: number
  revision: number
  change_count: number
  danger: string
  runtime_applied: boolean
  restart_required: boolean
}

export interface ConfigHistoryEntry {
  revision: number
  parent_revision?: number
  action: string
  actor?: string
  reason?: string
  rollback_target?: number
  changed: number
  danger?: string
  restart_required: boolean
  created_at: number
}

export interface ConfigHistory {
  entries: ConfigHistoryEntry[]
}
