export type AuthState =
  | { mode: 'none' }
  | { mode: 'token'; token: string }
  | { mode: 'basic'; username: string; password: string }

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

export interface Decision {
  target: string
  status_code: number
  limit_rate: string
  reason: string
  chain: string
  rule_name: string
}

export interface RuleItem {
  name: string
  match: Record<string, unknown>
  target: string
  chain?: string
  status?: number
  limit_rate?: string
  reason?: string
  mark?: string
}

export interface RuleChain {
  name: string
  policy: Decision
  rules: RuleItem[]
}

export interface RuleList {
  risk_control_enabled: boolean
  chains: RuleChain[]
}

export interface RulePreview {
  ok: boolean
  decision?: Decision
  trace?: Array<{
    chain: string
    rule: string
    matched: boolean
    target?: string
    jump_to?: string
  }>
  error?: string
}

export interface TokenRecord {
  id: string
  mode: string
  path: string
  uses: number
  max_uses: number
  expires_at: number
  created_at: number
  updated_at: number
  ip_hint?: string
}

export interface TokenGet {
  found: boolean
  token?: TokenRecord
}

export interface PendingEntry {
  ip: string
  pending: number
  blocked: boolean
  blocked_until?: number
}

export interface PendingList {
  scope: string
  entries: PendingEntry[]
}

export interface AuditEvent {
  timestamp: number
  action: string
  actor: string
  request_id?: string
  ip?: string
  ok: boolean
  detail?: string
}

export interface AuditList {
  available: boolean
  events: AuditEvent[]
  error?: string
}

export interface ConfigGet {
  config: Record<string, unknown>
}

export interface ConfigValidate {
  ok: boolean
  problems?: string[]
  error?: string
}
