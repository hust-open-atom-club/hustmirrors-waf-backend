import type { AuthState, StandardResponse } from './types'

export class AuthRequiredError extends Error {
  constructor() {
    super('需要管理员凭据')
    this.name = 'AuthRequiredError'
  }
}

export class RPCError extends Error {
  readonly status: number
  readonly requestID?: string

  constructor(message: string, status: number, requestID?: string) {
    super(message)
    this.name = 'RPCError'
    this.status = status
    this.requestID = requestID
  }
}

function authorization(auth: AuthState): string | undefined {
  if (auth.mode === 'token') {
    return `Bearer ${auth.token}`
  }
  if (auth.mode === 'basic') {
    const bytes = new TextEncoder().encode(`${auth.username}:${auth.password}`)
    let binary = ''
    for (const byte of bytes) binary += String.fromCharCode(byte)
    return `Basic ${btoa(binary)}`
  }
  return undefined
}

export async function rpc<TResponse, TRequest extends object = Record<string, unknown>>(
  action: string,
  body: TRequest,
  auth: AuthState,
  signal?: AbortSignal,
): Promise<TResponse> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  const authHeader = authorization(auth)
  if (authHeader) headers.Authorization = authHeader

  const response = await fetch(`/admin/api/${action}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
    credentials: 'same-origin',
    signal,
  })

  if (response.status === 401) throw new AuthRequiredError()

  let payload: StandardResponse<TResponse> | { error?: string }
  try {
    payload = await response.json()
  } catch {
    throw new RPCError(`后台返回了不可解析的响应（HTTP ${response.status}）`, response.status)
  }

  if (!response.ok) {
    const message = 'message' in payload && payload.message
      ? payload.message
      : 'error' in payload && payload.error
        ? payload.error
        : `请求失败（HTTP ${response.status}）`
    throw new RPCError(message, response.status, 'request_id' in payload ? payload.request_id : undefined)
  }

  const envelope = payload as StandardResponse<TResponse>
  if (!envelope.ok || envelope.data === undefined) {
    throw new RPCError(envelope.message || '后台未返回数据', response.status, envelope.request_id)
  }
  return envelope.data
}
