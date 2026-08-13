export function formatNumber(value: number): string {
  return new Intl.NumberFormat('zh-CN', { maximumFractionDigits: 2 }).format(value)
}

export function formatDate(unix?: number): string {
  if (!unix) return '—'
  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false,
  }).format(new Date(unix * 1000))
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds} 秒`
  if (seconds < 3600) return `${Math.round(seconds / 60)} 分钟`
  if (seconds < 86400) return `${Math.round(seconds / 3600)} 小时`
  return `${Math.round(seconds / 86400)} 天`
}

export function stringify(value: unknown): string {
  return JSON.stringify(value, null, 2)
}

export function shortCommit(commit: string): string {
  return commit && commit !== 'none' ? commit.slice(0, 8) : '未注入'
}
