export type Tone = 'good' | 'warn' | 'bad' | 'neutral'
const statuses: Record<string, [string, Tone]> = {
  completed: ['执行完成', 'good'], running: ['运行中', 'neutral'],
  partial: ['部分完成', 'warn'], failed: ['执行失败', 'bad'], interrupted: ['已中断', 'warn'],
  manual: ['手动触发', 'neutral'], scheduled: ['每日自动', 'neutral'],
  automatic: ['自动登记', 'good'], managed: ['纳入管理', 'neutral'], discovered: ['发现资产', 'neutral'],
  manual_confirmed: ['人工确认关联', 'neutral'], observed_mac: ['观测到 MAC', 'neutral'],
  mac_correlated: ['MAC 历史关联', 'neutral'], needs_review: ['待核验', 'warn'],
  not_enrolled: ['未接入采集', 'neutral'], not_collected: ['未采集', 'neutral'],
  direct_response: ['直接响应', 'good'], candidate_only: ['仅候选线索', 'warn'],
  linked: ['已关联档案', 'neutral'], unlinked: ['未关联档案', 'warn'],
  reply: ['收到响应', 'good'], resolved: ['地址已解析', 'neutral'], open: ['端口开放', 'good'],
  timeout: ['超时', 'warn'], refused: ['连接被拒绝', 'neutral'],
  no_response: ['未收到响应', 'neutral'], error: ['发生错误', 'bad'],
  response: ['收到 HTTP 响应', 'neutral'], verified: ['TLS 校验通过', 'good'],
  certificate_error: ['证书校验失败', 'bad'], unreachable: ['网络 / 主机不可达', 'warn'],
  not_applicable: ['不适用于当前连接', 'neutral'], received: ['收到服务文本', 'neutral'],
  empty: ['未收到服务文本', 'neutral'],
  not_supported: ['当前不支持', 'neutral'], skipped: ['已跳过', 'neutral'],
  stale: ['心跳过期', 'warn'], checking: ['正在判断到期 / 执行', 'neutral'],
  stopped: ['已停止', 'warn'], unknown: ['未知', 'neutral'],
  available: ['可读取', 'good'], unavailable: ['不可读取', 'bad'],
  missing: ['尚不存在', 'warn'], not_checked: ['未检查', 'neutral'],
  unconfigured: ['未配置', 'neutral'], disabled: ['已停用', 'neutral'],
  not_due: ['尚未到期', 'neutral'], pending: ['到期待执行', 'warn'],
  already_attempted: ['今日已尝试', 'neutral'], busy: ['扫描锁忙', 'warn'],
  invocation_failed: ['启动调用失败', 'bad'],
  observed: ['协议响应识别', 'neutral'], captured: ['已采集截图', 'neutral'],
  not_requested: ['未启用截图', 'neutral'], blocked: ['已阻止采集', 'warn'],
}
export function statusInfo(status: string): { label: string; tone: Tone } {
  const pair = Object.hasOwn(statuses, status) ? statuses[status] : null
  return pair ? { label: pair[0], tone: pair[1] } : { label: `未知 · ${status}`, tone: 'neutral' }
}
export function formatTime(value: string | null | undefined): string {
  if (!value) return '暂无记录'
  const time = new Date(value)
  if (Number.isNaN(time.getTime())) return '时间不可解析'
  return new Intl.DateTimeFormat('sv-SE', {
    timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
  }).format(time)
}
export function newestFirst<T extends { startedAt: string }>(items: T[]): T[] {
  return [...items].sort((a, b) => Date.parse(b.startedAt) - Date.parse(a.startedAt))
}
export function isStale(readAt: number | null, now: number): boolean {
  return readAt !== null && now - readAt > 60_000
}
