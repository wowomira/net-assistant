import type { components } from './api-schema'

type Schema = components['schemas']
export type Asset = Schema['AssetView']
export type Observation = Schema['LinkedObservationView']
export type Audit = Schema['AssetAuditView']
export type Job = Schema['JobView']
export type Host = Schema['HostView']
export type Probe = Schema['ProbeView']
export type Association = Schema['AssociationView']
export type Scheduler = Schema['SchedulerView']
export type ScheduledRun = Schema['ScheduledRunView']
export type Comparison = Schema['ComparisonView']
export interface Page<T> { items: T[]; nextCursor: string | null }
export interface Catalog<T> { items: T[]; complete: boolean }

export class ApiError extends Error {
  constructor(message: string, public status = 0, public code = 'request_failed', public requestId = '') {
    super(message)
    this.name = 'ApiError'
  }
}
export async function getJson<T>(path: string, signal?: AbortSignal): Promise<T> {
  if (!path.startsWith('/') || path.startsWith('//') || path.includes('://') || path.includes('..')) {
    throw new ApiError('只允许读取本机 /api/v1 接口')
  }
  const controller = new AbortController()
  const abort = () => controller.abort()
  signal?.addEventListener('abort', abort, { once: true })
  if (signal?.aborted) controller.abort()
  let timedOut = false
  const timer = setTimeout(() => { timedOut = true; controller.abort() }, 15_000)
  try {
    const response = await fetch(`/api/v1${path}`, {
      method: 'GET', cache: 'no-store', signal: controller.signal, headers: { Accept: 'application/json' },
    })
    const payload = await response.json().catch(() => null)
    if (!response.ok) {
      throw new ApiError(payload?.message || `读取失败（HTTP ${response.status}）`, response.status,
        payload?.code || 'http_error', payload?.requestId || response.headers.get('X-Request-ID') || '')
    }
    if (payload === null) throw new ApiError('接口没有返回有效 JSON', response.status, 'invalid_response')
    return payload as T
  } catch (error) {
    if (timedOut) throw new ApiError('读取超时，请确认 API 是否运行后重试', 0, 'request_timeout')
    if (error instanceof ApiError || controller.signal.aborted) throw error
    throw new ApiError('无法连接后端', 0, 'network_error')
  } finally {
    clearTimeout(timer)
    signal?.removeEventListener('abort', abort)
  }
}
export function withQuery(path: string, query: Record<string, string | null | undefined>): string {
  const [pathname, search = ''] = path.split('?')
  const params = new URLSearchParams(search)
  Object.entries(query).forEach(([key, value]) => {
    if (value != null && value !== '') params.set(key, value)
  })
  return `${pathname}?${params}`
}
export async function getPage<T>(path: string, signal?: AbortSignal): Promise<Page<T>> {
  const page = await getJson<Page<T>>(path, signal)
  if (!Array.isArray(page.items) || !(page.nextCursor === null || typeof page.nextCursor === 'string')) {
    throw new ApiError('接口分页数据不符合约定', 0, 'invalid_page')
  }
  return page
}
export async function readCatalog<T>(path: string, signal?: AbortSignal, maxPages = 20): Promise<Catalog<T>> {
  const items: T[] = []
  const seen = new Set<string>()
  let cursor: string | null = null
  for (let index = 0; index < maxPages; index++) {
    const page: Page<T> = await getPage<T>(withQuery(path, { limit: '200', cursor }), signal)
    items.push(...page.items)
    if (page.nextCursor === null) return { items, complete: true }
    if (seen.has(page.nextCursor)) throw new ApiError('分页游标重复，请核对接口', 0, 'cursor_repeated')
    seen.add(page.nextCursor)
    cursor = page.nextCursor
  }
  return { items, complete: false }
}
