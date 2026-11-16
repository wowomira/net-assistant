import { useEffect, useRef, useState, type ReactNode } from 'react'
import { ApiError, type Catalog } from './api'
import { formatTime, isStale, statusInfo } from './model'

export interface Resource<T> {
  key: string | null
  data: T | null
  loading: boolean
  error: Error | null
  readAt: number | null
}

/** Keep failed refreshes visibly stale; discard completions for a previous selection. */
export function useRead<T>(key: string | null, version: number,
  load: (signal: AbortSignal) => Promise<T>): Resource<T> {
  const loader = useRef(load)
  loader.current = load
  const [value, setValue] = useState<Resource<T>>({
    key: null, data: null, loading: false, error: null, readAt: null,
  })
  useEffect(() => {
    if (key === null) return
    const controller = new AbortController()
    let active = true
    setValue(previous => ({
      key, data: previous.key === key ? previous.data : null, loading: true,
      error: null, readAt: previous.key === key ? previous.readAt : null,
    }))
    loader.current(controller.signal).then(data => {
      if (active) setValue({ key, data, loading: false, error: null, readAt: Date.now() })
    }).catch(error => {
      if (active) setValue(previous => ({
        ...previous, loading: false, error: error instanceof Error ? error : new Error('读取失败'),
      }))
    })
    return () => { active = false; controller.abort() }
  }, [key, version])
  return value.key === key ? value : { key, data: null, loading: key !== null, error: null, readAt: null }
}

export function ReadState<T>({ value }: { value: Resource<T> }) {
  const [now, setNow] = useState(Date.now())
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 15_000)
    return () => clearInterval(timer)
  }, [])
  return <div className="read-state">
    {value.loading && <p role="status">读取中…</p>}
    {value.error && <div className="error-box" role="alert">
      <strong>读取失败：{value.error.message}</strong>
      {value.error instanceof ApiError && <small>错误码：{value.error.code}
        {value.error.requestId && <> · 请求编号：{value.error.requestId}</>}</small>}
      {value.data !== null && <p>保留上次读取的数据。</p>}
    </div>}
    {value.readAt !== null && <p className="muted tiny">本区读取于 {formatTime(new Date(value.readAt).toISOString())}
      {isStale(value.readAt, now) && <strong className="stale"> · 已超过 1 分钟，可能过期，请刷新</strong>}</p>}
  </div>
}
export function Badge({ value }: { value: string }) {
  const info = statusInfo(value)
  return <span className={`badge ${info.tone}`}>{info.label}</span>
}
export function Panel({ title, eyebrow, children, action }: {
  title: string; eyebrow?: string; children: ReactNode; action?: ReactNode
}) {
  return <section className="panel">
    <div className="panel-heading"><div>{eyebrow && <p className="eyebrow">{eyebrow}</p>}<h2>{title}</h2></div>{action}</div>
    {children}
  </section>
}
export function Facts({ rows }: { rows: [string, ReactNode][] }) {
  return <dl className="facts">{rows.map(([key, value]) => <div key={key}>
    <dt>{key}</dt><dd>{value ?? '暂无'}</dd>
  </div>)}</dl>
}
export function Raw({ value, label = '查看原始数据' }: { value: unknown; label?: string }) {
  return <details className="raw"><summary>{label}</summary><pre>{JSON.stringify(value, null, 2)}</pre></details>
}
export function CatalogNote<T>({ catalog }: { catalog: Catalog<T> }) {
  return <p className="muted tiny">已加载 {catalog.items.length} 条
    {catalog.complete ? '' : ' · 未读完'}</p>
}
export function Table({ children, label }: { children: ReactNode; label: string }) {
  return <div className="table-wrap" role="region" aria-label={label} tabIndex={0}>
    <table>{children}</table>
  </div>
}
export function Empty({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>
}
