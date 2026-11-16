import { afterEach, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import App from '../src/App'
import type { Asset, Job, Page, Scheduler } from '../src/api'

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

it('真实本机只读 API → React DOM 四区联调；不代表浏览器画面验收', async () => {
  const base = 'http://127.0.0.1:8000'
  const fetchActual = fetch
  const requests: string[] = []
  vi.stubGlobal('fetch', async (path: string, init: RequestInit) => {
    if (init.method !== 'GET' || !path.startsWith('/api/v1/')) throw new Error('联调只允许本机业务 GET')
    requests.push(path)
    return fetchActual(base + path, init)
  })
  const read = async <T,>(path: string): Promise<T> => {
    const response = await fetchActual(base + path)
    expect(response.status).toBe(200)
    return response.json() as Promise<T>
  }
  const assets = await read<Page<Asset>>('/api/v1/assets?limit=200')
  const jobs = await read<Page<Job>>('/api/v1/discovery-jobs?limit=200')
  const scheduler = await read<Scheduler>('/api/v1/scheduler')
  expect(assets.items.length).toBeGreaterThan(0)
  expect(jobs.items.length).toBeGreaterThan(0)

  render(<App />)
  const first = assets.items[0]
  fireEvent.click(await screen.findByRole('button', { name: `查看 ${first.name}` }))
  expect(await screen.findByRole('region', { name: '资产详情' })).toBeTruthy()
  await waitFor(() => expect(requests.some(path => path.includes(`/assets/${first.id}/observations`))).toBe(true))
  // The user previously removed explanatory metric placeholders; keep that preference.
  expect(screen.queryByText(/CPU、内存、进程：未采集/)).toBeNull()
  expect(screen.queryByText(/^CPU.*0%$/)).toBeNull()

  fireEvent.click(screen.getByRole('button', { name: /扫描批次/ }))
  await screen.findByRole('heading', { name: '当次执行结果' })
  const latest = [...jobs.items].sort((a, b) => Date.parse(b.startedAt) - Date.parse(a.startedAt))[0]
  expect((screen.getByLabelText('扫描批次') as HTMLSelectElement).value).toBe(latest.id)
  await screen.findByRole('region', { name: '扫描发现设备' })

  fireEvent.click(screen.getByRole('button', { name: /探测证据/ }))
  await screen.findByRole('region', { name: '探测证据列表' })
  const next = screen.getByRole('button', { name: '下一页' }) as HTMLButtonElement
  expect(next.disabled).toBe(false)
  fireEvent.click(next)
  await waitFor(() => expect(requests.some(path => path.includes('/probes?') && path.includes('cursor='))).toBe(true))

  fireEvent.click(screen.getByRole('button', { name: /每日调度/ }))
  await screen.findByRole('heading', { name: '每日调度状态' })
  if (scheduler.schedule) await screen.findByText(scheduler.schedule.name, { selector: 'dd' })
  expect(screen.queryByRole('button', { name: /立即扫描|保存配置/ })).toBeNull()
  console.log(JSON.stringify({
    evidenceType: 'real_api_dom_not_browser_layout', loadedAssets: assets.items.length,
    loadedJobs: jobs.items.length, latestJobId: latest.id, schedulerTodayStatus: scheduler.todayStatus,
    methods: ['GET'], uiRequestCount: requests.length,
  }))
})
