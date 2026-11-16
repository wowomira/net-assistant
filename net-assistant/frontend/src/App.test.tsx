import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import App from './App'
import type { Asset, Job } from './api'

// Isolated UI fixtures only. Never imported by the entry point or written to the real DB.
const asset: Asset = {
  id: 'asset-test', scopeId: 'lab', name: '隔离测试资产', assetKind: 'server', owner: null,
  notes: '', revision: 1, createdAt: '2026-11-15T01:00:00Z', updatedAt: '2026-11-15T01:00:00Z',
  managementStatus: 'managed', registrationSource: 'manual', identityStatus: 'manual_confirmed',
  identityVerified: false, collectionAccess: 'not_enrolled', hostMetrics: null,
  hostMetricsStatus: 'not_collected', linkedObservationCount: 1, lastObservedAt: '2026-11-15T01:00:00Z',
}
const job: Job = {
  id: 'job-test', scopeId: 'lab', scopeRevision: 1, state: 'completed',
  startedAt: '2026-11-15T01:00:00Z', finishedAt: '2026-11-15T01:01:00Z',
  configSnapshot: { targets: ['192.168.193.0/24'], ports: [80, 445] },
  coverage: { candidateAddresses: 251, responsiveHosts: 1, completedTcpChecks: 2, expectedTcpChecks: 2 },
  errorCode: null, trigger: 'scheduled', scheduleRunId: 'run-test',
}
const observation = {
  id: 'link-test', assetId: asset.id, discoveryHostId: 'host-test', jobId: job.id,
  scopeId: 'lab', address: '192.168.193.141', mac: '00:0C:29:11:22:33',
  observedAt: '2026-11-15T01:00:00Z', confirmedAt: '2026-11-15T01:01:00Z',
  confidence: 'direct_response', reason: 'test', actor: 'automatic_discovery',
}
function fakeApi(override?: (path: string) => Response | Promise<Response> | undefined) {
  const requests: { path: string; method?: string }[] = []
  vi.stubGlobal('fetch', async (input: string, init: RequestInit) => {
    const url = new URL(input, 'http://test')
    requests.push({ path: url.pathname + url.search, method: init.method })
    const special = override?.(url.pathname)
    if (special) return special
    let payload: unknown = { items: [], nextCursor: null }
    if (url.pathname === '/api/v1/assets') payload = { items: [asset], nextCursor: null }
    if (url.pathname === '/api/v1/discovery-jobs') payload = { items: [
      { ...job, id: 'older-job', startedAt: '2026-11-14T00:00:00Z' }, job,
    ], nextCursor: null }
    if (url.pathname.endsWith('/observations')) payload = { items: [observation], nextCursor: null }
    if (url.pathname.endsWith('/scheduler')) payload = {
      configured: false, checkedAt: '2026-11-15T01:00:00Z', schedule: null,
      worker: { state: 'unknown', heartbeatAt: null }, database: { state: 'not_checked' },
      todayStatus: 'unconfigured', latestRun: null, todayRun: null, capabilities: {},
    }
    if (url.pathname.endsWith('/hosts')) payload = { items: [{
      id: 'host-test', jobId: job.id, address: observation.address, mac: observation.mac,
      confidence: 'direct_response', discoveryMethods: ['icmp'], openPorts: [445], context: {},
      observedAt: observation.observedAt, assetId: asset.id, associationStatus: 'linked',
    }], nextCursor: null }
    if (url.pathname.endsWith('/probes')) payload = {
      items: [{ id: 'probe-test', jobId: job.id, address: observation.address, phase: 'discovery',
        method: 'icmp', port: null, status: 'reply', durationMs: 3, reasonCode: null,
        observedAt: observation.observedAt, evidence: { message: '<img src=x onerror=alert(1)>' } }],
      nextCursor: url.searchParams.has('cursor') ? null : '50',
    }
    return new Response(JSON.stringify(payload))
  })
  return requests
}
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

describe('最小工作台真实读取语义（隔离响应）', () => {
  it('临时Demo只保留数据，不再展示解释型侧栏、项目能力介绍与长篇开场', async () => {
    fakeApi()
    const { container } = render(<App />)
    expect(await screen.findByRole('button', { name: '查看 隔离测试资产' })).toBeTruthy()
    expect(screen.queryByText('临时数据 Demo')).toBeNull()
    expect(screen.queryByText(/实际 API 返回/)).toBeNull()
    expect(screen.queryByText(/刷新只读取已有数据/)).toBeNull()
    expect(container.querySelector('aside')).toBeNull()
    expect(screen.queryByText(/一台设备的管理档案有独立编号/)).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: /每日调度/ }))
    expect(screen.queryByRole('heading', { name: '目前的能力边界' })).toBeNull()
  })
  it('显示登记来源和观测历史，不伪造主机指标；刷新只有GET', async () => {
    const requests = fakeApi()
    render(<App />)
    fireEvent.click(await screen.findByRole('button', { name: '查看 隔离测试资产' }))
    expect(await screen.findByText('192.168.193.141')).toBeTruthy()
    expect(screen.getAllByText('人工登记').length).toBeGreaterThan(0)
    expect(screen.queryByText(/CPU、内存、进程：未采集/)).toBeNull()
    expect(screen.queryByText(/0%/)).toBeNull()
    const before = requests.length
    fireEvent.click(screen.getByRole('button', { name: '刷新数据' }))
    await waitFor(() => expect(requests.length).toBeGreaterThan(before))
    expect(requests.every(r => r.method === 'GET')).toBe(true)
    expect(screen.queryByRole('button', { name: /开始扫描|立即扫描/ })).toBeNull()
  })
  it('扫描默认选最新的记录，证据支持分页且恶意文本不渲染HTML', async () => {
    fakeApi()
    const { container } = render(<App />)
    await screen.findByRole('button', { name: '查看 隔离测试资产' })
    fireEvent.click(screen.getByRole('button', { name: /探测证据/ }))
    const selector = await screen.findByLabelText('扫描批次')
    expect((selector as HTMLSelectElement).value).toBe('job-test')
    expect(await screen.findByText(/192.168.193.141/)).toBeTruthy()
    const next = await screen.findByRole('button', { name: '下一页' })
    await waitFor(() => expect((next as HTMLButtonElement).disabled).toBe(false))
    fireEvent.click(screen.getByText('展开原始证据'))
    expect(screen.getByText(/<img src=x onerror=alert\(1\)>/)).toBeTruthy()
    expect(container.querySelector('img')).toBeNull()
    fireEvent.click(next)
    await waitFor(() => expect((screen.getByRole('button', { name: '下一页' }) as HTMLButtonElement).disabled).toBe(true))
    expect((screen.getByRole('button', { name: '上一页' }) as HTMLButtonElement).disabled).toBe(false)
  })
  it('资产API失败显示错误及请求编号，不显示为没有资产，调度仍可独立阅读', async () => {
    fakeApi(path => path === '/api/v1/assets' ? new Response(JSON.stringify({
      message: '隔离测试库不可读', code: 'database_unavailable', requestId: 'req-ui-test',
    }), { status: 503 }) : undefined)
    render(<App />)
    expect(await screen.findByText(/隔离测试库不可读/)).toBeTruthy()
    expect(screen.getByText(/req-ui-test/)).toBeTruthy()
    expect(screen.queryByText('暂无资产档案')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: /每日调度/ }))
    expect(await screen.findByText('未配置每日计划')).toBeTruthy()
  })
  it('刷新失败保留并明确标记旧资料，不把失败当最新成功', async () => {
    let fail = false
    fakeApi(path => fail && path === '/api/v1/assets' ? new Response(JSON.stringify({
      message: '刷新测试失败', code: 'test_failed', requestId: 'refresh-test',
    }), { status: 503 }) : undefined)
    render(<App />)
    await screen.findByRole('button', { name: '查看 隔离测试资产' })
    fail = true
    fireEvent.click(screen.getByRole('button', { name: '刷新数据' }))
    expect(await screen.findByText(/刷新测试失败/)).toBeTruthy()
    expect(screen.getByText(/保留上次读取/)).toBeTruthy()
    expect(screen.getByRole('button', { name: '查看 隔离测试资产' })).toBeTruthy()
  })
  it('切换资产时旧请求晚到不会覆盖新资产历史', async () => {
    let finishOld: ((response: Response) => void) | undefined
    fakeApi(path => {
      if (path === '/api/v1/assets') return new Response(JSON.stringify({
        items: [asset, { ...asset, id: 'second-asset', name: '第二测试资产' }], nextCursor: null,
      }))
      if (path === '/api/v1/assets/asset-test/observations') {
        return new Promise<Response>(resolve => { finishOld = resolve })
      }
      if (path === '/api/v1/assets/second-asset/observations') return new Response(JSON.stringify({
        items: [{ ...observation, id: 'second-link', address: '192.168.193.147' }], nextCursor: null,
      }))
    })
    render(<App />)
    fireEvent.click(await screen.findByRole('button', { name: '查看 隔离测试资产' }))
    await waitFor(() => expect(finishOld).toBeDefined())
    fireEvent.click(screen.getByRole('button', { name: '查看 第二测试资产' }))
    expect(await screen.findByText('192.168.193.147')).toBeTruthy()
    finishOld!(new Response(JSON.stringify({ items: [observation], nextCursor: null })))
    await new Promise(resolve => setTimeout(resolve, 20))
    const detail = screen.getByRole('region', { name: '资产详情' })
    expect(within(detail).queryByText('192.168.193.141')).toBeNull()
    expect(within(detail).getByText('192.168.193.147')).toBeTruthy()
  })
  it('应用筛选重置分页，修改输入但未应用时不偷换查询条件', async () => {
    const requests = fakeApi()
    render(<App />)
    await screen.findByRole('button', { name: '查看 隔离测试资产' })
    fireEvent.click(screen.getByRole('button', { name: /探测证据/ }))
    const next = await screen.findByRole('button', { name: '下一页' })
    await waitFor(() => expect((next as HTMLButtonElement).disabled).toBe(false))
    fireEvent.click(next)
    await waitFor(() => expect((screen.getByRole('button', { name: '上一页' }) as HTMLButtonElement).disabled).toBe(false))
    const before = requests.length
    fireEvent.change(screen.getByLabelText('当次 IP'), { target: { value: '192.168.193.147' } })
    expect(requests.length).toBe(before)
    fireEvent.click(screen.getByRole('button', { name: '应用筛选' }))
    await waitFor(() => expect((screen.getByRole('button', { name: '上一页' }) as HTMLButtonElement).disabled).toBe(true))
    expect(await screen.findByText(/当前生效：IP 192.168.193.147/)).toBeTruthy()
    expect(requests.some(row => row.path.includes('address=192.168.193.147') && !row.path.includes('cursor='))).toBe(true)
  })
  it('键盘可跳过导航并用Enter切换区块（DOM交互，不代替真实浏览器验收）', async () => {
    fakeApi()
    const user = userEvent.setup()
    render(<App />)
    await screen.findByRole('button', { name: '查看 隔离测试资产' })
    await user.tab()
    expect(document.activeElement).toBe(screen.getByRole('link', { name: '跳到主要内容' }))
    await user.tab()
    expect(document.activeElement).toBe(screen.getByRole('button', { name: '刷新数据' }))
    await user.tab()
    expect(document.activeElement).toBe(screen.getByRole('button', { name: /资产台账/ }))
    await user.tab()
    await user.keyboard('{Enter}')
    expect(screen.getByRole('button', { name: /扫描批次/ }).getAttribute('aria-current')).toBe('page')
    expect(screen.getByRole('heading', { level: 1 }).textContent).toContain('扫描批次')
  })
  it('扫描页读取后端比对结果，不在前端预设变化数据', async () => {
    const requests = fakeApi(path => path.endsWith('/comparison') ? new Response(JSON.stringify({
      status: 'available', reasonCode: null, baselineJobId: 'actual-baseline',
      addedAddresses: ['10.46.8.91'], notObservedAddresses: ['10.46.8.92'],
      macChanges: [],
      probeChanges: [{
        address: '10.46.8.93', phase: 'inventory', method: 'tcp', port: 8443,
        before: { status: 'open', evidence: {} }, after: { status: 'timeout', evidence: {} },
      }],
    })) : undefined)
    render(<App />)
    await screen.findByRole('button', { name: '查看 隔离测试资产' })
    fireEvent.click(screen.getByRole('button', { name: '扫描批次' }))
    const table = await screen.findByRole('region', { name: '探测变化' })
    expect(within(table).getByText('10.46.8.93')).toBeTruthy()
    expect(within(table).getByText('8443')).toBeTruthy()
    expect(within(table).getByText('超时')).toBeTruthy()
    expect(screen.getByText('actual-baseline')).toBeTruthy()
    expect(screen.getByText('10.46.8.91')).toBeTruthy()
    expect(requests.some(r => r.path.endsWith('/comparison'))).toBe(true)
  })
  it('ARP缓存解析不能显示成直接响应成功', async () => {
    fakeApi(path => path.endsWith('/probes') ? new Response(JSON.stringify({
      items: [{
        id: 'arp-cache', jobId: 'job-test', address: '10.46.8.10', phase: 'discovery',
        method: 'arp', port: null, status: 'resolved', durationMs: 2, reasonCode: null,
        observedAt: '2026-11-15T01:00:00Z', evidence: { cachePossible: true },
      }], nextCursor: null,
    })) : undefined)
    render(<App />)
    await screen.findByRole('button', { name: '查看 隔离测试资产' })
    fireEvent.click(screen.getByRole('button', { name: '探测证据' }))
    const badge = await screen.findByText('地址已解析')
    expect(badge.className).not.toContain('good')
  })
  it('扫描结果显示网络名、服务和网站，通过本机截图入口预览而不嵌入原站', async () => {
    fakeApi(path => path.endsWith('/hosts') ? new Response(JSON.stringify({
      items: [{
        id: 'host-inventory', jobId: job.id, address: '10.5.8.12', mac: null,
        hostname: 'inventory-host.test', hostnameSource: 'system_reverse_lookup',
        nameStatus: 'resolved', macStatus: 'not_applicable',
        confidence: 'direct_response', discoveryMethods: ['tcp:open'], openPorts: [22, 8080],
        observedAt: observation.observedAt, assetId: null, associationStatus: 'unlinked',
        portScan: { scope: 'configured', planned: 3, attempted: 3, open: 2,
          refused: 0, timeout: 1, unreachable: 0, error: 0, unattempted: 0, complete: true },
        services: [{ port: 22, transport: 'tcp', protocol: 'ssh', product: 'OpenSSH',
          version: '9.6p1', identification: 'observed', portHint: 'ssh', evidenceMethods: ['banner'] }],
        websites: [{
          url: 'http://10.5.8.12:8080/', scheme: 'http', port: 8080, status: 'response',
          statusCode: 503, title: 'Inventory maintenance', server: 'nginx/1.26.2',
          redirectLocation: null, tlsStatus: 'not_checked', durationMs: 15,
          observedAt: observation.observedAt,
          screenshot: { status: 'captured', capturedAt: observation.observedAt,
            probeId: 'screenshot-test', reasonCode: null },
        }],
      }], nextCursor: null,
    })) : undefined)
    const { container } = render(<App />)
    await screen.findByRole('button', { name: '查看 隔离测试资产' })
    fireEvent.click(screen.getByRole('button', { name: '扫描批次' }))
    expect(await screen.findByText('inventory-host.test')).toBeTruthy()
    fireEvent.click(screen.getByText(/服务与网站/))
    expect(screen.getByText('OpenSSH')).toBeTruthy()
    expect(screen.getByText('Inventory maintenance')).toBeTruthy()
    const link = screen.getByRole('link', { name: '打开原站' })
    expect(link.getAttribute('href')).toBe('http://10.5.8.12:8080/')
    expect(link.getAttribute('rel')).toContain('noopener')
    expect(container.querySelector('iframe')).toBeNull()
    expect(container.querySelector('img')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: '预览截图' }))
    const image = screen.getByRole('img', { name: /Inventory maintenance.*截图/ })
    expect(image.getAttribute('src')).toBe('/api/v1/discovery-jobs/job-test/screenshots/screenshot-test')
    expect(screen.getByText(/静态首屏/)).toBeTruthy()
  })
  it('网页入口拒绝脚本URL，缺少截图时不伪造预览', async () => {
    fakeApi(path => path.endsWith('/hosts') ? new Response(JSON.stringify({
      items: [{
        id: 'host-unsafe', jobId: job.id, address: '10.5.8.12', mac: null,
        confidence: 'direct_response', discoveryMethods: ['tcp:open'], openPorts: [8080],
        observedAt: observation.observedAt, assetId: null, associationStatus: 'unlinked',
        websites: [{ url: 'javascript:alert(1)', scheme: 'http', port: 8080, status: 'error',
          title: '<img src=x onerror=alert(1)>', statusCode: null, server: null,
          redirectLocation: null, tlsStatus: 'not_checked', observedAt: observation.observedAt,
          screenshot: { status: 'not_supported', capturedAt: null, probeId: null,
            reasonCode: 'screenshot_dependency_missing' } }],
      }], nextCursor: null,
    })) : undefined)
    const { container } = render(<App />)
    await screen.findByRole('button', { name: '查看 隔离测试资产' })
    fireEvent.click(screen.getByRole('button', { name: '扫描批次' }))
    fireEvent.click(await screen.findByText(/服务与网站/))
    expect(screen.queryByRole('link', { name: '打开原站' })).toBeNull()
    expect(screen.queryByRole('button', { name: '预览截图' })).toBeNull()
    expect(screen.getByText('screenshot_dependency_missing')).toBeTruthy()
    expect(container.querySelector('img')).toBeNull()
  })
})
