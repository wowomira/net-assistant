import { afterEach, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { SwitchesView } from './SwitchesView'

// Isolated UI fixtures, never used as production fallbacks.
const snapshot = {
  source: 'snmpv3_readonly', observedAt: '2026-11-16T00:00:00Z',
  system: { name: '<img src=x onerror=alert(1)>', objectId: '1.3.6.1.4.1.4881.1',
    description: 'isolated switch', uptimeSeconds: 100 },
  capabilities: { interfaces: { state: 'available' }, lldp: { state: 'no_data' } },
  interfaces: [{ ifIndex: 107, name: 'Gi0/7', description: null, alias: null, ifType: 6,
    adminStatus: 'up', operStatus: 'down', mac: null, speedMbps: 1000,
    inOctets: '18014398509481985', outOctets: null }],
  forwarding: [], lldp: [],
}
const run = { id: 'run-test', deviceId: 'device-test', address: '10.99.0.2', profileId: 'lab',
  state: 'completed', startedAt: '2026-11-16T00:00:00Z', finishedAt: '2026-11-16T00:00:01Z',
  errorCode: null, snapshot }
const device = { id: 'device-test', name: '隔离交换机', address: '10.99.0.2', objectId: '1.3.6.1.4.1.4881.1',
  vendor: 'Ruijie', identityVerified: false, assetId: null,
  firstSeenAt: '2026-11-16T00:00:00Z', lastSeenAt: '2026-11-16T00:00:00Z', latest: run }

function api(options: { failed?: boolean; empty?: boolean; apiError?: boolean } = {}) {
  const requests: { path: string; method?: string }[] = []
  vi.stubGlobal('fetch', async (url: string, init: RequestInit) => {
    const path = new URL(url, 'http://test').pathname
    requests.push({ path, method: init.method })
    if (options.apiError && path === '/api/v1/switches') return new Response(JSON.stringify({
      code: 'database_unavailable', message: '隔离交换机库读取失败', requestId: 'test-switch-request',
    }), { status: 503 })
    let value: unknown = { items: [], nextCursor: null }
    if (path.endsWith('/status')) value = {
      configured: true, state: options.empty ? 'waiting_configuration' : 'running',
      reasonCode: options.empty ? 'snmp_credentials_required' : null,
      intervalSeconds: 300, heartbeatAt: new Date().toISOString(), lastCycle: null, nextDueAt: null,
    }
    if (path === '/api/v1/switches') value = { items: options.empty ? [] : [{
      ...device, latest: options.failed ? { ...run, state: 'failed', errorCode: 'snmp_timeout', snapshot: null } : run,
    }], nextCursor: null }
    if (path.includes('/snapshots')) value = { items: [run], nextCursor: null }
    return new Response(JSON.stringify(value))
  })
  return requests
}
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

it('自动读取状态与设备，未配置时不显示模拟端口且所有请求为GET', async () => {
  const requests = api({ empty: true })
  render(<SwitchesView version={0} />)
  expect(await screen.findByText('等待只读凭据配置')).toBeTruthy()
  expect(await screen.findByText('尚未识别到锐捷交换机')).toBeTruthy()
  expect(screen.queryByText('Gi0/7')).toBeNull()
  expect(requests.every(row => row.method === 'GET')).toBe(true)
  expect(screen.queryByRole('button', { name: /连接|扫描|保存/ })).toBeNull()
})

it('选择设备显示真实字段并保持Counter64精度，不执行网络返回的HTML', async () => {
  api()
  const { container } = render(<SwitchesView version={0} />)
  fireEvent.click(await screen.findByRole('button', { name: '查看交换机 隔离交换机' }))
  expect(await screen.findByText('Gi0/7')).toBeTruthy()
  expect(screen.getByText('18014398509481985')).toBeTruthy()
  expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeTruthy()
  expect(container.querySelector('img')).toBeNull()
  expect(await screen.findByRole('region', { name: '交换机采集历史' })).toBeTruthy()
})

it('最新采集失败不能用旧成功端口冒充实时数据；历史仍可查', async () => {
  api({ failed: true })
  render(<SwitchesView version={0} />)
  fireEvent.click(await screen.findByRole('button', { name: '查看交换机 隔离交换机' }))
  expect(await screen.findByText(/最新采集失败/)).toBeTruthy()
  expect(screen.queryByText('Gi0/7')).toBeNull()
  expect(await screen.findByRole('region', { name: '交换机采集历史' })).toBeTruthy()
})

it('API故障展示错误和请求编号，不展示为空设备', async () => {
  api({ apiError: true })
  render(<SwitchesView version={0} />)
  expect(await screen.findByText(/隔离交换机库读取失败/)).toBeTruthy()
  expect(screen.getByText(/test-switch-request/)).toBeTruthy()
  expect(screen.queryByText('尚未识别到锐捷交换机')).toBeNull()
})

it('重新读取失败后保留旧设备但标记失败', async () => {
  api()
  const { rerender } = render(<SwitchesView version={0} />)
  await screen.findByRole('button', { name: '查看交换机 隔离交换机' })
  const requests = api({ apiError: true })
  rerender(<SwitchesView version={1} />)
  await waitFor(() => expect(requests.length).toBeGreaterThan(0))
  expect(await screen.findByText(/隔离交换机库读取失败/)).toBeTruthy()
  expect(screen.getByText('保留上次读取的数据。')).toBeTruthy()
  expect(screen.getByRole('button', { name: '查看交换机 隔离交换机' })).toBeTruthy()
  expect(screen.queryByText('尚未识别到锐捷交换机')).toBeNull()
})
