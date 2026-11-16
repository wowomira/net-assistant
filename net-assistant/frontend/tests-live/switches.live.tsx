import { afterEach, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import App from '../src/App'
import type { Page } from '../src/api'
import type { SwitchDevice, SwitchStatus } from '../src/switch-api'

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

it('真实本机交换机API → React交互；不触发采集、不代替浏览器视觉验收', async () => {
  const base = 'http://127.0.0.1:8000'
  const actualFetch = fetch
  const requests: string[] = []
  async function read<T>(path: string): Promise<T> {
    const response = await actualFetch(base + path)
    expect(response.status).toBe(200)
    return response.json() as Promise<T>
  }
  const status = await read<SwitchStatus>('/api/v1/switches/status')
  const devices = await read<Page<SwitchDevice>>('/api/v1/switches')
  vi.stubGlobal('fetch', async (path: string, init: RequestInit) => {
    expect(init.method).toBe('GET')
    expect(path.startsWith('/api/v1/')).toBe(true)
    requests.push(path)
    return actualFetch(base + path, init)
  })
  render(<App />)
  fireEvent.click(screen.getByRole('button', { name: '交换机接入' }))
  await waitFor(() => expect(requests).toContain('/api/v1/switches/status'))
  if (status.state === 'waiting_configuration') {
    expect(await screen.findByText('等待只读凭据配置')).toBeTruthy()
  }
  if (devices.items.length === 0) {
    expect(await screen.findByText('尚未识别到锐捷交换机')).toBeTruthy()
    expect(screen.queryByRole('region', { name: '交换机网络接口' })).toBeNull()
  } else {
    expect(await screen.findByRole('region', { name: '交换机列表' })).toBeTruthy()
  }
  expect(screen.queryByRole('button', { name: /连接|保存配置|立即扫描/ })).toBeNull()
  console.log(JSON.stringify({
    evidenceType: 'real_switch_api_dom_not_browser_layout', state: status.state,
    deviceCountInFirstPage: devices.items.length, methods: ['GET'], requests: requests.length,
  }))
})
