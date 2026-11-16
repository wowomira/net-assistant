import { afterEach, describe, expect, it, vi } from 'vitest'
import { getJson, getPage, readCatalog, ApiError } from './api'

afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers() })

describe('只读契约客户端', () => {
  it('完整读取多页目录，保留服务端过滤参数且只发GET', async () => {
    const urls: string[] = []
    vi.stubGlobal('fetch', async (url: string, init: RequestInit) => {
      expect(init.method).toBe('GET')
      expect(init.cache).toBe('no-store')
      urls.push(url)
      const second = new URL(url, 'http://test').searchParams.has('cursor')
      return new Response(JSON.stringify(second ? { items: [{ id: 'b' }], nextCursor: null }
        : { items: [{ id: 'a' }], nextCursor: '1' }), { status: 200 })
    })
    const catalog = await readCatalog<{ id: string }>('/assets?status=open')
    expect(catalog).toEqual({ items: [{ id: 'a' }, { id: 'b' }], complete: true })
    expect(urls).toEqual(['/api/v1/assets?status=open&limit=200',
      '/api/v1/assets?status=open&limit=200&cursor=1'])
  })
  it('循环游标失败，而不是静默重复和伪造全量统计', async () => {
    vi.stubGlobal('fetch', async () => new Response(JSON.stringify({ items: [], nextCursor: '1' })))
    await expect(readCatalog('/assets')).rejects.toThrow('分页游标重复')
  })
  it('目录上限未读完时显式标注不完整', async () => {
    let cursor = 0
    vi.stubGlobal('fetch', async () => new Response(JSON.stringify({
      items: [{ id: ++cursor }], nextCursor: String(cursor),
    })))
    expect(await readCatalog('/assets', undefined, 2)).toEqual({
      items: [{ id: 1 }, { id: 2 }], complete: false,
    })
  })
  it('保留服务端错误码和请求编号，503不会变成空列表', async () => {
    vi.stubGlobal('fetch', async () => new Response(JSON.stringify({
      code: 'database_unavailable', message: '数据库不可读', requestId: 'request-test',
    }), { status: 503 }))
    try {
      await getJson('/assets')
      expect.fail('请求必须失败')
    } catch (error) {
      expect(error).toBeInstanceOf(ApiError)
      expect(error).toMatchObject({ code: 'database_unavailable', requestId: 'request-test', status: 503 })
    }
  })
  it('拒绝非分页响应和站外路径', async () => {
    vi.stubGlobal('fetch', async () => new Response(JSON.stringify({ items: [], nextCursor: false })))
    await expect(getPage('/assets')).rejects.toThrow('分页数据')
    await expect(getJson('https://example.invalid/')).rejects.toThrow('只允许')
  })
  it('调用方中止不会悄悄回退成示例数据', async () => {
    vi.stubGlobal('fetch', async (_: string, init: RequestInit) => {
      init.signal?.throwIfAborted()
      throw new DOMException('已中止', 'AbortError')
    })
    const controller = new AbortController()
    controller.abort()
    await expect(getJson('/assets', controller.signal)).rejects.toMatchObject({ name: 'AbortError' })
  })
  it('请求超过15秒明确报告超时，而不是无限读取中', async () => {
    vi.useFakeTimers()
    vi.stubGlobal('fetch', (_: string, init: RequestInit) => new Promise((_resolve, reject) => {
      init.signal?.addEventListener('abort', () => reject(new DOMException('中止', 'AbortError')))
    }))
    const assertion = expect(getJson('/assets')).rejects.toMatchObject({
      code: 'request_timeout', message: '读取超时，请确认 API 是否运行后重试',
    })
    await vi.advanceTimersByTimeAsync(15_001)
    await assertion
  })
})
