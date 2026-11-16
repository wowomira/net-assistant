import { describe, expect, it } from 'vitest'
import { formatTime, newestFirst, statusInfo, isStale } from './model'

describe('展示不夸大实际结果', () => {
  it('完成是执行完成，不是资产健康；未知状态不变绿', () => {
    expect(statusInfo('completed')).toEqual({ label: '执行完成', tone: 'good' })
    expect(statusInfo('future_value')).toEqual({ label: '未知 · future_value', tone: 'neutral' })
    expect(statusInfo('constructor')).toEqual({ label: '未知 · constructor', tone: 'neutral' })
    expect(statusInfo('timeout').tone).not.toBe('good')
    expect(statusInfo('stale').tone).toBe('warn')
  })
  it('缺失时间不显示为现在；UTC 时间显示为北京时间', () => {
    expect(formatTime(null)).toBe('暂无记录')
    expect(formatTime('bad-date')).toBe('时间不可解析')
    expect(formatTime('2026-11-15T01:00:28Z')).toBe('2026-11-15 09:00:28')
  })
  it('任务按实际开始时间倒序，不把API正序第一条当最新', () => {
    const original = [{ id: 'old', startedAt: '2026-11-14T00:00:00Z' },
      { id: 'new', startedAt: '2026-11-15T00:00:00Z' }]
    expect(newestFirst(original).map(x => x.id)).toEqual(['new', 'old'])
    expect(original[0].id).toBe('old')
  })
  it('读取数据超过一分钟提示过期，不推断资产离线', () => {
    expect(isStale(1000, 62000)).toBe(true)
    expect(isStale(1000, 60000)).toBe(false)
    expect(isStale(null, 62000)).toBe(false)
  })
  it('HTTP响应不是HTTP正常，证书失败单独显示', () => {
    expect(statusInfo('response')).toEqual({ label: '收到 HTTP 响应', tone: 'neutral' })
    expect(statusInfo('certificate_error').tone).toBe('bad')
    expect(statusInfo('verified').label).toBe('TLS 校验通过')
  })
})
