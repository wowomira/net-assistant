import { useEffect, useState } from 'react'
import { getJson, getPage, readCatalog, type Page } from './api'
import { Empty, Facts, Panel, Raw, ReadState, Table, useRead } from './components'
import { formatTime } from './model'
import type { SwitchDevice, SwitchRun, SwitchSnapshot, SwitchStatus } from './switch-api'

const labels: Record<string, string> = {
  not_configured: '尚未配置交换机接入', waiting_configuration: '等待只读凭据配置',
  ready: '已就绪', running: '自动接入运行中', collecting: '正在自动采集',
  starting: '正在启动', stopped: '已停止', disabled: '已禁用', unknown: '状态未知',
  stale: '后台心跳已过期', error: '后台异常', completed: '完成', partial: '部分完成',
  failed: '失败', ignored: '非锐捷设备，已跳过', interrupted: '已中断',
  available: '已读取', no_data: '无记录或未暴露', limited: '已达读取上限',
  not_collected: '未采集', up: '启用 / Up', down: '关闭 / Down', testing: '测试中',
  dormant: '休眠', not_present: '接口不存在', lower_layer_down: '下层接口断开',
}
const label = (value: string) => labels[value] ?? value

function Status({ value }: { value: string }) {
  const tone = ['failed', 'error', 'stopped', 'down', 'interrupted'].includes(value) ? 'bad'
    : ['completed', 'available', 'running', 'up'].includes(value) ? 'good' : 'warn'
  return <span className={`badge ${tone}`}>{label(value)}</span>
}

/** Polling is read-only. The independent backend worker owns all SNMP traffic. */
export function SwitchesView({ version }: { version: number }) {
  const [poll, setPoll] = useState(0)
  const [selected, setSelected] = useState<string | null>(null)
  useEffect(() => {
    const timer = setInterval(() => setPoll(value => value + 1), 15_000)
    return () => clearInterval(timer)
  }, [])
  const revision = version + poll
  const status = useRead('switch-status', revision, signal => getJson<SwitchStatus>('/switches/status', signal))
  const devices = useRead('switches', revision, signal => readCatalog<SwitchDevice>('/switches', signal))
  const device = devices.data?.items.find(row => row.id === selected)
  return <>
    <Panel title="自动接入状态">
      <ReadState value={status} />
      {status.data && <Facts rows={[
        ['后台状态', <Status value={status.data.state} />],
        ['最近心跳', formatTime(status.data.heartbeatAt)],
        ['采集周期', status.data.intervalSeconds ? `${status.data.intervalSeconds} 秒` : '尚未配置'],
        ['下一轮', formatTime(status.data.nextDueAt)],
        ['本轮目标范围', status.data.targetCount === undefined ? '尚未配置' : `${status.data.targetCount} 个地址`],
        ['可用凭据组', status.data.readyProfileCount ?? '尚未配置'],
      ]} />}
      {status.data?.reasonCode && <p className="muted tiny">状态原因：<code>{status.data.reasonCode}</code></p>}
      {status.data?.lastCycle && <p className="muted tiny">上一轮结束：{formatTime(status.data.lastCycle.finishedAt)}
        {' · '}成功 {status.data.lastCycle.counts.completed ?? 0}
        {' · '}部分完成 {status.data.lastCycle.counts.partial ?? 0}
        {' · '}失败 {status.data.lastCycle.counts.failed ?? 0}</p>}
    </Panel>
    <Panel title="锐捷交换机">
      <ReadState value={devices} />
      {devices.data && (devices.data.items.length === 0 ? <Empty>尚未识别到锐捷交换机</Empty> :
        <Table label="交换机列表"><thead><tr>
          <th>设备名称 / 管理地址</th><th>最近采集</th><th>最近成功观测</th><th>识别依据</th>
        </tr></thead><tbody>{devices.data.items.map(row => <tr key={row.id}>
          <td><button className="text-button" aria-label={`查看交换机 ${row.name}`}
            aria-pressed={selected === row.id} onClick={() => setSelected(row.id)}>{row.name}</button>
            <code className="subline">{row.address}</code></td>
          <td>{row.latest ? <Status value={row.latest.state} /> : '暂无'}
            {row.latest?.errorCode && <code className="subline">{row.latest.errorCode}</code>}</td>
          <td>{formatTime(row.lastSeenAt)}</td><td><code>{row.objectId}</code>
            <small className="subline">{row.deviceKind === 'switch_product'
              ? '设备报告交换机产品族 OID' : '仅识别锐捷企业，类别待核验'}</small></td>
        </tr>)}</tbody></Table>)}
      {devices.data && !devices.data.complete && <p className="stale">设备列表未读完，当前不是全量。</p>}
    </Panel>
    {device && <SwitchDetail key={device.id} device={device} version={revision}
      interval={status.data?.intervalSeconds ?? 300} />}
    <AttemptHistory version={revision} />
  </>
}

function SwitchDetail({ device, version, interval }: { device: SwitchDevice; version: number; interval: number }) {
  const [historical, setHistorical] = useState<SwitchRun | null>(null)
  const current = historical ?? device.latest
  const snapshot = current?.snapshot
  const stale = snapshot && Date.now() - Date.parse(snapshot.observedAt) > interval * 3000
  return <section aria-label="交换机详情">
    <Panel title={device.name}>
      <Facts rows={[
        ['管理地址', device.address], ['设备编号', device.id],
        ['识别来源', 'SNMP sysObjectID'], ['最近尝试', formatTime(device.latest?.startedAt)],
        ['设备报告类别', device.deviceKind === 'switch_product' ? '交换机产品族 OID' : '网络设备，类别待核验'],
      ]} />
      {device.latest?.state === 'failed' && <p role="alert" className="error-box">
        最新采集失败：{device.latest.errorCode ?? '未知原因'}。历史记录保留，不作为本次成功结果。
      </p>}
      {historical && <p className="stale">正在查看历史快照：{formatTime(historical.startedAt)}{' '}
        <button onClick={() => setHistorical(null)}>返回最新采集</button></p>}
      {stale && <p className="stale">此快照已超过三个采集周期，仅代表当时观测。</p>}
      {snapshot ? <Snapshot value={snapshot} /> : <Empty>本次没有可展示的成功快照</Empty>}
    </Panel>
    <History deviceId={device.id} version={version} onSelect={setHistorical} />
  </section>
}

function Snapshot({ value }: { value: SwitchSnapshot }) {
  return <>
    <Facts rows={[
      ['设备报告名称', value.system.name], ['设备报告描述', value.system.description],
      ['运行时间（秒）', value.system.uptimeSeconds ?? '未读取'], ['观测时间', formatTime(value.observedAt)],
    ]} />
    <h3>分项采集状态</h3>
    <Table label="交换机采集能力"><thead><tr><th>项目</th><th>状态</th><th>细分结果</th></tr></thead>
      <tbody>{Object.entries(value.capabilities).map(([name, item]) => <tr key={name}>
        <td>{({ interfaces: '网络接口', forwarding: 'VLAN 转发表', bridgeForwarding: '基础转发表', lldp: 'LLDP 邻居' } as Record<string, string>)[name] ?? name}</td>
        <td><Status value={item.state} /></td><td><Raw value={item} label="字段读取状态" /></td>
      </tr>)}</tbody></Table>
    <h3>网络接口</h3>
    {!value.interfaces.length ? <Empty>本次未返回网络接口记录</Empty> :
      <Table label="交换机网络接口"><thead><tr>
        <th>接口 / ifIndex</th><th>描述 / 别名</th><th>管理状态</th><th>运行状态</th>
        <th>速率 Mbps</th><th>累计入站字节</th><th>累计出站字节</th>
      </tr></thead><tbody>{value.interfaces.map(row => <tr key={row.ifIndex}>
        <td>{row.name ?? '未读取'}<code className="subline">{row.ifIndex}</code></td>
        <td>{row.description ?? '未读取'}{row.alias && <small className="subline">{row.alias}</small>}</td>
        <td><Status value={row.adminStatus} /></td><td><Status value={row.operStatus} /></td>
        <td>{row.speedMbps ?? '未读取'}</td><td><code>{row.inOctets ?? '未读取'}</code></td>
        <td><code>{row.outOctets ?? '未读取'}</code></td>
      </tr>)}</tbody></Table>}
    <h3>MAC 转发表</h3>
    {!value.forwarding.length ? <Empty>本次未返回 MAC 转发表记录</Empty> :
      <Table label="交换机MAC转发表"><thead><tr><th>MAC</th><th>ifIndex</th><th>桥端口</th><th>VLAN</th><th>FDB ID</th><th>状态 / 来源</th></tr></thead>
        <tbody>{value.forwarding.map((row, index) => <tr key={index}>
          <td><code>{row.mac}</code></td><td>{row.ifIndex ?? '未映射'}</td><td>{row.bridgePort ?? '未读取'}</td>
          <td>{row.vlanIds.length ? row.vlanIds.join(', ') : '未映射'}</td><td>{row.fdbId ?? '无'}</td>
          <td>{row.status}<small className="subline">{row.source}</small></td>
        </tr>)}</tbody></Table>}
    <h3>LLDP 邻居</h3>
    {!value.lldp.length ? <Empty>本次未返回 LLDP 邻居记录</Empty> :
      <Table label="交换机LLDP邻居"><thead><tr><th>本地 LLDP 端口号</th><th>远端名称</th><th>远端机箱标识</th><th>远端端口标识</th></tr></thead>
        <tbody>{value.lldp.map((row, index) => <tr key={index}>
          <td>{row.localPortNumber}</td><td>{row.remoteSystemName ?? '未读取'}</td>
          <td><code>{row.remoteChassisId ?? '未读取'}</code></td><td>{row.remotePortId ?? '未读取'}</td>
        </tr>)}</tbody></Table>}
    <Raw value={value} label="完整采集 JSON" />
  </>
}

function useRunPage(path: string, version: number) {
  const [cursors, setCursors] = useState<(string | null)[]>([null])
  const cursor = cursors[cursors.length - 1]
  const resource = useRead(`${path}:${cursor ?? ''}`, version,
    signal => getPage<SwitchRun>(`${path}?limit=20${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`, signal))
  return { resource, cursors, setCursors }
}

function RunPagination({ page, cursors, setCursors }: {
  page: Page<SwitchRun>; cursors: (string | null)[];
  setCursors: (value: (string | null)[]) => void
}) {
  return <div className="pagination">
    <button disabled={cursors.length === 1} onClick={() => setCursors(cursors.slice(0, -1))}>上一页</button>
    <span>第 {cursors.length} 页 · 按记录顺序</span>
    <button disabled={page.nextCursor === null || cursors.includes(page.nextCursor)}
      onClick={() => setCursors([...cursors, page.nextCursor])}>下一页</button>
  </div>
}

function History({ deviceId, version, onSelect }: {
  deviceId: string; version: number; onSelect: (run: SwitchRun) => void
}) {
  const { resource, cursors, setCursors } = useRunPage(`/switches/${encodeURIComponent(deviceId)}/snapshots`, version)
  return <section aria-label="交换机采集历史"><Panel title="采集历史">
    <ReadState value={resource} />
    {resource.data && <>
      <Table label="交换机历史记录"><thead><tr><th>开始时间</th><th>结果</th><th>错误</th><th>详情</th></tr></thead>
        <tbody>{resource.data.items.map(row => <tr key={row.id}>
          <td>{formatTime(row.startedAt)}</td><td><Status value={row.state} /></td><td>{row.errorCode ?? '无'}</td>
          <td><button className="text-button" onClick={() => onSelect(row)}>查看记录</button></td>
        </tr>)}</tbody></Table>
      <RunPagination page={resource.data} cursors={cursors} setCursors={setCursors} />
    </>}
  </Panel></section>
}

function AttemptHistory({ version }: { version: number }) {
  const { resource, cursors, setCursors } = useRunPage('/switch-collection-runs', version)
  return <Panel title="自动接入尝试">
    <ReadState value={resource} />
    {resource.data && (resource.data.items.length ? <>
      <Table label="交换机接入尝试"><thead><tr><th>目标</th><th>开始时间</th><th>结果</th><th>原因</th></tr></thead>
        <tbody>{resource.data.items.map(row => <tr key={row.id}>
          <td><code>{row.address}</code></td><td>{formatTime(row.startedAt)}</td>
          <td><Status value={row.state} /></td><td><code>{row.errorCode ?? '无'}</code></td>
        </tr>)}</tbody></Table>
      <RunPagination page={resource.data} cursors={cursors} setCursors={setCursors} />
    </> : <Empty>暂无接入尝试</Empty>)}
  </Panel>
}
