import { Fragment, useState } from 'react'
import { type Catalog, type Host, type Job, type Probe, type Association, type Comparison, getJson, getPage, readCatalog, withQuery } from './api'
import { Badge, CatalogNote, Empty, Facts, Panel, Raw, ReadState, Table, useRead, type Resource } from './components'
import { formatTime, newestFirst } from './model'

export function JobSelect({ jobs, selected, onChange }: {
  jobs: Catalog<Job>; selected: string; onChange: (id: string) => void
}) {
  return <div className="job-select"><label htmlFor="job-select">扫描批次</label>
    <select id="job-select" value={selected} onChange={event => onChange(event.target.value)}>
      {newestFirst(jobs.items).map(job => <option key={job.id} value={job.id}>
        {formatTime(job.startedAt)} · {job.trigger === 'scheduled' ? '每日自动' : job.trigger === 'manual' ? '手动' : '未知'} · {job.id.slice(0, 8)}
      </option>)}
    </select></div>
}

export function ScansView({ jobs, version, onEvidence }: {
  jobs: Resource<Catalog<Job>>; version: number; onEvidence: (job: string, address: string) => void
}) {
  const [selected, setSelected] = useState('')
  const id = jobs.data?.items.some(item => item.id === selected) ? selected : newestFirst(jobs.data?.items ?? [])[0]?.id ?? ''
  const job = jobs.data?.items.find(item => item.id === id)
  return <>
    <Panel title="选择记录">
      <ReadState value={jobs} />
      {jobs.data && <><CatalogNote catalog={jobs.data} />
        {!jobs.data.items.length ? <Empty>暂无扫描记录。</Empty> :
          <JobSelect jobs={jobs.data} selected={id} onChange={setSelected} />}</>}
    </Panel>
    {job && <JobDetail key={job.id} job={job} version={version} onEvidence={onEvidence} />}
  </>
}
function count(value: unknown) { return typeof value === 'number' ? value.toLocaleString('zh-CN') : '未提供' }
function JobDetail({ job, version, onEvidence }: {
  job: Job; version: number; onEvidence: (job: string, address: string) => void
}) {
  const hosts = useRead(job.id, version, signal => readCatalog<Host>(`/discovery-jobs/${encodeURIComponent(job.id)}/hosts`, signal))
  return <>
    <Panel title="当次执行结果" action={<Badge value={job.state} />}>
      <Facts rows={[
        ['扫描编号', <code>{job.id}</code>], ['触发方式', <Badge value={job.trigger} />],
        ['开始时间', formatTime(job.startedAt)], ['结束时间', formatTime(job.finishedAt)],
        ['逻辑范围 / 配置版本', `${job.scopeId} / ${job.scopeRevision}`],
        ['目标范围', Array.isArray(job.configSnapshot.targets) ? job.configSnapshot.targets.join('、') : '未提供'],
        ['排除地址', Array.isArray(job.configSnapshot.exclude) ? job.configSnapshot.exclude.join('、') : '未提供'],
        ['错误码', job.errorCode ?? '无'],
      ]} />
      <Facts rows={[
        ['候选地址', count(job.coverage.candidateAddresses)],
        ['当次直接响应设备', count(job.coverage.responsiveHosts)],
        ['TCP 已尝试 / 计划', `${count(job.coverage.completedTcpChecks)} / ${count(job.coverage.expectedTcpChecks)}`],
        ['服务证据检查次数', count(job.coverage.serviceEvidenceChecks)],
      ]} />
      <Raw value={job} label="原始返回 JSON" />
    </Panel>
    <Panel title="本批次发现快照">
      <ReadState value={hosts} />
      {hosts.data && <><CatalogNote catalog={hosts.data} />
        {!hosts.data.items.length ? <Empty>暂无发现记录</Empty> :
          <Table label="扫描发现设备"><thead><tr><th>当次地址 / MAC</th><th>直接证据</th>
            <th>当次开放 TCP 端口</th><th>台账关联</th><th>详情</th></tr></thead>
          <tbody>{hosts.data.items.map(host => <Fragment key={host.id}><tr>
            <td><strong>{host.hostname ?? '网络名未获取'}</strong>
              <small className="subline">{host.hostnameSource ?? host.nameStatus ?? '未采集'}</small>
              <code className="subline">{host.address}</code><code className="subline">{host.mac ?? '未获取 MAC'}</code>
              <small className="subline">{formatTime(host.observedAt)}</small></td>
            <td><Badge value={host.confidence} /><small className="subline">{host.discoveryMethods.join('、')}</small></td>
            <td>{host.openPorts.length ? host.openPorts.join('、') :
              host.portScan?.complete ? '配置范围内未发现开放端口' : '未发现开放端口 · 扫描覆盖待核对'}
              {host.portScan && <small className="subline">已尝试 {host.portScan.attempted} / {host.portScan.planned}
                {' · '}超时 {host.portScan.timeout}{' · '}未尝试 {host.portScan.unattempted}</small>}</td>
            <td><Badge value={host.associationStatus} /><code className="subline">{host.assetId ?? '未关联'}</code></td>
            <td><button className="text-button" onClick={() => onEvidence(job.id, host.address)}>查看探测</button>
              <HostAssociation id={host.id} version={version} />
              <Raw value={host} label="原始快照 JSON" /></td>
          </tr><tr className="inventory-row"><td colSpan={5}>
            <InventoryDetails host={host} jobId={job.id} />
          </td></tr></Fragment>)}</tbody></Table>}</>}
    </Panel>
    <ScanComparison jobId={job.id} version={version} />
  </>
}

function InventoryDetails({ host, jobId }: { host: Host; jobId: string }) {
  return <details className="inventory-detail">
    <summary>服务与网站（{host.services?.length ?? 0} / {host.websites?.length ?? 0}）</summary>
    {!!host.services?.length && <Table label={`${host.address} 服务清单`}>
      <thead><tr><th>TCP</th><th>观测协议</th><th>产品声明</th><th>版本声明</th><th>识别 / 依据</th></tr></thead>
      <tbody>{host.services.map(service => <tr key={service.port}>
        <td>{service.port}</td><td>{service.protocol ?? '未识别'}
          {!service.protocol && service.portHint && <small className="subline">端口提示：{service.portHint}</small>}</td>
        <td>{service.product ?? '未获取'}</td><td>{service.version ?? '未获取'}</td>
        <td><Badge value={service.identification} /><small className="subline">{service.evidenceMethods.join('、') || '无协议证据'}</small></td>
      </tr>)}</tbody>
    </Table>}
    {host.websites?.map(site => <WebsitePreview key={`${site.scheme}:${site.port}`} site={site}
      address={host.address} jobId={jobId} />)}
    {!host.services?.length && !host.websites?.length && <p className="muted tiny">本批次未取得服务或网站记录。</p>}
  </details>
}

type Website = NonNullable<Host['websites']>[number]
function websiteLink(site: Website, address: string): string | null {
  try {
    const url = new URL(site.url)
    const port = Number(url.port || (url.protocol === 'https:' ? 443 : 80))
    if (!['http:', 'https:'].includes(url.protocol) || url.protocol !== `${site.scheme}:` ||
      url.hostname !== address || port !== site.port || url.username || url.password ||
      url.pathname !== '/' || url.search || url.hash) return null
    return url.href
  } catch { return null }
}

function WebsitePreview({ site, address, jobId }: { site: Website; address: string; jobId: string }) {
  const [preview, setPreview] = useState(false)
  const [imageFailed, setImageFailed] = useState(false)
  const link = websiteLink(site, address)
  const shot = site.screenshot
  const image = shot?.status === 'captured' && shot.probeId
    ? `/api/v1/discovery-jobs/${encodeURIComponent(jobId)}/screenshots/${encodeURIComponent(shot.probeId)}` : null
  return <section className="website-preview" aria-label={`${address}:${site.port} 网站`}>
    <div className="website-heading"><strong>{site.title ?? '未取得页面标题'}</strong>
      {link && <a className="text-button" href={link} target="_blank" rel="noopener noreferrer">打开原站</a>}</div>
    <code>{site.url}</code>
    <p className="tiny"><Badge value={site.status} />{' · '}HTTP {site.statusCode ?? '未取得'}
      {' · '}{site.server ?? 'Server 未提供'}{' · '}TLS <Badge value={site.tlsStatus} /></p>
    {site.redirectLocation && <p className="tiny">跳转目标：{site.redirectLocation}</p>}
    <p className="tiny muted">检测时间：{formatTime(site.observedAt)}
      {' · '}耗时 {typeof site.durationMs === 'number' ? `${site.durationMs.toFixed(1)} ms` : '未提供'}</p>
    <p className="tiny">截图：<Badge value={shot?.status ?? 'not_collected'} />
      {shot?.capturedAt && <> · {formatTime(shot.capturedAt)} · 静态首屏，脚本未执行</>}
      {shot?.reasonCode && <code className="subline">{shot.reasonCode}</code>}</p>
    {image && <button type="button" className="text-button" aria-expanded={preview}
      onClick={() => { setPreview(!preview); setImageFailed(false) }}>{preview ? '收起截图' : '预览截图'}</button>}
    {preview && image && (imageFailed ? <p className="error-box">截图文件不可读取。</p> :
      <a href={image} target="_blank" rel="noopener noreferrer" aria-label="打开截图原图">
        <img className="website-thumbnail" src={image} alt={`${site.title ?? site.url} 截图`}
          loading="lazy" onError={() => setImageFailed(true)} />
      </a>)}
  </section>
}
function ScanComparison({ jobId, version }: { jobId: string; version: number }) {
  const result = useRead(jobId, version, signal =>
    getJson<Comparison>(`/discovery-jobs/${encodeURIComponent(jobId)}/comparison`, signal))
  const data = result.data
  return <Panel title="历史比对">
    <ReadState value={result} />
    {data && <>
      <Facts rows={[
        ['基线任务', data.baselineJobId ?? '无'],
        ['比对状态', data.status === 'available' ? '已比对' : data.status === 'unavailable' ? '不可比对' : '未知'],
        ['原因码', data.reasonCode ?? '无'],
      ]} />
      {data.status === 'available' && <>
        <Facts rows={[
          ['新增观测地址', data.addedAddresses.join('、') || '无'],
          ['本次未观测地址', data.notObservedAddresses.join('、') || '无'],
        ]} />
        {data.macChanges.length > 0 && <Table label="MAC变化">
          <thead><tr><th>地址</th><th>原 MAC</th><th>本次 MAC</th></tr></thead>
          <tbody>{data.macChanges.map(row => <tr key={row.address}>
            <td>{row.address}</td><td>{row.before ?? '未获取'}</td><td>{row.after ?? '未获取'}</td>
          </tr>)}</tbody>
        </Table>}
        {data.probeChanges.length === 0 ? <Empty>无探测结果变化</Empty> :
          <Table label="探测变化">
            <thead><tr><th>地址</th><th>方法 / 阶段</th><th>端口</th><th>上次</th><th>本次</th><th>证据</th></tr></thead>
            <tbody>{data.probeChanges.map((row, index) => <tr key={index}>
              <td>{row.address}</td><td>{row.method} / {row.phase}</td><td>{row.port ?? '—'}</td>
              <td><Badge value={row.before.status} /></td><td><Badge value={row.after.status} /></td>
              <td><Raw value={{ before: row.before.evidence, after: row.after.evidence }} label="变化证据" /></td>
            </tr>)}</tbody>
          </Table>}
      </>}
    </>}
  </Panel>
}
function HostAssociation({ id, version }: { id: string; version: number }) {
  const [open, setOpen] = useState(false)
  const result = useRead(open ? id : null, version,
    signal => getJson<Association>(`/discovery-hosts/${encodeURIComponent(id)}/asset-association`, signal))
  return <div><button className="text-button" aria-expanded={open} onClick={() => setOpen(!open)}>
    {open ? '收起关联判断' : '查看关联判断'}</button>
    {open && <div className="inline-detail"><ReadState value={result} />{result.data && <>
      <p>待确认：{result.data.requiresConfirmation ? '是' : '否'} · 地址冲突：{result.data.addressConflict ? '有' : '未报告'}</p>
      <Raw value={result.data.automaticDecision} label="程序自动判断依据" />
    </>}</div>}</div>
}

export function EvidenceView({ jobs, version, initialJob, initialAddress }: {
  jobs: Resource<Catalog<Job>>; version: number; initialJob: string; initialAddress: string
}) {
  const [selection, setSelection] = useState(initialJob)
  const id = jobs.data?.items.some(job => job.id === selection) ? selection : newestFirst(jobs.data?.items ?? [])[0]?.id ?? ''
  return <>
    <Panel title="选择记录">
      <ReadState value={jobs} />
      {jobs.data && <><CatalogNote catalog={jobs.data} />
        {jobs.data.items.length ? <JobSelect jobs={jobs.data} selected={id} onChange={setSelection} /> : <Empty>暂无可读取的扫描批次。</Empty>}</>}
    </Panel>
    {id && <Probes key={id} jobId={id} initialAddress={id === initialJob ? initialAddress : ''} version={version} />}
  </>
}
function Probes({ jobId, initialAddress, version }: { jobId: string; initialAddress: string; version: number }) {
  const [filter, setFilter] = useState({ address: initialAddress, method: '', status: '' })
  const [draft, setDraft] = useState(filter)
  const [cursors, setCursors] = useState<(string | null)[]>([null])
  const [pageIndex, setPageIndex] = useState(0)
  const path = withQuery(`/discovery-jobs/${encodeURIComponent(jobId)}/probes`,
    { ...filter, limit: '50', cursor: cursors[pageIndex] })
  const result = useRead(path, version, signal => getPage<Probe>(path, signal))
  const canNext = !result.loading && !result.error && result.data?.nextCursor != null
  return <Panel title="逐条检查记录">
    <form className="filter-form" onSubmit={event => {
      event.preventDefault()
      setFilter({ ...draft, address: draft.address.trim() }); setPageIndex(0); setCursors([null])
    }}>
      <label>当次 IP<input value={draft.address} onChange={event => setDraft({ ...draft, address: event.target.value })}
        placeholder="留空查看全部地址" /></label>
      <label>方法<select value={draft.method} onChange={event => setDraft({ ...draft, method: event.target.value })}>
        <option value="">全部方法</option>{['icmp', 'arp', 'tcp', 'name', 'http', 'tls', 'banner', 'screenshot'].map(method => <option key={method}>{method}</option>)}
      </select></label>
      <label>结果<select value={draft.status} onChange={event => setDraft({ ...draft, status: event.target.value })}>
        <option value="">全部结果</option>{['reply', 'resolved', 'open', 'response', 'verified', 'received', 'empty',
          'timeout', 'refused', 'no_response', 'unreachable', 'certificate_error', 'error', 'not_supported', 'not_applicable', 'captured', 'blocked']
          .map(status => <option key={status} value={status}>{status}</option>)}
      </select></label>
      <button type="submit" className="primary">应用筛选</button>
      <button type="button" onClick={() => {
        const cleared = { address: '', method: '', status: '' }
        setDraft(cleared); setFilter(cleared); setPageIndex(0); setCursors([null])
      }}>清除筛选</button>
    </form>
    <p className="muted tiny">当前生效：IP {filter.address || '全部'} / 方法 {filter.method || '全部'} / 结果 {filter.status || '全部'}。输入后需应用筛选。</p>
    <ReadState value={result} />
    {result.data && <>
      <p className="tiny muted">第 {pageIndex + 1} 页 · 本页 {result.data.items.length} 条 · 每页最多 50 条 · 按记录顺序，不代表总数</p>
      {!result.data.items.length ? <Empty>该批次在当前筛选条件下没有探测记录。</Empty> :
        <Table label="探测证据列表"><thead><tr><th>检查对象</th><th>方法 / 阶段</th><th>当次结果</th><th>耗时</th><th>时间与原始证据</th></tr></thead>
          <tbody>{result.data.items.map(row => <tr key={row.id}>
            <td><code>{row.address}</code><small className="subline">{row.port == null ? '无端口项' : `TCP ${row.port}`}</small></td>
            <td>{row.method}<small className="subline">{row.phase}</small></td>
            <td><Badge value={row.status} /><small className="subline">{row.reasonCode ?? '无附加原因码'}</small></td>
            <td>{row.durationMs.toLocaleString('zh-CN', { maximumFractionDigits: 2 })} ms</td>
            <td>{formatTime(row.observedAt)}<Raw value={row.evidence} label="展开原始证据" /></td>
          </tr>)}</tbody></Table>}
    </>}
    <div className="pagination">
      <button disabled={pageIndex === 0 || result.loading} onClick={() => setPageIndex(pageIndex - 1)}>上一页</button>
      <span className="tiny muted">第 {pageIndex + 1} 页{result.data?.nextCursor === null && !result.loading && !result.error ? ' · 已到末页' : ''}</span>
      <button disabled={!canNext} onClick={() => {
        const next = result.data?.nextCursor
        if (next != null) { setCursors([...cursors.slice(0, pageIndex + 1), next]); setPageIndex(pageIndex + 1) }
      }}>下一页</button>
    </div>
  </Panel>
}
