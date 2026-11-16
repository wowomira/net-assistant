import { useState } from 'react'
import { type Asset, type Audit, type Catalog, type Observation, readCatalog } from './api'
import { Badge, CatalogNote, Empty, Facts, Panel, Raw, ReadState, Table, useRead, type Resource } from './components'
import { formatTime } from './model'

interface Props {
  assets: Resource<Catalog<Asset>>
  version: number
  onEvidence: (jobId: string, address: string) => void
}
export function AssetsView({ assets, version, onEvidence }: Props) {
  const [selected, setSelected] = useState<string | null>(null)
  const asset = assets.data?.items.find(item => item.id === selected)
  return <>
    <Panel title="资产列表">
      <ReadState value={assets} />
      {assets.data && <>
        <CatalogNote catalog={assets.data} />
        {assets.data.items.length === 0 ? <Empty>暂无资产档案</Empty> :
          <Table label="资产列表"><thead><tr>
            <th>名称 / assetId</th><th>登记来源</th><th>分类</th><th>关联状态</th><th>最近观测</th>
          </tr></thead><tbody>{assets.data.items.map(item => <tr key={item.id} className={selected === item.id ? 'selected' : ''}>
            <td><button className="text-button" aria-label={`查看 ${item.name}`} aria-pressed={selected === item.id}
              onClick={() => setSelected(item.id)}>{item.name}</button><code className="subline">{item.id}</code></td>
            <td>{item.registrationSource === 'manual' ? <span className="badge neutral">人工登记</span> : <Badge value={item.registrationSource} />}</td>
            <td><Badge value={item.managementStatus} /></td>
            <td><Badge value={item.identityStatus} /></td>
            <td>{formatTime(item.lastObservedAt)}<small className="subline">{item.linkedObservationCount} 条关联观测</small></td>
          </tr>)}</tbody></Table>}
      </>}
      {assets.data && <Raw value={assets.data.items} label="原始返回 JSON" />}
    </Panel>
    {asset ? <AssetDetail key={asset.id} asset={asset} version={version} onEvidence={onEvidence} />
      : null}
  </>
}

function AssetDetail({ asset, version, onEvidence }: {
  asset: Asset; version: number; onEvidence: Props['onEvidence']
}) {
  const observations = useRead(asset.id, version,
    signal => readCatalog<Observation>(`/assets/${encodeURIComponent(asset.id)}/observations`, signal))
  const audits = useRead(asset.id, version,
    signal => readCatalog<Audit>(`/assets/${encodeURIComponent(asset.id)}/audit`, signal))
  const history = observations.data?.items.slice().sort((a, b) => Date.parse(b.observedAt) - Date.parse(a.observedAt))
  return <section aria-label="资产详情">
    <Panel title={asset.name}>
      <Facts rows={[
        ['稳定台账编号', <code>{asset.id}</code>], ['逻辑范围', asset.scopeId],
        ['登记来源', asset.registrationSource === 'manual' ? '人工登记' : <Badge value={asset.registrationSource} />],
        ['负责人', asset.owner || '尚未填写'], ['资产类型（档案标签）', asset.assetKind],
        ['采集接入', <Badge value={asset.collectionAccess} />],
        ['登记时间', formatTime(asset.createdAt)], ['档案版本', asset.revision],
      ]} />
      {asset.notes && <p className="notes">档案备注：{asset.notes}</p>}
      <h3>观测历史</h3>
      <ReadState value={observations} />
      {observations.data && <>
        <CatalogNote catalog={observations.data} />
        {!history?.length ? <Empty>该档案暂无关联观测。</Empty> : <Table label="资产观测历史">
          <thead><tr><th>观测时间（北京时间）</th><th>当次 IP</th><th>当次 MAC</th><th>关联来源</th><th>证据</th></tr></thead>
          <tbody>{history.map(row => <tr key={row.id}>
            <td>{formatTime(row.observedAt)}</td><td><code>{row.address}</code></td>
            <td><code>{row.mac ?? '未获取'}</code></td>
            <td>{row.actor === 'automatic_discovery' ? '程序自动关联' : row.actor === 'local_cli' ? '本机人工操作' : '未知来源'}</td>
            <td><button className="text-button" onClick={() => onEvidence(row.jobId, row.address)}>查看探测</button>
              <Raw value={row} label="关联依据" /></td>
          </tr>)}</tbody></Table>}
      </>}
      <h3>登记与变更审计</h3>
      <ReadState value={audits} />
      {audits.data && <><CatalogNote catalog={audits.data} />
        {audits.data.items.length === 0 ? <Empty>暂无审计记录。</Empty> : <ul className="audit-list">
          {audits.data.items.map(row => <li key={row.id}><div>
            <strong>{({ registered: '登记档案', linked: '建立关联', unlinked: '解除关联', updated: '更新档案' })[row.action] ?? row.action}</strong>
            <span className="muted">{formatTime(row.occurredAt)}</span></div>
            <p>{row.actor === 'automatic_discovery' ? '程序自动执行' : row.actor === 'local_cli' ? '本机人工操作' : '未知来源'} · {row.reason}</p>
            <Raw value={row.details} label="查看审计详情" /></li>)}
        </ul>}</>}
    </Panel>
  </section>
}
