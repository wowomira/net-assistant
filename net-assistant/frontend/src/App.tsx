import { useState } from 'react'
import { type Asset, type Job, type Scheduler, getJson, readCatalog } from './api'
import { useRead } from './components'
import { AssetsView } from './AssetsView'
import { EvidenceView, ScansView } from './DiscoveryView'
import { SchedulerView } from './SchedulerView'
import { SwitchesView } from './SwitchesView'

const pages = [
  { id: 'assets', label: '资产台账' },
  { id: 'scans', label: '扫描批次' },
  { id: 'evidence', label: '探测证据' },
  { id: 'scheduler', label: '每日调度' },
  { id: 'switches', label: '交换机接入' },
] as const
type PageId = typeof pages[number]['id']

export default function App() {
  const [page, setPage] = useState<PageId>('assets')
  const [version, setVersion] = useState(0)
  const [evidence, setEvidence] = useState({ jobId: '', address: '', revision: 0 })
  const assets = useRead('assets', version, signal => readCatalog<Asset>('/assets', signal))
  const jobs = useRead('jobs', version, signal => readCatalog<Job>('/discovery-jobs', signal))
  const scheduler = useRead('scheduler', version, signal => getJson<Scheduler>('/scheduler', signal))
  const current = pages.find(item => item.id === page)!
  const loading = assets.loading || jobs.loading || scheduler.loading
  const showEvidence = (jobId: string, address: string) => {
    setEvidence(previous => ({ jobId, address, revision: previous.revision + 1 }))
    setPage('evidence')
    document.getElementById('main-title')?.focus()
  }
  return <div className="demo">
    <a className="skip-link" href="#main-content">跳到主要内容</a>
    <main id="main-content">
      <header className="page-header"><div><strong>网维助手</strong>
      </div><div className="header-actions">
        <button className="primary refresh" onClick={() => setVersion(version + 1)} disabled={loading}
          aria-label="刷新数据">{loading ? '读取中…' : '↻ 刷新数据'}</button></div></header>
      <nav aria-label="数据分类" className="tabs">{pages.map(item => <button key={item.id}
        className={page === item.id ? 'active' : ''} aria-current={page === item.id ? 'page' : undefined}
        onClick={() => setPage(item.id)}>{item.label}</button>)}</nav>
      <h1 id="main-title" tabIndex={-1}>{current.label}</h1>
      {page === 'assets' && <AssetsView assets={assets} version={version} onEvidence={showEvidence} />}
      {page === 'scans' && <ScansView jobs={jobs} version={version} onEvidence={showEvidence} />}
      {page === 'evidence' && <EvidenceView key={evidence.revision} jobs={jobs} version={version}
        initialJob={evidence.jobId} initialAddress={evidence.address} />}
      {page === 'scheduler' && <SchedulerView scheduler={scheduler} version={version} onJob={showEvidence} />}
      {page === 'switches' && <SwitchesView version={version} />}
    </main>
  </div>
}
