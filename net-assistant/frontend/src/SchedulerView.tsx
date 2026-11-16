import { type ScheduledRun, type Scheduler, readCatalog } from './api'
import { Badge, CatalogNote, Empty, Facts, Panel, Raw, ReadState, Table, useRead, type Resource } from './components'
import { formatTime, newestFirst } from './model'

export function SchedulerView({ scheduler, version, onJob }: {
  scheduler: Resource<Scheduler>; version: number; onJob: (id: string, address: string) => void
}) {
  const runs = useRead('scheduled-runs', version, signal => readCatalog<ScheduledRun>('/scheduler/runs', signal))
  const data = scheduler.data
  return <>
    <Panel title="每日调度状态">
      <ReadState value={scheduler} />
      {data && <>
        {!data.configured || !data.schedule ? <Empty>未配置每日计划</Empty> :
          <Facts rows={[
            ['计划名称', data.schedule.name],
            ['启用', data.schedule.enabled ? '是' : '否'],
            ['每日时刻', `${data.schedule.dailyAt}（UTC 偏移 ${data.schedule.utcOffsetMinutes} 分钟）`],
            ['下次应执行', formatTime(data.schedule.nextDueAt)],
            ['今日状态', <Badge value={data.todayStatus} />],
            ['接口核对时间', formatTime(data.checkedAt)],
          ]} />}
        <Facts rows={[
          ['工作进程', <Badge value={data.worker.state} />],
          ['最后心跳', formatTime(data.worker.heartbeatAt)],
          ['数据库读取', <Badge value={data.database.state} />],
          ['最近调度调用', data.worker.lastInvocation ? <Badge value={data.worker.lastInvocation.status} /> : '暂无'],
        ]} />
        <Raw value={data} label="原始返回 JSON" />
      </>}
    </Panel>
    <Panel title="每日执行记录">
      <ReadState value={runs} />
      {runs.data && <><CatalogNote catalog={runs.data} />
        {!runs.data.items.length ? <Empty>暂无每日执行记录。</Empty> :
          <Table label="每日自动扫描记录"><thead><tr><th>计划日期 / 名称</th><th>状态</th>
            <th>开始 / 结束</th><th>扫描批次</th></tr></thead><tbody>
            {newestFirst(runs.data.items).map(run => <tr key={run.id}>
              <td>{run.localDate}<small className="subline">{run.scheduleName}</small></td>
              <td><Badge value={run.state} /><code className="subline">{run.errorCode}</code></td>
              <td>{formatTime(run.startedAt)}<span className="subline">{formatTime(run.finishedAt)}</span></td>
              <td>{run.jobId ? <button className="text-button" onClick={() => onJob(run.jobId!, '')}>{run.jobId}</button> : '暂无'}</td>
            </tr>)}
          </tbody></Table>}
        <Raw value={runs.data.items} label="原始记录 JSON" /></>}
    </Panel>
  </>
}
