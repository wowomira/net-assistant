/** Switch API wire types. No demo fallback, credential fields, or write calls. */
export interface Capability {
  state: string
  reasonCode?: string | null
  columns?: Record<string, { state: string; reasonCode: string | null }>
}
export interface SwitchInterface {
  ifIndex: number
  name: string | null
  description: string | null
  alias: string | null
  ifType: number | null
  mac: string | null
  adminStatus: string
  operStatus: string
  speedMbps: number | null
  inOctets: string | null
  outOctets: string | null
}
export interface ForwardingEntry {
  mac: string
  bridgePort: number | null
  ifIndex: number | null
  fdbId: number | null
  vlanIds: number[]
  status: string
  source: string
}
export interface LldpEntry {
  localPortNumber: number
  localIfIndex: number | null
  remoteIndex: number
  remoteChassisId: string | null
  remoteChassisSubtype: number | null
  remotePortId: string | null
  remotePortSubtype: number | null
  remoteSystemName: string | null
}
export interface SwitchSnapshot {
  source: string
  observedAt: string
  system: {
    name: string | null
    objectId: string
    description?: string | null
    location?: string | null
    uptimeSeconds?: number | null
  }
  interfaces: SwitchInterface[]
  forwarding: ForwardingEntry[]
  lldp: LldpEntry[]
  capabilities: Record<string, Capability>
}
export interface SwitchRun {
  id: string
  deviceId: string | null
  address: string
  profileId: string
  state: string
  startedAt: string
  finishedAt: string | null
  errorCode: string | null
  snapshot: SwitchSnapshot | null
}
export interface SwitchDevice {
  id: string
  name: string
  address: string
  objectId: string
  vendor: string
  deviceKind: 'switch_product' | 'unverified_network_device'
  assetId: string | null
  identityVerified: false
  firstSeenAt: string
  lastSeenAt: string
  latest: SwitchRun | null
}
export interface SwitchStatus {
  configured: boolean
  state: string
  reasonCode: string | null
  heartbeatAt: string | null
  nextDueAt: string | null
  intervalSeconds?: number
  readyProfileCount?: number | null
  targetCount?: number
  lastCycle: {
    state: string
    finishedAt: string
    counts: Record<string, number>
  } | null
}
