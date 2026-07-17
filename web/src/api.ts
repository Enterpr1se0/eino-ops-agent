import type { AgentEvent, Approval, ApprovalExecutionResult, ChatMessage, ChatSession, ChatState, Health, Host, HostInput, ModelCatalog, ModelDiscoveryInput, ModelProvider, ModelProviderInput, ModelTestInput, ModelTestResult, Run, ServerLogResponse, SystemSettings, SystemSettingsInput } from './types'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init?.headers || {}) },
  })
  if (!response.ok) {
    const body = await response.json().catch(() => ({ error: response.statusText }))
    throw new Error(body.error || response.statusText)
  }
  if (response.status === 204) return undefined as T
  return response.json()
}

async function requestList<T>(path: string): Promise<T[]> {
  const value = await request<T[] | null>(path)
  return Array.isArray(value) ? value : []
}

export const api = {
  health: () => request<Health>('/api/v1/health'),
  systemSettings: () => request<SystemSettings>('/api/v1/settings'),
  saveSystemSettings: (settings: SystemSettingsInput) => request<SystemSettings>('/api/v1/settings', { method: 'PUT', body: JSON.stringify(settings) }),
  modelProviders: () => requestList<ModelProvider>('/api/v1/model-providers'),
  discoverModels: (input: ModelDiscoveryInput) => request<ModelCatalog>('/api/v1/model-providers/discover', { method: 'POST', body: JSON.stringify(input) }),
  testModelConfiguration: (input: ModelTestInput) => request<ModelTestResult>('/api/v1/model-providers/test', { method: 'POST', body: JSON.stringify(input) }),
  saveModelProvider: (provider: ModelProviderInput) => request<ModelProvider>('/api/v1/model-providers', { method: 'POST', body: JSON.stringify(provider) }),
  activateModelProvider: (id: string) => request<ModelProvider>(`/api/v1/model-providers/${id}/activate`, { method: 'POST', body: '{}' }),
  deleteModelProvider: (id: string) => request<void>(`/api/v1/model-providers/${id}`, { method: 'DELETE' }),
  testModelProvider: (id: string) => request<ModelTestResult>(`/api/v1/model-providers/${id}/test`, { method: 'POST', body: '{}' }),
  hosts: () => requestList<Host>('/api/v1/hosts'),
  saveHost: (host: HostInput) => request<Host>('/api/v1/hosts', { method: 'POST', body: JSON.stringify(host) }),
  deleteHost: (id: string) => request<void>(`/api/v1/hosts/${id}`, { method: 'DELETE' }),
  scanKey: (id: string) => request<{ fingerprint: string }>(`/api/v1/hosts/${id}/scan-key`, { method: 'POST', body: '{}' }),
  trustKey: (id: string, fingerprint: string) => request(`/api/v1/hosts/${id}/trust-key`, { method: 'POST', body: JSON.stringify({ fingerprint }) }),
  probe: (id: string) => request<Record<string, string>>(`/api/v1/hosts/${id}/probe`, { method: 'POST', body: '{}' }),
  approvals: () => requestList<Approval>('/api/v1/approvals?status=pending&limit=100'),
  approve: (id: string, challenge: string, reason: string, scope: 'once'|'session' = 'once') => request<ApprovalExecutionResult>(`/api/v1/approvals/${id}/approve`, { method: 'POST', body: JSON.stringify({ challenge, reason, scope }) }),
  reject: (id: string, reason: string) => request(`/api/v1/approvals/${id}/reject`, { method: 'POST', body: JSON.stringify({ reason }) }),
  runs: (query = '') => requestList<Run>(`/api/v1/runs?limit=100&q=${encodeURIComponent(query)}`),
  logs: (filters: {level?:string;component?:string;q?:string;limit?:number} = {}) => {
    const params=new URLSearchParams()
    if(filters.level)params.set('level',filters.level)
    if(filters.component)params.set('component',filters.component)
    if(filters.q)params.set('q',filters.q)
    params.set('limit',String(filters.limit||500))
    return request<ServerLogResponse>(`/api/v1/logs?${params}`)
  },
  chatSessions: () => requestList<ChatSession>('/api/v1/chat/sessions?limit=50'),
  chatMessages: (id: string) => requestList<ChatMessage>(`/api/v1/chat/${encodeURIComponent(id)}/messages?limit=200`),
  chatState: (id: string) => request<ChatState>(`/api/v1/chat/${encodeURIComponent(id)}/state`),
  deleteChatSession: (id: string) => request<void>(`/api/v1/chat/${encodeURIComponent(id)}`, { method: 'DELETE' }),
}

export async function streamChat(sessionId: string, message: string, onEvent: (event: AgentEvent) => void) {
  const response = await fetch('/api/v1/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId, message }),
  })
  if (!response.ok || !response.body) {
    const body = await response.json().catch(() => ({ error: response.statusText }))
    throw new Error(body.error || response.statusText)
  }
  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  while (true) {
    const { value, done } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    const frames = buffer.split('\n\n')
    buffer = frames.pop() || ''
    for (const frame of frames) {
      const line = frame.split('\n').find((part) => part.startsWith('data: '))
      if (!line) continue
      onEvent(JSON.parse(line.slice(6)))
    }
  }
}
