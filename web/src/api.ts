import type { AgentEvent, Approval, ApprovalExecutionResult, AuthSession, ChatMessage, ChatSession, ChatState, Health, Host, HostInput, LLMToolCatalog, ManagedSkill, MCPServer, MCPServerInput, MCPTestResult, ModelCatalog, ModelDiscoveryInput, ModelProvider, ModelProviderInput, ModelTestInput, ModelTestResult, Run, ServerLogResponse, SystemSettings, SystemSettingsInput, ToolCapabilities, WorkspaceDeleteResult, WorkspaceFileList, WorkspaceFilePreview, WorkspaceUploadResult } from './types'

let csrfToken = ''

function rememberAuth(session: AuthSession | null) { csrfToken = session?.csrf_token || '' }

async function request<T>(path: string, init?: RequestInit): Promise<T> {
	const method=(init?.method||'GET').toUpperCase()
	const multipart=typeof FormData!=='undefined'&&init?.body instanceof FormData
	const headers:Record<string,string> = { ...(multipart?{}:{'Content-Type':'application/json'}), ...(init?.headers as Record<string,string> || {}) }
	if(!['GET','HEAD','OPTIONS'].includes(method)&&csrfToken)headers['X-CSRF-Token']=csrfToken
  const response = await fetch(path, {
    ...init,
	credentials:'same-origin',
	headers,
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
	authSession: async()=>{const session=await request<AuthSession>('/api/v1/auth/session');rememberAuth(session);return session},
	login: async(password:string)=>{const session=await request<AuthSession>('/api/v1/auth/login',{method:'POST',body:JSON.stringify({password})});rememberAuth(session);return session},
	logout: async()=>{await request<void>('/api/v1/auth/logout',{method:'POST',body:'{}'});rememberAuth(null)},
	changePassword: async(currentPassword:string,newPassword:string)=>{const result=await request<{changed:boolean;login_required:boolean}>('/api/v1/auth/password',{method:'PUT',body:JSON.stringify({current_password:currentPassword,new_password:newPassword})});rememberAuth(null);return result},
  health: () => request<Health>('/api/v1/health'),
	systemSettings: () => request<SystemSettings>('/api/v1/settings'),
	capabilities: () => request<ToolCapabilities>('/api/v1/capabilities'),
	llmTools: () => request<LLMToolCatalog>('/api/v1/agent/tools'),
	setLLMToolEnabled: (name:string,enabled:boolean) => request<LLMToolCatalog>(`/api/v1/agent/tools/${encodeURIComponent(name)}/${enabled?'enable':'disable'}`,{method:'POST',body:'{}'}),
	skills: () => requestList<ManagedSkill>('/api/v1/skills'),
	skill: (name:string) => request<ManagedSkill>(`/api/v1/skills/${encodeURIComponent(name)}`),
	uploadSkill: (name:string,file:File) => {const body=new FormData();body.set('name',name);body.set('file',file);return request<ManagedSkill>('/api/v1/skills',{method:'POST',body})},
	saveSkill: (name:string,content:string) => request<ManagedSkill>(`/api/v1/skills/${encodeURIComponent(name)}`,{method:'PUT',body:JSON.stringify({content})}),
	deleteSkill: (name:string) => request<void>(`/api/v1/skills/${encodeURIComponent(name)}`,{method:'DELETE'}),
	setSkillEnabled: (name:string,enabled:boolean) => request<ManagedSkill>(`/api/v1/skills/${encodeURIComponent(name)}/${enabled?'enable':'disable'}`,{method:'POST',body:'{}'}),
	mcpServers: () => requestList<MCPServer>('/api/v1/mcp-servers'),
	saveMCPServer: (server:MCPServerInput) => server.id
		? request<MCPServer>(`/api/v1/mcp-servers/${encodeURIComponent(server.id)}`,{method:'PUT',body:JSON.stringify(server)})
		: request<MCPServer>('/api/v1/mcp-servers',{method:'POST',body:JSON.stringify(server)}),
	deleteMCPServer: (id:string) => request<void>(`/api/v1/mcp-servers/${encodeURIComponent(id)}`,{method:'DELETE'}),
	setMCPServerEnabled: (id:string,enabled:boolean) => request<MCPServer>(`/api/v1/mcp-servers/${encodeURIComponent(id)}/${enabled?'enable':'disable'}`,{method:'POST',body:'{}'}),
	retryMCPServer: (id:string) => request<MCPServer>(`/api/v1/mcp-servers/${encodeURIComponent(id)}/retry`,{method:'POST',body:'{}'}),
	testMCPServer: (id:string) => request<MCPTestResult>(`/api/v1/mcp-servers/${encodeURIComponent(id)}/test`,{method:'POST',body:'{}'}),
	workspaceFiles: (workspaceId:string,path='.') => request<WorkspaceFileList>(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/files?path=${encodeURIComponent(path)}`),
	previewWorkspaceFile: (workspaceId:string,path:string) => request<WorkspaceFilePreview>(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/preview?path=${encodeURIComponent(path)}`),
	uploadWorkspaceFile: (workspaceId:string,file:File,path:string) => {const body=new FormData();body.set('file',file);body.set('path',path);return request<WorkspaceUploadResult>(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/files`,{method:'POST',body})},
	deleteWorkspaceEntry: (workspaceId:string,path:string) => request<WorkspaceDeleteResult>(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/files?path=${encodeURIComponent(path)}`,{method:'DELETE'}),
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
  scanKey: (id: string) => request<{ fingerprint: string; algorithm?: string }>(`/api/v1/hosts/${id}/scan-key`, { method: 'POST', body: '{}' }),
  trustKey: (id: string, fingerprint: string) => request(`/api/v1/hosts/${id}/trust-key`, { method: 'POST', body: JSON.stringify({ fingerprint }) }),
  probe: (id: string) => request<Record<string, string>>(`/api/v1/hosts/${id}/probe`, { method: 'POST', body: '{}' }),
  approvals: () => requestList<Approval>('/api/v1/approvals?status=pending&limit=100'),
  retryApprovalExplanation: (id: string) => request<Approval>(`/api/v1/approvals/${id}/explanation/retry`, { method: 'POST', body: '{}' }),
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

export async function streamChat(sessionId: string, message: string, onEvent: (event: AgentEvent) => void, signal?: AbortSignal) {
  const response = await fetch('/api/v1/chat', {
    method: 'POST',
	credentials:'same-origin',
	headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
    body: JSON.stringify({ session_id: sessionId, message }),
    signal,
  })
  if (!response.ok || !response.body) {
    const body = await response.json().catch(() => ({ error: response.statusText }))
    throw new Error(body.error || response.statusText)
  }
  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  let terminalEventReceived = false
  let flushTimer: number | undefined
  let pending: AgentEvent[] = []

  const flushPending = () => {
    if (flushTimer !== undefined) window.clearTimeout(flushTimer)
    flushTimer = undefined
    const events = pending
    pending = []
    for (const event of events) onEvent(event)
  }
  const isContentDelta = (event: AgentEvent) =>
    !!event.content && (event.type === 'reasoning' || (event.type === 'message' && event.role !== 'tool'))
  const sameContentStream = (left: AgentEvent, right: AgentEvent) =>
    left.type === right.type && left.role === right.role && left.tool_name === right.tool_name &&
    left.segment_id === right.segment_id && left.session_id === right.session_id
  const dispatch = (event: AgentEvent) => {
    if (event.type === 'done' || event.type === 'error') terminalEventReceived = true
    if (!isContentDelta(event)) {
      flushPending()
      onEvent(event)
      return
    }
    const previous = pending.at(-1)
    if (previous && sameContentStream(previous, event)) {
      previous.content = (previous.content || '') + event.content
    } else {
      pending.push({ ...event })
    }
    if (flushTimer === undefined) flushTimer = window.setTimeout(flushPending, 40)
  }
  const processFrame = (frame: string) => {
    const data = frame.split('\n')
      .filter((line) => line.startsWith('data:'))
      .map((line) => line.slice(5).replace(/^ /, ''))
      .join('\n')
    if (!data) return // SSE comments are connection/heartbeat frames.
    dispatch(JSON.parse(data) as AgentEvent)
  }

  try {
    while (true) {
      const { value, done } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })
      buffer = buffer.replace(/\r\n/g, '\n')
      let boundary = buffer.indexOf('\n\n')
      while (boundary >= 0) {
        processFrame(buffer.slice(0, boundary))
        buffer = buffer.slice(boundary + 2)
        boundary = buffer.indexOf('\n\n')
      }
    }
    buffer += decoder.decode()
  } finally {
    flushPending()
  }
  if (buffer.trim()) throw new Error('SSE stream ended with an incomplete event')
  if (!terminalEventReceived) throw new Error('SSE stream ended before the Agent sent a terminal event')
}
