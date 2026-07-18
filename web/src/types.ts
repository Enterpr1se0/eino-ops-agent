export type Risk = 'read_only' | 'change' | 'critical' | 'forbidden'

export type HostAuthType = 'agent' | 'key' | 'password' | 'ssh_config'
export type HostSudoMode = 'none' | 'nopasswd' | 'password'

export interface Host {
  id: string
  name: string
  address: string
  port: number
  user: string
  auth_type: HostAuthType
  config_alias?: string
  identity_file?: string
  known_hosts_file?: string
  proxy_jump?: string
  has_password: boolean
  sudo_mode: HostSudoMode
  has_sudo_password: boolean
  created_at: string
  updated_at: string
}

export interface HostInput {
  id?: string
  name: string
  address: string
  port: number
  user: string
  auth_type: HostAuthType
  config_alias: string
  identity_file: string
  known_hosts_file: string
  proxy_jump: string
  password: string
  sudo_mode: HostSudoMode
  sudo_password: string
}

export interface Approval {
  id: string
  run_id: string
  session_id?: string
  host_id: string
  request_json: string
  request_digest: string
  risk: Risk
  status: string
  challenge?: string
  reason?: string
  ai_review?: CommandReview
  created_at: string
  expires_at: string
}

export interface ApprovalExecutionResult {
  run_id: string
  status: string
  risk: Risk
  operator_instruction?: string
  exit_code?: number
  stdout?: string
  stderr?: string
}

export interface Run {
  id: string
  session_id?: string
  host_id: string
  request_json: string
  risk: Risk
  status: string
  exit_code: number
  stdout_redacted?: string
  stderr_redacted?: string
  error?: string
  ai_review?: CommandReview
  started_at: string
  completed_at?: string
}

export interface CommandExplanation {
  summary: string
  mechanism: string
  effects: string[]
  risks: string[]
  beginner_tips: string[]
  rollback_guide: string
}

export interface AIRiskReview {
  risk: Risk
  recommendation: 'allow' | 'human_required' | 'deny'
  confidence: number
  reasons: string[]
  missing_evidence: string[]
  required_controls: string[]
}

export interface CommandReview {
  status: 'completed' | 'degraded' | 'unavailable'
  model?: string
  deterministic_risk: Risk
  effective_risk: Risk
  explanation?: CommandExplanation
  risk_review?: AIRiskReview
  errors?: string[]
  reviewed_at: string
}

export interface ServerLogEntry {
  time: string
  level: string
  message: string
  component?: string
  fields?: Record<string, unknown>
}

export interface ServerLogResponse {
  entries: ServerLogEntry[]
  components: string[]
  minimum_level: string
  file?: string
}

export interface AgentEvent {
  type: string
  role?: string
  tool_name?: string
  content?: string
  segment_id?: string
  session_id?: string
  error?: string
  approval_id?: string
  status?: string
  risk?: Risk
  challenge?: string
}

export interface ChatSession {
  id: string
  title: string
  message_count: number
  updated_at: string
}

export interface ChatMessage {
  role: 'user' | 'assistant' | 'tool' | 'reasoning'
  content: string
  tool_name?: string
  created_at: string
}

export interface AgentPlanStep {
  number: number
  title: string
  status: 'pending' | 'in_progress' | 'completed' | 'blocked'
  evidence?: string
  updated_at: string
}

export interface AgentPlan {
  session_id: string
  goal: string
  status: 'active' | 'completed' | 'blocked'
  steps: AgentPlanStep[]
  created_at: string
  updated_at: string
}

export interface ChatState {
  active: boolean
  messages: ChatMessage[]
  plan?: AgentPlan | null
}

export type ModelProviderKind = 'openai' | 'deepseek' | 'openai_compatible' | 'ollama'

export interface ModelProvider {
  id: string
  name: string
  kind: ModelProviderKind
  base_url?: string
  model: string
  has_api_key: boolean
  active: boolean
  created_at: string
  updated_at: string
}

export interface ModelProviderInput {
  id?: string
  name: string
  kind: ModelProviderKind
  base_url: string
  model: string
  api_key: string
}

export interface ModelDiscoveryInput {
  id?: string
  kind: ModelProviderKind
  base_url: string
  api_key: string
}

export interface ModelTestInput extends ModelDiscoveryInput {
  model: string
}

export interface ModelCatalog {
  models: string[]
  count: number
}

export interface ModelStatus {
  available: boolean
  review_agents_available: boolean
  source: 'database' | 'environment' | 'none'
  provider_id?: string
  name?: string
  model?: string
  error?: string
}

export interface ModelTestResult {
  provider_id?: string
  name?: string
  model: string
  response: string
  latency_ms: number
}

export interface Health {
  status: string
  agent_available: boolean
  model: ModelStatus
  time: string
}

export interface SystemSettings {
  agent_max_iterations: number
  subagent_reviews_enabled: boolean
  beginner_explanations_enabled: boolean
  updated_at: string
}

export interface SystemSettingsInput {
  agent_max_iterations: number
  subagent_reviews_enabled?: boolean
  beginner_explanations_enabled?: boolean
}

export interface AuthSession {
  authenticated: boolean
  csrf_token: string
  expires_at: string
}

export interface FileMetadata {
	operation_id?: string
  path: string
  size?: number
  mode?: string
  owner?: string
  group?: string
  modified_unix?: number
  sha256?: string
  before_sha256?: string
  backup_path?: string
  validator?: string
  validation_ok?: boolean
  sensitive?: boolean
  offset_bytes?: number
  returned_bytes?: number
}

export interface WorkspaceCapability {
  id: string
  access: 'read_only' | 'read_write'
  validators?: string[]
  root?: string
}

export interface WorkspaceUploadResult {
  workspace_id: string
  path: string
  size: number
  sha256: string
}

export interface WorkspaceFileEntry {
  name: string
  type: 'file' | 'directory'
  size?: number
}

export interface WorkspaceFileList {
  workspace_id: string
  path: string
  entries: WorkspaceFileEntry[]
  truncated?: boolean
}

export interface WorkspaceFilePreview {
  workspace_id: string
  path: string
  size: number
  sha256: string
  content?: string
  truncated?: boolean
  binary?: boolean
}

export interface WorkspaceDeleteResult {
  workspace_id: string
  path: string
  size: number
  sha256: string
  trash_id: string
  recoverable: boolean
}

export interface ToolCapabilities {
  workspaces: WorkspaceCapability[]
}
