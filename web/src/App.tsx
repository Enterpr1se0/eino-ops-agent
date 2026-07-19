import { FormEvent, memo, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import Markdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import {
  Activity, BookOpen, Bot, BrainCircuit, Braces, Check, ChevronRight, CircleDot, Clock3, Cpu, Edit3, FileText, FolderOpen, FunctionSquare, History, KeyRound, LockKeyhole, LogOut,
  ListChecks, LoaderCircle, Plus, Power, RefreshCw, Save, Search, Send, Server, Settings2, ShieldAlert, ShieldCheck, SlidersHorizontal, TerminalSquare, Trash2, UploadCloud, X, Zap,
} from 'lucide-react'
import { api, streamChat } from './api'
import type { AgentEvent, AgentPlan, Approval, ChatMessage, ChatSession, CommandReview, Health, Host, HostAuthType, HostInput, HostSudoMode, LLMToolCatalog, LLMToolDescriptor, LLMToolGuard, ManagedSkill, MCPServer, MCPServerInput, MCPTransport, ModelProvider, ModelProviderInput, ModelProviderKind, Run, ServerLogEntry, SystemSettings, ToolCapabilities, WorkspaceCapability, WorkspaceFilePreview, WorkspaceShellMode } from './types'

type Page = 'chat' | 'config' | 'extensions' | 'audit' | 'logs'
type ChatEntry = { id: string; kind: 'user' | 'assistant' | 'tool' | 'reasoning' | 'error'; content: string; tool?: string; active?: boolean; streaming?: boolean; status?: 'pending' | 'completed' | 'failed' }
type ActiveChatStream = { id: string; sessionId: string; controller: AbortController }

function historyEntries(messages:ChatMessage[]):ChatEntry[]{
  return messages.map((item,index)=>({id:`history_${index}_${item.created_at}`,kind:item.role,content:item.content,tool:item.tool_name,status:item.status}))
}

function deactivateReasoning(entry:ChatEntry):ChatEntry{
	return entry.kind==='reasoning'&&entry.active?{...entry,active:false}:entry
}

function planFromToolContent(content:string):AgentPlan|null{
  try{const value=JSON.parse(content) as AgentPlan&{found?:boolean;plan?:AgentPlan};const plan=value?.plan||value;return plan&&typeof plan.goal==='string'&&Array.isArray(plan.steps)?plan:null}catch{return null}
}

let clientIdCounter = 0
function clientId() {
  try {
    if (typeof globalThis.crypto?.randomUUID === 'function') return globalThis.crypto.randomUUID()
    const random = new Uint32Array(2)
    globalThis.crypto?.getRandomValues(random)
    if (random[0] || random[1]) return `client_${random[0].toString(36)}${random[1].toString(36)}`
  } catch { /* insecure or legacy browser: rendering keys do not require cryptographic randomness */ }
  clientIdCounter += 1
  return `client_${Date.now().toString(36)}_${clientIdCounter.toString(36)}_${Math.random().toString(36).slice(2)}`
}

function errorText(error: unknown) {
  const message = error instanceof Error ? error.message : String(error)
  if (/failed to fetch|networkerror|load failed/i.test(message)) {
    return 'Cannot reach the OpsPilot API. Check that the server is running on port 8080, then retry.'
  }
  if (message.includes('model provider request failed')) {
    return `Cannot reach the model provider. Check its Base URL, network, and service status. ${message}`
  }
  return message
}

const newSessionMarker = '__new__'
function rememberSession(id: string) { try { localStorage.setItem('opspilot.activeSession', id) } catch { /* storage may be disabled */ } }
function recalledSession() { try { return localStorage.getItem('opspilot.activeSession') || '' } catch { return '' } }

function App() {
	const [auth,setAuth]=useState<'checking'|'authenticated'|'guest'>('checking')
  const [page, setPage] = useState<Page>('chat')
  const [health, setHealth] = useState<Health | null>(null)
  const [hosts, setHosts] = useState<Host[]>([])
  const [providers, setProviders] = useState<ModelProvider[]>([])
  const [settings, setSettings] = useState<SystemSettings | null>(null)
	const [capabilities,setCapabilities]=useState<ToolCapabilities>({workspaces:[]})
	const [toolCatalog,setToolCatalog]=useState<LLMToolCatalog|null>(null)
	const [skills,setSkills]=useState<ManagedSkill[]>([])
	const [mcpServers,setMCPServers]=useState<MCPServer[]>([])
  const [approvals, setApprovals] = useState<Approval[]>([])
  const [runs, setRuns] = useState<Run[]>([])
  const [error, setError] = useState('')
	const [agentStreaming,setAgentStreaming]=useState(false)

  const refresh = useCallback(async () => {
    try {
	  const [nextHealth, nextHosts, nextProviders, nextSettings, nextCapabilities, nextToolCatalog, nextSkills, nextMCPServers, nextApprovals, nextRuns] = await Promise.all([
		api.health(), api.hosts(), api.modelProviders(), api.systemSettings(), api.capabilities(), api.llmTools(), api.skills(), api.mcpServers(), api.approvals(), api.runs(),
      ])
	  setHealth(nextHealth); setHosts(nextHosts); setProviders(nextProviders); setSettings(nextSettings);setCapabilities(nextCapabilities);setToolCatalog(nextToolCatalog);setSkills(nextSkills);setMCPServers(nextMCPServers); setApprovals(nextApprovals); setRuns(nextRuns); setError('')
	} catch (err) { const message=errorText(err);if(/authentication required/i.test(message))setAuth('guest');setError(message) }
  }, [])
	const refreshApprovals=useCallback(async()=>{
		try{setApprovals(await api.approvals())}
		catch(err){const message=errorText(err);if(/authentication required/i.test(message))setAuth('guest');setError(message)}
	},[])

	useEffect(()=>{api.authSession().then(()=>setAuth('authenticated')).catch(()=>setAuth('guest'))},[])
	useEffect(() => { if(auth==='authenticated')void refresh() }, [auth,refresh])
	useEffect(() => {
		if(auth!=='authenticated'||agentStreaming)return
		const timer=window.setInterval(()=>{if(document.visibilityState==='visible')void refresh()},10000)
		return()=>window.clearInterval(timer)
	},[auth,agentStreaming,refresh])

	if(auth==='checking')return <div className="auth-screen"><div className="auth-loading"><LoaderCircle className="spin" size={25}/><span>Securing control plane…</span></div></div>
	if(auth==='guest')return <LoginPage onAuthenticated={()=>setAuth('authenticated')}/>

  const title = { chat: 'Agent Workspace', config: 'Configuration Center', extensions: 'Agent Extensions', audit: 'Audit Explorer', logs: 'Server Logs' }[page]

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><TerminalSquare size={23}/></div><div><strong>OpsPilot</strong><span>SSH CONTROL PLANE</span></div></div>
      <nav>
        <Nav active={page === 'chat'} icon={<Bot/>} label="Agent" onClick={() => setPage('chat')}/>
        <Nav active={page === 'config'} icon={<Settings2/>} label="Configuration" onClick={() => setPage('config')}/>
		<Nav active={page === 'extensions'} icon={<Braces/>} label="Extensions" onClick={() => setPage('extensions')}/>
        <Nav active={page === 'audit'} icon={<History/>} label="Audit" onClick={() => setPage('audit')}/>
        <Nav active={page === 'logs'} icon={<FileText/>} label="Logs" onClick={() => setPage('logs')}/>
      </nav>
      <div className="sidebar-foot">
        <div className="security-card"><ShieldCheck size={18}/><div><b>Policy enforced</b><span>Every action is audited</span></div></div>
		<button className="logout-button" onClick={async()=>{try{await api.logout()}finally{setAuth('guest')}}}><LogOut size={15}/>Sign out</button>
        <div className="build">v0.1.0 · LOCAL MODE</div>
      </div>
    </aside>
    <main>
      <header className="topbar"><div><span className="eyebrow">OPS / {page.toUpperCase()}</span><h1>{title}</h1></div><div className="top-actions">
        <span className={`status ${health?.status === 'ok' ? 'online' : ''}`}><CircleDot size={14}/>{health?.status === 'ok' ? 'Control plane online' : 'Disconnected'}</span>
        <button className="icon-button" onClick={refresh} title="Refresh"><RefreshCw size={17}/></button>
      </div></header>
      {error && <div className="global-error"><ShieldAlert size={17}/>{error}<button onClick={() => setError('')}><X size={15}/></button></div>}
      <section className="workspace">
		{page === 'chat' && <ChatPage hosts={hosts} approvals={approvals} runs={runs} capabilities={capabilities} agentAvailable={!!health?.agent_available} modelName={health?.model?.model} refresh={refresh} refreshApprovals={refreshApprovals} onStreamingChange={setAgentStreaming}/>}
		{page === 'config' && <ConfigurationPage hosts={hosts} providers={providers} settings={settings} capabilities={capabilities} health={health} refresh={refresh}/>}
		{page === 'extensions' && <ExtensionsPage skills={skills} mcpServers={mcpServers} toolCatalog={toolCatalog} refresh={refresh}/>}
        {page === 'audit' && <AuditPage runs={runs}/>} 
        {page === 'logs' && <LogsPage/>}
      </section>
    </main>
  </div>
}

function LoginPage({onAuthenticated}:{onAuthenticated:()=>void}){
	const [password,setPassword]=useState('')
	const [busy,setBusy]=useState(false)
	const [error,setError]=useState('')
	const submit=async(event:FormEvent)=>{event.preventDefault();setBusy(true);setError('');try{await api.login(password);setPassword('');onAuthenticated()}catch(err){setError(errorText(err))}finally{setBusy(false)}}
	return <div className="auth-screen"><section className="login-card"><div className="login-mark"><TerminalSquare size={29}/></div><span>OPS PILOT · SECURE CONTROL PLANE</span><h1>Administrator sign in</h1><p>SSH credentials, approvals, logs and workspace operations are protected by the local administrator session.</p><form onSubmit={submit}><label><span>Administrator password</span><div className="login-input"><LockKeyhole size={17}/><input type="password" autoComplete="current-password" value={password} onChange={event=>setPassword(event.target.value)} autoFocus required/></div></label>{error&&<div className="login-error"><ShieldAlert size={15}/>{error}</div>}<button className="primary" disabled={busy||password.length===0}>{busy?<LoaderCircle className="spin" size={17}/>:<ShieldCheck size={17}/>}<span>{busy?'Authenticating…':'Enter control plane'}</span></button></form><small>Initial password: <code>OPS_AGENT_ADMIN_PASSWORD</code></small></section></div>
}

type ConfigurationSection = 'models' | 'hosts' | 'system'

function ConfigurationPage({hosts,providers,settings,capabilities,health,refresh}:{hosts:Host[];providers:ModelProvider[];settings:SystemSettings|null;capabilities:ToolCapabilities;health:Health|null;refresh:()=>Promise<void>}) {
  const [section,setSection]=useState<ConfigurationSection>('models')
  const tabs:[ConfigurationSection,React.ReactNode,string,string][]=[
    ['models',<Cpu size={17}/>, 'Model providers', `${providers.length} configured`],
    ['hosts',<Server size={17}/>, 'SSH hosts', `${hosts.length} registered`],
    ['system',<SlidersHorizontal size={17}/>, 'System settings', `${settings?.agent_max_iterations??50} max iterations`],
  ]
  return <div className="configuration-center page-stack">
    <section className="configuration-hero panel"><div><span>CONTROL PLANE CONFIGURATION</span><h2>One place for every Agent dependency</h2><p>Manage inference, remote access and runtime safeguards without editing local files.</p></div><dl><div><dt>Active model</dt><dd>{health?.model?.model||'Not configured'}</dd></div><div><dt>SSH targets</dt><dd>{hosts.length}</dd></div><div><dt>Loop budget</dt><dd>{settings?.agent_max_iterations??50} rounds</dd></div></dl></section>
    <div className="configuration-tabs" role="tablist" aria-label="Configuration sections">{tabs.map(([id,icon,label,meta])=><button type="button" role="tab" aria-selected={section===id} className={section===id?'active':''} onClick={()=>setSection(id)} key={id}>{icon}<span><b>{label}</b><small>{meta}</small></span><ChevronRight size={15}/></button>)}</div>
    <div className="configuration-content" role="tabpanel">
      {section==='models'&&<ModelsPage providers={providers} health={health} refresh={refresh}/>} 
      {section==='hosts'&&<HostsPage hosts={hosts} refresh={refresh}/>}
	  {section==='system'&&<SystemSettingsPage settings={settings} providers={providers} capabilities={capabilities} modelStatus={health?.model} refresh={refresh}/>}
    </div>
  </div>
}

type ExtensionSection = 'overview' | 'skills' | 'mcp' | 'tools'

function ExtensionsPage({skills,mcpServers,toolCatalog,refresh}:{skills:ManagedSkill[];mcpServers:MCPServer[];toolCatalog:LLMToolCatalog|null;refresh:()=>Promise<void>}){
	const [section,setSection]=useState<ExtensionSection>('overview')
	const enabledSkills=skills.filter(skill=>skill.enabled).length
	const readyMCP=mcpServers.filter(server=>server.status==='ready').length
	const externalTools=toolCatalog?.tools.filter(item=>item.category==='mcp').length??0
	const tabs:[ExtensionSection,React.ReactNode,string,string][]=[
		['overview',<Braces size={17}/>, 'Overview', `${enabledSkills+readyMCP} active`],
		['skills',<BookOpen size={17}/>, 'Skills', `${enabledSkills}/${skills.length} enabled`],
		['mcp',<Zap size={17}/>, 'MCP servers', `${readyMCP}/${mcpServers.length} ready`],
		['tools',<FunctionSquare size={17}/>, 'Loaded functions', `${toolCatalog?.count??0} loaded`],
	]
	return <div className="extensions-center page-stack">
		<section className="extensions-hero panel"><div className="extensions-hero-mark"><Braces size={24}/></div><div><span>AGENT EXTENSION CONTROL PLANE</span><h2>Knowledge, integrations and model-facing functions</h2><p>Enable only the capabilities the main Agent should see. Runtime changes rebuild the Eino tool snapshot automatically.</p></div><dl><div><dt>Enabled Skills</dt><dd>{enabledSkills}</dd></div><div><dt>Ready MCP</dt><dd>{readyMCP}</dd></div><div><dt>External tools</dt><dd>{externalTools}</dd></div></dl></section>
		<div className="extension-tabs configuration-tabs" role="tablist" aria-label="Extension sections">{tabs.map(([id,icon,label,meta])=><button type="button" role="tab" aria-selected={section===id} className={section===id?'active':''} onClick={()=>setSection(id)} key={id}>{icon}<span><b>{label}</b><small>{meta}</small></span><ChevronRight size={15}/></button>)}</div>
		<div className="configuration-content" role="tabpanel">
			{section==='overview'&&<div className="extension-overview"><button className="panel" onClick={()=>setSection('skills')}><div><BookOpen size={21}/></div><span><small>OPERATOR KNOWLEDGE</small><h3>Skills</h3><p>Markdown workflows loaded on demand through <code>ops_skill_get</code>.</p></span><strong>{enabledSkills}<small>enabled</small></strong><ChevronRight size={16}/></button><button className="panel" onClick={()=>setSection('mcp')}><div><Zap size={21}/></div><span><small>EXTERNAL INTEGRATIONS</small><h3>MCP Servers</h3><p>Discover external tools over stdio or Streamable HTTP.</p></span><strong>{readyMCP}<small>ready</small></strong><ChevronRight size={16}/></button><button className="panel" onClick={()=>setSection('tools')}><div><FunctionSquare size={21}/></div><span><small>RUNTIME SNAPSHOT</small><h3>Loaded functions</h3><p>Inspect the exact schemas currently passed to the ChatModel.</p></span><strong>{toolCatalog?.count??0}<small>functions</small></strong><ChevronRight size={16}/></button></div>}
			{section==='skills'&&<SkillsPage skills={skills} refresh={refresh}/>}
			{section==='mcp'&&<MCPServersPage servers={mcpServers} refresh={refresh}/>}
			{section==='tools'&&<LLMToolsPage catalog={toolCatalog} refresh={refresh}/>}
		</div>
	</div>
}

type MCPFormState = {
	id?:string;name:string;transport:MCPTransport;command:string;argsText:string;cwd:string;url:string;envText:string;headersText:string;enabled:boolean;clearEnv:boolean;clearHeaders:boolean
}

const emptyMCPForm:MCPFormState={name:'',transport:'stdio',command:'',argsText:'',cwd:'',url:'',envText:'',headersText:'',enabled:false,clearEnv:false,clearHeaders:false}

function parseMCPPairs(value:string,kind:'env'|'header'){
	const result:Record<string,string>={}
	for(const raw of value.split(/\r?\n/)){
		const line=raw.trim();if(!line)continue
		const separator=kind==='env'?line.indexOf('='):line.indexOf(':')
		if(separator<1)throw new Error(kind==='env'?`Invalid environment line “${line}”; use NAME=value.`:`Invalid header line “${line}”; use Name: value.`)
		const name=line.slice(0,separator).trim(),content=line.slice(separator+1).trim()
		if(!name)throw new Error(`Invalid ${kind} name.`)
		result[name]=content
	}
	return result
}

function MCPServersPage({servers,refresh}:{servers:MCPServer[];refresh:()=>Promise<void>}){
	const [form,setForm]=useState<MCPFormState|null>(null)
	const [busy,setBusy]=useState('')
	const [notice,setNotice]=useState('')
	const [error,setError]=useState('')
	const openCreate=()=>{setForm({...emptyMCPForm});setNotice('');setError('')}
	const openEdit=(server:MCPServer)=>{setForm({id:server.id,name:server.name,transport:server.transport,command:server.command||'',argsText:(server.args||[]).join('\n'),cwd:server.cwd||'',url:server.url||'',envText:'',headersText:'',enabled:server.enabled,clearEnv:false,clearHeaders:false});setNotice('');setError('')}
	const save=async(event:FormEvent)=>{event.preventDefault();if(!form)return;setBusy('save');setError('');try{
		const input:MCPServerInput={id:form.id,name:form.name.trim(),transport:form.transport,command:form.transport==='stdio'?form.command.trim():'',args:form.transport==='stdio'?form.argsText.split(/\r?\n/).map(item=>item.trim()).filter(Boolean):[],cwd:form.transport==='stdio'?form.cwd.trim():'',url:form.transport==='streamable_http'?form.url.trim():'',enabled:form.enabled}
		if(!form.id||form.envText.trim()||form.clearEnv)input.env=form.clearEnv?{}:parseMCPPairs(form.envText,'env')
		if(!form.id||form.headersText.trim()||form.clearHeaders)input.headers=form.clearHeaders?{}:parseMCPPairs(form.headersText,'header')
		const saved=await api.saveMCPServer(input);setForm(null);setNotice(`${saved.name} saved · ${saved.status}${saved.last_error?` · ${saved.last_error}`:''}`);await refresh()
	}catch(err){setError(errorText(err))}finally{setBusy('')}}
	const test=async(server:MCPServer)=>{setBusy(`test-${server.id}`);setError('');try{const result=await api.testMCPServer(server.id);setNotice(`Connection healthy · ${result.tool_count} tools discovered · ${result.latency_ms} ms`)}catch(err){setError(errorText(err))}finally{setBusy('')}}
	const toggle=async(server:MCPServer)=>{setBusy(`toggle-${server.id}`);setError('');try{const result=await api.setMCPServerEnabled(server.id,!server.enabled);setNotice(`${result.name} ${result.enabled?'enabled':'disabled'} · ${result.status}${result.last_error?` · ${result.last_error}`:''}`);await refresh()}catch(err){setError(errorText(err))}finally{setBusy('')}}
	const retry=async(server:MCPServer)=>{setBusy(`retry-${server.id}`);setError('');try{const result=await api.retryMCPServer(server.id);setNotice(`${result.name} reconnected · ${result.tool_count} tools loaded`);await refresh()}catch(err){setError(errorText(err));await refresh()}finally{setBusy('')}}
	const remove=async(server:MCPServer)=>{if(!confirm(`Permanently delete MCP server “${server.name}”?`))return;setBusy(`delete-${server.id}`);setError('');try{await api.deleteMCPServer(server.id);setNotice(`${server.name} deleted.`);await refresh()}catch(err){setError(errorText(err))}finally{setBusy('')}}
	return <div className="mcp-page page-stack">
		<div className="page-actions"><div><p>External MCP Servers</p><span>Connect tool providers through shell-free stdio commands or MCP Streamable HTTP.</span></div><button className="primary" onClick={openCreate}><Plus size={15}/>Add MCP server</button></div>
		<div className="mcp-boundary-note"><ShieldAlert size={16}/><div><b>External trust boundary</b><span>MCP tools execute in their own server's authority and are not automatically covered by OpsPilot's SSH policy or approval gate. Only enable servers you trust.</span></div></div>
		{notice&&<div className="notice">{notice}<button onClick={()=>setNotice('')}><X size={14}/></button></div>}
		{error&&<div className="skill-error"><ShieldAlert size={15}/>{error}<button onClick={()=>setError('')}><X size={14}/></button></div>}
		{form&&<form className="mcp-form panel" onSubmit={save}><header><div><Zap size={19}/><span><small>{form.id?'EDIT MCP SERVER':'NEW MCP SERVER'}</small><h3>{form.id?form.name||'MCP server':'Connect an external tool provider'}</h3></span></div><button type="button" onClick={()=>setForm(null)}><X size={15}/></button></header><div className="mcp-form-grid"><label><span>Display name</span><input value={form.name} onChange={event=>setForm({...form,name:event.target.value})} placeholder="GitHub tools" required/></label><label><span>Transport</span><select value={form.transport} onChange={event=>setForm({...form,transport:event.target.value as MCPTransport})}><option value="stdio">stdio · local process</option><option value="streamable_http">Streamable HTTP</option></select></label>{form.transport==='stdio'?<><label><span>Command</span><input value={form.command} onChange={event=>setForm({...form,command:event.target.value})} placeholder="npx" required/></label><label><span>Working directory · optional</span><input value={form.cwd} onChange={event=>setForm({...form,cwd:event.target.value})} placeholder="/absolute/path"/></label><label className="mcp-wide"><span>Arguments · one exact argument per line</span><textarea value={form.argsText} onChange={event=>setForm({...form,argsText:event.target.value})} placeholder={'-y\n@modelcontextprotocol/server-filesystem\n/srv/projects'}/></label></>:<label className="mcp-wide"><span>Streamable HTTP endpoint</span><input value={form.url} onChange={event=>setForm({...form,url:event.target.value})} placeholder="https://mcp.example.com/mcp" required/></label>}<label className="mcp-wide"><span>Environment variables · NAME=value, encrypted</span><textarea value={form.envText} onChange={event=>setForm({...form,envText:event.target.value,clearEnv:false})} placeholder={form.id?'Leave blank to preserve stored values':'GITHUB_TOKEN=…'}/>{form.id&&<small>Blank preserves stored values. <label><input type="checkbox" checked={form.clearEnv} onChange={event=>setForm({...form,clearEnv:event.target.checked,envText:event.target.checked?'':form.envText})}/> Clear all stored environment values</label></small>}</label><label className="mcp-wide"><span>HTTP headers · Name: value, encrypted</span><textarea value={form.headersText} onChange={event=>setForm({...form,headersText:event.target.value,clearHeaders:false})} placeholder={form.id?'Leave blank to preserve stored values':'Authorization: Bearer …'}/>{form.id&&<small>Blank preserves stored values. <label><input type="checkbox" checked={form.clearHeaders} onChange={event=>setForm({...form,clearHeaders:event.target.checked,headersText:event.target.checked?'':form.headersText})}/> Clear all stored headers</label></small>}</label></div><footer><label className="mcp-enable-on-save"><input type="checkbox" checked={form.enabled} onChange={event=>setForm({...form,enabled:event.target.checked})}/><i/><span><b>Enable after save</b><small>Connect, discover tools and rebuild the Eino runtime.</small></span></label><button type="button" onClick={()=>setForm(null)}>Cancel</button><button className="primary" disabled={busy==='save'}>{busy==='save'?<LoaderCircle className="spin" size={14}/>:<Save size={14}/>} {busy==='save'?'Saving…':'Save server'}</button></footer></form>}
		<div className="mcp-grid">{servers.map(server=><article className={`mcp-card panel ${server.status}`} key={server.id}><header><div className="mcp-card-icon"><Zap size={19}/></div><span><h3>{server.name}</h3><code>{server.transport==='stdio'?server.command:server.url}</code></span><em className={server.status}><CircleDot size={9}/>{server.status}</em></header><dl><div><dt>Discovered tools</dt><dd>{server.tool_count}</dd></div><div><dt>Secrets</dt><dd>{(server.env_keys?.length||0)+(server.header_keys?.length||0)} configured</dd></div><div><dt>Last connected</dt><dd>{server.connected_at?new Date(server.connected_at).toLocaleString():'—'}</dd></div></dl>{server.last_error&&<div className="mcp-card-error"><ShieldAlert size={13}/><span>{server.last_error}</span></div>}<div className="mcp-actions"><button onClick={()=>void test(server)} disabled={!!busy}><Activity size={13}/>{busy===`test-${server.id}`?'Testing…':'Test'}</button><button onClick={()=>openEdit(server)} disabled={!!busy}><Edit3 size={13}/>Edit</button>{server.enabled&&server.status!=='ready'&&<button onClick={()=>void retry(server)} disabled={!!busy}><RefreshCw className={busy===`retry-${server.id}`?'spin':''} size={13}/>Retry</button>}<button className={server.enabled?'disable':'enable'} onClick={()=>void toggle(server)} disabled={!!busy}>{busy===`toggle-${server.id}`?<LoaderCircle className="spin" size={13}/>:server.enabled?<X size={13}/>:<Check size={13}/>} {server.enabled?'Disable':'Enable'}</button><button className="danger" onClick={()=>void remove(server)} disabled={!!busy}><Trash2 size={13}/></button></div>{server.tools?.length?<details className="mcp-tools"><summary>{server.tools.length} model-facing tools <ChevronRight size={13}/></summary><div>{server.tools.map(item=><section key={item.exposed_name}><code>{item.exposed_name}</code><span>remote · {item.name}</span><p>{item.description}</p></section>)}</div></details>:null}</article>)}</div>
		{!servers.length&&<Empty icon={<Zap/>} title="No external MCP servers" text="Add a stdio or Streamable HTTP server, test it, then enable its tools for the main Agent."/>}
	</div>
}

type ToolParameterView = {name:string;type:string;description:string;required:boolean}

const toolCategoryLabels:Record<string,string>={planning:'Task planning',execution:'Command execution',hosts:'SSH hosts',tasks:'Long tasks',remote_files:'Remote files',workspace:'Workspace',history:'Audit history',approvals:'Approvals',skills:'Ops skills',mcp:'External MCP'}
const toolGuardLabels:Record<LLMToolGuard,string>={read_only:'Read only',policy_checked:'Dynamic policy',approval_required:'Human approval',agent_state:'Agent state',audited_control:'Audited control',external_mcp:'External MCP'}

function schemaRecord(value:unknown):Record<string,unknown>{return value!==null&&typeof value==='object'&&!Array.isArray(value)?value as Record<string,unknown>:{}}
function schemaType(value:unknown){if(Array.isArray(value))return value.map(String).join(' | ');return typeof value==='string'?value:'any'}
function toolParameters(tool?:LLMToolDescriptor):ToolParameterView[]{
	if(!tool)return[]
	const schema=schemaRecord(tool.input_schema)
	const properties=schemaRecord(schema.properties)
	const required=new Set(Array.isArray(schema.required)?schema.required.map(String):[])
	return Object.entries(properties).map(([name,value])=>{const field=schemaRecord(value);return{name,type:schemaType(field.type),description:typeof field.description==='string'?field.description:'',required:required.has(name)}})
}

function LLMToolsPage({catalog,refresh}:{catalog:LLMToolCatalog|null;refresh:()=>Promise<void>}){
	const [query,setQuery]=useState('')
	const [category,setCategory]=useState('all')
	const [selectedName,setSelectedName]=useState('')
	const [refreshing,setRefreshing]=useState(false)
	const [busyName,setBusyName]=useState('')
	const [error,setError]=useState('')
	const tools=catalog?.tools||[]
	const categories=useMemo(()=>Array.from(new Set(tools.map(tool=>tool.category))),[tools])
	const filtered=useMemo(()=>{const needle=query.trim().toLowerCase();return tools.filter(tool=>(category==='all'||tool.category===category)&&(!needle||`${tool.name} ${tool.description} ${tool.category}`.toLowerCase().includes(needle)))},[tools,query,category])
	const selected=filtered.find(tool=>tool.name===selectedName)||filtered[0]
	const parameters=toolParameters(selected)
	const protectedCount=tools.filter(tool=>tool.enabled&&tool.guard==='approval_required').length
	const readOnlyCount=tools.filter(tool=>tool.enabled&&tool.guard==='read_only').length
	const refreshCatalog=async()=>{setRefreshing(true);try{await refresh()}finally{setRefreshing(false)}}
	const setEnabled=async(tool:LLMToolDescriptor)=>{setBusyName(tool.name);setError('');try{await api.setLLMToolEnabled(tool.name,!tool.enabled);await refresh()}catch(err){setError(errorText(err))}finally{setBusyName('')}}

	return <div className="llm-tools-page page-stack">
		<section className={`tool-catalog-hero panel ${catalog?.loaded?'loaded':'unloaded'}`}>
			<div className="tool-catalog-mark"><FunctionSquare size={24}/><i/></div>
			<div><span>LIVE CHATMODEL TOOLSET</span><h2>{catalog?.loaded?'Functions currently loaded by the LLM':'No function toolset is loaded'}</h2><p>This is the runtime snapshot passed to the main Eino Agent, not a hand-written capability document.</p></div>
			<dl><div><dt>Agent</dt><dd>{catalog?.agent||'ops-pilot'}</dd></div><div><dt>Model</dt><dd>{catalog?.model||'Not loaded'}</dd></div><div><dt>Functions</dt><dd>{catalog?.count??0} / {catalog?.total??0}</dd></div><div><dt>Execution</dt><dd>{catalog?.execution_mode||'sequential'}</dd></div></dl>
			<button className="tool-catalog-refresh" onClick={refreshCatalog} disabled={refreshing}><RefreshCw className={refreshing?'spin':''} size={14}/>{refreshing?'Refreshing…':'Refresh snapshot'}</button>
		</section>
		<section className="tool-catalog-note"><BrainCircuit size={16}/><div><b>Main Agent tool boundary</b><span>The approval explanation Agent remains tool-free. Only enabled functions are passed to <code>{catalog?.agent||'ops-pilot'}</code>.</span></div><small>{catalog?.loaded_at?`Loaded ${new Date(catalog.loaded_at).toLocaleString()}`:'Waiting for a model runtime'}</small></section>
		{error&&<div className="tool-function-error"><ShieldAlert size={15}/><span>{error}</span><button onClick={()=>setError('')} title="Dismiss"><X size={14}/></button></div>}
		<div className="tool-catalog-metrics"><Metric label="Enabled functions" value={String(catalog?.count??0)} tone="green"/><Metric label="Available functions" value={String(catalog?.total??0)}/><Metric label="Read-only enabled" value={String(readOnlyCount)}/><Metric label="Approval-gated enabled" value={String(protectedCount)} tone="amber"/></div>
		<div className="tool-catalog-toolbar panel"><label><Search size={15}/><input value={query} onChange={event=>setQuery(event.target.value)} placeholder="Search function name or purpose…"/></label><select value={category} onChange={event=>setCategory(event.target.value)}><option value="all">All categories · {tools.length}</option>{categories.map(value=><option value={value} key={value}>{toolCategoryLabels[value]||value} · {tools.filter(tool=>tool.category===value).length}</option>)}</select><span>{filtered.length} visible</span></div>
		{!catalog?<div className="tool-catalog-loading panel"><LoaderCircle className="spin" size={20}/>Loading runtime function snapshot…</div>:!catalog.loaded?<Empty icon={<FunctionSquare/>} title="Agent runtime is not loaded" text="Activate a working model provider; functions appear here after the Eino runner builds successfully."/>:<div className="tool-catalog-browser">
			<section className="tool-function-list panel">{filtered.length?filtered.map(tool=>{const count=toolParameters(tool).length;return <button className={`${selected?.name===tool.name?'active':''} ${tool.enabled?'':'disabled'}`} onClick={()=>setSelectedName(tool.name)} key={tool.name}><div className="tool-function-icon"><Braces size={16}/></div><span><code>{tool.name}</code><p>{tool.description}</p><small><em>{toolCategoryLabels[tool.category]||tool.category}</em><i className={tool.guard}>{toolGuardLabels[tool.guard]}</i>{!tool.enabled&&<i className="disabled">Disabled</i>}</small></span><b>{count}<small>ARGS</small></b><ChevronRight size={14}/></button>}):<div className="tool-filter-empty"><Search size={20}/><b>No matching functions</b><span>Change the search text or category filter.</span></div>}</section>
			<aside className={`tool-function-inspector panel ${selected?.enabled?'':'disabled'}`}>{selected?<><header><div className="tool-function-icon"><FunctionSquare size={18}/></div><span><small>FUNCTION DETAIL</small><code>{selected.name}</code></span><div className="tool-function-controls"><em className={selected.guard}>{toolGuardLabels[selected.guard]}</em><button className={selected.enabled?'enabled':''} role="switch" aria-checked={selected.enabled} onClick={()=>void setEnabled(selected)} disabled={busyName===selected.name} title={selected.enabled?'Disable function':'Enable function'}>{busyName===selected.name?<LoaderCircle className="spin" size={14}/>:<Power size={14}/>}<span>{selected.enabled?'Enabled':'Disabled'}</span></button></div></header><p className="tool-function-description">{selected.description}</p><dl className="tool-function-meta"><div><dt>Category</dt><dd>{toolCategoryLabels[selected.category]||selected.category}</dd></div><div><dt>Arguments</dt><dd>{parameters.length}</dd></div><div><dt>Safety gate</dt><dd>{toolGuardLabels[selected.guard]}</dd></div></dl><section className="tool-parameter-list"><h3>Input parameters <span>{parameters.filter(item=>item.required).length} required</span></h3>{parameters.length?parameters.map(parameter=><div key={parameter.name}><code>{parameter.name}</code><em>{parameter.type}</em>{parameter.required&&<b>required</b>}<p>{parameter.description||'No additional description.'}</p></div>):<p className="tool-no-arguments">This function takes no arguments.</p>}</section><details className="tool-schema-raw"><summary>Raw JSON Schema <ChevronRight size={13}/></summary><pre>{JSON.stringify(selected.input_schema,null,2)}</pre></details></>:<div className="tool-inspector-empty"><Braces size={26}/><span>Select a function to inspect its model-facing schema.</span></div>}</aside>
		</div>}
	</div>
}

function SkillsPage({skills,refresh}:{skills:ManagedSkill[];refresh:()=>Promise<void>}){
	const [query,setQuery]=useState('')
	const [selectedName,setSelectedName]=useState('')
	const [selected,setSelected]=useState<ManagedSkill|null>(null)
	const [draft,setDraft]=useState('')
	const [loading,setLoading]=useState(false)
	const [saving,setSaving]=useState(false)
	const [uploading,setUploading]=useState(false)
	const [uploadOpen,setUploadOpen]=useState(false)
	const [uploadName,setUploadName]=useState('')
	const [uploadFile,setUploadFile]=useState<File|null>(null)
	const [deleteName,setDeleteName]=useState('')
	const [deleting,setDeleting]=useState(false)
	const [toggling,setToggling]=useState(false)
	const [notice,setNotice]=useState('')
	const [error,setError]=useState('')
	const filtered=useMemo(()=>{const needle=query.trim().toLowerCase();return skills.filter(skill=>!needle||`${skill.name} ${skill.summary}`.toLowerCase().includes(needle))},[skills,query])
	useEffect(()=>{if(!skills.length){setSelectedName('');setSelected(null);setDraft('');return}if(!selectedName||!skills.some(skill=>skill.name===selectedName))setSelectedName(skills[0].name)},[skills,selectedName])
	useEffect(()=>{if(!selectedName)return;let cancelled=false;setLoading(true);setError('');api.skill(selectedName).then(skill=>{if(cancelled)return;setSelected(skill);setDraft(skill.content||'')}).catch(err=>{if(!cancelled)setError(errorText(err))}).finally(()=>{if(!cancelled)setLoading(false)});return()=>{cancelled=true}},[selectedName])
	const dirty=!!selected&&draft!==selected.content
	const selectFile=(file:File|null)=>{setUploadFile(file);if(file&&!uploadName){const base=file.name.replace(/\.(markdown|md|zip)$/i,'').replace(/[^A-Za-z0-9_.-]+/g,'-').replace(/^-+|-+$/g,'').slice(0,64);setUploadName(base)}}
	const upload=async(event:FormEvent)=>{event.preventDefault();if(!uploadFile)return;setUploading(true);setError('');setNotice('');try{const result=await api.uploadSkill(uploadName.trim(),uploadFile);await refresh();setSelectedName(result.name);setSelected(result);setDraft(result.content||'');setUploadOpen(false);setUploadName('');setUploadFile(null);setNotice(`${result.name} uploaded and immediately available to the Agent.`)}catch(err){setError(errorText(err))}finally{setUploading(false)}}
	const save=async()=>{if(!selected)return;setSaving(true);setError('');setNotice('');try{const result=await api.saveSkill(selected.name,draft);setSelected(result);setDraft(result.content||'');await refresh();setNotice(`${result.name} saved. The next ops_skill_get call will load this version.`)}catch(err){setError(errorText(err))}finally{setSaving(false)}}
	const permanentlyDelete=async()=>{if(!deleteName)return;setDeleting(true);setError('');try{await api.deleteSkill(deleteName);setDeleteName('');setSelectedName('');setSelected(null);setDraft('');await refresh();setNotice(`${deleteName} permanently deleted.`)}catch(err){setError(errorText(err))}finally{setDeleting(false)}}
	const toggleEnabled=async()=>{if(!selected)return;setToggling(true);setError('');setNotice('');try{const result=await api.setSkillEnabled(selected.name,!selected.enabled);setSelected(result);setDraft(result.content||draft);await refresh();setNotice(`${result.name} ${result.enabled?'enabled and visible to the Agent':'disabled and removed from ops_skill_list'}.`)}catch(err){setError(errorText(err))}finally{setToggling(false)}}

	return <div className="skills-page page-stack">
		<div className="page-actions"><div><p>Administrator Skill Registry</p><span>Skills are trusted operator-authored instructions. Uploads and edits become available to the Agent immediately.</span></div><button className="primary" onClick={()=>{setUploadOpen(value=>!value);setError('')}}><UploadCloud size={15}/>{uploadOpen?'Close upload':'Upload Skill'}</button></div>
		{notice&&<div className="notice">{notice}<button onClick={()=>setNotice('')}><X size={14}/></button></div>}
		{error&&<div className="skill-error"><ShieldAlert size={15}/>{error}<button onClick={()=>setError('')}><X size={14}/></button></div>}
		{uploadOpen&&<form className="skill-upload-panel panel" onSubmit={upload}><div><div className="skill-upload-icon"><UploadCloud size={20}/></div><span><b>Upload Markdown or ZIP package</b><small>A ZIP must contain exactly one <code>SKILL.md</code>. Uploading an existing name replaces its package.</small></span></div><label><span>Skill name</span><input value={uploadName} onChange={event=>setUploadName(event.target.value)} placeholder="nginx-diagnosis" pattern="[A-Za-z0-9][A-Za-z0-9_.-]{0,63}" required/></label><label className="skill-file-picker"><FileText size={15}/><span><b>{uploadFile?.name||'Choose .md or .zip'}</b><small>{uploadFile?formatFileSize(uploadFile.size):'Maximum package size · 8 MiB'}</small></span><input type="file" accept=".md,.markdown,.zip,text/markdown,application/zip" onChange={event=>selectFile(event.target.files?.[0]||null)} required/></label><button className="primary" disabled={uploading||!uploadFile||!uploadName.trim()}>{uploading?<LoaderCircle className="spin" size={14}/>:<UploadCloud size={14}/>} {uploading?'Uploading…':'Upload & activate'}</button></form>}
		<section className="skill-registry-summary panel"><div><BookOpen size={19}/><span><b>{skills.filter(skill=>skill.enabled).length} enabled · {skills.length} installed</b><small>Only enabled Skills are discovered dynamically by <code>ops_skill_list</code>.</small></span></div><label><Search size={14}/><input value={query} onChange={event=>setQuery(event.target.value)} placeholder="Search skills…"/></label></section>
		<div className="skill-manager-layout">
			<section className="skill-list panel">{filtered.length?filtered.map(skill=><button className={`${selectedName===skill.name?'active':''} ${skill.enabled?'':'disabled'}`} onClick={()=>setSelectedName(skill.name)} key={skill.name}><div className="skill-card-icon"><BookOpen size={16}/></div><span><code>{skill.name}</code><p>{skill.summary||'No summary available.'}</p><small><em className={skill.enabled?'enabled':'disabled'}>{skill.enabled?'enabled':'disabled'}</em>{skill.file_count||1} files · {formatFileSize(skill.size_bytes||0)}{skill.updated_at?` · ${new Date(skill.updated_at).toLocaleDateString()}`:''}</small></span><ChevronRight size={14}/></button>):<div className="skill-list-empty"><BookOpen size={23}/><b>{skills.length?'No matching Skills':'No Skills installed'}</b><span>{skills.length?'Change the search text.':'Upload a Markdown or ZIP Skill package.'}</span></div>}</section>
			<section className="skill-editor panel">{loading?<div className="skill-editor-state"><LoaderCircle className="spin" size={21}/>Loading Skill…</div>:selected?<><header><div><BookOpen size={17}/><span><small>MANAGED SKILL · {selected.enabled?'ENABLED':'DISABLED'}</small><code>{selected.name}</code></span></div><section><button className={selected.enabled?'skill-disable':'skill-enable'} disabled={toggling} onClick={toggleEnabled}>{toggling?<LoaderCircle className="spin" size={13}/>:selected.enabled?<X size={13}/>:<Check size={13}/>} {selected.enabled?'Disable':'Enable'}</button><button disabled={!dirty||saving} onClick={save}>{saving?<LoaderCircle className="spin" size={13}/>:<Save size={13}/>} {saving?'Saving…':'Save changes'}</button><button className="danger" onClick={()=>setDeleteName(selected.name)}><Trash2 size={13}/>Delete</button></section></header><div className="skill-editor-meta"><span><b>SHA256</b><code title={selected.content_sha256}>{selected.content_sha256?.slice(0,16)||'—'}</code></span><span><b>Files</b><code>{selected.file_count||1}</code></span><span><b>Size</b><code>{formatFileSize(selected.size_bytes||0)}</code></span><span><b>Updated</b><code>{selected.updated_at?new Date(selected.updated_at).toLocaleString():'—'}</code></span></div><div className="skill-editor-split"><label><span>SKILL.md</span><textarea value={draft} spellCheck={false} onChange={event=>setDraft(event.target.value)}/></label><section><span>LIVE PREVIEW</span><div className="markdown-body"><Markdown skipHtml remarkPlugins={[remarkGfm]} components={{a:({href,children})=><a href={href} target="_blank" rel="noopener noreferrer">{children}</a>,img:({alt})=><span className="markdown-image-blocked">[Blocked image: {alt||'no description'}]</span>}}>{draft||'*Empty Skill*'}</Markdown></div></section></div></>:<div className="skill-editor-state"><BookOpen size={25}/><b>Select a Skill</b><span>View, edit or permanently delete its SKILL.md.</span></div>}</section>
		</div>
		{deleteName&&<div className="skill-delete-backdrop"><section className="skill-delete-dialog panel" role="dialog" aria-modal="true"><div><Trash2 size={21}/><span><small>PERMANENT DELETE</small><h3>Delete <code>{deleteName}</code>?</h3></span></div><p>The Skill directory and all reference files will be removed immediately. There is no recycle bin or recovery workflow.</p><footer><button disabled={deleting} onClick={()=>setDeleteName('')}>Cancel</button><button className="danger" disabled={deleting} onClick={permanentlyDelete}>{deleting?<LoaderCircle className="spin" size={14}/>:<Trash2 size={14}/>} {deleting?'Deleting…':'Permanently delete'}</button></footer></section></div>}
	</div>
}

function SystemSettingsPage({settings,providers,capabilities,modelStatus,refresh}:{settings:SystemSettings|null;providers:ModelProvider[];capabilities:ToolCapabilities;modelStatus?:Health['model'];refresh:()=>Promise<void>}) {
  const savedValue=settings?.agent_max_iterations??50
  const savedExplanation=settings?.approval_explanations_enabled??true
  const savedSubagentProvider=settings?.subagent_model_provider_id??''
  const savedSubagentTimeout=settings?.subagent_timeout_seconds??30
  const savedShellMode=settings?.workspace_shell_mode??'sandbox'
  const [maxIterations,setMaxIterations]=useState(savedValue)
  const [explanationEnabled,setExplanationEnabled]=useState(savedExplanation)
  const [subagentProvider,setSubagentProvider]=useState(savedSubagentProvider)
  const [subagentTimeout,setSubagentTimeout]=useState(savedSubagentTimeout)
  const [shellMode,setShellMode]=useState<WorkspaceShellMode>(savedShellMode)
  const [dirty,setDirty]=useState(false)
  const [saving,setSaving]=useState(false)
  const [notice,setNotice]=useState('')
  useEffect(()=>{if(!dirty){setMaxIterations(savedValue);setExplanationEnabled(savedExplanation);setSubagentProvider(savedSubagentProvider);setSubagentTimeout(savedSubagentTimeout);setShellMode(savedShellMode)}},[savedValue,savedExplanation,savedSubagentProvider,savedSubagentTimeout,savedShellMode,dirty])
  const update=(value:number)=>{setMaxIterations(Math.max(5,Math.min(100,value||5)));setDirty(true);setNotice('')}
  const toggleExplanation=(value:boolean)=>{setExplanationEnabled(value);setDirty(true);setNotice('')}
  const selectSubagentProvider=(value:string)=>{setSubagentProvider(value);setDirty(true);setNotice('')}
  const updateSubagentTimeout=(value:number)=>{setSubagentTimeout(Math.max(5,Math.min(120,value||5)));setDirty(true);setNotice('')}
  const selectShellMode=(value:WorkspaceShellMode)=>{setShellMode(value);setDirty(true);setNotice('')}
  const save=async(event:FormEvent)=>{event.preventDefault();setSaving(true);try{const result=await api.saveSystemSettings({agent_max_iterations:maxIterations,approval_explanations_enabled:explanationEnabled,subagent_model_provider_id:subagentProvider,subagent_timeout_seconds:subagentTimeout,workspace_shell_mode:shellMode});setMaxIterations(result.agent_max_iterations);setExplanationEnabled(result.approval_explanations_enabled);setSubagentProvider(result.subagent_model_provider_id);setSubagentTimeout(result.subagent_timeout_seconds);setShellMode(result.workspace_shell_mode);setDirty(false);setNotice(`Saved · Subagent timeout ${result.subagent_timeout_seconds}s · Workspace Shell ${result.workspace_shell_mode}.`);await refresh()}catch(err){setNotice(errorText(err))}finally{setSaving(false)}}
  const selectedSubagentProvider=providers.find(provider=>provider.id===subagentProvider)
  const subagentRoute=subagentProvider?(selectedSubagentProvider?`${selectedSubagentProvider.name} · ${selectedSubagentProvider.model}`:'Provider unavailable'):'Follow active main provider'
  return <div className="system-settings page-stack">
    <div className="page-actions"><div><p>Agent runtime safeguards</p><span>Runtime changes are persisted locally, audited and applied to new Agent runs without a server restart.</span></div></div>
    {notice&&<div className="notice">{notice}<button onClick={()=>setNotice('')}><X size={14}/></button></div>}
    <form className="settings-panel panel" onSubmit={save}><div className="settings-panel-head"><div className="settings-glyph"><SlidersHorizontal size={20}/></div><div><span>AGENT LOOP</span><h3>Maximum model iterations</h3><p>Limits how many model → tool → model decision rounds a single message may consume.</p></div><strong>{maxIterations}</strong></div>
      <div className="iteration-editor"><input aria-label="Maximum model iterations" type="range" min="5" max="100" step="1" value={maxIterations} onChange={event=>update(Number(event.target.value))}/><label><span>Rounds</span><input type="number" min="5" max="100" value={maxIterations} onChange={event=>update(Number(event.target.value))}/></label></div>
      <div className="iteration-presets"><span>QUICK PRESETS</span>{[20,50,100].map(value=><button type="button" className={maxIterations===value?'active':''} onClick={()=>update(value)} key={value}><b>{value}</b><small>{value===20?'Short diagnosis':value===50?'Recommended':'Long deployment'}</small></button>)}</div>
      <div className="subagent-settings"><div className="subagent-settings-head"><BrainCircuit size={18}/><div><b>Approval explanation</b><p>One isolated, tool-free Eino Agent explains commands in the background. Deterministic Policy remains the only risk classifier.</p></div><em className={modelStatus?.explanation_agent_available?'ready':'offline'}><CircleDot size={9}/>{modelStatus?.explanation_agent_available?'1 runner ready':'model unavailable'}</em></div><label className="subagent-toggle"><span><b>Command explanation Agent</b><small>Explains effects, risks, practical tips and rollback guidance without changing approval risk.</small></span><input type="checkbox" checked={explanationEnabled} onChange={event=>toggleExplanation(event.target.checked)}/><i/></label><div className="subagent-config-grid"><label><span><b>Model provider</b><small>{subagentRoute}</small></span><select value={subagentProvider} onChange={event=>selectSubagentProvider(event.target.value)}><option value="">Follow active main provider</option>{providers.map(provider=><option value={provider.id} key={provider.id}>{provider.name} · {provider.model}</option>)}</select></label><label><span><b>Request timeout</b><small>Applied to each background explanation request.</small></span><div className="subagent-timeout-input"><input aria-label="Subagent request timeout" type="number" min="5" max="120" step="1" value={subagentTimeout} onChange={event=>updateSubagentTimeout(Number(event.target.value))}/><em>seconds</em></div></label></div>{modelStatus?.explanation_error&&<div className="subagent-runtime-error"><ShieldAlert size={14}/><span>{modelStatus.explanation_error}</span></div>}</div>
	  <div className="workspace-shell-settings"><div className="workspace-shell-settings-head"><TerminalSquare size={18}/><div><b>Workspace Shell backend</b><p>Controls whether Workspace scripts run in Bubblewrap, directly on this host, or remain unavailable.</p></div><em>{settings?.workspace_shell_platform||'detecting'}</em></div><div className="workspace-shell-modes" role="group" aria-label="Workspace Shell backend"><button type="button" className={shellMode==='sandbox'?'active':''} disabled={!settings?.workspace_sandbox_available} onClick={()=>selectShellMode('sandbox')}><ShieldCheck size={16}/><span><b>Sandbox</b><small>{settings?.workspace_sandbox_available?'Linux · Bubblewrap · no network':'Unavailable on this host'}</small></span></button><button type="button" className={`${shellMode==='host'?'active ':''}host`} disabled={!settings?.workspace_host_shell_available} onClick={()=>selectShellMode('host')}><TerminalSquare size={16}/><span><b>Host Shell</b><small>{settings?.workspace_host_shell_available?`${settings.workspace_shell_name||'system shell'} · full host authority`:'No supported shell detected'}</small></span></button><button type="button" className={shellMode==='disabled'?'active':''} onClick={()=>selectShellMode('disabled')}><Power size={16}/><span><b>Disabled</b><small>Remove shell execution capability</small></span></button></div>{shellMode==='host'&&<div className="workspace-shell-warning"><ShieldAlert size={15}/><span><b>Full host filesystem and network access</b><small>Every Host Shell invocation requires a new one-time human approval. Session approvals are prohibited, and read-only Workspaces cannot use this backend.</small></span></div>}{shellMode==='sandbox'&&!settings?.workspace_sandbox_available&&<div className="workspace-shell-warning"><ShieldAlert size={15}/><span><b>Configured sandbox is unavailable</b><small>Execution fails closed. There is no automatic fallback to Host Shell.</small></span></div>}</div>
	  <div className="workspace-capabilities"><div><FileText size={17}/><span><b>Allowlisted Workspaces</b><small>Startup allowlist only. Browse and upload files directly from the Agent conversation.</small></span><em>{capabilities.workspaces.length}</em></div>{capabilities.workspaces.length?capabilities.workspaces.map(workspace=><section className="workspace-summary-row" key={workspace.id}><div><code>{workspace.id}</code><span className={workspace.access}>{workspace.access.replace('_',' ')}</span></div><code title={workspace.root}>{workspace.root}</code><small>{workspace.validators?.length?`validators · ${workspace.validators.join(', ')}`:'no validators'}</small></section>):<p>No local Workspace is exposed. The Agent remains SSH-only.</p>}</div>
      <div className="settings-advice"><ShieldCheck size={17}/><div><b>The safety limit remains enforced</b><p>Higher values support installations and multi-step recovery, but can increase token usage and tool calls. Values are restricted to 5–100.</p></div></div>
      <div className="settings-footer"><span>{settings?.updated_at?`Last updated ${new Date(settings.updated_at).toLocaleString()}`:'Using system default'}</span><button type="button" disabled={!dirty||saving} onClick={()=>{setMaxIterations(savedValue);setExplanationEnabled(savedExplanation);setSubagentProvider(savedSubagentProvider);setSubagentTimeout(savedSubagentTimeout);setShellMode(savedShellMode);setDirty(false);setNotice('')}}>Discard</button><button className="primary" disabled={!dirty||saving}>{saving?'Applying…':'Save & apply'}</button></div>
    </form>
	<AdminPasswordPanel/>
  </div>
}

function AdminPasswordPanel(){
	const [current,setCurrent]=useState(''),[replacement,setReplacement]=useState(''),[confirmation,setConfirmation]=useState(''),[notice,setNotice]=useState(''),[busy,setBusy]=useState(false)
	const submit=async(event:FormEvent)=>{event.preventDefault();if(replacement!==confirmation){setNotice('New password confirmation does not match.');return}setBusy(true);setNotice('');try{await api.changePassword(current,replacement);window.location.reload()}catch(err){setNotice(errorText(err))}finally{setBusy(false)}}
	return <form className="admin-password-panel panel" onSubmit={submit}><div><LockKeyhole size={19}/><span><b>Administrator password</b><small>Changing it revokes every active Web session. CLI recovery uses <code>admin reset-password</code>.</small></span></div><section><label><span>Current</span><input type="password" autoComplete="current-password" value={current} onChange={event=>setCurrent(event.target.value)} required/></label><label><span>New password</span><input type="password" autoComplete="new-password" minLength={12} value={replacement} onChange={event=>setReplacement(event.target.value)} required/></label><label><span>Confirm</span><input type="password" autoComplete="new-password" minLength={12} value={confirmation} onChange={event=>setConfirmation(event.target.value)} required/></label><button className="primary" disabled={busy||replacement.length<12}>{busy?'Changing…':'Change & sign out'}</button></section>{notice&&<p>{notice}</p>}</form>
}

function Nav({ active, icon, label, count, warn, onClick }: {active:boolean;icon:React.ReactNode;label:string;count?:number;warn?:boolean;onClick:()=>void}) {
  return <button className={`nav-item ${active ? 'active' : ''}`} onClick={onClick}>{icon}<span>{label}</span>{count !== undefined && <em className={warn ? 'warn' : ''}>{count}</em>}</button>
}

function ChatPage({ hosts, approvals, runs, capabilities, agentAvailable, modelName, refresh, refreshApprovals, onStreamingChange }: {hosts:Host[];approvals:Approval[];runs:Run[];capabilities:ToolCapabilities;agentAvailable:boolean;modelName?:string;refresh:()=>Promise<void>;refreshApprovals:()=>Promise<void>;onStreamingChange:(streaming:boolean)=>void}) {
  const [entries, setEntries] = useState<ChatEntry[]>([])
  const [message, setMessage] = useState('')
  const [sessionId, setSessionId] = useState('')
  const [sessions, setSessions] = useState<ChatSession[]>([])
  const [historyError, setHistoryError] = useState('')
  const [loadingSession, setLoadingSession] = useState('')
  const [historyOpen,setHistoryOpen]=useState(false)
  const [running, setRunning] = useState(false)
  const [detachedRunning,setDetachedRunning]=useState(false)
  const [reasoningSeen, setReasoningSeen] = useState(false)
  const [plan,setPlan]=useState<AgentPlan|null>(null)
  const [approvalNotice,setApprovalNotice]=useState('')
	const [workspaceID,setWorkspaceID]=useState('')
  const messagesRef=useRef<HTMLDivElement>(null)
  const stickToLatest=useRef(true)
  const activeStreamRef=useRef<ActiveChatStream|null>(null)
  const sessionLoadRef=useRef('')
  const hostNames = useMemo(() => hosts.map((host) => host.name).join(', '), [hosts])
  const currentApprovals=useMemo(()=>sessionId?approvals.filter(item=>item.session_id===sessionId):[],[approvals,sessionId])
	const pendingExplanationID=currentApprovals.find(item=>item.ai_review?.status==='pending')?.id||''
  const sessionBusy=running||detachedRunning
	const selectedWorkspace=capabilities.workspaces.find(workspace=>workspace.id===workspaceID)||capabilities.workspaces[0]
	useEffect(()=>{if(selectedWorkspace&&workspaceID!==selectedWorkspace.id)setWorkspaceID(selectedWorkspace.id)},[selectedWorkspace,workspaceID])
	useEffect(()=>{onStreamingChange(running)},[running,onStreamingChange])
	useEffect(()=>()=>onStreamingChange(false),[onStreamingChange])
	useEffect(()=>()=>{sessionLoadRef.current='';const stream=activeStreamRef.current;activeStreamRef.current=null;stream?.controller.abort()},[])
	useEffect(()=>{
		if(!pendingExplanationID)return
		void refreshApprovals()
		const timer=window.setInterval(()=>{if(document.visibilityState==='visible')void refreshApprovals()},1500)
		return()=>window.clearInterval(timer)
	},[pendingExplanationID,refreshApprovals])

  const refreshSessions = useCallback(async () => {
    try {
      const items = await api.chatSessions(); setSessions(items); setHistoryError(''); return items
    } catch (err) { setHistoryError(errorText(err)); return [] }
  }, [])

  const detachActiveStream = useCallback(() => {
    const stream=activeStreamRef.current
    if(!stream)return
    activeStreamRef.current=null
    stream.controller.abort()
    setRunning(false)
  }, [])

  const loadSession = useCallback(async (id: string) => {
    const requestID=clientId()
    sessionLoadRef.current=requestID
    setLoadingSession(id)
    stickToLatest.current=true
    try {
      const state = await api.chatState(id)
      if(sessionLoadRef.current!==requestID)return
      setEntries(historyEntries(state.messages||[]));setDetachedRunning(!!state.active);setPlan(state.plan||null)
      setSessionId(id); rememberSession(id); setHistoryError('')
      void refresh()
    } catch (err) { if(sessionLoadRef.current===requestID)setHistoryError(errorText(err)) }
    finally { if(sessionLoadRef.current===requestID)setLoadingSession('') }
  }, [refresh])

  useEffect(()=>{
    if(!sessionId||running||!detachedRunning)return
    let active=true
    const sync=async()=>{
      try{const state=await api.chatState(sessionId);if(!active)return;setDetachedRunning(!!state.active);setPlan(state.plan||null);setEntries(old=>[...historyEntries(state.messages||[]),...old.filter(item=>item.kind==='error'&&!item.id.startsWith('history_'))]);if(!state.active)void refreshSessions()}
      catch(err){if(active)setHistoryError(errorText(err))}
    }
    void sync();const timer=window.setInterval(()=>void sync(),2500)
    return()=>{active=false;window.clearInterval(timer)}
  },[sessionId,running,detachedRunning,refreshSessions])

  const activeSessionCount=useMemo(()=>sessions.filter(item=>item.active).length,[sessions])
  useEffect(()=>{
    if(!activeSessionCount)return
    const timer=window.setInterval(()=>{if(document.visibilityState==='visible')void refreshSessions()},2500)
    return()=>window.clearInterval(timer)
  },[activeSessionCount,refreshSessions])

  useEffect(()=>{
    if(!stickToLatest.current)return
    const frame=window.requestAnimationFrame(()=>{const container=messagesRef.current;if(container)container.scrollTop=container.scrollHeight})
    return()=>window.cancelAnimationFrame(frame)
  },[entries,loadingSession])

  useEffect(() => {
    let active = true
    void (async () => {
      const items = await api.chatSessions().catch((err) => { if (active) setHistoryError(errorText(err)); return [] })
      if (!active) return
      setSessions(items)
      const remembered = recalledSession()
      if (remembered === newSessionMarker) return
      const target = items.some((item) => item.id === remembered) ? remembered : items[0]?.id
      if (target) await loadSession(target)
    })()
    return () => { active = false }
  }, [loadSession])

  const newChat = () => {
    detachActiveStream()
    sessionLoadRef.current=''
    setLoadingSession('')
    setHistoryOpen(false)
    stickToLatest.current=true;setSessionId(''); setEntries([]); setMessage(''); setHistoryError(''); setReasoningSeen(false);setDetachedRunning(false);setPlan(null); rememberSession(newSessionMarker)
    void refreshSessions()
  }

  const switchSession = (id:string) => {
    setHistoryOpen(false)
    if(id===sessionId){
      if(loadingSession){sessionLoadRef.current='';setLoadingSession('')}
      return
    }
    detachActiveStream()
    void loadSession(id)
    void refreshSessions()
  }

  const removeSession = async (session: ChatSession) => {
    const active=session.active||(session.id===sessionId&&sessionBusy)
    if (active || !confirm(`Delete conversation “${session.title}”?`)) return
    try {
      await api.deleteChatSession(session.id)
      if (session.id === sessionId) newChat()
      await refreshSessions()
    } catch (err) { setHistoryError(errorText(err)) }
  }

  const sendQuery = async (query:string) => {
    query=query.trim(); if(!query||sessionBusy||loadingSession)return
    let querySessionID=sessionId
    const userEntryID=clientId()
    const streamID=clientId()
    const controller=new AbortController()
    activeStreamRef.current={id:streamID,sessionId:sessionId,controller}
    const isAttached=()=>activeStreamRef.current?.id===streamID
    stickToLatest.current=true
    setApprovalNotice('');setReasoningSeen(false);setRunning(true)
    setEntries((old) => [...old, { id: userEntryID, kind: 'user', content: query, status:'pending' }, { id: 'streaming', kind: 'assistant', content: '', streaming:true }])
    try {
      await streamChat(sessionId, query, (frame: AgentEvent) => {
        if(!isAttached())return
        if (frame.session_id) { querySessionID=frame.session_id;activeStreamRef.current!.sessionId=frame.session_id;setSessionId(frame.session_id); rememberSession(frame.session_id) }
        if (frame.type === 'approval') { setEntries(old=>old.map(item=>item.id===userEntryID?{...item,status:'completed'}:item));setApprovalNotice('');void refreshApprovals() }
        if (frame.type === 'reasoning' && frame.content) {
          setReasoningSeen(true)
          const reasoningID=`reasoning_${frame.segment_id||'current'}`
          setEntries((old) => {
            const existing=old.find((item)=>item.id===reasoningID)
            if(existing)return old.map((item)=>item.id===reasoningID?{...item,content:item.content+frame.content,active:true}:item)
            return [...old.filter((item)=>item.id!=='streaming').map(deactivateReasoning),{id:reasoningID,kind:'reasoning',content:frame.content!,active:true},{id:'streaming',kind:'assistant',content:'',streaming:true}]
          })
        }
        if (frame.type === 'message' && frame.content) {
          if (frame.role === 'tool') {setEntries((old) => [...old.filter((item) => item.id !== 'streaming').map(deactivateReasoning), { id: clientId(), kind: 'tool', content: frame.content!, tool: frame.tool_name }, { id: 'streaming', kind: 'assistant', content: '', streaming:true }]);if(frame.tool_name?.startsWith('ops_plan_')){const nextPlan=planFromToolContent(frame.content);if(nextPlan)setPlan(nextPlan)}if(/approval_id|approval_required/.test(frame.content))void refresh()}
          else setEntries((old) => old.map((item) => item.id === 'streaming' ? {...item, content: item.content + frame.content} : deactivateReasoning(item)))
        }
        if (frame.type === 'done') setEntries(old=>old.map(item=>item.id===userEntryID?{...item,status:'completed'}:item.id==='streaming'?{...item,streaming:false}:item))
        if (frame.type === 'error') setEntries((old) => [...old.map(item=>item.id===userEntryID?{...item,status:'failed' as const}:item.id==='streaming'?{...item,streaming:false}:item), { id: clientId(), kind: 'error', content: frame.error || 'Agent error' }])
      },controller.signal)
    } catch (err) { if(isAttached())setEntries((old) => [...old.map(item=>item.id===userEntryID?{...item,status:'failed' as const}:item), { id: clientId(), kind: 'error', content: errorText(err) }]) }
    finally {
      if(!isAttached())return
      setEntries((old) => old.filter((item) => item.id !== 'streaming' || item.content !== '').map((item)=>item.id==='streaming'?{...item,streaming:false}:deactivateReasoning(item)))
      setRunning(false)
      if(querySessionID){try{const state=await api.chatState(querySessionID);if(!isAttached())return;setDetachedRunning(!!state.active);setPlan(state.plan||null);if(state.active)setEntries(old=>[...historyEntries(state.messages||[]),...old.filter(item=>item.kind==='error'&&!item.id.startsWith('history_'))])}catch{/* polling or the next reload will recover state */}}
      if(!isAttached())return
      activeStreamRef.current=null
      void refreshSessions();void refresh()
    }
  }

  const submit = (event: FormEvent) => {event.preventDefault();const query=message.trim();if(!query||sessionBusy||loadingSession)return;setMessage('');void sendQuery(query)}
  const streamingResponseStarted=entries.some((item)=>item.id==='streaming'&&item.content!=='')

  return <div className="chat-layout">
    <ChatWorkspacePanel workspaces={capabilities.workspaces} workspaceID={selectedWorkspace?.id||''} onSelect={setWorkspaceID} refresh={refresh}/>
    <div className="chat-main panel">
      <div className="panel-header"><div><Bot size={18}/><span>OpsPilot session</span></div><div className="chat-header-actions"><span className="session-id">{sessionId ? sessionId.slice(0, 20) : 'NEW SESSION'}</span><button className="mobile-history-button" onClick={()=>setHistoryOpen(true)} title="Conversations" aria-label="Open conversations"><History size={15}/>{activeSessionCount>0&&<em>{activeSessionCount}</em>}</button></div></div>
      <div className="session-approval-slot">{currentApprovals.length>0&&<ApprovalDialog key={currentApprovals[0].id} approval={currentApprovals[0]} pendingCount={currentApprovals.length} hosts={hosts} running={sessionBusy} refresh={refresh} onNotice={setApprovalNotice}/>} {approvalNotice&&currentApprovals.length===0&&<div className="approval-toast"><ShieldCheck size={14}/><span>{approvalNotice}</span><button onClick={()=>setApprovalNotice('')}><X size={13}/></button></div>}</div>
      <div className="session-plan-slot">{plan&&<SessionPlan plan={plan}/>}</div>
      <div className="messages" ref={messagesRef} onScroll={event=>{const element=event.currentTarget;stickToLatest.current=element.scrollHeight-element.scrollTop-element.clientHeight<90}}>
        {entries.length === 0 && <div className="empty-chat"><div className="radar"><Activity size={35}/></div><h2>What should we investigate?</h2><p>Ask OpsPilot to inspect, diagnose, deploy, or recover a registered Linux host.</p><div className="suggestions">
          {['检查服务器磁盘和内存状态', '分析最近一次服务故障', '查看历史失败命令并继续排查'].map((item) => <button key={item} onClick={() => setMessage(item)}>{item}<ChevronRight size={14}/></button>)}
        </div></div>}
        {entries.map((entry) => <ChatBubble key={entry.id} entry={entry} runs={runs} hosts={hosts}/>) }
        {running && !reasoningSeen && !streamingResponseStarted && <div className="thinking"><span/><span/><span/> 等待模型响应</div>}
        {detachedRunning&&!running&&<div className="thinking background-agent"><span/><span/><span/> Agent 正在后台继续执行，刷新页面不会中断</div>}
      </div>
	  <form className="composer" onSubmit={submit}>{sessionBusy&&<div className="llm-work-status" role="status" aria-live="polite"><LoaderCircle className="spin" size={13}/><b>LLM 运行中</b></div>}<div className="context-line"><span><Server size={13}/>{hosts.length ? `${hosts.length} hosts: ${hostNames}` : 'No hosts registered'}</span><span className="composer-workspace"><FolderOpen size={13}/>{selectedWorkspace?`Workspace: ${selectedWorkspace.id}`:'No Workspace'}</span>{selectedWorkspace?.access==='read_write'&&<QuickWorkspaceUpload workspace={selectedWorkspace} refresh={refresh}/>}<span><Cpu size={13}/>{modelName || 'No active model'}</span><span><ShieldCheck size={13}/>Guarded execution</span></div><div className="input-row"><textarea value={message} onChange={(event) => setMessage(event.target.value)} placeholder={!agentAvailable?'Configure and activate a model provider':loadingSession?'Loading conversation…':sessionBusy?'Agent is still running in this conversation…':'Describe an incident or deployment goal…'} disabled={!agentAvailable||sessionBusy||!!loadingSession} onKeyDown={(event) => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); event.currentTarget.form?.requestSubmit() } }}/><button disabled={!agentAvailable || sessionBusy || !!loadingSession || !message.trim()}><Send size={18}/></button></div></form>
    </div>
	{historyOpen&&<button className="conversation-backdrop" onClick={()=>setHistoryOpen(false)} aria-label="Close conversations"/>}
	<aside className={`context-panel conversation-panel panel ${historyOpen?'mobile-open':''}`}><div className="panel-header"><div><History size={17}/><span>Conversations</span></div><section className="conversation-header-actions"><button className="new-chat-button" onClick={newChat} title="New conversation"><Plus size={14}/>New</button><button className="conversation-close-button" onClick={()=>setHistoryOpen(false)} title="Close conversations" aria-label="Close conversations"><X size={14}/></button></section></div><div className="session-list">
      {historyError&&<div className="history-error">{historyError}</div>}
      {!sessions.length&&!historyError&&<div className="history-empty">No saved conversations yet.</div>}
      {sessions.map(session=>{const pending=approvals.filter(item=>item.session_id===session.id).length;const active=session.active||(session.id===sessionId&&sessionBusy);return <div className={`session-item ${session.id===sessionId?'active':''}`} key={session.id}><button className="session-open" onClick={()=>switchSession(session.id)} disabled={loadingSession===session.id}><b>{session.title}{pending>0&&<em className="session-approval-count">{pending} approval</em>}{active&&<em className="session-running-count">running</em>}</b><span>{new Date(session.updated_at).toLocaleString()} · {session.message_count} messages</span></button><button className="session-delete" onClick={()=>removeSession(session)} disabled={active} title={active?'Agent is still running':'Delete conversation'}><Trash2 size={13}/></button></div>})}
    </div><div className="session-summary"><Metric label="Saved" value={sessions.length.toString()} tone="green"/><Metric label="Hosts" value={hosts.length.toString()}/></div></aside>
  </div>
}

function formatFileSize(size:number){if(size<1024)return `${size} B`;if(size<1024*1024)return `${(size/1024).toFixed(1)} KiB`;return `${(size/1024/1024).toFixed(1)} MiB`}

function ChatWorkspacePanel({workspaces,workspaceID,onSelect,refresh}:{workspaces:WorkspaceCapability[];workspaceID:string;onSelect:(id:string)=>void;refresh:()=>Promise<void>}){
	const workspace=workspaces.find(item=>item.id===workspaceID)||workspaces[0]
	const [path,setPath]=useState('.'),[entries,setEntries]=useState<{name:string;type:'file'|'directory';size?:number}[]>([]),[loading,setLoading]=useState(false),[error,setError]=useState('')
	const [file,setFile]=useState<File|null>(null),[target,setTarget]=useState(''),[uploading,setUploading]=useState(false),[notice,setNotice]=useState(''),[inputKey,setInputKey]=useState(0)
	const [preview,setPreview]=useState<WorkspaceFilePreview|null>(null),[previewLoading,setPreviewLoading]=useState(''),[deleting,setDeleting]=useState('')
	const load=useCallback(async()=>{if(!workspace)return;setLoading(true);try{const result=await api.workspaceFiles(workspace.id,path);setEntries(result.entries||[]);setError('')}catch(err){setEntries([]);setError(errorText(err))}finally{setLoading(false)}},[workspace,path])
	useEffect(()=>{setPath('.');setFile(null);setTarget('');setNotice('');setPreview(null)},[workspace?.id])
	useEffect(()=>{void load()},[load])
	const choose=(event:React.ChangeEvent<HTMLInputElement>)=>{const selected=event.target.files?.[0]||null;setFile(selected);setTarget(selected?(path==='.'?selected.name:`${path}/${selected.name}`):'');setNotice('')}
	const upload=async()=>{if(!workspace||!file||!target.trim())return;setUploading(true);setNotice('');try{const result=await api.uploadWorkspaceFile(workspace.id,file,target.trim());setNotice(`Uploaded · ${result.path}`);setFile(null);setTarget('');setInputKey(value=>value+1);await load();await refresh()}catch(err){setNotice(errorText(err))}finally{setUploading(false)}}
	const openEntry=async(name:string,type:'file'|'directory')=>{const next=path==='.'?name:`${path}/${name}`;if(type==='directory'){setPath(next);return}if(!workspace)return;setPreviewLoading(next);setNotice('');try{setPreview(await api.previewWorkspaceFile(workspace.id,next))}catch(err){setNotice(errorText(err))}finally{setPreviewLoading('')}}
	const removeEntry=async(name:string,type:'file'|'directory')=>{if(!workspace)return;const next=path==='.'?name:`${path}/${name}`;const target=type==='directory'?'folder and all of its contents':'file';if(!confirm(`Delete ${target} “${next}”?\n\nIt will be moved to OpsPilot's recovery area.`))return;setDeleting(next);setNotice('');try{const result=await api.deleteWorkspaceEntry(workspace.id,next);if(preview?.path===next)setPreview(null);setNotice(`Deleted ${result.type} · recoverable as ${result.trash_id}`);await load();await refresh()}catch(err){setNotice(errorText(err))}finally{setDeleting('')}}
	const up=()=>{if(path==='.')return;const parts=path.split('/');parts.pop();setPath(parts.join('/')||'.')}
	if(!workspace)return <aside className="workspace-browser-panel panel empty"><div className="panel-header"><div><FolderOpen size={17}/><span>Workspace</span></div></div><div className="workspace-empty"><FolderOpen size={23}/><span>No Workspace configured</span></div></aside>
	return <><aside className="workspace-browser-panel panel"><div className="panel-header"><div><FolderOpen size={17}/><span>Workspace</span></div>{workspaces.length>1?<select value={workspace.id} onChange={event=>onSelect(event.target.value)}>{workspaces.map(item=><option value={item.id} key={item.id}>{item.id}</option>)}</select>:<code>{workspace.id}</code>}</div><div className="chat-workspace-head"><span><b>Local files</b><small title={workspace.root}>{workspace.root}</small></span><em className={workspace.access}>{workspace.access.replace('_',' ')}</em></div><div className="workspace-path-row"><button onClick={up} disabled={path==='.'} title="Parent directory">‹</button><code title={path}>{path}</code>{workspace.access==='read_write'&&<label title="Upload file"><UploadCloud size={14}/><input key={inputKey} type="file" onChange={choose}/></label>}<button onClick={()=>void load()} title="Refresh files"><RefreshCw size={12}/></button></div>{file&&<div className="chat-upload-row"><input value={target} onChange={event=>setTarget(event.target.value)} aria-label="Relative upload path"/><button onClick={()=>void upload()} disabled={uploading||!target.trim()}>{uploading?'…':'Upload'}</button><button onClick={()=>{setFile(null);setTarget('');setInputKey(value=>value+1)}} title="Cancel upload"><X size={11}/></button></div>}<div className="workspace-file-list">{loading?<span className="workspace-files-state"><LoaderCircle className="spin" size={13}/>Loading</span>:error?<span className="workspace-files-state error">{error}</span>:entries.length?entries.map(entry=>{const fullPath=path==='.'?entry.name:`${path}/${entry.name}`;return <div className="workspace-file-row" key={`${entry.type}:${entry.name}`}><button className="workspace-file-open" onClick={()=>void openEntry(entry.name,entry.type)} title={entry.type==='file'?'Preview file':'Open directory'}>{previewLoading===fullPath?<LoaderCircle className="spin" size={13}/>:entry.type==='directory'?<FolderOpen size={13}/>:<FileText size={13}/>}<span>{entry.name}</span>{entry.type==='file'&&<small>{formatFileSize(entry.size??0)}</small>}</button>{workspace.access==='read_write'&&<button className="workspace-file-delete" onClick={()=>void removeEntry(entry.name,entry.type)} disabled={deleting===fullPath} title={`Delete ${entry.type}`}><Trash2 size={12}/></button>}</div>}):<span className="workspace-files-state">This directory is empty. Upload a file here.</span>}</div>{notice&&<div className={`chat-workspace-notice ${notice.startsWith('Uploaded')||notice.startsWith('Deleted')?'success':'error'}`}>{notice}</div>}<div className="workspace-browser-hint"><FileText size={12}/><span>Click a file to preview it. Nothing is added to the conversation automatically.</span></div></aside>{preview&&<div className="workspace-preview-backdrop" role="presentation" onMouseDown={event=>{if(event.target===event.currentTarget)setPreview(null)}}><section className="workspace-preview-dialog" role="dialog" aria-modal="true" aria-label={`Preview ${preview.path}`}><header><div><FileText size={18}/><span><b>{preview.path}</b><small>{formatFileSize(preview.size)} · SHA-256 {preview.sha256}</small></span></div><button onClick={()=>setPreview(null)} title="Close preview"><X size={16}/></button></header>{preview.binary?<div className="workspace-binary-preview"><FileText size={30}/><b>Binary file</b><span>This file cannot be rendered as text. Its size and checksum are shown above.</span></div>:<pre>{preview.content||''}</pre>}{preview.truncated&&<footer>Preview is limited to the first 1 MiB. The original file was not modified.</footer>}</section></div>}</>
}

function QuickWorkspaceUpload({workspace,refresh}:{workspace:WorkspaceCapability;refresh:()=>Promise<void>}){
	const [busy,setBusy]=useState(false),[status,setStatus]=useState(''),[inputKey,setInputKey]=useState(0)
	useEffect(()=>{if(status!=='Uploaded')return;const timer=window.setTimeout(()=>setStatus(''),3000);return()=>window.clearTimeout(timer)},[status])
	const choose=async(event:React.ChangeEvent<HTMLInputElement>)=>{const file=event.target.files?.[0];if(!file)return;setBusy(true);setStatus('');try{await api.uploadWorkspaceFile(workspace.id,file,file.name);setStatus('Uploaded');await refresh()}catch(err){setStatus(errorText(err))}finally{setBusy(false);setInputKey(value=>value+1)}}
	return <label className={`quick-workspace-upload ${busy?'busy':''} ${status&&status!=='Uploaded'?'error':''}`} title={status||`Upload to Workspace ${workspace.id}`}><UploadCloud size={12}/><b>{busy?'Uploading…':status==='Uploaded'?'Uploaded':status?'Upload failed':'Upload file'}</b><input key={inputKey} type="file" disabled={busy} onChange={event=>void choose(event)}/></label>
}

function SessionPlan({plan}:{plan:AgentPlan}){
  const [expanded,setExpanded]=useState(plan.status==='active')
  useEffect(()=>{if(plan.status==='active')setExpanded(true)},[plan.session_id,plan.status])
  const completed=plan.steps.filter(step=>step.status==='completed').length
  const current=plan.steps.find(step=>step.status==='in_progress'||step.status==='blocked')
  const progress=plan.steps.length?Math.round(completed/plan.steps.length*100):0
  return <details className={`session-plan ${plan.status}`} open={expanded} onToggle={event=>setExpanded(event.currentTarget.open)}><summary><span className="plan-icon"><ListChecks size={16}/></span><span className="plan-summary-copy"><b>{plan.goal}</b><small>{current?`${current.status==='blocked'?'阻塞在':'当前'} ${current.number}/${plan.steps.length} · ${current.title}`:`${completed}/${plan.steps.length} steps completed`}</small></span><span className="plan-progress"><i><em style={{width:`${progress}%`}}/></i><b>{progress}%</b></span><span className={`plan-state ${plan.status}`}>{plan.status}</span><ChevronRight size={14}/></summary><ol>{plan.steps.map(step=><li className={step.status} key={step.number}><span className="plan-step-marker">{step.status==='completed'?<Check size={12}/>:step.status==='in_progress'?<LoaderCircle size={12}/>:step.status==='blocked'?<ShieldAlert size={12}/>:step.number}</span><div><b>{step.title}</b>{step.evidence&&<p>{step.evidence}</p>}</div><em>{step.status.replace('_',' ')}</em></li>)}</ol></details>
}

const ChatBubble=memo(function ChatBubble({ entry, runs, hosts }: {entry: ChatEntry;runs:Run[];hosts:Host[]}) {
  if (entry.kind === 'tool') return <ToolEventCard entry={entry} runs={runs} hosts={hosts}/>
  if (entry.kind === 'reasoning') return <ReasoningCard content={entry.content} active={!!entry.active}/>
  if (entry.kind === 'assistant' && !entry.content) return null
  return <div className={`bubble ${entry.kind} ${entry.status||''}`}><div className="avatar">{entry.kind === 'user' ? 'YOU' : entry.kind === 'error' ? '!' : <Bot size={17}/>}</div><div><span className="bubble-label">{entry.kind === 'user' ? <>Operator{entry.status==='failed'&&<em>未进入后续上下文</em>}{entry.status==='pending'&&<em>处理中</em>}</> : entry.kind === 'error' ? 'Error' : 'OpsPilot'}</span><div className={`bubble-copy ${entry.kind==='assistant'&&!entry.streaming?'markdown-body':''}`}>{entry.kind==='assistant'&&!entry.streaming?<Markdown skipHtml remarkPlugins={[remarkGfm]} components={{a:({href,children})=><a href={href} target="_blank" rel="noopener noreferrer">{children}</a>,img:({alt})=><span className="markdown-image-blocked">[Blocked image: {alt||'no description'}]</span>}}>{entry.content||'…'}</Markdown>:entry.content||'…'}</div></div></div>
})

function latestReasoningLine(content:string){
  const lines=content.split(/\r?\n/).map((line)=>line.trim()).filter(Boolean)
  const line=lines.at(-1)||'正在思考…'
  const characters=Array.from(line)
  return characters.length>72?`…${characters.slice(-72).join('')}`:line
}

function ReasoningCard({content,active}:{content:string;active:boolean}){
  const latest=latestReasoningLine(content)
  return <details className={`reasoning-card ${active?'active':''}`}>
    <summary><span className="reasoning-icon"><BrainCircuit size={15}/></span><span className="reasoning-title">{active?'思考中':'思考过程'}</span><span className="reasoning-latest" title={latest}>{latest}</span><ChevronRight className="reasoning-chevron" size={14}/></summary>
    <div className="reasoning-content"><pre>{content}</pre></div>
  </details>
}

type JsonRecord = Record<string,unknown>
const toolLabels:Record<string,string>={ssh_exec:'执行远程命令',ssh_run_script:'执行 Bash 脚本',ssh_file_read:'读取远程文件',ssh_file_search:'搜索远程文件',ssh_file_list:'列出远程目录',ssh_file_stat:'读取文件信息',ssh_file_write:'事务写入远程文件',ssh_file_apply_patch:'事务应用远程补丁',ssh_config_apply:'应用远程配置事务',ssh_config_restore:'恢复远程配置备份',ssh_task_start:'启动远程任务',ssh_task_status:'查看任务状态',ssh_task_tail:'查看任务输出',ssh_task_list:'列出持久任务',ssh_host_list:'列出主机',ssh_host_inspect:'检查主机',workspace_list:'列出 Workspace',workspace_file_list:'列出 Workspace 目录',workspace_file_read:'读取 Workspace 文件',workspace_file_search:'搜索 Workspace 文件',workspace_file_apply_patch:'应用 Workspace 补丁',workspace_file_upload:'上传 Workspace 文件',workspace_shell:'在 Workspace 运行 Shell',ssh_history_search:'搜索执行历史',ssh_history_get:'读取执行历史',ops_skill_list:'列出 Skills',ops_skill_get:'加载 Skill',ops_plan_create:'创建任务计划',ops_plan_get:'读取任务计划',ops_plan_step_update:'推进任务步骤'}
function jsonRecord(value:unknown):JsonRecord|undefined{return value!==null&&typeof value==='object'&&!Array.isArray(value)?value as JsonRecord:undefined}
function parseRecord(value:string):JsonRecord{try{return jsonRecord(JSON.parse(value))||{value:JSON.parse(value)}}catch{return{value}}}
function requestFromRun(run?:Run):JsonRecord|undefined{if(!run)return;try{return jsonRecord(JSON.parse(run.request_json))}catch{return}}
function textValue(value:unknown){return typeof value==='string'?value:''}
function shellArg(value:string){return /^[A-Za-z0-9_@%+=:,./-]+$/.test(value)?value:JSON.stringify(value)}
function fullProgram(request:JsonRecord){const program=textValue(request.program);const args=Array.isArray(request.args)?request.args.map(value=>String(value)):[];return [program,...args].filter(Boolean).map(shellArg).join(' ')}
function compactScript(script:string){const lines=script.split(/\r?\n/).map(line=>line.trim()).filter(Boolean);if(!lines.length)return'Bash script';return lines.length===1?lines[0]:`${lines[0]}  … (+${lines.length-1} lines)`}
function latestOutput(value:string,limit=3){return value.trimEnd().split(/\r?\n/).filter(line=>line.trim()!=='').slice(-limit).map(line=>Array.from(line).length>180?`${Array.from(line).slice(0,180).join('')}…`:line).join('\n')}
function formatDuration(value:unknown,run?:Run){if(typeof value==='number'&&Number.isFinite(value))return value>=1e9?`${(value/1e9).toFixed(2)} s`:`${(value/1e6).toFixed(1)} ms`;if(run?.completed_at){const ms=Date.parse(run.completed_at)-Date.parse(run.started_at);if(Number.isFinite(ms))return ms>=1000?`${(ms/1000).toFixed(2)} s`:`${ms} ms`}return'—'}

function ToolEventCard({entry,runs,hosts}:{entry:ChatEntry;runs:Run[];hosts:Host[]}){
  const payload=parseRecord(entry.content)
	const taskPayload=jsonRecord(payload.task)
	const resultPayload=jsonRecord(payload.result)
  const runID=textValue(payload.run_id)||textValue(taskPayload?.run_id)||textValue(resultPayload?.run_id)
  const run=runs.find(item=>item.id===runID)
  const display=jsonRecord(payload._display)
  const request=jsonRecord(display?.request)||requestFromRun(run)
  const hostID=textValue(display?.host_id)||run?.host_id||textValue(request?.host_id)
  const hostName=hosts.find(host=>host.id===hostID||host.name===hostID)?.name||hostID||'—'
  const status=textValue(payload.status)||textValue(taskPayload?.status)||textValue(resultPayload?.status)||run?.status||'completed'
  const risk=textValue(display?.risk)||textValue(resultPayload?.risk)||run?.risk||''
  const program=request?fullProgram(request):''
  const script=request?textValue(request.script):''
  const remotePath=request?textValue(request.remote_path):''
	const workspaceID=request?textValue(request.workspace_id):''
	const relativePath=request?textValue(request.relative_path):''
	const requestMode=request?textValue(request.mode):''
	const workspaceShellBackend=request?textValue(request.workspace_shell_backend):''
	const workspaceTransfer=requestMode==='workspace_upload'
	const file=jsonRecord(payload.file)||jsonRecord(resultPayload?.file)
	const filePath=textValue(file?.path)||remotePath||relativePath
	const transferSummary=workspaceTransfer?`${workspaceID}:${relativePath} → ${remotePath}`:''
  const planSteps=Array.isArray(payload.steps)?payload.steps.map(jsonRecord).filter((step):step is JsonRecord=>!!step):[]
  const planSummary=textValue(payload.goal)||textValue(planSteps.find(step=>textValue(step.status)==='in_progress'||textValue(step.status)==='blocked')?.title)
	const operation=filePath||(script?'Bash script':program||toolLabels[entry.tool||'']||entry.tool||'Tool result')
  const args=request&&Array.isArray(request.args)?request.args.map(value=>String(value)):[]
  const env=request?jsonRecord(request.env):undefined
  const stdout=textValue(payload.stdout)||textValue(resultPayload?.stdout)||run?.stdout_redacted||''
  const stderr=textValue(payload.stderr)||textValue(resultPayload?.stderr)||run?.stderr_redacted||run?.error||''
  const stdoutPreview=latestOutput(stdout)
	const commandSummary=transferSummary||filePath||program||(script?compactScript(script):'')||planSummary||operation
  const instruction=textValue(payload.operator_instruction)||textValue(taskPayload?.operator_instruction)||textValue(resultPayload?.operator_instruction)
  const rawPayload={...payload};delete rawPayload._display
  const [expanded,setExpanded]=useState(false)
  const resultExitCode=resultPayload?.exit_code
  const exitCode=typeof payload.exit_code==='number'?payload.exit_code:typeof resultExitCode==='number'?resultExitCode:run?.exit_code??'—'
  return <details className={`tool-event tool-event-rich ${status}`} open={expanded} onToggle={event=>setExpanded(event.currentTarget.open)}>
    <summary><div className="tool-summary-icon"><TerminalSquare size={15}/></div><div className="tool-summary-copy"><b>{toolLabels[entry.tool||'']||entry.tool||'SSH Tool'}：</b><code title={commandSummary}>{commandSummary}</code></div><span className={`tool-status ${status}`}>{status.replaceAll('_',' ')}</span><ChevronRight size={14}/>{stdoutPreview&&<div className="tool-summary-preview"><span>STDOUT · 最新 {Math.min(3,stdoutPreview.split('\n').length)} 行</span><pre>{stdoutPreview}</pre></div>}</summary>
    <div className="tool-event-body">
      {request?<div className="tool-execution-layout">
        <section className="tool-command-pane">
		  <div className="tool-command-head"><span>{filePath?'受控文件操作':`LLM 请求运行的完整${script?'脚本':'命令'}`}</span>{workspaceShellBackend&&<em><TerminalSquare size={12}/>{workspaceShellBackend==='host'?'Host Shell':'Bubblewrap'}</em>}{request.elevated===true&&<em><ShieldAlert size={12}/>受控 sudo</em>}</div>
		  <div className="tool-command-block">{workspaceTransfer?<pre>workspace_upload {workspaceID}:{relativePath} → {remotePath}</pre>:filePath?<pre>{requestMode} {workspaceID?`${workspaceID}:`:''}{filePath}</pre>:script?<pre>{script}</pre>:program?<pre><span className="prompt-sign">$</span> {program}</pre>:<pre>{requestMode} {remotePath}</pre>}</div>
		  {filePath&&script&&<details className="tool-raw"><summary>查看完整事务脚本 / Patch</summary><pre>{script}</pre></details>}
          {program&&<CompactTable title="ARGV · 原始参数" columns={['INDEX','VALUE']} rows={[[0,textValue(request.program)],...args.map((arg,index)=>[index+1,JSON.stringify(arg)])]}/>} 
          {env&&Object.keys(env).length>0&&<CompactTable title="环境变量" columns={['KEY','VALUE']} rows={Object.entries(env).map(([key,value])=>[key,String(value)])}/>} 
        </section>
        <aside className="tool-context-pane">
		  <dl className="tool-context-grid"><div><dt>{workspaceTransfer?'目标主机':workspaceID?'Workspace':'目标主机'}</dt><dd>{workspaceTransfer?hostName:workspaceID||hostName}</dd></div><div><dt>{workspaceTransfer?'源文件':filePath?'文件路径':'工作目录'}</dt><dd>{workspaceTransfer?`${workspaceID}:${relativePath}`:filePath||textValue(request.cwd)||'默认目录'}</dd></div><div><dt>权限</dt><dd>{workspaceShellBackend==='host'?'宿主机完整权限':workspaceShellBackend==='sandbox'?'Bubblewrap 沙盒':request.elevated===true?'managed sudo':'普通用户'}</dd></div><div><dt>风险</dt><dd>{risk||'—'}</dd></div><div><dt>状态</dt><dd>{status}</dd></div><div><dt>退出码</dt><dd>{exitCode}</dd></div><div><dt>耗时</dt><dd>{formatDuration(payload.duration??resultPayload?.duration,run)}</dd></div><div><dt>Run ID</dt><dd>{runID||'—'}</dd></div></dl>
          {textValue(request.reason)&&<div className="tool-reason"><span>执行原因</span><p>{textValue(request.reason)}</p></div>}
          {textValue(request.expected_changes)&&<div className="tool-reason change"><span>预期变化</span><p>{textValue(request.expected_changes)}</p></div>}
          {textValue(request.rollback)&&<div className="tool-reason rollback"><span>回滚方案</span><p>{textValue(request.rollback)}</p></div>}
        </aside>
      </div>:<GenericToolResult payload={payload}/>} 
	  {file&&<FileMetadataPanel file={file}/>}
	  {(textValue(payload.message)||textValue(payload.next_action))&&<div className={`tool-guidance ${payload.ok===false?'error':''}`}><ShieldAlert size={15}/><div><b>{textValue(payload.code)||'Tool result'}</b>{textValue(payload.message)&&<p>{textValue(payload.message)}</p>}{textValue(payload.next_action)&&<small>Next · {textValue(payload.next_action)}</small>}</div></div>}
      {instruction&&<div className="tool-instruction"><ShieldAlert size={15}/><div><b>Operator instruction</b><p>{instruction}</p></div></div>}
      {(stdout||stderr)&&<div className="tool-output-grid">{stdout&&<div className="tool-output stdout"><span>STDOUT</span><pre>{stdout}</pre></div>}{stderr&&<div className="tool-output stderr"><span>STDERR / RESULT</span><pre>{stderr}</pre></div>}</div>}
      <details className="tool-raw"><summary>原始 Tool JSON · 排错用</summary><pre>{JSON.stringify(rawPayload,null,2)}</pre></details>
    </div>
  </details>
}

function FileMetadataPanel({file}:{file:JsonRecord}){
	const before=textValue(file.before_sha256),after=textValue(file.sha256),backup=textValue(file.backup_path),validator=textValue(file.validator),operationID=textValue(file.operation_id)
	return <section className="file-metadata-panel"><div className="file-metadata-head"><FileText size={16}/><div><b>文件事务证据</b><span>{textValue(file.path)}</span></div>{file.validation_ok===true&&<em><Check size={12}/>validated</em>}</div><dl><div><dt>读取大小</dt><dd>{typeof file.returned_bytes==='number'?`${file.returned_bytes} B`:'—'}</dd></div><div><dt>Mode</dt><dd>{textValue(file.mode)||'—'}</dd></div><div><dt>Owner</dt><dd>{[textValue(file.owner),textValue(file.group)].filter(Boolean).join(':')||'—'}</dd></div><div><dt>Validator</dt><dd>{validator||'—'}</dd></div></dl>{operationID&&<div className="hash-row"><span>Operation</span><code>{operationID}</code></div>}{before&&<div className="hash-row"><span>Before</span><code>{before}</code></div>}{after&&<div className="hash-row"><span>After</span><code>{after}</code></div>}{backup&&<div className="hash-row"><span>Backup</span><code>{backup}</code></div>}{file.sensitive===true&&<div className="file-sensitive"><ShieldAlert size={13}/>敏感内容已在模型视图中脱敏，禁止用占位符覆盖原文件。</div>}</section>
}

function CompactTable({title,columns,rows}:{title:string;columns:string[];rows:Array<Array<unknown>>}){
  return <div className="tool-compact-table"><span>{title}</span><div className="tool-table-scroll"><table><thead><tr>{columns.map(column=><th key={column}>{column}</th>)}</tr></thead><tbody>{rows.map((row,index)=><tr key={index}>{row.map((value,column)=><td key={column}>{displayValue(value)}</td>)}</tr>)}</tbody></table></div></div>
}

function displayValue(value:unknown):string{
  if(value===null||value===undefined||value==='')return'—'
  if(Array.isArray(value))return value.map(item=>displayValue(item)).join(', ')
  const record=jsonRecord(value)
  if(record)return Object.entries(record).map(([key,item])=>`${key}=${displayValue(item)}`).join(' · ')
  return String(value)
}

function GenericToolResult({payload}:{payload:JsonRecord}){
  const hidden=new Set(['_display','stdout','stderr','operator_instruction'])
  const entries=Object.entries(payload).filter(([key])=>!hidden.has(key))
  const scalars=entries.filter(([,value])=>value===null||typeof value==='string'||typeof value==='number'||typeof value==='boolean')
  const arrays=entries.filter(([,value])=>Array.isArray(value))
  const objects=entries.filter(([,value])=>!!jsonRecord(value))
  return <div className="tool-structured-result">
    {scalars.length>0&&<dl className="tool-generic-grid">{scalars.map(([key,value])=><div key={key}><dt>{key.replaceAll('_',' ')}</dt><dd>{displayValue(value)}</dd></div>)}</dl>}
    {arrays.map(([key,value])=><StructuredArray key={key} label={key} values={value as unknown[]}/>)}
    {objects.map(([key,value])=><StructuredObject key={key} label={key} value={value as JsonRecord}/>)}
    {!entries.length&&<div className="tool-generic-note">Tool 已完成，没有额外返回字段。</div>}
  </div>
}

function StructuredArray({label,values}:{label:string;values:unknown[]}){
  const records=values.map(jsonRecord).filter((item):item is JsonRecord=>!!item)
  if(records.length===values.length&&records.length>0){const columns=[...new Set(records.flatMap(record=>Object.keys(record)))].slice(0,10);return <CompactTable title={`${label.replaceAll('_',' ')} · ${records.length} ITEMS`} columns={columns.map(column=>column.replaceAll('_',' '))} rows={records.map(record=>columns.map(column=>record[column]))}/>} 
  return <div className="tool-array-section"><span>{label.replaceAll('_',' ')}</span><div>{values.map((value,index)=><code key={index}>{displayValue(value)}</code>)}</div></div>
}

function StructuredObject({label,value}:{label:string;value:JsonRecord}){
  return <section className="tool-object-section"><h4>{label.replaceAll('_',' ')}</h4><dl className="tool-generic-grid">{Object.entries(value).map(([key,item])=><div key={key}><dt>{key.replaceAll('_',' ')}</dt><dd>{displayValue(item)}</dd></div>)}</dl></section>
}

function ReviewList({title,items,tone}:{title:string;items?:string[];tone?:string}){
  if(!items?.length)return null
  return <div className={`review-list ${tone||''}`}><b>{title}</b><ul>{items.map((item,index)=><li key={`${title}_${index}`}>{item}</li>)}</ul></div>
}

function CommandExplanationPanel({review}:{review?:CommandReview}){
  if(!review)return null
	if(review.status==='pending')return <div className="command-review-panel pending" role="status" aria-live="polite"><div className="command-review-pending"><span className="review-agent-icon"><LoaderCircle className="spin" size={17}/></span><span><b>命令解释 Agent 正在后台工作</b><small>审批已经可以操作；说明完成后会自动更新。</small></span><em>NON-BLOCKING</em></div></div>
  const explanation=review.explanation
  return <details className={`command-review-panel ${review.status}`}><summary><span className="review-agent-icon"><BrainCircuit size={17}/></span><span><b>命令解释 Agent</b><small>{review.status==='completed'?'命令作用、风险与回滚说明已生成':review.status==='degraded'?'部分解释不可用，确定性策略不受影响':'解释暂不可用，继续由确定性策略与人工审批处理'}</small></span><em>POLICY · {review.deterministic_risk.replace('_',' ')}</em><ChevronRight size={14}/></summary><div className="command-review-body"><div className="review-advisory"><ShieldCheck size={14}/><span>AI 只解释命令，不能修改风险等级、执行命令或批准请求；风险完全由确定性 Policy 判定。</span></div>{explanation&&<section className="review-explanation"><div className="review-section-title"><span>AI</span><div><b>通俗命令说明</b><small>{explanation.summary}</small></div></div><p>{explanation.mechanism}</p><div className="review-list-grid"><ReviewList title="会产生什么影响" items={explanation.effects}/><ReviewList title="需要注意的风险" items={explanation.risks} tone="warn"/><ReviewList title="操作提示" items={explanation.beginner_tips}/></div>{explanation.rollback_guide&&<div className="review-rollback"><b>回滚建议</b><p>{explanation.rollback_guide}</p></div>}</section>}{review.errors&&review.errors.length>0&&<div className="review-errors"><b>降级信息</b>{review.errors.map((item,index)=><code key={index}>{item}</code>)}</div>}<div className="review-meta">Model {review.model||'unavailable'} · {new Date(review.reviewed_at).toLocaleString()}</div></div></details>
}

function ApprovalDialog({approval,pendingCount,hosts,running,refresh,onNotice}:{approval:Approval;pendingCount:number;hosts:Host[];running:boolean;refresh:()=>Promise<void>;onNotice:(message:string)=>void}) {
  const [challenge,setChallenge]=useState('')
  const [note,setNote]=useState('')
  const [decisionBusy,setDecisionBusy]=useState<''|'once'|'session'|'reject'>('')
  const [explanationBusy,setExplanationBusy]=useState(false)
  const [error,setError]=useState('')
  let request:Record<string,unknown>={}
  try{request=JSON.parse(approval.request_json)}catch{request={request:approval.request_json}}
  const script=textValue(request.script)
	const workspaceID=textValue(request.workspace_id)
	const filePath=textValue(request.remote_path)||textValue(request.relative_path)
	const requestMode=textValue(request.mode),relativePath=textValue(request.relative_path),remotePath=textValue(request.remote_path)
	const workspaceShellBackend=textValue(request.workspace_shell_backend)
	const hostWorkspaceShell=requestMode==='workspace_shell'&&workspaceShellBackend==='host'
	const workspaceTransfer=requestMode==='workspace_upload'
  const operation=workspaceTransfer?`${workspaceID}:${relativePath} → ${remotePath}`:fullProgram(request)||script||`${requestMode} ${filePath}`.trim()||'受控操作'
	const targetHost=hosts.find(host=>host.id===approval.host_id)?.name||approval.host_id
	const hostName=workspaceTransfer?targetHost:workspaceID?`Workspace / ${workspaceID}`:targetHost
	const expectedSHA=textValue(request.expected_sha256),validator=textValue(request.validator)
	const explanationPending=approval.ai_review?.status==='pending'
  const decide=async(scope:'once'|'session')=>{
    setDecisionBusy(scope);setError('')
    try{const result=await api.approve(approval.id,challenge,note.trim()||'Reviewed and approved in the current Agent session.',scope);onNotice(`审批已通过 · ${result.status} · ${result.run_id}`);await refresh()}
    catch(err){setError(errorText(err))}finally{setDecisionBusy('')}
  }
  const reject=async()=>{
    const instruction=note.trim();if(!instruction){setError('请先输入希望 OpsPilot 改为执行的方案。');return}
    setDecisionBusy('reject');setError('')
    try{await api.reject(approval.id,instruction);onNotice('审批已拒绝 · OpsPilot 正在按你的替代方案继续。');await refresh()}catch(err){setError(errorText(err))}finally{setDecisionBusy('')}
  }
  const retryExplanation=async()=>{
    setExplanationBusy(true);setError('')
    try{
      const updated=await api.retryApprovalExplanation(approval.id)
      const status=updated.ai_review?.status
      onNotice(status==='completed'?'命令解释已重新生成。':'解释 Agent 已重试，但模型仍处于降级状态。')
      await refresh()
    }catch(err){setError(errorText(err))}finally{setExplanationBusy(false)}
  }
  const decisionDisabled=!!decisionBusy
	return <div className="approval-modal-backdrop"><section className={`approval-dialog ${approval.risk}`} role="dialog" aria-modal="true" aria-labelledby="approval-dialog-title"><div className="approval-dialog-head"><div className="approval-dialog-icon"><ShieldAlert size={20}/></div><div><span>HUMAN APPROVAL · {pendingCount>1?`1 OF ${pendingCount}`:'CURRENT SESSION'}</span><h2 id="approval-dialog-title">OpsPilot 请求执行受控操作</h2></div><em className={`risk ${approval.risk}`}>{approval.risk.replace('_',' ')}</em></div><div className="approval-operation"><span className="approval-command-label">{filePath?'完整受控文件事务':`LLM 请求运行的完整${script?'脚本':'命令'}`}</span>{filePath&&<div className="approval-file-target"><FileText size={15}/><div><b>{workspaceTransfer?`${workspaceID}:${relativePath} → ${remotePath}`:filePath}</b><span>{expectedSHA?`Expected SHA256 · ${expectedSHA}`:'未绑定已有版本'}{validator?` · Validator ${validator}`:''}</span></div></div>}<pre className="approval-command-preview">{script||`$ ${operation}`}</pre><dl><div><dt>{workspaceTransfer?'Host':workspaceID?'Workspace':'Host'}</dt><dd>{hostName}</dd></div>{workspaceShellBackend&&<div><dt>Backend</dt><dd>{hostWorkspaceShell?'Host Shell · full authority':'Bubblewrap sandbox'}</dd></div>}<div><dt>Expires</dt><dd><Clock3 size={12}/>{new Date(approval.expires_at).toLocaleTimeString()}</dd></div><div><dt>Digest</dt><dd>{approval.request_digest.slice(0,12)}</dd></div></dl>{hostWorkspaceShell&&<div className="approval-host-shell-warning"><ShieldAlert size={14}/><span>此脚本直接访问宿主机文件系统与网络。本次授权仅对当前请求有效。</span></div>}{typeof request.reason==='string'&&<p>{request.reason}</p>}</div><CommandExplanationPanel review={approval.ai_review}/><div className="review-retry-row"><span>{explanationPending||explanationBusy?'后台解释不会阻塞当前审批。':'只重新生成命令说明，不会修改风险或执行命令。'}</span><button disabled={decisionDisabled||explanationPending||explanationBusy} onClick={retryExplanation}><RefreshCw className={explanationBusy||explanationPending?'spin':''} size={13}/>{explanationPending?'解释 Agent 工作中…':explanationBusy?'正在重新解释…':'重新生成命令解释'}</button></div>{approval.challenge&&<label className="approval-challenge-input"><span>Break-glass challenge · 输入 <code>{approval.challenge}</code></span><input value={challenge} onChange={event=>setChallenge(event.target.value)} placeholder="输入上方 challenge" autoComplete="off" autoFocus/></label>}<label className="approval-guidance"><span>审批说明 / 拒绝后告诉 LLM 应该改做什么</span><textarea value={note} maxLength={2000} onChange={event=>setNote(event.target.value)} placeholder="例如：不要重启服务，先只读取最近 100 行日志并分析原因。" autoFocus={!approval.challenge}/></label>{error&&<div className="approval-dialog-error"><ShieldAlert size={14}/>{error}</div>}<details className="approval-request-detail"><summary>查看完整请求</summary><pre>{JSON.stringify(request,null,2)}</pre></details><div className="approval-choice-grid"><button className="allow-once" disabled={decisionDisabled} onClick={()=>decide('once')}><Check size={16}/><span><b>{decisionBusy==='once'?'正在执行…':'仅允许本次'}</b><small>只批准当前请求摘要</small></span></button><button className="allow-session" disabled={decisionDisabled||approval.risk==='critical'||hostWorkspaceShell} onClick={()=>decide('session')} title={hostWorkspaceShell?'Host Shell 每次都必须单独授权':approval.risk==='critical'?'Critical 操作不能会话级放行':''}><ShieldCheck size={16}/><span><b>{decisionBusy==='session'?'正在授权…':'本会话允许相同操作'}</b><small>{hostWorkspaceShell?'Host Shell 不可用':approval.risk==='critical'?'Critical 不可用':'目标、内容和参数必须完全一致'}</small></span></button><button className="reject-guidance" disabled={decisionDisabled||!note.trim()} onClick={reject}><X size={16}/><span><b>{decisionBusy==='reject'?'正在反馈…':'拒绝并告诉 LLM'}</b><small>将输入框内容作为新指令</small></span></button></div><p className="approval-wait">{running?'当前 Agent 已暂停在这个 Tool 调用，审批后会从原位置继续。':'原 Agent 连接已结束；本次决定仍会被执行并写入审计。'}</p></section></div>
}

const maxPrivateKeyBytes=1<<20
const emptyHostForm: HostInput = {name:'',address:'',port:22,user:'',auth_type:'agent',private_key:'',known_hosts_file:'',proxy_jump_host_id:'',password:'',sudo_mode:'none',sudo_password:''}
const authLabels: Record<HostAuthType,string> = {agent:'SSH agent',key:'Uploaded private key',password:'Account password'}
const sudoLabels: Record<HostSudoMode,string> = {none:'Disabled',nopasswd:'sudo -n (NOPASSWD)',password:'Managed sudo password'}

function HostsPage({ hosts, refresh }: {hosts:Host[];refresh:()=>Promise<void>}) {
  const [showForm, setShowForm] = useState(false); const [notice, setNotice] = useState(''); const [saving,setSaving]=useState(false)
  const [form, setForm] = useState<HostInput>(emptyHostForm)
	const [privateKeyName,setPrivateKeyName]=useState(''),[privateKeyError,setPrivateKeyError]=useState(''),[existingPrivateKey,setExistingPrivateKey]=useState(false),[privateKeyInputKey,setPrivateKeyInputKey]=useState(0)
  const editing=!!form.id
	const resetPrivateKey=()=>{setPrivateKeyName('');setPrivateKeyError('');setExistingPrivateKey(false);setPrivateKeyInputKey(value=>value+1)}
	const openCreate=()=>{setForm(emptyHostForm);resetPrivateKey();setShowForm(true);setNotice('')}
	const openEdit=(host:Host)=>{setForm({id:host.id,name:host.name,address:host.address,port:host.port,user:host.user,auth_type:host.auth_type||'agent',private_key:'',known_hosts_file:host.known_hosts_file||'',proxy_jump_host_id:host.proxy_jump_host_id||'',password:'',sudo_mode:host.sudo_mode||'none',sudo_password:''});setPrivateKeyName('');setPrivateKeyError('');setExistingPrivateKey(host.auth_type==='key'&&host.has_private_key);setPrivateKeyInputKey(value=>value+1);setShowForm(true);setNotice('')}
	const setAuthType=(auth_type:HostAuthType)=>{setForm(current=>({...current,auth_type,password:'',private_key:auth_type==='key'?current.private_key:''}));if(auth_type!=='key'){setPrivateKeyName('');setPrivateKeyError('');setPrivateKeyInputKey(value=>value+1)}}
	const choosePrivateKey=async(event:React.ChangeEvent<HTMLInputElement>)=>{const selected=event.target.files?.[0];setPrivateKeyError('');if(!selected){setPrivateKeyName('');setForm(current=>({...current,private_key:''}));return}if(selected.size<=0||selected.size>maxPrivateKeyBytes){setPrivateKeyName('');setForm(current=>({...current,private_key:''}));setPrivateKeyError('Private key must be between 1 byte and 1 MiB.');return}try{const content=await selected.text();setPrivateKeyName(selected.name);setForm(current=>({...current,private_key:content}))}catch(err){setPrivateKeyName('');setForm(current=>({...current,private_key:''}));setPrivateKeyError(errorText(err))}}
	const missingPrivateKey=form.auth_type==='key'&&!form.private_key&&!existingPrivateKey
	const save = async (event:FormEvent) => { event.preventDefault(); if(missingPrivateKey)return;setSaving(true); try { const saved=await api.saveHost(form); setShowForm(false); setForm(emptyHostForm);resetPrivateKey(); setNotice(`${saved.name} ${editing?'updated':'registered'}. Credentials are encrypted and are never returned by the API.`); await refresh() } catch(err){setNotice(errorText(err))} finally{setSaving(false)} }
  const scan = async (host:Host) => { try { const key = await api.scanKey(host.id); if (confirm(`Trust ${host.name}?\n\n${key.algorithm?`${key.algorithm}\n`:''}${key.fingerprint}`)) { await api.trustKey(host.id, key.fingerprint); setNotice(`Trusted ${key.fingerprint}`) } } catch(err){setNotice(errorText(err))} }
  const probe = async (host:Host) => { try { const info = await api.probe(host.id); setNotice(`${host.name}: ${Object.values(info).join(' · ')}`) } catch(err){setNotice(errorText(err))} }
  return <div className="page-stack"><div className="page-actions"><div><p>Registered targets</p><span>SSH and sudo credentials are encrypted locally; the model receives only host IDs and capability flags.</span></div><button className="primary" onClick={openCreate}><Plus size={16}/>Add host</button></div>
    {notice && <div className="notice">{notice}<button onClick={()=>setNotice('')}><X size={14}/></button></div>}
    {showForm && <form className="host-form panel" onSubmit={save}><div className="host-form-head"><div><h3>{editing?'Edit SSH target':'Register SSH target'}</h3><p>{editing?'Leave password fields blank to keep their encrypted values.':'Choose how the control plane authenticates and whether managed sudo is permitted.'}</p></div><button type="button" className="close-button" onClick={()=>setShowForm(false)}><X size={16}/></button></div><div className="form-grid host-fields">
      <label><span>Name</span><input value={form.name} onChange={event=>setForm({...form,name:event.target.value})} required/></label>
      <label><span>Address</span><input value={form.address} onChange={event=>setForm({...form,address:event.target.value})} placeholder="192.0.2.10 or server.example.com" required/></label>
      <label><span>Port</span><input type="number" min="1" max="65535" value={form.port} onChange={event=>setForm({...form,port:Number(event.target.value)})} required/></label>
      <label><span>User</span><input value={form.user} onChange={event=>setForm({...form,user:event.target.value})} placeholder="ops" required/></label>
      <label><span>Authentication</span><select value={form.auth_type} onChange={event=>setAuthType(event.target.value as HostAuthType)}>{(Object.keys(authLabels) as HostAuthType[]).map(mode=><option value={mode} key={mode}>{authLabels[mode]}</option>)}</select></label>
      {form.auth_type==='password'&&<label><span>SSH password</span><input type="password" autoComplete="new-password" value={form.password} onChange={event=>setForm({...form,password:event.target.value})} placeholder={editing?'Leave blank to keep stored password':'Required'} required={!editing}/></label>}
      {form.auth_type==='key'&&<div className="private-key-field"><span>Private key</span><label className={`private-key-picker ${privateKeyError||missingPrivateKey?'invalid':''}`} title={privateKeyName||'Choose an OpenSSH private key'}><UploadCloud size={15}/><span><b>{privateKeyName||(existingPrivateKey?'Stored private key':'Choose private key')}</b><small>{privateKeyName?'Ready to encrypt':existingPrivateKey?'Encrypted key configured':'OpenSSH key · max 1 MiB'}</small></span><input key={privateKeyInputKey} type="file" onChange={event=>void choosePrivateKey(event)}/></label>{(privateKeyError||missingPrivateKey)&&<small className="private-key-error">{privateKeyError||'A private key upload is required.'}</small>}</div>}
      <label><span>ProxyJump host</span><select value={form.proxy_jump_host_id} onChange={event=>setForm({...form,proxy_jump_host_id:event.target.value})}><option value="">Direct connection</option>{hosts.filter(host=>host.id!==form.id).map(host=><option value={host.id} key={host.id}>{host.name} · {host.user}@{host.address}:{host.port}</option>)}</select></label>
      <label><span>Known hosts file</span><input value={form.known_hosts_file} onChange={event=>setForm({...form,known_hosts_file:event.target.value})} placeholder="Use control-plane default"/></label>
      <label><span>Sudo policy</span><select value={form.sudo_mode} onChange={event=>setForm({...form,sudo_mode:event.target.value as HostSudoMode,sudo_password:''})}>{(Object.keys(sudoLabels) as HostSudoMode[]).map(mode=><option value={mode} key={mode}>{sudoLabels[mode]}</option>)}</select></label>
      {form.sudo_mode==='password'&&<label><span>Sudo password</span><input type="password" autoComplete="new-password" value={form.sudo_password} onChange={event=>setForm({...form,sudo_password:event.target.value})} placeholder={editing?'Leave blank to keep stored password':'Required'} required={!editing}/></label>}
    </div><div className="credential-note"><ShieldCheck size={15}/><span>Built-in SSH. Uploaded keys and passwords are encrypted locally; managed sudo remains bound to <code>elevated: true</code> and break-glass approval.</span></div><div className="form-actions"><button type="button" onClick={()=>setShowForm(false)}>Cancel</button><button className="primary" disabled={saving||!!privateKeyError||missingPrivateKey}>{saving?'Saving…':editing?'Update host':'Save host'}</button></div></form>}
    <div className="host-grid">{hosts.map(host=>{const encryptedCredential=(host.auth_type==='password'&&host.has_password)||(host.auth_type==='key'&&host.has_private_key);return <article className="host-card panel" key={host.id}><div className="host-top"><div className="server-glyph"><Server size={22}/></div><div><h3>{host.name}</h3><span>{`${host.user}@${host.address}:${host.port}`}</span></div><span className="host-state">REGISTERED</span></div><dl><div><dt>Authentication</dt><dd>{authLabels[host.auth_type||'agent']}{encryptedCredential?' · encrypted':''}</dd></div><div><dt>Sudo</dt><dd>{sudoLabels[host.sudo_mode||'none']}{host.sudo_mode==='password'&&host.has_sudo_password?' · encrypted':''}</dd></div><div><dt>Host ID</dt><dd>{host.id}</dd></div></dl><div className="card-actions"><button onClick={()=>probe(host)}><Activity size={15}/>Probe</button><button onClick={()=>scan(host)}><KeyRound size={15}/>Trust key</button><button onClick={()=>openEdit(host)}><Edit3 size={15}/>Edit</button><button className="danger" onClick={async()=>{if(confirm(`Delete ${host.name}?`)){await api.deleteHost(host.id);await refresh()}}}><Trash2 size={15}/></button></div></article>})}</div>
    {!hosts.length && <Empty icon={<Server/>} title="No SSH hosts" text="Register a target, verify its fingerprint, then let OpsPilot inspect it."/>}
  </div>
}

const emptyProviderForm: ModelProviderInput = {name:'',kind:'openai',base_url:'',model:'gpt-4o-mini',api_key:''}
const providerLabels: Record<ModelProviderKind,string> = {
  openai: 'OpenAI', deepseek: 'DeepSeek', openai_compatible: 'OpenAI-compatible', ollama: 'Ollama',
}
const providerDefaults: Record<ModelProviderKind,Pick<ModelProviderInput,'base_url'|'model'>> = {
  openai: {base_url:'',model:'gpt-4o-mini'},
  deepseek: {base_url:'https://api.deepseek.com',model:'deepseek-v4-flash'},
  openai_compatible: {base_url:'',model:''},
  ollama: {base_url:'http://127.0.0.1:11434/v1',model:''},
}

function ModelsPage({providers,health,refresh}:{providers:ModelProvider[];health:Health|null;refresh:()=>Promise<void>}) {
  const [showForm,setShowForm]=useState(false)
  const [form,setForm]=useState<ModelProviderInput>(emptyProviderForm)
  const [notice,setNotice]=useState('')
  const [busy,setBusy]=useState('')
  const [catalog,setCatalog]=useState<string[]>([])
  const [discovering,setDiscovering]=useState(false)
  const editing=!!form.id

  const openCreate=()=>{setForm(emptyProviderForm);setCatalog([]);setShowForm(true);setNotice('')}
  const openEdit=(provider:ModelProvider)=>{setForm({id:provider.id,name:provider.name,kind:provider.kind,base_url:provider.base_url||'',model:provider.model,api_key:''});setCatalog([]);setShowForm(true);setNotice('')}
  const changeKind=(kind:ModelProviderKind)=>{setCatalog([]);setForm({...form,kind,...providerDefaults[kind]})}
  const discover=async()=>{setDiscovering(true);try{const result=await api.discoverModels({id:form.id,kind:form.kind,base_url:form.base_url,api_key:form.api_key});setCatalog(result.models);setForm(current=>({...current,model:result.models.includes(current.model)?current.model:''}));setNotice(`Found ${result.count} models. Expand the Model ID list and choose one.`)}catch(err){setCatalog([]);setNotice(errorText(err))}finally{setDiscovering(false)}}
  const testForm=async()=>{setBusy('test-form');try{const result=await api.testModelConfiguration({id:form.id,kind:form.kind,base_url:form.base_url,model:form.model,api_key:form.api_key});setNotice(`Healthy · ${result.model} replied “${result.response}” · ${result.latency_ms} ms`)}catch(err){setNotice(errorText(err))}finally{setBusy('')}}
  const save=async(event:FormEvent)=>{event.preventDefault();setBusy('save');try{const saved=await api.saveModelProvider(form);setNotice(`${saved.name} saved. API keys are encrypted and never returned by the API.`);setShowForm(false);setForm(emptyProviderForm);await refresh()}catch(err){setNotice(errorText(err))}finally{setBusy('')}}
  const activate=async(provider:ModelProvider)=>{setBusy(provider.id);try{await api.activateModelProvider(provider.id);setNotice(`${provider.name} is now active for new agent requests.`);await refresh()}catch(err){setNotice(errorText(err))}finally{setBusy('')}}
  const test=async(provider:ModelProvider)=>{setBusy(`test-${provider.id}`);try{const result=await api.testModelProvider(provider.id);setNotice(`Healthy · ${provider.name} replied “${result.response}” · ${result.latency_ms} ms`)}catch(err){setNotice(errorText(err))}finally{setBusy('')}}
  const remove=async(provider:ModelProvider)=>{if(!confirm(`Delete model provider ${provider.name}?${provider.active?' The agent will fall back to environment configuration if available.':''}`))return;setBusy(provider.id);try{await api.deleteModelProvider(provider.id);setNotice(`${provider.name} deleted.`);await refresh()}catch(err){setNotice(errorText(err))}finally{setBusy('')}}

  return <div className="page-stack">
    <div className="page-actions"><div><p>Runtime model routing</p><span>Store multiple OpenAI-compatible endpoints and switch the Eino agent without restarting.</span></div><button className="primary" onClick={openCreate}><Plus size={16}/>Add provider</button></div>
    {notice&&<div className="notice">{notice}<button onClick={()=>setNotice('')}><X size={14}/></button></div>}
    <div className="model-summary panel"><div><span>ACTIVE ROUTE</span><b>{health?.model?.name||'No model configured'}</b><small>{health?.model?.model||'Add and activate a provider to enable chat'}</small></div><div className={`model-signal ${health?.agent_available?'ready':''}`}><CircleDot size={16}/>{health?.agent_available?'READY':'OFFLINE'}</div><div><span>SOURCE</span><b>{health?.model?.source||'none'}</b><small>{health?.model?.provider_id||'Environment fallback is supported'}</small></div></div>
    {showForm&&<form className="model-form panel" onSubmit={save}>
      <div className="model-form-head"><div><h3>{editing?'Edit provider':'New model provider'}</h3><p>{editing?'Leave API key blank to keep the encrypted value.':'The API key is encrypted locally before it reaches SQLite.'}</p></div><button type="button" className="close-button" onClick={()=>setShowForm(false)}><X size={16}/></button></div>
      <div className="form-grid model-fields">
        <label><span>Display name</span><input value={form.name} onChange={event=>setForm({...form,name:event.target.value})} placeholder="Production model" required/></label>
        <label><span>Provider type</span><select value={form.kind} onChange={event=>changeKind(event.target.value as ModelProviderKind)}>{(Object.keys(providerLabels) as ModelProviderKind[]).map(kind=><option key={kind} value={kind}>{providerLabels[kind]}</option>)}</select></label>
        <label className="model-id-field"><span className="field-title"><span>Model ID</span><button type="button" onClick={discover} disabled={discovering}><RefreshCw size={12}/>{discovering?'Fetching…':'Fetch models'}</button></span>{catalog.length>0?<select value={form.model} onChange={event=>setForm({...form,model:event.target.value})} required><option value="">Select a model…</option>{catalog.map(model=><option value={model} key={model}>{model}</option>)}</select>:<input value={form.model} onChange={event=>setForm({...form,model:event.target.value})} placeholder="Fetch models or enter an ID" required/>}{catalog.length>0&&<small>{catalog.length} models available · <button type="button" onClick={()=>setCatalog([])}>enter manually</button></small>}</label>
        <label><span>API key</span><input type="password" autoComplete="new-password" value={form.api_key} onChange={event=>{setCatalog([]);setForm({...form,api_key:event.target.value})}} placeholder={editing?'Leave blank to keep current key':'Optional for local endpoints'}/></label>
        <label className="base-url-field"><span>Base URL</span><input value={form.base_url} onChange={event=>{setCatalog([]);setForm({...form,base_url:event.target.value})}} placeholder={form.kind==='openai'?'Blank uses the official OpenAI endpoint':'127.0.0.1:11434/v1 or api.example.com/v1'}/><small>Protocol is optional: local addresses use HTTP, public domains use HTTPS. Full /models or /chat/completions URLs are accepted.</small></label>
      </div>
      <div className="form-actions"><button type="button" onClick={()=>setShowForm(false)}>Cancel</button><button type="button" className="test-config" onClick={testForm} disabled={!!busy||!form.model}><Activity size={14}/>{busy==='test-form'?'Sending Hello…':'Test model'}</button><button className="primary" disabled={!!busy}>{busy==='save'?'Saving…':'Save provider'}</button></div>
    </form>}
    <div className="model-grid">{providers.map(provider=><article className={`model-card panel ${provider.active?'active':''}`} key={provider.id}>
      <div className="model-card-head"><div className="provider-glyph"><Cpu size={21}/></div><div><h3>{provider.name}</h3><span>{providerLabels[provider.kind]}</span></div>{provider.active&&<em><Zap size={12}/>ACTIVE</em>}</div>
      <div className="model-name">{provider.model}</div>
      <dl><div><dt>Endpoint</dt><dd>{provider.base_url||'Provider default'}</dd></div><div><dt>Credential</dt><dd>{provider.has_api_key?'Encrypted key stored':'No API key'}</dd></div><div><dt>Updated</dt><dd>{new Date(provider.updated_at).toLocaleString()}</dd></div></dl>
      <div className="model-actions"><button onClick={()=>test(provider)} disabled={!!busy}><Activity size={14}/>{busy===`test-${provider.id}`?'Testing…':'Test'}</button><button onClick={()=>openEdit(provider)} disabled={!!busy}><Edit3 size={14}/>Edit</button>{!provider.active&&<button className="use-model" onClick={()=>activate(provider)} disabled={!!busy}><Zap size={14}/>{busy===provider.id?'Switching…':'Use model'}</button>}<button className="danger" onClick={()=>remove(provider)} disabled={!!busy}><Trash2 size={14}/></button></div>
    </article>)}</div>
    {!providers.length&&<Empty icon={<Cpu/>} title="No saved model providers" text={health?.model?.source==='environment'?'The agent currently uses OPENAI_API_KEY. Add a provider to enable Web switching.':'Add OpenAI, DeepSeek, Ollama, or another OpenAI-compatible endpoint.'}/>} 
  </div>
}

function AuditPage({runs}:{runs:Run[]}) {
  const [query,setQuery]=useState('')
  const [sessions,setSessions]=useState<ChatSession[]>([])
  useEffect(()=>{let active=true;void api.chatSessions().then(items=>{if(active)setSessions(items)}).catch(()=>{});return()=>{active=false}},[])
  const filtered=useMemo(()=>{const needle=query.toLowerCase();return runs.filter(run=>(run.request_json+run.stdout_redacted+run.stderr_redacted).toLowerCase().includes(needle))},[query,runs])
  const groups=useMemo(()=>{
    const titles=new Map(sessions.map(session=>[session.id,session.title]))
    const grouped=new Map<string,Run[]>()
    for(const run of filtered){const key=run.session_id||'__direct__';grouped.set(key,[...(grouped.get(key)||[]),run])}
    return [...grouped.entries()].map(([id,items])=>{items.sort((a,b)=>Date.parse(b.started_at)-Date.parse(a.started_at));return{id,title:id==='__direct__'?'Direct / legacy operations':titles.get(id)||'Deleted or unavailable conversation',runs:items,latest:items[0]?.started_at,critical:items.filter(run=>run.risk==='critical'||run.risk==='forbidden').length,pending:items.filter(run=>run.status==='approval_required').length}}).sort((a,b)=>Date.parse(b.latest||'')-Date.parse(a.latest||''))
  },[filtered,sessions])
  return <div className="page-stack"><div className="audit-toolbar"><div className="search-box"><Search size={16}/><input value={query} onChange={event=>setQuery(event.target.value)} placeholder="Search commands and redacted output"/></div><span>{groups.length} SESSIONS · {filtered.length} RUNS</span></div><div className="audit-groups">{groups.map(group=><details className="audit-session panel" key={group.id}><summary className="audit-session-summary"><div className="audit-session-glyph"><History size={17}/></div><div className="audit-session-name"><b>{group.title}</b><span>{group.id==='__direct__'?'No Agent session context':group.id} · Last run {new Date(group.latest).toLocaleString()}</span></div><div className="audit-session-stats"><span><b>{group.runs.length}</b> runs</span>{group.critical>0&&<span className="critical-count"><b>{group.critical}</b> critical</span>}{group.pending>0&&<span className="pending-count"><b>{group.pending}</b> pending</span>}</div><ChevronRight className="audit-session-chevron" size={17}/></summary><div className="audit-table"><div className="audit-row audit-head"><span>Time</span><span>Operation</span><span>Risk</span><span>Status</span><span>Host</span><span>Exit</span></div>{group.runs.map(run=>{let req:Record<string,unknown>={};try{req=JSON.parse(run.request_json)}catch{req={request:run.request_json}};const args=Array.isArray(req.args)?req.args.join(' '):'';return <details key={run.id}><summary className="audit-row"><span>{new Date(run.started_at).toLocaleString()}</span><span className="command">{typeof req.program==='string'?`${req.program} ${args}`.trim():'bash script'}</span><span><i className={`risk-dot ${run.risk}`}/>{run.risk}</span><span className={`run-status ${run.status}`}>{run.status}</span><span>{run.host_id.slice(0,16)}</span><span>{run.exit_code}</span></summary><div className="run-detail"><pre>{JSON.stringify(req,null,2)}</pre>{run.stdout_redacted&&<div><b>STDOUT · REDACTED</b><pre>{run.stdout_redacted}</pre></div>}{run.stderr_redacted&&<div><b>STDERR · REDACTED</b><pre>{run.stderr_redacted}</pre></div>}</div></details>})}</div></details>)}</div>{!runs.length&&<Empty icon={<History/>} title="No audit history" text="Every SSH attempt, denial, approval, and result will be preserved here."/>}{runs.length>0&&!groups.length&&<Empty icon={<Search/>} title="No matching audit runs" text="Try a different command, output, or reason."/>}</div>
}

function logFieldValue(value:unknown){
  if(value===null||value===undefined)return'—'
  if(typeof value==='object')return JSON.stringify(value)
  return String(value)
}

function LogsPage(){
  const [entries,setEntries]=useState<ServerLogEntry[]>([])
  const [components,setComponents]=useState<string[]>([])
  const [minimumLevel,setMinimumLevel]=useState('info')
  const [logFile,setLogFile]=useState('')
  const [level,setLevel]=useState('debug')
  const [component,setComponent]=useState('')
  const [query,setQuery]=useState('')
  const [live,setLive]=useState(true)
  const [loading,setLoading]=useState(false)
  const [logError,setLogError]=useState('')
  const refreshLogs=useCallback(async(silent=false)=>{
    if(!silent)setLoading(true)
    try{const result=await api.logs({level,component,q:query,limit:500});setEntries(result.entries||[]);setComponents(result.components||[]);setMinimumLevel(result.minimum_level||'info');setLogFile(result.file||'');setLogError('')}
    catch(err){setLogError(errorText(err))}
    finally{if(!silent)setLoading(false)}
  },[level,component,query])
  useEffect(()=>{void refreshLogs();if(!live)return;const timer=window.setInterval(()=>void refreshLogs(true),3000);return()=>window.clearInterval(timer)},[refreshLogs,live])
  return <div className="logs-page page-stack">
    <div className="logs-toolbar panel">
      <div className="search-box"><Search size={16}/><input value={query} onChange={event=>setQuery(event.target.value)} placeholder="Search messages, IDs, hosts, status…"/></div>
      <label><span>Minimum level</span><select value={level} onChange={event=>setLevel(event.target.value)}><option value="debug">Debug+</option><option value="info">Info+</option><option value="warn">Warn+</option><option value="error">Error</option></select></label>
      <label><span>Component</span><select value={component} onChange={event=>setComponent(event.target.value)}><option value="">All components</option>{components.map(item=><option value={item} key={item}>{item}</option>)}</select></label>
      <button className={`live-toggle ${live?'active':''}`} onClick={()=>setLive(value=>!value)}><CircleDot size={13}/>{live?'Live · 3s':'Paused'}</button>
      <button className="log-refresh" onClick={()=>void refreshLogs()} disabled={loading}><RefreshCw size={14} className={loading?'spin':''}/>{loading?'Loading':'Refresh'}</button>
    </div>
    <div className="logs-meta"><span>{entries.length} recent entries</span><span>SERVER CAPTURE · {minimumLevel.toUpperCase()}+</span><span>{logFile?`File: ${logFile} · JSONL rotation`:'File logging disabled'}</span></div>
    {minimumLevel!=='debug'&&level==='debug'&&<div className="log-hint"><ShieldAlert size={15}/><span>Debug 日志当前未采集。设置 <code>OPS_AGENT_LOG_LEVEL=debug</code> 后重启服务即可查看详细链路。</span></div>}
    {logError&&<div className="history-error panel">{logError}</div>}
    <div className="log-stream panel">
      <div className="log-row log-head"><span>Time</span><span>Level</span><span>Component</span><span>Event / fields</span></div>
      {entries.map((entry,index)=><div className={`log-row log-entry ${entry.level}`} key={`${entry.time}_${index}`}><time>{new Date(entry.time).toLocaleTimeString(undefined,{hour12:false,fractionalSecondDigits:3})}</time><span><i className={`log-level ${entry.level}`}>{entry.level}</i></span><code className="log-component">{entry.component||'general'}</code><div className="log-event"><b>{entry.message}</b>{entry.fields&&Object.keys(entry.fields).length>0&&<div className="log-fields">{Object.entries(entry.fields).map(([key,value])=><span key={key}><em>{key}</em><code title={logFieldValue(value)}>{logFieldValue(value)}</code></span>)}</div>}</div></div>)}
      {!entries.length&&!logError&&<Empty icon={<FileText/>} title="No matching server logs" text="Adjust filters or perform an operation to generate a structured log entry."/>}
    </div>
  </div>
}

function Metric({label,value,tone}:{label:string;value:string;tone?:string}){return <div className={`metric ${tone||''}`}><span>{label}</span><b>{value}</b></div>}
function Empty({icon,title,text}:{icon:React.ReactNode;title:string;text:string}){return <div className="empty-state"><div>{icon}</div><h2>{title}</h2><p>{text}</p></div>}
function pretty(value:string){try{return JSON.stringify(JSON.parse(value),null,2)}catch{return value}}

export default App
