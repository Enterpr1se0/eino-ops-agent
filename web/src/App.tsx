import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import Markdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import {
  Activity, Bot, BrainCircuit, Check, ChevronRight, CircleDot, Clock3, Cpu, Edit3, FileText, History, KeyRound,
  ListChecks, LoaderCircle, Plus, RefreshCw, Search, Send, Server, Settings2, ShieldAlert, ShieldCheck, SlidersHorizontal, TerminalSquare, Trash2, X, Zap,
} from 'lucide-react'
import { api, streamChat } from './api'
import type { AgentEvent, AgentPlan, Approval, ChatMessage, ChatSession, Health, Host, HostAuthType, HostInput, HostSudoMode, ModelProvider, ModelProviderInput, ModelProviderKind, Run, ServerLogEntry, SystemSettings } from './types'

type Page = 'chat' | 'config' | 'audit' | 'logs'
type ChatEntry = { id: string; kind: 'user' | 'assistant' | 'tool' | 'reasoning' | 'error'; content: string; tool?: string; active?: boolean }

function historyEntries(messages:ChatMessage[]):ChatEntry[]{
  return messages.map((item,index)=>({id:`history_${index}_${item.created_at}`,kind:item.role,content:item.content,tool:item.tool_name}))
}

function planFromToolContent(content:string):AgentPlan|null{
  try{const value=JSON.parse(content) as AgentPlan;return value&&typeof value.goal==='string'&&Array.isArray(value.steps)?value:null}catch{return null}
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
  const [page, setPage] = useState<Page>('chat')
  const [health, setHealth] = useState<Health | null>(null)
  const [hosts, setHosts] = useState<Host[]>([])
  const [providers, setProviders] = useState<ModelProvider[]>([])
  const [settings, setSettings] = useState<SystemSettings | null>(null)
  const [approvals, setApprovals] = useState<Approval[]>([])
  const [runs, setRuns] = useState<Run[]>([])
  const [error, setError] = useState('')

  const refresh = useCallback(async () => {
    try {
      const [nextHealth, nextHosts, nextProviders, nextSettings, nextApprovals, nextRuns] = await Promise.all([
        api.health(), api.hosts(), api.modelProviders(), api.systemSettings(), api.approvals(), api.runs(),
      ])
      setHealth(nextHealth); setHosts(nextHosts); setProviders(nextProviders); setSettings(nextSettings); setApprovals(nextApprovals); setRuns(nextRuns); setError('')
    } catch (err) { setError(errorText(err)) }
  }, [])

  useEffect(() => { refresh(); const timer = window.setInterval(refresh, 10000); return () => window.clearInterval(timer) }, [refresh])

  const title = { chat: 'Agent Workspace', config: 'Configuration Center', audit: 'Audit Explorer', logs: 'Server Logs' }[page]

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><TerminalSquare size={23}/></div><div><strong>OpsPilot</strong><span>SSH CONTROL PLANE</span></div></div>
      <nav>
        <Nav active={page === 'chat'} icon={<Bot/>} label="Agent" onClick={() => setPage('chat')}/>
        <Nav active={page === 'config'} icon={<Settings2/>} label="Configuration" onClick={() => setPage('config')}/>
        <Nav active={page === 'audit'} icon={<History/>} label="Audit" onClick={() => setPage('audit')}/>
        <Nav active={page === 'logs'} icon={<FileText/>} label="Logs" onClick={() => setPage('logs')}/>
      </nav>
      <div className="sidebar-foot">
        <div className="security-card"><ShieldCheck size={18}/><div><b>Policy enforced</b><span>Every action is audited</span></div></div>
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
        {page === 'chat' && <ChatPage hosts={hosts} approvals={approvals} runs={runs} agentAvailable={!!health?.agent_available} modelName={health?.model?.model} refresh={refresh}/>} 
        {page === 'config' && <ConfigurationPage hosts={hosts} providers={providers} settings={settings} health={health} refresh={refresh}/>} 
        {page === 'audit' && <AuditPage runs={runs}/>} 
        {page === 'logs' && <LogsPage/>}
      </section>
    </main>
  </div>
}

type ConfigurationSection = 'models' | 'hosts' | 'system'

function ConfigurationPage({hosts,providers,settings,health,refresh}:{hosts:Host[];providers:ModelProvider[];settings:SystemSettings|null;health:Health|null;refresh:()=>Promise<void>}) {
  const [section,setSection]=useState<ConfigurationSection>('models')
  const tabs:[ConfigurationSection,React.ReactNode,string,string][]=[
    ['models',<Cpu size={17}/>, 'Model providers', `${providers.length} configured`],
    ['hosts',<Server size={17}/>, 'SSH hosts', `${hosts.length} registered`],
    ['system',<SlidersHorizontal size={17}/>, 'System settings', `${settings?.agent_max_iterations??20} max iterations`],
  ]
  return <div className="configuration-center page-stack">
    <section className="configuration-hero panel"><div><span>CONTROL PLANE CONFIGURATION</span><h2>One place for every Agent dependency</h2><p>Manage inference, remote access and runtime safeguards without editing local files.</p></div><dl><div><dt>Active model</dt><dd>{health?.model?.model||'Not configured'}</dd></div><div><dt>SSH targets</dt><dd>{hosts.length}</dd></div><div><dt>Loop budget</dt><dd>{settings?.agent_max_iterations??20} rounds</dd></div></dl></section>
    <div className="configuration-tabs" role="tablist" aria-label="Configuration sections">{tabs.map(([id,icon,label,meta])=><button type="button" role="tab" aria-selected={section===id} className={section===id?'active':''} onClick={()=>setSection(id)} key={id}>{icon}<span><b>{label}</b><small>{meta}</small></span><ChevronRight size={15}/></button>)}</div>
    <div className="configuration-content" role="tabpanel">
      {section==='models'&&<ModelsPage providers={providers} health={health} refresh={refresh}/>} 
      {section==='hosts'&&<HostsPage hosts={hosts} refresh={refresh}/>} 
      {section==='system'&&<SystemSettingsPage settings={settings} refresh={refresh}/>} 
    </div>
  </div>
}

function SystemSettingsPage({settings,refresh}:{settings:SystemSettings|null;refresh:()=>Promise<void>}) {
  const savedValue=settings?.agent_max_iterations??20
  const [maxIterations,setMaxIterations]=useState(savedValue)
  const [dirty,setDirty]=useState(false)
  const [saving,setSaving]=useState(false)
  const [notice,setNotice]=useState('')
  useEffect(()=>{if(!dirty)setMaxIterations(savedValue)},[savedValue,dirty])
  const update=(value:number)=>{setMaxIterations(Math.max(5,Math.min(50,value||5)));setDirty(true);setNotice('')}
  const save=async(event:FormEvent)=>{event.preventDefault();setSaving(true);try{const result=await api.saveSystemSettings({agent_max_iterations:maxIterations});setMaxIterations(result.agent_max_iterations);setDirty(false);setNotice(`Saved · New Agent runs can use up to ${result.agent_max_iterations} model iterations.`);await refresh()}catch(err){setNotice(errorText(err))}finally{setSaving(false)}}
  return <div className="system-settings page-stack">
    <div className="page-actions"><div><p>Agent runtime safeguards</p><span>Runtime changes are persisted locally, audited and applied to new Agent runs without a server restart.</span></div></div>
    {notice&&<div className="notice">{notice}<button onClick={()=>setNotice('')}><X size={14}/></button></div>}
    <form className="settings-panel panel" onSubmit={save}><div className="settings-panel-head"><div className="settings-glyph"><SlidersHorizontal size={20}/></div><div><span>AGENT LOOP</span><h3>Maximum model iterations</h3><p>Limits how many model → tool → model decision rounds a single message may consume.</p></div><strong>{maxIterations}</strong></div>
      <div className="iteration-editor"><input aria-label="Maximum model iterations" type="range" min="5" max="50" step="1" value={maxIterations} onChange={event=>update(Number(event.target.value))}/><label><span>Rounds</span><input type="number" min="5" max="50" value={maxIterations} onChange={event=>update(Number(event.target.value))}/></label></div>
      <div className="iteration-presets"><span>QUICK PRESETS</span>{[10,20,30].map(value=><button type="button" className={maxIterations===value?'active':''} onClick={()=>update(value)} key={value}><b>{value}</b><small>{value===10?'Short diagnosis':value===20?'Recommended':'Long deployment'}</small></button>)}</div>
      <div className="settings-advice"><ShieldCheck size={17}/><div><b>The safety limit remains enforced</b><p>Higher values support installations and multi-step recovery, but can increase token usage and tool calls. Values are restricted to 5–50.</p></div></div>
      <div className="settings-footer"><span>{settings?.updated_at?`Last updated ${new Date(settings.updated_at).toLocaleString()}`:'Using system default'}</span><button type="button" disabled={!dirty||saving} onClick={()=>{setMaxIterations(savedValue);setDirty(false);setNotice('')}}>Discard</button><button className="primary" disabled={!dirty||saving}>{saving?'Applying…':'Save & apply'}</button></div>
    </form>
  </div>
}

function Nav({ active, icon, label, count, warn, onClick }: {active:boolean;icon:React.ReactNode;label:string;count?:number;warn?:boolean;onClick:()=>void}) {
  return <button className={`nav-item ${active ? 'active' : ''}`} onClick={onClick}>{icon}<span>{label}</span>{count !== undefined && <em className={warn ? 'warn' : ''}>{count}</em>}</button>
}

function ChatPage({ hosts, approvals, runs, agentAvailable, modelName, refresh }: {hosts:Host[];approvals:Approval[];runs:Run[];agentAvailable:boolean;modelName?:string;refresh:()=>Promise<void>}) {
  const [entries, setEntries] = useState<ChatEntry[]>([])
  const [message, setMessage] = useState('')
  const [sessionId, setSessionId] = useState('')
  const [sessions, setSessions] = useState<ChatSession[]>([])
  const [historyError, setHistoryError] = useState('')
  const [loadingSession, setLoadingSession] = useState('')
  const [running, setRunning] = useState(false)
  const [detachedRunning,setDetachedRunning]=useState(false)
  const [reasoningSeen, setReasoningSeen] = useState(false)
  const [plan,setPlan]=useState<AgentPlan|null>(null)
  const [approvalNotice,setApprovalNotice]=useState('')
  const messagesRef=useRef<HTMLDivElement>(null)
  const stickToLatest=useRef(true)
  const hostNames = useMemo(() => hosts.map((host) => host.name).join(', '), [hosts])
  const currentApprovals=useMemo(()=>sessionId?approvals.filter(item=>item.session_id===sessionId):[],[approvals,sessionId])
  const sessionBusy=running||detachedRunning

  const refreshSessions = useCallback(async () => {
    try {
      const items = await api.chatSessions(); setSessions(items); setHistoryError(''); return items
    } catch (err) { setHistoryError(errorText(err)); return [] }
  }, [])

  const loadSession = useCallback(async (id: string) => {
    setLoadingSession(id)
    stickToLatest.current=true
    try {
      const state = await api.chatState(id)
      setEntries(historyEntries(state.messages||[]));setDetachedRunning(!!state.active);setPlan(state.plan||null)
      setSessionId(id); rememberSession(id); setHistoryError('')
      void refresh()
    } catch (err) { setHistoryError(errorText(err)) }
    finally { setLoadingSession('') }
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
    if (running) return
    stickToLatest.current=true;setSessionId(''); setEntries([]); setMessage(''); setHistoryError(''); setReasoningSeen(false);setDetachedRunning(false);setPlan(null); rememberSession(newSessionMarker)
  }

  const removeSession = async (session: ChatSession) => {
    if (running || (session.id===sessionId&&detachedRunning) || !confirm(`Delete conversation “${session.title}”?`)) return
    try {
      await api.deleteChatSession(session.id)
      if (session.id === sessionId) newChat()
      await refreshSessions()
    } catch (err) { setHistoryError(errorText(err)) }
  }

  const sendQuery = async (query:string) => {
    query=query.trim(); if(!query||sessionBusy)return
    let querySessionID=sessionId
    stickToLatest.current=true
    setApprovalNotice('');setReasoningSeen(false);setRunning(true)
    setEntries((old) => [...old, { id: clientId(), kind: 'user', content: query }, { id: 'streaming', kind: 'assistant', content: '' }])
    try {
      await streamChat(sessionId, query, (frame: AgentEvent) => {
        if (frame.session_id) { querySessionID=frame.session_id;setSessionId(frame.session_id); rememberSession(frame.session_id) }
        if (frame.type === 'approval') { setApprovalNotice(''); void refresh() }
        if (frame.type === 'reasoning' && frame.content) {
          setReasoningSeen(true)
          const reasoningID=`reasoning_${frame.segment_id||'current'}`
          setEntries((old) => {
            const existing=old.find((item)=>item.id===reasoningID)
            if(existing)return old.map((item)=>item.id===reasoningID?{...item,content:item.content+frame.content,active:true}:item)
            return [...old.filter((item)=>item.id!=='streaming').map((item)=>item.kind==='reasoning'?{...item,active:false}:item),{id:reasoningID,kind:'reasoning',content:frame.content!,active:true},{id:'streaming',kind:'assistant',content:''}]
          })
        }
        if (frame.type === 'message' && frame.content) {
          if (frame.role === 'tool') {setEntries((old) => [...old.filter((item) => item.id !== 'streaming').map((item)=>item.kind==='reasoning'?{...item,active:false}:item), { id: clientId(), kind: 'tool', content: frame.content!, tool: frame.tool_name }, { id: 'streaming', kind: 'assistant', content: '' }]);if(frame.tool_name?.startsWith('ops_plan_')){const nextPlan=planFromToolContent(frame.content);if(nextPlan)setPlan(nextPlan)}if(/approval_id|approval_required/.test(frame.content))void refresh()}
          else setEntries((old) => old.map((item) => item.id === 'streaming' ? {...item, content: item.content + frame.content} : item.kind==='reasoning'?{...item,active:false}:item))
        }
        if (frame.type === 'error') setEntries((old) => [...old, { id: clientId(), kind: 'error', content: frame.error || 'Agent error' }])
      })
    } catch (err) { setEntries((old) => [...old, { id: clientId(), kind: 'error', content: errorText(err) }]) }
    finally {
      setEntries((old) => old.filter((item) => item.id !== 'streaming' || item.content !== '').map((item)=>item.kind==='reasoning'?{...item,active:false}:item))
      setRunning(false)
      if(querySessionID){try{const state=await api.chatState(querySessionID);setDetachedRunning(!!state.active);setPlan(state.plan||null);if(state.active)setEntries(old=>[...historyEntries(state.messages||[]),...old.filter(item=>item.kind==='error'&&!item.id.startsWith('history_'))])}catch{/* polling or the next reload will recover state */}}
      void refreshSessions();void refresh()
    }
  }

  const submit = (event: FormEvent) => {event.preventDefault();const query=message.trim();if(!query||sessionBusy)return;setMessage('');void sendQuery(query)}
  const streamingResponseStarted=entries.some((item)=>item.id==='streaming'&&item.content!=='')

  return <div className="chat-layout">
    <div className="chat-main panel">
      <div className="panel-header"><div><Bot size={18}/><span>OpsPilot session</span></div><span className="session-id">{sessionId ? sessionId.slice(0, 20) : 'NEW SESSION'}</span></div>
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
      <form className="composer" onSubmit={submit}><div className="context-line"><span><Server size={13}/>{hosts.length ? `${hosts.length} hosts: ${hostNames}` : 'No hosts registered'}</span><span><Cpu size={13}/>{modelName || 'No active model'}</span><span><ShieldCheck size={13}/>Guarded execution</span></div><div className="input-row"><textarea value={message} onChange={(event) => setMessage(event.target.value)} placeholder={!agentAvailable?'Configure and activate a model provider':sessionBusy?'Agent is still running in this conversation…':'Describe an incident or deployment goal…'} disabled={!agentAvailable||sessionBusy} onKeyDown={(event) => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); event.currentTarget.form?.requestSubmit() } }}/><button disabled={!agentAvailable || sessionBusy || !message.trim()}><Send size={18}/></button></div></form>
    </div>
    <aside className="context-panel conversation-panel panel"><div className="panel-header"><div><History size={17}/><span>Conversations</span></div><button className="new-chat-button" onClick={newChat} disabled={running} title="New conversation"><Plus size={14}/>New</button></div><div className="session-list">
      {historyError&&<div className="history-error">{historyError}</div>}
      {!sessions.length&&!historyError&&<div className="history-empty">No saved conversations yet.</div>}
      {sessions.map(session=>{const pending=approvals.filter(item=>item.session_id===session.id).length;const active=session.id===sessionId&&detachedRunning;return <div className={`session-item ${session.id===sessionId?'active':''}`} key={session.id}><button className="session-open" onClick={()=>loadSession(session.id)} disabled={running||loadingSession===session.id}><b>{session.title}{pending>0&&<em className="session-approval-count">{pending} approval</em>}{active&&<em className="session-running-count">running</em>}</b><span>{new Date(session.updated_at).toLocaleString()} · {session.message_count} messages</span></button><button className="session-delete" onClick={()=>removeSession(session)} disabled={running||active} title={active?'Agent is still running':'Delete conversation'}><Trash2 size={13}/></button></div>})}
    </div><div className="session-summary"><Metric label="Saved" value={sessions.length.toString()} tone="green"/><Metric label="Hosts" value={hosts.length.toString()}/></div></aside>
  </div>
}

function SessionPlan({plan}:{plan:AgentPlan}){
  const [expanded,setExpanded]=useState(plan.status==='active')
  useEffect(()=>{if(plan.status==='active')setExpanded(true)},[plan.session_id,plan.status])
  const completed=plan.steps.filter(step=>step.status==='completed').length
  const current=plan.steps.find(step=>step.status==='in_progress'||step.status==='blocked')
  const progress=plan.steps.length?Math.round(completed/plan.steps.length*100):0
  return <details className={`session-plan ${plan.status}`} open={expanded} onToggle={event=>setExpanded(event.currentTarget.open)}><summary><span className="plan-icon"><ListChecks size={16}/></span><span className="plan-summary-copy"><b>{plan.goal}</b><small>{current?`${current.status==='blocked'?'阻塞在':'当前'} ${current.number}/${plan.steps.length} · ${current.title}`:`${completed}/${plan.steps.length} steps completed`}</small></span><span className="plan-progress"><i><em style={{width:`${progress}%`}}/></i><b>{progress}%</b></span><span className={`plan-state ${plan.status}`}>{plan.status}</span><ChevronRight size={14}/></summary><ol>{plan.steps.map(step=><li className={step.status} key={step.number}><span className="plan-step-marker">{step.status==='completed'?<Check size={12}/>:step.status==='in_progress'?<LoaderCircle size={12}/>:step.status==='blocked'?<ShieldAlert size={12}/>:step.number}</span><div><b>{step.title}</b>{step.evidence&&<p>{step.evidence}</p>}</div><em>{step.status.replace('_',' ')}</em></li>)}</ol></details>
}

function ChatBubble({ entry, runs, hosts }: {entry: ChatEntry;runs:Run[];hosts:Host[]}) {
  if (entry.kind === 'tool') return <ToolEventCard entry={entry} runs={runs} hosts={hosts}/>
  if (entry.kind === 'reasoning') return <ReasoningCard content={entry.content} active={!!entry.active}/>
  if (entry.kind === 'assistant' && !entry.content) return null
  return <div className={`bubble ${entry.kind}`}><div className="avatar">{entry.kind === 'user' ? 'YOU' : entry.kind === 'error' ? '!' : <Bot size={17}/>}</div><div><span className="bubble-label">{entry.kind === 'user' ? 'Operator' : entry.kind === 'error' ? 'Error' : 'OpsPilot'}</span><div className={`bubble-copy ${entry.kind==='assistant'?'markdown-body':''}`}>{entry.kind==='assistant'?<Markdown skipHtml remarkPlugins={[remarkGfm]} components={{a:({href,children})=><a href={href} target="_blank" rel="noopener noreferrer">{children}</a>,img:({alt})=><span className="markdown-image-blocked">[Blocked image: {alt||'no description'}]</span>}}>{entry.content||'…'}</Markdown>:entry.content||'…'}</div></div></div>
}

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
const toolLabels:Record<string,string>={ssh_exec:'执行远程命令',ssh_run_script:'执行 Bash 脚本',ssh_file_read:'读取远程文件',ssh_file_list:'列出远程目录',ssh_file_stat:'读取文件信息',ssh_file_write:'写入远程文件',ssh_file_apply_patch:'应用远程补丁',ssh_file_upload:'上传制品',ssh_file_download:'下载文件',ssh_task_start:'启动远程任务',ssh_task_status:'查看任务状态',ssh_task_tail:'查看任务输出',ssh_host_list:'列出主机',ssh_host_inspect:'检查主机',ssh_history_search:'搜索执行历史',ssh_history_get:'读取执行历史',ssh_approval_status:'查询审批状态',ops_skill_list:'列出 Skills',ops_skill_get:'加载 Skill',ops_plan_create:'创建任务计划',ops_plan_get:'读取任务计划',ops_plan_step_update:'推进任务步骤'}
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
  const runID=textValue(payload.run_id)
  const run=runs.find(item=>item.id===runID)
  const display=jsonRecord(payload._display)
  const request=jsonRecord(display?.request)||requestFromRun(run)
  const hostID=textValue(display?.host_id)||run?.host_id||textValue(request?.host_id)
  const hostName=hosts.find(host=>host.id===hostID||host.name===hostID)?.name||hostID||'—'
  const status=textValue(payload.status)||run?.status||'completed'
  const risk=textValue(display?.risk)||run?.risk||''
  const program=request?fullProgram(request):''
  const script=request?textValue(request.script):''
  const remotePath=request?textValue(request.remote_path):''
  const planSteps=Array.isArray(payload.steps)?payload.steps.map(jsonRecord).filter((step):step is JsonRecord=>!!step):[]
  const planSummary=textValue(payload.goal)||textValue(planSteps.find(step=>textValue(step.status)==='in_progress'||textValue(step.status)==='blocked')?.title)
  const operation=script?'Bash script':program||remotePath||toolLabels[entry.tool||'']||entry.tool||'Tool result'
  const args=request&&Array.isArray(request.args)?request.args.map(value=>String(value)):[]
  const env=request?jsonRecord(request.env):undefined
  const stdout=textValue(payload.stdout)||run?.stdout_redacted||''
  const stderr=textValue(payload.stderr)||run?.stderr_redacted||run?.error||''
  const stdoutPreview=latestOutput(stdout)
  const commandSummary=script?compactScript(script):program||remotePath||planSummary||operation
  const instruction=textValue(payload.operator_instruction)
  const rawPayload={...payload};delete rawPayload._display
  const [expanded,setExpanded]=useState(false)
  const exitCode=typeof payload.exit_code==='number'?payload.exit_code:run?.exit_code??'—'
  return <details className={`tool-event tool-event-rich ${status}`} open={expanded} onToggle={event=>setExpanded(event.currentTarget.open)}>
    <summary><div className="tool-summary-icon"><TerminalSquare size={15}/></div><div className="tool-summary-copy"><b>{toolLabels[entry.tool||'']||entry.tool||'SSH Tool'}：</b><code title={commandSummary}>{commandSummary}</code></div><span className={`tool-status ${status}`}>{status.replaceAll('_',' ')}</span><ChevronRight size={14}/>{stdoutPreview&&<div className="tool-summary-preview"><span>STDOUT · 最新 {Math.min(3,stdoutPreview.split('\n').length)} 行</span><pre>{stdoutPreview}</pre></div>}</summary>
    <div className="tool-event-body">
      {request?<div className="tool-execution-layout">
        <section className="tool-command-pane">
          <div className="tool-command-head"><span>LLM 请求运行的完整{script?'脚本':'命令'}</span>{request.elevated===true&&<em><ShieldAlert size={12}/>受控 sudo</em>}</div>
          <div className="tool-command-block">{script?<pre>{script}</pre>:program?<pre><span className="prompt-sign">$</span> {program}</pre>:<pre>{textValue(request.mode)} {remotePath}</pre>}</div>
          {program&&<CompactTable title="ARGV · 原始参数" columns={['INDEX','VALUE']} rows={[[0,textValue(request.program)],...args.map((arg,index)=>[index+1,JSON.stringify(arg)])]}/>} 
          {env&&Object.keys(env).length>0&&<CompactTable title="环境变量" columns={['KEY','VALUE']} rows={Object.entries(env).map(([key,value])=>[key,String(value)])}/>} 
        </section>
        <aside className="tool-context-pane">
          <dl className="tool-context-grid"><div><dt>目标主机</dt><dd>{hostName}</dd></div><div><dt>工作目录</dt><dd>{textValue(request.cwd)||'默认目录'}</dd></div><div><dt>权限</dt><dd>{request.elevated===true?'managed sudo':'普通用户'}</dd></div><div><dt>风险</dt><dd>{risk||'—'}</dd></div><div><dt>状态</dt><dd>{status}</dd></div><div><dt>退出码</dt><dd>{exitCode}</dd></div><div><dt>耗时</dt><dd>{formatDuration(payload.duration,run)}</dd></div><div><dt>Run ID</dt><dd>{runID||'—'}</dd></div></dl>
          {textValue(request.reason)&&<div className="tool-reason"><span>执行原因</span><p>{textValue(request.reason)}</p></div>}
          {textValue(request.expected_changes)&&<div className="tool-reason change"><span>预期变化</span><p>{textValue(request.expected_changes)}</p></div>}
          {textValue(request.rollback)&&<div className="tool-reason rollback"><span>回滚方案</span><p>{textValue(request.rollback)}</p></div>}
        </aside>
      </div>:<GenericToolResult payload={payload}/>} 
      {instruction&&<div className="tool-instruction"><ShieldAlert size={15}/><div><b>Operator instruction</b><p>{instruction}</p></div></div>}
      {(stdout||stderr)&&<div className="tool-output-grid">{stdout&&<div className="tool-output stdout"><span>STDOUT</span><pre>{stdout}</pre></div>}{stderr&&<div className="tool-output stderr"><span>STDERR / RESULT</span><pre>{stderr}</pre></div>}</div>}
      <details className="tool-raw"><summary>原始 Tool JSON · 排错用</summary><pre>{JSON.stringify(rawPayload,null,2)}</pre></details>
    </div>
  </details>
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

function ApprovalDialog({approval,pendingCount,hosts,running,refresh,onNotice}:{approval:Approval;pendingCount:number;hosts:Host[];running:boolean;refresh:()=>Promise<void>;onNotice:(message:string)=>void}) {
  const [challenge,setChallenge]=useState('')
  const [note,setNote]=useState('')
  const [busy,setBusy]=useState('')
  const [error,setError]=useState('')
  let request:Record<string,unknown>={}
  try{request=JSON.parse(approval.request_json)}catch{request={request:approval.request_json}}
  const script=textValue(request.script)
  const operation=fullProgram(request)||script||`${textValue(request.mode)} ${textValue(request.remote_path)}`.trim()||'受控操作'
  const hostName=hosts.find(host=>host.id===approval.host_id)?.name||approval.host_id
  const decide=async(scope:'once'|'session')=>{
    setBusy(scope);setError('')
    try{const result=await api.approve(approval.id,challenge,note.trim()||'Reviewed and approved in the current Agent session.',scope);onNotice(`审批已通过 · ${result.status} · ${result.run_id}`);await refresh()}
    catch(err){setError(errorText(err))}finally{setBusy('')}
  }
  const reject=async()=>{
    const instruction=note.trim();if(!instruction){setError('请先输入希望 OpsPilot 改为执行的方案。');return}
    setBusy('reject');setError('')
    try{await api.reject(approval.id,instruction);onNotice('审批已拒绝 · OpsPilot 正在按你的替代方案继续。');await refresh()}catch(err){setError(errorText(err))}finally{setBusy('')}
  }
  const disabled=!!busy
  return <div className="approval-modal-backdrop"><section className={`approval-dialog ${approval.risk}`} role="dialog" aria-modal="true" aria-labelledby="approval-dialog-title"><div className="approval-dialog-head"><div className="approval-dialog-icon"><ShieldAlert size={20}/></div><div><span>HUMAN APPROVAL · {pendingCount>1?`1 OF ${pendingCount}`:'CURRENT SESSION'}</span><h2 id="approval-dialog-title">OpsPilot 请求执行受控操作</h2></div><em className={`risk ${approval.risk}`}>{approval.risk.replace('_',' ')}</em></div><div className="approval-operation"><span className="approval-command-label">LLM 请求运行的完整{script?'脚本':'命令'}</span><pre className="approval-command-preview">{script||`$ ${operation}`}</pre><dl><div><dt>Host</dt><dd>{hostName}</dd></div><div><dt>Expires</dt><dd><Clock3 size={12}/>{new Date(approval.expires_at).toLocaleTimeString()}</dd></div><div><dt>Digest</dt><dd>{approval.request_digest.slice(0,12)}</dd></div></dl>{typeof request.reason==='string'&&<p>{request.reason}</p>}</div>{approval.challenge&&<label className="approval-challenge-input"><span>Break-glass challenge · 输入 <code>{approval.challenge}</code></span><input value={challenge} onChange={event=>setChallenge(event.target.value)} placeholder="输入上方 challenge" autoComplete="off" autoFocus/></label>}<label className="approval-guidance"><span>审批说明 / 拒绝后告诉 LLM 应该改做什么</span><textarea value={note} maxLength={2000} onChange={event=>setNote(event.target.value)} placeholder="例如：不要重启服务，先只读取最近 100 行日志并分析原因。" autoFocus={!approval.challenge}/></label>{error&&<div className="approval-dialog-error"><ShieldAlert size={14}/>{error}</div>}<details className="approval-request-detail"><summary>查看完整请求</summary><pre>{JSON.stringify(request,null,2)}</pre></details><div className="approval-choice-grid"><button className="allow-once" disabled={disabled} onClick={()=>decide('once')}><Check size={16}/><span><b>{busy==='once'?'正在执行…':'仅允许本次'}</b><small>只批准当前请求摘要</small></span></button><button className="allow-session" disabled={disabled||approval.risk==='critical'} onClick={()=>decide('session')} title={approval.risk==='critical'?'Critical 操作不能会话级放行':''}><ShieldCheck size={16}/><span><b>{busy==='session'?'正在授权…':'本会话允许相同操作'}</b><small>{approval.risk==='critical'?'Critical 不可用':'主机、命令和参数必须完全一致'}</small></span></button><button className="reject-guidance" disabled={disabled||!note.trim()} onClick={reject}><X size={16}/><span><b>{busy==='reject'?'正在反馈…':'拒绝并告诉 LLM'}</b><small>将输入框内容作为新指令</small></span></button></div><p className="approval-wait">{running?'当前 Agent 已暂停在这个 Tool 调用，审批后会从原位置继续。':'原 Agent 连接已结束；本次决定仍会被执行并写入审计。'}</p></section></div>
}

const emptyHostForm: HostInput = {name:'',address:'',port:22,user:'',auth_type:'agent',config_alias:'',identity_file:'',known_hosts_file:'',proxy_jump:'',password:'',sudo_mode:'none',sudo_password:''}
const authLabels: Record<HostAuthType,string> = {agent:'SSH agent',key:'Private key file',password:'Account password',ssh_config:'SSH config alias'}
const sudoLabels: Record<HostSudoMode,string> = {none:'Disabled',nopasswd:'sudo -n (NOPASSWD)',password:'Managed sudo password'}

function HostsPage({ hosts, refresh }: {hosts:Host[];refresh:()=>Promise<void>}) {
  const [showForm, setShowForm] = useState(false); const [notice, setNotice] = useState(''); const [saving,setSaving]=useState(false)
  const [form, setForm] = useState<HostInput>(emptyHostForm)
  const editing=!!form.id
  const openCreate=()=>{setForm(emptyHostForm);setShowForm(true);setNotice('')}
  const openEdit=(host:Host)=>{setForm({id:host.id,name:host.name,address:host.address,port:host.port,user:host.user,auth_type:host.auth_type||'agent',config_alias:host.config_alias||'',identity_file:host.identity_file||'',known_hosts_file:host.known_hosts_file||'',proxy_jump:host.proxy_jump||'',password:'',sudo_mode:host.sudo_mode||'none',sudo_password:''});setShowForm(true);setNotice('')}
  const save = async (event:FormEvent) => { event.preventDefault(); setSaving(true); try { const saved=await api.saveHost(form); setShowForm(false); setForm(emptyHostForm); setNotice(`${saved.name} ${editing?'updated':'registered'}. Passwords are encrypted and are never returned by the API.`); await refresh() } catch(err){setNotice(errorText(err))} finally{setSaving(false)} }
  const scan = async (host:Host) => { try { const key = await api.scanKey(host.id); if (confirm(`Trust ${host.name}?\n\n${key.fingerprint}`)) { await api.trustKey(host.id, key.fingerprint); setNotice(`Trusted ${key.fingerprint}`) } } catch(err){setNotice(errorText(err))} }
  const probe = async (host:Host) => { try { const info = await api.probe(host.id); setNotice(`${host.name}: ${Object.values(info).join(' · ')}`) } catch(err){setNotice(errorText(err))} }
  return <div className="page-stack"><div className="page-actions"><div><p>Registered targets</p><span>SSH and sudo credentials are encrypted locally; the model receives only host IDs and capability flags.</span></div><button className="primary" onClick={openCreate}><Plus size={16}/>Add host</button></div>
    {notice && <div className="notice">{notice}<button onClick={()=>setNotice('')}><X size={14}/></button></div>}
    {showForm && <form className="host-form panel" onSubmit={save}><div className="host-form-head"><div><h3>{editing?'Edit SSH target':'Register SSH target'}</h3><p>{editing?'Leave password fields blank to keep their encrypted values.':'Choose how the control plane authenticates and whether managed sudo is permitted.'}</p></div><button type="button" className="close-button" onClick={()=>setShowForm(false)}><X size={16}/></button></div><div className="form-grid host-fields">
      <label><span>Name</span><input value={form.name} onChange={event=>setForm({...form,name:event.target.value})} required/></label>
      <label><span>Address</span><input value={form.address} onChange={event=>setForm({...form,address:event.target.value})} placeholder="192.0.2.10 or server.example.com" required={!form.config_alias}/></label>
      <label><span>Port</span><input type="number" min="1" max="65535" value={form.port} onChange={event=>setForm({...form,port:Number(event.target.value)})} required/></label>
      <label><span>User</span><input value={form.user} onChange={event=>setForm({...form,user:event.target.value})} placeholder="ops" required={!form.config_alias}/></label>
      <label><span>Authentication</span><select value={form.auth_type} onChange={event=>setForm({...form,auth_type:event.target.value as HostAuthType,password:''})}>{(Object.keys(authLabels) as HostAuthType[]).map(mode=><option value={mode} key={mode}>{authLabels[mode]}</option>)}</select></label>
      {form.auth_type==='password'&&<label><span>SSH password</span><input type="password" autoComplete="new-password" value={form.password} onChange={event=>setForm({...form,password:event.target.value})} placeholder={editing?'Leave blank to keep stored password':'Required'} required={!editing}/></label>}
      {form.auth_type==='key'&&<label><span>Identity file</span><input value={form.identity_file} onChange={event=>setForm({...form,identity_file:event.target.value})} placeholder="/home/ops/.ssh/id_ed25519" required/></label>}
      <label><span>SSH config alias</span><input value={form.config_alias} onChange={event=>setForm({...form,config_alias:event.target.value})} placeholder="Optional alias" required={form.auth_type==='ssh_config'}/></label>
      <label><span>ProxyJump</span><input value={form.proxy_jump} onChange={event=>setForm({...form,proxy_jump:event.target.value})} placeholder="Optional bastion target"/></label>
      <label><span>Known hosts file</span><input value={form.known_hosts_file} onChange={event=>setForm({...form,known_hosts_file:event.target.value})} placeholder="Use control-plane default"/></label>
      <label><span>Sudo policy</span><select value={form.sudo_mode} onChange={event=>setForm({...form,sudo_mode:event.target.value as HostSudoMode,sudo_password:''})}>{(Object.keys(sudoLabels) as HostSudoMode[]).map(mode=><option value={mode} key={mode}>{sudoLabels[mode]}</option>)}</select></label>
      {form.sudo_mode==='password'&&<label><span>Sudo password</span><input type="password" autoComplete="new-password" value={form.sudo_password} onChange={event=>setForm({...form,sudo_password:event.target.value})} placeholder={editing?'Leave blank to keep stored password':'Required'} required={!editing}/></label>}
    </div><div className="credential-note"><ShieldCheck size={15}/><span>LLM 调用提权命令时只设置 <code>elevated: true</code>。所有提权操作都会进入 break-glass 审批，密码不会进入模型上下文。通过局域网填写密码时，请先为 Web 接口配置 HTTPS 隧道。</span></div><div className="form-actions"><button type="button" onClick={()=>setShowForm(false)}>Cancel</button><button className="primary" disabled={saving}>{saving?'Saving…':editing?'Update host':'Save host'}</button></div></form>}
    <div className="host-grid">{hosts.map(host=><article className="host-card panel" key={host.id}><div className="host-top"><div className="server-glyph"><Server size={22}/></div><div><h3>{host.name}</h3><span>{host.config_alias || `${host.user}@${host.address}:${host.port}`}</span></div><span className="host-state">REGISTERED</span></div><dl><div><dt>Authentication</dt><dd>{authLabels[host.auth_type||'agent']}{host.auth_type==='password'&&host.has_password?' · encrypted':''}</dd></div><div><dt>Sudo</dt><dd>{sudoLabels[host.sudo_mode||'none']}{host.sudo_mode==='password'&&host.has_sudo_password?' · encrypted':''}</dd></div><div><dt>Host ID</dt><dd>{host.id}</dd></div></dl><div className="card-actions"><button onClick={()=>probe(host)}><Activity size={15}/>Probe</button><button onClick={()=>scan(host)}><KeyRound size={15}/>Trust key</button><button onClick={()=>openEdit(host)}><Edit3 size={15}/>Edit</button><button className="danger" onClick={async()=>{if(confirm(`Delete ${host.name}?`)){await api.deleteHost(host.id);await refresh()}}}><Trash2 size={15}/></button></div></article>)}</div>
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
