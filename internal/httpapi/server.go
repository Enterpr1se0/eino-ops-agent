package httpapi

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"eino-ops-agent/internal/agent"
	"eino-ops-agent/internal/domain"
	"eino-ops-agent/internal/ids"
	"eino-ops-agent/internal/observability"
	"eino-ops-agent/internal/security"
	"eino-ops-agent/internal/service"
	"eino-ops-agent/internal/skills"
	"eino-ops-agent/internal/store"
	webui "eino-ops-agent/web"
)

type Server struct {
	service       *service.Service
	agent         *agent.Runtime
	auth          *security.WebAuth
	secureCookies bool
	mux           *http.ServeMux
	loginMu       sync.Mutex
	loginAttempts map[string]loginAttempt
}

type loginAttempt struct {
	Count int
	Reset time.Time
}

func New(svc *service.Service, runtime *agent.Runtime, auth *security.WebAuth, secureCookies ...bool) *Server {
	secure := len(secureCookies) > 0 && secureCookies[0]
	s := &Server{service: svc, agent: runtime, auth: auth, secureCookies: secure, mux: http.NewServeMux(), loginAttempts: make(map[string]loginAttempt)}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler {
	return requestLogMiddleware(recoverMiddleware(corsMiddleware(s.authMiddleware(s.mux))))
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/v1/health", s.health)
	s.mux.HandleFunc("GET /api/v1/auth/session", s.authSession)
	s.mux.HandleFunc("POST /api/v1/auth/login", s.login)
	s.mux.HandleFunc("POST /api/v1/auth/logout", s.logout)
	s.mux.HandleFunc("PUT /api/v1/auth/password", s.changePassword)
	s.mux.HandleFunc("GET /api/v1/model-providers", s.listModelProviders)
	s.mux.HandleFunc("POST /api/v1/model-providers", s.saveModelProvider)
	s.mux.HandleFunc("POST /api/v1/model-providers/discover", s.discoverModels)
	s.mux.HandleFunc("POST /api/v1/model-providers/test", s.testModelConfiguration)
	s.mux.HandleFunc("DELETE /api/v1/model-providers/{id}", s.deleteModelProvider)
	s.mux.HandleFunc("POST /api/v1/model-providers/{id}/activate", s.activateModelProvider)
	s.mux.HandleFunc("POST /api/v1/model-providers/{id}/test", s.testModelProvider)
	s.mux.HandleFunc("GET /api/v1/settings", s.systemSettings)
	s.mux.HandleFunc("GET /api/v1/web-search/settings", s.webSearchSettings)
	s.mux.HandleFunc("PUT /api/v1/web-search/settings", s.saveWebSearchSettings)
	s.mux.HandleFunc("POST /api/v1/web-search/test", s.testWebSearch)
	s.mux.HandleFunc("GET /api/v1/capabilities", s.capabilities)
	s.mux.HandleFunc("GET /api/v1/agent/tools", s.agentTools)
	s.mux.HandleFunc("POST /api/v1/agent/tools/{name}/enable", s.enableAgentTool)
	s.mux.HandleFunc("POST /api/v1/agent/tools/{name}/disable", s.disableAgentTool)
	s.mux.HandleFunc("GET /api/v1/skills", s.listSkills)
	s.mux.HandleFunc("POST /api/v1/skills", s.uploadSkill)
	s.mux.HandleFunc("GET /api/v1/skills/{name}", s.getSkill)
	s.mux.HandleFunc("PUT /api/v1/skills/{name}", s.saveSkill)
	s.mux.HandleFunc("DELETE /api/v1/skills/{name}", s.deleteSkill)
	s.mux.HandleFunc("POST /api/v1/skills/{name}/enable", s.enableSkill)
	s.mux.HandleFunc("POST /api/v1/skills/{name}/disable", s.disableSkill)
	s.mux.HandleFunc("GET /api/v1/mcp-servers", s.listMCPServers)
	s.mux.HandleFunc("POST /api/v1/mcp-servers", s.saveMCPServer)
	s.mux.HandleFunc("GET /api/v1/mcp-servers/{id}", s.getMCPServer)
	s.mux.HandleFunc("PUT /api/v1/mcp-servers/{id}", s.updateMCPServer)
	s.mux.HandleFunc("DELETE /api/v1/mcp-servers/{id}", s.deleteMCPServer)
	s.mux.HandleFunc("POST /api/v1/mcp-servers/{id}/enable", s.enableMCPServer)
	s.mux.HandleFunc("POST /api/v1/mcp-servers/{id}/disable", s.disableMCPServer)
	s.mux.HandleFunc("POST /api/v1/mcp-servers/{id}/retry", s.retryMCPServer)
	s.mux.HandleFunc("POST /api/v1/mcp-servers/{id}/test", s.testMCPServer)
	s.mux.HandleFunc("POST /api/v1/workspaces", s.createWorkspace)
	s.mux.HandleFunc("PUT /api/v1/workspaces/{id}", s.updateWorkspace)
	s.mux.HandleFunc("DELETE /api/v1/workspaces/{id}", s.deleteWorkspace)
	s.mux.HandleFunc("GET /api/v1/workspaces/{id}/files", s.listWorkspaceFiles)
	s.mux.HandleFunc("POST /api/v1/workspaces/{id}/files", s.uploadWorkspaceFile)
	s.mux.HandleFunc("DELETE /api/v1/workspaces/{id}/files", s.deleteWorkspaceEntry)
	s.mux.HandleFunc("GET /api/v1/workspaces/{id}/preview", s.previewWorkspaceFile)
	s.mux.HandleFunc("PUT /api/v1/settings", s.saveSystemSettings)
	s.mux.HandleFunc("GET /api/v1/hosts", s.listHosts)
	s.mux.HandleFunc("POST /api/v1/hosts", s.saveHost)
	s.mux.HandleFunc("GET /api/v1/hosts/{id}", s.getHost)
	s.mux.HandleFunc("DELETE /api/v1/hosts/{id}", s.deleteHost)
	s.mux.HandleFunc("POST /api/v1/hosts/{id}/scan-key", s.scanHostKey)
	s.mux.HandleFunc("POST /api/v1/hosts/{id}/trust-key", s.trustHostKey)
	s.mux.HandleFunc("POST /api/v1/hosts/{id}/probe", s.probeHost)
	s.mux.HandleFunc("POST /api/v1/policy/evaluate", s.evaluate)
	s.mux.HandleFunc("POST /api/v1/exec", s.exec)
	s.mux.HandleFunc("POST /api/v1/tasks", s.startTask)
	s.mux.HandleFunc("GET /api/v1/tasks/{id}", s.getTask)
	s.mux.HandleFunc("POST /api/v1/tasks/{id}/cancel", s.cancelTask)
	s.mux.HandleFunc("GET /api/v1/approvals", s.listApprovals)
	s.mux.HandleFunc("POST /api/v1/approvals/{id}/explanation/retry", s.retryApprovalExplanation)
	s.mux.HandleFunc("POST /api/v1/approvals/{id}/approve", s.approve)
	s.mux.HandleFunc("POST /api/v1/approvals/{id}/reject", s.reject)
	s.mux.HandleFunc("GET /api/v1/runs", s.searchRuns)
	s.mux.HandleFunc("GET /api/v1/runs/{id}", s.getRun)
	s.mux.HandleFunc("GET /api/v1/audit", s.listAudit)
	s.mux.HandleFunc("GET /api/v1/logs", s.logs)
	s.mux.HandleFunc("POST /api/v1/chat", s.chat)
	s.mux.HandleFunc("GET /api/v1/chat/sessions", s.chatSessions)
	s.mux.HandleFunc("POST /api/v1/chat/{id}/cancel", s.cancelChatSession)
	s.mux.HandleFunc("DELETE /api/v1/chat/{id}", s.deleteChatSession)
	s.mux.HandleFunc("GET /api/v1/chat/{id}/messages", s.chatMessages)
	s.mux.HandleFunc("GET /api/v1/chat/{id}/state", s.chatState)
	s.mux.HandleFunc("/api/v1/", func(w http.ResponseWriter, _ *http.Request) {
		writeErrorStatus(w, fmt.Errorf("API endpoint not found"), http.StatusNotFound)
	})
	s.mux.Handle("/", spaHandler(webui.Assets()))
}

func (s *Server) capabilities(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"workspaces": s.service.ListAdminWorkspaceCapabilities()})
}

func (s *Server) createWorkspace(w http.ResponseWriter, r *http.Request) {
	var input domain.WorkspaceInput
	if !decode(w, r, &input) {
		return
	}
	result, err := s.service.CreateAdminWorkspace(r.Context(), input, actor(r))
	if err != nil {
		writeErrorStatus(w, err, http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (s *Server) updateWorkspace(w http.ResponseWriter, r *http.Request) {
	var input domain.WorkspaceInput
	if !decode(w, r, &input) {
		return
	}
	result, err := s.service.UpdateAdminWorkspace(r.Context(), r.PathValue("id"), input, actor(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) deleteWorkspace(w http.ResponseWriter, r *http.Request) {
	if err := s.service.DeleteAdminWorkspace(r.Context(), r.PathValue("id"), actor(r)); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) agentTools(w http.ResponseWriter, _ *http.Request) {
	if s.agent == nil {
		writeJSON(w, http.StatusOK, agent.ToolCatalog{Agent: "ops-pilot", Framework: "Eino InferTool", ExecutionMode: "sequential", Tools: []agent.ToolDescriptor{}})
		return
	}
	writeJSON(w, http.StatusOK, s.agent.ToolCatalog())
}

func (s *Server) enableAgentTool(w http.ResponseWriter, r *http.Request) {
	s.setAgentToolEnabled(w, r, true)
}

func (s *Server) disableAgentTool(w http.ResponseWriter, r *http.Request) {
	s.setAgentToolEnabled(w, r, false)
}

func (s *Server) setAgentToolEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	name := r.PathValue("name")
	if s.agent == nil || !s.agent.HasTool(name) {
		writeErrorStatus(w, fmt.Errorf("agent function %q not found", name), http.StatusNotFound)
		return
	}
	if err := s.service.SetAgentToolEnabled(r.Context(), name, enabled, actor(r)); err != nil {
		writeErrorStatus(w, err, http.StatusBadRequest)
		return
	}
	if err := s.agent.Reload(r.Context()); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.agent.ToolCatalog())
}

func (s *Server) listSkills(w http.ResponseWriter, _ *http.Request) {
	result, err := s.service.ListSkills()
	respond(w, result, err)
}

func (s *Server) getSkill(w http.ResponseWriter, r *http.Request) {
	result, err := s.service.GetAdminSkill(r.PathValue("name"))
	if errors.Is(err, skills.ErrNotFound) {
		writeErrorStatus(w, err, http.StatusNotFound)
		return
	}
	respond(w, result, err)
}

func (s *Server) uploadSkill(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 9<<20)
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		status := http.StatusBadRequest
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writeErrorStatus(w, fmt.Errorf("invalid skill upload: %w", err), status)
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeErrorStatus(w, fmt.Errorf("skill file is required"), http.StatusBadRequest)
		return
	}
	defer file.Close()
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(header.Filename), filepath.Ext(header.Filename))
	}
	result, err := s.service.ImportAdminSkill(r.Context(), name, header.Filename, file, actor(r))
	if err != nil {
		writeErrorStatus(w, err, http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (s *Server) saveSkill(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, (2<<20)+(16<<10))
	var input service.SkillContentInput
	if !decode(w, r, &input) {
		return
	}
	result, err := s.service.SaveAdminSkill(r.Context(), r.PathValue("name"), input.Content, actor(r))
	if err != nil {
		writeErrorStatus(w, err, http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) deleteSkill(w http.ResponseWriter, r *http.Request) {
	err := s.service.DeleteAdminSkill(r.Context(), r.PathValue("name"), actor(r))
	if errors.Is(err, skills.ErrNotFound) {
		writeErrorStatus(w, err, http.StatusNotFound)
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) enableSkill(w http.ResponseWriter, r *http.Request) {
	s.setSkillEnabled(w, r, true)
}

func (s *Server) disableSkill(w http.ResponseWriter, r *http.Request) {
	s.setSkillEnabled(w, r, false)
}

func (s *Server) setSkillEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	result, err := s.service.SetAdminSkillEnabled(r.Context(), r.PathValue("name"), enabled, actor(r))
	if errors.Is(err, skills.ErrNotFound) {
		writeErrorStatus(w, err, http.StatusNotFound)
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}
	if s.agent != nil {
		if err := s.agent.Reload(r.Context()); err != nil {
			writeError(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) listMCPServers(w http.ResponseWriter, r *http.Request) {
	result, err := s.service.ListMCPServers(r.Context())
	respond(w, result, err)
}

func (s *Server) getMCPServer(w http.ResponseWriter, r *http.Request) {
	result, err := s.service.GetMCPServer(r.Context(), r.PathValue("id"))
	respond(w, result, err)
}

func (s *Server) saveMCPServer(w http.ResponseWriter, r *http.Request) {
	s.saveMCPServerInput(w, r, "", http.StatusCreated)
}

func (s *Server) updateMCPServer(w http.ResponseWriter, r *http.Request) {
	s.saveMCPServerInput(w, r, r.PathValue("id"), http.StatusOK)
}

func (s *Server) saveMCPServerInput(w http.ResponseWriter, r *http.Request, id string, status int) {
	var input domain.MCPServerInput
	if !decode(w, r, &input) {
		return
	}
	if id != "" {
		input.ID = id
	}
	result, err := s.service.SaveMCPServer(r.Context(), input, actor(r))
	if err != nil {
		writeErrorStatus(w, err, http.StatusBadRequest)
		return
	}
	if err := s.reloadAgent(r.Context()); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, status, result)
}

func (s *Server) deleteMCPServer(w http.ResponseWriter, r *http.Request) {
	if err := s.service.DeleteMCPServer(r.Context(), r.PathValue("id"), actor(r)); err != nil {
		writeError(w, err)
		return
	}
	if err := s.reloadAgent(r.Context()); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) enableMCPServer(w http.ResponseWriter, r *http.Request) {
	s.setMCPServerEnabled(w, r, true)
}

func (s *Server) disableMCPServer(w http.ResponseWriter, r *http.Request) {
	s.setMCPServerEnabled(w, r, false)
}

func (s *Server) setMCPServerEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	result, err := s.service.SetMCPServerEnabled(r.Context(), r.PathValue("id"), enabled, actor(r))
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.reloadAgent(r.Context()); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) retryMCPServer(w http.ResponseWriter, r *http.Request) {
	err := s.service.ReconnectMCPServer(r.Context(), r.PathValue("id"))
	reloadErr := s.reloadAgent(r.Context())
	if err != nil {
		writeErrorStatus(w, err, http.StatusBadGateway)
		return
	}
	if reloadErr != nil {
		writeError(w, reloadErr)
		return
	}
	result, err := s.service.GetMCPServer(r.Context(), r.PathValue("id"))
	respond(w, result, err)
}

func (s *Server) testMCPServer(w http.ResponseWriter, r *http.Request) {
	result, err := s.service.TestMCPServer(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErrorStatus(w, err, http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) reloadAgent(ctx context.Context) error {
	if s.agent == nil {
		return nil
	}
	return s.agent.Reload(ctx)
}

func (s *Server) listWorkspaceFiles(w http.ResponseWriter, r *http.Request) {
	result, err := s.service.ListAdminWorkspaceFiles(r.PathValue("id"), r.URL.Query().Get("path"))
	respond(w, result, err)
}

func (s *Server) previewWorkspaceFile(w http.ResponseWriter, r *http.Request) {
	result, err := s.service.PreviewAdminWorkspaceFile(r.PathValue("id"), r.URL.Query().Get("path"))
	respond(w, result, err)
}

func (s *Server) deleteWorkspaceEntry(w http.ResponseWriter, r *http.Request) {
	result, err := s.service.DeleteAdminWorkspaceEntry(r.Context(), r.PathValue("id"), r.URL.Query().Get("path"), actor(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) uploadWorkspaceFile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, (100<<20)+(1<<20))
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		status := http.StatusBadRequest
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writeErrorStatus(w, fmt.Errorf("invalid workspace upload: %w", err), status)
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeErrorStatus(w, fmt.Errorf("file is required"), http.StatusBadRequest)
		return
	}
	defer file.Close()
	if header.Size > 100<<20 {
		writeErrorStatus(w, fmt.Errorf("workspace upload exceeds 100 MiB"), http.StatusRequestEntityTooLarge)
		return
	}
	result, err := s.service.UploadWorkspaceFile(r.Context(), r.PathValue("id"), r.FormValue("path"), header.Filename, file, actor(r))
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, store.ErrNotFound) {
			status = http.StatusNotFound
		} else if strings.Contains(err.Error(), "already exists") {
			status = http.StatusConflict
		}
		writeErrorStatus(w, err, status)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.auth == nil || !strings.HasPrefix(r.URL.Path, "/api/v1/") || r.URL.Path == "/api/v1/health" || r.URL.Path == "/api/v1/auth/login" {
			next.ServeHTTP(w, r)
			return
		}
		cookie, err := r.Cookie(security.SessionCookieName)
		if err != nil {
			writeErrorStatus(w, fmt.Errorf("authentication required"), http.StatusUnauthorized)
			return
		}
		session, err := s.auth.Authenticate(r.Context(), cookie.Value)
		if err != nil {
			s.clearSessionCookie(w)
			writeErrorStatus(w, fmt.Errorf("authentication required"), http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			provided := strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
			if provided == "" || provided != session.CSRFToken {
				writeErrorStatus(w, fmt.Errorf("invalid CSRF token"), http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		writeErrorStatus(w, fmt.Errorf("web authentication is unavailable"), http.StatusServiceUnavailable)
		return
	}
	remote := remoteIP(r)
	if !s.allowLoginAttempt(remote) {
		writeErrorStatus(w, fmt.Errorf("too many login attempts; retry later"), http.StatusTooManyRequests)
		return
	}
	var input struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &input) {
		return
	}
	token, session, err := s.auth.Login(r.Context(), input.Password)
	if err != nil {
		time.Sleep(250 * time.Millisecond)
		writeErrorStatus(w, fmt.Errorf("invalid administrator credentials"), http.StatusUnauthorized)
		return
	}
	s.resetLoginAttempts(remote)
	http.SetCookie(w, &http.Cookie{Name: security.SessionCookieName, Value: token, Path: "/", HttpOnly: true, Secure: s.secureCookies, SameSite: http.SameSiteStrictMode, Expires: session.ExpiresAt, MaxAge: int(time.Until(session.ExpiresAt).Seconds())})
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "csrf_token": session.CSRFToken, "expires_at": session.ExpiresAt})
}

func (s *Server) authSession(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie(security.SessionCookieName)
	session, err := s.auth.Authenticate(r.Context(), cookie.Value)
	if err != nil {
		writeErrorStatus(w, fmt.Errorf("authentication required"), http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "csrf_token": session.CSRFToken, "expires_at": session.ExpiresAt})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie(security.SessionCookieName)
	if cookie != nil {
		_ = s.auth.Logout(r.Context(), cookie.Value)
	}
	s.clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Current     string `json:"current_password"`
		Replacement string `json:"new_password"`
	}
	if !decode(w, r, &input) {
		return
	}
	if err := s.auth.ChangePassword(r.Context(), input.Current, input.Replacement); err != nil {
		writeErrorStatus(w, err, http.StatusBadRequest)
		return
	}
	s.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{"changed": true, "login_required": true})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: security.SessionCookieName, Value: "", Path: "/", HttpOnly: true, Secure: s.secureCookies, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

func (s *Server) allowLoginAttempt(remote string) bool {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	now := time.Now()
	attempt := s.loginAttempts[remote]
	if now.After(attempt.Reset) {
		attempt = loginAttempt{Reset: now.Add(5 * time.Minute)}
	}
	attempt.Count++
	s.loginAttempts[remote] = attempt
	return attempt.Count <= 10
}

func (s *Server) resetLoginAttempts(remote string) {
	s.loginMu.Lock()
	delete(s.loginAttempts, remote)
	s.loginMu.Unlock()
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	result := observability.Recent(observability.LogFilter{
		Level: r.URL.Query().Get("level"), Component: r.URL.Query().Get("component"),
		Query: r.URL.Query().Get("q"), Limit: limit,
	})
	writeJSON(w, http.StatusOK, map[string]any{"entries": result, "components": observability.Components(), "minimum_level": observability.MinimumLevel(), "file": observability.File()})
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	model := agent.Status{Source: "none"}
	if s.agent != nil {
		model = s.agent.Status()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok", "agent_available": model.Available, "model": model, "time": time.Now().UTC(),
	})
}

func (s *Server) systemSettings(w http.ResponseWriter, r *http.Request) {
	result, err := s.service.SystemSettings(r.Context())
	respond(w, result, err)
}

func (s *Server) saveSystemSettings(w http.ResponseWriter, r *http.Request) {
	var input domain.SystemSettingsInput
	if !decode(w, r, &input) {
		return
	}
	result, err := s.service.SaveSystemSettings(r.Context(), input, actor(r))
	if err != nil {
		writeError(w, err)
		return
	}
	if s.agent != nil {
		if err := s.agent.Reload(r.Context()); err != nil {
			writeError(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) webSearchSettings(w http.ResponseWriter, r *http.Request) {
	result, err := s.service.WebSearchSettings(r.Context())
	respond(w, result, err)
}

func (s *Server) saveWebSearchSettings(w http.ResponseWriter, r *http.Request) {
	var input domain.WebSearchSettingsInput
	if !decode(w, r, &input) {
		return
	}
	result, err := s.service.SaveWebSearchSettings(r.Context(), input, actor(r))
	if err != nil {
		writeErrorStatus(w, err, http.StatusBadRequest)
		return
	}
	if s.agent != nil {
		if err := s.agent.Reload(r.Context()); err != nil {
			writeError(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) testWebSearch(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Query string `json:"query"`
	}
	if !decode(w, r, &input) {
		return
	}
	if strings.TrimSpace(input.Query) == "" {
		input.Query = "Tavily Search API"
	}
	result, err := s.service.SearchWeb(r.Context(), domain.WebSearchRequest{Query: input.Query, MaxResults: 1}, actor(r))
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, context.DeadlineExceeded) {
			status = http.StatusGatewayTimeout
		} else if errors.Is(err, service.ErrWebSearchUpstream) {
			status = http.StatusBadGateway
		}
		writeErrorStatus(w, err, status)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) listModelProviders(w http.ResponseWriter, r *http.Request) {
	result, err := s.service.ListModelProviders(r.Context())
	respond(w, result, err)
}

func (s *Server) saveModelProvider(w http.ResponseWriter, r *http.Request) {
	var input domain.ModelProviderInput
	if !decode(w, r, &input) {
		return
	}
	result, err := s.service.SaveModelProvider(r.Context(), input, actor(r))
	if err != nil {
		writeError(w, err)
		return
	}
	settings, err := s.service.SystemSettings(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	if (result.Active || settings.SubagentModelProviderID == result.ID) && s.agent != nil {
		if err := s.agent.Reload(r.Context()); err != nil {
			writeError(w, err)
			return
		}
	}
	writeJSON(w, http.StatusCreated, result)
}

func (s *Server) discoverModels(w http.ResponseWriter, r *http.Request) {
	var input domain.ModelDiscoveryInput
	if !decode(w, r, &input) {
		return
	}
	result, err := s.service.DiscoverModels(r.Context(), input, actor(r))
	if err != nil {
		if errors.Is(err, service.ErrModelProviderUpstream) {
			writeErrorStatus(w, err, http.StatusBadGateway)
			return
		}
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) testModelConfiguration(w http.ResponseWriter, r *http.Request) {
	if s.agent == nil {
		writeErrorStatus(w, agent.ErrUnavailable, http.StatusServiceUnavailable)
		return
	}
	var input domain.ModelTestInput
	if !decode(w, r, &input) {
		return
	}
	cfg, err := s.service.ModelTestConfig(r.Context(), input)
	if err != nil {
		writeError(w, err)
		return
	}
	result, err := s.agent.TestProvider(r.Context(), cfg)
	if err != nil {
		writeErrorStatus(w, err, http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) activateModelProvider(w http.ResponseWriter, r *http.Request) {
	result, err := s.service.ActivateModelProvider(r.Context(), r.PathValue("id"), actor(r))
	if err != nil {
		writeError(w, err)
		return
	}
	if s.agent == nil {
		writeError(w, agent.ErrUnavailable)
		return
	}
	if err := s.agent.Reload(r.Context()); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) deleteModelProvider(w http.ResponseWriter, r *http.Request) {
	wasActive, err := s.service.DeleteModelProvider(r.Context(), r.PathValue("id"), actor(r))
	if err != nil {
		if errors.Is(err, service.ErrModelProviderInUse) {
			writeErrorStatus(w, err, http.StatusConflict)
			return
		}
		writeError(w, err)
		return
	}
	if wasActive && s.agent != nil {
		if err := s.agent.Reload(r.Context()); err != nil {
			writeError(w, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) testModelProvider(w http.ResponseWriter, r *http.Request) {
	if s.agent == nil {
		writeErrorStatus(w, agent.ErrUnavailable, http.StatusServiceUnavailable)
		return
	}
	cfg, provider, err := s.service.ModelProviderConfig(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	result, err := s.agent.TestProvider(r.Context(), cfg)
	if err != nil {
		writeErrorStatus(w, err, http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"provider_id": provider.ID, "name": provider.Name, "model": result.Model,
		"response": result.Response, "latency_ms": result.LatencyMS,
	})
}

func (s *Server) listHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.service.ListHosts(r.Context())
	respond(w, hosts, err)
}

func (s *Server) saveHost(w http.ResponseWriter, r *http.Request) {
	var host domain.HostInput
	if !decodeLimit(w, r, &host, 3<<20) {
		return
	}
	result, err := s.service.SaveHost(r.Context(), host, actor(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (s *Server) getHost(w http.ResponseWriter, r *http.Request) {
	host, err := s.service.GetHost(r.Context(), r.PathValue("id"))
	respond(w, host, err)
}

func (s *Server) deleteHost(w http.ResponseWriter, r *http.Request) {
	err := s.service.DeleteHost(r.Context(), r.PathValue("id"), actor(r))
	if err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) scanHostKey(w http.ResponseWriter, r *http.Request) {
	result, err := s.service.ScanHostKey(r.Context(), r.PathValue("id"))
	respond(w, result, err)
}

func (s *Server) trustHostKey(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Fingerprint string `json:"fingerprint"`
	}
	if !decode(w, r, &input) {
		return
	}
	result, err := s.service.TrustHostKey(r.Context(), r.PathValue("id"), input.Fingerprint, actor(r))
	respond(w, result, err)
}

func (s *Server) probeHost(w http.ResponseWriter, r *http.Request) {
	result, err := s.service.ProbeHost(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, err)
		} else {
			writeErrorStatus(w, err, http.StatusBadGateway)
		}
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) evaluate(w http.ResponseWriter, r *http.Request) {
	var req domain.ExecRequest
	if !decode(w, r, &req) {
		return
	}
	result, err := s.service.Evaluate(r.Context(), req)
	respond(w, result, err)
}

func (s *Server) exec(w http.ResponseWriter, r *http.Request) {
	var req domain.ExecRequest
	if !decode(w, r, &req) {
		return
	}
	result, err := s.service.Submit(r.Context(), req, actor(r))
	respond(w, result, err)
}

func (s *Server) startTask(w http.ResponseWriter, r *http.Request) {
	var req domain.ExecRequest
	if !decode(w, r, &req) {
		return
	}
	result, err := s.service.StartTask(r.Context(), req, actor(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, result)
}

func (s *Server) getTask(w http.ResponseWriter, r *http.Request) {
	task, result, taskErr, err := s.service.GetTask(r.PathValue("id"))
	respond(w, map[string]any{"task": task, "result": result, "error": taskErr}, err)
}

func (s *Server) cancelTask(w http.ResponseWriter, r *http.Request) {
	err := s.service.CancelTask(r.PathValue("id"), actor(r))
	respond(w, map[string]any{"cancelled": err == nil}, err)
}

func (s *Server) listApprovals(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	result, err := s.service.ListApprovals(r.Context(), r.URL.Query().Get("status"), limit)
	respond(w, result, err)
}

func (s *Server) retryApprovalExplanation(w http.ResponseWriter, r *http.Request) {
	result, err := s.service.RetryApprovalExplanation(r.Context(), r.PathValue("id"), actor(r))
	respond(w, result, err)
}

func (s *Server) approve(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Reason string `json:"reason"`
		Scope  string `json:"scope"`
	}
	if !decode(w, r, &input) {
		return
	}
	result, err := s.service.ApproveWithScope(r.Context(), r.PathValue("id"), input.Reason, input.Scope, actor(r))
	respond(w, result, err)
}

func (s *Server) reject(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Reason string `json:"reason"`
	}
	if !decode(w, r, &input) {
		return
	}
	err := s.service.Reject(r.Context(), r.PathValue("id"), input.Reason, actor(r))
	respond(w, map[string]any{"rejected": err == nil}, err)
}

func (s *Server) searchRuns(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	result, err := s.service.SearchRuns(r.Context(), r.URL.Query().Get("q"), r.URL.Query().Get("host_id"), limit)
	respond(w, result, err)
}

func (s *Server) getRun(w http.ResponseWriter, r *http.Request) {
	includeRaw := r.URL.Query().Get("raw") == "1"
	result, err := s.service.GetRun(r.Context(), r.PathValue("id"), includeRaw)
	respond(w, result, err)
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	result, err := s.service.ListAudit(r.Context(), r.URL.Query().Get("run_id"), limit)
	respond(w, result, err)
}

func (s *Server) chat(w http.ResponseWriter, r *http.Request) {
	if s.agent == nil || !s.agent.Available() {
		writeErrorStatus(w, agent.ErrUnavailable, http.StatusServiceUnavailable)
		return
	}
	var input struct {
		SessionID string `json:"session_id"`
		Message   string `json:"message"`
	}
	if !decode(w, r, &input) {
		return
	}
	if strings.TrimSpace(input.Message) == "" {
		writeErrorStatus(w, fmt.Errorf("message is required"), http.StatusBadRequest)
		return
	}
	streamAgentEvents(w, r, 10*time.Second, func(emit func(agent.Event)) {
		queryCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Minute)
		defer cancel()
		_, err := s.agent.Query(queryCtx, input.SessionID, input.Message, emit)
		if err != nil && !errors.Is(err, context.Canceled) {
			emit(agent.Event{Type: "error", Error: err.Error(), SessionID: input.SessionID})
		}
	})
}

// streamAgentEvents keeps the ResponseWriter owned by the HTTP goroutine while
// the Agent continues independently. This makes heartbeats and disconnects safe:
// a browser or proxy disappearing stops only the SSE writer, not the Agent loop.
func streamAgentEvents(w http.ResponseWriter, r *http.Request, heartbeatInterval time.Duration, run func(func(agent.Event))) {
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Connection", "keep-alive")
	if _, ok := w.(http.Flusher); !ok {
		writeError(w, fmt.Errorf("streaming is unavailable"))
		return
	}

	controller := http.NewResponseController(w)
	write := func(payload string) error {
		if _, err := fmt.Fprint(w, payload); err != nil {
			return err
		}
		return controller.Flush()
	}
	if err := write(": connected\n\n"); err != nil {
		return
	}

	events := make(chan agent.Event, 64)
	clientClosed := make(chan struct{})
	publish := func(event agent.Event) {
		select {
		case <-clientClosed:
			return
		default:
		}
		select {
		case events <- event:
		case <-clientClosed:
		}
	}
	go func() {
		defer close(events)
		defer func() {
			if recovered := recover(); recovered != nil {
				observability.FromContext(r.Context()).ErrorContext(r.Context(), "agent stream panic", "component", "agent", "error", recovered)
				publish(agent.Event{Type: "error", Error: "internal agent stream error"})
			}
		}()
		run(publish)
	}()

	heartbeat := time.NewTicker(heartbeatInterval)
	defer heartbeat.Stop()
	defer close(clientClosed)
	lastSessionID := ""
	logger := observability.FromContext(r.Context())
	for {
		select {
		case <-r.Context().Done():
			logger.DebugContext(r.Context(), "chat client disconnected; agent continues in background", "component", "agent", "session_id", lastSessionID, "error", r.Context().Err())
			return
		case event, ok := <-events:
			if !ok {
				return
			}
			if event.SessionID != "" {
				lastSessionID = event.SessionID
			}
			data, err := json.Marshal(event)
			if err != nil {
				continue
			}
			if err := write(fmt.Sprintf("event: %s\ndata: %s\n\n", event.Type, data)); err != nil {
				logger.DebugContext(r.Context(), "chat client disconnected; agent continues in background", "component", "agent", "session_id", lastSessionID, "error", err)
				return
			}
		case <-heartbeat.C:
			if err := write(": heartbeat\n\n"); err != nil {
				logger.DebugContext(r.Context(), "chat heartbeat failed; agent continues in background", "component", "agent", "session_id", lastSessionID, "error", err)
				return
			}
		}
	}
}

func (s *Server) chatMessages(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	result, err := s.service.ListChatMessages(r.Context(), r.PathValue("id"), limit)
	respond(w, result, err)
}

func (s *Server) chatState(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")
	messages, err := s.service.ListChatMessages(r.Context(), sessionID, 200)
	if err != nil {
		writeError(w, err)
		return
	}
	var plan *domain.AgentPlan
	currentPlan, planErr := s.service.GetAgentPlan(r.Context(), sessionID)
	if planErr == nil {
		plan = &currentPlan
	} else if !errors.Is(planErr, store.ErrNotFound) {
		writeError(w, planErr)
		return
	}
	active := s.agent != nil && s.agent.IsSessionActive(sessionID)
	writeJSON(w, http.StatusOK, map[string]any{"active": active, "messages": messages, "plan": plan})
}

func (s *Server) chatSessions(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	result, err := s.service.ListChatSessions(r.Context(), limit)
	if err != nil {
		writeError(w, err)
		return
	}
	if s.agent != nil {
		for index := range result {
			result[index].Active = s.agent.IsSessionActive(result[index].ID)
		}
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) cancelChatSession(w http.ResponseWriter, r *http.Request) {
	if s.agent == nil {
		writeErrorStatus(w, agent.ErrUnavailable, http.StatusServiceUnavailable)
		return
	}
	sessionID := strings.TrimSpace(r.PathValue("id"))
	if sessionID == "" {
		writeErrorStatus(w, fmt.Errorf("session id is required"), http.StatusBadRequest)
		return
	}
	cancelled := s.agent.CancelSession(sessionID)
	rejectedApprovals := 0
	if s.service != nil {
		var err error
		rejectedApprovals, err = s.service.RejectPendingApprovalsForSession(r.Context(), sessionID, "Agent run stopped by the operator", actor(r))
		if err != nil {
			writeError(w, fmt.Errorf("cancel Agent session approvals: %w", err))
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"cancelled": cancelled, "rejected_approvals": rejectedApprovals})
}

func (s *Server) deleteChatSession(w http.ResponseWriter, r *http.Request) {
	if s.agent != nil && s.agent.IsSessionActive(r.PathValue("id")) {
		writeErrorStatus(w, fmt.Errorf("cannot delete a conversation while its Agent run is active"), http.StatusConflict)
		return
	}
	if err := s.service.DeleteChatSession(r.Context(), r.PathValue("id"), actor(r)); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func decode(w http.ResponseWriter, r *http.Request, target any) bool {
	return decodeLimit(w, r, target, 2<<20)
}

func decodeLimit(w http.ResponseWriter, r *http.Request, target any, maxBytes int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeErrorStatus(w, fmt.Errorf("invalid JSON: %w", err), http.StatusBadRequest)
		return false
	}
	return true
}

func respond(w http.ResponseWriter, value any, err error) {
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
		status = http.StatusNotFound
	} else if strings.Contains(err.Error(), "required") || strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "expired") || strings.Contains(err.Error(), "mismatch") || strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "not a regular file") || strings.Contains(err.Error(), "can be deleted") {
		status = http.StatusBadRequest
	}
	writeErrorStatus(w, err, status)
}

func writeErrorStatus(w http.ResponseWriter, err error, status int) {
	writeJSON(w, status, map[string]any{"error": err.Error()})
}

func actor(r *http.Request) string {
	return "admin-web"
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "http://localhost:5173" || origin == "http://127.0.0.1:5173" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				observability.FromContext(r.Context()).ErrorContext(r.Context(), "HTTP panic", "component", "http", "error", recovered, "path", r.URL.Path)
				writeErrorStatus(w, fmt.Errorf("internal server error"), http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type logResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *logResponseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *logResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	written, err := w.ResponseWriter.Write(data)
	w.bytes += written
	return written, err
}

func (w *logResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *logResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func requestLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		requestID := ids.New("request")
		logger := slog.Default().With("request_id", requestID)
		ctx := observability.WithLogger(r.Context(), logger)
		r = r.WithContext(ctx)
		w.Header().Set("X-Request-ID", requestID)
		recorder := &logResponseWriter{ResponseWriter: w}
		next.ServeHTTP(recorder, r)
		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		if r.URL.Path == "/api/v1/logs" || r.URL.Path == "/api/v1/health" || (strings.HasPrefix(r.URL.Path, "/api/v1/chat/") && strings.HasSuffix(r.URL.Path, "/state")) {
			return
		}
		host := r.RemoteAddr
		if parsed, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			host = parsed
		}
		level := slog.LevelDebug
		if r.Method != http.MethodGet && r.Method != http.MethodOptions {
			level = slog.LevelInfo
		}
		if status >= 500 {
			level = slog.LevelError
		} else if status >= 400 {
			level = slog.LevelWarn
		}
		logger.With("component", "http").LogAttrs(ctx, level, "HTTP request completed",
			slog.String("method", r.Method), slog.String("path", r.URL.Path), slog.Int("status", status),
			slog.Int64("duration_ms", time.Since(started).Milliseconds()), slog.Int("response_bytes", recorder.bytes), slog.String("remote_ip", host))
	})
}

func spaHandler(root fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		clean := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if clean == "" || clean == "." {
			clean = "index.html"
		}
		if info, err := fs.Stat(root, clean); err == nil && !info.IsDir() {
			if clean == "index.html" {
				w.Header().Set("Cache-Control", "no-cache, max-age=0")
			}
			fileServer.ServeHTTP(w, r)
			return
		}
		index, err := root.Open("index.html")
		if err != nil {
			http.Error(w, "embedded web UI is unavailable", http.StatusNotFound)
			return
		}
		defer index.Close()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache, max-age=0")
		_, _ = bufio.NewReader(index).WriteTo(w)
	})
}
