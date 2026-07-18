package httpapi

import (
	"encoding/json"
	"net/http"

	"naust/daemon/internal/api"
	"naust/daemon/internal/checks"
	entcheckresult "naust/daemon/internal/store/ent/checkresult"
	entsetting "naust/daemon/internal/store/ent/setting"
)

// CheckRunner is the slice of *checks.Engine the API uses.
type CheckRunner interface {
	RunNow(req checks.RunRequest)
	Busy() bool
}

func (s *Server) handleChecksStatus(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Store.CheckResult.Query().
		Order(entcheckresult.ByCategory(), entcheckresult.ByCheck(), entcheckresult.ByDomain()).
		All(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "status lookup failed")
		return
	}
	resp := api.ChecksStatusResponse{Results: make([]api.CheckResultInfo, 0, len(rows)), Running: s.Checks.Busy()}
	for _, row := range rows {
		info := api.CheckResultInfo{
			Check: row.Check, Category: row.Category, Domain: row.Domain,
			Status: row.Status, Message: row.Message,
			RanAt: row.RanAt, ElapsedMs: row.ElapsedMs, FirstFailedAt: row.FirstFailedAt,
		}
		// Step JSON is written by the engine in the api.CheckStep
		// field shape; a decode failure degrades to no steps.
		if err := json.Unmarshal([]byte(row.Steps), &info.Steps); err != nil || info.Steps == nil {
			info.Steps = []api.CheckStep{}
		}
		resp.Results = append(resp.Results, info)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleChecksRun(w http.ResponseWriter, r *http.Request) {
	var req api.ChecksRunRequest
	if r.ContentLength != 0 && !decodeBody(w, r, &req) {
		return
	}
	known := map[string]bool{}
	categories := map[string]bool{}
	for _, chk := range checks.All() {
		known[chk.Name] = true
		categories[chk.Category] = true
	}
	for _, name := range req.Checks {
		if !known[name] {
			writeError(w, http.StatusBadRequest, "unknown check: "+name)
			return
		}
	}
	if req.Category != "" && !categories[req.Category] {
		writeError(w, http.StatusBadRequest, "unknown category: "+req.Category)
		return
	}
	s.Checks.RunNow(checks.RunRequest{Checks: req.Checks, Category: req.Category, Domain: req.Domain})
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleChecksConfigGet(w http.ResponseWriter, r *http.Request) {
	cfg, err := checks.LoadConfig(r.Context(), s.Store)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "setting lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, api.ChecksConfigResponse{
		Config:    configToAPI(cfg),
		Available: checkCatalog(),
	})
}

func (s *Server) handleChecksConfigSet(w http.ResponseWriter, r *http.Request) {
	var req api.ChecksConfig
	if !decodeBody(w, r, &req) {
		return
	}
	cfg := configFromAPI(req)
	if err := cfg.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "setting update failed")
		return
	}
	err = s.Store.Setting.Create().
		SetKey(checks.SettingKey).
		SetValue(string(encoded)).
		OnConflictColumns(entsetting.FieldKey).
		UpdateNewValues().
		Exec(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "setting update failed")
		return
	}
	writeJSON(w, http.StatusOK, api.ChecksConfigResponse{Config: configToAPI(cfg), Available: checkCatalog()})
}

func checkCatalog() []api.CheckMeta {
	var out []api.CheckMeta
	for _, chk := range checks.All() {
		title := chk.Title
		if title == "" {
			title = chk.Name
		}
		class := chk.Class
		if class == "" {
			class = checks.ClassStandard
		}
		out = append(out, api.CheckMeta{
			Name: chk.Name, Title: title, Description: chk.Description,
			Category: chk.Category, Class: string(class), DefaultCadence: string(chk.Tier),
		})
	}
	return out
}

func configToAPI(cfg checks.Config) api.ChecksConfig {
	out := api.ChecksConfig{Report: cfg.Report}
	if len(cfg.Checks) > 0 {
		out.Checks = map[string]api.CheckOverrideConfig{}
		for name, o := range cfg.Checks {
			out.Checks[name] = api.CheckOverrideConfig{Cadence: o.Cadence, Enabled: o.Enabled}
		}
	}
	return out
}

func configFromAPI(cfg api.ChecksConfig) checks.Config {
	out := checks.Config{Report: cfg.Report}
	if len(cfg.Checks) > 0 {
		out.Checks = map[string]checks.CheckOverride{}
		for name, o := range cfg.Checks {
			out.Checks[name] = checks.CheckOverride{Cadence: o.Cadence, Enabled: o.Enabled}
		}
	}
	return out
}
