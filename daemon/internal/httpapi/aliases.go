package httpapi

import (
	"net/http"

	"naust/daemon/internal/api"
	"naust/daemon/internal/materialize"
	"naust/daemon/internal/store/ent"
	entalias "naust/daemon/internal/store/ent/alias"
)

func (s *Server) handleListAliases(w http.ResponseWriter, r *http.Request) {
	aliases, err := s.Store.Alias.Query().
		Order(entalias.BySource()).
		All(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "alias query failed")
		return
	}
	routes, err := materialize.SystemRoutes(r.Context(), s.Store, s.PrimaryHostname)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "system route derivation failed")
		return
	}
	resp := api.AliasesResponse{
		Aliases: make([]api.Alias, 0, len(aliases)),
		System:  make([]api.SystemRoute, 0, len(routes)),
	}
	for _, a := range aliases {
		resp.Aliases = append(resp.Aliases, apiAlias(a))
	}
	for _, rt := range routes {
		resp.System = append(resp.System, api.SystemRoute{
			Source:      rt.Source,
			Destination: rt.Destinations[0],
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleUpsertAlias(w http.ResponseWriter, r *http.Request) {
	var req api.UpsertAliasRequest
	if !decodeBody(w, r, &req) {
		return
	}
	req.Source = asciiEmailDomain(req.Source)
	if err := validateAliasSource(req.Source); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Destinations) == 0 {
		writeError(w, http.StatusBadRequest, "at least one destination is required")
		return
	}
	for i, d := range req.Destinations {
		req.Destinations[i] = asciiEmailDomain(d)
		if err := validateEmailBasic(req.Destinations[i]); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	for i, p := range req.PermittedSenders {
		req.PermittedSenders[i] = asciiEmailDomain(p)
		if err := validateEmailBasic(req.PermittedSenders[i]); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	// Upserting over a system-generated (auto) alias turns it into a
	// manual one: the operator's rule overrides the generated default.
	err := s.Store.Alias.Create().
		SetSource(req.Source).
		SetDestinations(req.Destinations).
		SetPermittedSenders(req.PermittedSenders).
		SetAuto(false).
		SetTenantID(s.TenantID).
		OnConflictColumns(entalias.FieldSource).
		UpdateNewValues().
		Exec(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "alias save failed")
		return
	}
	a, err := s.Store.Alias.Query().
		Where(entalias.Source(req.Source)).
		Only(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "alias query failed")
		return
	}
	s.mailDataChanged()
	writeJSON(w, http.StatusOK, apiAlias(a))
}

func (s *Server) handleDeleteAlias(w http.ResponseWriter, r *http.Request) {
	// Normalize so a Unicode spelling deletes the punycoded row.
	source := asciiEmailDomain(r.PathValue("source"))
	a, err := s.Store.Alias.Query().
		Where(entalias.Source(source)).
		Only(r.Context())
	if ent.IsNotFound(err) {
		writeError(w, http.StatusNotFound, "no such alias")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "alias query failed")
		return
	}
	if a.Auto {
		writeError(w, http.StatusBadRequest, "system-generated aliases cannot be deleted; create an alias with the same source to override it")
		return
	}
	if err := s.Store.Alias.DeleteOne(a).Exec(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "alias deletion failed")
		return
	}
	s.mailDataChanged()
	w.WriteHeader(http.StatusNoContent)
}

func apiAlias(a *ent.Alias) api.Alias {
	return api.Alias{
		Source:           a.Source,
		Destinations:     a.Destinations,
		PermittedSenders: a.PermittedSenders,
		Auto:             a.Auto,
	}
}
