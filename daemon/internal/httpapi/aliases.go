package httpapi

import (
	"net/http"

	"naust/daemon/internal/adminops"
	"naust/daemon/internal/api"
	"naust/daemon/internal/mailaddr"
	"naust/daemon/internal/materialize"
	"naust/daemon/internal/store/ent"
	entalias "naust/daemon/internal/store/ent/alias"
)

func (s *Server) handleListAliases(w http.ResponseWriter, r *http.Request) {
	aliases, err := adminops.ListAliases(r.Context(), s.Store)
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
	// The panel's set-this-alias semantics overwrite: upserting over a
	// system-generated (auto) alias turns it into a manual one.
	a, err := adminops.UpsertAlias(r.Context(), s.Store, s.TenantID, adminops.AliasParams{
		Source:           req.Source,
		Destinations:     req.Destinations,
		PermittedSenders: req.PermittedSenders,
	}, true)
	if err != nil {
		writeAccountError(w, err, "alias save failed")
		return
	}
	s.mailDataChanged()
	writeJSON(w, http.StatusOK, apiAlias(a))
}

func (s *Server) handleDeleteAlias(w http.ResponseWriter, r *http.Request) {
	// Normalize so a Unicode spelling deletes the punycoded row.
	source := mailaddr.NormalizeDomain(r.PathValue("source"))
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
