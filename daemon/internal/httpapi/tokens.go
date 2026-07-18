package httpapi

import (
	"net/http"
	"strconv"

	"naust/daemon/internal/api"
	"naust/daemon/internal/auth"
	"naust/daemon/internal/store/ent"
	entapitoken "naust/daemon/internal/store/ent/apitoken"
	entuser "naust/daemon/internal/store/ent/user"
)

const maxTokenNameLen = 100

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Store.APIToken.Query().
		Where(entapitoken.HasUserWith(entuser.ID(userFrom(r).ID))).
		Order(entapitoken.ByID()).
		All(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token query failed")
		return
	}
	resp := api.APITokensResponse{Tokens: make([]api.APIToken, 0, len(rows))}
	for _, t := range rows {
		resp.Tokens = append(resp.Tokens, apiToken(t))
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var req api.CreateAPITokenRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Name == "" || len(req.Name) > maxTokenNameLen {
		writeError(w, http.StatusBadRequest, "a token name of at most 100 characters is required")
		return
	}
	scope := entapitoken.Scope(req.Scope)
	if err := entapitoken.ScopeValidator(scope); err != nil {
		writeError(w, http.StatusBadRequest, "scope must be \"read\" or \"write\"")
		return
	}
	plaintext, row, err := auth.NewAPIToken(r.Context(), s.Store, userFrom(r), req.Name, scope)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token creation failed")
		return
	}
	writeJSON(w, http.StatusCreated, api.CreateAPITokenResponse{
		Token:    plaintext,
		Metadata: apiToken(row),
	})
}

func (s *Server) handleDeleteToken(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid token id")
		return
	}
	// Scoped to the owner: one admin cannot revoke another's tokens.
	n, err := s.Store.APIToken.Delete().
		Where(entapitoken.ID(id), entapitoken.HasUserWith(entuser.ID(userFrom(r).ID))).
		Exec(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token deletion failed")
		return
	}
	if n == 0 {
		writeError(w, http.StatusNotFound, "no such token")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func apiToken(t *ent.APIToken) api.APIToken {
	return api.APIToken{
		ID:        t.ID,
		Name:      t.Name,
		Scope:     string(t.Scope),
		CreatedAt: t.CreatedAt,
		LastUsed:  t.LastUsed,
	}
}
