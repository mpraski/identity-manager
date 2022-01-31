package service

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/mpraski/identity-manager/app/rbac"
)

type (
	Authorization struct {
		authority rbac.Authorization
	}

	authorizationRequest struct {
		Scopes []string `validate:"required" json:"scopes"`
	}
)

func NewAuthorization(authority rbac.Authorization) *Authorization {
	return &Authorization{authority: authority}
}

func (a *Authorization) Router() *chi.Mux {
	r := chi.NewRouter()

	r.Post("/{identityID}", a.authorize)

	return r
}

func (a *Authorization) authorize(w http.ResponseWriter, r *http.Request) {
	identityID := chi.URLParam(r, "identityID")

	id, err := uuid.Parse(identityID)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	var body authorizationRequest
	if err = json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if err = validate.StructCtx(r.Context(), body); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	c, err := a.authority.HasScopes(r.Context(), id, body.Scopes)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	code := http.StatusForbidden
	if c {
		code = http.StatusOK
	}

	http.Error(w, http.StatusText(code), code)
}
