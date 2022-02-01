package service

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/mpraski/identity-manager/app/activation"
	"github.com/mpraski/identity-manager/app/storage"
)

type (
	Activation struct {
		provider activation.Provider
	}

	activationRequest struct {
		Token string `validate:"required,len=32" json:"token"`
	}
)

func NewActivation(provider activation.Provider) *Activation {
	return &Activation{provider: provider}
}

func (a *Activation) Router() *chi.Mux {
	r := chi.NewRouter()

	r.Get("/activate", a.activate)

	return r
}

func (a *Activation) activate(w http.ResponseWriter, r *http.Request) {
	var body activationRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if err := validate.StructCtx(r.Context(), body); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	request := activation.Request{
		Token: strings.TrimSpace(body.Token),
	}

	_, err := a.provider.Activate(r.Context(), request)
	if err != nil {
		code := http.StatusInternalServerError

		switch unwrap(err) {
		case storage.ErrIdentityNotFound,
			storage.ErrAddressNotFound,
			storage.ErrTokenNotFound:
			code = http.StatusNotFound
		case activation.ErrIdentityAlreadyActive:
			code = http.StatusConflict
		case activation.ErrInvalidRequest,
			activation.ErrTokenInvalid:
			code = http.StatusBadRequest
		}

		http.Error(w, http.StatusText(code), code)

		return
	}

	render.Status(r, http.StatusOK)
}
