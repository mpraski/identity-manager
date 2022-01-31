package service

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/mpraski/identity-manager/app/registration"
)

type (
	Registration struct {
		password registration.Provider
	}

	registrationRequest struct {
		FirstName string `validate:"required" json:"first_name"`
		LastName  string `validate:"required" json:"last_name"`
		Email     string `validate:"required,email" json:"email"`
		Password  string `validate:"required" json:"password"`
	}
)

func NewRegistration(password registration.Provider) *Registration {
	return &Registration{password: password}
}

func (e *Registration) Router() *chi.Mux {
	r := chi.NewRouter()

	r.Post("/password", e.registerWithPassword)
	r.Get("/password/activate", e.activateWithPassword)

	return r
}

func (e *Registration) registerWithPassword(w http.ResponseWriter, r *http.Request) {
	var body registrationRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if err := validate.StructCtx(r.Context(), body); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	request := registration.PasswordRequest{
		FirstName: strings.TrimSpace(body.FirstName),
		LastName:  strings.TrimSpace(body.LastName),
		Email:     strings.TrimSpace(strings.ToLower(body.Email)),
		Password:  strings.TrimSpace(body.Password),
	}

	i, err := e.password.Register(r.Context(), &request)
	if err != nil {
		code := http.StatusInternalServerError

		switch unwrap(err) {
		case registration.ErrIdentityExists:
			code = http.StatusConflict
		case registration.ErrInvalidRequest:
			code = http.StatusBadRequest
		}

		http.Error(w, http.StatusText(code), code)

		return
	}

	render.Status(r, http.StatusCreated)
	render.JSON(w, r, i)
}

func (e *Registration) activateWithPassword(w http.ResponseWriter, r *http.Request) {
}
