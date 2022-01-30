package service

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/mpraski/identity-manager/app/authentication"
)

type (
	Authentication struct {
		password authentication.Provider
	}

	passwordRequest struct {
		Email    string `validate:"required,email" json:"email"`
		Password string `validate:"required" json:"password"`
	}
)

func NewAuthentication(password authentication.Provider) *Authentication {
	return &Authentication{password: password}
}

func (a *Authentication) Router() *chi.Mux {
	r := chi.NewRouter()

	r.Post("/password", a.authenticateWithPassword)

	return r
}

func (a *Authentication) authenticateWithPassword(w http.ResponseWriter, r *http.Request) {
	var body passwordRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if err := validate.StructCtx(r.Context(), body); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	challenge := authentication.PasswordChallenge{
		Email:    strings.TrimSpace(strings.ToLower(body.Email)),
		Password: strings.TrimSpace(body.Password),
	}

	i, err := a.password.Authenticate(r.Context(), &challenge)
	if err != nil {
		switch unwrap(err) {
		case authentication.ErrPasswordChallengeMissing,
			authentication.ErrPasswordChallengeInvalid:
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		case authentication.ErrPasswordAuthenticationFailed:
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		default:
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}

		return
	}

	render.JSON(w, r, i)
}
