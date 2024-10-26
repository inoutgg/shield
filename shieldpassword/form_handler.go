package shieldpassword

import (
	"cmp"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-playground/mold/v4/modifiers"
	"github.com/go-playground/mold/v4/scrubbers"
	"github.com/go-playground/validator/v10"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.inout.gg/foundations/debug"
	"go.inout.gg/foundations/http/httperror"
	"go.inout.gg/shield"
)

var (
	FormValidator = validator.New(validator.WithRequiredStructEnabled())
	FormScrubber  = scrubbers.New()
	FormModifier  = modifiers.New()
)

const (
	DefaultFieldNameFirstName = "first_name"
	DefaultFieldNameLastName  = "last_name"
	DefaultFieldNameEmail     = "email"
	DefaultFieldNamePassword  = "password"
)

type FormConfig[T any] struct {
	*Config[T]

	FirstNameFieldName string // optional (default: DefaultFieldNameFirstName)
	LastNameFieldName  string // optional (default: DefaultFieldNameLastName)
	EmailFieldName     string // optional (default: DefaultFieldNameEmail)
	PasswordFieldName  string // optional (default: DefaultFieldNamePassword)
}

func (c *FormConfig[T]) defaults() {
	c.FirstNameFieldName = cmp.Or(c.FirstNameFieldName, DefaultFieldNameEmail)
	c.LastNameFieldName = cmp.Or(c.LastNameFieldName, DefaultFieldNameEmail)
	c.EmailFieldName = cmp.Or(c.EmailFieldName, DefaultFieldNameEmail)
	c.PasswordFieldName = cmp.Or(c.PasswordFieldName, DefaultFieldNameEmail)
	if c.Config == nil {
		c.Config = NewConfig[T]()
	}
}

func (c *FormConfig[T]) assert() {
	debug.Assert(c.Config != nil, "Config must be set")
}

// NewFormConfig[T] creates a new FormConfig[T] with the given configuration options.
func NewFormConfig[T any](opts ...func(*FormConfig[T])) *FormConfig[T] {
	var config FormConfig[T]
	for _, opt := range opts {
		opt(&config)
	}

	config.defaults()

	return &config
}

// FormHandler[T] is a wrapper around Handler handling HTTP form requests.
type FormHandler[T any] struct {
	handler *Handler[T]
	config  *FormConfig[T]
}

// NewFormHandler[T] creates a new FormHandler[T] with the given configuration.
//
// If config is nil, the default config is used.
func NewFormHandler[T any](pool *pgxpool.Pool, config *FormConfig[T]) *FormHandler[T] {
	if config == nil {
		config = NewFormConfig[T]()
	}
	config.assert()

	h := FormHandler[T]{
		NewHandler(pool, config.Config),
		config,
	}
	h.assert()

	return &h
}

func (h *FormHandler[T]) assert() {
	debug.Assert(h.handler != nil, "handler must be set")
}

// userRegistrationForm is the form for user login.
type userRegistrationForm struct {
	FirstName string `mod:"trim"`
	LastName  string `mod:"trim"`
	Email     string `mod:"trim" validate:"required,email" scrub:"emails"`
	Password  string `mod:"trim" validate:"required"`
}

// userLoginForm is the form for user login.
type userLoginForm struct {
	Email    string `mod:"trim" validate:"required,email" scrub:"emails"`
	Password string `mod:"trim" validate:"required"`
}

func (h *FormHandler[T]) parseUserRegistrationForm(
	req *http.Request,
) (*userRegistrationForm, error) {
	ctx := req.Context()

	if err := req.ParseForm(); err != nil {
		return nil, fmt.Errorf("password: failed to parse request form: %w", err)
	}

	form := &userRegistrationForm{
		FirstName: req.PostFormValue(h.config.FirstNameFieldName),
		LastName:  req.PostFormValue(h.config.LastNameFieldName),
		Email:     req.PostFormValue(h.config.EmailFieldName),
		Password:  req.PostFormValue(h.config.PasswordFieldName),
	}

	if err := FormModifier.Struct(ctx, form); err != nil {
		return nil, fmt.Errorf("password: failed to parse request form: %w", err)
	}

	if err := FormValidator.Struct(form); err != nil {
		return nil, fmt.Errorf("password: failed to parse request form: %w", err)
	}

	return form, nil
}

// HandleUserRegistration handles a user registration request.
func (h *FormHandler[T]) HandleUserRegistration(r *http.Request) (*shield.User[T], error) {
	form, err := h.parseUserRegistrationForm(r)
	if err != nil {
		return nil, httperror.FromError(err, http.StatusBadRequest)
	}

	result, err := h.handler.HandleUserRegistration(r.Context(), form.Email, form.Password)
	if err != nil {
		if errors.Is(err, shield.ErrAuthenticatedUser) {
			return nil, httperror.FromError(err, http.StatusForbidden)
		}

		return nil, httperror.FromError(err, http.StatusInternalServerError)
	}

	return result, nil
}

func (h *FormHandler[T]) parseUserLoginForm(req *http.Request) (*userLoginForm, error) {
	ctx := req.Context()

	if err := req.ParseForm(); err != nil {
		return nil, fmt.Errorf("password: failed to parse request form: %w", err)
	}

	form := &userLoginForm{
		Email:    req.PostFormValue(h.config.EmailFieldName),
		Password: req.PostFormValue(h.config.PasswordFieldName),
	}

	if err := FormModifier.Struct(ctx, form); err != nil {
		return nil, fmt.Errorf("password: failed to parse request form: %w", err)
	}

	if err := FormValidator.Struct(form); err != nil {
		return nil, fmt.Errorf("password: failed to parse request form: %w", err)
	}

	return form, nil
}

// HandleUserLogin handles a user login request.
func (h *FormHandler[T]) HandleUserLogin(r *http.Request) (*shield.User[T], error) {
	form, err := h.parseUserLoginForm(r)
	if err != nil {
		return nil, httperror.FromError(err, http.StatusBadRequest)
	}

	result, err := h.handler.HandleUserLogin(r.Context(), form.Email, form.Password)
	if err != nil {
		if errors.Is(err, shield.ErrAuthenticatedUser) {
			return nil, httperror.FromError(err, http.StatusForbidden)
		} else if errors.Is(err, ErrPasswordIncorrect) || errors.Is(err, shield.ErrUserNotFound) {
			return nil, httperror.FromError(err, http.StatusUnauthorized, "either email or password is incorrect")
		}

		return nil, httperror.FromError(err, http.StatusInternalServerError)
	}

	return result, nil
}
