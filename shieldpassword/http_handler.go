package shieldpassword

import (
	"cmp"
	"errors"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.inout.gg/foundations/debug"
	"go.inout.gg/foundations/http/httperror"

	"go.inout.gg/shield"
)

var (
	//nolint:gochecknoglobals
	FormValidator = shield.DefaultFormValidator

	//nolint:gochecknoglobals
	FormScrubber = shield.DefaultFormScrubber

	//nolint:gochecknoglobals
	FormModifier = shield.DefaultFormModifier
)

const (
	DefaultFieldFirstName = "first_name"
	DefaultFieldLastName  = "last_name"
	DefaultFieldEmail     = "email"
	DefaultFieldPassword  = "password"
)

type HTTPConfig[T any] struct {
	*Config[T]

	FieldFirstName string // optional (default: DefaultFieldFirstName)
	FieldLastName  string // optional (default: DefaultFieldLastName)
	FieldEmail     string // optional (default: DefaultFieldEmail)
	FieldPassword  string // optional (default: DefaultFieldPassword)
}

func (c *HTTPConfig[T]) defaults() {
	c.FieldFirstName = cmp.Or(c.FieldFirstName, DefaultFieldEmail)
	c.FieldLastName = cmp.Or(c.FieldLastName, DefaultFieldEmail)
	c.FieldEmail = cmp.Or(c.FieldEmail, DefaultFieldEmail)
	c.FieldPassword = cmp.Or(c.FieldPassword, DefaultFieldEmail)

	if c.Config == nil {
		c.Config = NewConfig[T]()
	}
}

func (c *HTTPConfig[T]) assert() {
	debug.Assert(c.Config != nil, "Config must be set")
}

// NewHTTPConfig[T] creates a new FormConfig[T] with the given configuration options.
func NewHTTPConfig[T any](opts ...func(*HTTPConfig[T])) *HTTPConfig[T] {
	var config HTTPConfig[T]
	for _, opt := range opts {
		opt(&config)
	}

	config.defaults()

	return &config
}

// HTTPHandler[T] is a wrapper around Handler handling HTTP form requests.
type HTTPHandler[T any] struct {
	handler *Handler[T]
	config  *HTTPConfig[T]
	parser  HTTPRequestParser
}

// newHTTPHandler[T] creates a new FormHandler[T] with the given configuration.
//
// If config is nil, the default config is used.
func newHTTPHandler[T any](pool *pgxpool.Pool, config *HTTPConfig[T], parser HTTPRequestParser) *HTTPHandler[T] {
	h := HTTPHandler[T]{
		NewHandler(pool, config.Config),
		config,
		parser,
	}

	debug.Assert(h.handler != nil, "handler must be set")
	debug.Assert(h.config != nil, "config must be set")
	debug.Assert(h.parser != nil, "parser must be set")

	return &h
}

// NewFormHandler creates a new HTTP handler that handles multipart form requests.
func NewFormHandler[T any](pool *pgxpool.Pool, config *HTTPConfig[T]) *HTTPHandler[T] {
	if config == nil {
		config = NewHTTPConfig[T]()
	}

	config.assert()

	return newHTTPHandler(pool, config, &formParser[T]{config})
}

// NewJSONHandler creates a new HTTP handler that handles JSON requests.
func NewJSONHandler[T any](pool *pgxpool.Pool, config *HTTPConfig[T]) *HTTPHandler[T] {
	if config == nil {
		config = NewHTTPConfig[T]()
	}

	config.assert()

	return newHTTPHandler(pool, config, &jsonParser[T]{config})
}

func (h *HTTPHandler[T]) parseUserRegistrationData(
	req *http.Request,
) (*UserRegistrationData, error) {
	ctx := req.Context()

	form, err := h.parser.ParseUserRegistrationData(req)
	if err != nil {
		return nil, fmt.Errorf("password: failed to parse request form: %w", err)
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
func (h *HTTPHandler[T]) HandleUserRegistration(r *http.Request) (*shield.User[T], error) {
	form, err := h.parseUserRegistrationData(r)
	if err != nil {
		return nil, httperror.FromError(err, http.StatusBadRequest)
	}

	result, err := h.handler.HandleUserRegistration(r.Context(), form.Email, form.Password)
	if err != nil {
		if errors.Is(err, shield.ErrAuthenticatedUser) {
			return nil, httperror.FromError(err, http.StatusForbidden)
		}

		if errors.Is(err, ErrEmailAlreadyTaken) {
			return nil, httperror.FromError(err, http.StatusConflict)
		}

		return nil, httperror.FromError(err, http.StatusInternalServerError)
	}

	return result, nil
}

func (h *HTTPHandler[T]) parseUserLoginData(req *http.Request) (*UserLoginData, error) {
	ctx := req.Context()

	form, err := h.parser.ParseUserLoginData(req)
	if err != nil {
		return nil, fmt.Errorf("password: failed to parse request form: %w", err)
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
func (h *HTTPHandler[T]) HandleUserLogin(r *http.Request) (*shield.User[T], error) {
	form, err := h.parseUserLoginData(r)
	if err != nil {
		return nil, httperror.FromError(err, http.StatusBadRequest)
	}

	result, err := h.handler.HandleUserLogin(r.Context(), form.Email, form.Password)
	if err != nil {
		if errors.Is(err, shield.ErrAuthenticatedUser) {
			return nil, httperror.FromError(err, http.StatusForbidden)
		} else if errors.Is(err, ErrPasswordIncorrect) ||
			errors.Is(err, shield.ErrUserNotFound) {
			return nil, httperror.FromError(err, http.StatusUnauthorized,
				"either email or password is incorrect")
		}

		return nil, httperror.FromError(err, http.StatusInternalServerError, "unexpected server error")
	}

	return result, nil
}
