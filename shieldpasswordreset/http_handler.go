package shieldpasswordreset

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.inout.gg/foundations/debug"
	"go.inout.gg/foundations/http/httperror"

	"go.inout.gg/shield"
	"go.inout.gg/shield/shieldpassword"
	"go.inout.gg/shield/shieldsender"
)

const (
	DefaultFieldEmail      = "email"
	DefaultFieldResetToken = "reset_token"
	DefaultFieldPassword   = "password"
)

// HTTPConfig is the configuration for form-based password reset.
type HTTPConfig struct {
	*Config

	FieldEmail      string
	FieldResetToken string
	FieldPassword   string
}

// HTTPHandler is a wrapper around Handler handling HTTP form requests.
type HTTPHandler struct {
	handler *Handler
	config  *HTTPConfig
	parser  HTTPRequestParser
}

// NewHTTPConfig creates a new FormConfig with the given configuration options.
func NewHTTPConfig(
	opts ...func(*HTTPConfig),
) *HTTPConfig {
	//nolint:exhaustruct
	cfg := &HTTPConfig{
		FieldEmail:      DefaultFieldEmail,
		FieldResetToken: DefaultFieldResetToken,
		FieldPassword:   DefaultFieldPassword,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// Set defaults.
	if cfg.Config == nil {
		cfg.Config = NewConfig()
	}

	debug.Assert(cfg.Config != nil, "Config must be set")

	return cfg
}

// WithConfig sets the configuration for the underlying Handler for FormHandler.
func WithConfig(config *Config) func(*HTTPConfig) {
	return func(cfg *HTTPConfig) { cfg.Config = config }
}

// If config is nil, it.
func newHTTPHandler(
	pool *pgxpool.Pool,
	sender shieldsender.Sender,
	parser HTTPRequestParser,
	config *HTTPConfig,
) *HTTPHandler {
	if config == nil {
		config = NewHTTPConfig()
	}

	config.assert()

	h := HTTPHandler{NewHandler(pool, sender, config.Config), config, parser}

	debug.Assert(h.config != nil, "config must be set")
	debug.Assert(h.handler != nil, "handler must be set")
	debug.Assert(h.parser != nil, "parser must be set")

	return &h
}

func NewFormHandler(
	pool *pgxpool.Pool,
	sender shieldsender.Sender,
	config *HTTPConfig,
) *HTTPHandler {
	return newHTTPHandler(pool, sender, &formParser{config}, config)
}

func NewJSONHandler(
	pool *pgxpool.Pool,
	sender shieldsender.Sender,
	config *HTTPConfig,
) *HTTPHandler {
	return newHTTPHandler(pool, sender, &jsonParser{config}, config)
}

func (h *HTTPHandler) parsePasswordResetRequest(
	r *http.Request,
) (*PasswordResetRequestData, error) {
	form, err := h.parser.ParsePasswordResetRequestData(r)
	if err != nil {
		return nil, fmt.Errorf("shield/passwordreset: failed to parse request form: %w", err)
	}

	if err := shieldpassword.FormModifier.Struct(r.Context(), form); err != nil {
		return nil, fmt.Errorf("shield/passwordreset: failed to parse request form: %w", err)
	}

	if err := shieldpassword.FormValidator.Struct(form); err != nil {
		return nil, fmt.Errorf("shield/passwordreset: failed to parse request form: %w", err)
	}

	return form, nil
}

// HandlePasswordReset handles a password reset request.
func (h *HTTPHandler) HandlePasswordReset(req *http.Request) error {
	ctx := req.Context()

	data, err := h.parsePasswordResetRequest(req)
	if err != nil {
		return httperror.FromError(err, http.StatusBadRequest)
	}

	if err := h.handler.HandlePasswordReset(ctx, data.Email); err != nil {
		if errors.Is(err, shield.ErrAuthenticatedUser) {
			return httperror.FromError(err, http.StatusForbidden)
		}

		return httperror.FromError(err, http.StatusInternalServerError)
	}

	return nil
}

func (h *HTTPHandler) parsePasswordResetConfirm(
	req *http.Request,
) (*PasswordResetConfirmData, error) {
	form, err := h.parser.ParsePasswordResetConfirmData(req)
	if err != nil {
		return nil, fmt.Errorf("shield/passwordreset: failed to parse request form: %w", err)
	}

	if err := shieldpassword.FormModifier.Struct(req.Context(), form); err != nil {
		return nil, fmt.Errorf("shield/passwordreset: failed to parse request form: %w", err)
	}

	if err := shieldpassword.FormValidator.Struct(form); err != nil {
		return nil, fmt.Errorf("shield/passwordreset: failed to parse request form: %w", err)
	}

	return form, nil
}

// HandlePasswordResetConfirm handles a password reset confirmation.
func (h *HTTPHandler) HandlePasswordResetConfirm(req *http.Request) error {
	ctx := req.Context()

	form, err := h.parsePasswordResetConfirm(req)
	if err != nil {
		return httperror.FromError(err, http.StatusBadRequest)
	}

	if err := h.handler.HandlePasswordResetConfirm(ctx, form.Password, form.ResetToken); err != nil {
		// Don't allow to change password for logged in users.
		if errors.Is(err, shield.ErrAuthenticatedUser) {
			return httperror.FromError(err, http.StatusForbidden)
		} else if errors.Is(err, ErrUsedPasswordResetToken) {
			return httperror.FromError(err, http.StatusBadRequest)
		}

		return httperror.FromError(err, http.StatusInternalServerError)
	}

	return nil
}
