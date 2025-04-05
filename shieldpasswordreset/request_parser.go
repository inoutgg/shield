package shieldpasswordreset

import (
	"encoding/json"
	"fmt"
	"net/http"
)

var (
	_ HTTPRequestParser = (*jsonParser)(nil)
	_ HTTPRequestParser = (*formParser)(nil)
)

// HTTPRequestParser parses HTTP requests to grab password reset data.
type HTTPRequestParser interface {
	ParsePasswordResetRequestData(r *http.Request) (*PasswordResetRequestData, error)
	ParsePasswordResetConfirmData(r *http.Request) (*PasswordResetConfirmData, error)
}

// PasswordResetRequestData is the form used to request a password reset.
type PasswordResetRequestData struct {
	Email string `mod:"trim" scrub:"emails" validate:"required,email"`
}

// PasswordResetConfirmData is the form used to confirm a password reset.
type PasswordResetConfirmData struct {
	Password   string `mod:"trim" validate:"required"`
	ResetToken string `mod:"trim" validate:"required"`
}

type jsonParser struct {
	config *HTTPConfig
}

func (p *jsonParser) ParsePasswordResetRequestData(r *http.Request) (*PasswordResetRequestData, error) {
	var m map[string]string
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		return nil, fmt.Errorf("shieldpasswordreset: failed to parse JSON data: %w", err)
	}

	return &PasswordResetRequestData{
		Email: m[p.config.FieldEmail],
	}, nil
}

func (p *jsonParser) ParsePasswordResetConfirmData(r *http.Request) (*PasswordResetConfirmData, error) {
	var m map[string]string
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		return nil, fmt.Errorf("shieldpasswordreset: failed to parse JSON data: %w", err)
	}

	return &PasswordResetConfirmData{
		Password:   m[p.config.FieldPassword],
		ResetToken: m[p.config.FieldResetToken],
	}, nil
}

type formParser struct {
	config *HTTPConfig
}

func (p *formParser) ParsePasswordResetRequestData(r *http.Request) (*PasswordResetRequestData, error) {
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("shieldpasswordreset: failed to parse form data: %w", err)
	}

	return &PasswordResetRequestData{
		Email: r.PostFormValue(p.config.FieldEmail),
	}, nil
}

func (p *formParser) ParsePasswordResetConfirmData(r *http.Request) (*PasswordResetConfirmData, error) {
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("shieldpasswordreset: failed to parse form data: %w", err)
	}

	return &PasswordResetConfirmData{
		Password:   r.PostFormValue(p.config.FieldPassword),
		ResetToken: r.FormValue(p.config.FieldResetToken),
	}, nil
}
