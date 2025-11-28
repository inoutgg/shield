// Package shieldtelegram implements Telegram Bot Login authentication flow.
//
// Telegram Bot Login uses a widget-based authentication mechanism where users
// authorize via the Telegram app and authentication data is returned as URL
// hash parameters. This differs from standard OAuth2 flows.
//
// See: https://core.telegram.org/widgets/login
package shieldtelegram

import (
	"context"
	"errors"
	"time"

	"go.inout.gg/foundations/debug"
)

//nolint:gochecknoglobals
var d = debug.Debuglog("shieldtelegram")

var (
	// ErrInvalidHash is returned when the authentication hash verification fails.
	ErrInvalidHash = errors.New("shieldtelegram: invalid authentication hash")

	// ErrAuthExpired is returned when the authentication data is too old.
	ErrAuthExpired = errors.New("shieldtelegram: authentication data expired")

	// ErrMissingAuthData is returned when required authentication data is missing.
	ErrMissingAuthData = errors.New("shieldtelegram: missing required authentication data")
)

// AuthData represents the authentication data received from Telegram.
//
// This data is passed as URL hash parameters after successful authentication
// via the Telegram Login Widget.
type AuthData struct {
	// ID is the unique Telegram user identifier.
	ID int64 `json:"id"`

	// FirstName is the user's first name.
	FirstName string `json:"first_name"`

	// LastName is the user's last name (optional).
	LastName string `json:"last_name,omitempty"`

	// Username is the user's Telegram username (optional).
	Username string `json:"username,omitempty"`

	// PhotoURL is the URL to the user's profile photo (optional).
	PhotoURL string `json:"photo_url,omitempty"`

	// AuthDate is the Unix timestamp when the authentication occurred.
	AuthDate int64 `json:"auth_date"`

	// Hash is the HMAC-SHA256 signature of the data using the bot token.
	Hash string `json:"hash"`
}

// UserInfo contains the validated user information after successful authentication.
type UserInfo struct {
	ID        int64
	FirstName string
	LastName  string
	Username  string
	PhotoURL  string
	AuthDate  time.Time
}

// Config holds the configuration for Telegram Bot Login.
type Config struct {
	// BotToken is the bot token obtained from BotFather.
	BotToken string

	// BotUsername is the bot's username (without @) for the login widget.
	// This is required for generating the Telegram Login Widget.
	BotUsername string

	// MaxAuthAge is the maximum age of authentication data to accept.
	// If zero, a default of 24 hours is used.
	MaxAuthAge time.Duration
}

// Provider handles Telegram Bot Login authentication.
type Provider interface {
	// Verify validates the authentication data and returns user information.
	Verify(ctx context.Context, data *AuthData) (*UserInfo, error)

	// GenerateWidget returns HTML/JavaScript code for the Telegram Login Widget.
	GenerateWidget(redirectURL string, opts *WidgetOptions) string
}

// WidgetOptions contains options for customizing the Telegram Login Widget.
type WidgetOptions struct {
	// Size of the widget button: "large", "medium", or "small".
	Size string

	// RequestAccess requests permission to message the user.
	RequestAccess bool

	// Radius sets the border radius of the button (0-20).
	Radius *int

	// UsePic displays the user's photo in the button.
	UsePic bool

	// Lang sets the widget language (default: "en").
	Lang string
}
