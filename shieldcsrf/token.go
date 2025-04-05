package shieldcsrf

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"go.inout.gg/foundations/must"

	"go.inout.gg/shield/internal/random"
)

var (
	ErrInvalidToken  = errors.New("shield/csrf: invalid token")
	ErrTokenMismatch = errors.New("shield/csrf: token mismatch")
	ErrTokenNotFound = errors.New("shield/csrf: token not found")
)

type tokenConfig struct {
	ChecksumSecret string
	HeaderName     string
	FieldName      string
	CookieName     string
	TokenLength    int
	CookieSameSite http.SameSite
	CookieSecure   bool
}

func (opt *tokenConfig) cookieName() string {
	name := opt.CookieName
	if opt.CookieSecure {
		name = "__Secure-" + name
	}

	return name
}

// Token implements CSRF token using the double submit cookie pattern.
type Token struct {
	config   *tokenConfig
	value    string
	checksum string
}

// newToken returns a new CSRF token.
// An error is returned if the token cannot be generated.
func newToken(opt *tokenConfig) (*Token, error) {
	val, err := random.SecureHexString(opt.TokenLength)
	if err != nil {
		return nil, fmt.Errorf("shieldcsrf: failed to create CSRF token: %w", err)
	}

	checksum := computeChecksum(val, opt.ChecksumSecret)

	return &Token{
		value:    val,
		checksum: checksum,
		config:   opt,
	}, nil
}

// fromRequest returns a CSRF token from an HTTP request by reading a cookie.
func fromRequest(r *http.Request, opt *tokenConfig) (*Token, error) {
	cookie, err := r.Cookie(opt.cookieName())
	if err != nil {
		return nil, fmt.Errorf("shield/csrf: unable to retrieve cookie: %w", err)
	}

	value, checksum, err := decodeCookieValue(cookie.Value)
	if err != nil {
		return nil, err
	}

	tok := &Token{
		value:    value,
		checksum: checksum,
		config:   opt,
	}

	if !tok.validateChecksum() {
		return nil, ErrInvalidToken
	}

	return tok, nil
}

// validateRequest returns true if the HTTP request contains a valid CSRF token.
func validateRequest(r *http.Request, opt *tokenConfig) error {
	tok, err := fromRequest(r, opt)
	if err != nil {
		return err
	}

	return tok.validateRequest(r)
}

func (t *Token) validateChecksum() bool {
	expectedChecksum := computeChecksum(t.value, t.config.ChecksumSecret)
	return t.checksum == expectedChecksum
}

func (t *Token) validateRequest(r *http.Request) error {
	opt := t.config

	// Get the CSRF token from the header or the form field.
	tokValue := r.Header.Get(opt.HeaderName)
	if tokValue == "" {
		tokValue = r.PostFormValue(opt.FieldName)
	}

	// If the token is missing, try to get it from the multipart form.
	if tokValue == "" && r.MultipartForm != nil {
		vals := r.MultipartForm.Value[opt.FieldName]
		if len(vals) > 0 {
			tokValue = vals[0]
		}
	}

	if subtle.ConstantTimeCompare([]byte(t.value), []byte(tokValue)) != 1 {
		return ErrTokenMismatch
	}

	return nil
}

// String returns the CSRF token value.
func (t *Token) String() string {
	return t.value
}

// cookie returns an HTTP cookie containing the CSRF token.
func (t *Token) cookie() *http.Cookie {
	//nolint:exhaustruct
	cookie := http.Cookie{
		Name:     t.config.cookieName(),
		Value:    t.cookieValue(),
		HttpOnly: true,
		Secure:   t.config.CookieSecure,
		SameSite: t.config.CookieSameSite,
	}

	return &cookie
}

func (t *Token) cookieValue() string {
	content := []byte(fmt.Sprintf("%s|%s", t.value, t.checksum))
	return base64.URLEncoding.EncodeToString(content)
}

func decodeCookieValue(val string) (string, string, error) {
	bytes, err := base64.URLEncoding.DecodeString(val)
	if err != nil {
		return "", "", ErrInvalidToken
	}

	content := string(bytes)

	parts := strings.Split(content, "|")
	if len(parts) != 2 {
		return "", "", ErrInvalidToken
	}

	return parts[0], parts[1], nil
}

// computeChecksum return the sha256 checksum of the given value with secret.
func computeChecksum(val, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	_ = must.Must(h.Write([]byte(val)))

	return hex.EncodeToString(h.Sum(nil))
}
