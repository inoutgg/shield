package shieldtelegram

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

var _ Provider = (*provider)(nil)

type provider struct {
	botToken    string
	botUsername string
	maxAuthAge  time.Duration
}

// NewProvider creates a new Telegram Login provider.
func NewProvider(cfg *Config) Provider {
	maxAuthAge := cfg.MaxAuthAge
	if maxAuthAge == 0 {
		maxAuthAge = 24 * time.Hour
	}

	return &provider{
		botToken:    cfg.BotToken,
		botUsername: cfg.BotUsername,
		maxAuthAge:  maxAuthAge,
	}
}

// Verify validates the Telegram authentication data using HMAC-SHA256.
//
// The verification process follows Telegram's specification:
// 1. Create a data-check-string by concatenating key=value pairs (excluding hash)
// 2. Calculate SHA256 hash of the bot token
// 3. Calculate HMAC-SHA256 of the data-check-string using the token hash as key
// 4. Compare the resulting hash with the provided hash
//
// See: https://core.telegram.org/widgets/login#checking-authorization
func (p *provider) Verify(ctx context.Context, data *AuthData) (*UserInfo, error) {
	if data == nil {
		return nil, ErrMissingAuthData
	}

	if data.ID == 0 || data.AuthDate == 0 || data.Hash == "" {
		return nil, ErrMissingAuthData
	}

	// Check if the authentication data is not too old
	authTime := time.Unix(data.AuthDate, 0)
	if time.Since(authTime) > p.maxAuthAge {
		return nil, ErrAuthExpired
	}

	// Verify the hash
	if !p.verifyHash(data) {
		return nil, ErrInvalidHash
	}

	// Return validated user info
	return &UserInfo{
		ID:        data.ID,
		FirstName: data.FirstName,
		LastName:  data.LastName,
		Username:  data.Username,
		PhotoURL:  data.PhotoURL,
		AuthDate:  authTime,
	}, nil
}

// verifyHash validates the HMAC-SHA256 signature of the authentication data.
func (p *provider) verifyHash(data *AuthData) bool {
	// Build the data-check-string from all fields except hash
	dataCheckString := p.buildDataCheckString(data)

	// Calculate the secret key: SHA256 hash of the bot token
	secretKey := sha256.Sum256([]byte(p.botToken))

	// Calculate HMAC-SHA256 of the data-check-string
	h := hmac.New(sha256.New, secretKey[:])
	h.Write([]byte(dataCheckString))
	calculatedHash := hex.EncodeToString(h.Sum(nil))

	// Compare with the provided hash
	return hmac.Equal([]byte(calculatedHash), []byte(data.Hash))
}

// buildDataCheckString creates the data-check-string from authentication data.
//
// The string is built by:
// 1. Creating key=value pairs for all non-empty fields (excluding hash)
// 2. Sorting the pairs alphabetically by key
// 3. Joining them with newline characters
func (p *provider) buildDataCheckString(data *AuthData) string {
	var pairs []string

	// Add all non-empty fields
	if data.ID != 0 {
		pairs = append(pairs, fmt.Sprintf("id=%d", data.ID))
	}

	if data.FirstName != "" {
		pairs = append(pairs, fmt.Sprintf("first_name=%s", data.FirstName))
	}

	if data.LastName != "" {
		pairs = append(pairs, fmt.Sprintf("last_name=%s", data.LastName))
	}

	if data.Username != "" {
		pairs = append(pairs, fmt.Sprintf("username=%s", data.Username))
	}

	if data.PhotoURL != "" {
		pairs = append(pairs, fmt.Sprintf("photo_url=%s", data.PhotoURL))
	}

	if data.AuthDate != 0 {
		pairs = append(pairs, fmt.Sprintf("auth_date=%s", strconv.FormatInt(data.AuthDate, 10)))
	}

	// Sort alphabetically
	sort.Strings(pairs)

	// Join with newlines
	return strings.Join(pairs, "\n")
}
