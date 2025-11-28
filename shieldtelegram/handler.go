package shieldtelegram

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// HandleCallback processes the Telegram login callback.
//
// Telegram sends authentication data as URL hash parameters (client-side).
// This means the data needs to be extracted via JavaScript and sent to the server.
// This handler expects the data to be submitted as either:
// - URL query parameters (if forwarded from client-side)
// - JSON in the request body
func HandleCallback(
	ctx context.Context,
	r *http.Request,
	provider Provider,
) (*UserInfo, error) {
	authData, err := parseAuthData(r)
	if err != nil {
		return nil, fmt.Errorf("shieldtelegram: failed to parse auth data: %w", err)
	}

	userInfo, err := provider.Verify(ctx, authData)
	if err != nil {
		return nil, fmt.Errorf("shieldtelegram: verification failed: %w", err)
	}

	return userInfo, nil
}

// parseAuthData extracts authentication data from the HTTP request.
//
// It tries to parse data from:
// 1. URL query parameters (GET request)
// 2. Form data (POST request)
// 3. JSON body (POST request)
func parseAuthData(r *http.Request) (*AuthData, error) {
	var values url.Values

	// Try to get data from URL query parameters first
	if r.URL.Query().Get("id") != "" {
		values = r.URL.Query()
	} else if r.Method == http.MethodPost {
		// Try to parse as JSON
		if r.Header.Get("Content-Type") == "application/json" {
			var authData AuthData
			if err := json.NewDecoder(r.Body).Decode(&authData); err != nil {
				return nil, fmt.Errorf("failed to decode JSON: %w", err)
			}
			return &authData, nil
		}

		// Try to parse as form data
		if err := r.ParseForm(); err == nil && r.Form.Get("id") != "" {
			values = r.Form
		}
	}

	if values == nil {
		return nil, ErrMissingAuthData
	}

	return parseValuesIntoAuthData(values)
}

// parseValuesIntoAuthData converts url.Values into AuthData struct.
func parseValuesIntoAuthData(values url.Values) (*AuthData, error) {
	idStr := values.Get("id")
	if idStr == "" {
		return nil, ErrMissingAuthData
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	authDateStr := values.Get("auth_date")
	if authDateStr == "" {
		return nil, ErrMissingAuthData
	}

	authDate, err := strconv.ParseInt(authDateStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid auth_date: %w", err)
	}

	hash := values.Get("hash")
	if hash == "" {
		return nil, ErrMissingAuthData
	}

	return &AuthData{
		ID:        id,
		FirstName: values.Get("first_name"),
		LastName:  values.Get("last_name"),
		Username:  values.Get("username"),
		PhotoURL:  values.Get("photo_url"),
		AuthDate:  authDate,
		Hash:      hash,
	}, nil
}
