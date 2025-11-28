package shieldtelegram

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func TestVerify_ValidData(t *testing.T) {
	botToken := "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	provider := NewProvider(&Config{
		BotToken:    botToken,
		BotUsername: "test_bot",
		MaxAuthAge:  24 * time.Hour,
	})

	// Create valid auth data with a proper hash
	authDate := time.Now().Unix()
	authData := &AuthData{
		ID:        123456789,
		FirstName: "John",
		LastName:  "Doe",
		Username:  "johndoe",
		AuthDate:  authDate,
	}

	// Calculate the correct hash
	authData.Hash = calculateHash(botToken, authData)

	// Verify the data
	userInfo, err := provider.Verify(context.Background(), authData)
	if err != nil {
		t.Fatalf("Expected valid auth data to verify, got error: %v", err)
	}

	if userInfo.ID != authData.ID {
		t.Errorf("Expected ID %d, got %d", authData.ID, userInfo.ID)
	}

	if userInfo.FirstName != authData.FirstName {
		t.Errorf("Expected FirstName %s, got %s", authData.FirstName, userInfo.FirstName)
	}
}

func TestVerify_InvalidHash(t *testing.T) {
	provider := NewProvider(&Config{
		BotToken:    "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		BotUsername: "test_bot",
		MaxAuthAge:  24 * time.Hour,
	})

	authData := &AuthData{
		ID:        123456789,
		FirstName: "John",
		AuthDate:  time.Now().Unix(),
		Hash:      "invalid_hash",
	}

	_, err := provider.Verify(context.Background(), authData)
	if err != ErrInvalidHash {
		t.Errorf("Expected ErrInvalidHash, got %v", err)
	}
}

func TestVerify_ExpiredAuth(t *testing.T) {
	provider := NewProvider(&Config{
		BotToken:    "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		BotUsername: "test_bot",
		MaxAuthAge:  1 * time.Hour,
	})

	// Create auth data from 2 hours ago
	authDate := time.Now().Add(-2 * time.Hour).Unix()
	authData := &AuthData{
		ID:        123456789,
		FirstName: "John",
		AuthDate:  authDate,
		Hash:      "some_hash",
	}

	_, err := provider.Verify(context.Background(), authData)
	if err != ErrAuthExpired {
		t.Errorf("Expected ErrAuthExpired, got %v", err)
	}
}

func TestVerify_MissingData(t *testing.T) {
	provider := NewProvider(&Config{
		BotToken:    "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		BotUsername: "test_bot",
	})

	tests := []struct {
		name string
		data *AuthData
	}{
		{
			name: "nil data",
			data: nil,
		},
		{
			name: "missing ID",
			data: &AuthData{
				FirstName: "John",
				AuthDate:  time.Now().Unix(),
				Hash:      "hash",
			},
		},
		{
			name: "missing auth_date",
			data: &AuthData{
				ID:        123456789,
				FirstName: "John",
				Hash:      "hash",
			},
		},
		{
			name: "missing hash",
			data: &AuthData{
				ID:        123456789,
				FirstName: "John",
				AuthDate:  time.Now().Unix(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := provider.Verify(context.Background(), tt.data)
			if err != ErrMissingAuthData {
				t.Errorf("Expected ErrMissingAuthData, got %v", err)
			}
		})
	}
}

func TestBuildDataCheckString(t *testing.T) {
	p := &provider{}

	authData := &AuthData{
		ID:        123456789,
		FirstName: "John",
		LastName:  "Doe",
		Username:  "johndoe",
		PhotoURL:  "https://example.com/photo.jpg",
		AuthDate:  1234567890,
	}

	dataCheckString := p.buildDataCheckString(authData)

	// The string should be sorted alphabetically
	expected := "auth_date=1234567890\nfirst_name=John\nid=123456789\nlast_name=Doe\nphoto_url=https://example.com/photo.jpg\nusername=johndoe"

	if dataCheckString != expected {
		t.Errorf("Expected:\n%s\n\nGot:\n%s", expected, dataCheckString)
	}
}

// Helper function to calculate a valid hash for testing
func calculateHash(botToken string, data *AuthData) string {
	p := &provider{botToken: botToken}
	dataCheckString := p.buildDataCheckString(data)
	secretKey := sha256.Sum256([]byte(botToken))
	h := hmac.New(sha256.New, secretKey[:])
	h.Write([]byte(dataCheckString))
	return hex.EncodeToString(h.Sum(nil))
}
