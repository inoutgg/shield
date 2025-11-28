# shieldtelegram

Telegram Bot Login authentication for Shield framework.

## Overview

`shieldtelegram` implements Telegram's Bot Login (Login with Telegram) authentication flow. Unlike standard OAuth2 flows, Telegram uses a widget-based approach where authentication data is returned as URL hash parameters and verified using HMAC-SHA256.

## Features

- ✅ HMAC-SHA256 signature verification
- ✅ Telegram Login Widget generation
- ✅ HTTP handler for processing callbacks
- ✅ Configurable authentication data age validation
- ✅ Multiple input formats (query params, form data, JSON)

## Installation

```bash
go get go.inout.gg/shield/shieldtelegram
```

## Quick Start

### 1. Create a Telegram Bot

First, create a bot with [@BotFather](https://t.me/botfather) on Telegram and obtain:
- Bot token (e.g., `123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ`)
- Bot username (e.g., `my_auth_bot`)

### 2. Set up the Provider

```go
import "go.inout.gg/shield/shieldtelegram"

provider := shieldtelegram.NewProvider(&shieldtelegram.Config{
    BotToken:    "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    BotUsername: "my_auth_bot",
    MaxAuthAge:  24 * time.Hour, // Optional, defaults to 24h
})
```

### 3. Generate the Login Widget

```go
http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
    radius := 10
    widget := provider.GenerateWidget(
        "https://yoursite.com/auth/telegram/callback",
        &shieldtelegram.WidgetOptions{
            Size:          "large",
            RequestAccess: true,
            Radius:        &radius,
            UsePic:        true,
            Lang:          "en",
        },
    )

    // Render the widget in your HTML
    fmt.Fprintf(w, `
        <html>
        <body>
            <h1>Login with Telegram</h1>
            %s
            %s
        </body>
        </html>
    `, widget, shieldtelegram.GenerateWidgetCallback("/api/auth/telegram"))
})
```

### 4. Handle the Callback

```go
http.HandleFunc("/api/auth/telegram", func(w http.ResponseWriter, r *http.Request) {
    userInfo, err := shieldtelegram.HandleCallback(r.Context(), r, provider)
    if err != nil {
        http.Error(w, err.Error(), http.StatusUnauthorized)
        return
    }

    // userInfo contains validated user data:
    // - userInfo.ID (Telegram user ID)
    // - userInfo.FirstName
    // - userInfo.LastName
    // - userInfo.Username
    // - userInfo.PhotoURL
    // - userInfo.AuthDate

    // Create session, set cookies, etc.
    // ...
})
```

## How It Works

### Authentication Flow

1. User clicks the Telegram Login Widget on your website
2. User is redirected to Telegram (app or web)
3. User authorizes your bot
4. Telegram redirects back with authentication data in URL hash
5. JavaScript extracts the data and sends it to your server
6. Server validates the HMAC-SHA256 signature
7. Server creates a session for the authenticated user

### Security

The package implements Telegram's security specification:

1. **Data Integrity**: All authentication data is signed with HMAC-SHA256 using your bot token
2. **Freshness**: Authentication data age is validated (configurable, default 24 hours)
3. **Authenticity**: The hash is verified against the data-check-string

The verification process:
```
data-check-string = "auth_date=<timestamp>\nfirst_name=<name>\n..."
secret_key = SHA256(bot_token)
hash = HMAC-SHA256(data-check-string, secret_key)
```

## API Reference

### Types

#### `Config`
```go
type Config struct {
    BotToken    string        // Bot token from BotFather
    BotUsername string        // Bot username (without @)
    MaxAuthAge  time.Duration // Max age of auth data (default: 24h)
}
```

#### `AuthData`
```go
type AuthData struct {
    ID        int64  // Telegram user ID
    FirstName string // User's first name
    LastName  string // User's last name (optional)
    Username  string // User's username (optional)
    PhotoURL  string // Profile photo URL (optional)
    AuthDate  int64  // Unix timestamp
    Hash      string // HMAC-SHA256 signature
}
```

#### `UserInfo`
```go
type UserInfo struct {
    ID        int64
    FirstName string
    LastName  string
    Username  string
    PhotoURL  string
    AuthDate  time.Time
}
```

#### `WidgetOptions`
```go
type WidgetOptions struct {
    Size          string // "large", "medium", or "small"
    RequestAccess bool   // Request permission to message user
    Radius        *int   // Border radius (0-20)
    UsePic        bool   // Show user photo in button
    Lang          string // Widget language (default: "en")
}
```

### Functions

#### `NewProvider(cfg *Config) Provider`
Creates a new Telegram Login provider.

#### `HandleCallback(ctx context.Context, r *http.Request, provider Provider) (*UserInfo, error)`
Processes the Telegram login callback and returns validated user information.

#### `GenerateWidgetCallback(serverCallbackURL string) string`
Generates JavaScript code to extract auth data from URL hash and send it to your server.

### Provider Interface

```go
type Provider interface {
    Verify(ctx context.Context, data *AuthData) (*UserInfo, error)
    GenerateWidget(redirectURL string, opts *WidgetOptions) string
}
```

## Error Handling

The package defines the following errors:

- `ErrInvalidHash`: Authentication hash verification failed
- `ErrAuthExpired`: Authentication data is too old
- `ErrMissingAuthData`: Required authentication data is missing

## Integration with Shield

This package follows Shield's modular architecture and can be integrated alongside other authentication methods:

```go
// Combine with password authentication
passwordProvider := shieldpassword.NewProvider(...)
telegramProvider := shieldtelegram.NewProvider(...)

// Use both in your auth flow
```

## Testing

Run tests:
```bash
go test ./shieldtelegram/...
```

## References

- [Telegram Login Widget Documentation](https://core.telegram.org/widgets/login)
- [Telegram Bot API](https://core.telegram.org/bots/api)

## License

MIT License (same as Shield framework)
