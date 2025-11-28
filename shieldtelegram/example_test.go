package shieldtelegram_test

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.inout.gg/shield/shieldtelegram"
)

// Example of setting up a Telegram login provider.
func ExampleNewProvider() {
	provider := shieldtelegram.NewProvider(&shieldtelegram.Config{
		BotToken:   "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
		MaxAuthAge: 24 * time.Hour,
	})

	fmt.Printf("Provider created: %T\n", provider)
	// Output: Provider created: *shieldtelegram.provider
}

// Example of handling a Telegram login callback.
func ExampleHandleCallback() {
	provider := shieldtelegram.NewProvider(&shieldtelegram.Config{
		BotToken: "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
	})

	// Simulate an HTTP request with Telegram auth data
	req, _ := http.NewRequest("GET", "/auth/telegram/callback?id=123456789&first_name=John&auth_date=1234567890&hash=abc123", nil)

	userInfo, err := shieldtelegram.HandleCallback(context.Background(), req, provider)
	if err != nil {
		fmt.Printf("Authentication failed: %v\n", err)
		return
	}

	fmt.Printf("User ID: %d, Name: %s\n", userInfo.ID, userInfo.FirstName)
}

// Example of generating a Telegram login widget.
func ExampleProvider_GenerateWidget() {
	provider := shieldtelegram.NewProvider(&shieldtelegram.Config{
		BotToken: "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
	})

	// Generate widget with custom options
	radius := 10
	widget := provider.GenerateWidget(
		"https://example.com/auth/telegram/callback",
		&shieldtelegram.WidgetOptions{
			Size:          "large",
			RequestAccess: true,
			Radius:        &radius,
			UsePic:        true,
			Lang:          "en",
		},
	)

	fmt.Printf("Widget HTML generated: %d bytes\n", len(widget))
}

// Example of a complete HTTP handler for Telegram login.
func Example_httpHandler() {
	provider := shieldtelegram.NewProvider(&shieldtelegram.Config{
		BotToken:   "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
		MaxAuthAge: 1 * time.Hour,
	})

	// Login page handler
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		widget := provider.GenerateWidget(
			"https://example.com/auth/telegram/callback",
			&shieldtelegram.WidgetOptions{
				Size: "large",
				Lang: "en",
			},
		)

		fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head><title>Login with Telegram</title></head>
<body>
	<h1>Login with Telegram</h1>
	%s
	%s
</body>
</html>
`, widget, shieldtelegram.GenerateWidgetCallback("https://example.com/api/auth/telegram"))
	})

	// Callback handler
	http.HandleFunc("/api/auth/telegram", func(w http.ResponseWriter, r *http.Request) {
		userInfo, err := shieldtelegram.HandleCallback(r.Context(), r, provider)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// Create session, set cookies, etc.
		fmt.Fprintf(w, `{"success": true, "user_id": %d, "username": "%s"}`,
			userInfo.ID, userInfo.Username)
	})

	// In a real application, you would start the server here
	// http.ListenAndServe(":8080", nil)
}
