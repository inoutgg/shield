package shieldtelegram

import (
	"fmt"
	"html/template"
	"strconv"
	"strings"
)

// GenerateWidget generates HTML/JavaScript code for the Telegram Login Widget.
//
// The widget can be embedded in a web page to allow users to authenticate
// using their Telegram account. When the user clicks the button, they will
// be redirected to Telegram for authentication, and then back to the redirectURL
// with authentication data in the URL hash.
//
// See: https://core.telegram.org/widgets/login
func (p *provider) GenerateWidget(redirectURL string, opts *WidgetOptions) string {
	if opts == nil {
		opts = &WidgetOptions{
			Size: "large",
			Lang: "en",
		}
	}

	// Build widget attributes
	attrs := p.buildWidgetAttributes(redirectURL, opts)

	// Generate the widget HTML
	return fmt.Sprintf(`<script async src="https://telegram.org/js/telegram-widget.js?22" data-telegram-login="%s"%s></script>`,
		template.HTMLEscapeString(p.botUsername),
		attrs,
	)
}

// buildWidgetAttributes builds the HTML attributes for the Telegram widget script tag.
func (p *provider) buildWidgetAttributes(redirectURL string, opts *WidgetOptions) string {
	var attrs []string

	// Add redirect URL (auth-url attribute)
	attrs = append(attrs, fmt.Sprintf(` data-auth-url="%s"`, template.HTMLEscapeString(redirectURL)))

	// Add size
	if opts.Size != "" {
		attrs = append(attrs, fmt.Sprintf(` data-size="%s"`, template.HTMLEscapeString(opts.Size)))
	}

	// Add request-access
	if opts.RequestAccess {
		attrs = append(attrs, ` data-request-access="write"`)
	}

	// Add radius
	if opts.Radius != nil {
		radius := *opts.Radius
		if radius < 0 {
			radius = 0
		}
		if radius > 20 {
			radius = 20
		}
		attrs = append(attrs, fmt.Sprintf(` data-radius="%s"`, strconv.Itoa(radius)))
	}

	// Add userpic
	if opts.UsePic {
		attrs = append(attrs, ` data-userpic="true"`)
	}

	// Add language
	if opts.Lang != "" && opts.Lang != "en" {
		attrs = append(attrs, fmt.Sprintf(` data-lang="%s"`, template.HTMLEscapeString(opts.Lang)))
	}

	return strings.Join(attrs, "")
}

// GenerateWidgetCallback generates JavaScript code to handle the widget callback.
//
// This code should be included on the page that will receive the callback.
// It extracts the authentication data from the URL hash and sends it to your server.
func GenerateWidgetCallback(serverCallbackURL string) string {
	return fmt.Sprintf(`
<script>
(function() {
	// Parse authentication data from URL hash
	function getTelegramAuthData() {
		const hash = window.location.hash.substring(1);
		if (!hash) return null;

		const params = new URLSearchParams(hash);
		const data = {};

		for (const [key, value] of params) {
			if (key.startsWith('tgAuthResult')) {
				// Telegram wraps the data in tgAuthResult
				try {
					return JSON.parse(decodeURIComponent(value));
				} catch (e) {
					console.error('Failed to parse Telegram auth data:', e);
					return null;
				}
			}
			// Also support direct parameter format
			data[key] = value;
		}

		return Object.keys(data).length > 0 ? data : null;
	}

	// Send auth data to server
	const authData = getTelegramAuthData();
	if (authData) {
		fetch(%q, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
			},
			body: JSON.stringify(authData)
		})
		.then(response => response.json())
		.then(data => {
			console.log('Authentication successful:', data);
			// Handle successful authentication
			// Redirect or update UI as needed
		})
		.catch(error => {
			console.error('Authentication failed:', error);
			// Handle authentication failure
		});
	}
})();
</script>
`, serverCallbackURL)
}
