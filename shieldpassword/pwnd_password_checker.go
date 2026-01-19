//nolint:gci // import order
package shieldpassword

import (
	"bytes"
	"context"
	"log/slog"

	//nolint:gosec // SHA1 is required by pwnedpasswords.com
	"crypto/sha1"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"go.inout.gg/foundations/debug"
	"go.inout.gg/shield/internal/httputil"
)

var _ PasswordChecker = (*PwndPasswordChecker)(nil)

// ErrPwnedPassword is returned when a password has been pwned.
var ErrPwnedPassword = errors.New("shieldpassword: password has been pwned")

type PwndPasswordCheckerConfig struct {
	Client httputil.Doer
	Logger *slog.Logger // optional
}

func (c *PwndPasswordCheckerConfig) defaults() {
	if c.Client == nil {
		c.Client = http.DefaultClient
	}

	debug.Assert(c.Client != nil, "Client must be set")
}

type PwndPasswordChecker struct {
	config *PwndPasswordCheckerConfig
}

func NewPwndPasswordChecker(opts ...func(*PwndPasswordCheckerConfig)) *PwndPasswordChecker {
	var config PwndPasswordCheckerConfig
	for _, opt := range opts {
		opt(&config)
	}

	config.defaults()

	return &PwndPasswordChecker{config: &config}
}

func (c *PwndPasswordChecker) Check(ctx context.Context, password string) error {
	//nolint:gosec // SHA1 is required by pwnedpasswords.com
	hash := sha1.Sum([]byte(password))
	hashHex := fmt.Sprintf("%X", hash)
	prefix := hashHex[:5]
	suffix := hashHex[5:]

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"https://api.pwnedpasswords.com/range/"+prefix,
		nil,
	)
	if err != nil {
		return fmt.Errorf("shieldpassword: failed to create request: %w", err)
	}

	req.Header.Add("User-Agent", "shield-go")
	req.Header.Add("Add-Padding", "true")

	resp, err := c.config.Client.Do(req)
	if err != nil {
		return fmt.Errorf("shieldpassword: failed to check password: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("shieldpassword: unexpected status code: %d", resp.StatusCode)
	}

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return fmt.Errorf("shieldpassword: failed to read response body: %w", err)
	}

	suffixes := strings.SplitSeq(buf.String(), "\n")
	for s := range suffixes {
		if strings.HasPrefix(s, suffix) {
			split := strings.Split(s, ":")
			if len(split) != 2 {
				return errors.New("shieldpassword: invalid response format")
			}

			count, err := strconv.Atoi(split[1])
			if err != nil {
				return errors.New("shieldpassword: invalid response format")
			}

			if split[0] == suffix && count > 0 {
				return ErrPwnedPassword
			}
		}
	}

	return nil
}
