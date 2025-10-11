//nolint:gci // import order
package shieldpassword

import (
	"bytes"
	"cmp"
	"context"

	//nolint:gosec // SHA1 is required by pwnedpasswords.com
	"crypto/sha1"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"go.inout.gg/foundations/debug"
)

var _ PasswordChecker = (*pwndPasswordChecker)(nil)

// ErrPwnedPassword is returned when a password has been pwned.
var ErrPwnedPassword = errors.New("shieldpassword: password has been pwned")

type PwndPasswordCheckerConfig struct {
	Client *http.Client
}

func (c *PwndPasswordCheckerConfig) defaults() {
	c.Client = cmp.Or(c.Client, http.DefaultClient)

	debug.Assert(c.Client != nil, "Client must be set")
}

type pwndPasswordChecker struct {
	config *PwndPasswordCheckerConfig
}

func NewPwndPasswordChecker(opts ...func(*PwndPasswordCheckerConfig)) PasswordChecker {
	var config PwndPasswordCheckerConfig
	for _, opt := range opts {
		opt(&config)
	}

	config.defaults()

	return &pwndPasswordChecker{config: &config}
}

func (c *pwndPasswordChecker) Check(ctx context.Context, password string) error {
	//nolint:gosec // SHA1 is required by pwnedpasswords.com
	hash := sha1.New().Sum([]byte(password))
	prefix := fmt.Sprintf("%08x", hash[:5])
	suffix := fmt.Sprintf("%08x", hash[5:])

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

			if s == suffix && count > 0 {
				return ErrPwnedPassword
			}
		}
	}

	return nil
}
