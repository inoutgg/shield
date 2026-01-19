package mocks

import (
	"bytes"
	"crypto/sha1" //nolint:gosec
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"

	"go.uber.org/mock/gomock"
)

// PwnedPasswordsMockServer simulates the Have I Been Pwned Passwords API.
//
// It stores a map of SHA1 hash prefixes to their suffixes with counts.
type PwnedPasswordsMockServer struct {
	responseError error
	passwords     map[string]int
	statusCode    int
}

// NewPwnedPasswordsMockServer creates a new mock server instance.
func NewPwnedPasswordsMockServer() *PwnedPasswordsMockServer {
	return &PwnedPasswordsMockServer{
		passwords:     make(map[string]int),
		statusCode:    http.StatusOK,
		responseError: nil,
	}
}

// AddPassword adds a password to the mock database with the given breach count.
// The password is hashed using SHA1 and stored.
func (s *PwnedPasswordsMockServer) AddPassword(
	password string,
	count int,
) *PwnedPasswordsMockServer {
	hash := sha1Hash(password)
	s.passwords[hash] = count

	return s
}

// AddHash adds a raw SHA1 hash (uppercase hex string) to the mock database.
func (s *PwnedPasswordsMockServer) AddHash(hash string, count int) *PwnedPasswordsMockServer {
	s.passwords[strings.ToUpper(hash)] = count
	return s
}

// WithStatusCode sets the HTTP status code to return.
func (s *PwnedPasswordsMockServer) WithStatusCode(code int) *PwnedPasswordsMockServer {
	s.statusCode = code
	return s
}

// WithError sets an error to return instead of a response.
func (s *PwnedPasswordsMockServer) WithError(err error) *PwnedPasswordsMockServer {
	s.responseError = err
	return s
}

// SetupMock configures the MockDoer to respond to requests matching the given prefix.
//
// If prefix is empty, it matches any request to the pwnedpasswords API.
func (s *PwnedPasswordsMockServer) SetupMock(mock *MockDoer) *gomock.Call {
	return mock.EXPECT().
		Do(gomock.Any()).
		DoAndReturn(func(req *http.Request) (*http.Response, error) {
			if s.responseError != nil {
				return nil, s.responseError
			}

			// Extract prefix from URL path
			path := req.URL.Path
			if !strings.HasPrefix(path, "/range/") {
				//nolint:exhaustruct
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       io.NopCloser(strings.NewReader("Not Found")),
				}, nil
			}

			prefix := strings.ToUpper(strings.TrimPrefix(path, "/range/"))
			body := s.buildResponse(prefix)

			//nolint:exhaustruct
			return &http.Response{
				StatusCode: s.statusCode,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		})
}

// buildResponse generates the API response body for a given hash prefix.
// Returns suffixes with counts in the format: SUFFIX:COUNT\n.
func (s *PwnedPasswordsMockServer) buildResponse(prefix string) string {
	var buf bytes.Buffer

	for hash, count := range s.passwords {
		if strings.HasPrefix(hash, prefix) {
			suffix := hash[len(prefix):]
			fmt.Fprintf(&buf, "%s:%d\n", suffix, count)
		}
	}

	return strings.TrimSuffix(buf.String(), "\n")
}

// sha1Hash computes the SHA1 hash of a string and returns it as uppercase hex.
func sha1Hash(s string) string {
	//nolint:gosec // SHA1 is required by pwnedpasswords.com API
	h := sha1.New()
	h.Write([]byte(s))

	return strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}
