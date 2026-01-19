package httputil

import "net/http"

// Doer interface defines the contract for making HTTP requests.
//
//go:generate mockgen -destination=../mocks/http_doer_mock.go -package=mocks . Doer
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}
