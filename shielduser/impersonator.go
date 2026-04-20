package shielduser

import (
	"context"
	"fmt"
	"net/http"

	"go.inout.gg/foundations/debug"
)

// Impersonator issues an impersonated session for a target user.
//
// Implementations may apply impersonation-specific policies such as bypassing
// the target user's MFA requirement or using a short absolute session lifetime.
//
//go:generate mockgen -destination=../internal/mocks/impersonator_mock.go -package=mocks -typed . Impersonator
type Impersonator[U, S any] interface {
	Impersonate(http.ResponseWriter, *http.Request, *Session[S], *User[U]) (Session[S], error)
}

// IsImpersonated returns true if the current authenticated session is impersonated.
func IsImpersonated[S any](ctx context.Context) bool {
	sess, err := FromContext[S](ctx)
	if err != nil {
		return false
	}

	return sess.ImpersonatedBy != nil
}

// ImpersonationHandler coordinates actor session loading, authorization, and
// backend impersonation.
type ImpersonationHandler[U, S any] struct {
	impersonator Impersonator[U, S]
}

func NewImpersonationHandler[U, S any](
	impersonator Impersonator[U, S],
) *ImpersonationHandler[U, S] {
	debug.Assert(impersonator != nil, "impersonator must be set")

	return &ImpersonationHandler[U, S]{
		impersonator: impersonator,
	}
}

// HandleImpersonate issues an impersonated session for the target user.
//
// The request is expected to already have an authenticated actor session in its
// context, for example via shielduser.Middleware.
func (h *ImpersonationHandler[U, S]) HandleImpersonate(w http.ResponseWriter, r *http.Request, targetUser *User[U]) (Session[S], error) {
	var sess Session[S]

	actorSession, err := FromRequest[S](r)
	if err != nil {
		return sess, fmt.Errorf(
			"shielduser: failed to retrieve actor session from request: %w",
			err,
		)
	}

	sess, err = h.impersonator.Impersonate(w, r, actorSession, targetUser)
	if err != nil {
		return sess, fmt.Errorf(
			"shielduser: failed to impersonate user: %w",
			err,
		)
	}

	return sess, nil
}
