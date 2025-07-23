package shielduser

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"go.inout.gg/shield/internal/dbsqlc"
	"go.inout.gg/shield/shieldsender"
	"go.inout.gg/shield/shieldsession"
)

type Handler[S any] struct {
	pool   *pgxpool.Pool
	sender shieldsender.Sender
}

func NewHandler[S any](
	pool *pgxpool.Pool,
	sender shieldsender.Sender,
) *Handler[S] {
	return &Handler[S]{
		pool:   pool,
		sender: sender,
	}
}

// HandleChangeEmail updates the email address associated with a user's account.
//
// It requires a session to be present in the context, otherwise it fails.
func (h Handler[S]) HandleChangeEmail(ctx context.Context, email string) error {
	sess, err := shieldsession.FromContext[S](ctx)
	if err != nil {
		return fmt.Errorf(
			"shielduser: failed to retrieve session: %w",
			err,
		)
	}

	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf(
			"shielduser: failed to begin transaction: %w",
			err,
		)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	if err = dbsqlc.New().ChangeUserEmailByID(ctx, tx, dbsqlc.ChangeUserEmailByIDParams{
		ID:    sess.UserID,
		Email: email,
	}); err != nil {
		return fmt.Errorf(
			"shielduser: failed to change user email: %w",
			err,
		)
	}

	if err = dbsqlc.New().ChangePasswordCredentialEmailByUserID(ctx, tx, dbsqlc.ChangePasswordCredentialEmailByUserIDParams{
		UserID: sess.UserID,
		Email:  email,
	}); err != nil {
		return fmt.Errorf(
			"shielduser: failed to change password credential email: %w",
			err,
		)
	}

	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf(
			"shielduser: failed to commit transaction: %w",
			err,
		)
	}

	if err = h.sender.Send(ctx, shieldsender.Message{
		Key:     shieldsender.MessageKeyEmailChange,
		Email:   email,
		Payload: nil,
	}); err != nil {
		return fmt.Errorf(
			"shielduser: failed to send email change message: %w",
			err,
		)
	}

	return nil
}
