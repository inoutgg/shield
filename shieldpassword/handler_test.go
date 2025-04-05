package shieldpassword

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.inout.gg/foundations/must"

	"go.inout.gg/shield/internal/testutil"
)

func TestUserRegistration(t *testing.T) {
	ctx := t.Context()
	db := testutil.MustDB(t)
	config := NewConfig[any]()
	pool := db.Pool()
	h := NewHandler(pool, config)

	t.Run("register user", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		must.Must1(db.Reset(ctx))

		// Act
		user, err := h.HandleUserRegistration(ctx, "test@test.org", "test")
		if err != nil {
			t.Fatal(err)
		}

		// Assert
		actual := struct {
			UserEmail          string
			CredentialEmail    string
			CredentialPassword string
		}{}
		uid := user.ID.String()

		if err := pool.QueryRow(ctx, `
      SELECT
        "user".email,
        cred.user_credential_key,
        cred.user_credential_secret
      FROM shield_users AS "user"
      JOIN shield_user_credentials AS cred
        ON "user".id = cred.user_id
      WHERE "user".id = $1`, uid).
			Scan(&actual.UserEmail, &actual.CredentialEmail, &actual.CredentialPassword); err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, "test@test.org", actual.UserEmail)
		assert.Equal(t, "test@test.org", actual.CredentialEmail)
		assert.NotEmpty(t, actual.CredentialPassword)
		assert.True(
			t,
			must.Must(h.config.PasswordHasher.Verify(actual.CredentialPassword, "test")),
		)
	})

	t.Run("user already exists", func(*testing.T) {
		must.Must1(db.Reset(ctx))
	})
}

func TestUserLogin(t *testing.T) {
	ctx := t.Context()
	db := testutil.MustDB(t)

	t.Run("user not found", func(*testing.T) {
		must.Must1(db.Reset(ctx))
	})
}
