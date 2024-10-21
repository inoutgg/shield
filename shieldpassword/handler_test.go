package shieldpassword

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"go.inout.gg/foundations/must"
	"go.inout.gg/foundations/sqldb/sqldbtest"
	"go.inout.gg/shield/db/driverpgxv5"
	"go.inout.gg/shield/shieldmigrate"
)

var migrator = shieldmigrate.New()

func makeDB(ctx context.Context, t *testing.T) *sqldbtest.DB {
	return sqldbtest.Must(ctx, t, sqldbtest.WithUp(func(ctx context.Context, conn *pgx.Conn) error {
		return migrator.Up(ctx, conn, nil)
	}))
}

func TestUserRegistration(t *testing.T) {
	ctx := context.Background()
	db := makeDB(ctx, t)
	logger := slog.Default()
	config := &Config[any]{
		PasswordHasher: DefaultPasswordHasher,
		Logger:         logger,
	}
	pool := db.Pool()
	pgxDriver := driverpgxv5.New(logger, pool)
	h := &Handler[any]{
		config:           config,
		driver:           pgxDriver,
		PasswordVerifier: nil,
	}

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
        users.email,
        user_credentials.user_credential_key,
        user_credentials.user_credential_secret
      FROM users
      JOIN user_credentials
        ON users.id = user_credentials.user_id
      WHERE users.id = $1`, uid).
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

	t.Run("user already exists", func(t *testing.T) {
		must.Must1(db.Reset(ctx))
	})
}

func TestUserLogin(t *testing.T) {
	ctx := context.Background()
	db := makeDB(ctx, t)

	t.Run("user not found", func(t *testing.T) {
		must.Must1(db.Reset(ctx))
	})
}
