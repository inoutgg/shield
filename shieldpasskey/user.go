package shieldpasskey

import (
	"encoding/json"

	"github.com/go-webauthn/webauthn/webauthn"

	"go.inout.gg/shield/internal/dbsqlc"
)

var _ webauthn.User = (*user)(nil)

type user struct {
	dbsqlc.FindUserWithPasskeyCredentialByEmailRow
}

func (u *user) WebAuthnCredentials() []webauthn.Credential {
	var credentials []webauthn.Credential
	if err := json.Unmarshal(u.UserCredential, &credentials); err != nil {
		panic(err)
	}

	return credentials
}

func (u *user) WebAuthnDisplayName() string { return u.Email }
func (u *user) WebAuthnID() []byte          { return u.ID[:] }
func (u *user) WebAuthnIcon() string        { return "" }
func (u *user) WebAuthnName() string        { return u.Email }
