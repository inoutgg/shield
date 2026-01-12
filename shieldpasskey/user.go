package shieldpasskey

import (
	"encoding/binary"
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
func (u *user) WebAuthnID() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(u.ID)) //#nosec:G115

	return b
}
func (u *user) WebAuthnIcon() string { return "" }
func (u *user) WebAuthnName() string { return u.Email }
