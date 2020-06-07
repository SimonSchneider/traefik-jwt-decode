package decoder

import (
	"fmt"
	"time"
)

// TokenDecoder can decode and validate raw JTW tokens
type TokenDecoder interface {
	Decode(raw string) (*Token, error)
}

// Token contains the expiration time and a remapped map of claims from the JWT Token
type Token struct {
	Claims     map[string]string
	Expiration time.Time
}

// Validate the token (currently only checks the expirationTime but could potentially do more checks)
func (t *Token) Validate() error {
	if !t.Expiration.IsZero() && time.Now().After(t.Expiration) {
		return fmt.Errorf("token expired")
	}
	return nil
}
