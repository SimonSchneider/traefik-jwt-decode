package decoder

import (
	"context"
	"fmt"
	"time"
)

// TokenDecoder can decode and validate raw JTW tokens
type TokenDecoder interface {
	Decode(ctx context.Context, raw string) (*Token, error)
}

// Token contains the expiration time and a remapped map of claims from the JWT Token
type Token struct {
	Claims     map[string]string
	Expiration time.Time
}

type TokenExpiredError struct {
	expiredAt time.Time
}

func (e TokenExpiredError) Error() string {
	return fmt.Sprintf("token is expired (expired at: %s)", e.expiredAt.Format(time.RFC3339))
}

// Validate the token (currently only checks the expirationTime but could potentially do more checks)
func (t *Token) Validate() error {
	if !t.Expiration.IsZero() && time.Now().After(t.Expiration) {
		return TokenExpiredError{t.Expiration}
	}
	return nil
}
