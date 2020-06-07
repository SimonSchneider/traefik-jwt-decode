package decoder

import (
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
