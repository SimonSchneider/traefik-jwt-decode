package decoder

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
)

type jwsDecoder struct {
	jwks         *jwk.Set
	claimMapping map[string]string
}

// NewJwsDecoder returns a root Decoder that can decode and validate JWS Tokens
// It will also map the claims via the claim mapping
// `claimMapping = map[string][string]{ "key123", "headerKey123" }`
// will cause the claim `key123` in the JWS token to be mapped to `headerKey123` in the decoded token
func NewJwsDecoder(jwksURL string, claimMapping map[string]string) (TokenDecoder, error) {
	jwks, err := jwk.FetchHTTP(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("jwks: failed to fetch from url %s", err)
	}
	return &jwsDecoder{jwks: jwks, claimMapping: claimMapping}, nil
}

func (d *jwsDecoder) Decode(rawJws string) (*Token, error) {
	jwtToken, err := d.parseAndValidate(rawJws)
	if err != nil {
		return nil, err
	}
	token := &Token{
		Expiration: jwtToken.Expiration(),
		Claims:     make(map[string]string),
	}
	if !token.Expiration.IsZero() && time.Now().After(token.Expiration) {
		return nil, fmt.Errorf("token expired")
	}
	for key, destKey := range d.claimMapping {
		if value, ok := jwtToken.Get(key); ok {
			if strVal, ok := value.(string); ok {
				token.Claims[destKey] = strVal
			} else {
				return nil, fmt.Errorf("unexpected claim type, expected string")
			}
		}
	}
	return token, nil
}

func (d *jwsDecoder) parseAndValidate(rawJws string) (jwt.Token, error) {
	_, err := jws.VerifyWithJWKSet([]byte(rawJws), d.jwks, nil)
	if err != nil {
		return nil, err
	}
	return jwt.ParseString(rawJws)
}
