package decoder

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
)

type jwsDecoder struct {
	jwks         *jwk.Set
	claimMapping map[string]string
	jwksURL      string
	jwksFetcher  *jwk.AutoRefresh
	mutex        sync.RWMutex
}

// UnexpectedClaimTypeError is thrown if a mapped claim in the token has an unexpected type
// the token should always have type string
type UnexpectedClaimTypeError struct {
	name  string
	claim interface{}
}

func (e UnexpectedClaimTypeError) Error() string {
	return fmt.Sprintf("claim %s has type %T not string", e.name, e.claim)
}

// NewJwsDecoder returns a root Decoder that can decode and validate JWS Tokens
// It will also map the claims via the claim mapping
// `claimMapping = map[string][string]{ "key123", "headerKey123" }`
// will cause the claim `key123` in the JWS token to be mapped to `headerKey123` in the decoded token
func NewJwsDecoder(jwksURL string, claimMapping map[string]string) (TokenDecoder, error) {
	ar := jwk.NewAutoRefresh(context.Background())
	ar.Configure(jwksURL)
	d := jwsDecoder{claimMapping: claimMapping, jwksFetcher: ar, jwksURL: jwksURL}
	_, err := ar.Fetch(context.Background(), jwksURL)
	return &d, err
}

func (d *jwsDecoder) Decode(ctx context.Context, rawJws string) (*Token, error) {
	jwtToken, err := d.parseAndValidate(ctx, rawJws)
	if err != nil {
		return nil, err
	}
	token := &Token{
		Expiration: jwtToken.Expiration(),
		Claims:     make(map[string]string),
	}
	for key, destKey := range d.claimMapping {
		if value, ok := jwtToken.Get(key); ok {
			if strVal, ok := value.(string); ok {
				token.Claims[destKey] = strVal
			} else {
				strJSON, err := json.Marshal(value)

				if err != nil {
					return nil, UnexpectedClaimTypeError{key, value}
				}

				token.Claims[destKey] = string(strJSON)
			}
		}
	}
	return token, nil
}

func (d *jwsDecoder) parseAndValidate(ctx context.Context, rawJws string) (jwt.Token, error) {
	jwks, err := d.jwksFetcher.Fetch(ctx, d.jwksURL)
	if err != nil {
		return nil, err
	}
	_, err = jws.VerifySet([]byte(rawJws), jwks)
	if err != nil {
		return nil, fmt.Errorf("unable to verify token with jwks: %w", err)
	}
	t, err := jwt.ParseString(rawJws)
	if err != nil {
		return nil, fmt.Errorf("unable to parse token: %w", err)
	}
	return t, nil
}
