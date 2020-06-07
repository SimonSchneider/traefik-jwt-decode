package decoder

/*
JWT - interface
headers: typ + cty

JWS implementation of JWT
headers: kid + alg

JWE implementation of JWT
*/
import (
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
)

// KeySupplier supplies public keys for use in the JWT decoder
type KeySupplier func(keyID string) (key interface{}, err error)

// RemoteKeySupplier the default KeySupplier to be used
func RemoteKeySupplier(jwksURL string) (KeySupplier, error) {
	jwks, err := jwk.FetchHTTP(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("jwks: failed to fetch from url %s", err)
	}
	return func(keyID string) (rawKey interface{}, err error) {
		keys := jwks.LookupKeyID(keyID)
		if len(keys) != 1 {
			return nil, fmt.Errorf("jwks: invalid number of keys with keyID %s found: %d", keyID, len(keys))
		}
		err = keys[0].Raw(&rawKey)
		return
	}, nil
}

type jwsDecoder struct {
	keys         KeySupplier
	claimMapping map[string]string
}

// NewJwsDecoder returns a root Decoder that can decode and validate JWS Tokens
// It will also map the claims via the claim mapping
// `claimMapping = map[string][string]{ "key123", "headerKey123" }`
// will cause the claim `key123` in the JWS token to be mapped to `headerKey123` in the decoded token
func NewJwsDecoder(keySupplier KeySupplier, claimMapping map[string]string) (TokenDecoder, error) {
	return &jwsDecoder{keys: keySupplier, claimMapping: claimMapping}, nil
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
	t, err := jws.Parse(strings.NewReader(rawJws))
	if err != nil {
		return nil, err
	}
	if len(t.Signatures()) != 1 {
		return nil, fmt.Errorf("too many signatures")
	}
	headers := t.Signatures()[0].ProtectedHeaders()
	kid := headers.KeyID()
	alg := headers.Algorithm()
	key, err := d.keys(kid)
	if err != nil {
		return nil, err
	}
	return jwt.ParseVerify(strings.NewReader(rawJws), alg, key)
}
