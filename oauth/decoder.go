package oauth

import (
	"fmt"
	"strings"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

// KeySupplier supplies public keys for use in the JWT decoder
type KeySupplier func() (key interface{}, err error)

// RemoteKeySupplier the default KeySupplier to be used
func RemoteKeySupplier(jwksURL string, keyID string) KeySupplier {
	return func() (interface{}, error) {
		return getKeyFrom(jwksURL, keyID)
	}
}

func getKeyFrom(jwksURL string, keyID string) (interface{}, error) {
	var key interface{}
	if jwks, err := jwk.FetchHTTP(jwksURL); err != nil {
		return nil, fmt.Errorf("failed to fetch jwks: %s", err)
	} else if keys := jwks.LookupKeyID(keyID); len(keys) != 1 {
		return nil, fmt.Errorf("invalid number of %q found: %d", keyID, len(keys))
	} else if usage := keys[0].KeyUsage(); usage != string(jwk.ForSignature) {
		return nil, fmt.Errorf("%s: invalid usage %q", keyID, usage)
	} else if err = keys[0].Raw(&key); err != nil {
		return nil, fmt.Errorf("%s: %s", keyID, err)
	}
	return key, nil
}

// JwtDecoder can decode and validate raw JTW tokens
type JwtDecoder interface {
	Decode(raw string) (*Token, error)
}

// Token contains the expiration time and a remapped map of claims from the JWT Token
type Token struct {
	Claims     map[string]string
	Expiration time.Time
}

type jwtDecoder struct {
	key          interface{}
	claimMapping map[string]string
}

// NewDecoder returns a root JwtDecoder that can decode and validate JWT Tokens.NewDecoder
// It will also map the claims via the claim mapping
// `claimMapping = map[string][string]{ "key123", "headerKey123" }`
// will cause the claim `key123` in the JWT token to be mapped to `headerKey123` in the decoded token
func NewDecoder(keySupplier KeySupplier, claimMapping map[string]string) (JwtDecoder, error) {
	key, err := keySupplier()
	if err != nil {
		return nil, err
	}
	return &jwtDecoder{key: key, claimMapping: claimMapping}, nil
}

func (d *jwtDecoder) Decode(raw string) (*Token, error) {
	var jwtToken jwt.Token
	var err error
	if jwtToken, err = jwt.ParseVerify(strings.NewReader(raw), jwa.RS256, d.key); err != nil {
		return nil, err
	}

	token := &Token{
		Expiration: jwtToken.Expiration(),
		Claims:     make(map[string]string),
	}

	if !token.Expiration.IsZero() && time.Now().After(token.Expiration) {
		return nil, fmt.Errorf("access token expired")
	}

	for key, destKey := range d.claimMapping {
		if value, ok := jwtToken.Get(key); ok {
			if strVal, ok := value.(string); ok {
				token.Claims[destKey] = strVal
			} else {
				return nil, fmt.Errorf("unexpected claim type")
			}
		}
	}
	return token, nil
}

type cachedJwtDecoder struct {
	cache    *ristretto.Cache
	delegate JwtDecoder
}

// NewCachedJwtDecoder returns a new JwtDecoder that will cache Tokens decoded by the delegate
func NewCachedJwtDecoder(delegate JwtDecoder) (JwtDecoder, func(), error) {
	cache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 1e7,     // number of keys to track frequency of (10M).
		MaxCost:     1 << 30, // maximum cost of cache (1GB).
		BufferItems: 64,      // number of keys per Get buffer.
		Metrics:     true,
	})
	if err != nil {
		return nil, func() {}, err
	}
	decoder := &cachedJwtDecoder{cache: cache, delegate: delegate}
	return decoder, decoder.printStats, nil
}

func (d *cachedJwtDecoder) Decode(raw string) (*Token, error) {
	if t, ok := d.cache.Get(raw); ok {
		token := t.(*Token)
		return token, nil
	}
	token, err := d.delegate.Decode(raw)
	if err != nil {
		return nil, err
	}
	expiresIn := token.Expiration.Sub(time.Now())
	d.cache.SetWithTTL(raw, token, 100, expiresIn-time.Second*120)
	return token, nil
}

func (d *cachedJwtDecoder) printStats() {
	m := d.cache.Metrics
	fmt.Printf("ratio %f\n", m.Ratio())
	fmt.Printf("hits %d\n", m.Hits())
	fmt.Printf("misses %d\n", m.Misses())
}
