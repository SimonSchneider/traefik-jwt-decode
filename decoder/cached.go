package decoder

import (
	"time"

	"github.com/dgraph-io/ristretto"
)

type cachedJwtDecoder struct {
	cache    *ristretto.Cache
	delegate TokenDecoder
}

type cacheVal struct {
	token *Token
	err   error
}

// NewCachedJwtDecoder returns a new JwtDecoder that will cache Tokens decoded by the delegate
func NewCachedJwtDecoder(cache *ristretto.Cache, delegate TokenDecoder) TokenDecoder {
	return &cachedJwtDecoder{cache: cache, delegate: delegate}
}

func (d *cachedJwtDecoder) Decode(raw string) (*Token, error) {
	if t, ok := d.cache.Get(raw); ok {
		fromCache := t.(*cacheVal)
		return fromCache.token, fromCache.err
	}
	token, err := d.delegate.Decode(raw)
	toCache := &cacheVal{token: token, err: err}
	d.cache.SetWithTTL(raw, toCache, 100, 10*time.Minute)
	return token, err
}
