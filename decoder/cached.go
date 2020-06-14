package decoder

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"

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

func (d *cachedJwtDecoder) Decode(ctx context.Context, raw string) (*Token, error) {
	if t, ok := d.cache.Get(raw); ok {
		fromCache := t.(*cacheVal)
		return fromCache.token, fromCache.err
	}
	log.Ctx(ctx).Trace().Msg("cache miss, resolving token from delegate")
	token, err := d.delegate.Decode(ctx, raw)
	toCache := &cacheVal{token: token, err: err}
	d.cache.SetWithTTL(raw, toCache, 100, 10*time.Minute)
	return token, err
}
