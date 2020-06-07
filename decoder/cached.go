package decoder

import (
	"fmt"
	"time"

	"github.com/dgraph-io/ristretto"
)

type cachedJwtDecoder struct {
	cache    *ristretto.Cache
	delegate TokenDecoder
}

// NewCachedJwtDecoder returns a new JwtDecoder that will cache Tokens decoded by the delegate
func NewCachedJwtDecoder(delegate TokenDecoder) (TokenDecoder, error) {
	cache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 1e7,     // number of keys to track frequency of (10M).
		MaxCost:     1 << 30, // maximum cost of cache (1GB).
		BufferItems: 64,      // number of keys per Get buffer.
		Metrics:     true,
	})
	if err != nil {
		return nil, err
	}
	decoder := &cachedJwtDecoder{cache: cache, delegate: delegate}
	return decoder, nil
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
