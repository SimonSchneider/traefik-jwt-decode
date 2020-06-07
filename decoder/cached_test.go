package decoder

import (
	"fmt"
	"testing"
	"time"

	dt "github.com/SimonSchneider/traefik-jwt-decode/decoder/decodertest"
)

func TestCacheResponsesThatDontReturnErrors(t *testing.T) {
	token := &Token{Expiration: time.Now().Add(time.Hour)}
	delegate := newMock(func(raw string) (*Token, error) {
		return token, nil
	})
	dec, _ := NewCachedJwtDecoder(delegate)
	getAndCompareCached(t, dec, delegate, token, 1)
	time.Sleep(10 * time.Millisecond)
	getAndCompareCached(t, dec, delegate, token, 1)
}

func getAndCompareCached(t *testing.T, dec TokenDecoder, delegate *decoderMock, expectedToken *Token, expectedCalls int) {
	token, err := dec.Decode("raw")
	dt.Report(t, err != nil, "got error from cache with working delegate %v", err)
	dt.Report(t, token != expectedToken, "got value from cache '%v' that is not equal value from delegate '%v'", token, expectedToken)
	dt.Report(t, delegate.calls != expectedCalls, "incorrect number of calls to delegate %d expected %d", delegate.calls, expectedCalls)
}

func TestDontCacheWhenDelegateReturnsError(t *testing.T) {
	token := &Token{Expiration: time.Now().Add(time.Hour)}
	delegateErr := fmt.Errorf("bad token")
	delegate := newMock(func(raw string) (*Token, error) {
		return nil, delegateErr
	})
	dec, _ := NewCachedJwtDecoder(delegate)
	token, err := dec.Decode("raw")
	dt.Report(t, token != nil, "expected nil resp from cache")
	dt.Report(t, delegate.calls != 1, "expected 1 call to delegate had %d", delegate.calls)
	dt.Report(t, err != delegateErr, "expected cache error %v to be delegate error %v", err, delegateErr)
	time.Sleep(100 * time.Millisecond)
	token, err = dec.Decode("raw")
	dt.Report(t, token != nil, "expected nil resp from cache")
	dt.Report(t, delegate.calls != 2, "expected 2 call to delegate had %d", delegate.calls)
	dt.Report(t, err != delegateErr, "expected cache error %v to be delegate error %v", err, delegateErr)
}

type DecodeFunc func(raw string) (*Token, error)

type decoderMock struct {
	calls    int
	delegate DecodeFunc
}

func (d *decoderMock) Decode(raw string) (*Token, error) {
	d.calls = d.calls + 1
	fmt.Println("called with", raw)
	return d.delegate(raw)
}

func newMock(delegate DecodeFunc) *decoderMock {
	return &decoderMock{calls: 0, delegate: delegate}
}
