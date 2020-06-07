package decoder

import (
	"fmt"
	"testing"
	"time"

	dt "github.com/SimonSchneider/traefik-jwt-decode/decoder/decodertest"
)

func TestCacheAllResponses(t *testing.T) {
	tests := map[string]struct {
		token *Token
		err   error
	}{
		"TokenAndNoError": {token: &Token{Expiration: time.Now().Add(time.Hour)}, err: nil},
		"TokenAndError":   {token: &Token{Expiration: time.Now().Add(time.Hour)}, err: fmt.Errorf("some error")},
		"NoTokenAndError": {token: nil, err: fmt.Errorf("some other error")},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			delegate := newMock(func(raw string) (*Token, error) {
				return tc.token, tc.err
			})
			dec, _ := NewCachedJwtDecoder(delegate)
			getAndCompareCached(t, name, dec, delegate, tc.token, tc.err, 1)
			time.Sleep(100 * time.Millisecond)
			getAndCompareCached(t, name, dec, delegate, tc.token, tc.err, 1)
		})
	}
}

func getAndCompareCached(t *testing.T, name string, dec TokenDecoder, delegate *decoderMock, expectedToken *Token, expectedError error, expectedCalls int) {
	token, err := dec.Decode(name)
	dt.Report(t, err != expectedError, "got unexpected error %v from cache expected %v", err, expectedError)
	dt.Report(t, token != expectedToken, "got unexpected token %v from cache expected %v", token, expectedToken)
	dt.Report(t, delegate.calls != expectedCalls, "incorrect number of calls to delegate %d expected %d", delegate.calls, expectedCalls)
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
