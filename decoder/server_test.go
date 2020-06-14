package decoder_test

import (
	"context"
	"fmt"
	rnd "math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"

	dt "github.com/SimonSchneider/traefik-jwt-decode/decodertest"

	"github.com/rs/zerolog"

	"github.com/SimonSchneider/traefik-jwt-decode/decoder"
)

const (
	nTokens           = 5000
	randomClaim       = "rnd-claim"
	randomClaimHeader = "test-token-random-claim"
)

var (
	allClaims = map[string]string{
		"claim1":     "claim number 1",
		"claim2":     "claim number 2",
		"claim3":     "claim number 3",
		"otherClaim": "this-claim-is-not-set",
	}
	claimMappings = map[string]string{
		"claim1":    "test-token-claim1",
		"claim2":    "test-token-claim2",
		"claim3":    "test-token-claim3",
		randomClaim: randomClaimHeader,
	}
)

func TestNoAuthHeaderIsOKWithoutTokenHeaders(t *testing.T) {
	req, _ := http.NewRequestWithContext(dt.Ctx(), "GET", "/", nil)
	rr := httptest.NewRecorder()
	tc := dt.NewTest()
	serverTest(tc, func(srv *decoder.Server) func(*testing.T) {
		return func(t *testing.T) {
			srv.DecodeToken(rr, req)
			status := rr.Result().StatusCode
			dt.Report(t, status != http.StatusOK, "no token should be ok got %d", status)
		}
	})(t)
}

func TestServerResponseCode(t *testing.T) {
	tc := dt.NewTest()
	tests := map[string]struct {
		token []byte
		code  int
	}{
		"Valid token":   {token: validRndToken(tc), code: http.StatusOK},
		"Expired token": {token: expiredRndToken(tc), code: http.StatusUnauthorized},
		"Invalid token": {token: invalidRndToken(tc), code: http.StatusUnauthorized},
	}
	for name, test := range tests {
		t.Run(name, serverTest(tc, func(srv *decoder.Server) func(*testing.T) {
			return func(t *testing.T) {
				rr, req := reqFor(test.token)
				srv.DecodeToken(rr, req)
				status := rr.Result().StatusCode
				dt.Report(t, status != test.code, "incorrect server response, %d, expected: %d", status, test.code)
			}
		}))
	}
}

func TestServerResponseHeaders(t *testing.T) {
	tc := dt.NewTest()
	serverTest(tc, func(srv *decoder.Server) func(t *testing.T) {
		return func(t *testing.T) {
			rndClaim := strconv.FormatInt(rnd.Int63(), 10)
			rr, req := reqFor(validToken(tc, rndClaim))
			srv.DecodeToken(rr, req)
			headers := rr.Header()
			rndClaimHeader := headers.Get(randomClaimHeader)
			dt.Report(t, rndClaim != rndClaimHeader, "incorrect random header %s expected %s", rndClaimHeader, rndClaim)
			for claimKey, headerKey := range claimMappings {
				if headerKey == randomClaimHeader {
					continue
				}
				headerVal := headers.Get(headerKey)
				claimVal := allClaims[claimKey]
				dt.Report(t, headerVal != claimVal, "claim '%s=%s' has incorrect val '%s=%s'", claimKey, claimVal, headerKey, headerVal)
			}
		}
	})(t)
}

func serverTest(tc *dt.TestConfig, subTest func(s *decoder.Server) func(t *testing.T)) func(t *testing.T) {
	return func(t *testing.T) {
		t.Run("unCachedServer", subTest(tc.UncachedServer(claimMappings)))
		t.Run("cachedServer", subTest(tc.CachedServer(claimMappings)))
	}
}

func BenchmarkFull(b *testing.B) {
	tc := dt.NewTest()
	logger := zerolog.New(os.Stdout).Level(zerolog.WarnLevel).With().Timestamp().Caller().Logger()
	ctx := logger.WithContext(context.Background())
	tokens := make([]string, nTokens, nTokens)
	for i := 0; i < nTokens; i++ {
		tokens[i] = fmt.Sprintf("Bearer %s", validRndToken(tc))
	}
	uncachedSrv := tc.UncachedServer(claimMappings)
	cachedSrv := tc.CachedServer(claimMappings)
	b.Run("benchmark uncached server serial", benchmarkServerSerial(ctx, tokens, uncachedSrv))
	b.Run("benchmark uncached server parallel", benchmarkServerParallel(ctx, tokens, uncachedSrv))
	b.Run("benchmark cached server serial", benchmarkServerSerial(ctx, tokens, cachedSrv))
	b.Run("benchmark cached server parallel", benchmarkServerParallel(ctx, tokens, cachedSrv))
}

func benchmarkServerSerial(ctx context.Context, tokens []string, srv *decoder.Server) func(b *testing.B) {
	return func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			req, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)
			req.Header.Add(dt.AuthHeaderKey, tokens[i%nTokens])
			rr := httptest.NewRecorder()
			srv.DecodeToken(rr, req)
		}
	}
}

func benchmarkServerParallel(ctx context.Context, tokens []string, srv *decoder.Server) func(b *testing.B) {
	return func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				req, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)
				req.Header.Add(dt.AuthHeaderKey, tokens[rnd.Intn(nTokens)])
				rr := httptest.NewRecorder()
				srv.DecodeToken(rr, req)
			}
		})
	}
}

func reqFor(token []byte) (*httptest.ResponseRecorder, *http.Request) {
	req, _ := http.NewRequestWithContext(dt.Ctx(), "GET", "/", nil)
	req.Header.Add(dt.AuthHeaderKey, fmt.Sprintf("Bearer %s", token))
	rr := httptest.NewRecorder()
	return rr, req
}

func validRndToken(tc *dt.TestConfig) []byte {
	return tc.NewValidToken(newRndClaims())
}

func invalidRndToken(tc *dt.TestConfig) []byte {
	return tc.NewInvalidToken(newRndClaims())
}

func validToken(tc *dt.TestConfig, rndClaimVal string) []byte {
	return tc.NewValidToken(newClaims(rndClaimVal))
}

func expiredRndToken(tc *dt.TestConfig) []byte {
	return tc.NewExpiredToken(newRndClaims())
}

func newRndClaims() map[string]interface{} {
	return newClaims(strconv.FormatInt(rnd.Int63(), 10))
}

func newClaims(rndClaimVal string) map[string]interface{} {
	claims := make(map[string]interface{})
	for k, v := range allClaims {
		claims[k] = v
	}
	claims[randomClaim] = rndClaimVal
	return claims
}
