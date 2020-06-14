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

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/SimonSchneider/traefik-jwt-decode/decoder"
)

const (
	nTokens           = 5000
	randomClaim       = "rnd-claim"
	randomClaimHeader = "test-token-random-claim"
	authHeaderKey     = "Authorization"
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
	uncachedSrv, cachedSrv *decoder.Server
	ctx                    context.Context
	tokens                 = make([]string, nTokens, nTokens)
)

func TestNoAuthHeaderIsOKWithoutTokenHeaders(t *testing.T) {
	req, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)
	rr := httptest.NewRecorder()
	serverTest(func(srv *decoder.Server) func(*testing.T) {
		return func(t *testing.T) {
			srv.DecodeToken(rr, req)
			status := rr.Result().StatusCode
			Report(t, status != http.StatusOK, "no token should be ok got %d", status)
		}
	})(t)
}

func TestServerResponseCode(t *testing.T) {
	tests := map[string]struct {
		token []byte
		code  int
	}{
		"Valid token":   {token: validRndToken(), code: http.StatusOK},
		"Expired token": {token: expiredRndToken(), code: http.StatusUnauthorized},
		"Invalid token": {token: invalidRndToken(), code: http.StatusUnauthorized},
	}
	for name, tc := range tests {
		t.Run(name, serverTest(func(srv *decoder.Server) func(*testing.T) {
			return func(t *testing.T) {
				rr, req := reqFor(tc.token)
				srv.DecodeToken(rr, req)
				status := rr.Result().StatusCode
				Report(t, status != tc.code, "incorrect server response, %d, expected: %d", status, tc.code)
			}
		}))
	}
}

func TestServerResponseHeaders(t *testing.T) {
	serverTest(func(srv *decoder.Server) func(t *testing.T) {
		return func(t *testing.T) {
			rndClaim := strconv.FormatInt(rnd.Int63(), 10)
			rr, req := reqFor(validToken(rndClaim))
			srv.DecodeToken(rr, req)
			headers := rr.Header()
			rndClaimHeader := headers.Get(randomClaimHeader)
			Report(t, rndClaim != rndClaimHeader, "incorrect random header %s expected %s", rndClaimHeader, rndClaim)
			for claimKey, headerKey := range claimMappings {
				if headerKey == randomClaimHeader {
					continue
				}
				headerVal := headers.Get(headerKey)
				claimVal := allClaims[claimKey]
				Report(t, headerVal != claimVal, "claim '%s=%s' has incorrect val '%s=%s'", claimKey, claimVal, headerKey, headerVal)
			}
		}
	})(t)
}

func serverTest(subTest func(s *decoder.Server) func(t *testing.T)) func(t *testing.T) {
	return func(t *testing.T) {
		t.Run("unCachedServer", subTest(uncachedSrv))
		t.Run("cachedServer", subTest(cachedSrv))
	}
}

func BenchmarkFull(b *testing.B) {
	log.Logger = zerolog.New(os.Stdout).Level(zerolog.WarnLevel).With().Timestamp().Caller().Logger()
	for i := 0; i < nTokens; i++ {
		tokens[i] = fmt.Sprintf("Bearer %s", validRndToken())
	}
	b.Run("benchmark uncached server serial", benchmarkServerSerial(uncachedSrv))
	b.Run("benchmark uncached server parallel", benchmarkServerParallel(uncachedSrv))
	b.Run("benchmark cached server serial", benchmarkServerSerial(cachedSrv))
	b.Run("benchmark cached server parallel", benchmarkServerParallel(cachedSrv))
}

func benchmarkServerSerial(srv *decoder.Server) func(b *testing.B) {
	return func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			req, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)
			req.Header.Add(authHeaderKey, tokens[i%nTokens])
			rr := httptest.NewRecorder()
			srv.DecodeToken(rr, req)
		}
	}
}

func benchmarkServerParallel(srv *decoder.Server) func(b *testing.B) {
	return func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				req, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)
				req.Header.Add(authHeaderKey, tokens[rnd.Intn(nTokens)])
				rr := httptest.NewRecorder()
				srv.DecodeToken(rr, req)
			}
		})
	}
}

func reqFor(token []byte) (*httptest.ResponseRecorder, *http.Request) {
	req, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)
	req.Header.Add(authHeaderKey, fmt.Sprintf("Bearer %s", token))
	rr := httptest.NewRecorder()
	return rr, req
}

func validRndToken() []byte {
	return NewValidToken(newRndClaims())
}

func invalidRndToken() []byte {
	return NewInvalidToken(newRndClaims())
}

func validToken(rndClaimVal string) []byte {
	return NewValidToken(newClaims(rndClaimVal))
}

func expiredRndToken() []byte {
	return NewExpiredToken(newRndClaims())
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

func init() {
	log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout}).With().Timestamp().Caller().Logger()
	ctx = log.Logger.WithContext(context.Background())
	var err error
	var dec, cachedDec decoder.TokenDecoder
	dec, err = decoder.NewJwsDecoder(JwksURL, claimMappings)
	HandleByPanic(err)
	cachedDec = decoder.NewCachedJwtDecoder(cache, dec)
	HandleByPanic(err)
	uncachedSrv = decoder.NewServer(dec, authHeaderKey)
	cachedSrv = decoder.NewServer(cachedDec, authHeaderKey)
}
