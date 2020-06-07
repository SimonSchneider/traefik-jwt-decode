package decoder

import (
	"fmt"
	rnd "math/rand"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	dt "github.com/SimonSchneider/traefik-jwt-decode/decoder/decodertest"
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
	uncachedSrv, cachedSrv *Server
	tokens                 = make([]string, nTokens, nTokens)
)

func TestNoAuthHeaderIsOKWithoutTokenHeaders(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	serverTest(func(srv *Server) func(*testing.T) {
		return func(t *testing.T) {
			srv.DecodeToken(rr, req)
			status := rr.Result().StatusCode
			dt.Report(t, status != http.StatusOK, "no token should be ok got %d", status)
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
		t.Run(name, serverTest(func(srv *Server) func(*testing.T) {
			return func(t *testing.T) {
				rr, req := reqFor(tc.token)
				srv.DecodeToken(rr, req)
				status := rr.Result().StatusCode
				dt.Report(t, status != tc.code, "incorrect server response, %d, expected: %d", status, tc.code)
			}
		}))
	}
}

func TestServerResponseHeaders(t *testing.T) {
	serverTest(func(srv *Server) func(t *testing.T) {
		return func(t *testing.T) {
			rndClaim := strconv.FormatInt(rnd.Int63(), 10)
			rr, req := reqFor(validToken(rndClaim))
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

func serverTest(subTest func(s *Server) func(t *testing.T)) func(t *testing.T) {
	return func(t *testing.T) {
		t.Run("unCachedServer", subTest(uncachedSrv))
		t.Run("cachedServer", subTest(cachedSrv))
	}
}

func BenchmarkFull(b *testing.B) {
	for i := 0; i < nTokens; i++ {
		tokens[i] = fmt.Sprintf("Bearer %s", validRndToken())
	}
	b.Run("benchmark uncached server serial", benchmarkServerSerial(uncachedSrv))
	b.Run("benchmark uncached server parallel", benchmarkServerParallel(uncachedSrv))
	b.Run("benchmark cached server serial", benchmarkServerSerial(cachedSrv))
	b.Run("benchmark cached server parallel", benchmarkServerParallel(cachedSrv))
}

func benchmarkServerSerial(srv *Server) func(b *testing.B) {
	return func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			req, _ := http.NewRequest("GET", "/", nil)
			req.Header.Add(authHeaderKey, tokens[i%nTokens])
			rr := httptest.NewRecorder()
			srv.DecodeToken(rr, req)
		}
	}
}

func benchmarkServerParallel(srv *Server) func(b *testing.B) {
	return func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				req, _ := http.NewRequest("GET", "/", nil)
				req.Header.Add(authHeaderKey, tokens[rnd.Intn(nTokens)])
				rr := httptest.NewRecorder()
				srv.DecodeToken(rr, req)
			}
		})
	}
}

func reqFor(token []byte) (*httptest.ResponseRecorder, *http.Request) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add(authHeaderKey, fmt.Sprintf("Bearer %s", token))
	rr := httptest.NewRecorder()
	return rr, req
}

func validRndToken() []byte {
	return dt.NewValidToken(newRndClaims())
}

func invalidRndToken() []byte {
	return dt.NewInvalidToken(newRndClaims())
}

func validToken(rndClaimVal string) []byte {
	return dt.NewValidToken(newClaims(rndClaimVal))
}

func expiredRndToken() []byte {
	return dt.NewExpiredToken(newRndClaims())
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
	var err error
	var dec, cachedDec TokenDecoder
	dec, err = NewJwsDecoder(dt.JwksUrl, claimMappings)
	dt.HandleByPanic(err)
	cachedDec, err = NewCachedJwtDecoder(dec)
	dt.HandleByPanic(err)
	uncachedSrv, err = NewServer(dec, authHeaderKey)
	dt.HandleByPanic(err)
	cachedSrv, err = NewServer(cachedDec, authHeaderKey)
	dt.HandleByPanic(err)
}
