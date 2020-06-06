package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	rnd "math/rand"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
)

const (
	nTokens           = 5000
	exp               = "exp"
	randomClaim       = "rnd-claim"
	randomClaimHeader = "test-token-random-claim"
	authHeaderKey     = "Authorization"
	jwksKeyID         = "auth#0"
)

var (
	allClaims = map[string]string{
		"claim1":     "claim number 1",
		"claim2":     "claim number 2",
		"claim3":     "claim number 3",
		"otherClaim": "this-claim-is-not-set",
	}
	pk, _         = rsa.GenerateKey(rand.Reader, 2048)
	claimMappings = map[string]string{
		"claim1":    "test-token-claim1",
		"claim2":    "test-token-claim2",
		"claim3":    "test-token-claim3",
		randomClaim: randomClaimHeader,
	}
	dec, _ = NewDecoder(func() (interface{}, error) {
		return pk.PublicKey, nil
	}, claimMappings)
	cachedDec, printStats, _ = NewCachedJwtDecoder(dec)
	srv, _                   = NewServer(cachedDec, authHeaderKey)
	o                        = options()
	tokens                   []string
)

func TestToken(t *testing.T) {
	token, err := newSignedToken()
	if err != nil {
		t.Errorf("couldn't create token %v", err)
	}
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add(authHeaderKey, fmt.Sprintf("Bearer %s", token))
	rr := httptest.NewRecorder()
	srv.DecodeToken(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("incorrect response %d", status)
	}
	headers := rr.Header()
	if val := headers.Get(randomClaimHeader); val == "" {
		t.Fatal("random header not found in response", val)
	}
	for claimKey, headerKey := range claimMappings {
		if headerKey == randomClaimHeader {
			continue
		}
		headerVal := headers.Get(headerKey)
		if headerVal == "" {
			t.Fatalf("claim %s not found in header", headerKey)
		}
		claimVal := allClaims[claimKey]
		if headerVal != claimVal {
			t.Fatalf("claim %s has incorrect value %s, expected %s", claimKey, headerVal, claimVal)
		}
	}
}

func BenchmarkFull(b *testing.B) {
	tokens = make([]string, nTokens, nTokens)
	for i := 0; i < nTokens; i++ {
		token, err := newSignedToken()
		if err != nil {
			panic(err)
		}
		tokens[i] = fmt.Sprintf("Bearer %s", token)
	}
	b.Run("benchmark token", benchmarkToken)
	printStats()
}

func benchmarkToken(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := rnd.Intn(nTokens)
			req, _ := http.NewRequest("GET", "/entries", nil)
			req.Header.Add("Authorization", tokens[i])
			rr := httptest.NewRecorder()
			srv.DecodeToken(rr, req)
		}
	})
}

func options() jws.Option {
	h := jws.NewHeaders()
	h.Set(jws.TypeKey, "JWT")
	h.Set(jws.KeyIDKey, jwksKeyID)
	return jws.WithHeaders(h)
}

func newSignedToken() ([]byte, error) {
	t := jwt.New()
	for k, v := range allClaims {
		t.Set(k, v)
	}
	t.Set(exp, time.Now().Add(time.Hour*24))
	t.Set(randomClaim, strconv.FormatInt(rnd.Int63(), 10))

	buf, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return nil, err
	}

	return jws.Sign(buf, jwa.RS256, pk, o)
}
