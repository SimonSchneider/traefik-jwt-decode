package decodertest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
)

var (
	// JwksURL is where the JWKS is hosted
	JwksURL    string
	privateKey *rsa.PrivateKey
	opts       jws.Option
)

func init() {
	var jwkKey jwk.Key
	privateKey, jwkKey = generateKey()
	jwkKeyID := jwkKey.KeyID()
	opts = options(jwkKeyID)
	jwks := &jwk.Set{Keys: []jwk.Key{jwkKey}}
	JwksURL = startJwksServer(jwks)
}

func options(kid string) jws.Option {
	h := jws.NewHeaders()
	h.Set(jws.TypeKey, "JWT")
	h.Set(jws.KeyIDKey, kid)
	return jws.WithHeaders(h)
}

func generateKey() (*rsa.PrivateKey, jwk.Key) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	HandleByPanic(err)
	jwkKey, err := jwk.New(privKey.PublicKey)
	HandleByPanic(err)
	jwk.AssignKeyID(jwkKey)
	jwkKey.Set(jwk.AlgorithmKey, jwa.RS256)
	jwkKey.Set(jwk.KeyUsageKey, jwk.ForSignature)
	return privKey, jwkKey
}

func startJwksServer(jwks *jwk.Set) string {
	keys, err := json.Marshal(jwks)
	HandleByPanic(err)
	listener, err := net.Listen("tcp", ":0")
	HandleByPanic(err)
	path := "/.well-known/jwks.json"
	go func() {
		http.HandleFunc(path, func(rw http.ResponseWriter, r *http.Request) {
			rw.WriteHeader(http.StatusOK)
			rw.Write(keys)
		})
		panic(http.Serve(listener, nil))
	}()
	return fmt.Sprintf("http://0.0.0.0:%d%s", listener.Addr().(*net.TCPAddr).Port, path)
}

// NewValidToken generates a signed valid token with the given claims
func NewValidToken(claims map[string]interface{}) []byte {
	return newSignedToken(claims, time.Now().Add(time.Hour*24), privateKey)
}

// NewExpiredToken generates a signed but expired token with the given claims
func NewExpiredToken(claims map[string]interface{}) []byte {
	return newSignedToken(claims, time.Now().Add(-time.Hour*24), privateKey)
}

// NewInvalidToken generates a token signed with a key that does not exist in the JWKS
func NewInvalidToken(claims map[string]interface{}) []byte {
	privKey, _ := generateKey()
	return newSignedToken(claims, time.Now().Add(time.Hour*24), privKey)
}

func newSignedToken(claims map[string]interface{}, exp time.Time, key *rsa.PrivateKey) []byte {
	t := jwt.New()
	for k, v := range claims {
		t.Set(k, v)
	}
	t.Set(jwt.ExpirationKey, exp)
	buf, err := json.MarshalIndent(t, "", "  ")
	HandleByPanic(err)
	token, err := jws.Sign(buf, jwa.RS256, key, opts)
	HandleByPanic(err)
	return token
}

// Report the error message to testing if the condition is met
func Report(t *testing.T, condition bool, message string, args ...interface{}) {
	if condition {
		t.Fatalf(message, args...)
	}
}

// HandleByPanic handles a non nil error by panicing
func HandleByPanic(err error) {
	if err != nil {
		panic(err)
	}
}
