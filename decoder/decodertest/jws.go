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
	PrivateKey *rsa.PrivateKey
	JwkKey     jwk.Key
	JwkKeyID   string
	opts       jws.Option
	JwksUrl    string
	Jwks       *jwk.Set
)

func init() {
	PrivateKey, JwkKey = generateKey()
	JwkKeyID = JwkKey.KeyID()
	opts = options(JwkKeyID)
	Jwks = &jwk.Set{Keys: []jwk.Key{JwkKey}}
	JwksUrl = startJwksServer()
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
	jwk.AssignKeyID(jwkKey)
	jwkKey.Set(jwk.AlgorithmKey, jwa.RS256)
	jwkKey.Set(jwk.KeyUsageKey, jwk.ForSignature)
	return privKey, jwkKey
}

func startJwksServer() string {
	keys, err := json.Marshal(Jwks)
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
	return newSignedToken(claims, time.Now().Add(time.Hour*24), PrivateKey)
}

// NewExpiredToken generates a signed but expired token with the given claims
func NewExpiredToken(claims map[string]interface{}) []byte {
	return newSignedToken(claims, time.Now().Add(-time.Hour*24), PrivateKey)
}

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

func Report(t *testing.T, pred bool, message string, args ...interface{}) {
	if pred {
		t.Fatalf(message, args...)
	}
}

func HandleByPanic(err error) {
	if err != nil {
		panic(err)
	}
}
