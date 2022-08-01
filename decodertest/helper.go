package decodertest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/SimonSchneider/traefik-jwt-decode/decoder"

	"github.com/rs/zerolog"

	"github.com/rs/zerolog/log"

	"github.com/dgraph-io/ristretto"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
)

const (
	// AuthHeaderKey for the test
	AuthHeaderKey = "Authorization"
	// TokenValidatedHeaderKey for the test
	TokenValidatedHeaderKey = "jwt-token-validated"
	// AuthHeaderRequired for the test
	AuthHeaderRequired = false
)

var (
	// Cache to be reused between all tests
	Cache, _ = ristretto.NewCache(&ristretto.Config{
		NumCounters: 1e7,     // number of keys to track frequency of (10M).
		MaxCost:     1 << 30, // maximum cost of cache (1GB).
		BufferItems: 64,      // number of keys per Get buffer.
		Metrics:     true,
	})
)

// TestConfig holds most config used for tests also starts a JWKS server
type TestConfig struct {
	// JwksURL is where the JWKS is hosted
	JwksURL    string
	privateKey *rsa.PrivateKey
	opts       jws.SignOption
}

// NewTest creates a new test config
func NewTest() *TestConfig {
	var jwkKey jwk.Key
	tc := &TestConfig{}
	tc.privateKey, jwkKey = generateKey()
	jwkKeyID := jwkKey.KeyID()
	tc.opts = options(jwkKeyID)
	jwks := jwk.NewSet()
	jwks.Add(jwkKey)
	tc.JwksURL = startJwksServer(jwks)
	return tc
}

func options(kid string) jws.SignOption {
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

func startJwksServer(jwks jwk.Set) string {
	keys, err := json.Marshal(jwks)
	HandleByPanic(err)
	listener, err := net.Listen("tcp", ":0")
	HandleByPanic(err)
	path := "/.well-known/jwks.json"
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc(path, func(rw http.ResponseWriter, r *http.Request) {
			rw.WriteHeader(http.StatusOK)
			rw.Write(keys)
		})
		panic(http.Serve(listener, mux))
	}()
	return fmt.Sprintf("http://0.0.0.0:%d%s", listener.Addr().(*net.TCPAddr).Port, path)
}

// NewValidToken generates a signed valid token with the given claims
func (tc *TestConfig) NewValidToken(claims map[string]interface{}) []byte {
	return tc.newSignedToken(claims, time.Now().Add(time.Hour*24), tc.privateKey)
}

// NewExpiredToken generates a signed but expired token with the given claims
func (tc *TestConfig) NewExpiredToken(claims map[string]interface{}) []byte {
	return tc.newSignedToken(claims, time.Now().Add(-time.Hour*24), tc.privateKey)
}

// NewInvalidToken generates a token signed with a key that does not exist in the JWKS
func (tc *TestConfig) NewInvalidToken(claims map[string]interface{}) []byte {
	privKey, _ := generateKey()
	return tc.newSignedToken(claims, time.Now().Add(time.Hour*24), privKey)
}

func (tc *TestConfig) newSignedToken(claims map[string]interface{}, exp time.Time, key *rsa.PrivateKey) []byte {
	t := jwt.New()
	for k, v := range claims {
		t.Set(k, v)
	}
	t.Set(jwt.ExpirationKey, exp)
	buf, err := json.MarshalIndent(t, "", "  ")
	HandleByPanic(err)
	token, err := jws.Sign(buf, jwa.RS256, key, tc.opts)
	HandleByPanic(err)
	return token
}

func (tc *TestConfig) newJwsDecoder(claimMappings map[string]string) decoder.TokenDecoder {
	d, err := decoder.NewJwsDecoder(tc.JwksURL, claimMappings)
	HandleByPanic(err)
	return d
}

func (tc *TestConfig) newCachedDecoder(claimMappings map[string]string) decoder.TokenDecoder {
	d := tc.newJwsDecoder(claimMappings)
	return decoder.NewCachedJwtDecoder(Cache, d)
}

// UncachedServer creates an uncached server
func (tc *TestConfig) UncachedServer(claimMappings map[string]string) *decoder.Server {

	return decoder.NewServer(tc.newJwsDecoder(claimMappings), AuthHeaderKey, TokenValidatedHeaderKey, AuthHeaderRequired)
}

// CachedServer creates a cached server
func (tc *TestConfig) CachedServer(claimMappings map[string]string) *decoder.Server {
	return decoder.NewServer(tc.newCachedDecoder(claimMappings), AuthHeaderKey, TokenValidatedHeaderKey, AuthHeaderRequired)
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

// Ctx creates a new test config with a logger
func Ctx() context.Context {
	return log.Logger.WithContext(context.Background())
}

func init() {
	log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout}).With().Timestamp().Caller().Logger().Level(zerolog.TraceLevel)
}
