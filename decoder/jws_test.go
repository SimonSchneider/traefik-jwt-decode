package decoder_test

import (
	"testing"

	"github.com/SimonSchneider/traefik-jwt-decode/decoder"
)

var (
	claims = map[string]string{
		"email": "bob@uncle.com",
	}
	claimMapping = map[string]string{
		"email": "claim-email",
	}
)

func TestInvalidJwksURLFailsFast(t *testing.T) {
	_, err := decoder.NewJwsDecoder("https://this.com/does/not/exist", claimMapping)
	Report(t, err == nil, "able to create jws decoder with incorrect jwks url")
}

func TestTokenWithInvalidClaims(t *testing.T) {
	invalidTokens := map[string]interface{}{
		"int":    123,
		"double": 123.321,
		"struct": struct{ key string }{key: "123"},
	}
	dec, _ := decoder.NewJwsDecoder(JwksURL, claimMapping)
	for k, v := range invalidTokens {
		token := NewValidToken(map[string]interface{}{"email": v})
		resp, err := dec.Decode(string(token))
		Report(t, err == nil, "able to decode token with unexpected type: (%s : %+v) into %+v", k, v, resp)
	}
}
