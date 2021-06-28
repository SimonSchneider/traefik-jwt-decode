package decoder_test

import (
	"testing"

	dt "github.com/SimonSchneider/traefik-jwt-decode/decodertest"

	"github.com/SimonSchneider/traefik-jwt-decode/decoder"
)

func TestInvalidJwksURLFailsFast(t *testing.T) {
	claimMapping := make(map[string]string)
	_, err := decoder.NewJwsDecoder("https://this.com/does/not/exist", claimMapping)
	dt.Report(t, err == nil, "able to create jws decoder with incorrect jwks url")
}

func TestTokenWithInvalidClaims(t *testing.T) {
	invalidTokens := map[string]interface{}{
		"int":    123,
		"double": 123.321,
		"struct": struct{ key string }{key: "123"},
	}
	tc := dt.NewTest()
	claimKey := "claimKey"
	claimMapping := map[string]string{
		claimKey: "claim-email",
	}
	dec, _ := decoder.NewJwsDecoder(tc.JwksURL, claimMapping)
	for k, v := range invalidTokens {
		token := tc.NewValidToken(map[string]interface{}{claimKey: v})
		resp, err := dec.Decode(dt.Ctx(), string(token))
		dt.Report(t, err != nil, "not able to decode token with unusual JSON type: (%s : %+v) into %+v", k, v, resp)
	}
}
