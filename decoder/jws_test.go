package decoder_test

import (
	"context"
	"testing"

	"github.com/SimonSchneider/traefik-jwt-decode/decoder"
	"github.com/rs/zerolog/log"
)

func TestInvalidJwksURLFailsFast(t *testing.T) {
	claimMapping := make(map[string]string)
	_, err := decoder.NewJwsDecoder("https://this.com/does/not/exist", claimMapping)
	Report(t, err == nil, "able to create jws decoder with incorrect jwks url")
}

func TestTokenWithInvalidClaims(t *testing.T) {
	invalidTokens := map[string]interface{}{
		"int":    123,
		"double": 123.321,
		"struct": struct{ key string }{key: "123"},
	}
	tc := newTest()
	claimKey := "claimKey"
	claimMapping := map[string]string{
		claimKey: "claim-email",
	}
	dec, _ := decoder.NewJwsDecoder(tc.JwksURL, claimMapping)
	for k, v := range invalidTokens {
		token := tc.NewValidToken(map[string]interface{}{claimKey: v})
		ctx := log.Logger.WithContext(context.Background())
		resp, err := dec.Decode(ctx, string(token))
		Report(t, err == nil, "able to decode token with unexpected type: (%s : %+v) into %+v", k, v, resp)
	}
}
