package decoder_test

import (
	"testing"

	dt "github.com/SimonSchneider/traefik-jwt-decode/decodertest"

	"github.com/SimonSchneider/traefik-jwt-decode/decoder"
)

func TestInvalidJwksURLGivesWarning(t *testing.T) {
	claimMapping := make(map[string]string)
	dec, err := decoder.NewJwsDecoder("https://this.com/does/not/exist", claimMapping)
	dt.Report(t, dec == nil && err == nil, "not able to create jws decoder with incorrect jwks url, and no warning given: %s", err)
}

func TestValidJwksURL(t *testing.T) {
	claimMapping := make(map[string]string)
	dec, err := decoder.NewJwsDecoder("https://www.googleapis.com/oauth2/v3/certs", claimMapping)
	dt.Report(t, dec == nil || err != nil, "not able to create jws decoder with correct jwks url")
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

func TestTokenWithNestedClaims(t *testing.T) {
	tc := dt.NewTest()
	claimMapping := map[string]string{
		"claim1":                "claim-name",
		"claim2.nested":         "claim-email",
		"claim3:complex.nested": "claim-address",
	}
	dec, _ := decoder.NewJwsDecoder(tc.JwksURL, claimMapping)
	token := tc.NewValidToken(map[string]interface{}{
		"claim1":         "name",
		"claim2":         map[string]interface{}{"nested": "email"},
		"claim3:complex": map[string]interface{}{"nested": "address"},
	})
	resp, err := dec.Decode(dt.Ctx(), string(token))
	dt.Report(t, err != nil, "not able to decode token with nested claims: %s", err)
	dt.Report(t, resp.Claims["claim-name"] != "name", "not able to decode token: (claim1 : name) into %+v", resp)
	dt.Report(t, resp.Claims["claim-email"] != "email", "not able to decode token: (claim2 : { nested: email }) into %+v", resp)
	dt.Report(t, resp.Claims["claim-address"] != "address", "not able to decode token: (claim3:complex : { nested: address }) into %+v", resp)
}

func TestTokenWithEmptyNestedClaims(t *testing.T) {
	tc := dt.NewTest()
	claimMapping := map[string]string{
		"claim.nested": "claim-email",
	}
	dec, _ := decoder.NewJwsDecoder(tc.JwksURL, claimMapping)
	token := tc.NewValidToken(map[string]interface{}{"claim": "email"})
	resp, err := dec.Decode(dt.Ctx(), string(token))
	dt.Report(t, err != nil, "not able to decode token with conflicting nested claims: %+v", resp)
	dt.Report(t, resp.Claims["claim-email"] != "", "decoded token should contain no claim: %+v", resp)
}
