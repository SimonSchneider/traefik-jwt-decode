package main

import (
	"fmt"
	"net/http"

	"github.com/SimonSchneider/traefik-jwt-decode/oauth"
)

var (
	authKeyID     = "auth-#0"
	jwksURL       = "http://api-dev.gloot.com/.well-known/jwks.json"
	authHeaderKey = "Authorization"
	port          = "8081"
	claimMapping  = map[string]string{
		"glootId":  "g-token-user-id",
		"email":    "g-token-email",
		"username": "g-token-username",
		"p":        "g-token-p",
	}
)

func main() {
	decoder, err := defaultDecoder(claimMapping)
	if err != nil {
		panic(err)
	}
	srv, err := oauth.NewServer(decoder, authHeaderKey)
	if err != nil {
		panic(err)
	}
	serve := fmt.Sprintf(":%s", port)
	done := make(chan struct{})
	go func() {
		http.HandleFunc("/", srv.DecodeToken)
		http.ListenAndServe(serve, nil)
		done <- struct{}{}
	}()
	fmt.Println("server running on", serve)
	<-done
}

func defaultDecoder(claimMapping map[string]string) (oauth.JwtDecoder, error) {
	decoder, err := oauth.NewDecoder(oauth.RemoteKeySupplier(jwksURL, authKeyID), claimMapping)
	if err != nil {
		return nil, err
	}
	cachedDec, _, err := oauth.NewCachedJwtDecoder(decoder)
	return cachedDec, err
}
