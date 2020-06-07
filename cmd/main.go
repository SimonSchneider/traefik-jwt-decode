package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/SimonSchneider/traefik-jwt-decode/decoder"
)

const (
	defaultAuthHeaderKey        = "Authorization"
	defaultPort                 = "8080"
	defaultClaimMappingFilePath = "config.json"
)

func main() {
	conf, err := parseConfig()
	if err != nil {
		panic(err)
	}
	dec, err := defaultDecoder(conf)
	if err != nil {
		panic(err)
	}
	srv, err := decoder.NewServer(dec, conf.authHeaderKey)
	if err != nil {
		panic(err)
	}
	serve := fmt.Sprintf(":%s", conf.port)
	done := make(chan struct{})
	go func() {
		http.HandleFunc("/", srv.DecodeToken)
		http.ListenAndServe(serve, nil)
		done <- struct{}{}
	}()
	fmt.Println("server running on", serve)
	for k, v := range conf.claimMapping {
		fmt.Printf("mapping claim %s to header %s\n", k, v)
	}
	<-done
}

func defaultDecoder(conf config) (decoder.TokenDecoder, error) {
	keySupplier, err := decoder.RemoteKeySupplier(conf.jwksURL)
	if err != nil {
		return nil, err
	}
	jwsDec, err := decoder.NewJwsDecoder(keySupplier, conf.claimMapping)
	if err != nil {
		return nil, err
	}
	cachedDec, _, err := decoder.NewCachedJwtDecoder(jwsDec)
	return cachedDec, err
}

type config struct {
	jwksURL       string
	authHeaderKey string
	port          string
	claimMapping  map[string]string
}

func parseConfig() (conf config, err error) {
	claimMappingFilePath := getEnvDefault("CLAIM_MAPPING_FILE_PATH", defaultClaimMappingFilePath)
	claimMappingFile, err := os.Open(claimMappingFilePath)
	if err != nil {
		return config{}, err
	}
	defer claimMappingFile.Close()
	err = json.NewDecoder(claimMappingFile).Decode(&conf.claimMapping)
	if err != nil {
		return config{}, err
	}
	conf.authHeaderKey = getEnvDefault("AUTH_HEADER_KEY", defaultAuthHeaderKey)
	conf.port = getEnvDefault("PORT", defaultPort)
	conf.jwksURL, err = getEnv("JWKS_URL")
	return
}

func getEnvDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getEnv(key string) (string, error) {
	if val := os.Getenv(key); val != "" {
		return val, nil
	}
	return "", fmt.Errorf("required key %s not found in env", key)
}
