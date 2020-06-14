package config

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/rs/zerolog/hlog"

	"github.com/SimonSchneider/traefik-jwt-decode/decoder"
	"github.com/dgraph-io/ristretto"
	"github.com/rs/zerolog"
)

// Env variable constants
const (
	JwksURLEnv              = "JWKS_URL"
	ClaimMappingFileEnv     = "CLAIM_MAPPING_FILE_PATH"
	ClaimMappingFileDefault = "config.json"
	AuthHeaderEnv           = "AUTH_HEADER_KEY"
	AuthHeaderDefault       = "Authorization"
	PortEnv                 = "PORT"
	PortDefault             = "8080"
	LogLevelEnv             = "LOG_LEVEL"
	LogLevelDefault         = "info"
	LogTypeEnv              = "LOG_TYPE"
	LogTypeDefault          = "json"
	MaxCacheKeysEnv         = "MAX_CACHE_KEYS"
	MaxCacheKeysDefault     = "10000"
	ClaimMappingsEnv        = "CLAIM_MAPPINGS"
)

// Config to bootstrap decoder server
type Config struct {
	jwksURL              envVar
	claimMappingFilePath envVar
	authHeader           envVar
	port                 envVar
	logLevel             envVar
	logType              envVar
	claimMappings        envVar
	maxCacheKeys         envVar
	keyCost              int64
}

// NewConfig creates a new Config from the current env
func NewConfig() *Config {
	var c Config
	c.jwksURL = envVar{JwksURLEnv, "", true}
	c.claimMappingFilePath = envVar{ClaimMappingFileEnv, ClaimMappingFileDefault, true}
	c.authHeader = envVar{AuthHeaderEnv, AuthHeaderDefault, true}
	c.port = envVar{PortEnv, PortDefault, true}
	c.logLevel = envVar{LogLevelEnv, LogLevelDefault, true}
	c.logType = envVar{LogTypeEnv, LogTypeDefault, true}
	c.claimMappings = envVar{ClaimMappingsEnv, "", false}
	c.maxCacheKeys = envVar{MaxCacheKeysEnv, MaxCacheKeysDefault, true}
	c.keyCost = 100
	return &c
}

// RunServer starts a server from the config
func (c *Config) RunServer() (chan error, *http.Server) {
	logger := c.getLogger()
	log.Logger = logger
	server := c.getServer()
	var handler http.HandlerFunc = server.DecodeToken
	loggingMiddleWare := hlog.NewHandler(logger)
	serve := fmt.Sprintf(":%s", c.port.get())
	done := make(chan error)
	srv := &http.Server{Addr: serve}
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/", loggingMiddleWare(handler))
		srv.Handler = mux
		done <- srv.ListenAndServe()
		close(done)
	}()
	log.Info().Msgf("server running on %s", serve)
	return done, srv
}

func (c *Config) getServer() *decoder.Server {
	jwksURL := c.jwksURL.get()
	claimMappings := c.getClaimMappings()
	jwsDec, err := decoder.NewJwsDecoder(jwksURL, claimMappings)
	if err != nil {
		panic(err)
	}
	claimMsg := zerolog.Dict()
	for k, v := range claimMappings {
		claimMsg.Str(k, v)
	}
	log.Info().Dict("mappings", claimMsg).Msg("mappings from claim keys to header")
	cachedDec := decoder.NewCachedJwtDecoder(c.getCache(), jwsDec)
	return decoder.NewServer(cachedDec, c.authHeader.get())
}

func (c *Config) getLogger() (logger zerolog.Logger) {
	switch c.logType.get() {
	case "json":
		logger = zerolog.New(os.Stdout)
	case "pretty":
		logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout})
	default:
		panic(fmt.Errorf("unknown logger type %s", c.logType.get()))
	}
	logger = logger.With().Timestamp().Caller().Logger()
	level, err := zerolog.ParseLevel(c.logLevel.get())
	if err != nil {
		panic(err)
	}
	return logger.Level(level)
}

func (c *Config) getCache() *ristretto.Cache {
	keys := c.maxCacheKeys.getInt64()
	if keys < 1 {
		panic(fmt.Errorf("Max keys need to be a positive number, was %d", keys))
	}
	cache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 1e7,              // number of keys to track frequency of (10M).
		MaxCost:     keys * c.keyCost, // maximum cost of cache (1GB).
		BufferItems: 64,               // number of keys per Get buffer.
		Metrics:     true,
	})
	if err != nil {
		panic(err)
	}
	return cache
}

func (c *Config) getClaimMappings() map[string]string {
	var claimMappings claimMappingsT = make(map[string]string)
	path := c.claimMappingFilePath.get()
	errFile := claimMappings.fromFile(path)
	if errFile != nil {
		log.Warn().Err(errFile).Msgf("unable to load file resolving from env only")
	}
	errString := claimMappings.fromString(c.claimMappings.get())
	if errString != nil {
		log.Warn().Err(errString).Msgf("unable to parse claimMappingsEnv from env")
		if errFile != nil {
			panic(fmt.Errorf("either file or env needs to be valid"))
		}
	}
	return claimMappings
}

type claimMappingsT map[string]string

func (c claimMappingsT) fromFile(path string) error {
	claimMappingFile, err := os.Open(path)
	if err != nil {
		return err
	}
	defer claimMappingFile.Close()
	return json.NewDecoder(claimMappingFile).Decode(&c)
}

func (c claimMappingsT) fromString(val string) error {
	mappings := strings.Split(val, ",")
	for _, mapping := range mappings {
		pair := strings.Split(mapping, ":")
		if len(pair) != 2 {
			return fmt.Errorf("unexpected number of ':' in claim mapping '%s'", mapping)
		}
		c[pair[0]] = pair[1]
	}
	return nil
}

type envVar struct {
	name, defaultValue string
	required           bool
}

func (e envVar) get() string {
	if val := os.Getenv(e.name); val != "" {
		return val
	}
	if e.defaultValue == "" && e.required {
		panic(fmt.Errorf("required key %s not found in env", e.name))
	}
	return e.defaultValue
}

func (e envVar) getInt64() (val int64) {
	str := e.get()
	val, err := strconv.ParseInt(str, 10, 64)
	if err != nil {
		panic(fmt.Errorf("cache size has to be an integer: %w", err))
	}
	return
}
