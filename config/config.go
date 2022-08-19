package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	prom "github.com/prometheus/client_golang/prometheus"

	"github.com/rs/cors"
	"github.com/rs/zerolog/log"

	"github.com/rs/zerolog/hlog"

	"github.com/SimonSchneider/traefik-jwt-decode/decoder"
	"github.com/dgraph-io/ristretto"
	"github.com/rs/zerolog"
)

// Env variable constants
const (
	JwksURLEnv                  = "JWKS_URL"
	ForceJwksOnStart            = "FORCE_JWKS_ON_START"
	ForceJwksOnStartDefault     = "true"
	ClaimMappingFileEnv         = "CLAIM_MAPPING_FILE_PATH"
	ClaimMappingFileDefault     = "config.json"
	AuthHeaderEnv               = "AUTH_HEADER_KEY"
	AuthHeaderDefault           = "Authorization"
	TokenValidatedHeaderEnv     = "TOKEN_VALIDATED_HEADER_KEY"
	TokenValidatedHeaderDefault = "jwt-token-validated"
	AuthHeaderRequired          = "AUTH_HEADER_REQUIRED"
	AuthHeaderRequiredDefault   = "false"
	PortEnv                     = "PORT"
	PortDefault                 = "8080"
	LogLevelEnv                 = "LOG_LEVEL"
	LogLevelDefault             = "info"
	LogTypeEnv                  = "LOG_TYPE"
	LogTypeDefault              = "json"
	MaxCacheKeysEnv             = "MAX_CACHE_KEYS"
	MaxCacheKeysDefault         = "10000"
	CacheEnabledEnv             = "CACHE_ENABLED"
	CacheEnabledDefault         = "true"
	ClaimMappingsEnv            = "CLAIM_MAPPINGS"
)

// NewConfig creates a new Config from the current env
func NewConfig() *Config {
	var c Config
	c.jwksURL = required(JwksURLEnv)
	c.forceJwksOnStart = withDefault(ForceJwksOnStart, ForceJwksOnStartDefault)
	c.claimMappingFilePath = withDefault(ClaimMappingFileEnv, ClaimMappingFileDefault)
	c.authHeader = withDefault(AuthHeaderEnv, AuthHeaderDefault)
	c.tokenValidatedHeader = withDefault(TokenValidatedHeaderEnv, TokenValidatedHeaderDefault)
	c.authHeaderRequired = withDefault(AuthHeaderRequired, AuthHeaderRequiredDefault)
	c.port = withDefault(PortEnv, PortDefault)
	c.logLevel = withDefault(LogLevelEnv, LogLevelDefault)
	c.logType = withDefault(LogTypeEnv, LogTypeDefault)
	c.maxCacheKeys = withDefault(MaxCacheKeysEnv, MaxCacheKeysDefault)
	c.cacheEnabled = withDefault(CacheEnabledEnv, CacheEnabledDefault)
	c.claimMappings = optional(ClaimMappingsEnv)
	c.keyCost = 100
	return &c
}

// Config to bootstrap decoder server
type Config struct {
	jwksURL              envVar
	forceJwksOnStart     envVar
	claimMappingFilePath envVar
	authHeader           envVar
	tokenValidatedHeader envVar
	authHeaderRequired   envVar
	port                 envVar
	logLevel             envVar
	logType              envVar
	maxCacheKeys         envVar
	cacheEnabled         envVar
	claimMappings        envVar
	keyCost              int64
}

func (c *Config) PingHandler(rw http.ResponseWriter, r *http.Request) {
	log.Debug().Msg("Ping OK")
	rw.WriteHeader(http.StatusOK)
	return
}

// type MyServer struct {
// 	r *http.ServeMux
// }

// func (s MyServer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
// 	fmt.Println("\n\n\n OVERRIDE \n\n\n,", req.Method, req.Header.Get("Origin"))

// 	// if origin := req.Header.Get("Origin"); origin != "" {
// 	rw.Header().Set("Access-Control-Allow-Origin", "*")
// 	rw.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
// 	rw.Header().Set("Access-Control-Allow-Headers",
// 		"Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
// 	// }
// 	// Stop here if its Preflighted OPTIONS request
// 	if req.Method == "OPTIONS" {
// 		fmt.Println("\n\n\nRETURNING\n\n\n")
// 		rw.WriteHeader(http.StatusOK)
// 		return
// 	}
// 	// Lets Gorilla work
// 	s.r.ServeHTTP(rw, req)
// }

// RunServer starts a server from the config
func (c *Config) RunServer() (chan error, net.Listener) {
	logger := c.getLogger()
	log.Logger = logger
	registry := prom.NewRegistry()
	server := c.getServer(registry)
	var handler http.HandlerFunc = server.DecodeToken
	var pingHandler http.HandlerFunc = c.PingHandler
	histogramMw := histogramMiddleware(registry)
	loggingMiddleWare := hlog.NewHandler(logger)
	serve := fmt.Sprintf(":%s", c.port.get())
	done := make(chan error)
	listener, err := net.Listen("tcp", serve)
	if err != nil {
		panic(err)
	}
	go func() {
		srv := &http.Server{}
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
		mux.Handle("/ping", pingHandler)
		mux.Handle("/", histogramMw(loggingMiddleWare(handler)))

		h := cors.New(cors.Options{
			Debug:          true,
			AllowedOrigins: []string{"*"},
			AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders: []string{"*"},
		}).Handler(mux)
		srv.Handler = h
		done <- srv.Serve(listener)
		close(done)
	}()
	log.Info().Msgf("server running on %s", serve)
	return done, listener
}

func (c *Config) getServer(r *prom.Registry) *decoder.Server {
	jwksURL := c.jwksURL.get()
	claimMappings := c.getClaimMappings()
	jwsDec, err := decoder.NewJwsDecoder(jwksURL, claimMappings)
	if err != nil {
		if c.forceJwksOnStart.getBool() {
			panic(err)
		} else {
			log.Warn().Err(err).Msg("will try again")
		}
	}
	claimMsg := zerolog.Dict()
	for k, v := range claimMappings {
		claimMsg.Str(k, v)
	}
	log.Info().Dict("mappings", claimMsg).Msg("mappings from claim keys to header")
	var dec decoder.TokenDecoder
	if c.cacheEnabled.getBool() {
		dec = decoder.NewCachedJwtDecoder(c.getCache(r), jwsDec)
	} else {
		dec = jwsDec
	}
	return decoder.NewServer(dec, c.authHeader.get(), c.tokenValidatedHeader.get(), c.authHeaderRequired.getBool())
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

func (c *Config) getCache(r *prom.Registry) *ristretto.Cache {
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
	c.registerCacheMetrics(r, cache)
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
		if len(mapping) == 0 {
			continue
		}
		lastInd := strings.LastIndex(mapping, ":")
		if lastInd == -1 {
			return fmt.Errorf("unexpected number of ':' in claim mapping '%s'", mapping)
		}
		key := mapping[:lastInd]
		value := mapping[lastInd+1:]
		c[key] = value
	}
	return nil
}

func histogramMiddleware(r *prom.Registry) func(handler http.Handler) http.Handler {
	hist := prom.NewHistogramVec(histOpts("requests"), []string{})
	r.MustRegister(hist)
	return func(next http.Handler) http.Handler {
		return promhttp.InstrumentHandlerDuration(hist, next)
	}
}

func (c *Config) registerCacheMetrics(r *prom.Registry, cache *ristretto.Cache) {
	m := cache.Metrics
	hr := prom.NewGaugeFunc(cacheOpts("hit_ratio"), m.Ratio)
	r.MustRegister(hr)
	hit := prom.NewGaugeFunc(cacheOpts("requests", "outcome", "hit"), func() float64 {
		return float64(m.Hits())
	})
	r.MustRegister(hit)
	miss := prom.NewGaugeFunc(cacheOpts("requests", "outcome", "miss"), func() float64 {
		return float64(m.Misses())
	})
	r.MustRegister(miss)
}

func cacheOpts(name string, labels ...string) prom.GaugeOpts {
	return prom.GaugeOpts{Namespace: "traefik_jwt_decode", Subsystem: "cache", Name: name,
		ConstLabels: promLabels(labels)}
}

func histOpts(name string, labels ...string) prom.HistogramOpts {
	return prom.HistogramOpts{Namespace: "traefik_jwt_decode", Subsystem: "http_server", Name: name,
		ConstLabels: promLabels(labels), Buckets: []float64{0.001, 0.005, 0.01, 0.02, 0.05, 0.1}}
}

func promLabels(labels []string) prom.Labels {
	labelMap := make(map[string]string)
	if len(labels)%2 != 0 {
		panic("labels need to be defined in pairs")
	}
	for i := 0; i < len(labels); i += 2 {
		labelMap[labels[i]] = labels[i+1]
	}
	return labelMap
}

type envVar struct {
	name, defaultValue string
	required           bool
}

func withDefault(name, defaultValue string) envVar {
	return envVar{name: name, defaultValue: defaultValue, required: true}
}

func required(name string) envVar {
	return envVar{name: name, defaultValue: "", required: true}
}

func optional(name string) envVar {
	return envVar{name: name, defaultValue: "", required: false}
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

func (e envVar) getBool() (val bool) {
	str := e.get()
	switch str {
	case "true":
		return true
	case "false":
		return false
	default:
		panic(fmt.Errorf("unknown bool value %s", str))
	}
}
