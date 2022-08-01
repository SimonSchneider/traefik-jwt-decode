package decoder

import (
	"fmt"
	"net/http"
	"strings"

	zLog "github.com/rs/zerolog/log"
)

const (
	statusKey = "status"
)

// Server is a http handler that will use a decoder to decode the authHeaderKey JWT-Token
// and put the resulting claims in headers
type Server struct {
	decoders                []TokenDecoder
	authHeaderKey           string
	tokenValidatedHeaderKey string
	authHeaderRequired      bool
}

type statuses struct {
	err    error
	status int
}

// NewServer returns a new server that will decode the header with key authHeaderKey
// with the given TokenDecoder decoder.
func NewServer(decoders []TokenDecoder, authHeaderKey, tokenValidatedHeaderKey string, authHeaderRequired bool) *Server {
	return &Server{decoders: decoders, authHeaderKey: authHeaderKey, tokenValidatedHeaderKey: tokenValidatedHeaderKey, authHeaderRequired: authHeaderRequired}
}

// DecodeToken http handler
func (s *Server) DecodeToken(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := zLog.Ctx(ctx)
	if _, ok := r.Header[s.authHeaderKey]; !ok {
		var status int
		if s.authHeaderRequired {
			status = http.StatusUnauthorized
			log.Warn().Int(statusKey, status).Msgf("no auth header %s, early exit", s.authHeaderKey)
		} else {
			status = http.StatusOK
			rw.Header().Set(s.tokenValidatedHeaderKey, "false")
			log.Debug().Int(statusKey, http.StatusOK).Str(s.tokenValidatedHeaderKey, "false").Msgf("no auth header %s, early exit", s.authHeaderKey)
		}
		rw.WriteHeader(status)
		return
	}
	authHeader := r.Header.Get(s.authHeaderKey)

	// var errs []statuses
	for _, d := range s.decoders {
		t, err := d.Decode(ctx, strings.TrimPrefix(authHeader, "Bearer "))

		if err != nil {
			log.Warn().Err(err).Int(statusKey, http.StatusUnauthorized).Msg("unable to decode token")
			// errs = append(errs, statuses{err: err, status: http.StatusUnauthorized})
			rw.WriteHeader(http.StatusUnauthorized)
			continue
		}

		if err = t.Validate(); err != nil {
			// errs = append(errs, statuses{err: err, status: http.StatusUnauthorized})
			log.Warn().Err(err).Int(statusKey, http.StatusUnauthorized).Msg("unable to validate token")
			rw.WriteHeader(http.StatusUnauthorized)
			continue
		}

		le := log.Debug()
		for k, v := range t.Claims {
			rw.Header().Set(k, v)
			le.Str(k, v)
		}
		fmt.Println("here")
		rw.Header().Set(s.tokenValidatedHeaderKey, "true")
		le.Str(s.tokenValidatedHeaderKey, "true")
		le.Int(statusKey, http.StatusOK).Msg("ok")
		rw.WriteHeader(http.StatusOK)
	}

}
