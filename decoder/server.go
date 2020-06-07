package decoder

import (
	"fmt"
	"net/http"
	"strings"
)

// Server is a http handler that will use a decoder to decode the authHeaderKey JWT-Token
// and put the resulting claims in headers
type Server struct {
	decoder       TokenDecoder
	authHeaderKey string
}

// NewServer returns a new server that will decode the header with key authHeaderKey
// with the given TokenDecoder decoder.
func NewServer(decoder TokenDecoder, authHeaderKey string) (*Server, error) {
	return &Server{decoder: decoder, authHeaderKey: authHeaderKey}, nil
}

// DecodeToken http handler
func (s *Server) DecodeToken(rw http.ResponseWriter, r *http.Request) {
	if _, ok := r.Header[s.authHeaderKey]; !ok {
		rw.WriteHeader(http.StatusOK)
		return
	}
	authHeader := r.Header.Get(s.authHeaderKey)
	t, err := s.decoder.Decode(strings.TrimPrefix(authHeader, "Bearer "))
	if err != nil {
		fmt.Printf("unable to validate token: %v\n", err)
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}
	for k, v := range t.Claims {
		rw.Header().Set(k, v)
	}
	rw.WriteHeader(http.StatusOK)
	return
}
