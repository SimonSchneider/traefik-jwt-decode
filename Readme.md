# Traefik JWT Decode

[![](https://images.microbadger.com/badges/version/simonschneider/traefik-jwt-decode.svg)](https://hub.docker.com/repository/docker/simonschneider/traefik-jwt-decode)
[![Coverage](http://gocover.io/_badge/github.com/SimonSchneider/traefik-jwt-decode/oauth?0)](http://gocover.io/github.com/SimonSchneider/traefik-jwt-decode/oauth)

Traefik Forward auth implementation that decodes and validates JWT tokens and populates headers with configurable claims from the token.
The tokens are validated using jwks, checked for expiration and cached until 2 minutes before expiration for faster responses on subsequent requests.
