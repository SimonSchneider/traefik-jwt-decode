# Traefik JWT Decode

[![GitHub release](https://img.shields.io/github.com/SimonSchneider/traefik-jwt-decode.js.svg)](https://github.com/SimonSchneider/traefik-jwt-decode/releases/)
[![Coverage](http://gocover.io/_badge/github.com/SimonSchneider/traefik-jwt-decode/oauth?0)](http://gocover.io/github.com/SimonSchneider/traefik-jwt-decode/oauth)

Traefik Forward auth implementation that decodes and validates JWT tokens and populates headers with configurable claims from the token.
The tokens are validated using jwks, checked for expiration and cached until 2 minutes before expiration for faster responses on subsequent requests.
