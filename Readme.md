# Traefik JWT Decode

![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/SimonSchneider/traefik-jwt-decode)
![Docker Image Size (latest by date)](https://img.shields.io/docker/image-size/simonschneider/traefik-jwt-decode)
[![Coverage](http://gocover.io/_badge/github.com/SimonSchneider/traefik-jwt-decode/decoder)](http://gocover.io/github.com/SimonSchneider/traefik-jwt-decode/decoder)
[![Go Report Card](https://goreportcard.com/badge/github.com/SimonSchneider/traefik-jwt-decode)](https://goreportcard.com/report/github.com/SimonSchneider/traefik-jwt-decode)

[Traefik Forward auth](https://docs.traefik.io/middlewares/forwardauth/)
implementation that decodes and validates JWT (JWS) tokens and populates
headers with configurable claims from the token.
The tokens are validated using jwks, checked for expiration and cached.
If the token is invalid, ie. can't be verified or is expired `traefik-jwt-decode`
will respond with a `UNAUTHORIZED 401`.
If the token is valid `traefik-jwt-decode` will respond with a `OK 200` and
headers mapped from the claims of the token. Traefik should be configured to
forward these headers via the `authResponseHeaders` which forwards them to the
end destination.

## Installation and usage

### Configuring and running the docker image:

minimal (with claimMapping env variable)
```
docker run \
  -e CLAIM_MAPPINGS="claim-123:header-123,claim-456:header-456" \
  -e JWKS_URL="https://www.googleapis.com/oauth2/v3/certs" \
  -p 8080:8080 \
  simonschneider/traefik-jwt-decode:latest
```

minimal (with claim file):
```
echo "{ \"claim-123\": \"header-123\" }" > config.json

docker run \
  -v $(pwd)/config.json:/config.json \
  -e JWKS_URL="https://www.googleapis.com/oauth2/v3/certs" \
  -p 8080:8080 \
  simonschneider/traefik-jwt-decode:latest
```

### Configuration reference

required configurations:
```
JWKS_URL
url pointing at the jwks json file (https://auth0.com/docs/tokens/concepts/jwks)
```

default configurations
```
CLAIM_MAPPING_FILE_PATH = config.json
AUTH_HEADER_KEY         = Authorization
PORT                    = 8080
LOG_LEVEL               = info           = trace | debug | info | warn | crit
LOG_TYPE                = json           = json | pretty
MAX_CACHE_KEYS          = 10000
```

optional configurations
```
CLAIM_MAPPINGS
set up claim mappings by env, on the format
{claim1}:{header1},{claim2}:{header2}
corresponds to the json

{
  "claim1": "header1",
  "claim2": "header2"
}
```
