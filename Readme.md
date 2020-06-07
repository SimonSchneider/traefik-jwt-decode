# Traefik JWT Decode

![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/SimonSchneider/traefik-jwt-decode)
[![Coverage](http://gocover.io/_badge/github.com/SimonSchneider/traefik-jwt-decode/decoder?0)](http://gocover.io/github.com/SimonSchneider/traefik-jwt-decode/decoder)
![Docker Image Size (latest by date)](https://img.shields.io/docker/image-size/simonschneider/traefik-jwt-decode)

Traefik Forward auth implementation that decodes and validates JWT tokens and populates headers with configurable claims from the token.
The tokens are validated using jwks, checked for expiration and cached until 2 minutes before expiration for faster responses on subsequent requests.

## Installation and usage

### Configuring and running the docker image:

minimal:

```
echo "{ \"claim-123\": \"header-123\" " > config.json

docker run -v $(pwd)/config.json:/config/config.json -e JWKS_URL="http://some.com/.well-known/jwks.json" -p 8080:8080 simonschneider/traefik-jwt-decode:latest
```

available configuration:

| Type | Configuration               | Description                                                                        | Example                                                      | Default         |
| ---- | --------------------------- | ---------------------------------------------------------------------------------- | ------------------------------------------------------------ | --------------- |
| env  | `PORT`                      | port to run the server on                                                          | `8080`                                                       | `8080`          |
| env  | `JWKS_URL`                  | url pointing at the jwks json file (https://auth0.com/docs/tokens/concepts/jwks)   | http://some.com/.well-known/jwks.json                        | Required        |
| file | `/$CLAIM_MAPPING_FILE_PATH` | json file located at `$CLAIM_MAPPING_FILE_PATH` containing claim to header mapping | `{"claimKey-1": "headerKey-1", "claimKey-2": "headerKey-2"}` | Required        |
| env  | `CLAIM_MAPPING_FILE_PATH`   | path to the claim mapping json file                                                | `config.json`                                                | `config.json`   |
| env  | `AUTH_HEADER_KEY`           | Authorization Header Key Containing the token                                      | `Authorization`                                              | `Authorization` |
