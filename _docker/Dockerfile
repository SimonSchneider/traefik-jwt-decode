FROM golang:alpine as build
RUN apk --no-cache add ca-certificates

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --chown=0:0 main /
USER 65534

VOLUME ["/config"]

ENV CLAIM_MAPPING_FILE="/config/config.json"
EXPOSE 8080

ENTRYPOINT ["/main"]
