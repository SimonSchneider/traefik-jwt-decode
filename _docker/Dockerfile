# FROM golang:alpine as build
# RUN apk --no-cache add ca-certificates

# FROM scratch
# # COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
# # COPY --chown=0:0 main /
# USER 65534

# VOLUME ["/config"]

# ENV CLAIM_MAPPING_FILE="/config/config.json"
# EXPOSE 8080

# ENTRYPOINT ["/main"]


FROM golang:1.16 AS build

WORKDIR $GOPATH/src
COPY go.mod ./
COPY go.sum ./
RUN go get -d -v ./...
RUN go install -v ./...

COPY . .
RUN go build ./cmd/main.go


# # Deploy
# FROM golang:1.16

# COPY --from=build /go/src /go/server # TODO: multi stage build

EXPOSE 8080

CMD [ "/go/src/main" ]