FROM golang:1.16 AS build

WORKDIR $GOPATH/src
COPY go.mod ./
COPY go.sum ./
RUN go get -d -v ./...
RUN go install -v ./...

COPY . .
RUN go build ./cmd/main.go


# Deploy
FROM alpine:latest 

RUN apk add libc6-compat
COPY --from=build /go/src/main /go/src/main

EXPOSE 8080

CMD [ "/go/src/main" ]