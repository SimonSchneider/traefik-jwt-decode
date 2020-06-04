set -x
set -e

export GO111MODULE=on
export CGO_ENABLED=0
export GOARCH=amd64
export GOOS=linux
DIR=_build

mkdir -p $DIR/bin

go mod download
go build -o ./$DIR/bin/main ./cmd/main.go

docker build $DIR -t $1
