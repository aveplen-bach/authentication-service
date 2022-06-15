FROM golang:1.18 as builder

RUN mkdir -p /go/src/github.com/aveplen-bach/authentication_service

WORKDIR /go/src/github.com/aveplen-bach/authentication_service

COPY go.mod go.mod
COPY go.sum go.sum

COPY . ./

RUN go build -o bin/auth cmd/main.go

RUN apt update
RUN apt install curl

ENTRYPOINT [ "go", "run", "cmd/main.go" ]
