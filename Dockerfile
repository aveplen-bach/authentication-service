FROM golang:1.18 as builder

RUN mkdir -p /go/src/github.com/aveplen-bach/authentication_service

WORKDIR /go/src/github.com/aveplen-bach/authentication_service

COPY go.mod go.mod
COPY go.sum go.sum

RUN go mod download

COPY . ./

RUN CGO_ENABLED=0 go build -o /bin/authentication_service \
    /go/src/github.com/aveplen-bach/authentication_service/cmd/main.go

FROM alpine:3.15.4 as runtime

RUN apk add curl

COPY --from=builder /bin/authentication_service /bin/authentication_service
COPY ./auth-service.yaml ./auth-service.yaml

ENTRYPOINT [ "/bin/authentication_service" ]
