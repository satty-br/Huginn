FROM golang:1.21.6 AS builder

WORKDIR /go/src/github.com/satty-br/Huginn
COPY . .
RUN CGO_ENABLED=0 go build -o bin/huginn -ldflags "-X="github.com/satty-br/Huginn/v1/cmd.Version=1

RUN go build -o huginn

FROM alpine:3.19

RUN adduser -D huginn
COPY --from=builder /go/src/github.com/satty-br/Huginn/bin/* /usr/bin/
USER huginn

ENTRYPOINT ["huginn"]
