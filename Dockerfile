# Stage 1: build the binary.
FROM golang:1.22-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /callback-ledger .

# Stage 2: minimal runtime image.
FROM alpine:3.19

RUN apk add --no-cache ca-certificates

COPY --from=build /callback-ledger /usr/local/bin/callback-ledger

EXPOSE 8080
EXPOSE 5353/udp

ENTRYPOINT ["callback-ledger"]
CMD ["--http-port", "8080", "--dns-port", "5353"]
