FROM golang:1.13 as builder
WORKDIR /src/app

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo .


FROM alpine:latest
WORKDIR /src/app

COPY --from=builder /src/app/matrix-private-registration .

COPY ./templates ./templates
COPY ./static ./static

EXPOSE 8000
ENTRYPOINT ["/src/app/matrix-private-registration"]
CMD ["-server"]